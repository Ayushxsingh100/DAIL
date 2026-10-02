"""Doc 06 §31 lifecycle matrix and the §25, §26 scenarios through ``SqliteUnitOfWork`` (P1b step 8).

``test_lifecycle_matrix.py`` checks these rows on in-memory objects. Here every row goes through
the repositories, and after each commit the result is read back through a new connection (a new
unit of work), so only committed data counts. The row "promotion DB failure" is the Step 5 fault
injection, run again over the §26 promotion at all four checkpoints.

Expected values come from the P1b prompt's Section 8 table and the scenarios' descriptions in the
existing domain tests, not from the implementation.
"""

from __future__ import annotations

import unittest
from typing import Any

from core.domain.enums import CandidateStatus, InvariantStatus, ProofOrigin, VerificationResult
from core.domain.errors import (
    DomainValidationError,
    IllegalTransitionError,
    PersistenceError,
    StaleParentError,
)
from core.domain.invariant import InvariantEvaluation, InvariantRef
from core.domain.state import (
    CandidateState,
    TrustedState,
    mark_promoted,
    reject_stale_candidate,
    transition_candidate,
)
from core.persistence.sqlite import CHECKPOINTS
from tests.domain_builders import (
    FUNC,
    LINEAGE,
    SEC,
    at,
    baseline,
    canonical_resources,
    new_candidate,
    patch_for,
    promotable_candidate,
    promote,
    proof,
    uid,
    verified_proof,
)
from tests.persistence_builders import SAFE, SAFE_OTHER, Boom, RepoCase, definitions

CS = CandidateStatus
S = InvariantStatus
R = VerificationResult
BROKEN = SAFE_OTHER  # SSH closed, EC2 -> RDS path gone


def ref_of(refs: tuple[InvariantRef, ...], invariant_id: str) -> InvariantRef:
    return next(r for r in refs if r.invariant_id == invariant_id)


class LifecycleCase(RepoCase):
    def setUp(self) -> None:
        super().setUp()
        self.v0 = self.seed(baseline(resources=canonical_resources(ssh_open=True, db_path=True)))
        self.v0_before = self.v0.to_dict()

    def refs_of(self, state_id: str) -> tuple[InvariantRef, ...]:
        with self.uow() as u:
            return u.invariants.get_state_refs(state_id)

    def current(self) -> TrustedState | None:
        with self.uow() as u:
            return u.trusted_states.get_current(LINEAGE)

    def assert_v0_untouched(self) -> None:
        """vN's state and its references are exactly as saved (C-23, DATA-INT-006)."""
        stored = self.read_state(self.v0.state_id)
        assert stored is not None
        self.assertEqual(stored.to_dict(), self.v0_before)
        self.assertEqual(self.refs_of(self.v0.state_id), self.v0.invariant_refs)

    def commit_promotion(
        self, promotable: CandidateState, parent: TrustedState, **kwargs: Any
    ) -> TrustedState:
        new_state = promote(promotable, parent, **kwargs)
        with self.uow() as u:
            u.trusted_states.save_promoted(new_state)
            u.candidates.save_transition(mark_promoted(promotable, new_state))
        return new_state


# --- candidate rows of the matrix ----------------------------------------------------------------


class TestMatrixCandidateRows(LifecycleCase):
    def test_create_candidate_from_vN(self) -> None:
        created = self.store_stages(self.v0, SAFE, n=1, sequence=1, upto=0)[0]
        stored = self.read_candidate(created.candidate_id)
        assert stored is not None
        self.assertEqual(stored.parent_state_id, self.v0.state_id)
        self.assertEqual(stored.status, CS.CREATED)
        self.assert_v0_untouched()
        # ... and from a later state too.
        promotable = self.store_stages(self.v0, SAFE, n=2, sequence=2)[-1]
        v1 = self.commit_promotion(promotable, self.v0, decision=2)
        v1_before = v1.to_dict()
        again = self.store_stages(v1, SAFE, n=5, sequence=3, upto=0)[0]
        stored_again = self.read_candidate(again.candidate_id)
        assert stored_again is not None
        self.assertEqual(stored_again.parent_state_id, v1.state_id)
        stored_v1 = self.read_state(v1.state_id)
        assert stored_v1 is not None
        self.assertEqual(stored_v1.to_dict(), v1_before)

    def test_reject(self) -> None:
        analyzing = self.store_stages(self.v0, BROKEN, n=1, sequence=1, upto=3)[3]
        rejected = transition_candidate(analyzing, CS.REJECTED)
        with self.uow() as u:
            u.candidates.save_transition(rejected)
        stored = self.read_candidate(rejected.candidate_id)
        assert stored is not None
        self.assertEqual(stored.status, CS.REJECTED)
        current = self.current()
        assert current is not None
        self.assertEqual(current.state_id, self.v0.state_id)  # still vN
        self.assertEqual(self.count("trusted_states"), 1)
        with self.assertRaises(IllegalTransitionError) as ctx:
            promote(rejected, self.v0)
        self.assertEqual(ctx.exception.rule, "SM-003")
        self.assert_v0_untouched()

    def test_retry(self) -> None:
        analyzing = self.store_stages(self.v0, BROKEN, n=1, sequence=1, upto=3)[3]
        retry = transition_candidate(analyzing, CS.RETRY_REQUIRED)
        with self.uow() as u:
            u.candidates.save_transition(retry)
        next_candidate = self.store_stages(self.v0, SAFE, n=2, sequence=2, upto=0)[0]
        stored = self.read_candidate(next_candidate.candidate_id)
        assert stored is not None
        self.assertEqual(stored.parent_state_id, self.v0.state_id)
        self.assertEqual(stored.candidate_sequence, retry.candidate_sequence + 1)
        # A candidate is never the trusted parent of the next one (DATA-INT-002, SM-004).
        with self.assertRaises(DomainValidationError) as ctx:
            CandidateState.create(
                parent=retry,  # type: ignore[arg-type]
                patch=patch_for(self.v0, n=3),
                candidate_sequence=3,
                now=at(4),
            )
        self.assertIn("DATA-INT-002", str(ctx.exception))
        with self.assertRaises(IllegalTransitionError) as ctx2:
            promote(retry, self.v0)
        self.assertEqual(ctx2.exception.rule, "SM-004")
        self.assert_v0_untouched()

    def test_a_sequence_number_is_never_reused_in_a_lineage(self) -> None:
        """C-46: the retry takes sequence + 1; repeating a sequence is refused."""
        self.store_stages(self.v0, BROKEN, n=1, sequence=1, upto=0)
        with self.uow() as u:
            u.patches.save(patch_for(self.v0, n=3))
            with self.assertRaises(PersistenceError):
                u.candidates.create(new_candidate(self.v0, sequence=1, n=3))

    def test_escalate(self) -> None:
        analyzing = self.store_stages(self.v0, BROKEN, n=1, sequence=1, upto=3)[3]
        escalated = transition_candidate(analyzing, CS.ESCALATED)
        with self.uow() as u:
            u.candidates.save_transition(escalated)
        stored = self.read_candidate(escalated.candidate_id)
        assert stored is not None
        self.assertEqual(stored.status, CS.ESCALATED)
        with self.assertRaises(IllegalTransitionError) as ctx:
            promote(escalated, self.v0)
        self.assertEqual(ctx.exception.rule, "SM-005")
        self.assertEqual(self.count("trusted_states"), 1)
        self.assert_v0_untouched()

    def test_promote(self) -> None:
        parent = self.v0
        for round_number in (1, 2):
            with self.subTest(parent_version=parent.version):
                parent_before = parent.to_dict()
                promotable = self.store_stages(parent, SAFE, n=round_number, sequence=round_number)[
                    -1
                ]
                new = self.commit_promotion(promotable, parent, decision=round_number)
                current = self.current()
                assert current is not None
                self.assertEqual(current.state_id, new.state_id)  # the head is vN+1
                self.assertEqual(current.version, parent.version + 1)
                self.assertEqual(new.parent_state_id, parent.state_id)
                self.assertEqual(new.commit_decision_id, uid(4000 + round_number))
                refs = self.refs_of(new.state_id)
                self.assertEqual({r.origin for r in refs}, {ProofOrigin.VERIFIED})
                stored_candidate = self.read_candidate(promotable.candidate_id)
                assert stored_candidate is not None
                self.assertEqual(stored_candidate.status, CS.PROMOTED)
                self.assertEqual(new.resource_set_hash(), stored_candidate.state_hash)
                stored_parent = self.read_state(parent.state_id)
                assert stored_parent is not None
                self.assertEqual(stored_parent.to_dict(), parent_before)
                parent = new

    def test_the_baseline_refs_carry_the_baseline_origin(self) -> None:
        self.assertEqual({r.origin for r in self.refs_of(self.v0.state_id)}, {ProofOrigin.BASELINE})

    def test_promote_stale(self) -> None:
        first = self.store_stages(self.v0, SAFE, n=1, sequence=1)[-1]
        second = self.store_stages(self.v0, BROKEN, n=2, sequence=2)[-1]
        v1 = self.commit_promotion(first, self.v0, decision=1)
        # The domain refuses it ...
        with self.assertRaises(StaleParentError) as ctx:
            promote(second, v1, decision=2)
        self.assertEqual(ctx.exception.rule, "SM-010")
        # ... and so does the repository, even for a state built before the first promotion.
        stale_state = promote(second, self.v0, decision=2)
        before = self.snapshot_counts()
        with self.uow() as u, self.assertRaises(StaleParentError) as ctx2:
            u.trusted_states.save_promoted(stale_state)
        self.assertEqual(ctx2.exception.rule, "SM-010")
        self.assertEqual(self.snapshot_counts(), before)
        # The stale candidate is rejected with STALE_PARENT; the current state is unchanged.
        with self.uow() as u:
            u.candidates.save_transition(reject_stale_candidate(second, v1))
        stored = self.read_candidate(second.candidate_id)
        assert stored is not None
        self.assertEqual((stored.status, stored.status_reason), (CS.REJECTED, "STALE_PARENT"))
        current = self.current()
        assert current is not None
        self.assertEqual(current, v1)
        # A candidate whose parent is still current is not stale.
        third = self.store_stages(v1, SAFE, n=3, sequence=3)[-1]
        with self.assertRaises(IllegalTransitionError):
            reject_stale_candidate(third, v1)
        self.assert_v0_untouched()


# --- invariant rows of the matrix ----------------------------------------------------------------


class TestMatrixInvariantRows(LifecycleCase):
    def setUp(self) -> None:
        super().setUp()
        self.candidate = self.store_stages(self.v0, SAFE, n=1, sequence=1)[-1]
        stored = self.refs_of(self.v0.state_id)
        self.sec = ref_of(stored, SEC)
        self.func = ref_of(stored, FUNC)

    def reverify(self, result: VerificationResult, evidence: int = 40) -> InvariantEvaluation:
        affected = InvariantEvaluation.affect(self.sec, self.candidate, "ssh rule changed")
        return affected.start_reverification().apply_result(result, [uid(9000 + evidence)], at(20))

    def promote_with(self, evaluation: InvariantEvaluation) -> tuple[TrustedState, InvariantRef]:
        v1 = self.commit_promotion(
            self.candidate,
            self.v0,
            proofs=[
                evaluation.to_proof(),
                verified_proof(self.v0, self.candidate, FUNC, S.PROTECTED, 12),
            ],
        )
        return v1, ref_of(self.refs_of(v1.state_id), SEC)

    def test_affect_a_protected_invariant(self) -> None:
        evaluation = InvariantEvaluation.affect(self.sec, self.candidate, "ssh rule changed")
        self.assertEqual(evaluation.status, S.AFFECTED)
        # C-23: the stored reference of vN is untouched, and nothing was written for the evaluation.
        self.assertEqual(ref_of(self.refs_of(self.v0.state_id), SEC).status, S.PROTECTED)
        self.assert_v0_untouched()
        self.assertEqual(self.count("invariant_refs"), len(self.v0.invariant_refs))

    def test_reverify_pass_is_the_only_result_that_yields_a_protected_reference(self) -> None:
        evaluation = self.reverify(R.PASS)
        self.assertEqual(evaluation.status, S.PROTECTED)
        v1, new_ref = self.promote_with(evaluation)
        self.assertEqual(new_ref.status, S.PROTECTED)
        self.assertEqual(new_ref.state_id, v1.state_id)
        self.assertEqual(new_ref.evidence_ids, (uid(9040),))
        self.assertEqual(new_ref.origin, ProofOrigin.VERIFIED)
        self.assertTrue(new_ref.can_satisfy_proof())
        self.assert_v0_untouched()

    def assert_not_protected(self, result: VerificationResult, expected: InvariantStatus) -> None:
        evaluation = self.reverify(result)
        self.assertEqual(evaluation.status, expected)
        self.assertEqual(evaluation.last_result, result)
        v1, new_ref = self.promote_with(evaluation)
        self.assertEqual(new_ref.status, expected)
        self.assertNotEqual(new_ref.status, S.PROTECTED)
        self.assertFalse(new_ref.can_satisfy_proof())
        # The status of vN is unchanged on disk; only vN+1 carries the new one.
        self.assertEqual(ref_of(self.refs_of(self.v0.state_id), SEC).status, S.PROTECTED)
        self.assert_v0_untouched()
        self.assertEqual(self.refs_of(v1.state_id), v1.invariant_refs)

    def test_reverify_fail_is_stored_as_violated(self) -> None:
        self.assert_not_protected(R.FAIL, S.VIOLATED)

    def test_reverify_unknown_is_stored_as_uncertain(self) -> None:
        self.assert_not_protected(R.UNKNOWN, S.UNCERTAIN)

    def test_an_unsupported_verifier_is_stored_as_uncertain(self) -> None:
        self.assert_not_protected(R.UNSUPPORTED, S.UNCERTAIN)

    def test_a_verifier_error_is_stored_as_uncertain(self) -> None:
        self.assert_not_protected(R.VERIFIER_ERROR, S.UNCERTAIN)

    def test_a_violated_reference_is_reopened_by_a_later_candidate_and_can_pass(self) -> None:
        v1, violated = self.promote_with(self.reverify(R.FAIL))
        self.assertEqual(violated.status, S.VIOLATED)
        later = self.store_stages(v1, SAFE, n=6, sequence=2)[-1]
        reopened = InvariantEvaluation.reopen(violated, later, "fix attempted")
        self.assertEqual(reopened.status, S.REVERIFYING)
        passed = reopened.apply_result(R.PASS, [uid(9050)], at(30))
        v2 = self.commit_promotion(
            later,
            v1,
            decision=2,
            proofs=[passed.to_proof(), verified_proof(v1, later, FUNC, S.PROTECTED, 13)],
        )
        new_ref = ref_of(self.refs_of(v2.state_id), SEC)
        self.assertEqual(new_ref.status, S.PROTECTED)
        self.assertEqual(new_ref.evidence_ids, (uid(9050),))
        # v1's violated reference is still on record.
        self.assertEqual(ref_of(self.refs_of(v1.state_id), SEC).status, S.VIOLATED)


# --- the Doc 06 §25 and §26 scenarios ------------------------------------------------------------


class TestScenarioDoc06Section25(LifecycleCase):
    """The canonical regression: v0 (SEC, FUNC PROTECTED) -> R1 (SEC PASS, FUNC FAIL) -> REJECT ->
    v0 remains current -> R2 starts from v0."""

    def test_regression_is_rejected_and_the_next_candidate_starts_from_v0(self) -> None:
        r1_steps = self.store_stages(self.v0, BROKEN, n=1, sequence=1, upto=2)
        r1 = r1_steps[2]  # READY
        stored_refs = self.refs_of(self.v0.state_id)
        sec_eval = InvariantEvaluation.affect(ref_of(stored_refs, SEC), r1, "ssh rule removed")
        func_eval = InvariantEvaluation.affect(
            ref_of(stored_refs, FUNC), r1, "ec2_to_rds rule changed"
        )
        self.assertEqual({sec_eval.status, func_eval.status}, {S.AFFECTED})
        sec_done = sec_eval.start_reverification().apply_result(R.PASS, [uid(9101)], at(20))
        func_done = func_eval.start_reverification().apply_result(R.FAIL, [uid(9102)], at(20))
        self.assertEqual((sec_done.status, func_done.status), (S.PROTECTED, S.VIOLATED))
        analyzing = transition_candidate(r1, CS.ANALYZING)
        rejected = transition_candidate(analyzing, CS.REJECTED)
        with self.uow() as u:
            u.candidates.save_transition(analyzing)
            u.candidates.save_transition(rejected)
        # Trusted State does not advance, and v0's references are all still PROTECTED.
        current = self.current()
        assert current is not None
        self.assertEqual(current.state_id, self.v0.state_id)
        self.assertEqual(self.count("trusted_states"), 1)
        for stored in self.refs_of(self.v0.state_id):
            self.assertEqual(stored.status, S.PROTECTED)
            self.assertTrue(stored.can_satisfy_proof())
        self.assert_v0_untouched()
        with self.assertRaises(IllegalTransitionError):
            promote(rejected, self.v0, proofs=[sec_done.to_proof(), func_done.to_proof()])
        # The rejected candidate is retained (Doc 05 §33) and is never a trusted parent.
        stored_r1 = self.read_candidate(rejected.candidate_id)
        assert stored_r1 is not None
        self.assertEqual(stored_r1.status, CS.REJECTED)
        with self.assertRaises(DomainValidationError):
            CandidateState.create(
                parent=rejected,  # type: ignore[arg-type]
                patch=patch_for(self.v0, n=2),
                candidate_sequence=2,
                now=at(22),
            )
        r2 = self.store_stages(self.v0, SAFE, n=2, sequence=2, upto=0)[0]
        stored_r2 = self.read_candidate(r2.candidate_id)
        assert stored_r2 is not None
        self.assertEqual(
            (stored_r2.parent_state_id, stored_r2.candidate_sequence), (self.v0.state_id, 2)
        )
        self.assert_v0_untouched()


class TestScenarioDoc06Section26(LifecycleCase):
    """Safe promotion: v0 -> S1 (SEC PASS, FUNC PASS) -> PROMOTE -> v1, SEC and FUNC PROTECTED."""

    def passes(self, candidate: CandidateState) -> dict[str, InvariantEvaluation]:
        stored_refs = self.refs_of(self.v0.state_id)
        evidence = {SEC: uid(9201), FUNC: uid(9202)}
        done = {}
        for invariant_id in (SEC, FUNC):
            evaluation = InvariantEvaluation.affect(
                ref_of(stored_refs, invariant_id), candidate, f"{invariant_id} affected"
            )
            done[invariant_id] = evaluation.start_reverification().apply_result(
                R.PASS, [evidence[invariant_id]], at(20)
            )
        return done

    def test_safe_candidate_is_promoted_with_current_evidence(self) -> None:
        s1 = self.store_stages(self.v0, SAFE, n=1, sequence=1)[-1]
        done = self.passes(s1)
        evidence = {SEC: uid(9201), FUNC: uid(9202)}
        v1 = TrustedState.promote(
            candidate=s1,
            current=self.v0,
            decision_id=uid(4001),
            invariant_proofs=[done[SEC].to_proof(), done[FUNC].to_proof()],
            evidence_refs=sorted(evidence.values()),
            invariant_registry_version=1,
            now=at(25),
            state_id=uid(11),
        )
        with self.uow() as u:
            u.trusted_states.save_promoted(v1)
            u.candidates.save_transition(mark_promoted(s1, v1))
        current = self.current()
        assert current is not None
        self.assertEqual((current.version, current.parent_state_id), (1, self.v0.state_id))
        stored = self.read_candidate(s1.candidate_id)
        assert stored is not None
        self.assertEqual(stored.status, CS.PROMOTED)
        refs = self.refs_of(v1.state_id)
        for invariant_id in (SEC, FUNC):
            new_ref = ref_of(refs, invariant_id)
            self.assertEqual(new_ref.status, S.PROTECTED)
            self.assertTrue(new_ref.can_satisfy_proof())
            self.assertEqual(new_ref.evidence_ids, (evidence[invariant_id],))
            self.assertEqual(new_ref.state_id, v1.state_id)
            self.assertEqual(new_ref.origin, ProofOrigin.VERIFIED)
        self.assertEqual(set(evidence.values()), set(current.evidence_refs))
        # v0 keeps its own references and evidence.
        self.assert_v0_untouched()
        self.assertNotIn(evidence[SEC], self.v0.evidence_refs)


class TestEndToEnd(LifecycleCase):
    """§25 and then §26 on one lineage: R1 is rejected, then R2 is promoted. ``lineage()`` returns
    [v1, v0] and every reloaded object hashes as the in-memory one did (DATA-INT-010)."""

    def test_the_regression_then_the_safe_promotion_on_one_lineage(self) -> None:
        # §25: R1 breaks EC2 -> RDS and is rejected.
        r1_steps = self.store_stages(self.v0, BROKEN, n=1, sequence=1, upto=3)
        rejected = transition_candidate(r1_steps[3], CS.REJECTED)
        with self.uow() as u:
            u.candidates.save_transition(rejected)
        current = self.current()
        assert current is not None
        self.assertEqual(current.state_id, self.v0.state_id)
        # §26: R2 starts from v0 (sequence 2), fixes SSH and keeps the path, and is promoted.
        r2_steps = self.store_stages(self.v0, SAFE, n=2, sequence=2)
        r2 = r2_steps[-1]
        v1 = self.commit_promotion(r2, self.v0, decision=2)

        with self.uow() as u:
            lineage = u.trusted_states.lineage(v1.state_id)
            head = u.trusted_states.get_current(LINEAGE)
            reloaded_r1 = u.candidates.get(rejected.candidate_id)
            reloaded_r2 = u.candidates.get(r2.candidate_id)
            reloaded_patch = u.patches.get(patch_for(self.v0, n=2).patch_id)
            definition = u.invariants.get_definition(SEC, 1)
        self.assertEqual([s.version for s in lineage], [1, 0])
        self.assertEqual([s.state_id for s in lineage], [v1.state_id, self.v0.state_id])
        self.assertEqual(lineage, [v1, self.v0])
        self.assertEqual(head, v1)
        # DATA-INT-010: the hashes of the reloaded objects equal the in-memory ones.
        self.assertEqual([s.state_hash for s in lineage], [v1.state_hash, self.v0.state_hash])
        assert reloaded_r1 is not None and reloaded_r2 is not None and definition is not None
        self.assertEqual(reloaded_r1.state_hash, rejected.state_hash)
        self.assertEqual(reloaded_r2.state_hash, r2.state_hash)
        self.assertEqual(reloaded_r2.patch_hash, r2.patch_hash)
        self.assertEqual(reloaded_patch, patch_for(self.v0, n=2))
        self.assertEqual(definition.definition_hash(), definitions()[0].definition_hash())
        # The rejected candidate and both raw patches are retained (Doc 05 §33).
        self.assertEqual((reloaded_r1.status, reloaded_r2.status), (CS.REJECTED, CS.PROMOTED))
        self.assertEqual(self.count("candidates"), 2)
        self.assertEqual(self.count("patches"), 2)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assert_v0_untouched()


# --- the DB-failure row of the matrix ------------------------------------------------------------


class TestMatrixPromotionDatabaseFailure(LifecycleCase):
    """Doc 06 §31: "Promotion DB failure -> No partial trusted advancement", over the §26 case."""

    def test_a_failure_at_every_checkpoint_leaves_vN_current_and_the_candidate_promotable(
        self,
    ) -> None:
        s1 = self.store_stages(self.v0, SAFE, n=1, sequence=1)[-1]
        new_state = promote(s1, self.v0)
        before = self.snapshot_counts()
        for name in CHECKPOINTS:
            with self.subTest(checkpoint=name):

                def checkpoint(point: str, target: str = name) -> None:
                    if point == target:
                        raise Boom(point)

                with self.assertRaises(Boom), self.uow(checkpoint=checkpoint) as u:
                    u.trusted_states.save_promoted(new_state)
                    u.candidates.save_transition(mark_promoted(s1, new_state))
                self.assertEqual(self.snapshot_counts(), before)
                current = self.current()
                assert current is not None
                self.assertEqual(current.state_id, self.v0.state_id)
                self.assertIsNone(self.read_state(new_state.state_id))
                stored = self.read_candidate(s1.candidate_id)
                assert stored is not None
                self.assertEqual(stored.status, CS.PROMOTABLE)
        self.assert_v0_untouched()

    def test_the_retry_after_a_failed_commit_succeeds(self) -> None:
        s1 = self.store_stages(self.v0, SAFE, n=1, sequence=1)[-1]
        new_state = promote(s1, self.v0)

        def fail_once(point: str) -> None:
            if point == "before_commit":
                raise Boom(point)

        with self.assertRaises(Boom), self.uow(checkpoint=fail_once) as u:
            u.trusted_states.save_promoted(new_state)
            u.candidates.save_transition(mark_promoted(s1, new_state))
        with self.uow() as u:  # the same promotion, no fault
            u.trusted_states.save_promoted(new_state)
            u.candidates.save_transition(mark_promoted(s1, new_state))
        current = self.current()
        assert current is not None
        self.assertEqual(current.state_id, new_state.state_id)
        self.assertEqual(self.count("trusted_states"), 2)


class TestHelperIsHonest(unittest.TestCase):
    def test_a_baseline_proof_cannot_stand_in_for_a_verified_one(self) -> None:
        """So that the matrix above cannot pass by promoting with ``proof()`` (C-40)."""
        v0 = baseline()
        candidate = promotable_candidate(v0, SAFE)
        with self.assertRaises(DomainValidationError):
            TrustedState.promote(
                candidate=candidate,
                current=v0,
                decision_id=uid(4001),
                invariant_proofs=[proof(SEC), proof(FUNC)],
                evidence_refs=[],
                invariant_registry_version=1,
                now=at(10),
            )


if __name__ == "__main__":
    unittest.main()
