"""Doc 06 §31 lifecycle test matrix at domain level, and the §25 and §26 scenarios.

One test per §31 row. The row "promotion DB failure" is NOT RUN in P1a: it needs the
repository ports and the promotion transaction (P1b, P6). Everything here is deterministic.
"""

from __future__ import annotations

import unittest

from core.domain.enums import CandidateStatus, InvariantStatus, VerificationResult
from core.domain.errors import (
    DomainValidationError,
    IllegalTransitionError,
    StaleParentError,
)
from core.domain.invariant import InvariantEvaluation, InvariantRef
from core.domain.state import (
    CandidateState,
    TrustedState,
    mark_promoted,
    reject_stale_candidate,
    resource_set_hash,
    transition_candidate,
)
from tests.domain_builders import (
    FUNC,
    SEC,
    analyzing_candidate,
    at,
    baseline,
    canonical_resources,
    new_candidate,
    patch_for,
    promotable_candidate,
    promote,
    proof,
    ready_candidate,
    uid,
    verified_proof,
)

CS = CandidateStatus
S = InvariantStatus
R = VerificationResult

SAFE = canonical_resources(ssh_open=False, db_path=True)
BROKEN = canonical_resources(ssh_open=False, db_path=False)


def ref(state: TrustedState, invariant_id: str) -> InvariantRef:
    return next(r for r in state.invariant_refs if r.invariant_id == invariant_id)


class TestMatrixCandidateRows(unittest.TestCase):
    def setUp(self) -> None:
        self.v0 = baseline()
        self.v0_before = self.v0.to_dict()

    def test_create_candidate_from_vN(self) -> None:
        candidate = new_candidate(self.v0)
        self.assertEqual(candidate.parent_state_id, self.v0.state_id)
        self.assertEqual(candidate.status, CS.CREATED)
        self.assertEqual(self.v0.to_dict(), self.v0_before)
        # ... and from a later state too.
        v1 = promote(promotable_candidate(self.v0, SAFE), self.v0)
        v1_before = v1.to_dict()
        again = new_candidate(v1, sequence=1, n=5)
        self.assertEqual(again.parent_state_id, v1.state_id)
        self.assertEqual(v1.to_dict(), v1_before)

    def test_reject(self) -> None:
        analyzing = analyzing_candidate(self.v0, BROKEN)
        rejected = transition_candidate(analyzing, CS.REJECTED)
        self.assertEqual(rejected.status, CS.REJECTED)
        with self.assertRaises(IllegalTransitionError) as ctx:
            TrustedState.promote(
                candidate=rejected,
                current=self.v0,
                decision_id=uid(4001),
                invariant_proofs=[proof()],
                evidence_refs=list(proof().evidence_ids),
                invariant_registry_version=1,
                now=at(10),
            )
        self.assertEqual(ctx.exception.rule, "SM-003")
        self.assertEqual(self.v0.to_dict(), self.v0_before)

    def test_retry(self) -> None:
        retry = transition_candidate(analyzing_candidate(self.v0, BROKEN), CS.RETRY_REQUIRED)
        self.assertEqual(retry.status, CS.RETRY_REQUIRED)
        nxt = CandidateState.create(
            parent=self.v0,
            patch=patch_for(self.v0, n=2),
            candidate_sequence=2,
            now=at(4),
            candidate_id=uid(3002),
        )
        self.assertEqual(nxt.parent_state_id, self.v0.state_id)
        self.assertEqual(nxt.candidate_sequence, 2)
        self.assertEqual(nxt.candidate_sequence, retry.candidate_sequence + 1)
        # A candidate can never be the trusted parent of the next one (DATA-INT-002, SM-004).
        with self.assertRaises(DomainValidationError) as ctx:
            CandidateState.create(
                parent=retry,  # type: ignore[arg-type]
                patch=patch_for(self.v0, n=3),
                candidate_sequence=2,
                now=at(4),
            )
        self.assertIn("DATA-INT-002", str(ctx.exception))
        with self.assertRaises(IllegalTransitionError) as ctx2:
            TrustedState.promote(
                candidate=retry,
                current=self.v0,
                decision_id=uid(4001),
                invariant_proofs=[proof()],
                evidence_refs=list(proof().evidence_ids),
                invariant_registry_version=1,
                now=at(10),
            )
        self.assertEqual(ctx2.exception.rule, "SM-004")
        self.assertEqual(self.v0.to_dict(), self.v0_before)

    def test_escalate(self) -> None:
        escalated = transition_candidate(analyzing_candidate(self.v0, BROKEN), CS.ESCALATED)
        self.assertEqual(escalated.status, CS.ESCALATED)
        self.assertEqual(self.v0.to_dict(), self.v0_before)
        with self.assertRaises(IllegalTransitionError) as ctx:
            TrustedState.promote(
                candidate=escalated,
                current=self.v0,
                decision_id=uid(4001),
                invariant_proofs=[proof()],
                evidence_refs=list(proof().evidence_ids),
                invariant_registry_version=1,
                now=at(10),
            )
        self.assertEqual(ctx.exception.rule, "SM-005")

    def test_promote(self) -> None:
        for parent in (
            self.v0,
            promote(promotable_candidate(self.v0, SAFE, n=9), self.v0, decision=9),
        ):
            with self.subTest(parent_version=parent.version):
                parent_before = parent.to_dict()
                candidate = promotable_candidate(parent, SAFE, n=1)
                new = promote(candidate, parent, decision=1)
                self.assertEqual(new.version, parent.version + 1)
                self.assertEqual(new.parent_state_id, parent.state_id)
                self.assertEqual(new.lineage_id, parent.lineage_id)
                self.assertEqual(new.commit_decision_id, uid(4001))
                promoted = mark_promoted(candidate, new)
                self.assertEqual(promoted.status, CS.PROMOTED)
                self.assertEqual(new.resource_set_hash(), candidate.state_hash)
                self.assertEqual(
                    new.resource_set_hash(), resource_set_hash(SAFE, parent.normalization_version)
                )
                self.assertEqual(parent.to_dict(), parent_before)
                self.assertEqual(candidate.status, CS.PROMOTABLE)  # inputs are unchanged

    def test_promote_stale(self) -> None:
        a = promotable_candidate(self.v0, SAFE, n=1)
        b = promotable_candidate(self.v0, BROKEN, n=2, sequence=2)
        v1 = promote(a, self.v0, decision=1)
        with self.assertRaises(StaleParentError) as ctx:
            promote(b, v1, decision=2)
        self.assertEqual(ctx.exception.rule, "SM-010")
        stale = reject_stale_candidate(b, v1)
        self.assertEqual(stale.status, CS.REJECTED)
        self.assertEqual(stale.status_reason, "STALE_PARENT")
        # The current state is unchanged by all of this.
        v1_before = v1.to_dict()
        reject_stale_candidate(b, v1)
        self.assertEqual(v1.to_dict(), v1_before)
        # A candidate whose parent is still current is not stale.
        with self.assertRaises(IllegalTransitionError):
            reject_stale_candidate(promotable_candidate(v1, SAFE, n=3), v1)
        # A stale candidate that is not PROMOTABLE cannot be rejected this way.
        with self.assertRaises(IllegalTransitionError):
            reject_stale_candidate(analyzing_candidate(self.v0, SAFE, n=4), v1)


class TestMatrixInvariantRows(unittest.TestCase):
    def setUp(self) -> None:
        self.v0 = baseline()
        self.candidate = promotable_candidate(self.v0, SAFE)
        self.sec = ref(self.v0, SEC)
        self.func = ref(self.v0, FUNC)
        self.sec_before = self.sec.to_dict()

    def reverify(self, result: VerificationResult, evidence: int = 40) -> InvariantEvaluation:
        affected = InvariantEvaluation.affect(self.sec, self.candidate, "ssh rule changed")
        return affected.start_reverification().apply_result(result, [uid(9000 + evidence)], at(20))

    def test_affect_a_protected_invariant(self) -> None:
        ev = InvariantEvaluation.affect(self.sec, self.candidate, "ssh rule changed")
        self.assertEqual(ev.status, S.AFFECTED)
        self.assertEqual(self.sec.to_dict(), self.sec_before)  # C-23: the parent ref is unchanged
        self.assertEqual(self.sec.status, S.PROTECTED)

    def test_reverify_pass(self) -> None:
        ev = self.reverify(R.PASS)
        self.assertEqual(ev.status, S.PROTECTED)
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[ev.to_proof(), verified_proof(self.v0, self.candidate, FUNC, S.PROTECTED, 12)],
        )
        new_ref = ref(v1, SEC)
        self.assertEqual(new_ref.status, S.PROTECTED)
        self.assertEqual(new_ref.state_id, v1.state_id)
        self.assertEqual(new_ref.evidence_ids, (uid(9040),))
        self.assertTrue(new_ref.can_satisfy_proof())
        self.assertEqual(self.sec.to_dict(), self.sec_before)

    def test_reverify_fail(self) -> None:
        ev = self.reverify(R.FAIL)
        self.assertEqual(ev.status, S.VIOLATED)
        self.assertEqual(ev.last_result, R.FAIL)
        # No way to PROTECTED from here without REVERIFYING, then a PASS.
        for attempt in (
            lambda: ev.apply_result(R.PASS, [uid(1)], at(21)),
            lambda: ev.start_verification(),
            lambda: ev.start_reverification(),
        ):
            with self.assertRaises(IllegalTransitionError):
                attempt()
        # The proper path: the violated state is recorded, a later candidate reopens it.
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[ev.to_proof(), verified_proof(self.v0, self.candidate, FUNC, S.PROTECTED, 12)],
        )
        violated_ref = ref(v1, SEC)
        self.assertEqual(violated_ref.status, S.VIOLATED)
        self.assertFalse(violated_ref.can_satisfy_proof())
        later = ready_candidate(v1, SAFE, n=6)
        reopened = InvariantEvaluation.reopen(violated_ref, later, "fix attempted")
        self.assertEqual(reopened.status, S.REVERIFYING)
        passed = reopened.apply_result(R.PASS, [uid(9050)], at(30))
        self.assertEqual(passed.status, S.PROTECTED)

    def test_reverify_unknown(self) -> None:
        ev = self.reverify(R.UNKNOWN)
        self.assertEqual(ev.status, S.UNCERTAIN)
        self.assertEqual(ev.last_result, R.UNKNOWN)

    def test_unsupported_verifier(self) -> None:
        ev = self.reverify(R.UNSUPPORTED)
        self.assertEqual(ev.status, S.UNCERTAIN)
        self.assertEqual(ev.last_result, R.UNSUPPORTED)
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[ev.to_proof(), verified_proof(self.v0, self.candidate, FUNC, S.PROTECTED, 12)],
        )
        self.assertFalse(ref(v1, SEC).can_satisfy_proof())
        self.assertEqual(ref(v1, SEC).status, S.UNCERTAIN)

    def test_verifier_error_also_stays_uncertain(self) -> None:
        ev = self.reverify(R.VERIFIER_ERROR)
        self.assertEqual((ev.status, ev.last_result), (S.UNCERTAIN, R.VERIFIER_ERROR))


class TestScenarioDoc06Section25(unittest.TestCase):
    """Doc 06 §25, the canonical regression: baseline v0 (SEC, FUNC PROTECTED) -> candidate R1
    (SEC PASS, FUNC FAIL) -> REJECT -> v0 remains current -> candidate R2 starts from v0."""

    def test_regression_is_rejected_and_the_next_candidate_starts_from_v0(self) -> None:
        v0 = baseline(resources=canonical_resources(ssh_open=True, db_path=True))
        v0_before = v0.to_dict()
        r1 = ready_candidate(v0, BROKEN, n=1)
        # Impact marks both invariants AFFECTED for R1; the parent refs are not touched.
        sec_eval = InvariantEvaluation.affect(ref(v0, SEC), r1, "ssh rule removed")
        func_eval = InvariantEvaluation.affect(ref(v0, FUNC), r1, "ec2_to_rds rule changed")
        self.assertEqual({sec_eval.status, func_eval.status}, {S.AFFECTED})
        sec_done = sec_eval.start_reverification().apply_result(R.PASS, [uid(9101)], at(20))
        func_done = func_eval.start_reverification().apply_result(R.FAIL, [uid(9102)], at(20))
        self.assertEqual((sec_done.status, func_done.status), (S.PROTECTED, S.VIOLATED))
        # R1 is rejected; Trusted State does not advance.
        rejected = transition_candidate(transition_candidate(r1, CS.ANALYZING), CS.REJECTED)
        self.assertEqual(rejected.status, CS.REJECTED)
        self.assertEqual(v0.to_dict(), v0_before)
        for r in v0.invariant_refs:
            self.assertEqual(r.status, S.PROTECTED)
            self.assertTrue(r.can_satisfy_proof())
        with self.assertRaises(IllegalTransitionError):
            TrustedState.promote(
                candidate=rejected,
                current=v0,
                decision_id=uid(4001),
                invariant_proofs=[sec_done.to_proof(), func_done.to_proof()],
                evidence_refs=[uid(9101), uid(9102)],
                invariant_registry_version=1,
                now=at(21),
            )
        # A rejected candidate is never a trusted parent; R2 starts from v0.
        with self.assertRaises(DomainValidationError):
            CandidateState.create(
                parent=rejected,  # type: ignore[arg-type]
                patch=patch_for(v0, n=2),
                candidate_sequence=2,
                now=at(22),
            )
        r2 = CandidateState.create(
            parent=v0, patch=patch_for(v0, n=2), candidate_sequence=2, now=at(22)
        )
        self.assertEqual(r2.parent_state_id, v0.state_id)
        self.assertEqual(r2.candidate_sequence, 2)
        self.assertEqual(v0.to_dict(), v0_before)


class TestScenarioDoc06Section26(unittest.TestCase):
    """Doc 06 §26, safe promotion: baseline v0 -> candidate S1 (SEC PASS, FUNC PASS) -> PROMOTE
    -> v1 with SEC and FUNC PROTECTED (current evidence)."""

    def test_safe_candidate_is_promoted_with_current_evidence(self) -> None:
        v0 = baseline(resources=canonical_resources(ssh_open=True, db_path=True))
        v0_before = v0.to_dict()
        s1 = ready_candidate(v0, SAFE, n=1)
        evidence = {SEC: uid(9201), FUNC: uid(9202)}
        done = {}
        for invariant_id in (SEC, FUNC):
            ev = InvariantEvaluation.affect(ref(v0, invariant_id), s1, f"{invariant_id} affected")
            done[invariant_id] = ev.start_reverification().apply_result(
                R.PASS, [evidence[invariant_id]], at(20)
            )
        promotable = transition_candidate(transition_candidate(s1, CS.ANALYZING), CS.PROMOTABLE)
        v1 = TrustedState.promote(
            candidate=promotable,
            current=v0,
            decision_id=uid(4001),
            invariant_proofs=[done[SEC].to_proof(), done[FUNC].to_proof()],
            evidence_refs=sorted(evidence.values()),
            invariant_registry_version=1,
            now=at(25),
            state_id=uid(11),
        )
        promoted = mark_promoted(promotable, v1)
        self.assertEqual(promoted.status, CS.PROMOTED)
        self.assertEqual((v1.version, v1.parent_state_id), (1, v0.state_id))
        for invariant_id in (SEC, FUNC):
            new_ref = ref(v1, invariant_id)
            self.assertEqual(new_ref.status, S.PROTECTED)
            self.assertTrue(new_ref.can_satisfy_proof())
            self.assertEqual(new_ref.evidence_ids, (evidence[invariant_id],))
            self.assertEqual(new_ref.state_id, v1.state_id)
        self.assertEqual(set(evidence.values()), set(v1.evidence_refs))
        # v0 keeps its own references and evidence.
        self.assertEqual(v0.to_dict(), v0_before)
        self.assertNotIn(evidence[SEC], v0.evidence_refs)


if __name__ == "__main__":
    unittest.main()
