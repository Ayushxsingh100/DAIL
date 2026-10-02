"""Forbidden transitions SM-001 to SM-010 (Doc 06 §22), attacked at the domain boundary.

Each rule has its own class. The docstring quotes the rule and says what P1a enforces and what
P1b (repositories, database triggers) or P6 (Promotion Controller) adds. These tests are safety
tests: each was shown to fail when its rule is broken (see the P1a report).
"""

from __future__ import annotations

import dataclasses
import unittest
from typing import Any

from core.domain.enums import (
    CandidateSource,
    CandidateStatus,
    InvariantCategory,
    InvariantStatus,
    ProofOrigin,
    VerificationResult,
)
from core.domain.errors import (
    DomainValidationError,
    HashMismatchError,
    IllegalTransitionError,
    StaleParentError,
    UnauthorizedConstructionError,
)
from core.domain.hashing import content_hash
from core.domain.invariant import (
    Invariant,
    InvariantEvaluation,
    InvariantProof,
    InvariantRef,
    InvariantScope,
)
from core.domain.lifecycle import (
    apply_verification_result,
    check_candidate_transition,
    check_invariant_transition,
)
from core.domain.patch import Patch
from core.domain.state import (
    CandidateState,
    TrustedState,
    mark_promoted,
    reject_stale_candidate,
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
    resource,
    uid,
    verified_proof,
)

CS = CandidateStatus
S = InvariantStatus
R = VerificationResult
SAFE = canonical_resources(ssh_open=False, db_path=True)
BROKEN = canonical_resources(ssh_open=False, db_path=False)


def promote_args(candidate: CandidateState, current: TrustedState) -> dict[str, Any]:
    p = proof()
    return {
        "candidate": candidate,
        "current": current,
        "decision_id": uid(4001),
        "invariant_proofs": [p],
        "evidence_refs": list(p.evidence_ids),
        "invariant_registry_version": 1,
        "now": at(10),
    }


def ref_of(state: TrustedState, invariant_id: str) -> InvariantRef:
    return next(r for r in state.invariant_refs if r.invariant_id == invariant_id)


class TestSM001(unittest.TestCase):
    """SM-001: TRUSTED state may advance only through PROMOTE.

    P1a: a TrustedState exists only as a baseline (``establish_baseline``), from ``promote`` on
    a PROMOTABLE candidate of the current state, or rebuilt from verified data (``from_dict``,
    restricted by contract rule R9). No constructor, ``replace`` or setter advances a state.
    P6 adds the PROMOTE decision itself; P1b adds the database triggers (DATA-INT-006).
    """

    def setUp(self) -> None:
        self.v0 = baseline()

    def test_a_trusted_state_cannot_be_constructed_directly(self) -> None:
        kwargs = {f.name: getattr(self.v0, f.name) for f in dataclasses.fields(self.v0)}
        kwargs.update(version=1, parent_state_id=uid(1), commit_decision_id=uid(4001))
        with self.assertRaises(UnauthorizedConstructionError):
            TrustedState(**kwargs)

    def test_replace_cannot_advance_a_state(self) -> None:
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(
                self.v0, version=1, parent_state_id=uid(1), commit_decision_id=uid(2)
            )

    def test_promote_requires_a_promotable_candidate(self) -> None:
        for status_candidate in (
            new_candidate(self.v0),
            ready_candidate(self.v0, SAFE),
            analyzing_candidate(self.v0, SAFE),
        ):
            with (
                self.subTest(status=status_candidate.status.value),
                self.assertRaises(IllegalTransitionError),
            ):
                TrustedState.promote(**promote_args(status_candidate, self.v0))

    def test_the_only_advance_is_by_exactly_one_version_with_lineage(self) -> None:
        candidate = promotable_candidate(self.v0, SAFE)
        v1 = promote(candidate, self.v0)
        self.assertEqual((v1.version, v1.parent_state_id), (self.v0.version + 1, self.v0.state_id))
        v2 = promote(promotable_candidate(v1, SAFE, n=2), v1, decision=2)
        self.assertEqual((v2.version, v2.parent_state_id), (2, v1.state_id))

    def test_a_forged_advance_through_from_dict_is_caught_by_the_hash(self) -> None:
        v1 = promote(promotable_candidate(self.v0, SAFE), self.v0)
        forged = {**v1.to_dict(), "version": 7}
        with self.assertRaises(HashMismatchError):
            TrustedState.from_dict(forged)


class TestConstructionGuardIsolation(unittest.TestCase):
    """The construction guard is the only thing that stops these forgeries.

    Each forged object is otherwise fully valid: the data is rebuilt through ``from_dict`` as a
    control (which accepts it, because every hash and cross-field rule holds), and then the same
    values are offered to the direct constructor or to ``dataclasses.replace``. Only
    ``UnauthorizedConstructionError`` may stop those, never a hash or field check (SM-001, SM-002).
    """

    def forged_trusted_state_data(self) -> dict[str, Any]:
        """A version-5 state with arbitrary parent and decision ids and a correct state_hash,
        computed here from the C-33 payload with the public ``content_hash``."""
        data = baseline().to_dict()
        data.update(version=5, parent_state_id=uid(777), commit_decision_id=uid(778))
        for ref in data["invariant_refs"]:
            ref["origin"] = "VERIFIED"  # C-40: a later state holds no BASELINE reference
        data["state_hash"] = content_hash(
            {
                "lineage_id": data["lineage_id"],
                "version": 5,
                "normalization_version": data["normalization_version"],
                "resources": [
                    {
                        "address": r["address"],
                        "resource_type": r["resource_type"],
                        "fingerprint": r["fingerprint"],
                    }
                    for r in sorted(data["resources"], key=lambda r: r["address"])
                ],
                "invariants": [
                    {
                        "invariant_id": ref["invariant_id"],
                        "invariant_version": ref["invariant_version"],
                        "status": ref["status"],
                    }
                    for ref in sorted(
                        data["invariant_refs"],
                        key=lambda r: (r["invariant_id"], r["invariant_version"]),
                    )
                ],
            }
        )
        return data

    def test_a_valid_forged_trusted_state_is_stopped_only_by_the_guard(self) -> None:
        data = self.forged_trusted_state_data()
        control = TrustedState.from_dict(data)  # every other rule holds for this data
        self.assertEqual((control.version, control.parent_state_id), (5, uid(777)))
        kwargs: dict[str, Any] = {
            "state_id": data["state_id"],
            "lineage_id": data["lineage_id"],
            "version": 5,
            "parent_state_id": uid(777),
            "state_hash": data["state_hash"],
            "resources": control.resources,
            "invariant_refs": control.invariant_refs,
            "evidence_refs": control.evidence_refs,
            "created_at": control.created_at,
            "committed_at": control.committed_at,
            "commit_decision_id": uid(778),
            "normalization_version": data["normalization_version"],
            "invariant_registry_version": data["invariant_registry_version"],
        }
        with self.assertRaises(UnauthorizedConstructionError):
            TrustedState(**kwargs)

    def test_a_consistent_replace_to_promotable_is_stopped_only_by_the_guard(self) -> None:
        analyzing = analyzing_candidate(baseline(), SAFE)
        control = CandidateState.from_dict({**analyzing.to_dict(), "status": "PROMOTABLE"})
        self.assertEqual(control.status, CS.PROMOTABLE)  # the target state is itself consistent
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(analyzing, status=CS.PROMOTABLE)

    def test_a_consistent_replace_of_a_trusted_state_is_stopped_only_by_the_guard(self) -> None:
        data = self.forged_trusted_state_data()
        control = TrustedState.from_dict(data)
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(
                baseline(),
                version=5,
                parent_state_id=uid(777),
                commit_decision_id=uid(778),
                state_hash=control.state_hash,
            )


class TestSM002(unittest.TestCase):
    """SM-002: CANDIDATE cannot directly transition to TRUSTED without Promotion Controller
    authorization.

    P1a: no status change reaches PROMOTED except ``mark_promoted``, which needs a TrustedState
    already built by ``TrustedState.promote``; both are reserved for P6 by contract rule R8.
    P6 adds the authorization itself (the Promotion Controller and its decision).
    """

    def setUp(self) -> None:
        self.v0 = baseline()
        self.promotable = promotable_candidate(self.v0, SAFE)

    def test_the_status_check_refuses_promoted_from_every_status(self) -> None:
        for status in CandidateStatus:
            with self.subTest(status=status.value), self.assertRaises(IllegalTransitionError):
                if status is CS.PROMOTABLE:
                    # Legal in the table, but never through a plain transition function:
                    transition_candidate(self.promotable, CS.PROMOTED)
                else:
                    check_candidate_transition(status, CS.PROMOTED)

    def test_ready_to_promoted_cites_sm_002(self) -> None:
        with self.assertRaises(IllegalTransitionError) as ctx:
            check_candidate_transition(CS.READY, CS.PROMOTED)
        self.assertEqual(ctx.exception.rule, "SM-002")

    def test_replace_cannot_promote_a_candidate(self) -> None:
        for candidate in (self.promotable, ready_candidate(self.v0, SAFE, n=3)):
            with (
                self.subTest(status=candidate.status.value),
                self.assertRaises(UnauthorizedConstructionError),
            ):
                dataclasses.replace(candidate, status=CS.PROMOTED)

    def test_replace_cannot_make_a_candidate_promotable(self) -> None:
        ready = ready_candidate(self.v0, SAFE, n=4)
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(ready, status=CS.PROMOTABLE)

    def test_mark_promoted_needs_a_state_that_really_came_from_this_candidate(self) -> None:
        v1 = promote(self.promotable, self.v0)
        other = promotable_candidate(self.v0, BROKEN, n=2, sequence=2)
        with self.assertRaises(DomainValidationError):
            mark_promoted(other, v1)  # resources differ: DATA-INT-010
        with self.assertRaises(DomainValidationError):
            mark_promoted(self.promotable, self.v0)  # not a successor of the parent
        with self.assertRaises(DomainValidationError):
            mark_promoted(self.promotable, "state")  # type: ignore[arg-type]

    def test_a_non_promotable_candidate_cannot_be_marked_promoted(self) -> None:
        v1 = promote(self.promotable, self.v0)
        for candidate in (
            ready_candidate(self.v0, SAFE, n=5),
            analyzing_candidate(self.v0, SAFE, n=6),
        ):
            with (
                self.subTest(status=candidate.status.value),
                self.assertRaises(IllegalTransitionError),
            ):
                mark_promoted(candidate, v1)


class TestSM003(unittest.TestCase):
    """SM-003: REJECT preserves current Trusted State.

    P1a: rejecting a candidate never touches a TrustedState (the candidate functions do not
    receive one), a REJECTED candidate can never be promoted, and a rejected candidate can never
    be the trusted parent of the next one. P6 adds the decision record; P1b adds the triggers.
    """

    def setUp(self) -> None:
        self.v0 = baseline()
        self.before = self.v0.to_dict()
        self.rejected = transition_candidate(analyzing_candidate(self.v0, BROKEN), CS.REJECTED)

    def test_rejection_leaves_the_trusted_state_equal(self) -> None:
        self.assertEqual(self.rejected.status, CS.REJECTED)
        self.assertEqual(self.v0.to_dict(), self.before)
        for ref in self.v0.invariant_refs:
            self.assertTrue(ref.can_satisfy_proof())

    def test_a_rejected_candidate_cannot_be_promoted(self) -> None:
        with self.assertRaises(IllegalTransitionError) as ctx:
            TrustedState.promote(**promote_args(self.rejected, self.v0))
        self.assertEqual(ctx.exception.rule, "SM-003")
        with self.assertRaises(IllegalTransitionError):
            mark_promoted(self.rejected, promote(promotable_candidate(self.v0, SAFE), self.v0))

    def test_a_rejected_candidate_never_becomes_the_trusted_parent(self) -> None:
        with self.assertRaises(DomainValidationError) as ctx:
            CandidateState.create(
                parent=self.rejected,  # type: ignore[arg-type]
                patch=patch_for(self.v0, n=2),
                candidate_sequence=2,
                now=at(5),
            )
        self.assertIn("DATA-INT-002", str(ctx.exception))

    def test_a_rejected_candidate_has_no_exit(self) -> None:
        for target in CandidateStatus:
            with self.subTest(target=target.value), self.assertRaises(IllegalTransitionError):
                check_candidate_transition(CS.REJECTED, target)


class TestSM004(unittest.TestCase):
    """SM-004: RETRY preserves current Trusted State.

    P1a: RETRY_REQUIRED is terminal for its candidate, never touches a TrustedState, and cannot
    be promoted; the retry is a new candidate (sequence + 1) from the same parent. P6 adds the
    retry budget and decision.
    """

    def test_retry_preserves_the_trusted_state_and_the_next_candidate_starts_from_it(self) -> None:
        v0 = baseline()
        before = v0.to_dict()
        retry = transition_candidate(analyzing_candidate(v0, BROKEN), CS.RETRY_REQUIRED)
        self.assertEqual(v0.to_dict(), before)
        with self.assertRaises(IllegalTransitionError) as ctx:
            TrustedState.promote(**promote_args(retry, v0))
        self.assertEqual(ctx.exception.rule, "SM-004")
        nxt = CandidateState.create(
            parent=v0, patch=patch_for(v0, n=2), candidate_sequence=2, now=at(5)
        )
        self.assertEqual((nxt.parent_state_id, nxt.candidate_sequence), (v0.state_id, 2))
        for target in CandidateStatus:
            with self.subTest(target=target.value), self.assertRaises(IllegalTransitionError):
                check_candidate_transition(CS.RETRY_REQUIRED, target)


class TestSM005(unittest.TestCase):
    """SM-005: ESCALATE preserves current Trusted State.

    P1a: ESCALATED is terminal for its candidate, never touches a TrustedState, and cannot be
    promoted. P6 adds the escalation decision and its handling.
    """

    def test_escalate_preserves_the_trusted_state(self) -> None:
        v0 = baseline()
        before = v0.to_dict()
        escalated = transition_candidate(analyzing_candidate(v0, BROKEN), CS.ESCALATED)
        self.assertEqual(v0.to_dict(), before)
        with self.assertRaises(IllegalTransitionError) as ctx:
            TrustedState.promote(**promote_args(escalated, v0))
        self.assertEqual(ctx.exception.rule, "SM-005")
        for target in CandidateStatus:
            with self.subTest(target=target.value), self.assertRaises(IllegalTransitionError):
                check_candidate_transition(CS.ESCALATED, target)


class TestSM006(unittest.TestCase):
    """SM-006: AFFECTED invariant cannot be treated as PROTECTED for a new state without required
    verification.

    P1a: PROTECTED, VIOLATED and UNCERTAIN are reachable only by applying a verification result
    to a VERIFYING or REVERIFYING evaluation (Doc 06 §12). An AFFECTED, REVERIFYING or
    never-verified evaluation cannot produce a proof, and a reference cannot carry an in-flight
    status. P5 adds the verifiers; P6 adds the policy for when carry-forward is allowed.

    Round 2 (C-40): a proof is created only by ``for_baseline``, ``to_proof`` and ``carry_forward``,
    and ``promote`` accepts only proofs bound to the candidate or carried from the current state,
    covering every invariant on it. Without that, a VIOLATED invariant on v0 could be recorded
    PROTECTED on v1, or dropped from v1, with no evaluation at all (review F10).
    """

    def setUp(self) -> None:
        self.v0 = baseline()
        self.candidate = ready_candidate(self.v0, SAFE)
        self.affected = InvariantEvaluation.affect(
            ref_of(self.v0, SEC), self.candidate, "ssh rule changed"
        )

    def test_affected_cannot_become_protected_by_a_transition_check(self) -> None:
        for target in (S.PROTECTED, S.VIOLATED, S.UNCERTAIN):
            with (
                self.subTest(target=target.value),
                self.assertRaises(IllegalTransitionError) as ctx,
            ):
                check_invariant_transition(S.AFFECTED, target)
            self.assertEqual(ctx.exception.rule, "SM-006")

    def test_a_result_cannot_be_applied_to_an_affected_evaluation(self) -> None:
        for result in VerificationResult:
            with self.subTest(result=result.value), self.assertRaises(IllegalTransitionError):
                self.affected.apply_result(result, [uid(1)], at(20))
            with self.assertRaises(IllegalTransitionError):
                apply_verification_result(S.AFFECTED, result)

    def test_affected_and_reverifying_evaluations_cannot_produce_a_proof(self) -> None:
        for ev in (self.affected, self.affected.start_reverification()):
            with (
                self.subTest(status=ev.status.value),
                self.assertRaises(IllegalTransitionError) as ctx,
            ):
                ev.to_proof()
            self.assertEqual(ctx.exception.rule, "SM-006")

    def test_an_evaluation_that_was_never_verified_cannot_produce_a_proof(self) -> None:
        registered = InvariantEvaluation.register(self.candidate, _extra_invariant(), self.v0)
        for ev in (registered, registered.start_verification()):
            with self.assertRaises(IllegalTransitionError):
                ev.to_proof()

    def test_replace_cannot_turn_an_evaluation_into_protected(self) -> None:
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(self.affected, status=S.PROTECTED)
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(
                self.affected, status=S.PROTECTED, last_result=R.PASS, evidence_ids=(uid(2),)
            )

    def violated_func(self) -> tuple[TrustedState, CandidateState]:
        v0 = baseline(proofs=[proof(SEC, evidence=1), proof(FUNC, S.VIOLATED, evidence=2)])
        return v0, promotable_candidate(v0, SAFE)

    def test_a_violated_invariant_cannot_be_recorded_protected_without_an_evaluation(self) -> None:
        """The review's first forgery: VIOLATED INV-FUNC-001 on v0 became PROTECTED on v1."""
        v0, candidate = self.violated_func()
        sec = verified_proof(v0, candidate, SEC, S.PROTECTED, 11)
        # (a) The proof cannot be built by hand, nor rewritten with replace.
        with self.assertRaises(UnauthorizedConstructionError):
            InvariantProof(  # type: ignore[call-arg]
                invariant_id=FUNC,
                invariant_version=1,
                status=S.PROTECTED,
                evidence_ids=(uid(1012),),
                verified_at=at(10),
                origin=ProofOrigin.VERIFIED,
                candidate_id=candidate.candidate_id,
                source_state_id=None,
            )
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(proof(FUNC, S.VIOLATED, evidence=2), status=S.PROTECTED)
        # (b) A baseline proof is not accepted at promotion.
        with self.assertRaises(DomainValidationError):
            promote(candidate, v0, proofs=[sec, proof(FUNC, S.PROTECTED, evidence=12)])
        # (c) Carrying the reference forward keeps it VIOLATED.
        carried = promote(
            candidate, v0, proofs=[sec, InvariantProof.carry_forward(ref_of(v0, FUNC), candidate)]
        )
        self.assertEqual(ref_of(carried, FUNC).status, S.VIOLATED)
        self.assertFalse(ref_of(carried, FUNC).can_satisfy_proof())

    def test_a_violated_invariant_becomes_protected_only_through_a_passing_reverification(
        self,
    ) -> None:
        v0, candidate = self.violated_func()
        reopened = InvariantEvaluation.reopen(ref_of(v0, FUNC), candidate, "fix attempted")
        self.assertEqual(reopened.status, S.REVERIFYING)
        failed = reopened.apply_result(R.FAIL, [uid(1012)], at(10))
        passed = reopened.apply_result(R.PASS, [uid(1012)], at(10))
        sec = verified_proof(v0, candidate, SEC, S.PROTECTED, 11)
        still = promote(candidate, v0, proofs=[sec, failed.to_proof()])
        self.assertEqual(ref_of(still, FUNC).status, S.VIOLATED)
        fixed = promote(candidate, v0, proofs=[sec, passed.to_proof()], decision=2)
        self.assertEqual(ref_of(fixed, FUNC).status, S.PROTECTED)
        self.assertEqual(ref_of(fixed, FUNC).origin, ProofOrigin.VERIFIED)

    def test_a_violated_invariant_cannot_disappear_at_promotion(self) -> None:
        """The review's second forgery: with another proof list, INV-FUNC-001 vanished from v1."""
        v0, candidate = self.violated_func()
        sec = verified_proof(v0, candidate, SEC, S.PROTECTED, 11)
        with self.assertRaises(DomainValidationError) as ctx:
            promote(candidate, v0, proofs=[sec])
        self.assertIn(FUNC, str(ctx.exception))
        self.assertIn("C-40", str(ctx.exception))

    def test_a_proof_verified_for_another_candidate_cannot_promote_this_one(self) -> None:
        v0, candidate = self.violated_func()
        other = promotable_candidate(v0, SAFE, n=2, sequence=2)
        foreign = [
            verified_proof(v0, other, SEC, S.PROTECTED, 11),
            verified_proof(v0, other, FUNC, S.PROTECTED, 12),
        ]
        with self.assertRaises(DomainValidationError) as ctx:
            promote(candidate, v0, proofs=foreign)
        self.assertIn("C-40", str(ctx.exception))

    def test_a_proof_or_reference_cannot_carry_an_in_flight_status(self) -> None:
        for status in (S.AFFECTED, S.REVERIFYING, S.VERIFYING, S.REGISTERED):
            with self.subTest(status=status.value), self.assertRaises(DomainValidationError):
                InvariantProof.for_baseline(
                    invariant_id=SEC,
                    invariant_version=1,
                    status=status,
                    evidence_ids=(uid(1),),
                    verified_at=at(1),
                )
            data = ref_of(self.v0, SEC).to_dict()
            with self.assertRaises(DomainValidationError):
                InvariantRef.from_dict({**data, "status": status.value})

    def test_the_parent_reference_stays_protected_while_a_candidate_is_affected(self) -> None:
        self.assertEqual(ref_of(self.v0, SEC).status, S.PROTECTED)
        self.assertEqual(self.affected.status, S.AFFECTED)


def _extra_invariant() -> Invariant:
    return Invariant(
        invariant_id="INV-FUNC-002",
        version=1,
        name="n",
        category=InvariantCategory.FUNCTIONAL,
        description="d",
        predicate={"op": "x"},
        scope=InvariantScope(("a.x",), (), (), (), 0),
        verifier_id="v",
        verifier_version="1",
        created_at=at(0),
    )


class _UnprovenResult:
    """Shared checks for SM-007 and SM-008."""

    result: VerificationResult

    def setUp(self) -> None:  # type: ignore[misc]
        self.v0 = baseline()
        self.candidate = promotable_candidate(self.v0, SAFE)
        affected = InvariantEvaluation.affect(ref_of(self.v0, SEC), self.candidate, "changed")
        self.evaluation = affected.start_reverification().apply_result(
            self.result, [uid(9300)], at(20)
        )


class TestSM007(_UnprovenResult, unittest.TestCase):
    """SM-007: UNKNOWN cannot transition to PROTECTED when proof is required.

    P1a: UNKNOWN maps to UNCERTAIN (C-30), UNCERTAIN has no plain path to PROTECTED, the
    evaluation keeps ``last_result`` UNKNOWN, and a reference built from it can never satisfy
    proof. P6 adds the policy that decides when proof is required.
    """

    result = R.UNKNOWN

    def test_unknown_leads_to_uncertain_and_never_to_protected(self) -> None:
        self.assertEqual(self.evaluation.status, S.UNCERTAIN)
        self.assertEqual(self.evaluation.last_result, R.UNKNOWN)
        self.assertFalse(R.UNKNOWN.is_pass)
        for current in InvariantStatus:
            if current in (S.VERIFYING, S.REVERIFYING):
                self.assertNotEqual(apply_verification_result(current, R.UNKNOWN), S.PROTECTED)

    def test_uncertain_cannot_become_protected_without_reverification(self) -> None:
        with self.assertRaises(IllegalTransitionError):
            check_invariant_transition(S.UNCERTAIN, S.PROTECTED)
        with self.assertRaises(IllegalTransitionError):
            self.evaluation.apply_result(R.PASS, [uid(9301)], at(21))
        with self.assertRaises(IllegalTransitionError):
            self.evaluation.start_verification()

    def test_the_reference_built_from_it_cannot_satisfy_proof(self) -> None:
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[
                self.evaluation.to_proof(),
                verified_proof(self.v0, self.candidate, FUNC, S.PROTECTED, 12),
            ],
        )
        self.assertEqual(ref_of(v1, SEC).status, S.UNCERTAIN)
        self.assertFalse(ref_of(v1, SEC).can_satisfy_proof())


class TestSM008(_UnprovenResult, unittest.TestCase):
    """SM-008: UNSUPPORTED cannot transition to PROTECTED when proof is required.

    P1a: as SM-007 for UNSUPPORTED, and VERIFIER_ERROR (Doc 09 §4, §37) is held to the same
    rule. P5 adds the real verifiers and their coverage declarations.
    """

    result = R.UNSUPPORTED

    def test_unsupported_leads_to_uncertain_and_never_to_protected(self) -> None:
        self.assertEqual(self.evaluation.status, S.UNCERTAIN)
        self.assertEqual(self.evaluation.last_result, R.UNSUPPORTED)
        self.assertFalse(R.UNSUPPORTED.is_pass)
        for current in (S.VERIFYING, S.REVERIFYING):
            self.assertNotEqual(apply_verification_result(current, R.UNSUPPORTED), S.PROTECTED)

    def test_the_reference_built_from_it_cannot_satisfy_proof(self) -> None:
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[
                self.evaluation.to_proof(),
                verified_proof(self.v0, self.candidate, FUNC, S.PROTECTED, 12),
            ],
        )
        self.assertFalse(ref_of(v1, SEC).can_satisfy_proof())

    def test_verifier_error_is_neither_pass_nor_fail(self) -> None:
        affected = InvariantEvaluation.affect(ref_of(self.v0, SEC), self.candidate, "changed")
        errored = affected.start_reverification().apply_result(
            R.VERIFIER_ERROR, [uid(9302)], at(20)
        )
        self.assertEqual((errored.status, errored.last_result), (S.UNCERTAIN, R.VERIFIER_ERROR))
        self.assertFalse(R.VERIFIER_ERROR.is_pass)
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[
                errored.to_proof(),
                verified_proof(self.v0, self.candidate, FUNC, S.PROTECTED, 12),
            ],
        )
        self.assertFalse(ref_of(v1, SEC).can_satisfy_proof())

    def test_unsupported_and_unknown_stay_distinguishable(self) -> None:
        affected = InvariantEvaluation.affect(ref_of(self.v0, SEC), self.candidate, "changed")
        unknown = affected.start_reverification().apply_result(R.UNKNOWN, [uid(9303)], at(20))
        self.assertNotEqual(unknown.last_result, self.evaluation.last_result)


class TestSM009(unittest.TestCase):
    """SM-009: Historical state records are immutable.

    P1a: every entity is a frozen dataclass with deeply immutable JSON, built from copies of its
    inputs; semantic content cannot change without a matching hash. P1b adds the database
    triggers (DATA-INT-006) that make stored rows immutable.
    """

    def setUp(self) -> None:
        self.v0 = baseline()
        self.candidate = ready_candidate(self.v0, SAFE)
        self.patch = patch_for(self.v0)
        self.res = resource("aws_instance.app")
        self.entities: list[Any] = [
            self.v0,
            self.candidate,
            self.v0.invariant_refs[0],
            self.res,
            self.patch,
            InvariantEvaluation.affect(ref_of(self.v0, SEC), self.candidate, "changed"),
        ]

    def test_setting_any_attribute_of_any_entity_raises(self) -> None:
        for entity in self.entities:
            for field in dataclasses.fields(entity):
                with (
                    self.subTest(entity=type(entity).__name__, field=field.name),
                    self.assertRaises(dataclasses.FrozenInstanceError),
                ):
                    setattr(entity, field.name, None)

    def test_deleting_an_attribute_raises(self) -> None:
        for entity in self.entities:
            with (
                self.subTest(entity=type(entity).__name__),
                self.assertRaises(dataclasses.FrozenInstanceError),
            ):
                delattr(entity, dataclasses.fields(entity)[0].name)

    def test_nested_json_cannot_be_mutated(self) -> None:
        with self.assertRaises(TypeError):
            self.res.attributes["size"] = "huge"  # type: ignore[index]
        with self.assertRaises(TypeError):
            self.res.security_attributes["new"] = 1  # type: ignore[index]
        patch = Patch.create(
            source=CandidateSource.FIXED_PATCH,
            content="x",
            parent_state_id=self.v0.state_id,
            now=at(0),
            metadata={"a": {"b": 1}},
        )
        with self.assertRaises(TypeError):
            patch.metadata["a"]["b"] = 2  # type: ignore[index]
        self.assertIsInstance(self.v0.resources, tuple)

    def test_mutating_the_inputs_afterwards_changes_nothing(self) -> None:
        attributes: dict[str, Any] = {"size": "small", "tags": {"a": "1"}}
        res = resource("aws_instance.app", attributes=attributes)
        state = baseline(resources=[res])
        before_state, before_hash = state.to_dict(), state.state_hash
        attributes["tags"]["a"] = "evil"
        attributes["size"] = "huge"
        self.assertEqual(state.to_dict(), before_state)
        self.assertEqual(state.state_hash, before_hash)
        resources = [resource("aws_instance.a")]
        ready = ready_candidate(self.v0, resources)
        resources.append(resource("aws_instance.b"))
        self.assertEqual([r.address for r in ready.resources], ["aws_instance.a"])

    def test_semantic_content_cannot_change_without_a_matching_hash(self) -> None:
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(self.res, attributes={"size": "huge"})
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(self.patch, content='resource "y" "p" {}\n')
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(self.v0, resources=())
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(self.candidate, resources=())

    def test_a_tampered_state_is_caught_when_rebuilt(self) -> None:
        data = self.v0.to_dict()
        data["resources"][0]["attributes"]["size"] = "tampered"
        with self.assertRaises(HashMismatchError):
            TrustedState.from_dict(data)
        cand = self.candidate.to_dict()
        cand["resources"][0]["attributes"]["size"] = "tampered"
        with self.assertRaises(HashMismatchError):
            CandidateState.from_dict(cand)

    def test_promotion_does_not_modify_the_previous_state(self) -> None:
        before = self.v0.to_dict()
        promote(promotable_candidate(self.v0, SAFE, n=7), self.v0)
        self.assertEqual(self.v0.to_dict(), before)


class TestSM010(unittest.TestCase):
    """SM-010: Stale-parent candidates cannot promote.

    P1a: ``TrustedState.promote`` raises ``StaleParentError`` when the candidate's parent is not
    the ``current`` state it is given, and ``reject_stale_candidate`` records STALE_PARENT.
    P1b/P6 add the check against the database's current pointer, made atomic with the commit
    (P1a risk R3).
    """

    def setUp(self) -> None:
        self.v0 = baseline()
        self.first = promotable_candidate(self.v0, SAFE, n=1)
        self.second = promotable_candidate(self.v0, BROKEN, n=2, sequence=2)
        self.v1 = promote(self.first, self.v0, decision=1)

    def test_a_stale_candidate_cannot_promote(self) -> None:
        with self.assertRaises(StaleParentError) as ctx:
            promote(self.second, self.v1, decision=2)
        self.assertEqual(ctx.exception.rule, "SM-010")
        self.assertIn("SM-010", str(ctx.exception))

    def test_p1a_trusts_the_current_state_it_is_given(self) -> None:
        """Limitation (P1a risk R3): the check against the database's current pointer, made atomic
        with the commit, is P1b/P6. Here the caller supplies ``current``."""
        again = promote(self.second, self.v0, decision=2)
        self.assertEqual(again.parent_state_id, self.v0.state_id)
        self.assertNotEqual(again.state_id, self.v1.state_id)

    def test_the_stale_candidate_is_rejected_with_a_reason(self) -> None:
        rejected = reject_stale_candidate(self.second, self.v1)
        self.assertEqual((rejected.status, rejected.status_reason), (CS.REJECTED, "STALE_PARENT"))

    def test_a_candidate_whose_parent_is_current_is_not_stale(self) -> None:
        with self.assertRaises(IllegalTransitionError):
            reject_stale_candidate(promotable_candidate(self.v1, SAFE, n=3), self.v1)

    def test_other_lineages_are_not_comparable(self) -> None:
        other = baseline(lineage_id=uid(0xDD), state_id=uid(55))
        with self.assertRaises(DomainValidationError):
            reject_stale_candidate(self.second, other)
        with self.assertRaises(DomainValidationError):
            promote(self.second, other)

    def test_staleness_never_changes_the_current_state(self) -> None:
        before = self.v1.to_dict()
        with self.assertRaises(StaleParentError):
            promote(self.second, self.v1, decision=2)
        reject_stale_candidate(self.second, self.v1)
        self.assertEqual(self.v1.to_dict(), before)


class TestConstructionGuardSurface(unittest.TestCase):
    """Doc 06 §30: no persistence-layer convenience (replace, direct construction) bypasses the
    lifecycle."""

    def test_a_direct_ref_cannot_be_built(self) -> None:
        with self.assertRaises(UnauthorizedConstructionError):
            InvariantRef(  # type: ignore[call-arg]
                invariant_id=SEC,
                invariant_version=1,
                state_id=uid(1),
                status=S.PROTECTED,
                evidence_ids=(uid(2),),
                last_verified_at=at(0),
                invalidated_by_candidate_id=None,
                invalidation_reason=None,
                origin=ProofOrigin.BASELINE,
            )


if __name__ == "__main__":
    unittest.main()
