"""InvariantEvaluation: candidate-scoped invariant status (Doc 06 §8, §9, §12, §29; C-23, C-30,
C-31; P1a step 11, tested with the state module from step 12)."""

from __future__ import annotations

import dataclasses
import json
import unittest
from typing import Any

from core.domain.enums import InvariantStatus, VerificationResult
from core.domain.errors import (
    DomainValidationError,
    IllegalTransitionError,
    UnauthorizedConstructionError,
)
from core.domain.invariant import InvariantEvaluation, InvariantRef
from core.domain.state import TrustedState, finish_building, start_building
from tests.domain_builders import (
    FUNC,
    SEC,
    at,
    baseline,
    canonical_resources,
    invariant,
    new_candidate,
    proof,
    uid,
)

S = InvariantStatus
R = VerificationResult
EVIDENCE = (uid(7001),)

SEC2 = "INV-SEC-002"
FUNC2 = "INV-FUNC-002"


def base_with_every_status() -> TrustedState:
    """SEC PROTECTED, FUNC VIOLATED, SEC2 UNCERTAIN on the parent state."""
    return baseline(
        proofs=[
            proof(SEC, S.PROTECTED, evidence=1),
            proof(FUNC, S.VIOLATED, evidence=2),
            proof(SEC2, S.UNCERTAIN, evidence=3),
        ]
    )


def ref_for(state: TrustedState, invariant_id: str) -> InvariantRef:
    return next(r for r in state.invariant_refs if r.invariant_id == invariant_id)


class EvaluationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.base = base_with_every_status()
        self.candidate = new_candidate(self.base)
        self.protected = ref_for(self.base, SEC)
        self.violated = ref_for(self.base, FUNC)
        self.uncertain = ref_for(self.base, SEC2)

    def affected(self) -> InvariantEvaluation:
        return InvariantEvaluation.affect(self.protected, self.candidate, "ingress rule changed")

    def reverifying(self) -> InvariantEvaluation:
        return self.affected().start_reverification()

    def verifying(self) -> InvariantEvaluation:
        return InvariantEvaluation.register(
            self.candidate, invariant(FUNC2), self.base
        ).start_verification()


class TestAffect(EvaluationTestCase):
    def test_a_protected_reference_becomes_affected_for_the_candidate(self) -> None:
        ev = self.affected()
        self.assertEqual(ev.status, S.AFFECTED)
        self.assertEqual(ev.candidate_id, self.candidate.candidate_id)
        self.assertEqual(ev.parent_state_id, self.base.state_id)
        self.assertEqual((ev.invariant_id, ev.invariant_version), (SEC, 1))
        self.assertIsNone(ev.last_result)
        self.assertIsNone(ev.verified_at)
        self.assertEqual(ev.evidence_ids, ())
        self.assertEqual(ev.reason, "ingress rule changed")

    def test_the_parent_reference_and_state_are_untouched(self) -> None:
        """C-23: AFFECTED is candidate-scoped; the trusted state's references never change."""
        ref_before, state_before = self.protected.to_dict(), self.base.to_dict()
        self.affected()
        self.assertEqual(self.protected.to_dict(), ref_before)
        self.assertEqual(self.base.to_dict(), state_before)
        self.assertEqual(self.protected.status, S.PROTECTED)
        self.assertTrue(self.protected.can_satisfy_proof())

    def test_a_reason_is_required(self) -> None:
        """Doc 06 §29: every status transition has a reason."""
        for bad in ("", "  ", None):
            with self.subTest(reason=bad), self.assertRaises(DomainValidationError):
                InvariantEvaluation.affect(self.protected, self.candidate, bad)  # type: ignore[arg-type]

    def test_only_a_protected_reference_can_be_affected(self) -> None:
        for ref in (self.violated, self.uncertain):
            with self.subTest(status=ref.status.value), self.assertRaises(IllegalTransitionError):
                InvariantEvaluation.affect(ref, self.candidate, "why")

    def test_the_reference_must_belong_to_the_candidates_parent(self) -> None:
        other_base = baseline(proofs=[proof(SEC, S.PROTECTED, evidence=9)], state_id=uid(88))
        other_ref = ref_for(other_base, SEC)
        with self.assertRaises(DomainValidationError) as ctx:
            InvariantEvaluation.affect(other_ref, self.candidate, "why")
        self.assertIn("DATA-INT-009", str(ctx.exception))

    def test_argument_types_are_checked(self) -> None:
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.affect(self.protected.to_dict(), self.candidate, "why")  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.affect(self.protected, self.candidate.to_dict(), "why")


class TestReopen(EvaluationTestCase):
    def test_violated_and_uncertain_references_reopen_as_reverifying(self) -> None:
        for ref in (self.violated, self.uncertain):
            with self.subTest(status=ref.status.value):
                ev = InvariantEvaluation.reopen(ref, self.candidate, "new candidate evaluated")
                self.assertEqual(ev.status, S.REVERIFYING)
                self.assertEqual(ev.invariant_id, ref.invariant_id)
                self.assertIsNone(ev.last_result)

    def test_a_protected_reference_cannot_be_reopened(self) -> None:
        with self.assertRaises(IllegalTransitionError):
            InvariantEvaluation.reopen(self.protected, self.candidate, "why")

    def test_reason_and_parent_checks_apply(self) -> None:
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.reopen(self.violated, self.candidate, "")
        other = baseline(proofs=[proof(FUNC, S.VIOLATED, evidence=9)], state_id=uid(89))
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.reopen(ref_for(other, FUNC), self.candidate, "why")

    def test_the_parent_reference_is_untouched(self) -> None:
        before = self.violated.to_dict()
        InvariantEvaluation.reopen(self.violated, self.candidate, "why")
        self.assertEqual(self.violated.to_dict(), before)


class TestRegisterChecksTheParent(EvaluationTestCase):
    """L1 (P1a review, C-31): ``register`` is only for an invariant the candidate's parent does not
    hold. An invariant the parent holds goes through ``affect`` or ``reopen``."""

    def test_an_invariant_the_parent_already_holds_is_refused(self) -> None:
        for invariant_id in (SEC, FUNC, SEC2):  # PROTECTED, VIOLATED, UNCERTAIN on the parent
            with self.subTest(invariant_id=invariant_id):
                with self.assertRaises(DomainValidationError) as ctx:
                    InvariantEvaluation.register(self.candidate, invariant(invariant_id), self.base)
                message = str(ctx.exception)
                self.assertIn("L1", message)
                self.assertIn("C-31", message)
                self.assertIn(invariant_id, message)

    def test_a_parent_that_is_not_the_candidates_parent_is_refused(self) -> None:
        other = baseline(state_id=uid(77), proofs=[proof(SEC, S.PROTECTED, evidence=4)])
        with self.assertRaises(DomainValidationError) as ctx:
            InvariantEvaluation.register(self.candidate, invariant(FUNC2), other)
        self.assertIn("L1", str(ctx.exception))
        self.assertIn("parent", str(ctx.exception))

    def test_the_parents_identity_is_checked_even_when_it_lacks_the_invariant(
        self,
    ) -> None:
        # ``other`` lacks FUNC, so only the parent-identity check can refuse this.
        other = baseline(state_id=uid(78), proofs=[proof(SEC, S.PROTECTED, evidence=4)])
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.register(self.candidate, invariant(FUNC), other)

    def test_the_parent_must_be_a_trusted_state(self) -> None:
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.register(
                self.candidate, invariant(FUNC2), self.base.to_dict()  # type: ignore[arg-type]
            )
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.register(self.candidate, invariant(FUNC2), self.candidate)

    def test_a_genuinely_new_invariant_is_registered(self) -> None:
        self.assertNotIn(FUNC2, {ref.invariant_id for ref in self.base.invariant_refs})
        ev = InvariantEvaluation.register(self.candidate, invariant(FUNC2), self.base)
        self.assertEqual(ev.status, S.REGISTERED)
        self.assertEqual(ev.parent_state_id, self.base.state_id)
        self.assertEqual(ev.candidate_id, self.candidate.candidate_id)

    def test_a_refused_register_leaves_the_parent_untouched(self) -> None:
        before = self.base.to_dict()
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.register(self.candidate, invariant(SEC), self.base)
        self.assertEqual(self.base.to_dict(), before)


class TestRegisterAndVerify(EvaluationTestCase):
    def test_register_gives_a_registered_evaluation(self) -> None:
        ev = InvariantEvaluation.register(self.candidate, invariant(FUNC2), self.base)
        self.assertEqual(ev.status, S.REGISTERED)
        self.assertEqual((ev.invariant_id, ev.invariant_version), (FUNC2, 1))
        self.assertEqual(ev.parent_state_id, self.base.state_id)

    def test_register_checks_its_arguments(self) -> None:
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.register(self.candidate.to_dict(), invariant(), self.base)
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.register(self.candidate, {"invariant_id": SEC}, self.base)  # type: ignore[arg-type]

    def test_start_verification_only_from_registered(self) -> None:
        registered = InvariantEvaluation.register(self.candidate, invariant(FUNC2), self.base)
        self.assertEqual(registered.start_verification().status, S.VERIFYING)
        self.assertEqual(registered.status, S.REGISTERED)
        for ev in (self.affected(), self.reverifying(), self.verifying()):
            with self.subTest(status=ev.status.value), self.assertRaises(IllegalTransitionError):
                ev.start_verification()

    def test_start_reverification_only_from_affected(self) -> None:
        self.assertEqual(self.reverifying().status, S.REVERIFYING)
        registered = InvariantEvaluation.register(self.candidate, invariant(FUNC2), self.base)
        for ev in (registered, self.verifying(), self.reverifying()):
            with self.subTest(status=ev.status.value), self.assertRaises(IllegalTransitionError):
                ev.start_reverification()
        done = self.reverifying().apply_result(R.PASS, EVIDENCE, at(20))
        for status_holder in (done,):
            with self.assertRaises(IllegalTransitionError):
                status_holder.start_reverification()


class TestApplyResult(EvaluationTestCase):
    def test_every_result_maps_to_its_status_and_is_kept(self) -> None:
        expected = {
            R.PASS: S.PROTECTED,
            R.FAIL: S.VIOLATED,
            R.UNKNOWN: S.UNCERTAIN,
            R.UNSUPPORTED: S.UNCERTAIN,
            R.VERIFIER_ERROR: S.UNCERTAIN,
        }
        for make in (self.verifying, self.reverifying):
            for result, status in expected.items():
                with self.subTest(start=make.__name__, result=result.value):
                    ev = make().apply_result(result, EVIDENCE, at(20))
                    self.assertEqual(ev.status, status)
                    self.assertEqual(ev.last_result, result)
                    self.assertEqual(ev.evidence_ids, EVIDENCE)
                    self.assertEqual(ev.verified_at, at(20))

    def test_unknown_unsupported_and_error_stay_distinguishable(self) -> None:
        outcomes = {
            r: self.reverifying().apply_result(r, EVIDENCE, at(20)).last_result
            for r in (R.UNKNOWN, R.UNSUPPORTED, R.VERIFIER_ERROR)
        }
        self.assertEqual(len(set(outcomes.values())), 3)

    def test_evidence_is_required_for_every_result(self) -> None:
        """Doc 06 §29, Doc 09 §37: even VERIFIER_ERROR needs evidence."""
        for result in VerificationResult:
            for bad in ((), [], None):
                with (
                    self.subTest(result=result.value, evidence=bad),
                    self.assertRaises(DomainValidationError),
                ):
                    self.reverifying().apply_result(result, bad, at(20))  # type: ignore[arg-type]

    def test_a_result_applies_only_while_verifying(self) -> None:
        registered = InvariantEvaluation.register(self.candidate, invariant(FUNC2), self.base)
        done = self.reverifying().apply_result(R.PASS, EVIDENCE, at(20))
        for ev in (registered, self.affected(), done):
            for result in VerificationResult:
                with (
                    self.subTest(status=ev.status.value, result=result.value),
                    self.assertRaises(IllegalTransitionError),
                ):
                    ev.apply_result(result, EVIDENCE, at(20))

    def test_a_non_result_is_rejected(self) -> None:
        for bad in ("PASS", None, S.PROTECTED):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                self.reverifying().apply_result(bad, EVIDENCE, at(20))  # type: ignore[arg-type]

    def test_verification_time_must_be_aware_utc(self) -> None:
        from datetime import datetime

        with self.assertRaises(DomainValidationError):
            self.reverifying().apply_result(R.PASS, EVIDENCE, datetime(2026, 10, 1))

    def test_methods_return_new_objects_and_leave_the_input_alone(self) -> None:
        start = self.reverifying()
        before = start.to_dict()
        result = start.apply_result(R.PASS, EVIDENCE, at(20))
        self.assertIsNot(result, start)
        self.assertEqual(start.to_dict(), before)


class TestToProof(EvaluationTestCase):
    def test_a_verified_evaluation_gives_a_matching_proof(self) -> None:
        for result, status in (
            (R.PASS, S.PROTECTED),
            (R.FAIL, S.VIOLATED),
            (R.UNKNOWN, S.UNCERTAIN),
        ):
            with self.subTest(result=result.value):
                ev = self.reverifying().apply_result(result, EVIDENCE, at(20))
                p = ev.to_proof()
                self.assertEqual(p.status, status)
                self.assertEqual((p.invariant_id, p.invariant_version), (SEC, 1))
                self.assertEqual(p.evidence_ids, EVIDENCE)
                self.assertEqual(p.verified_at, at(20))

    def test_an_evaluation_never_given_a_result_cannot_produce_a_proof(self) -> None:
        """SM-006: refused because no verification result was ever applied, and it says so."""
        registered = InvariantEvaluation.register(self.candidate, invariant(FUNC2), self.base)
        for ev in (registered, self.verifying(), self.affected(), self.reverifying()):
            with self.subTest(status=ev.status.value):
                self.assertIsNone(ev.last_result)
                with self.assertRaises(IllegalTransitionError) as ctx:
                    ev.to_proof()
                self.assertEqual(ctx.exception.rule, "SM-006")
                self.assertIn("never given a verification result", str(ctx.exception))

    def test_an_unverified_evaluation_cannot_produce_a_proof(self) -> None:
        registered = InvariantEvaluation.register(self.candidate, invariant(FUNC2), self.base)
        for ev in (registered, self.verifying(), self.affected(), self.reverifying()):
            with (
                self.subTest(status=ev.status.value),
                self.assertRaises(IllegalTransitionError) as ctx,
            ):
                ev.to_proof()
            self.assertEqual(ctx.exception.rule, "SM-006")


class TestConstructionGuard(EvaluationTestCase):
    def test_direct_construction_is_refused(self) -> None:
        ev = self.reverifying()
        kwargs = {f.name: getattr(ev, f.name) for f in dataclasses.fields(ev)}
        with self.assertRaises(UnauthorizedConstructionError):
            InvariantEvaluation(**kwargs)

    def test_replace_cannot_change_a_status(self) -> None:
        for ev in (self.affected(), self.reverifying()):
            for target in (S.PROTECTED, S.VIOLATED, S.UNCERTAIN, S.REVERIFYING):
                with (
                    self.subTest(status=ev.status.value, target=target.value),
                    self.assertRaises(UnauthorizedConstructionError),
                ):
                    dataclasses.replace(ev, status=target)

    def test_evaluations_are_frozen(self) -> None:
        ev = self.affected()
        for field in ("status", "last_result", "evidence_ids", "reason", "candidate_id"):
            with self.subTest(field=field), self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(ev, field, None)


class TestEvaluationSerialization(EvaluationTestCase):
    def test_round_trip_in_every_state(self) -> None:
        verified = [
            self.reverifying().apply_result(r, EVIDENCE, at(20)) for r in VerificationResult
        ]
        pending = [
            self.affected(),
            self.reverifying(),
            self.verifying(),
            InvariantEvaluation.register(self.candidate, invariant(FUNC2), self.base),
        ]
        for ev in (*pending, *verified):
            with self.subTest(status=ev.status.value, result=ev.last_result):
                data = ev.to_dict()
                json.dumps(data)
                self.assertEqual(InvariantEvaluation.from_dict(data), ev)

    def rejected(self, data: dict[str, Any], fragment: str) -> None:
        with self.assertRaises(DomainValidationError) as ctx:
            InvariantEvaluation.from_dict(data)
        self.assertIn(fragment, str(ctx.exception))

    def test_from_dict_rejects_inconsistent_status_result_and_evidence(self) -> None:
        verified = self.reverifying().apply_result(R.PASS, EVIDENCE, at(20)).to_dict()
        self.rejected({**verified, "last_result": None}, "last_result")
        self.rejected({**verified, "last_result": "FAIL"}, "C-30")
        self.rejected({**verified, "last_result": "UNKNOWN"}, "C-30")
        self.rejected({**verified, "evidence_ids": []}, "evidence")
        self.rejected({**verified, "verified_at": None}, "verification")
        pending = self.affected().to_dict()
        self.rejected({**pending, "status": "PROTECTED"}, "last_result")
        self.rejected({**pending, "evidence_ids": [EVIDENCE[0]]}, "no result")
        self.rejected({**pending, "last_result": "PASS"}, "no result")
        self.rejected({**pending, "reason": ""}, "reason")

    def test_from_dict_validates_fields_and_keys(self) -> None:
        data = self.affected().to_dict()
        for key, bad in (
            ("candidate_id", "c"),
            ("parent_state_id", "p"),
            ("invariant_id", "x"),
            ("status", "DONE"),
            ("last_result", "MAYBE"),
        ):
            with self.subTest(key=key), self.assertRaises(DomainValidationError):
                InvariantEvaluation.from_dict({**data, key: bad})
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.from_dict({k: v for k, v in data.items() if k != "reason"})
        with self.assertRaises(DomainValidationError):
            InvariantEvaluation.from_dict({**data, "extra": 1})


class TestEvaluationsDoNotTouchTheParent(EvaluationTestCase):
    def test_a_full_flow_leaves_every_parent_object_equal(self) -> None:
        state_before = self.base.to_dict()
        refs_before = [r.to_dict() for r in self.base.invariant_refs]
        ready = finish_building(
            start_building(self.candidate), canonical_resources(ssh_open=False, db_path=True)
        )
        _ = ready
        flow = self.affected().start_reverification().apply_result(R.PASS, EVIDENCE, at(30))
        reopened = InvariantEvaluation.reopen(self.violated, self.candidate, "again").apply_result(
            R.FAIL, EVIDENCE, at(31)
        )
        _ = (flow, reopened)
        self.assertEqual(self.base.to_dict(), state_before)
        self.assertEqual([r.to_dict() for r in self.base.invariant_refs], refs_before)


if __name__ == "__main__":
    unittest.main()
