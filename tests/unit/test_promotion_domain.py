"""The promotion types (P6a step 2; Doc 05 §15, Doc 11 §26; C-157 to C-161).

Expected values come from the spec text: a PROMOTE "must reference the evidence that satisfied the
promotion policy"; "non-promotion decisions must preserve their blocking reasons for audit"
(Doc 05 §15); ``committed_state_id`` is null until the commit of P6b (DATA-INT-004); the five
decision reasons of C-157 are a closed vocabulary; ``PromotionEvidence`` has the fields of Doc 11
§26 and a PROMOTE "must reference every mandatory verification result used".
"""

from __future__ import annotations

import dataclasses
import unittest
from typing import Any

from core.domain.enums import DecisionType, VerificationResult
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.promotion import (
    BlockingCondition,
    DecisionReason,
    OracleVerdict,
    PromotionDecision,
    PromotionEvidence,
    PromotionInputError,
    ProofSource,
    RequiredCheck,
)
from tests.domain_builders import at, uid

CANDIDATE = uid(3001)
PARENT = uid(1)
RESULT_A, RESULT_B = uid(7001), uid(7002)


def checks() -> tuple[RequiredCheck, ...]:
    return (
        RequiredCheck("CONSISTENCY", "GATE", ProofSource.VERIFIED, RESULT_A),
        RequiredCheck("INVARIANT:INV-SEC-001:1", "INVARIANT", ProofSource.VERIFIED, RESULT_B),
    )


def blocking(code: DecisionReason = DecisionReason.REQUIRED_CHECK_FAILED) -> BlockingCondition:
    return BlockingCondition(code, DecisionType.REJECT, "INVARIANT:INV-SEC-001:1", "result FAIL")


def decision(**changes: Any) -> PromotionDecision:
    fields: dict[str, Any] = {
        "decision_id": uid(9001),
        "candidate_id": CANDIDATE,
        "parent_state_id": PARENT,
        "decision": DecisionType.PROMOTE,
        "reason": DecisionReason.ALL_REQUIRED_PROVEN,
        "policy_version": "policy-1",
        "attempt_number": 1,
        "required_checks": checks(),
        "blocking_conditions": (),
        "supporting_results": (RESULT_A, RESULT_B),
        "created_at": at(5),
    }
    fields.update(changes)
    return PromotionDecision.create(**fields)


def rejection(**changes: Any) -> PromotionDecision:
    fields: dict[str, Any] = {
        "decision": DecisionType.REJECT,
        "reason": DecisionReason.REQUIRED_CHECK_FAILED,
        "blocking_conditions": (blocking(),),
        "supporting_results": (RESULT_A,),
    }
    fields.update(changes)
    return decision(**fields)


class TestVocabularies(unittest.TestCase):
    def test_the_reasons_are_the_closed_list_of_c157(self) -> None:
        self.assertEqual(
            {reason.value for reason in DecisionReason},
            {
                "STALE_PARENT",
                "STRUCTURAL_FAILURE",
                "INCONSISTENT_REPORTS",
                "REQUIRED_CHECK_FAILED",
                "REQUIRED_UNKNOWN",
                "REQUIRED_UNSUPPORTED",
                "VERIFIER_ERROR",
                "INSUFFICIENT_EVIDENCE",
                "EVIDENCE_NOT_SUFFICIENT",
                "EVIDENCE_STALE",
                "EVIDENCE_CONFLICT",
                "RETRY_BUDGET_EXHAUSTED",
                "POLICY_REGISTRY_REGRESSION",
                "AUTOMATIC_PROMOTION_DISABLED",
                "DECISION_INCOMPLETE",
                "ALL_REQUIRED_PROVEN",
            },
        )

    def test_a_proof_comes_from_verification_or_from_carrying_forward(self) -> None:
        self.assertEqual({s.value for s in ProofSource}, {"VERIFIED", "CARRIED_FORWARD"})

    def test_an_input_error_is_a_domain_validation_error(self) -> None:
        self.assertTrue(issubclass(PromotionInputError, DomainValidationError))


class TestRequiredCheckAndBlockingCondition(unittest.TestCase):
    def test_a_verified_check_names_its_result_and_a_carried_one_names_none(self) -> None:
        RequiredCheck("INVARIANT:INV-SEC-002:1", "INVARIANT", ProofSource.VERIFIED, RESULT_A)
        RequiredCheck("INVARIANT:INV-SEC-002:1", "INVARIANT", ProofSource.CARRIED_FORWARD, None)
        RequiredCheck("INVARIANT:INV-SEC-002:1", "INVARIANT", None, None)
        for source, result in (
            (ProofSource.VERIFIED, None),
            (ProofSource.CARRIED_FORWARD, RESULT_A),
            (None, RESULT_A),
        ):
            with (
                self.subTest(source=source, result=result),
                self.assertRaises(DomainValidationError),
            ):
                RequiredCheck("INVARIANT:INV-SEC-002:1", "INVARIANT", source, result)

    def test_a_check_has_a_known_kind_and_a_text_target(self) -> None:
        for kind in ("GATE", "INVARIANT", "BASELINE"):
            RequiredCheck("T", kind, None, None)
        with self.assertRaises(DomainValidationError):
            RequiredCheck("T", "OTHER", None, None)
        with self.assertRaises(DomainValidationError):
            RequiredCheck("", "GATE", None, None)

    def test_a_blocking_condition_is_never_a_promote(self) -> None:
        BlockingCondition(DecisionReason.STALE_PARENT, DecisionType.REJECT, "STATE", "x")
        with self.assertRaises(DomainValidationError):
            BlockingCondition(DecisionReason.STALE_PARENT, DecisionType.PROMOTE, "STATE", "x")
        with self.assertRaises(DomainValidationError):
            BlockingCondition("STALE_PARENT", DecisionType.REJECT, "STATE", "x")  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            BlockingCondition(DecisionReason.STALE_PARENT, DecisionType.REJECT, "", "x")

    def test_round_trips(self) -> None:
        condition = blocking()
        self.assertEqual(BlockingCondition.from_dict(condition.to_dict()), condition)
        check = checks()[1]
        self.assertEqual(RequiredCheck.from_dict(check.to_dict()), check)


class TestPromotionDecision(unittest.TestCase):
    def test_a_promote_references_the_results_that_satisfied_the_policy(self) -> None:
        made = decision()
        self.assertEqual(made.decision, DecisionType.PROMOTE)
        self.assertEqual(made.supporting_results, (RESULT_A, RESULT_B))
        self.assertIsNone(made.committed_state_id)
        with self.assertRaises(DomainValidationError):
            decision(supporting_results=())

    def test_a_promote_has_no_blocking_condition_and_the_proven_reason(self) -> None:
        with self.assertRaises(DomainValidationError):
            decision(blocking_conditions=(blocking(),))
        with self.assertRaises(DomainValidationError):
            decision(reason=DecisionReason.REQUIRED_CHECK_FAILED)

    def test_a_non_promote_preserves_its_blocking_reasons(self) -> None:
        for kind in (DecisionType.REJECT, DecisionType.RETRY, DecisionType.ESCALATE):
            with self.subTest(decision=kind):
                made = rejection(decision=kind)
                self.assertEqual(made.blocking_conditions, (blocking(),))
                with self.assertRaises(DomainValidationError):
                    rejection(decision=kind, blocking_conditions=())

    def test_a_non_promote_cannot_claim_everything_is_proven(self) -> None:
        with self.assertRaises(DomainValidationError):
            rejection(reason=DecisionReason.ALL_REQUIRED_PROVEN)

    def test_the_reason_is_one_of_the_blocking_conditions(self) -> None:
        with self.assertRaises(DomainValidationError):
            rejection(reason=DecisionReason.STRUCTURAL_FAILURE)
        made = rejection(
            reason=DecisionReason.STRUCTURAL_FAILURE,
            blocking_conditions=(
                blocking(),
                BlockingCondition(
                    DecisionReason.STRUCTURAL_FAILURE, DecisionType.REJECT, "STRUCTURAL", "x"
                ),
            ),
        )
        self.assertEqual(len(made.blocking_conditions), 2)

    def test_the_commit_is_not_part_of_p6a(self) -> None:
        # DATA-INT-004: committed_state_id is set only by the commit of P6b
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(decision(), committed_state_id=uid(55))

    def test_ids_and_text_are_checked(self) -> None:
        for field, value in (
            ("candidate_id", "not-a-uuid"),
            ("parent_state_id", "x"),
            ("decision_id", ""),
            ("policy_version", ""),
            ("attempt_number", 0),
            ("attempt_number", True),
            ("decision", "PROMOTE"),
            ("reason", "ALL_REQUIRED_PROVEN"),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(DomainValidationError):
                decision(**{field: value})

    def test_supporting_results_are_sorted_distinct_uuids(self) -> None:
        with self.assertRaises(DomainValidationError):
            decision(supporting_results=(RESULT_B, RESULT_A))
        with self.assertRaises(DomainValidationError):
            decision(supporting_results=(RESULT_A, RESULT_A))
        with self.assertRaises(DomainValidationError):
            decision(supporting_results=("not-a-uuid",))

    def test_required_checks_are_sorted_and_one_per_target(self) -> None:
        first, second = checks()
        with self.assertRaises(DomainValidationError):
            decision(required_checks=(second, first))
        with self.assertRaises(DomainValidationError):
            decision(required_checks=(first, first))

    def test_blocking_conditions_are_sorted_and_distinct(self) -> None:
        low = BlockingCondition(DecisionReason.EVIDENCE_STALE, DecisionType.REJECT, "A", "x")
        high = BlockingCondition(
            DecisionReason.REQUIRED_CHECK_FAILED, DecisionType.REJECT, "B", "x"
        )
        both = rejection(blocking_conditions=(low, high), reason=DecisionReason.EVIDENCE_STALE)
        self.assertEqual(
            both.blocking_conditions, tuple(sorted((low, high), key=lambda c: c.sort_key()))
        )
        with self.assertRaises(DomainValidationError):
            rejection(blocking_conditions=(high, high))

    def test_the_hash_is_recomputed_by_the_constructor(self) -> None:
        made = decision()
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(made, policy_version="policy-2")
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(made, content_hash="0" * 64)

    def test_the_hash_ignores_the_id_and_the_clock_and_follows_the_content(self) -> None:
        a = decision()
        b = decision(decision_id=uid(9002), created_at=at(99))
        self.assertEqual(a.content_hash, b.content_hash)
        for change in (
            {"policy_version": "policy-2"},
            {"attempt_number": 2},
            {"supporting_results": (RESULT_A,)},
            {"parent_state_id": uid(2)},
        ):
            with self.subTest(change=change):
                self.assertNotEqual(decision(**change).content_hash, a.content_hash)

    def test_a_round_trip_keeps_everything(self) -> None:
        for made in (decision(), rejection(), rejection(decision=DecisionType.ESCALATE)):
            with self.subTest(decision=made.decision):
                self.assertEqual(PromotionDecision.from_dict(made.to_dict()), made)

    def test_from_dict_refuses_missing_extra_and_unknown_values(self) -> None:
        data = decision().to_dict()
        for broken in (
            {k: v for k, v in data.items() if k != "reason"},
            {**data, "extra": 1},
            {**data, "reason": "MADE_UP"},
            {**data, "decision": "MAYBE"},
        ):
            with self.subTest(keys=sorted(broken)), self.assertRaises(DomainValidationError):
                PromotionDecision.from_dict(broken)

    def test_the_dict_is_plain_json(self) -> None:
        import json

        text = json.dumps(rejection().to_dict(), sort_keys=True)
        self.assertEqual(json.loads(text), rejection().to_dict())


class TestPromotionEvidence(unittest.TestCase):
    def evidence(self, **changes: Any) -> PromotionEvidence:
        fields: dict[str, Any] = {
            "decision_id": uid(9001),
            "candidate_id": CANDIDATE,
            "parent_state_id": PARENT,
            "required_checks": checks(),
            "verification_refs": (RESULT_A, RESULT_B),
            "evidence_sufficiency": "SUFFICIENT",
            "policy_version": "policy-1",
            "decision": DecisionType.PROMOTE,
            "reason": DecisionReason.ALL_REQUIRED_PROVEN,
        }
        fields.update(changes)
        return PromotionEvidence.create(**fields)

    def test_the_fields_of_doc_11_section_26(self) -> None:
        made = self.evidence()
        self.assertEqual(
            set(made.to_dict()),
            {
                "decision_id",
                "candidate_id",
                "parent_state_id",
                "required_checks",
                "verification_refs",
                "evidence_sufficiency",
                "policy_version",
                "decision",
                "reason",
                "new_state_id",
                "content_hash",
            },
        )
        self.assertIsNone(made.new_state_id)

    def test_a_promote_references_every_mandatory_result_it_used(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.evidence(verification_refs=())
        with self.assertRaises(DomainValidationError):
            self.evidence(evidence_sufficiency="INSUFFICIENT")

    def test_a_non_promote_may_say_the_evidence_is_insufficient(self) -> None:
        made = self.evidence(
            decision=DecisionType.REJECT,
            reason=DecisionReason.INSUFFICIENT_EVIDENCE,
            evidence_sufficiency="INSUFFICIENT",
            verification_refs=(RESULT_A,),
        )
        self.assertEqual(made.evidence_sufficiency, "INSUFFICIENT")

    def test_the_sufficiency_is_a_closed_value(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.evidence(evidence_sufficiency="MAYBE")

    def test_the_new_state_is_not_part_of_p6a(self) -> None:
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(self.evidence(), new_state_id=uid(77))

    def test_hash_and_round_trip(self) -> None:
        made = self.evidence()
        self.assertEqual(PromotionEvidence.from_dict(made.to_dict()), made)
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(made, policy_version="policy-2")

    def test_the_references_are_sorted_distinct_uuids(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.evidence(verification_refs=(RESULT_B, RESULT_A))
        with self.assertRaises(DomainValidationError):
            self.evidence(verification_refs=("x",))


class TestOracleVerdict(unittest.TestCase):
    def test_a_verdict_names_an_invariant_a_result_and_an_oracle_version(self) -> None:
        verdict = OracleVerdict("INV-SEC-001", 1, VerificationResult.FAIL, "oracle-1")
        self.assertEqual(verdict.result, VerificationResult.FAIL)

    def test_malformed_verdicts_are_refused(self) -> None:
        for args in (
            ("SEC-1", 1, VerificationResult.PASS, "o"),
            ("INV-SEC-001", 0, VerificationResult.PASS, "o"),
            ("INV-SEC-001", 1, "PASS", "o"),
            ("INV-SEC-001", 1, VerificationResult.PASS, ""),
        ):
            with self.subTest(args=args), self.assertRaises(DomainValidationError):
                OracleVerdict(*args)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
