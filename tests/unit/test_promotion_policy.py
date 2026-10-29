"""The promotion policy (P6a step 2; Doc 09 §17-§23, §28, Doc 14 §37; C-22, C-41, C-157 to C-161).

Expected values come from the prompt's spec extracts: the non-success table (UNKNOWN retries,
UNSUPPORTED rejects, VERIFIER_ERROR escalates unless its type is listed as transient); the retry
budget is validated 1..10 with default 3; the evidence level is "L1"; ``accept_oracle_for_unknown``
must be refused; the Stateful-Full policy differs from the DAIL policy in carry-forward only (C-22).
"""

from __future__ import annotations

import dataclasses
import unittest
from typing import Any

from core.domain.enums import DecisionType, VerificationResult
from core.domain.errors import DomainValidationError
from core.domain.promotion import PromotionPolicy
from core.promotion.policy import (
    DEFAULT_NON_SUCCESS,
    GATE_VERIFIERS,
    dail_policy,
    stateful_full_policy,
)
from tests.domain_builders import FUNC, SEC, invariant

U, S, E = (
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
    VerificationResult.VERIFIER_ERROR,
)


def invariants() -> tuple[Any, ...]:
    return (invariant(FUNC), invariant(SEC))


def dail(**changes: Any) -> PromotionPolicy:
    fields: dict[str, Any] = {
        "policy_version": "policy-1",
        "invariants": invariants(),
        "automatic_enabled": True,
    }
    fields.update(changes)
    return dail_policy(**fields)


def raw(**changes: Any) -> PromotionPolicy:
    """The class itself, for values the constructors would not offer."""
    fields: dict[str, Any] = {
        "policy_version": "policy-1",
        "invariant_registry_version": 1,
        "invariants": invariants(),
        "extra_required": (),
        "min_evidence_level": "L1",
        "carry_forward_enabled": True,
        "non_success": DEFAULT_NON_SUCCESS,
        "transient_errors": (),
        "max_attempts": 3,
        "conflict_decision": DecisionType.ESCALATE,
        "automatic_enabled": True,
        "accept_oracle_for_unknown": False,
        "gate_verifiers": GATE_VERIFIERS,
    }
    fields.update(changes)
    return PromotionPolicy(**fields)


class TestDefaults(unittest.TestCase):
    def test_the_dail_policy_defaults(self) -> None:
        policy = dail()
        self.assertTrue(policy.carry_forward_enabled)
        self.assertEqual(policy.min_evidence_level, "L1")
        self.assertEqual(policy.max_attempts, 3)
        self.assertEqual(policy.conflict_decision, DecisionType.ESCALATE)
        self.assertEqual(policy.transient_errors, ())
        self.assertFalse(policy.accept_oracle_for_unknown)
        self.assertEqual(policy.extra_required, ())

    def test_the_default_non_success_table(self) -> None:
        policy = dail()
        self.assertEqual(policy.non_success_decision(U), DecisionType.RETRY)
        self.assertEqual(policy.non_success_decision(S), DecisionType.REJECT)
        self.assertEqual(policy.non_success_decision(E), DecisionType.ESCALATE)

    def test_a_listed_transient_error_type_is_retried(self) -> None:
        policy = dail(transient_errors=("TimeoutError",))
        self.assertEqual(policy.non_success_decision(E, "TimeoutError"), DecisionType.RETRY)
        self.assertEqual(policy.non_success_decision(E, "ValueError"), DecisionType.ESCALATE)
        self.assertEqual(policy.non_success_decision(E, None), DecisionType.ESCALATE)
        self.assertEqual(policy.non_success_decision(U, "TimeoutError"), DecisionType.RETRY)

    def test_only_a_non_success_has_a_decision(self) -> None:
        policy = dail()
        for result in (VerificationResult.PASS, VerificationResult.FAIL):
            with self.subTest(result=result), self.assertRaises(DomainValidationError):
                policy.non_success_decision(result)

    def test_the_gate_verifiers_are_those_of_the_verification_engine(self) -> None:
        # tests may import both packages; the policy copies the ids because core.promotion may not
        from core.verification.engine import (
            CONSISTENCY_ID,
            CONSISTENCY_VERIFIER,
            STRUCTURAL_ID,
            STRUCTURAL_VERIFIER,
        )

        self.assertEqual(
            dict((target, (vid, ver)) for target, vid, ver in GATE_VERIFIERS),
            {STRUCTURAL_ID: STRUCTURAL_VERIFIER, CONSISTENCY_ID: CONSISTENCY_VERIFIER},
        )


class TestStatefulFull(unittest.TestCase):
    def test_it_differs_from_the_dail_policy_in_carry_forward_only(self) -> None:
        # C-22: the same controller, carry-forward disabled
        full = stateful_full_policy(
            policy_version="policy-1", invariants=invariants(), automatic_enabled=True
        )
        self.assertFalse(full.carry_forward_enabled)
        self.assertEqual(dataclasses.replace(full, carry_forward_enabled=True), dail())

    def test_the_switch_has_no_default(self) -> None:
        with self.assertRaises(TypeError):
            dail_policy(policy_version="p", invariants=invariants())  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            stateful_full_policy(policy_version="p", invariants=invariants())  # type: ignore[call-arg]


class TestValidation(unittest.TestCase):
    def test_the_oracle_cannot_be_accepted(self) -> None:
        with self.assertRaises(DomainValidationError):
            raw(accept_oracle_for_unknown=True)

    def test_the_retry_budget_is_one_to_ten(self) -> None:
        for good in (1, 3, 10):
            self.assertEqual(raw(max_attempts=good).max_attempts, good)
        for bad in (0, 11, -1, True, "3", 2.5):
            with self.subTest(bad=bad), self.assertRaises(DomainValidationError):
                raw(max_attempts=bad)

    def test_the_evidence_level_is_a_known_level(self) -> None:
        self.assertEqual(raw(min_evidence_level="L0").min_evidence_level, "L0")
        with self.assertRaises(DomainValidationError):
            raw(min_evidence_level="L9")

    def test_the_conflict_decision_is_reject_or_escalate(self) -> None:
        for good in (DecisionType.REJECT, DecisionType.ESCALATE):
            self.assertEqual(raw(conflict_decision=good).conflict_decision, good)
        for bad in (DecisionType.PROMOTE, DecisionType.RETRY, "REJECT"):
            with self.subTest(bad=bad), self.assertRaises(DomainValidationError):
                raw(conflict_decision=bad)

    def test_the_non_success_table_is_closed_and_never_promotes(self) -> None:
        good = ((U, DecisionType.REJECT), (S, DecisionType.REJECT), (E, DecisionType.RETRY))
        self.assertEqual(raw(non_success=good).non_success_decision(U), DecisionType.REJECT)
        for bad in (
            ((U, DecisionType.RETRY), (S, DecisionType.REJECT)),
            (
                (U, DecisionType.RETRY),
                (S, DecisionType.REJECT),
                (E, DecisionType.ESCALATE),
                (U, DecisionType.RETRY),
            ),
            ((U, DecisionType.PROMOTE), (S, DecisionType.REJECT), (E, DecisionType.ESCALATE)),
            (
                (VerificationResult.PASS, DecisionType.REJECT),
                (S, DecisionType.REJECT),
                (E, DecisionType.ESCALATE),
            ),
            ((U, "RETRY"), (S, DecisionType.REJECT), (E, DecisionType.ESCALATE)),
        ):
            with self.subTest(bad=bad), self.assertRaises(DomainValidationError):
                raw(non_success=bad)

    def test_the_registry_version_and_the_texts(self) -> None:
        for field, value in (
            ("invariant_registry_version", 0),
            ("invariant_registry_version", True),
            ("policy_version", ""),
            ("transient_errors", ("",)),
            ("transient_errors", "TimeoutError"),
            ("extra_required", "INV-SEC-001"),
            ("carry_forward_enabled", 1),
            ("automatic_enabled", "yes"),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(DomainValidationError):
                raw(**{field: value})

    def test_the_registry_holds_one_definition_per_id_at_the_policy_version(self) -> None:
        sec = invariant(SEC)
        with self.assertRaises(DomainValidationError):
            raw(invariants=(sec, sec))
        with self.assertRaises(DomainValidationError):
            raw(invariants=())
        with self.assertRaises(DomainValidationError):
            raw(invariants=("INV-SEC-001",))
        policy = raw(invariants=(invariant(SEC), invariant(FUNC)))
        self.assertEqual([d.invariant_id for d in policy.invariants], [FUNC, SEC])
        self.assertEqual(policy.definition(SEC), invariant(SEC))
        self.assertIsNone(policy.definition("INV-SEC-009"))

    def test_an_extra_required_invariant_must_be_defined(self) -> None:
        self.assertEqual(raw(extra_required=(FUNC,)).extra_required, (FUNC,))
        with self.assertRaises(DomainValidationError):
            raw(extra_required=("INV-SEC-009",))
        with self.assertRaises(DomainValidationError):
            raw(extra_required=(SEC, SEC))

    def test_both_gate_items_name_a_verifier(self) -> None:
        only = (GATE_VERIFIERS[0],)
        with self.assertRaises(DomainValidationError):
            raw(gate_verifiers=only)
        with self.assertRaises(DomainValidationError):
            raw(gate_verifiers=(("OTHER", "v", "1"), GATE_VERIFIERS[1]))
        with self.assertRaises(DomainValidationError):
            raw(gate_verifiers=(("STRUCTURAL", "", "1"), GATE_VERIFIERS[1]))

    def test_the_policy_is_frozen(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            dail().carry_forward_enabled = False  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
