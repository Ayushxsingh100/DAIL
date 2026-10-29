"""The committed decision and the committed evidence (P6b step 3; Doc 05 §15, DATA-INT-004;
C-163).

HAND EXPECTATIONS, written before the code:

* DATA-INT-004: ``committed_state_id`` is non-null only for a committed PROMOTE decision. So
  ``PromotionDecision.committed(state_id)`` is allowed for a PROMOTE whose ``committed_state_id`` is
  null and for nothing else; it returns a new object (the original is unchanged), recomputes
  ``content_hash`` (the hash covers ``committed_state_id``; it still excludes the id and the clock),
  and the result survives a ``to_dict`` / ``from_dict`` round trip. A committed value cannot be put
  in by hand: ``create`` takes none and ``dataclasses.replace`` is refused.
* The same holds for ``PromotionEvidence.with_new_state``.
"""

from __future__ import annotations

import dataclasses
import unittest

from core.domain.enums import DecisionType
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.promotion import (
    ConflictingDuplicateError,
    DecisionReason,
    PromotionDecision,
    PromotionEvidence,
)
from tests.domain_builders import uid
from tests.unit.test_promotion_domain import RESULT_A, RESULT_B, checks, decision, rejection

STATE = uid(555)


class TestACommittedDecision(unittest.TestCase):
    def test_a_promote_can_be_committed_once_and_the_original_is_unchanged(self) -> None:
        made = decision()
        done = made.committed(STATE)
        self.assertEqual(done.committed_state_id, STATE)
        self.assertIsNone(made.committed_state_id)
        self.assertNotEqual(done.content_hash, made.content_hash)
        self.assertEqual(done.decision_id, made.decision_id)
        self.assertEqual(done.supporting_results, (RESULT_A, RESULT_B))

    def test_the_hash_covers_the_state_but_not_the_id_or_the_clock(self) -> None:
        one = decision().committed(STATE)
        other = decision(decision_id=uid(9002), created_at=decision().created_at).committed(STATE)
        self.assertEqual(one.content_hash, other.content_hash)
        self.assertNotEqual(one.content_hash, decision().committed(uid(556)).content_hash)

    def test_it_cannot_be_committed_twice(self) -> None:
        with self.assertRaises(DomainValidationError):
            decision().committed(STATE).committed(uid(556))

    def test_only_a_promote_can_be_committed(self) -> None:
        for kind in (DecisionType.REJECT, DecisionType.RETRY, DecisionType.ESCALATE):
            with self.subTest(decision=kind), self.assertRaises(DomainValidationError):
                rejection(decision=kind).committed(STATE)

    def test_the_state_must_be_a_uuid(self) -> None:
        for bad in ("", "not-a-uuid", None, 5):
            with self.subTest(state=bad), self.assertRaises(DomainValidationError):
                decision().committed(bad)  # type: ignore[arg-type]

    def test_a_committed_value_cannot_be_put_in_by_hand(self) -> None:
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(decision(), committed_state_id=STATE)
        with self.assertRaises(TypeError):  # create takes no committed state at all
            PromotionDecision.create(  # type: ignore[call-arg]
                **{**{"committed_state_id": STATE}, **self._fields()}
            )

    def _fields(self) -> dict[str, object]:
        made = decision()
        return {
            "decision_id": made.decision_id,
            "candidate_id": made.candidate_id,
            "parent_state_id": made.parent_state_id,
            "decision": made.decision,
            "reason": made.reason,
            "policy_version": made.policy_version,
            "attempt_number": made.attempt_number,
            "required_checks": made.required_checks,
            "blocking_conditions": made.blocking_conditions,
            "supporting_results": made.supporting_results,
            "created_at": made.created_at,
        }

    def test_a_committed_decision_survives_a_round_trip(self) -> None:
        done = decision().committed(STATE)
        again = PromotionDecision.from_dict(done.to_dict())
        self.assertEqual(again, done)
        self.assertEqual(again.committed_state_id, STATE)

    def test_a_stored_committed_value_on_another_decision_is_refused_on_reading(self) -> None:
        # DATA-INT-004 in the domain: a REJECT row with a committed state cannot be rebuilt
        data = rejection().to_dict()
        data["committed_state_id"] = STATE
        with self.assertRaises(DomainValidationError):
            PromotionDecision.from_dict(data)

    def test_a_committed_decision_whose_hash_was_not_updated_is_refused(self) -> None:
        data = decision().to_dict()
        data["committed_state_id"] = STATE
        with self.assertRaises(HashMismatchError):
            PromotionDecision.from_dict(data)

    def test_committing_does_not_hide_a_changed_field(self) -> None:
        done = decision().committed(STATE)
        with self.assertRaises(DomainValidationError):  # replace() cannot carry the commit token
            dataclasses.replace(done, policy_version="policy-9")

    def test_the_conflicting_duplicate_error_is_a_domain_validation_error(self) -> None:
        self.assertTrue(issubclass(ConflictingDuplicateError, DomainValidationError))
        self.assertEqual(DecisionReason.ALL_REQUIRED_PROVEN.value, "ALL_REQUIRED_PROVEN")


class TestCommittedEvidence(unittest.TestCase):
    def evidence(self, **changes: object) -> PromotionEvidence:
        fields: dict[str, object] = {
            "decision_id": uid(9001),
            "candidate_id": uid(3001),
            "parent_state_id": uid(1),
            "required_checks": checks(),
            "verification_refs": (RESULT_A, RESULT_B),
            "evidence_sufficiency": "SUFFICIENT",
            "policy_version": "policy-1",
            "decision": DecisionType.PROMOTE,
            "reason": DecisionReason.ALL_REQUIRED_PROVEN,
        }
        fields.update(changes)
        return PromotionEvidence.create(**fields)  # type: ignore[arg-type]

    def test_a_promote_evidence_names_the_new_state_once(self) -> None:
        made = self.evidence()
        done = made.with_new_state(STATE)
        self.assertEqual(done.new_state_id, STATE)
        self.assertIsNone(made.new_state_id)
        self.assertNotEqual(done.content_hash, made.content_hash)
        self.assertEqual(PromotionEvidence.from_dict(done.to_dict()), done)
        with self.assertRaises(DomainValidationError):
            done.with_new_state(uid(556))

    def test_only_a_promote_evidence_names_a_state(self) -> None:
        other = self.evidence(
            decision=DecisionType.REJECT,
            reason=DecisionReason.INSUFFICIENT_EVIDENCE,
            evidence_sufficiency="INSUFFICIENT",
            verification_refs=(RESULT_A,),
        )
        with self.assertRaises(DomainValidationError):
            other.with_new_state(STATE)

    def test_a_state_cannot_be_put_in_by_hand(self) -> None:
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(self.evidence(), new_state_id=STATE)
        data = self.evidence().to_dict()
        data["new_state_id"] = STATE
        with self.assertRaises(HashMismatchError):
            PromotionEvidence.from_dict(data)


if __name__ == "__main__":
    unittest.main()
