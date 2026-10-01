"""Lifecycle tables and pure transition functions (Doc 06 §5, §8, §9, §12; C-29, C-30; P1a step 10).

The expected tables below are typed from the Step 10 specification and the cited
Doc 06 sections, never derived from the implementation.
"""

from __future__ import annotations

import itertools
import random
import unittest
from collections.abc import Callable
from typing import Any

from core.domain.enums import CandidateStatus, InvariantStatus, VerificationResult
from core.domain.errors import DomainValidationError, IllegalTransitionError
from core.domain.invariant import InvariantEvaluation
from core.domain.lifecycle import (
    CANDIDATE_TRANSITIONS,
    INVARIANT_PLAIN_TRANSITIONS,
    RESULT_TO_STATUS,
    TRUSTED_REF_STATUSES,
    apply_verification_result,
    check_candidate_transition,
    check_invariant_transition,
    status_for_result,
)
from core.domain.state import (
    CandidateState,
    TrustedState,
    fail_building,
    finish_building,
    mark_promoted,
    reject_stale_candidate,
    start_building,
    transition_candidate,
)
from tests.domain_builders import (
    FUNC,
    SEC,
    at,
    baseline,
    canonical_resources,
    invariant,
    new_candidate,
    promotable_candidate,
    promote,
    proof,
    ready_candidate,
    uid,
)

C = CandidateStatus
I = InvariantStatus  # noqa: E741
R = VerificationResult

# Doc 06 §5 as amended by C-29.
LEGAL_CANDIDATE: set[tuple[C, C]] = {
    (C.CREATED, C.BUILDING),
    (C.BUILDING, C.READY),
    (C.BUILDING, C.FAILED),
    (C.READY, C.ANALYZING),
    (C.ANALYZING, C.REJECTED),
    (C.ANALYZING, C.RETRY_REQUIRED),
    (C.ANALYZING, C.ESCALATED),
    (C.ANALYZING, C.PROMOTABLE),
    (C.PROMOTABLE, C.PROMOTED),
    (C.PROMOTABLE, C.REJECTED),
}

# Doc 06 §9, plain (result-free) transitions only.
LEGAL_INVARIANT_PLAIN: set[tuple[I, I]] = {
    (I.REGISTERED, I.VERIFYING),
    (I.PROTECTED, I.AFFECTED),
    (I.AFFECTED, I.REVERIFYING),
    (I.VIOLATED, I.REVERIFYING),
    (I.UNCERTAIN, I.REVERIFYING),
}

RESULT_STATUS: dict[R, I] = {
    R.PASS: I.PROTECTED,
    R.FAIL: I.VIOLATED,
    R.UNKNOWN: I.UNCERTAIN,
    R.UNSUPPORTED: I.UNCERTAIN,
    R.VERIFIER_ERROR: I.UNCERTAIN,
}

RESULT_ONLY_STATUSES = {I.PROTECTED, I.VIOLATED, I.UNCERTAIN}


class TestTables(unittest.TestCase):
    def test_candidate_table_equals_the_spec(self) -> None:
        actual = {(a, b) for a, targets in CANDIDATE_TRANSITIONS.items() for b in targets}
        self.assertEqual(actual, LEGAL_CANDIDATE)

    def test_candidate_table_covers_every_status_and_terminals_are_empty(self) -> None:
        self.assertEqual(set(CANDIDATE_TRANSITIONS), set(CandidateStatus))
        for status in (C.FAILED, C.REJECTED, C.RETRY_REQUIRED, C.ESCALATED, C.PROMOTED):
            self.assertEqual(CANDIDATE_TRANSITIONS[status], frozenset(), status)

    def test_invariant_table_equals_the_spec(self) -> None:
        actual = {(a, b) for a, targets in INVARIANT_PLAIN_TRANSITIONS.items() for b in targets}
        self.assertEqual(actual, LEGAL_INVARIANT_PLAIN)
        self.assertEqual(set(INVARIANT_PLAIN_TRANSITIONS), set(InvariantStatus))
        self.assertEqual(INVARIANT_PLAIN_TRANSITIONS[I.VERIFYING], frozenset())
        self.assertEqual(INVARIANT_PLAIN_TRANSITIONS[I.REVERIFYING], frozenset())

    def test_result_mapping_equals_c30(self) -> None:
        self.assertEqual(dict(RESULT_TO_STATUS), RESULT_STATUS)
        self.assertEqual(set(RESULT_TO_STATUS), set(VerificationResult))

    def test_trusted_ref_statuses(self) -> None:
        self.assertEqual(set(TRUSTED_REF_STATUSES), {I.PROTECTED, I.VIOLATED, I.UNCERTAIN})

    def test_tables_are_immutable(self) -> None:
        with self.assertRaises(TypeError):
            CANDIDATE_TRANSITIONS[C.CREATED] = frozenset({C.PROMOTED})  # type: ignore[index]
        with self.assertRaises(TypeError):
            INVARIANT_PLAIN_TRANSITIONS[I.PROTECTED] = frozenset({I.REVERIFYING})  # type: ignore[index]
        with self.assertRaises(TypeError):
            RESULT_TO_STATUS[R.UNKNOWN] = I.PROTECTED  # type: ignore[index]
        with self.assertRaises(AttributeError):
            CANDIDATE_TRANSITIONS[C.CREATED].add(C.PROMOTED)  # type: ignore[attr-defined]

    def test_no_uncertain_result_maps_to_protected(self) -> None:
        for result in (R.UNKNOWN, R.UNSUPPORTED, R.VERIFIER_ERROR, R.FAIL):
            self.assertNotEqual(RESULT_TO_STATUS[result], I.PROTECTED)


class TestCandidateTransitionCheck(unittest.TestCase):
    def test_every_pair_matches_the_table_exactly(self) -> None:
        for current, target in itertools.product(CandidateStatus, repeat=2):
            with self.subTest(current=current.value, target=target.value):
                if (current, target) in LEGAL_CANDIDATE:
                    check_candidate_transition(current, target)
                else:
                    with self.assertRaises(IllegalTransitionError) as ctx:
                        check_candidate_transition(current, target)
                    self.assertEqual(ctx.exception.kind, "candidate")
                    self.assertEqual(ctx.exception.current, current)
                    self.assertEqual(ctx.exception.requested, target)

    def test_error_names_a_rule(self) -> None:
        with self.assertRaises(IllegalTransitionError) as ctx:
            check_candidate_transition(C.READY, C.PROMOTED)
        self.assertEqual(ctx.exception.rule, "SM-002")
        self.assertIn("SM-002", str(ctx.exception))
        with self.assertRaises(IllegalTransitionError) as ctx:
            check_candidate_transition(C.CREATED, C.READY)
        self.assertIn("Doc 06 §5", str(ctx.exception))

    def test_terminal_candidates_have_no_exit(self) -> None:
        for current in (C.FAILED, C.REJECTED, C.RETRY_REQUIRED, C.ESCALATED, C.PROMOTED):
            for target in CandidateStatus:
                with (
                    self.subTest(current=current.value, target=target.value),
                    self.assertRaises(IllegalTransitionError),
                ):
                    check_candidate_transition(current, target)

    def test_non_status_arguments_are_rejected(self) -> None:
        with self.assertRaises(DomainValidationError):
            check_candidate_transition("CREATED", C.BUILDING)  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            check_candidate_transition(C.CREATED, "BUILDING")  # type: ignore[arg-type]


class TestInvariantTransitionCheck(unittest.TestCase):
    def test_every_pair_matches_the_plain_table_exactly(self) -> None:
        for current, target in itertools.product(InvariantStatus, repeat=2):
            with self.subTest(current=current.value, target=target.value):
                if (current, target) in LEGAL_INVARIANT_PLAIN:
                    check_invariant_transition(current, target)
                else:
                    with self.assertRaises(IllegalTransitionError) as ctx:
                        check_invariant_transition(current, target)
                    self.assertEqual(ctx.exception.kind, "invariant")

    def test_result_statuses_are_never_reachable_by_a_plain_transition(self) -> None:
        for current, target in itertools.product(InvariantStatus, RESULT_ONLY_STATUSES):
            with self.subTest(current=current.value, target=target.value):
                with self.assertRaises(IllegalTransitionError) as ctx:
                    check_invariant_transition(current, target)
                self.assertIn("SM-006", str(ctx.exception))
                self.assertIn("Doc 06 §12", str(ctx.exception))

    def test_affected_cannot_shortcut_to_violated_or_protected(self) -> None:
        for target in (I.VIOLATED, I.PROTECTED):
            with self.assertRaises(IllegalTransitionError):
                check_invariant_transition(I.AFFECTED, target)

    def test_non_status_arguments_are_rejected(self) -> None:
        with self.assertRaises(DomainValidationError):
            check_invariant_transition("REGISTERED", I.VERIFYING)  # type: ignore[arg-type]


class TestApplyVerificationResult(unittest.TestCase):
    def test_every_status_and_result_pair(self) -> None:
        for current, result in itertools.product(InvariantStatus, VerificationResult):
            with self.subTest(current=current.value, result=result.value):
                if current in (I.VERIFYING, I.REVERIFYING):
                    outcome = apply_verification_result(current, result)
                    self.assertEqual(outcome, RESULT_STATUS[result])
                    self.assertEqual(outcome is I.PROTECTED, result is R.PASS)
                else:
                    with self.assertRaises(IllegalTransitionError):
                        apply_verification_result(current, result)

    def test_protected_is_returned_only_for_pass(self) -> None:
        for current in (I.VERIFYING, I.REVERIFYING):
            for result in VerificationResult:
                self.assertEqual(
                    apply_verification_result(current, result) is I.PROTECTED, result.is_pass
                )

    def test_applying_a_result_to_a_protected_or_affected_invariant_cites_the_rule(self) -> None:
        for current in (I.PROTECTED, I.AFFECTED):
            with self.assertRaises(IllegalTransitionError) as ctx:
                apply_verification_result(current, R.PASS)
            self.assertIn("SM-006", str(ctx.exception))

    def test_status_for_result_matches_the_mapping(self) -> None:
        for result in VerificationResult:
            self.assertEqual(status_for_result(result), RESULT_STATUS[result])

    def test_non_result_arguments_are_rejected(self) -> None:
        for bad in ("PASS", None, I.PROTECTED):
            with self.subTest(value=bad):
                with self.assertRaises(DomainValidationError):
                    status_for_result(bad)  # type: ignore[arg-type]
                with self.assertRaises(DomainValidationError):
                    apply_verification_result(I.VERIFYING, bad)  # type: ignore[arg-type]

    def test_uncertain_results_stay_uncertain_and_are_not_a_pass(self) -> None:
        for result in (R.UNKNOWN, R.UNSUPPORTED, R.VERIFIER_ERROR):
            self.assertIs(apply_verification_result(I.REVERIFYING, result), I.UNCERTAIN)
            self.assertFalse(result.is_pass)


# --- seeded random walks -----------------------------------------------------------------------

WALK_SEED = 20261001
WALKS = 500
SAFE_RESOURCES = canonical_resources(ssh_open=False, db_path=True)
NOT_REACHABLE_BY_PLAIN_TRANSITION = {C.READY, C.FAILED, C.PROMOTED}


def candidate_event_is_legal(status: C, event: str) -> tuple[bool, C]:
    """Legality and expected resulting status of ``event``, from the literal Step 10 table
    and the function contracts, independent of the implementation."""
    if event == "start_building":
        return status is C.CREATED, C.BUILDING
    if event == "finish_building":
        return status is C.BUILDING, C.READY
    if event == "fail_building":
        return status is C.BUILDING, C.FAILED
    if event == "reject_stale":
        return status is C.PROMOTABLE, C.REJECTED
    if event == "promote_and_mark":
        return status is C.PROMOTABLE, C.PROMOTED
    target = C(event.removeprefix("to_"))
    legal = (
        target not in NOT_REACHABLE_BY_PLAIN_TRANSITION
        and (status, target) in LEGAL_CANDIDATE
        and not (status is C.PROMOTABLE and target is C.REJECTED)
    )
    return legal, target


CANDIDATE_EVENTS = [
    "start_building",
    "finish_building",
    "fail_building",
    "reject_stale",
    "promote_and_mark",
    *[f"to_{status.value}" for status in CandidateStatus],
]

INVARIANT_EVENTS = [
    "start_verification",
    "start_reverification",
    *[f"apply_{result.value}" for result in VerificationResult],
    "to_proof",
]


class TestRandomWalks(unittest.TestCase):
    """Seeded random walks over both lifecycles (random.Random(20261001), 500 walks each)."""

    parent: TrustedState
    newer: TrustedState

    @classmethod
    def setUpClass(cls) -> None:
        cls.parent = baseline()
        cls.newer = promote(promotable_candidate(cls.parent, SAFE_RESOURCES, n=99), cls.parent)

    def run_candidate_event(self, event: str, candidate: CandidateState) -> CandidateState:
        if event == "start_building":
            return start_building(candidate)
        if event == "finish_building":
            return finish_building(candidate, SAFE_RESOURCES)
        if event == "fail_building":
            return fail_building(candidate, "walk failure")
        if event == "reject_stale":
            return reject_stale_candidate(candidate, self.newer)
        if event == "promote_and_mark":
            return mark_promoted(candidate, promote(candidate, self.parent))
        return transition_candidate(candidate, C(event.removeprefix("to_")))

    def test_candidate_walks(self) -> None:
        rng = random.Random(WALK_SEED)
        visited: set[C] = set()
        for walk in range(WALKS):
            candidate = new_candidate(self.parent, n=walk % 40 + 1)
            fixed_hash: str | None = None
            for step in range(rng.randrange(4, 16)):
                event = rng.choice(CANDIDATE_EVENTS)
                where = f"walk={walk} step={step} event={event} status={candidate.status.value}"
                legal, expected = candidate_event_is_legal(candidate.status, event)
                before = candidate.to_dict()
                try:
                    after = self.run_candidate_event(event, candidate)
                except DomainValidationError:
                    self.assertFalse(legal, where)
                    self.assertEqual(candidate.to_dict(), before, where)
                    continue
                self.assertTrue(legal, where)
                self.assertEqual(after.status, expected, where)
                self.assertEqual(candidate.to_dict(), before, where)  # the input is untouched
                candidate = after
                visited.add(candidate.status)
                if fixed_hash is None and candidate.state_hash is not None:
                    fixed_hash = candidate.state_hash
                if fixed_hash is not None:
                    self.assertEqual(candidate.state_hash, fixed_hash, where)
        # The walks must actually exercise the whole lifecycle, or they prove little.
        self.assertEqual(visited, set(CandidateStatus) - {C.CREATED})

    def start_evaluation(
        self, rng: random.Random, base: TrustedState, candidate: CandidateState
    ) -> InvariantEvaluation:
        refs = {ref.invariant_id: ref for ref in base.invariant_refs}
        kind = rng.choice(["affect", "reopen_violated", "reopen_uncertain", "register"])
        if kind == "affect":
            return InvariantEvaluation.affect(refs[SEC], candidate, "walk")
        if kind == "reopen_violated":
            return InvariantEvaluation.reopen(refs[FUNC], candidate, "walk")
        if kind == "reopen_uncertain":
            return InvariantEvaluation.reopen(refs["INV-SEC-002"], candidate, "walk")
        return InvariantEvaluation.register(candidate, invariant("INV-FUNC-002"), base)

    def test_invariant_walks(self) -> None:
        rng = random.Random(WALK_SEED)
        base = baseline(
            proofs=[
                proof(SEC, I.PROTECTED, evidence=1),
                proof(FUNC, I.VIOLATED, evidence=2),
                proof("INV-SEC-002", I.UNCERTAIN, evidence=3),
            ]
        )
        candidate = ready_candidate(base, SAFE_RESOURCES)
        protected_reached = 0
        for walk in range(WALKS):
            ev = self.start_evaluation(rng, base, candidate)
            came_from_a_pass = False
            for step in range(rng.randrange(3, 10)):
                event = rng.choice(INVARIANT_EVENTS)
                where = f"walk={walk} step={step} event={event} status={ev.status.value}"
                before = ev.to_dict()
                action: Callable[[], Any]
                if event == "start_verification":
                    legal, expected = ev.status is I.REGISTERED, I.VERIFYING
                    action = ev.start_verification
                elif event == "start_reverification":
                    legal, expected = ev.status is I.AFFECTED, I.REVERIFYING
                    action = ev.start_reverification
                elif event == "to_proof":
                    legal, expected = ev.status in RESULT_ONLY_STATUSES, ev.status
                    action = ev.to_proof
                else:
                    result = VerificationResult(event.removeprefix("apply_"))
                    legal = ev.status in (I.VERIFYING, I.REVERIFYING)
                    expected = RESULT_STATUS[result]
                    evidence = [uid(9500 + walk)]

                    def action(
                        res: VerificationResult = result, e: Any = ev, ids: Any = evidence
                    ) -> Any:
                        return e.apply_result(res, ids, at(40))

                try:
                    outcome = action()
                except DomainValidationError:
                    self.assertFalse(legal, where)
                    self.assertEqual(ev.to_dict(), before, where)
                    continue
                self.assertTrue(legal, where)
                self.assertEqual(ev.to_dict(), before, where)
                self.assertEqual(outcome.status, expected, where)
                if event == "to_proof":
                    continue
                came_from_a_pass = event == "apply_PASS"
                ev = outcome
                if ev.status is I.PROTECTED:
                    protected_reached += 1
                    self.assertTrue(came_from_a_pass, where)
                    self.assertIs(ev.last_result, VerificationResult.PASS, where)
        self.assertGreater(protected_reached, 0)


if __name__ == "__main__":
    unittest.main()
