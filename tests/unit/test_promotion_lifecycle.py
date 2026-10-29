"""Applying a decision to the candidate (P6a step 5; Doc 06 §4-§5, §20, §22 SM-001 to SM-004 and
SM-010, §25-§26, Doc 09 §21-§25).

Expected values come from the spec text: ANALYZING leaves to REJECTED, RETRY_REQUIRED, ESCALATED or
PROMOTABLE (Doc 06 §5); a PROMOTE makes the candidate PROMOTABLE and never PROMOTED (SM-002: only
the commit of P6b); a REJECT or a RETRY "preserves the current Trusted State" (SM-003, SM-004) and
"later attempts start from the unchanged baseline" (Doc 06 §25); a stale-parent candidate cannot
promote (SM-010) and a PROMOTABLE one is rejected only through the stale-parent exit (C-29).
"""

from __future__ import annotations

import ast
import dataclasses
import unittest
from pathlib import Path

from core.domain.enums import CandidateStatus as CS
from core.domain.enums import DecisionType
from core.domain.errors import IllegalTransitionError, StaleParentError
from core.domain.promotion import DecisionOutcome, DecisionReason, PromotionInputError
from core.domain.state import (
    CandidateState,
    TrustedState,
    mark_promoted,
    transition_candidate,
)
from core.promotion.lifecycle import candidate_after
from tests.domain_builders import analyzing_candidate, canonical_resources, patch_for, uid
from tests.promotion_builders import (
    ERROR,
    FAIL,
    FUNC1,
    UNKNOWN,
    World,
    make_world,
    run,
    target,
    trusted_state,
)

D, R = DecisionType, DecisionReason
ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE = ROOT / "core" / "promotion" / "lifecycle.py"


def apply(world: World, outcome: DecisionOutcome) -> CandidateState:
    return candidate_after(outcome.decision, world.candidate, world.trusted)


class TestFromAnalyzing(unittest.TestCase):
    def test_each_decision_takes_the_candidate_to_the_status_of_doc_06_section_5(self) -> None:
        cases = (
            (make_world(), D.PROMOTE, CS.PROMOTABLE),
            (make_world(results={target(FUNC1): FAIL}), D.REJECT, CS.REJECTED),
            (make_world(results={target(FUNC1): UNKNOWN}), D.RETRY, CS.RETRY_REQUIRED),
            (make_world(results={target(FUNC1): ERROR}), D.ESCALATE, CS.ESCALATED),
        )
        for world, decision, status in cases:
            outcome = run(world)
            with self.subTest(decision=decision):
                self.assertEqual(outcome.decision.decision, decision)
                self.assertEqual(world.candidate.status, CS.ANALYZING)
                self.assertEqual(apply(world, outcome).status, status)

    def test_a_promote_never_makes_the_candidate_promoted(self) -> None:
        # SM-002: PROMOTED is reached only by mark_promoted after TrustedState.promote (P6b)
        world = make_world()
        moved = apply(world, run(world))
        self.assertNotEqual(moved.status, CS.PROMOTED)
        with self.assertRaises(IllegalTransitionError) as caught:
            transition_candidate(moved, CS.PROMOTED)
        self.assertEqual(caught.exception.rule, "SM-002")

    def test_the_candidate_keeps_its_content(self) -> None:
        for results in ({}, {target(FUNC1): FAIL}, {target(FUNC1): UNKNOWN}):
            world = make_world(results=results)
            moved = apply(world, run(world))
            with self.subTest(results=results):
                self.assertEqual(moved.candidate_id, world.candidate.candidate_id)
                self.assertEqual(moved.state_hash, world.candidate.state_hash)
                self.assertEqual(moved.parent_state_id, world.candidate.parent_state_id)
                self.assertEqual(moved.resources, world.candidate.resources)

    def test_the_applied_candidate_is_a_new_object(self) -> None:
        world = make_world()
        before = world.candidate.to_dict()
        moved = apply(world, run(world))
        self.assertIsNot(moved, world.candidate)
        self.assertEqual(world.candidate.to_dict(), before)


class TestTheTrustedStateIsNeverTouched(unittest.TestCase):
    """SM-001, SM-003, SM-004: a decision never advances Trusted State, and a rejection or a retry
    leaves the current one in place."""

    def test_no_decision_changes_the_trusted_state(self) -> None:
        for results in (
            {},
            {target(FUNC1): FAIL},
            {target(FUNC1): UNKNOWN},
            {target(FUNC1): ERROR},
        ):
            world = make_world(results=results)
            before = (world.trusted.state_hash, world.trusted.to_dict())
            apply(world, run(world))
            with self.subTest(results=results):
                self.assertEqual((world.trusted.state_hash, world.trusted.to_dict()), before)

    def test_a_later_attempt_starts_again_from_the_unchanged_parent(self) -> None:
        # SM-003 / Doc 06 §25: after a REJECT the next candidate is built from the same state
        world = make_world(results={target(FUNC1): FAIL})
        rejected = apply(world, run(world))
        self.assertEqual(rejected.status, CS.REJECTED)
        again = CandidateState.create(
            parent=world.trusted,
            patch=patch_for(world.trusted, n=9),
            candidate_sequence=2,
            now=world.trusted.created_at,
        )
        self.assertEqual(again.parent_state_id, world.trusted.state_id)
        self.assertEqual(again.parent_state_id, rejected.parent_state_id)

    def test_a_rejected_retried_or_escalated_candidate_cannot_become_promotable(self) -> None:
        for results, final in (
            ({target(FUNC1): FAIL}, CS.REJECTED),
            ({target(FUNC1): UNKNOWN}, CS.RETRY_REQUIRED),
            ({target(FUNC1): ERROR}, CS.ESCALATED),
        ):
            world = make_world(results=results)
            moved = apply(world, run(world))
            with self.subTest(status=final), self.assertRaises(IllegalTransitionError):
                transition_candidate(moved, CS.PROMOTABLE)
            self.assertEqual(moved.status, final)

    def test_nothing_here_can_create_or_advance_a_trusted_state(self) -> None:
        source = ast.parse(LIFECYCLE.read_text(encoding="utf-8"))
        names = {n.attr for n in ast.walk(source) if isinstance(n, ast.Attribute)} | {
            n.id for n in ast.walk(source) if isinstance(n, ast.Name)
        }
        for forbidden in ("promote", "mark_promoted", "establish_baseline"):
            self.assertNotIn(forbidden, names)
        self.assertTrue(callable(mark_promoted) and callable(TrustedState.promote))


class TestStaleParent(unittest.TestCase):
    def newer(self, world: World) -> World:
        return dataclasses.replace(world, trusted=trusted_state(state_id=uid(2)))

    def test_an_analyzing_candidate_of_an_old_parent_is_rejected(self) -> None:
        world = self.newer(make_world())
        outcome = run(world)
        self.assertEqual(
            (outcome.decision.decision, outcome.decision.reason), (D.REJECT, R.STALE_PARENT)
        )
        self.assertEqual(apply(world, outcome).status, CS.REJECTED)

    def test_a_promotable_candidate_is_rejected_through_the_stale_parent_exit(self) -> None:
        # C-29: PROMOTABLE -> REJECTED only as a stale parent
        world = self.newer(make_world(candidate_status=CS.PROMOTABLE))
        outcome = run(world)
        moved = apply(world, outcome)
        self.assertEqual(moved.status, CS.REJECTED)
        self.assertEqual(moved.status_reason, "STALE_PARENT")

    def test_a_promotable_candidate_cannot_be_rejected_for_another_reason(self) -> None:
        world = make_world(candidate_status=CS.PROMOTABLE, results={target(FUNC1): FAIL})
        outcome = run(world)
        self.assertEqual(outcome.decision.decision, D.REJECT)
        with self.assertRaises(IllegalTransitionError):
            apply(world, outcome)

    def test_a_promote_cannot_be_applied_when_the_parent_is_no_longer_current(self) -> None:
        # SM-010: build a PROMOTE for the old parent, then try to apply it against the new state
        world = make_world()
        outcome = run(world)
        self.assertEqual(outcome.decision.decision, D.PROMOTE)
        with self.assertRaises(StaleParentError) as caught:
            candidate_after(outcome.decision, world.candidate, trusted_state(state_id=uid(2)))
        self.assertEqual(caught.exception.rule, "SM-010")


class TestBindings(unittest.TestCase):
    def test_a_decision_for_another_candidate_is_refused(self) -> None:
        world = make_world()
        other = analyzing_candidate(
            world.trusted, canonical_resources(ssh_open=False, db_path=True), n=2
        )
        with self.assertRaises(PromotionInputError):
            candidate_after(run(world).decision, other, world.trusted)

    def test_a_decision_for_another_parent_is_refused(self) -> None:
        world = make_world()
        decision = run(world).decision
        elsewhere = trusted_state(state_id=uid(2))
        other_candidate = analyzing_candidate(
            elsewhere, canonical_resources(ssh_open=False, db_path=True), n=1
        )
        with self.assertRaises(PromotionInputError):
            candidate_after(decision, other_candidate, elsewhere)

    def test_the_arguments_are_type_checked(self) -> None:
        world = make_world()
        decision = run(world).decision
        for args in (
            (None, world.candidate, world.trusted),
            (decision, world.trusted, world.trusted),
            (decision, world.candidate, world.candidate),
        ):
            with (
                self.subTest(args=[type(a).__name__ for a in args]),
                self.assertRaises(PromotionInputError),
            ):
                candidate_after(*args)  # type: ignore[arg-type]

    def test_a_candidate_that_was_already_decided_cannot_be_decided_again(self) -> None:
        world = make_world()
        outcome = run(world)
        moved = apply(world, outcome)
        with self.assertRaises(IllegalTransitionError):
            candidate_after(outcome.decision, moved, world.trusted)

    def test_a_candidate_that_is_not_analyzing_cannot_receive_a_decision(self) -> None:
        world = make_world(results={target(FUNC1): UNKNOWN})
        retried = apply(world, run(world))
        failing = make_world(results={target(FUNC1): FAIL})
        with self.assertRaises(IllegalTransitionError):
            candidate_after(run(failing).decision, retried, failing.trusted)


if __name__ == "__main__":
    unittest.main()
