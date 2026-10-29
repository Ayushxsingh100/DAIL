"""The same promotion twice (P6b step 6; Doc 09 §38, §39, Appendix B; Doc 11 §38; C-163).

HAND EXPECTATIONS, written before the run. The key of a promotion is its decision id (C-163):

* committing a decision that is already committed returns the state it made, with ``duplicate=True``
  and the committed decision; no table gains or loses a row, whatever the clock or the context ids
  of the second request say;
* the same decision id with other content is never merged: ``ConflictingDuplicateError``, and no
  table changes (Doc 09 §38); the same holds for a decision that was stored but not committed;
* a candidate that a decision already promoted refuses a second PROMOTE under another id;
* recording the same decision twice changes nothing, for each of the four decisions;
* two threads committing the same decision at once make one state: one result is the commit, the
  other the duplicate, whichever pause point holds the first thread.
"""

from __future__ import annotations

import dataclasses
import unittest

from core.domain.enums import CandidateStatus, DecisionType
from core.domain.promotion import ConflictingDuplicateError
from core.persistence.sqlite import ALL_CHECKPOINTS
from core.promotion import ids
from core.promotion.commit import (
    PromotionCommitError,
    PromotionContext,
    commit_promotion,
    record_decision,
)
from tests.domain_builders import at, uid
from tests.promotion_builders import ERROR, FAIL, FUNC1, UNKNOWN, make_world, run, target
from tests.promotion_commit_builders import (
    CONTEXT,
    NOW,
    CommitCase,
    Gate,
    InjectedFault,
    Runner,
    check_database,
)

DECISION = uid(9100)
TABLES = (
    "trusted_states",
    "lineage_heads",
    "invariant_refs",
    "state_resources",
    "promotion_decisions",
    "candidates",
    "audit_events",
    "evidence_events",
    "evidence_artifacts",
)


class IdempotencyCase(CommitCase):
    def rows(self) -> dict[str, int]:
        return {table: self.count(table) for table in TABLES}


class TestSequentialDuplicates(IdempotencyCase):
    def setUp(self) -> None:
        super().setUp()
        self.outcome = run(self.world)
        self.first = self.commit(outcome=self.outcome)
        self.assertFalse(self.first.duplicate)

    def test_each_repeat_is_the_same_state_and_writes_nothing(self) -> None:
        before = self.rows()
        for _ in range(3):
            again = self.commit(outcome=self.outcome)
            self.assertTrue(again.duplicate)
            self.assertEqual(again.state, self.first.state)
            self.assertEqual(again.decision, self.first.decision)
            self.assertFalse(again.stale or again.escalated)
            self.assertEqual(self.rows(), before)
        self.assertEqual(before["trusted_states"], 2)
        self.assertEqual(check_database(self.path), [])

    def test_another_clock_and_other_context_ids_change_nothing(self) -> None:
        before = self.rows()
        other = PromotionContext(
            run_id=uid(1), correlation_id=uid(2), operation_id=uid(3), attempt_id=uid(4)
        )
        again = commit_promotion(
            self.factory(),
            self.outcome,
            self.world.candidate,
            self.world.impact,
            self.world.verification,
            self.world.policy,
            self.evidence_ids,
            other,
            now=at(99),
        )
        self.assertTrue(again.duplicate)
        self.assertEqual(again.state, self.first.state)
        self.assertEqual(self.rows(), before)

    def test_the_state_is_the_stored_one_and_not_a_rebuilt_one(self) -> None:
        again = self.commit(outcome=self.outcome)
        assert again.state is not None and self.first.state is not None
        self.assertEqual(again.state.created_at, self.first.state.created_at)
        self.assertEqual(again.state.state_hash, self.first.state.state_hash)
        self.assertEqual(again.state.state_id, ids.state_id_for(DECISION))

    def test_recording_a_committed_decision_again_changes_nothing(self) -> None:
        before = self.rows()
        with self.uow() as u:
            stored = record_decision(u, self.outcome, self.world.candidate, CONTEXT, now=NOW)
        self.assertEqual(stored.status.value, "PROMOTED")
        self.assertEqual(self.rows(), before)

    def test_a_second_promote_for_a_promoted_candidate_is_refused(self) -> None:
        before = self.rows()
        second = run(self.world, decision_id=uid(9101))
        with self.assertRaises(ConflictingDuplicateError):
            self.commit(outcome=second)
        self.assertEqual(self.rows(), before)


class TestConflictingDuplicates(IdempotencyCase):
    def test_other_content_under_the_id_of_a_committed_decision(self) -> None:
        outcome = run(self.world)
        self.commit(outcome=outcome)
        before = self.rows()
        variants = {
            "another policy version": run(
                dataclasses.replace(
                    self.world, policy=dataclasses.replace(self.world.policy, policy_version="p-2")
                )
            ),
            "another attempt number": run(self.world, attempt_number=2),
        }
        for label, other in variants.items():
            with self.subTest(label), self.assertRaises(ConflictingDuplicateError):
                self.commit(outcome=other)
            self.assertEqual(self.rows(), before)

    def test_other_content_under_the_id_of_a_stored_decision(self) -> None:
        outcome = run(self.world)
        with self.uow() as u:
            u.decisions.save(outcome.decision)
        before = self.rows()
        other = run(self.world, attempt_number=3)
        self.assertEqual(other.decision.decision_id, outcome.decision.decision_id)
        with self.assertRaises(ConflictingDuplicateError):
            self.commit(outcome=other)
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.candidate_status(), "PROMOTABLE")

    def test_a_decision_of_a_non_promote_cannot_be_overwritten_by_a_promote(self) -> None:
        reject_world = make_world(results={target(FUNC1): FAIL})
        reject = run(reject_world)
        self.assertIs(reject.decision.decision, DecisionType.REJECT)
        # recorded for the stored (PROMOTABLE) candidate only as a decision row
        with self.uow() as u:
            u.decisions.save(reject.decision)
        with self.assertRaises(ConflictingDuplicateError):
            self.commit(outcome=run(self.world))
        self.assertEqual(self.count("trusted_states"), 1)


class TestRecordingTwice(CommitCase):
    stored_status = (
        CandidateStatus.ANALYZING
    )  # a decision is recorded for a candidate under analysis

    def test_each_decision_recorded_twice_changes_nothing_the_second_time(self) -> None:
        cases = (
            {},
            {target(FUNC1): FAIL},
            {target(FUNC1): UNKNOWN},
            {target(FUNC1): ERROR},
        )
        seen = set()
        for results in cases:
            self.tearDown()
            self.setUp()
            outcome = run(make_world(results=results))
            seen.add(outcome.decision.decision)
            with self.uow() as u:
                record_decision(u, outcome, self.world.candidate, CONTEXT, now=NOW)
            rows = {t: self.count(t) for t in ("promotion_decisions", "audit_events", "candidates")}
            status = self.candidate_status()
            with self.uow() as u:
                record_decision(u, outcome, self.world.candidate, CONTEXT, now=NOW)
            again = {
                t: self.count(t) for t in ("promotion_decisions", "audit_events", "candidates")
            }
            with self.subTest(decision=outcome.decision.decision):
                self.assertEqual(again, rows)
                self.assertEqual(self.candidate_status(), status)
        self.assertEqual(
            seen,
            {DecisionType.PROMOTE, DecisionType.REJECT, DecisionType.RETRY, DecisionType.ESCALATE},
        )

    def test_the_same_id_with_other_content_is_a_conflict(self) -> None:
        outcome = run(self.world)
        with self.uow() as u:
            record_decision(u, outcome, self.world.candidate, CONTEXT, now=NOW)
        other = run(self.world, attempt_number=2)
        with self.uow() as u, self.assertRaises(ConflictingDuplicateError):
            record_decision(u, other, self.world.candidate, CONTEXT, now=NOW)


class TestConcurrentDuplicates(IdempotencyCase):
    def setUp(self) -> None:
        super().setUp()
        self.outcome = run(self.world)

    def race(self, point: str) -> tuple[Runner, Runner]:
        gate = Gate(point)
        leader = Runner(lambda: self.commit(outcome=self.outcome, checkpoint=gate))
        leader.start()
        self.assertTrue(leader.wait_for(gate), f"{point} was never reached")
        follower = Runner(lambda: self.commit(outcome=self.outcome))
        follower.start()
        follower.started_running.wait(60)
        gate.release.set()
        leader.join(60)
        follower.join(60)
        self.assertFalse(leader.is_alive() or follower.is_alive(), "a thread is stuck")
        return leader, follower

    def test_two_threads_with_one_decision_make_one_state_at_every_point(self) -> None:
        for index, point in enumerate(ALL_CHECKPOINTS):
            with self.subTest(point=point):
                if index:
                    self.tearDown()
                    self.setUp()
                leader, follower = self.race(point)
                self.assertIsNone(leader.error)
                self.assertIsNone(follower.error)
                self.assertFalse(leader.result.duplicate)
                self.assertTrue(follower.result.duplicate)
                self.assertEqual(leader.result.state, follower.result.state)
                self.assertEqual(self.count("trusted_states"), 2)
                self.assertEqual(self.count("audit_events", "event_type = 'STATE_PROMOTED'"), 1)
                self.assertEqual(self.count("promotion_decisions"), 1)
                self.assertEqual(check_database(self.path), [])

    def test_a_leader_that_fails_leaves_the_follower_to_make_the_state(self) -> None:
        gate = Gate("after_lineage_head_update", fail=True)
        leader = Runner(lambda: self.commit(outcome=self.outcome, checkpoint=gate))
        leader.start()
        self.assertTrue(leader.wait_for(gate))
        follower = Runner(lambda: self.commit(outcome=self.outcome))
        follower.start()
        follower.started_running.wait(60)
        gate.release.set()
        leader.join(60)
        follower.join(60)
        self.assertIsInstance(leader.error, PromotionCommitError)
        self.assertIsInstance(leader.error.__cause__, InjectedFault)
        self.assertIsNone(follower.error)
        self.assertFalse(follower.result.duplicate)
        again = self.commit(outcome=self.outcome)
        self.assertTrue(again.duplicate)
        self.assertEqual(again.state, follower.result.state)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(check_database(self.path), [])


if __name__ == "__main__":
    unittest.main()
