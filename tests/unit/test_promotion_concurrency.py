"""Two promotions racing from one parent (P6b step 6; Doc 09 §38-§39, Appendix B; Doc 06 §20, §25
to §27; Doc 12 §19; C-38, C-163, C-166).

HAND EXPECTATIONS, written before the run. Two candidates A and B were made from the same trusted
state v0 and both are PROMOTABLE with a PROMOTE decision (ids 9100 and 9200). Real threads, two
connections to one SQLite file, and the checkpoint seam of the unit of work stop one commit at a
named point while the other starts; nothing sleeps.

Whatever the interleaving, the spec (Doc 09 §39: promotion only from the current parent; Doc 06 §20,
§27: a stale candidate is rejected, no new state is created for it) fixes the outcome:

* the commit that finishes first is the winner: exactly one new state, version 1, parent v0, id
  derived from the winner's decision, the lineage head, its candidate PROMOTED, one binding record,
  one STATE_PROMOTED event;
* the other is the loser: ``stale=True``, no state, its candidate REJECTED, a stored REJECT decision
  with reason STALE_PARENT under the derived rejection id and no committed state;
* a commit that fails after it moved the head (an injected fault, rolled back) leaves no trace but a
  PROMOTION_FAILED event, so the other commit is then the winner, and the failed one, tried again,
  is the loser;
* no table holds an orphan row, and ``check_database`` finds nothing.

Rows of the finished database: 2 trusted states, 8 invariant references (4 each), 1 lineage head,
2 promotion decisions (the committed PROMOTE and the loser's REJECT), 1 ``promotion.committed``
record.
"""

from __future__ import annotations

import random
import unittest
from collections import Counter
from itertools import product
from typing import Any

from core.domain.audit import AuditEventType as AE
from core.domain.promotion import DecisionReason
from core.persistence.sqlite import ALL_CHECKPOINTS, SqliteUnitOfWork
from core.promotion import ids
from core.promotion.commit import CommitResult, PromotionCommitError, commit_promotion
from tests.domain_builders import uid
from tests.promotion_builders import run
from tests.promotion_commit_builders import (
    CONTEXT,
    NOW,
    CommitCase,
    Gate,
    InjectedFault,
    Runner,
    check_database,
)

DECISIONS = {"A": uid(9100), "B": uid(9200)}
MODES = ("overlap", "sequential", "first_fails")
SEEDED_EXTRA = 24
SEED = 20261029


def every_schedule() -> list[tuple[str, str, str]]:
    """Every first-runner, mode and pause point, then SEEDED_EXTRA more drawn with a seeded
    ``random`` (so the run is the same every time and covers all 42 combinations at least once)."""
    fixed = [(first, mode, point) for first, mode, point in product("AB", MODES, ALL_CHECKPOINTS)]
    rng = random.Random(SEED)
    drawn = [
        (rng.choice("AB"), rng.choice(MODES), rng.choice(ALL_CHECKPOINTS))
        for _ in range(SEEDED_EXTRA)
    ]
    return fixed + drawn


class RaceCase(CommitCase):
    def setUp(self) -> None:
        super().setUp()
        self.second_world, self.second_ids = self.rival()
        self.entries = {
            "A": (self.world, self.evidence_ids),
            "B": (self.second_world, self.second_ids),
        }
        self.outcomes = {
            key: run(world, decision_id=DECISIONS[key]) for key, (world, _) in self.entries.items()
        }

    def go(self, key: str, hook: Any = None) -> CommitResult:
        world, evidence = self.entries[key]
        return self.commit(
            world, outcome=self.outcomes[key], evidence_ids=evidence, checkpoint=hook
        )

    def candidate_of(self, key: str) -> str:
        return self.entries[key][0].candidate.candidate_id

    def assert_one_winner(self, winner: str, loser: str) -> None:
        state_id = ids.state_id_for(DECISIONS[winner])
        self.assertEqual(self.current().state_id, state_id)
        self.assertEqual(self.current().version, 1)
        self.assertEqual(self.current().parent_state_id, self.world.trusted.state_id)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(self.count("lineage_heads"), 1)
        self.assertEqual(self.count("invariant_refs"), 8)
        self.assertEqual(self.candidate_status(self.candidate_of(winner)), "PROMOTED")
        self.assertEqual(self.candidate_status(self.candidate_of(loser)), "REJECTED")
        self.assertEqual(self.count("promotion_decisions"), 2)
        self.assertEqual(
            self.scalar(
                "SELECT committed_state_id FROM promotion_decisions WHERE decision_id = ?",
                (DECISIONS[winner],),
            ),
            state_id,
        )
        rejection = ids.rejection_decision_id_for(DECISIONS[loser])
        self.assertEqual(
            self.scalar(
                "SELECT decision || '/' || reason || '/' || COALESCE(committed_state_id, 'none') "
                "FROM promotion_decisions WHERE decision_id = ?",
                (rejection,),
            ),
            "REJECT/STALE_PARENT/none",
        )
        self.assertEqual(self.count("evidence_events", "event_name = 'promotion.committed'"), 1)
        self.assertEqual(self.count("audit_events", "event_type = 'STATE_PROMOTED'"), 1)
        self.assertEqual(check_database(self.path), [])


class TestSchedules(RaceCase):
    def run_schedule(self, first: str, mode: str, point: str) -> str:
        """Run one schedule; return the winner's key."""
        second = "B" if first == "A" else "A"
        if mode == "sequential":
            before = self.go(first)
            after = self.go(second)
            self.assertIsNotNone(before.state)
            self.assertTrue(after.stale)
            self.assert_one_winner(first, second)
            return first
        gate = Gate(point, fail=mode == "first_fails")
        leader = Runner(lambda: self.go(first, gate))
        leader.start()
        self.assertTrue(leader.wait_for(gate), f"{point} was never reached")
        follower = Runner(lambda: self.go(second))
        follower.start()
        follower.started_running.wait(60)
        gate.release.set()
        leader.join(60)
        follower.join(60)
        self.assertFalse(leader.is_alive() or follower.is_alive(), "a thread is stuck")
        if mode == "overlap":
            self.assertIsNone(leader.error)
            self.assertIsNone(follower.error)
            self.assertIsNotNone(leader.result.state)
            self.assertTrue(follower.result.stale)
            self.assert_one_winner(first, second)
            return first
        # the leader failed after the head had moved in its own transaction
        self.assertIsInstance(leader.error, PromotionCommitError)
        self.assertIsInstance(leader.error.__cause__, InjectedFault)
        self.assertIsNone(follower.error)
        self.assertIsNotNone(follower.result.state)
        self.assertEqual(self.candidate_status(self.candidate_of(first)), "PROMOTABLE")
        self.assertEqual(self.count("promotion_decisions", "committed_state_id IS NOT NULL"), 1)
        retried = self.go(first)  # the failed commit, tried again, now lost the race
        self.assertTrue(retried.stale)
        self.assert_one_winner(second, first)
        failed = self.count("audit_events", "event_type = 'PROMOTION_FAILED'")
        self.assertEqual(failed, 1)
        return second

    def test_at_least_fifty_schedules_leave_exactly_one_winner(self) -> None:
        schedules = every_schedule()
        self.assertGreaterEqual(len(schedules), 50)
        seen: Counter[tuple[str, str]] = Counter()
        winners: Counter[str] = Counter()
        for index, (first, mode, point) in enumerate(schedules):
            with self.subTest(schedule=index, first=first, mode=mode, point=point):
                if index:
                    self.tearDown()
                    self.setUp()
                winners[self.run_schedule(first, mode, point)] += 1
                seen[(mode, point)] += 1
        self.assertEqual({m for m, _ in seen}, set(MODES))
        self.assertEqual({p for _, p in seen}, set(ALL_CHECKPOINTS))
        self.assertEqual(set(winners), {"A", "B"})
        self.assertEqual(sum(winners.values()), len(schedules))


class TestCompareAndSwap(RaceCase):
    """The write lock makes the stale check and the swap one step. If the stale check were fooled,
    the compare-and-swap of ``save_promoted`` (SM-010) is the last line of defence."""

    def test_a_commit_that_believes_the_head_has_not_moved_still_loses(self) -> None:
        self.assertIsNotNone(self.go("A").state)
        old_head = self.world.trusted
        opened: list[int] = []
        path = self.path

        class Believer(SqliteUnitOfWork):
            @property
            def trusted_states(self) -> Any:
                real = super().trusted_states

                class Stale:
                    def __getattr__(self, name: str) -> Any:
                        return getattr(real, name)

                    def get_current(self, lineage_id: str) -> Any:
                        return old_head if lineage_id == old_head.lineage_id else None

                return Stale()

        def factory() -> Any:
            opened.append(1)
            return Believer(path) if len(opened) == 1 else SqliteUnitOfWork(path)

        world, evidence = self.entries["B"]
        result = commit_promotion(
            factory,
            self.outcomes["B"],
            world.candidate,
            world.impact,
            world.verification,
            world.policy,
            evidence,
            CONTEXT,
            now=NOW,
        )
        self.assertTrue(result.stale)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(self.candidate_status(self.candidate_of("B")), "REJECTED")
        self.assertEqual(check_database(self.path), [])


class TestRaceOutcomesStayDurable(RaceCase):
    def test_the_loser_is_rejected_once_and_keeps_its_reason(self) -> None:
        self.go("A")
        first = self.go("B")
        again = self.go("B")
        self.assertTrue(first.stale and again.stale)
        self.assertEqual(first.decision, again.decision)
        self.assertIs(first.decision.reason, DecisionReason.STALE_PARENT)
        self.assertEqual(self.count("audit_events", "event_type = 'CANDIDATE_REJECTED'"), 1)
        self.assertEqual(check_database(self.path), [])

    def test_the_failure_event_names_the_failed_commit(self) -> None:
        gate = Gate("after_lineage_head_update", fail=True)
        gate.release.set()
        with self.assertRaises(PromotionCommitError):
            self.go("A", gate)
        with self.uow() as u:
            events = [
                e
                for e in u.audit.list_for_candidate(self.candidate_of("A"))
                if e.event_type is AE.PROMOTION_FAILED
            ]
        self.assertEqual(
            [e.event_id for e in events],
            [ids.failure_event_id_for(DECISIONS["A"], "INFRASTRUCTURE")],
        )
        self.assertEqual(self.candidate_status(self.candidate_of("A")), "PROMOTABLE")


class TestGateAndRunner(unittest.TestCase):
    """The test machinery is itself checked: a gate ignores other points and acts once."""

    def test_a_gate_ignores_other_points_and_acts_once(self) -> None:
        gate = Gate("here", fail=True)
        gate("elsewhere")
        self.assertFalse(gate.reached.is_set())
        gate.release.set()
        with self.assertRaises(InjectedFault):
            gate("here")
        gate("here")  # one shot
        self.assertTrue(gate.reached.is_set())

    def test_a_runner_keeps_a_result_or_an_error(self) -> None:
        ok = Runner(lambda: 7)
        bad = Runner(lambda: 1 // 0)
        for runner in (ok, bad):
            runner.start()
            runner.join(10)
        self.assertEqual(ok.result, 7)
        self.assertIsInstance(bad.error, ZeroDivisionError)


if __name__ == "__main__":
    unittest.main()
