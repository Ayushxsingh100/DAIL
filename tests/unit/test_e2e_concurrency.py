"""Two orchestrators on one database file (P6c step 5; Doc 09 §25, §39; Doc 12 §14 steps 10-11;
C-38, C-166, C-173; R5 of the P6c prompt).

Two candidates, both written against version 0, are evaluated by two ``EvaluationOrchestrator``
objects on two threads over one SQLite file. A ``Schedule`` decides in which order the threads pass
the stage checkpoints of the orchestrator (the test-only ``checkpoint`` hook), so every interleaving
is forced by the schedule, not by timing: nothing sleeps.

HAND EXPECTATIONS (Doc 09 §25, §39; CLAUDE.md canonical scenario; C-166):

* exactly one of the two is promoted, into version 1, parent version 0; the other is REJECTED with
  ``STALE_PARENT`` (kind STALE) and its candidate is REJECTED; Trusted State has exactly two states;
* a loser that read the state before the winner committed loses inside the commit (the PROMOTE it
  recorded stays beside the stored REJECT); a loser that started after the winner committed is
  rejected before any commit; both chains are complete (``problems() == []``);
* the structural rules of promoted history hold (``check_database``): one child per parent, the
  head is the newest state, every promoted state has its decision and its binding record.

The "schedules" are the deterministic ones named below and 24 random permutations seeded with the
numbers in ``SEEDS`` (the failing seed is in the subtest label).
"""

from __future__ import annotations

import random
import threading
import unittest
from typing import Any

from core.application.chain import describe_chain
from core.application.orchestrator import EvaluationResult, ResultKind
from core.domain.enums import CandidateStatus, DecisionType
from core.domain.promotion import DecisionReason
from tests.promotion_commit_builders import Runner, check_database
from tests.promotion_orchestrator_builders import PATCH_SAFE_DIR, OrchestratorCase

STAGE_POINTS = 8  # the checkpoints one full evaluation passes (a stale loser passes 7)
SEEDS = tuple(range(7000, 7024))
WAIT = 60.0


class Schedule:
    """The order in which two threads pass their checkpoints. ``order`` holds ``"A"`` and ``"B"``
    (a thread may pass its next checkpoint when its letter is first) and ``"A_done"``/``"B_done"``
    (consumed once that thread has finished). A thread whose partner has finished never waits."""

    def __init__(self, order: list[str]) -> None:
        self.order = list(order)
        self.done: set[str] = set()
        self.cv = threading.Condition()

    def _ready(self, who: str) -> bool:
        other = "B" if who == "A" else "A"
        while self.order and self.order[0].endswith("_done") and self.order[0][0] in self.done:
            self.order.pop(0)
        return not self.order or self.order[0] == who or other in self.done

    def hook(self, who: str) -> Any:
        def passage(name: str) -> None:
            del name
            with self.cv:
                if not self.cv.wait_for(lambda: self._ready(who), timeout=WAIT):
                    raise TimeoutError(f"{who} waited for its turn: {self.order[:6]}")
                if self.order and self.order[0] == who:
                    self.order.pop(0)
                self.cv.notify_all()

        return passage

    def finished(self, who: str) -> None:
        with self.cv:
            self.done.add(who)
            self.cv.notify_all()


def random_order(seed: int) -> list[str]:
    order = ["A"] * STAGE_POINTS + ["B"] * STAGE_POINTS
    random.Random(seed).shuffle(order)
    return order


class RaceCase(OrchestratorCase):
    def race(self, order: list[str]) -> tuple[EvaluationResult, EvaluationResult]:
        v0 = self.baseline().state
        schedule = Schedule(order)
        requests = {
            "A": self.request(v0, PATCH_SAFE_DIR, n=1),
            "B": self.request(v0, PATCH_SAFE_DIR, n=2),
        }

        def work(who: str) -> Any:
            def run() -> EvaluationResult:
                try:
                    return self.orchestrator(checkpoint=schedule.hook(who)).evaluate(requests[who])
                finally:
                    schedule.finished(who)

            return run

        runners = {who: Runner(work(who)) for who in ("A", "B")}
        for runner in runners.values():
            runner.start()
        for runner in runners.values():
            runner.join(WAIT * 2)
            self.assertFalse(runner.is_alive(), "a thread never finished")
        for who, runner in runners.items():
            self.assertIsNone(runner.error, f"{who}: {runner.error!r}")
        return runners["A"].result, runners["B"].result

    def assert_one_winner(self, a: EvaluationResult, b: EvaluationResult) -> None:
        kinds = sorted(r.kind.value for r in (a, b))
        self.assertEqual(kinds, sorted([ResultKind.PROMOTED.value, ResultKind.STALE.value]))
        winner, loser = (a, b) if a.kind is ResultKind.PROMOTED else (b, a)
        assert winner.state is not None and loser.decision is not None
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(self.current(), winner.state)
        self.assertEqual(winner.state.version, 1)
        self.assertIs(loser.decision.decision, DecisionType.REJECT)
        self.assertIs(loser.decision.reason, DecisionReason.STALE_PARENT)
        self.assertIsNone(loser.state)
        self.assertEqual(self.count("promotion_decisions", "committed_state_id IS NOT NULL"), 1)
        self.assertEqual(check_database(self.path), [])
        with self.uow() as u:
            for result in (winner, loser):
                self.assertEqual(
                    describe_chain(u, result.candidate.candidate_id).problems(),
                    [],
                    result.kind.value,
                )
            for result, status in (
                (winner, CandidateStatus.PROMOTED),
                (loser, CandidateStatus.REJECTED),
            ):
                stored = u.candidates.get(result.candidate.candidate_id)
                assert stored is not None
                self.assertIs(stored.status, status)


class TestNamedInterleavings(RaceCase):
    def test_one_runs_to_the_end_before_the_other_starts(self) -> None:
        a, b = self.race(["A"] * STAGE_POINTS + ["B"] * STAGE_POINTS)
        self.assert_one_winner(a, b)
        self.assertIs(a.kind, ResultKind.PROMOTED)
        # the late one never asked for a commit: it was rejected before any request
        with self.uow() as u:
            types = [
                e.event_type.value for e in u.audit.list_for_candidate(b.candidate.candidate_id)
            ]
        self.assertNotIn("PROMOTION_REQUESTED", types)
        self.assertNotIn("STATE_PROMOTED", types)

    def test_the_other_way_round(self) -> None:
        a, b = self.race(["B"] * STAGE_POINTS + ["A"] * STAGE_POINTS)
        self.assert_one_winner(a, b)
        self.assertIs(b.kind, ResultKind.PROMOTED)

    def test_both_read_version_zero_and_the_second_loses_inside_its_commit(self) -> None:
        """Both pass every stage and both ask for the commit; B commits only after A has finished,
        so B read version 0, decided PROMOTE, and loses the race inside ``commit_promotion``."""
        order = ["A", "B"] * (STAGE_POINTS - 1) + ["A", "A_done", "B"]
        a, b = self.race(order)
        self.assert_one_winner(a, b)
        self.assertIs(a.kind, ResultKind.PROMOTED)
        with self.uow() as u:
            chain = describe_chain(u, b.candidate.candidate_id)
        self.assertEqual(
            [t for t in chain.event_types() if t.startswith("PROMOTION")],
            ["PROMOTION_DECIDED", "PROMOTION_REQUESTED", "PROMOTION_DECIDED"],
        )
        self.assertEqual(len(chain.decisions), 2)  # its PROMOTE, and the stored REJECT beside it

    def test_both_commit_at_the_same_time(self) -> None:
        order = ["A", "B"] * STAGE_POINTS
        a, b = self.race(order)
        self.assert_one_winner(a, b)


class TestSeededSchedules(RaceCase):
    def test_every_schedule_ends_with_one_promotion_and_one_stale_rejection(self) -> None:
        inside, before = 0, 0
        for seed in SEEDS:
            with self.subTest(seed=seed):
                self.fresh_database()
                a, b = self.race(random_order(seed))
                self.assert_one_winner(a, b)
                loser = b if a.kind is ResultKind.PROMOTED else a
                with self.uow() as u:
                    types = [
                        e.event_type.value
                        for e in u.audit.list_for_candidate(loser.candidate.candidate_id)
                    ]
                if "PROMOTION_REQUESTED" in types:
                    inside += 1
                else:
                    before += 1
        # the schedules are not all alike: they reach a loser that was rejected before it asked for
        # a commit, and one that lost inside the commit
        self.assertGreater(inside, 0)
        self.assertGreater(before, 0)


if __name__ == "__main__":
    unittest.main()
