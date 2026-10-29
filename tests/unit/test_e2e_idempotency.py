"""Idempotency and crash windows of ``evaluate`` (P6c step 5; Doc 09 §26, §38-§39, Appendix B;
Doc 11 §38; C-38, C-163, C-166, C-170 (4), (5), (7)).

HAND EXPECTATIONS (the prompt's C-170 (5) and (7), P6b's contract):

* a second ``evaluate`` with an equal request writes nothing and returns the stored outcome; a
  committed promotion comes back as ``DUPLICATE`` with the same state; this holds when the second
  call is made by another orchestrator whose clock reads another time (everything that is hashed
  uses the candidate's own instant, so a rerun with a real clock is not a conflict);
* an exception injected after any stage leaves every record written so far valid
  (``problems(finished=False) == []``, ``check_database`` clean) and does not change Trusted State;
  a rerun completes and exactly one new state exists;
* a crash between ``record_decision`` and the commit leaves a PROMOTABLE candidate and the rerun
  commits it;
* a failure at the commit of the n-th unit of work, for every n, is recoverable the same way;
* a failure inside the promotion's own transaction raises ``PromotionCommitError`` (P6b), leaves the
  candidate PROMOTABLE and no new state, and the same request then commits.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from core.application.chain import describe_chain
from core.application.orchestrator import EvaluationRequest, ResultKind
from core.domain.enums import CandidateStatus
from core.domain.errors import PersistenceError
from core.promotion.commit import PromotionCommitError
from core.verification.dispatch import DEFAULT_VERIFIERS, REACHABILITY_CFG
from tests.pipeline_builders import fixed_clock
from tests.promotion_commit_builders import Gate, InjectedFault, check_database, dump
from tests.promotion_orchestrator_builders import (
    PATCH_REGRESSION_DIR,
    PATCH_SAFE_DIR,
    OrchestratorCase,
    config_with,
)
from tests.promotion_pipeline import failing_reachability
from tests.unit.test_orchestrator import unknown

STAGES = (
    "after_candidate",
    "after_build",
    "after_identity",
    "after_dependency",
    "after_impact",
    "after_verification",
    "after_decision",
    "after_request",
)


class Stop(Exception):
    """An exception put into a stage on purpose."""


def stop_after(point: str) -> Any:
    def hook(name: str) -> None:
        if name == point:
            raise Stop(point)

    return hook


class IdempotencyCase(OrchestratorCase):
    def chain_problems(self, request: EvaluationRequest, *, finished: bool = True) -> list[str]:
        """The problems of the candidate's chain; none while nothing about it has been written."""
        with self.uow() as u:
            if u.candidates.get(request.candidate_id) is None:
                return []
            return describe_chain(u, request.candidate_id).problems(finished=finished)

    def scenarios(self) -> list[tuple[str, EvaluationRequest, dict[str, Any]]]:
        v0 = self.baseline().state
        broken = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (broken / "main.tf").write_text('resource "aws_instance" "x" {{{\n', encoding="utf-8")
        return [
            ("promote", self.request(v0, PATCH_SAFE_DIR, n=1), {}),
            ("reject", self.request(v0, PATCH_REGRESSION_DIR, n=2), {}),
            (
                "retry",
                self.request(v0, PATCH_SAFE_DIR, n=3),
                {"verifiers": {**DEFAULT_VERIFIERS, REACHABILITY_CFG: unknown}},
            ),
            (
                "verifier error",
                self.request(v0, PATCH_SAFE_DIR, n=4),
                {"verifiers": {**DEFAULT_VERIFIERS, REACHABILITY_CFG: failing_reachability}},
            ),
            ("construction failure", self.request(v0, broken, n=5), {}),
        ]


class TestEvaluateTwice(IdempotencyCase):
    def test_the_second_call_writes_nothing_and_returns_the_stored_outcome(self) -> None:
        for name, request, options in self.scenarios():
            with self.subTest(scenario=name):
                first = self.evaluate(request, **options)
                before = dump(self.path)
                second = self.evaluate(request, **options)
                self.assertEqual(dump(self.path), before)
                self.assertTrue(second.duplicate)
                self.assertEqual(second.decision, first.decision)
                self.assertEqual(second.state, first.state)
                self.assertEqual(second.candidate, first.candidate)
                expected = ResultKind.DUPLICATE if first.state is not None else first.kind
                self.assertIs(second.kind, expected)

    def test_another_orchestrator_with_another_clock_is_still_a_duplicate(self) -> None:
        for name, request, options in self.scenarios():
            with self.subTest(scenario=name):
                self.evaluate(request, clock=fixed_clock(10), **options)
                before = dump(self.path)
                again = self.evaluate(request, clock=fixed_clock(5000), **options)
                self.assertTrue(again.duplicate)
                self.assertEqual(dump(self.path), before)

    def test_a_stale_rejection_again_is_a_duplicate(self) -> None:
        v0 = self.baseline().state
        late = self.request(v0, PATCH_SAFE_DIR, n=2)
        self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=1))
        first = self.evaluate(late)
        before = dump(self.path)
        second = self.evaluate(late, clock=fixed_clock(999))
        self.assertIs(first.kind, ResultKind.STALE)
        self.assertIs(second.kind, ResultKind.STALE)
        self.assertTrue(second.duplicate)
        self.assertEqual(dump(self.path), before)

    def test_the_switch_off_escalation_again_is_a_duplicate(self) -> None:
        self.automatic_enabled = False
        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)
        first = self.evaluate(request)
        before = dump(self.path)
        again = self.evaluate(request)
        self.assertIs(first.kind, ResultKind.ESCALATED)
        self.assertTrue(again.duplicate)
        self.assertEqual(dump(self.path), before)

    def test_turning_the_switch_on_does_not_reopen_an_escalated_candidate(self) -> None:
        """The stored decision is the decision: the candidate stays ESCALATED, no state appears."""
        self.automatic_enabled = False
        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)
        self.evaluate(request)
        again = self.evaluate(request, config=config_with(True))
        self.assertIs(again.kind, ResultKind.ESCALATED)
        self.assertEqual(self.count("trusted_states"), 1)


class TestACrashAfterEachStage(IdempotencyCase):
    def test_every_stage_boundary_is_recoverable(self) -> None:
        for point in STAGES:
            with self.subTest(after=point):
                self.fresh_database()
                v0 = self.baseline().state
                request = self.request(v0, PATCH_SAFE_DIR)
                with self.assertRaises(Stop):
                    self.evaluate(request, checkpoint=stop_after(point))
                self.assertEqual(check_database(self.path), [])
                self.assertEqual(self.chain_problems(request, finished=False), [])
                stored = self.read_candidate(request.candidate_id)
                assert stored is not None
                if point in ("after_decision", "after_request"):
                    self.assertIs(stored.status, CandidateStatus.PROMOTABLE)
                    self.assertEqual(self.current(), v0)
                    self.assertEqual(self.count("promotion_decisions"), 1)
                else:
                    self.assertIn(
                        stored.status,
                        (CandidateStatus.BUILDING, CandidateStatus.ANALYZING),
                    )
                self.assertEqual(self.current(), v0)
                self.assertEqual(self.count("trusted_states"), 1)
                done = self.evaluate(request)
                self.assertIs(done.kind, ResultKind.PROMOTED)
                self.assertEqual(self.count("trusted_states"), 2)
                self.assertEqual(self.chain_problems(request), [])
                self.assertEqual(check_database(self.path), [])

    def test_a_crash_after_the_decision_leaves_a_promotable_candidate_the_rerun_commits(
        self,
    ) -> None:
        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)
        with self.assertRaises(Stop):
            self.evaluate(request, checkpoint=stop_after("after_decision"))
        stored = self.read_candidate(request.candidate_id)
        assert stored is not None
        self.assertIs(stored.status, CandidateStatus.PROMOTABLE)
        done = self.evaluate(request)
        assert done.state is not None
        self.assertEqual(done.state.parent_state_id, v0.state_id)
        self.assertEqual(self.count("trusted_states"), 2)

    def test_a_crash_after_a_non_promote_decision_is_a_duplicate_on_rerun(self) -> None:
        v0 = self.baseline().state
        request = self.request(v0, PATCH_REGRESSION_DIR)
        with self.assertRaises(Stop):
            self.evaluate(request, checkpoint=stop_after("after_decision"))
        before = dump(self.path)
        again = self.evaluate(request)
        self.assertIs(again.kind, ResultKind.REJECTED)
        self.assertTrue(again.duplicate)
        self.assertEqual(dump(self.path), before)

    def test_a_crash_while_the_candidate_is_stale_is_recoverable(self) -> None:
        v0 = self.baseline().state
        late = self.request(v0, PATCH_SAFE_DIR, n=2)
        self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=1))
        with self.assertRaises(Stop):
            self.evaluate(late, checkpoint=stop_after("after_verification"))
        done = self.evaluate(late)
        self.assertIs(done.kind, ResultKind.STALE)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(self.chain_problems(late), [])

    def read_candidate(self, candidate_id: str) -> Any:
        with self.uow() as u:
            return u.candidates.get(candidate_id)


class Counter:
    """A database checkpoint that counts the commits of units of work and fails the n-th, once."""

    def __init__(self, fail_at: int | None = None) -> None:
        self.fail_at = fail_at
        self.seen = 0

    def __call__(self, name: str) -> None:
        if name != "before_commit":
            return
        self.seen += 1
        if self.fail_at == self.seen:
            raise InjectedFault(f"commit {self.seen}")


class TestAFailureAtEveryCommit(IdempotencyCase):
    def test_a_failure_at_the_n_th_commit_is_recoverable_for_every_n(self) -> None:
        self.fresh_database()
        v0 = self.baseline().state
        counter = Counter()
        self.evaluate(self.request(v0, PATCH_SAFE_DIR), db_checkpoint=counter)
        total = counter.seen
        self.assertGreaterEqual(total, 10, "an evaluation opens many units of work")
        for n in range(1, total + 1):
            with self.subTest(commit=n, of=total):
                self.fresh_database()
                v0 = self.baseline().state
                request = self.request(v0, PATCH_SAFE_DIR)
                with self.assertRaises((InjectedFault, PersistenceError, PromotionCommitError)):
                    self.evaluate(request, db_checkpoint=Counter(fail_at=n))
                self.assertEqual(check_database(self.path), [])
                self.assertEqual(self.chain_problems(request, finished=False), [])
                done = self.evaluate(request)
                self.assertIn(done.kind, (ResultKind.PROMOTED, ResultKind.DUPLICATE))
                self.assertEqual(self.count("trusted_states"), 2)
                self.assertEqual(self.chain_problems(request), [])
                self.assertEqual(check_database(self.path), [])


class TestAFailureInsideThePromotion(IdempotencyCase):
    POINTS = (
        "after_trusted_state_insert",
        "after_invariant_refs_insert",
        "after_lineage_head_update",
        "after_decision_commit",
    )

    def test_the_promotion_is_atomic_and_the_same_request_then_commits(self) -> None:
        for point in self.POINTS:
            with self.subTest(point=point):
                self.fresh_database()
                v0 = self.baseline().state
                request = self.request(v0, PATCH_SAFE_DIR)
                gate = Gate(point, fail=True)
                gate.release.set()
                with self.assertRaises(PromotionCommitError):
                    self.evaluate(request, db_checkpoint=gate)
                self.assertTrue(gate.fired)
                self.assertEqual(self.current(), v0)
                self.assertEqual(self.count("trusted_states"), 1)
                stored = self.read_candidate_status(request.candidate_id)
                self.assertEqual(stored, CandidateStatus.PROMOTABLE.value)
                self.assertEqual(check_database(self.path), [])
                done = self.evaluate(request)
                self.assertIs(done.kind, ResultKind.PROMOTED)
                self.assertEqual(self.count("trusted_states"), 2)
                self.assertEqual(self.chain_problems(request, finished=True), [])

    def read_candidate_status(self, candidate_id: str) -> str:
        return str(
            self.scalar("SELECT status FROM candidates WHERE candidate_id = ?", (candidate_id,))
        )


if __name__ == "__main__":
    unittest.main()
