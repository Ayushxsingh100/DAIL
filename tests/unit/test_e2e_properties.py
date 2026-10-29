"""Seeded properties of ``evaluate`` over random sequences of candidates (P6c step 5; Doc 09 §26,
§39; Doc 15 §13.3; stdlib ``random`` only).

For each seed a lineage starts from the canonical baseline and then 1 to 4 candidates are evaluated
in turn; each is a randomly chosen fixture configuration (the 18 fixtures with a parent), written
against the state that is current when it is evaluated, with a random attempt number 1 to 4.

PROPERTIES, each from the P6c prompt and Doc 15 §13.3 ("no unsafe candidate can advance Trusted
State, and a valid candidate can advance exactly once"):

* **lineage**: the trusted states are a chain with no gap (versions 0 to k, each the child of the
  previous, one head);
* **non-promotion**: an evaluation that does not end in a promotion changes no row of
  ``trusted_states`` and no lineage head; a promotion appends exactly one;
* **chains**: the chain of every evaluated candidate is complete (``problems() == []``);
* **replay**: evaluating the same requests again, in order, by another orchestrator, writes nothing;
* **switch**: with ``promotion.automatic_enabled`` false no candidate is ever promoted.

``TestTheCheckersFire`` shows that each property's checker fails on a database or a pair of dumps
that breaks it, so a checker that can no longer fail is itself caught.
"""

from __future__ import annotations

import random
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any

from core.application.chain import describe_chain
from core.application.orchestrator import EvaluationRequest, EvaluationResult, ResultKind
from tests.pipeline_builders import fixed_clock
from tests.promotion_commit_builders import check_database, dump
from tests.promotion_orchestrator_builders import (
    PATCH_SAFE_DIR,
    OrchestratorCase,
)
from tests.promotion_pipeline import ROOT, fixtures_with_a_parent

SEEDS = (11, 12, 13, 14, 15, 16)
SWITCH_OFF_SEEDS = (21, 22, 23)


def lineage_problems(path: str | Path) -> list[str]:
    """The trusted states form a chain with no gap and one head per lineage."""
    problems: list[str] = []
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute(
            "SELECT lineage_id, version, state_id, parent_state_id FROM trusted_states "
            "ORDER BY lineage_id, version"
        ).fetchall()
        heads = dict(conn.execute("SELECT lineage_id, current_state_id FROM lineage_heads"))
    by_lineage: dict[str, list[tuple[Any, ...]]] = {}
    for row in rows:
        by_lineage.setdefault(row[0], []).append(row)
    for lineage, states in by_lineage.items():
        if [s[1] for s in states] != list(range(len(states))):
            problems.append(f"{lineage}: versions {[s[1] for s in states]} have a gap")
        for before, after in zip(states, states[1:], strict=False):
            if after[3] != before[2]:
                problems.append(f"{lineage}: version {after[1]} is not the child of {before[1]}")
        if heads.get(lineage) != states[-1][2]:
            problems.append(f"{lineage}: the head is not the newest state")
    return problems


def trusted_rows(path: str | Path) -> list[tuple[Any, ...]]:
    with closing(sqlite3.connect(path)) as conn:
        return [
            tuple(r) for r in conn.execute("SELECT * FROM trusted_states ORDER BY rowid").fetchall()
        ] + [tuple(r) for r in conn.execute("SELECT * FROM lineage_heads ORDER BY rowid")]


def promotion_delta_problems(
    before: list[tuple[Any, ...]], after: list[tuple[Any, ...]], promoted: bool
) -> list[str]:
    """A non-promotion changes nothing; a promotion adds one state and moves the head."""
    if not promoted:
        return [] if before == after else ["trusted state changed without a promotion"]
    new_states = [row for row in after if row not in before]
    gone = [row for row in before if row not in after]
    # one new state row, and the head row replaced by one that names it
    heads_moved = len(gone) == 1 and len(new_states) == 2
    return [] if heads_moved else [f"a promotion changed {len(new_states)} rows, lost {len(gone)}"]


class PropertyCase(OrchestratorCase):
    def sequence(self, seed: int) -> list[tuple[EvaluationRequest, EvaluationResult]]:
        """Run one seeded sequence, checking the per-step properties as it goes."""
        rng = random.Random(seed)
        self.fresh_database()
        self.baseline()
        fixtures = list(fixtures_with_a_parent().values())
        done: list[tuple[EvaluationRequest, EvaluationResult]] = []
        for step in range(rng.randint(1, 4)):
            fixture = rng.choice(fixtures)
            attempt = rng.randint(1, 4)
            request = self.request(
                self.current(), ROOT / fixture.data["config"], n=step + 1, attempt=attempt
            )
            before = trusted_rows(self.path)
            result = self.evaluate(request)
            promoted = result.kind is ResultKind.PROMOTED
            self.assertEqual(
                promotion_delta_problems(before, trusted_rows(self.path), promoted),
                [],
                f"seed {seed}, step {step}, {fixture.data['fixture_id']}: {result.kind}",
            )
            done.append((request, result))
        return done

    def chains_are_complete(self, done: list[tuple[EvaluationRequest, EvaluationResult]]) -> None:
        with self.uow() as u:
            for request, _ in done:
                self.assertEqual(describe_chain(u, request.candidate_id).problems(), [])


class TestRandomSequences(PropertyCase):
    def test_the_properties_hold_for_every_seed(self) -> None:
        kinds: set[ResultKind] = set()
        promotions = 0
        for seed in SEEDS:
            with self.subTest(seed=seed):
                done = self.sequence(seed)
                self.assertEqual(lineage_problems(self.path), [])
                self.assertEqual(check_database(self.path), [])
                self.chains_are_complete(done)
                promotions += sum(1 for _, r in done if r.kind is ResultKind.PROMOTED)
                self.assertEqual(self.count("trusted_states"), 1 + promotions_in(done))
                kinds |= {r.kind for _, r in done}
        # the seeds reach more than one kind of ending and at least one promotion
        self.assertGreater(len(kinds), 1, kinds)
        self.assertGreater(promotions, 0)

    def test_replaying_the_requests_changes_nothing(self) -> None:
        for seed in SEEDS:
            with self.subTest(seed=seed):
                done = self.sequence(seed)
                before = dump(self.path)
                for request, first in done:
                    again = self.evaluate(request, clock=fixed_clock(900))
                    self.assertTrue(again.duplicate, (request.candidate_id, first.kind))
                self.assertEqual(dump(self.path), before)

    def test_a_promotion_happens_at_most_once_per_candidate(self) -> None:
        for seed in SEEDS:
            with self.subTest(seed=seed):
                done = self.sequence(seed)
                self.assertEqual(
                    self.count("promotion_decisions", "committed_state_id IS NOT NULL"),
                    promotions_in(done),
                )


class TestWithTheSwitchOff(PropertyCase):
    automatic_enabled = False

    def test_nothing_is_ever_promoted(self) -> None:
        for seed in SWITCH_OFF_SEEDS:
            with self.subTest(seed=seed):
                done = self.sequence(seed)
                self.assertEqual(self.count("trusted_states"), 1)
                self.assertNotIn(ResultKind.PROMOTED, {r.kind for _, r in done})
                self.assertEqual(lineage_problems(self.path), [])
                self.chains_are_complete(done)


def promotions_in(done: list[tuple[EvaluationRequest, EvaluationResult]]) -> int:
    return sum(1 for _, result in done if result.kind is ResultKind.PROMOTED)


class TestTheCheckersFire(OrchestratorCase):
    """Each property's checker, shown to fail where its rule is broken."""

    def promoted_database(self) -> None:
        v0 = self.baseline().state
        self.evaluate(self.request(v0, PATCH_SAFE_DIR))

    def test_the_lineage_checker_finds_a_gap(self) -> None:
        self.promoted_database()
        self.assertEqual(lineage_problems(self.path), [])
        self.tamper("UPDATE trusted_states SET version = 2 WHERE version = 1")
        self.assertTrue(any("gap" in p for p in lineage_problems(self.path)))

    def test_the_lineage_checker_finds_a_broken_parent_link(self) -> None:
        self.promoted_database()
        self.tamper("UPDATE trusted_states SET parent_state_id = state_id WHERE version = 1")
        self.assertTrue(any("child" in p for p in lineage_problems(self.path)))

    def test_the_lineage_checker_finds_a_head_that_is_not_the_newest_state(self) -> None:
        self.promoted_database()
        self.tamper(
            "UPDATE lineage_heads SET current_state_id = "
            "(SELECT state_id FROM trusted_states WHERE version = 0)"
        )
        self.assertTrue(any("head" in p for p in lineage_problems(self.path)))

    def test_the_delta_checker_finds_a_change_without_a_promotion(self) -> None:
        self.promoted_database()
        after = trusted_rows(self.path)
        self.assertEqual(promotion_delta_problems(after, after, False), [])
        shorter = after[:1]
        self.assertTrue(promotion_delta_problems(shorter, after, False))

    def test_the_delta_checker_finds_a_promotion_that_changed_nothing_or_too_much(self) -> None:
        self.promoted_database()
        after = trusted_rows(self.path)
        self.assertTrue(promotion_delta_problems(after, after, True))
        self.assertEqual(promotion_delta_problems(after[:1] + after[2:], after, True) != [], True)

    def test_the_chain_checker_finds_a_deleted_event(self) -> None:
        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)
        self.evaluate(request)
        with self.uow() as u:
            self.assertEqual(describe_chain(u, request.candidate_id).problems(), [])
        self.tamper("DELETE FROM audit_events WHERE event_type = 'IMPACT_COMPLETED'")
        with self.uow() as u:
            self.assertTrue(describe_chain(u, request.candidate_id).problems())

    def test_the_replay_check_finds_a_write(self) -> None:
        self.promoted_database()
        before = dump(self.path)
        self.tamper(
            "INSERT INTO lineage_heads VALUES ('99999999-9999-9999-9999-999999999999', 'x')"
        )
        self.assertNotEqual(dump(self.path), before)


if __name__ == "__main__":
    unittest.main()
