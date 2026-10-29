"""Properties of promoted history (P6b step 6; Doc 09 §26-§27, §38-§40; Doc 06 §6, §20-§21, §27;
Doc 11 §8, §44; C-41, C-45, C-163, C-164).

Seeded chains of decisions (stdlib ``random``; the seeds are fixed, so a run repeats exactly): each
chain starts from v0, makes a candidate whose INV-FUNC-001 result is drawn from PASS, FAIL, UNKNOWN
or ERROR, records the decision and commits a PROMOTE, sometimes commits it again, and goes on from
the new head until a decision is not a PROMOTE or the chain has three states.

HAND EXPECTATIONS (the rules, from the specs, written before the run):

* a PASS gives PROMOTE, FAIL gives REJECT, UNKNOWN gives RETRY, ERROR gives ESCALATE (Doc 09 §19,
  §20); only a PROMOTE changes ``trusted_states`` or ``lineage_heads``, and a non-PROMOTE changes
  neither, however often it is recorded (SM-003, SM-004);
* a committed state's references cover every invariant of its parent with no lower version (C-41);
* every reference of a promoted state carries the state's binding record, and the record is proof
  for that state (``usable_as_proof``, C-164);
* a state has at most one child, a decision commits at most one state, and ``commit_decision_id``
  is unique (C-163);
* replaying a decision (a second commit, a second record) changes no row of any table;
* ``check_database`` reports each of these rules when a database breaks it, and only then.
"""

from __future__ import annotations

import random
import unittest
from collections import Counter
from typing import Any

from core.domain.enums import CandidateStatus, DecisionType, VerificationResult
from core.domain.evidence import EvidenceContext
from core.promotion import ids
from core.promotion.commit import record_decision
from evidence.service import EvidenceService
from tests.domain_builders import uid
from tests.promotion_builders import ERROR, FAIL, FUNC1, PASS, UNKNOWN, make_world, run, target
from tests.promotion_commit_builders import CONTEXT, NOW, CommitCase, check_database, dump

SEEDS = 40
OUTCOMES = {
    PASS: DecisionType.PROMOTE,
    FAIL: DecisionType.REJECT,
    UNKNOWN: DecisionType.RETRY,
    ERROR: DecisionType.ESCALATE,
}
STATE_TABLES = ("trusted_states", "lineage_heads", "invariant_refs", "state_resources")
DECISION = uid(9100)


class TestChains(CommitCase):
    stored_status = CandidateStatus.ANALYZING

    def generation(self, g: int, head: Any, result: VerificationResult) -> tuple[Any, Any]:
        """The world and the evidence-id map of the g-th candidate of a chain."""
        if g == 0:
            if result is PASS:
                return self.world, self.evidence_ids
            return make_world(results={target(FUNC1): result}), self.evidence_ids
        world = self.next_world(head, sequence=g + 1, n=10 + g, func_result=result)
        self.store_candidate(world, n=10 + g, sequence=g + 1)
        return world, self.store_results(world, first=100 + 10 * g)

    def promoted_properties(self) -> None:
        with self.uow() as u:
            head = u.trusted_states.get_current(self.world.trusted.lineage_id)
            assert head is not None
            lineage = u.trusted_states.lineage(head.state_id)
            for child, parent in zip(lineage, lineage[1:], strict=False):
                held = {r.invariant_id: r.invariant_version for r in child.invariant_refs}
                for ref in parent.invariant_refs:
                    self.assertGreaterEqual(held.get(ref.invariant_id, 0), ref.invariant_version)
                assert child.commit_decision_id is not None
                binding = ids.evidence_id_for(child.commit_decision_id)
                context = EvidenceContext.state(child.state_id)
                for ref in child.invariant_refs:
                    self.assertIn(binding, ref.evidence_ids)
                self.assertIn(binding, child.evidence_refs)
                check = EvidenceService().usable_as_proof(u, binding, context)
                self.assertTrue(check.usable, check.reasons)
        self.assertEqual(check_database(self.path), [])

    def play(self, seed: int) -> Counter[str]:
        rng = random.Random(seed)
        seen: Counter[str] = Counter()
        head = self.world.trusted
        for g in range(3):
            result = rng.choices([PASS, FAIL, UNKNOWN, ERROR], weights=[6, 1.5, 1, 1.5])[0]
            world, evidence = self.generation(g, head, result)
            outcome = run(world, decision_id=uid(9400 + g))
            self.assertIs(outcome.decision.decision, OUTCOMES[result])
            seen[outcome.decision.decision.value] += 1
            before = dump(self.path)
            with self.uow() as u:
                record_decision(u, outcome, world.candidate, CONTEXT, now=NOW)
            if outcome.decision.decision is not DecisionType.PROMOTE:
                after = dump(self.path)
                for table in STATE_TABLES:
                    self.assertEqual(after[table], before[table], table)
                with self.uow() as u:
                    record_decision(u, outcome, world.candidate, CONTEXT, now=NOW)
                self.assertEqual(dump(self.path), after)  # recording it again writes nothing
                break
            committed = self.commit(world, outcome=outcome, evidence_ids=evidence)
            assert committed.state is not None
            head = committed.state
            if rng.random() < 0.5:
                settled = dump(self.path)
                again = self.commit(world, outcome=outcome, evidence_ids=evidence)
                self.assertTrue(again.duplicate)
                self.assertEqual(again.state, head)
                self.assertEqual(dump(self.path), settled)  # committing it again writes nothing
                seen["duplicate"] += 1
            self.promoted_properties()
            seen["promoted"] += 1
        seen[f"length {head.version}"] += 1
        return seen

    def test_seeded_chains_keep_every_rule(self) -> None:
        total: Counter[str] = Counter()
        for seed in range(SEEDS):
            with self.subTest(seed=seed):
                if seed:
                    self.tearDown()
                    self.setUp()
                total += self.play(seed)
        for kind in ("PROMOTE", "REJECT", "RETRY", "ESCALATE", "duplicate", "length 3"):
            self.assertGreater(total[kind], 0, f"no chain reached {kind}")


class TestTheCheckerFires(CommitCase):
    """Each rule of ``check_database`` is shown to fire when the database breaks it: a checker that
    cannot fail proves nothing."""

    def setUp(self) -> None:
        super().setUp()
        self.state = self.commit(outcome=run(self.world)).state
        assert self.state is not None
        self.v0 = self.world.trusted.state_id
        self.v1 = self.state.state_id
        self.binding = ids.evidence_id_for(DECISION)

    def corruptions(self) -> dict[str, tuple[str, str, tuple[Any, ...]]]:
        copy = (
            "INSERT INTO trusted_states (state_id, lineage_id, version, parent_state_id, "
            "state_hash, commit_decision_id, content_json) SELECT ?, lineage_id, ?, "
            "parent_state_id, state_hash, ?, content_json FROM trusted_states WHERE state_id = ?"
        )
        return {
            "the head is not the newest state": (
                "the head is not its newest state",
                "UPDATE lineage_heads SET current_state_id = ?",
                (self.v0,),
            ),
            "two children": (
                "2 children",
                copy,
                (uid(5001), 9, None, self.v1),
            ),
            "a decision that commits two states": (
                "commits 2 states",
                copy,
                (uid(5002), 9, DECISION, self.v1),
            ),
            "a state no decision names": (
                "no committed decision",
                "UPDATE promotion_decisions SET committed_state_id = NULL",
                (),
            ),
            "a decision that names a state that is not its own": (
                "committed to a state that is not its own",
                "UPDATE promotion_decisions SET committed_state_id = ?",
                (self.v0,),
            ),
            "a version that is not the parent's plus one": (
                "not its parent's plus one",
                "UPDATE trusted_states SET version = 5 WHERE state_id = ?",
                (self.v1,),
            ),
            "a baseline with a parent": (
                "a baseline with a parent or a decision",
                "UPDATE trusted_states SET parent_state_id = ? WHERE state_id = ?",
                (self.v1, self.v0),
            ),
            "a binding record that is not one": (
                "its binding record is",
                "UPDATE evidence_events SET event_name = 'x' WHERE evidence_id = ?",
                (self.binding,),
            ),
            "a reference without the binding record": (
                "a reference without the binding record",
                "UPDATE invariant_refs SET evidence_ids = '[]' WHERE state_id = ?",
                (self.v1,),
            ),
            "no STATE_PROMOTED event": (
                "0 STATE_PROMOTED events",
                "DELETE FROM audit_events WHERE event_type = 'STATE_PROMOTED'",
                (),
            ),
            "an invariant dropped": (
                "dropped or lowered",
                "DELETE FROM invariant_refs WHERE state_id = ? AND invariant_id = 'INV-SEC-002'",
                (self.v1,),
            ),
            "an orphan reference": (
                "orphan rows in invariant_refs",
                "INSERT INTO invariant_refs SELECT ?, invariant_id, invariant_version, status, "
                "origin, evidence_ids, last_verified_at, invalidated_by_candidate_id, "
                "invalidation_reason FROM invariant_refs WHERE state_id = ? LIMIT 1",
                (uid(5003), self.v1),
            ),
            "an orphan evidence record": (
                "orphan rows in evidence_events",
                "UPDATE evidence_events SET state_id = ? WHERE evidence_id = ?",
                (uid(5004), self.binding),
            ),
        }

    def test_the_database_is_clean_before_it_is_broken(self) -> None:
        self.assertEqual(check_database(self.path), [])

    def test_each_rule_fires_on_a_database_that_breaks_it(self) -> None:
        for index, (label, (expected, sql, params)) in enumerate(self.corruptions().items()):
            with self.subTest(rule=label):
                if index:
                    self.tearDown()
                    self.setUp()
                self.assertEqual(check_database(self.path), [])
                if "commits two" in label:  # the unique index would stop it; an attacker drops it
                    self.tamper("DROP INDEX uq_trusted_states_commit_decision", ())
                self.tamper(sql, params)
                found = check_database(self.path)
                self.assertTrue(any(expected in p for p in found), f"{expected!r} not in {found}")

    def test_a_promoted_candidate_without_a_committed_decision_fires(self) -> None:
        other, _ = self.rival()
        self.tamper(
            "UPDATE candidates SET status = 'PROMOTED' WHERE candidate_id = ?",
            (other.candidate.candidate_id,),
        )
        found = check_database(self.path)
        self.assertTrue(any("PROMOTED without a committed decision" in p for p in found), found)

    def test_a_dump_changes_when_anything_is_written(self) -> None:
        before = dump(self.path)
        self.assertEqual(dump(self.path), before)
        self.tamper("UPDATE candidates SET status_reason = 'x'", ())
        self.assertNotEqual(dump(self.path), before)


if __name__ == "__main__":
    unittest.main()
