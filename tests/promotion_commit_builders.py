"""Builders for the commit tests (P6b steps 5 and 6). Not a test module.

``CommitCase`` stores the canonical world of ``tests/promotion_builders.py`` in a real SQLite file:
the four registry definitions, the baseline v0 (with evidence bound to it), and the candidate walked
to ANALYZING or PROMOTABLE. It also stores the evidence of every verification result the way the
verification engine's ``to_evidence_submission`` does (candidate-bound, with the candidate's hash),
which P6c's orchestrator will do in production, and gives the commit a factory that opens units of
work on the file (with an optional fault-injection checkpoint).
"""

from __future__ import annotations

import dataclasses
import sqlite3
import threading
from collections import Counter
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any

from core.domain.enums import CandidateStatus
from core.domain.repositories import UnitOfWork
from core.domain.state import CandidateState, TrustedState, transition_candidate
from core.promotion import ids
from core.promotion.commit import CommitResult, PromotionContext, commit_promotion
from core.verification.engine import to_evidence_submission
from tests.domain_builders import at, patch_for, uid
from tests.persistence_builders import RepoCase, seed_evidence, stages
from tests.promotion_builders import (
    BASELINE_ITEM,
    FUNC1,
    SEC1,
    SEC2,
    SEC3,
    World,
    impact_for,
    make_world,
    record,
    report_of,
    run,
    target,
)

CONTEXT = PromotionContext(
    run_id=uid(0x7A01),
    correlation_id=uid(0x7A02),
    operation_id=uid(0x7A03),
    attempt_id=uid(0x7A04),
    actor_id=None,
)
NOW = at(30)


class CommitCase(RepoCase):
    """A database holding a baseline and the PROMOTABLE candidate of ``make_world()``."""

    stored_status = CandidateStatus.PROMOTABLE

    def setUp(self) -> None:
        super().setUp()
        self.world: World = make_world(candidate_status=self.stored_status)
        self.install(self.world)
        self.evidence_ids: dict[str, str] = self.store_results(self.world)

    # --- installing a world --------------------------------------------------------------------

    def install(self, world: World, *, n: int = 1) -> None:
        """Register the definitions, store the baseline and walk the candidate."""
        with self.uow() as u:
            for definition in world.definitions.values():
                u.invariants.register_definition(definition)
            self.seeded_evidence += seed_evidence(u, world.trusted, bound=True)
            u.trusted_states.save_baseline(world.trusted)
        self.store_candidate(world, n=n)

    def store_candidate(self, world: World, *, n: int = 1, sequence: int = 1) -> CandidateState:
        upto = 4 if world.candidate.status is CandidateStatus.PROMOTABLE else 3
        steps = stages(world.trusted, list(world.candidate.resources), n=n, sequence=sequence)
        with self.uow() as u:
            u.patches.save(patch_for(world.trusted, n=n))
            u.candidates.create(steps[0])
            for step in steps[1 : upto + 1]:
                u.candidates.save_transition(step)
        assert steps[upto].candidate_id == world.candidate.candidate_id
        assert steps[upto].state_hash == world.candidate.state_hash
        return steps[upto]

    def store_results(self, world: World, *, first: int = 0) -> dict[str, str]:
        """The evidence record of every verification result, by verification id."""
        found: dict[str, str] = {}
        with self.uow() as u:
            for index, result in enumerate(world.verification.results, start=first):
                evidence_id = uid(8800 + index)
                u.evidence.append(
                    to_evidence_submission(
                        result,
                        evidence_id=evidence_id,
                        run_id=CONTEXT.run_id,
                        attempt_id=CONTEXT.attempt_id,
                        correlation_id=CONTEXT.correlation_id,
                        operation_id=CONTEXT.operation_id,
                        parent_state_id=world.trusted.state_id,
                    )
                )
                found[result.verification_id] = evidence_id
        return found

    # --- committing ----------------------------------------------------------------------------

    def factory(self, checkpoint: Callable[[str], None] | None = None) -> Callable[[], UnitOfWork]:
        return lambda: self.uow(checkpoint=checkpoint)

    def commit(
        self,
        world: World | None = None,
        *,
        outcome: Any = None,
        checkpoint: Callable[[str], None] | None = None,
        evidence_ids: dict[str, str] | None = None,
        opener: Callable[[], UnitOfWork] | None = None,
        **options: Any,
    ) -> CommitResult:
        chosen = world or self.world
        return commit_promotion(
            opener or self.factory(checkpoint),
            outcome or run(chosen),
            chosen.candidate,
            chosen.impact,
            chosen.verification,
            chosen.policy,
            self.evidence_ids if evidence_ids is None else evidence_ids,
            CONTEXT,
            now=NOW,
            **options,
        )

    # --- reading -------------------------------------------------------------------------------

    def current(self) -> TrustedState:
        with self.uow() as u:
            state = u.trusted_states.get_current(self.world.trusted.lineage_id)
        assert state is not None
        return state

    def candidate_status(self, candidate_id: str | None = None) -> str:
        return self.scalar(
            "SELECT status FROM candidates WHERE candidate_id = ?",
            (candidate_id or self.world.candidate.candidate_id,),
        )

    def audit_types(self) -> list[str]:
        with self.uow() as u:
            events = u.audit.list_for_candidate(self.world.candidate.candidate_id)
        return [e.event_type.value for e in events]

    def next_world(self, state: TrustedState, *, sequence: int = 2, n: int = 2) -> World:
        """A second candidate from ``state`` (a promoted state): INV-FUNC-001 is affected, the other
        three are unaffected with eligible evidence."""
        from tests.domain_builders import analyzing_candidate, canonical_resources

        candidate = analyzing_candidate(
            state,
            canonical_resources(ssh_open=False, db_path=True),
            sequence=sequence,
            n=n,
        )
        candidate = dataclasses.replace(candidate) if False else candidate
        impact = impact_for(state, candidate, affected=(FUNC1,), carry=(SEC1, SEC2, SEC3))
        definition = self.world.definitions[FUNC1]
        records = [
            record(candidate, "STRUCTURAL", n=1),
            record(candidate, "CONSISTENCY", n=2),
            record(candidate, target(FUNC1), definition=definition, n=3),
            record(candidate, BASELINE_ITEM, n=4),
        ]
        return dataclasses.replace(
            self.world,
            trusted=state,
            candidate=candidate,
            impact=impact,
            verification=report_of(candidate, records),
            records={r.target_id: r for r in records},
        )

    def rival(
        self, *, sequence: int = 2, n: int = 2, first: int = 40
    ) -> tuple[World, dict[str, str]]:
        """A second PROMOTABLE candidate of the same parent, stored beside the first, with its
        verification evidence; returns its world and its own ``verification_id -> evidence_id``
        map (kept apart from ``self.evidence_ids``, because two candidates' results can share a
        verification id)."""
        from tests.domain_builders import analyzing_candidate, canonical_resources

        trusted = self.world.trusted
        analyzing = analyzing_candidate(
            trusted, canonical_resources(ssh_open=False, db_path=True), sequence=sequence, n=n
        )
        promotable = transition_candidate(analyzing, CandidateStatus.PROMOTABLE)
        definitions = self.world.definitions
        records = [
            record(promotable, "STRUCTURAL", n=1),
            record(promotable, "CONSISTENCY", n=2),
            record(promotable, target(SEC1), definition=definitions[SEC1], n=3),
            record(promotable, target(FUNC1), definition=definitions[FUNC1], n=4),
            record(promotable, BASELINE_ITEM, n=5),
        ]
        world = dataclasses.replace(
            self.world,
            candidate=promotable,
            impact=impact_for(trusted, promotable, affected=(SEC1, FUNC1), carry=(SEC2, SEC3)),
            verification=report_of(promotable, records),
            records={r.target_id: r for r in records},
        )
        self.store_candidate(world, n=n, sequence=sequence)
        return world, self.store_results(world, first=first)


# --- threads that meet at a checkpoint ----------------------------------------------------------


class InjectedFault(RuntimeError):
    """A failure put into a commit on purpose."""


class Gate:
    """A checkpoint hook that stops its thread the first time it reaches one named checkpoint,
    until released, and then either goes on or raises ``InjectedFault``. It acts once: later
    transactions of the same commit (the failure event) pass through. Nothing sleeps: the thread
    waits on an event."""

    def __init__(self, point: str | None, *, fail: bool = False, wait: float = 60.0) -> None:
        self.point = point
        self.fail = fail
        self.wait = wait
        self.fired = False
        self.reached = threading.Event()
        self.release = threading.Event()

    def __call__(self, name: str) -> None:
        if name != self.point or self.fired:
            return
        self.fired = True
        self.reached.set()
        if not self.release.wait(self.wait):
            raise TimeoutError(f"the gate at {name} was never released")
        if self.fail:
            raise InjectedFault(name)


class Runner(threading.Thread):
    """Runs one callable on its own thread and keeps its result or its exception."""

    def __init__(self, work: Callable[[], Any]) -> None:
        super().__init__(daemon=True)
        self.work = work
        self.started_running = threading.Event()
        self.result: Any = None
        self.error: BaseException | None = None

    def run(self) -> None:
        self.started_running.set()
        try:
            self.result = self.work()
        except BaseException as failure:  # kept for the test to inspect
            self.error = failure

    def wait_for(self, gate: Gate) -> bool:
        """True once ``gate`` was reached, False if the thread ended without reaching it."""
        while not gate.reached.wait(0.02):
            if not self.is_alive():
                return gate.reached.is_set()
        return True


# --- the rules every database of promotions must satisfy -----------------------------------------


def check_database(path: str | Path) -> list[str]:
    """The structural rules of promoted history, read from the file with plain SQL: every problem
    found (an empty list means none). Used by the concurrency, fault and property tests; each rule
    is shown to fire on a database that breaks it (``test_promotion_checker``)."""
    problems: list[str] = []
    with closing(sqlite3.connect(path)) as conn:
        states = {
            r[0]: r
            for r in conn.execute(
                "SELECT state_id, lineage_id, version, parent_state_id, commit_decision_id "
                "FROM trusted_states"
            )
        }
        for state_id, lineage, version, parent, decision in states.values():
            if version == 0:
                if parent is not None or decision is not None:
                    problems.append(f"{state_id}: a baseline with a parent or a decision")
                continue
            if parent not in states:
                problems.append(f"{state_id}: its parent {parent} is not stored")
            elif states[parent][2] != version - 1 or states[parent][1] != lineage:
                problems.append(f"{state_id}: version {version} is not its parent's plus one")
        for state, count in Counter(r[3] for r in states.values() if r[3] is not None).items():
            if count > 1:
                problems.append(f"{state}: {count} children (one parent, two futures)")
        used = Counter(r[4] for r in states.values() if r[4] is not None)
        problems += [f"decision {d}: commits {n} states" for d, n in used.items() if n > 1]
        for lineage, head in conn.execute("SELECT lineage_id, current_state_id FROM lineage_heads"):
            top = max(r[2] for r in states.values() if r[1] == lineage)
            if head not in states or states[head][2] != top:
                problems.append(f"lineage {lineage}: the head is not its newest state")
        committed = {
            r[0]: r[1]
            for r in conn.execute(
                "SELECT decision_id, committed_state_id FROM promotion_decisions "
                "WHERE committed_state_id IS NOT NULL"
            )
        }
        for state_id, (_, _, version, _, decision) in states.items():
            if version > 0 and committed.get(decision) != state_id:
                problems.append(f"{state_id}: no committed decision {decision} names it")
        for decision, state_id in committed.items():
            if state_id not in states or states[state_id][4] != decision:
                problems.append(f"decision {decision}: committed to a state that is not its own")
        owners = conn.execute(
            "SELECT s.state_id, s.version FROM trusted_states s WHERE s.version > 0"
        ).fetchall()
        for state_id, _ in owners:
            decision = states[state_id][4]
            binding = ids.evidence_id_for(decision)
            rows = conn.execute(
                "SELECT state_id, event_name FROM evidence_events WHERE evidence_id = ?",
                (binding,),
            ).fetchall()
            if rows != [(state_id, "promotion.committed")]:
                problems.append(f"{state_id}: its binding record is {rows}")
            for (evidence_ids_json,) in conn.execute(
                "SELECT evidence_ids FROM invariant_refs WHERE state_id = ?", (state_id,)
            ):
                if binding not in evidence_ids_json:
                    problems.append(f"{state_id}: a reference without the binding record")
            events = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event_type = 'STATE_PROMOTED' "
                "AND state_id = ?",
                (state_id,),
            ).fetchone()[0]
            if events != 1:
                problems.append(f"{state_id}: {events} STATE_PROMOTED events")
            parents = {
                r[0]: r[1]
                for r in conn.execute(
                    "SELECT invariant_id, invariant_version FROM invariant_refs WHERE state_id = ?",
                    (states[state_id][3],),
                )
            }
            mine = {
                r[0]: r[1]
                for r in conn.execute(
                    "SELECT invariant_id, invariant_version FROM invariant_refs WHERE state_id = ?",
                    (state_id,),
                )
            }
            for invariant, version in parents.items():
                if mine.get(invariant, 0) < version:
                    problems.append(f"{state_id}: {invariant} dropped or lowered")
        for table in ("invariant_refs", "state_resources"):
            orphans = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE state_id NOT IN "
                "(SELECT state_id FROM trusted_states)"
            ).fetchone()[0]
            if orphans:
                problems.append(f"{orphans} orphan rows in {table}")
        for table, column in (
            ("evidence_events", "state_id"),
            ("audit_events", "state_id"),
        ):
            orphans = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {column} IS NOT NULL AND {column} NOT IN "
                "(SELECT state_id FROM trusted_states)"
            ).fetchone()[0]
            if orphans:
                problems.append(f"{orphans} orphan rows in {table}")
        promoted = {
            r[0]
            for r in conn.execute("SELECT candidate_id FROM candidates WHERE status = 'PROMOTED'")
        }
        has_commit = {
            r[0]
            for r in conn.execute(
                "SELECT candidate_id FROM promotion_decisions WHERE committed_state_id IS NOT NULL"
            )
        }
        if promoted != has_commit:
            problems.append("a candidate is PROMOTED without a committed decision, or the reverse")
    return problems
