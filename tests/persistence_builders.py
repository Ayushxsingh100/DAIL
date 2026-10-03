"""Shared builders for the persistence tests (P1b). Not a test module.

``RepoCase`` gives a test a fresh schema-4 database in a temporary directory, a way to open a unit
of work on it, counts read from a brand-new connection (committed data only), a ``tamper`` that
edits rows as an attacker with file access would, and seeding helpers.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any

from core.domain.enums import CandidateStatus, InvariantCategory
from core.domain.invariant import Invariant
from core.domain.state import (
    CandidateState,
    TrustedState,
    finish_building,
    mark_promoted,
    start_building,
    transition_candidate,
)
from core.persistence.schema import initialize_database
from core.persistence.sqlite import SqliteUnitOfWork
from tests.domain_builders import (
    FUNC,
    SEC,
    baseline,
    canonical_resources,
    invariant,
    new_candidate,
    patch_for,
    promote,
    uid,
)
from tests.evidence_builders import submission as evidence_submission

CS = CandidateStatus
SAFE = canonical_resources(ssh_open=False, db_path=True)
SAFE_OTHER = canonical_resources(ssh_open=False, db_path=False)


# Seeded evidence carries ids of its own, so it never shows up in a run, a correlation or an
# attempt that a test builds for itself.
SEED_RUN, SEED_CORRELATION, SEED_OPERATION = uid(0x9FF1), uid(0x9FF2), uid(0x9FF3)


def seed_evidence(uow: Any, state: Any, *, bound: bool = True) -> list[str]:
    """Store the evidence a trusted state links to, in the same unit of work and immediately
    before ``save_baseline`` or ``save_promoted`` (DATA-INT-007; C-47, C-60). Returns the ids it
    stored.

    The adapter refuses a state whose ``evidence_refs`` (or whose invariant references' evidence
    ids) name evidence that is not stored. For every such id not yet stored, append a VERIFICATION
    record with exactly that id, bound to this state. The binding is a test convenience: C-60
    checks that the evidence exists, and P6 checks that it has the right binding. Anything that is
    not a ``TrustedState`` is ignored, so a test that passes a bad argument still reaches the
    adapter's own refusal.

    ``bound=False`` stores *unbound* evidence instead. A state is bound by a deferred foreign key,
    so evidence bound to a state that is never stored cannot commit; a test that expects its save
    to be refused, but whose unit of work still commits (``with self.uow() as u,
    self.assertRaises``), seeds unbound evidence so that the commit does not depend on the state.
    """
    if not isinstance(state, TrustedState):
        return []
    wanted = dict.fromkeys(
        [*state.evidence_refs, *(e for ref in state.invariant_refs for e in ref.evidence_ids)]
    )
    stored: list[str] = []
    for evidence_id in wanted:
        if uow.evidence.get(evidence_id) is None:
            uow.evidence.append(
                evidence_submission(
                    0,
                    evidence_id=evidence_id,
                    payload={"seed": evidence_id},
                    run_id=SEED_RUN,
                    correlation_id=SEED_CORRELATION,
                    operation_id=SEED_OPERATION,
                    state_id=state.state_id if bound else None,
                    state_hash=state.state_hash if bound else None,
                )
            )
            stored.append(evidence_id)
    return stored


class Boom(RuntimeError):
    """An injected fault."""


def definitions() -> list[Invariant]:
    return [invariant(SEC), invariant(FUNC, InvariantCategory.FUNCTIONAL)]


def stages(
    parent: TrustedState, resources: list[Any], *, n: int = 1, sequence: int = 1
) -> list[CandidateState]:
    """CREATED, BUILDING, READY, ANALYZING and PROMOTABLE versions of one candidate."""
    created = new_candidate(parent, sequence=sequence, n=n)
    building = start_building(created)
    ready = finish_building(building, resources)
    analyzing = transition_candidate(ready, CS.ANALYZING)
    promotable = transition_candidate(analyzing, CS.PROMOTABLE)
    return [created, building, ready, analyzing, promotable]


class RepoCase(unittest.TestCase):
    # Evidence stored by ``seed`` and ``promote_stored`` for DATA-INT-007. An evidence test sets
    # ``seed_bound = False`` (the seeds are unbound) and ``hide_seeded_evidence = True`` (``count``
    # leaves the seeds out), so that its own counts and lists mean what they say.
    seed_bound = True
    hide_seeded_evidence = False

    def setUp(self) -> None:
        self.seeded_evidence: list[str] = []
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "t.db"
        initialize_database(self.path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # --- access -----------------------------------------------------------------------------

    def uow(self, **kwargs: Any) -> SqliteUnitOfWork:
        return SqliteUnitOfWork(self.path, **kwargs)

    def count(self, table: str, where: str = "1", params: tuple[Any, ...] = ()) -> int:
        """Rows in ``table``, read from a brand-new connection (a committed state only)."""
        if self.hide_seeded_evidence and self.seeded_evidence:
            marks = ", ".join("?" for _ in self.seeded_evidence)
            if table == "evidence_events":
                where = f"({where}) AND evidence_id NOT IN ({marks})"
                params = (*params, *self.seeded_evidence)
            elif table == "evidence_artifacts":
                where = (
                    f"({where}) AND content_hash NOT IN (SELECT content_hash FROM "
                    f"evidence_events WHERE evidence_id IN ({marks}))"
                )
                params = (*params, *self.seeded_evidence)
        with closing(sqlite3.connect(self.path)) as conn:
            return int(
                conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()[0]
            )

    def scalar(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        with closing(sqlite3.connect(self.path)) as conn:
            return conn.execute(sql, params).fetchone()[0]

    def tamper(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        """Edit a row the way an attacker with file access would: triggers dropped, FKs off."""
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            for (name,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            ).fetchall():
                conn.execute(f"DROP TRIGGER {name}")
            conn.execute(sql, params)
            conn.commit()

    def snapshot_counts(self) -> dict[str, int]:
        return {
            table: self.count(table)
            for table in (
                "trusted_states",
                "lineage_heads",
                "invariant_refs",
                "state_resources",
                "resources",
                "candidates",
                "candidate_resources",
                "patches",
                "invariants",
            )
        }

    # --- seeding ----------------------------------------------------------------------------

    def seed(self, state: TrustedState | None = None) -> TrustedState:
        """Register SEC and FUNC and store the baseline (version 0)."""
        v0 = state or baseline()
        with self.uow() as u:
            for definition in definitions():
                u.invariants.register_definition(definition)
            self.seeded_evidence += seed_evidence(u, v0, bound=self.seed_bound)
            u.trusted_states.save_baseline(v0)
        return v0

    def store_stages(
        self,
        parent: TrustedState,
        resources: list[Any],
        *,
        n: int = 1,
        sequence: int = 1,
        upto: int = 4,
    ) -> list[CandidateState]:
        """Store a candidate and walk it through ``stages[:upto + 1]``; return all five stages."""
        steps = stages(parent, resources, n=n, sequence=sequence)
        with self.uow() as u:
            u.patches.save(patch_for(parent, n=n))
            u.candidates.create(steps[0])
            for step in steps[1 : upto + 1]:
                u.candidates.save_transition(step)
        return steps

    def read_candidate(self, candidate_id: str) -> CandidateState | None:
        with self.uow() as u:
            return u.candidates.get(candidate_id)

    def read_state(self, state_id: str) -> TrustedState | None:
        with self.uow() as u:
            return u.trusted_states.get(state_id)

    def promote_stored(
        self, promotable: CandidateState, parent: TrustedState, **kwargs: Any
    ) -> TrustedState:
        """The Step 5 composition: save_promoted, then save_transition(mark_promoted)."""
        new_state = promote(promotable, parent, **kwargs)
        with self.uow() as u:
            self.seeded_evidence += seed_evidence(u, new_state, bound=self.seed_bound)
            u.trusted_states.save_promoted(new_state)
            u.candidates.save_transition(mark_promoted(promotable, new_state))
        return new_state
