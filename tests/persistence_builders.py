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
)

CS = CandidateStatus
SAFE = canonical_resources(ssh_open=False, db_path=True)
SAFE_OTHER = canonical_resources(ssh_open=False, db_path=False)


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
    def setUp(self) -> None:
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
            u.trusted_states.save_promoted(new_state)
            u.candidates.save_transition(mark_promoted(promotable, new_state))
        return new_state
