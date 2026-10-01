"""SQLite repositories and the unit of work (Doc 05 §22, §26, §32, §33, §36; Doc 06 §6, §20, §27,
§30, §31; C-42, C-43, C-46, C-48; P1b step 5 and 13.2, 13.3, 13.4).

Expected values come from the P1b prompt and the specification passages it quotes. These tests
also carry over every requirement of the interim storage tests that step 6 retires
(``test_storage.py`` and ``test_storage_p1_gate.py``); the retirement table in the P1b report maps
each old test to the test names here.
"""

from __future__ import annotations

import ast
import json
import re
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import core.persistence.schema as schema_module
import core.persistence.sqlite as sqlite_module
from core.domain.enums import CandidateSource, CandidateStatus, InvariantCategory
from core.domain.errors import (
    DomainValidationError,
    HashMismatchError,
    IllegalTransitionError,
    PersistenceError,
    StaleParentError,
)
from core.domain.invariant import Invariant, new_version
from core.domain.state import (
    CandidateState,
    TrustedState,
    finish_building,
    mark_promoted,
    reject_stale_candidate,
    start_building,
    transition_candidate,
)
from core.persistence.schema import initialize_database
from core.persistence.sqlite import CHECKPOINTS, SqliteUnitOfWork
from tests.domain_builders import (
    FUNC,
    LINEAGE,
    SEC,
    at,
    baseline,
    canonical_resources,
    invariant,
    new_candidate,
    patch_for,
    promote,
    resource,
    uid,
)

CS = CandidateStatus
SAFE = canonical_resources(ssh_open=False, db_path=True)
SAFE_OTHER = canonical_resources(ssh_open=False, db_path=False)


class Boom(RuntimeError):
    """An injected fault."""


class _LosingCas:
    """A connection on which the compare-and-swap UPDATE of the current pointer reports that it
    changed no row, as if another writer had moved the pointer first."""

    class _Result:
        rowcount = 0

    def __init__(self, conn: sqlite3.Connection) -> None:
        object.__setattr__(self, "_conn", conn)

    def execute(self, sql: str, *args: Any) -> Any:
        result = self._conn.execute(sql, *args)  # type: ignore[attr-defined]
        return self._Result() if sql.startswith("UPDATE lineage_heads") else result

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)  # type: ignore[attr-defined]

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._conn, name, value)  # type: ignore[attr-defined]


class _FailingCommit:
    """A connection whose COMMIT fails, as a full disk or an I/O error would."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        object.__setattr__(self, "_conn", conn)

    def execute(self, sql: str, *args: Any) -> Any:
        if sql == "COMMIT":
            raise sqlite3.OperationalError("disk I/O error")
        return self._conn.execute(sql, *args)  # type: ignore[attr-defined]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)  # type: ignore[attr-defined]

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._conn, name, value)  # type: ignore[attr-defined]


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


# --- unit of work --------------------------------------------------------------------------------


class TestUnitOfWork(RepoCase):
    def test_a_clean_exit_commits_and_the_rows_are_visible_to_a_new_connection(self) -> None:
        v0 = self.seed()
        self.assertEqual(self.count("trusted_states"), 1)
        self.assertEqual(self.read_state(v0.state_id), v0)

    def test_an_exception_rolls_back_and_propagates_unchanged(self) -> None:
        failure = Boom("fault")
        with self.assertRaises(Boom) as ctx, self.uow() as u:
            for definition in definitions():
                u.invariants.register_definition(definition)
            u.trusted_states.save_baseline(baseline())
            raise failure
        self.assertIs(ctx.exception, failure)
        self.assertEqual(sum(self.snapshot_counts().values()), 0)

    def test_nothing_is_visible_to_another_connection_before_the_commit(self) -> None:
        with self.uow() as u:
            u.invariants.register_definition(invariant(SEC))
            with closing(sqlite3.connect(self.path, timeout=0.1)) as other:
                # A reader sees the database as it was; the uncommitted row is not there.
                self.assertEqual(other.execute("SELECT COUNT(*) FROM invariants").fetchone()[0], 0)
            self.assertIsNotNone(u.invariants.get_definition(SEC, 1))
        self.assertEqual(self.count("invariants"), 1)

    def test_a_second_writer_is_refused_while_the_first_holds_the_transaction(self) -> None:
        with self.uow():
            with self.assertRaises(PersistenceError) as ctx, self.uow(timeout=0.05):
                pass
            self.assertIn("busy", str(ctx.exception))

    def test_the_repositories_are_unusable_outside_a_with_block(self) -> None:
        u = self.uow()
        for name in ("trusted_states", "candidates", "patches", "invariants"):
            with self.subTest(name=name), self.assertRaises(PersistenceError):
                getattr(u, name)

    def test_a_unit_of_work_cannot_be_entered_twice(self) -> None:
        with self.uow() as u, self.assertRaises(PersistenceError), u:
            pass

    def test_a_database_with_another_schema_version_is_refused(self) -> None:
        other = Path(self._tmp.name) / "v3.db"
        with closing(sqlite3.connect(other)) as conn:
            conn.executescript(
                "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "INSERT INTO schema_meta VALUES ('schema_version', '3');"
            )
        with self.assertRaises(PersistenceError) as ctx, SqliteUnitOfWork(other):
            pass
        self.assertIn("schema version 4", str(ctx.exception))

    def test_constructing_a_unit_of_work_does_not_create_the_file(self) -> None:
        missing = Path(self._tmp.name) / "later.db"
        SqliteUnitOfWork(missing)
        self.assertFalse(missing.exists())

    def test_an_uninitialized_database_is_refused(self) -> None:
        with (
            self.assertRaises(PersistenceError),
            SqliteUnitOfWork(Path(self._tmp.name) / "none.db"),
        ):
            pass

    def test_the_adapter_satisfies_the_domain_port_by_name(self) -> None:
        u = self.uow()
        for name in ("trusted_states", "candidates", "patches", "invariants"):
            self.assertTrue(hasattr(type(u), name))

    def test_the_checkpoint_seam_is_off_by_default(self) -> None:
        self.seed()  # no checkpoint passed: nothing is called, nothing fails
        self.assertEqual(self.count("trusted_states"), 1)

    def test_the_four_named_checkpoints_are_called_in_order_during_a_promotion(self) -> None:
        v0 = self.seed()
        promotable = self.store_stages(v0, SAFE)[-1]
        seen: list[str] = []
        new_state = promote(promotable, v0)
        with self.uow(checkpoint=seen.append) as u:
            u.trusted_states.save_promoted(new_state)
            u.candidates.save_transition(mark_promoted(promotable, new_state))
        self.assertEqual(seen, list(CHECKPOINTS))
        self.assertEqual(
            CHECKPOINTS,
            (
                "after_trusted_state_insert",
                "after_invariant_refs_insert",
                "after_lineage_head_update",
                "before_commit",
            ),
        )


# --- round trips ---------------------------------------------------------------------------------


class TestRoundTrips(RepoCase):
    def test_a_baseline_round_trips_equal_with_the_same_hash(self) -> None:
        v0 = self.seed()
        loaded = self.read_state(v0.state_id)
        self.assertEqual(loaded, v0)
        assert loaded is not None
        self.assertEqual(loaded.state_hash, v0.state_hash)  # DATA-INT-010
        self.assertEqual(loaded.invariant_refs, v0.invariant_refs)

    def test_a_promoted_state_round_trips_with_its_references_and_their_origins(self) -> None:
        v0 = self.seed()
        promotable = self.store_stages(v0, SAFE)[-1]
        v1 = self.promote_stored(promotable, v0)
        loaded = self.read_state(v1.state_id)
        self.assertEqual(loaded, v1)
        assert loaded is not None
        self.assertEqual(loaded.state_hash, v1.state_hash)
        self.assertEqual(loaded.invariant_refs, v1.invariant_refs)
        self.assertEqual({r.origin.value for r in loaded.invariant_refs}, {"VERIFIED"})

    def test_a_patch_round_trips(self) -> None:
        v0 = self.seed()
        patch = patch_for(v0)
        with self.uow() as u:
            u.patches.save(patch)
        with self.uow() as u:
            self.assertEqual(u.patches.get(patch.patch_id), patch)

    def test_a_candidate_round_trips_at_every_stage(self) -> None:
        v0 = self.seed()
        steps = stages(v0, SAFE)
        with self.uow() as u:
            u.patches.save(patch_for(v0))
            u.candidates.create(steps[0])
        for step in steps:
            if step is not steps[0]:
                with self.uow() as u:
                    u.candidates.save_transition(step)
            self.assertEqual(self.read_candidate(step.candidate_id), step, step.status)

    def test_a_failed_build_is_stored_with_its_reason(self) -> None:
        from core.domain.state import fail_building

        v0 = self.seed()
        created = new_candidate(v0)
        building = start_building(created)
        failed = fail_building(building, "syntax error")
        with self.uow() as u:
            u.patches.save(patch_for(v0))
            u.candidates.create(created)
            u.candidates.save_transition(building)
            u.candidates.save_transition(failed)
        loaded = self.read_candidate(created.candidate_id)
        assert loaded is not None
        self.assertEqual((loaded.status, loaded.status_reason), (CS.FAILED, "syntax error"))
        self.assertEqual(loaded, failed)

    def test_an_invariant_definition_round_trips_with_its_hash(self) -> None:
        inv = invariant(SEC)
        with self.uow() as u:
            u.invariants.register_definition(inv)
        with self.uow() as u:
            loaded = u.invariants.get_definition(SEC, 1)
        self.assertEqual(loaded, inv)
        assert loaded is not None
        self.assertEqual(loaded.definition_hash(), inv.definition_hash())

    def test_definition_versions_coexist(self) -> None:
        v1 = invariant(SEC)
        v2 = new_version(v1, now=datetime(2026, 10, 2, tzinfo=UTC), description="tighter")
        with self.uow() as u:
            u.invariants.register_definition(v1)
            u.invariants.register_definition(v2)
        with self.uow() as u:
            self.assertEqual(u.invariants.get_definition(SEC, 2), v2)
            self.assertEqual(u.invariants.get_definition(SEC, 1), v1)

    def test_state_refs_are_those_of_the_state_with_their_origins(self) -> None:
        v0 = self.seed()
        with self.uow() as u:
            refs = u.invariants.get_state_refs(v0.state_id)
        self.assertEqual(refs, v0.invariant_refs)
        self.assertEqual({r.origin.value for r in refs}, {"BASELINE"})

    def test_state_refs_of_an_unknown_state_are_refused(self) -> None:
        self.seed()
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.invariants.get_state_refs(uid(0xDEAD))

    def test_a_missing_row_reads_as_none(self) -> None:
        self.seed()
        with self.uow() as u:
            self.assertIsNone(u.trusted_states.get(uid(0xDEAD)))
            self.assertIsNone(u.trusted_states.get_current(uid(0xDEAD)))
            self.assertIsNone(u.candidates.get(uid(0xDEAD)))
            self.assertIsNone(u.patches.get(uid(0xDEAD)))
            self.assertIsNone(u.invariants.get_definition("INV-NOPE-001", 1))

    def test_a_stored_candidate_is_never_a_trusted_state(self) -> None:
        v0 = self.seed()
        created = self.store_stages(v0, SAFE, upto=0)[0]
        with self.uow() as u:
            self.assertIsNone(u.trusted_states.get(created.candidate_id))
        self.assertEqual(self.count("trusted_states"), 1)
        self.assertIsInstance(self.read_candidate(created.candidate_id), CandidateState)

    def test_scalar_columns_mirror_the_entities(self) -> None:
        v0 = self.seed()
        row = self.scalar(
            "SELECT json_array(lineage_id, version, parent_state_id, state_hash, "
            "commit_decision_id) "
            "FROM trusted_states WHERE state_id = ?",
            (v0.state_id,),
        )
        self.assertEqual(json.loads(row), [LINEAGE, 0, None, v0.state_hash, None])
        created = self.store_stages(v0, SAFE, upto=0)[0]
        row = self.scalar(
            "SELECT json_array(parent_state_id, lineage_id, candidate_sequence, status, "
            "patch_hash) "
            "FROM candidates WHERE candidate_id = ?",
            (created.candidate_id,),
        )
        self.assertEqual(json.loads(row), [v0.state_id, LINEAGE, 1, "CREATED", created.patch_hash])

    def test_a_ready_candidates_resources_are_stored_as_links_to_shared_records(self) -> None:
        v0 = self.seed()
        self.store_stages(v0, SAFE, upto=2)
        self.assertEqual(self.count("candidate_resources"), len(SAFE))
        self.assertEqual(self.count("resources"), len(v0.resources) + len(SAFE))


# --- lineage and the current pointer -------------------------------------------------------------


class TestLineage(RepoCase):
    def chain(self, length: int) -> list[TrustedState]:
        states = [self.seed()]
        for n in range(1, length):
            promotable = self.store_stages(states[-1], SAFE, n=n, sequence=n)[-1]
            states.append(self.promote_stored(promotable, states[-1], decision=n))
        return states

    def test_lineage_is_newest_first_and_ends_at_version_zero(self) -> None:
        states = self.chain(4)
        with self.uow() as u:
            lineage = u.trusted_states.lineage(states[-1].state_id)
        self.assertEqual([s.version for s in lineage], [3, 2, 1, 0])
        self.assertIsNone(lineage[-1].parent_state_id)
        self.assertEqual(lineage, list(reversed(states)))

    def test_get_current_follows_the_promotions(self) -> None:
        v0 = self.seed()
        with self.uow() as u:
            self.assertEqual(u.trusted_states.get_current(LINEAGE), v0)
        promotable = self.store_stages(v0, SAFE)[-1]
        v1 = self.promote_stored(promotable, v0)
        with self.uow() as u:
            self.assertEqual(u.trusted_states.get_current(LINEAGE), v1)

    def test_another_lineage_has_its_own_current_state(self) -> None:
        self.seed()
        other_lineage = uid(0xEE)
        other = baseline(lineage_id=other_lineage, state_id=uid(2))
        with self.uow() as u:
            u.trusted_states.save_baseline(other)
        with self.uow() as u:
            self.assertEqual(u.trusted_states.get_current(other_lineage), other)
            self.assertEqual(u.trusted_states.get_current(LINEAGE).version, 0)  # type: ignore[union-attr]

    def test_an_unknown_state_has_no_lineage(self) -> None:
        self.seed()
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.trusted_states.lineage(uid(0xDEAD))

    def test_a_broken_lineage_is_loud(self) -> None:
        states = self.chain(2)
        self.tamper("DELETE FROM trusted_states WHERE state_id = ?", (states[0].state_id,))
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.trusted_states.lineage(states[1].state_id)

    def test_assert_current_accepts_the_head_and_refuses_everything_else(self) -> None:
        v0 = self.seed()
        promotable = self.store_stages(v0, SAFE)[-1]
        with self.uow() as u:
            u.trusted_states.assert_current(v0.state_id)
        v1 = self.promote_stored(promotable, v0)
        with self.uow() as u:
            u.trusted_states.assert_current(v1.state_id)
            for stale in (v0.state_id, uid(0xDEAD)):
                with self.subTest(state=stale), self.assertRaises(StaleParentError) as ctx:
                    u.trusted_states.assert_current(stale)
                self.assertEqual(ctx.exception.rule, "SM-010")


# --- saving states -------------------------------------------------------------------------------


class TestSaveBaseline(RepoCase):
    def test_only_version_zero_is_a_baseline(self) -> None:
        v0 = self.seed()
        promotable = self.store_stages(v0, SAFE)[-1]
        v1 = promote(promotable, v0)
        with self.uow() as u, self.assertRaises(DomainValidationError) as ctx:
            u.trusted_states.save_baseline(v1)
        self.assertIn("version 0", str(ctx.exception))

    def test_a_lineage_has_one_baseline(self) -> None:
        self.seed()
        twin = baseline(state_id=uid(2))  # same lineage, version 0, another state id
        before = self.snapshot_counts()
        with self.uow() as u, self.assertRaises(DomainValidationError) as ctx:
            u.trusted_states.save_baseline(twin)
        self.assertIn("already has a baseline", str(ctx.exception))
        self.assertEqual(self.snapshot_counts(), before)

    def test_the_same_baseline_cannot_be_saved_twice(self) -> None:
        v0 = self.seed()
        with self.uow() as u, self.assertRaises(DomainValidationError):
            u.trusted_states.save_baseline(v0)

    def test_the_same_version_in_another_lineage_is_fine(self) -> None:
        self.seed()
        with self.uow() as u:
            u.trusted_states.save_baseline(baseline(lineage_id=uid(0xEE), state_id=uid(2)))
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(self.count("lineage_heads"), 2)

    def test_the_baseline_rows_are_written_together(self) -> None:
        v0 = self.seed()
        self.assertEqual(self.count("lineage_heads", "current_state_id = ?", (v0.state_id,)), 1)
        self.assertEqual(self.count("invariant_refs", "state_id = ?", (v0.state_id,)), 2)
        self.assertEqual(self.count("state_resources", "state_id = ?", (v0.state_id,)), 4)

    def test_a_reference_needs_its_definition_to_be_registered_first(self) -> None:
        with self.uow() as u, self.assertRaises(PersistenceError) as ctx:
            u.trusted_states.save_baseline(baseline())
        self.assertIn("FOREIGN KEY", str(ctx.exception))
        self.assertEqual(sum(self.snapshot_counts().values()), 0)

    def test_only_trusted_states_can_be_saved(self) -> None:
        v0 = self.seed()
        with self.uow() as u:
            with self.assertRaises(DomainValidationError):
                u.trusted_states.save_baseline(v0.to_dict())  # type: ignore[arg-type]
            with self.assertRaises(DomainValidationError):
                u.trusted_states.save_baseline(new_candidate(v0))  # type: ignore[arg-type]
            with self.assertRaises(DomainValidationError):
                u.trusted_states.save_promoted(v0.to_dict())  # type: ignore[arg-type]


class TestSavePromoted(RepoCase):
    def test_a_promotion_advances_the_head_and_adds_exactly_its_rows(self) -> None:
        v0 = self.seed()
        promotable = self.store_stages(v0, SAFE)[-1]
        before = self.snapshot_counts()
        v1 = self.promote_stored(promotable, v0)
        after = self.snapshot_counts()
        self.assertEqual(
            {key: after[key] - before[key] for key in after},
            {
                "trusted_states": 1,
                "lineage_heads": 0,
                "invariant_refs": 2,
                "state_resources": len(SAFE),
                "resources": 0,  # the promoted state shares its candidate's records (13.3)
                "candidates": 0,
                "candidate_resources": 0,
                "patches": 0,
                "invariants": 0,
            },
        )
        self.assertEqual(self.scalar("SELECT current_state_id FROM lineage_heads"), v1.state_id)
        stored = self.read_candidate(promotable.candidate_id)
        assert stored is not None
        self.assertEqual(stored.status, CS.PROMOTED)

    def test_a_stale_promotion_is_refused_and_writes_nothing(self) -> None:
        """Doc 06 §20, SM-010: two PROMOTABLE candidates from v0; the first commits."""
        v0 = self.seed()
        first = self.store_stages(v0, SAFE, n=1, sequence=1)[-1]
        second = self.store_stages(v0, SAFE_OTHER, n=2, sequence=2)[-1]
        v1 = self.promote_stored(first, v0, decision=1)
        stale_state = promote(second, v0, decision=2)
        before = self.snapshot_counts()
        with self.uow() as u, self.assertRaises(StaleParentError) as ctx:
            u.trusted_states.save_promoted(stale_state)
        self.assertEqual(ctx.exception.rule, "SM-010")
        self.assertEqual(self.snapshot_counts(), before)
        with self.uow() as u:
            self.assertEqual(u.trusted_states.get_current(LINEAGE), v1)
            self.assertIsNone(u.trusted_states.get(stale_state.state_id))
            stored = u.candidates.get(second.candidate_id)
        assert stored is not None
        self.assertEqual(stored.status, CS.PROMOTABLE)

    def test_a_stale_candidate_is_then_rejected_by_the_domain_function(self) -> None:
        v0 = self.seed()
        first = self.store_stages(v0, SAFE, n=1, sequence=1)[-1]
        second = self.store_stages(v0, SAFE_OTHER, n=2, sequence=2)[-1]
        v1 = self.promote_stored(first, v0, decision=1)
        rejected = reject_stale_candidate(second, v1)
        with self.uow() as u:
            u.candidates.save_transition(rejected)
        stored = self.read_candidate(second.candidate_id)
        assert stored is not None
        self.assertEqual((stored.status, stored.status_reason), (CS.REJECTED, "STALE_PARENT"))
        with self.uow() as u:
            self.assertEqual(u.trusted_states.get_current(LINEAGE), v1)

    def test_a_lost_compare_and_swap_is_a_stale_parent_and_writes_nothing(self) -> None:
        """The pointer UPDATE must change exactly one row (SM-010 at the database level)."""
        v0 = self.seed()
        promotable = self.store_stages(v0, SAFE)[-1]
        new_state = promote(promotable, v0)
        before = self.snapshot_counts()
        real_open = schema_module.open_connection

        def losing_open(path: Any, *, timeout: float = 5.0) -> _LosingCas:
            return _LosingCas(real_open(path, timeout=timeout))

        with (
            mock.patch.object(sqlite_module, "open_connection", losing_open),
            self.assertRaises(StaleParentError) as ctx,
            self.uow() as u,
        ):
            u.trusted_states.save_promoted(new_state)
        self.assertEqual(ctx.exception.rule, "SM-010")
        self.assertEqual(self.snapshot_counts(), before)
        with self.uow() as u:
            self.assertEqual(u.trusted_states.get_current(LINEAGE), v0)

    def test_the_baseline_cannot_be_saved_as_a_promotion(self) -> None:
        v0 = self.seed()
        with self.uow() as u, self.assertRaises(DomainValidationError):
            u.trusted_states.save_promoted(v0)

    def test_a_lineage_without_a_baseline_cannot_be_promoted(self) -> None:
        v0 = baseline()
        promotable = promote(stages(v0, SAFE)[-1], v0)  # built entirely in memory, never stored
        with self.uow() as u, self.assertRaises(PersistenceError) as ctx:
            u.trusted_states.save_promoted(promotable)
        self.assertIn("no baseline", str(ctx.exception))

    def test_the_commit_decision_is_stored(self) -> None:
        v0 = self.seed()
        promotable = self.store_stages(v0, SAFE)[-1]
        v1 = self.promote_stored(promotable, v0, decision=7)
        self.assertEqual(
            self.scalar(
                "SELECT commit_decision_id FROM trusted_states WHERE state_id = ?", (v1.state_id,)
            ),
            uid(4007),
        )


# --- Doc 06 §31 and Doc 05 §32: a promotion DB failure ------------------------------------------


class TestPromotionDatabaseFailure(RepoCase):
    """Doc 06 §31: "Promotion DB failure -> no partial trusted advancement"; Doc 05 §32."""

    def setUp(self) -> None:
        super().setUp()
        self.v0 = self.seed()
        self.promotable = self.store_stages(self.v0, SAFE)[-1]
        self.new_state = promote(self.promotable, self.v0)
        self.before = self.snapshot_counts()

    def fail_at(self, name: str, *, catch_inside: bool = False) -> None:
        def checkpoint(point: str) -> None:
            if point == name:
                raise Boom(point)

        if catch_inside:
            with self.uow(checkpoint=checkpoint) as u, suppress(Boom):  # swallowed by the caller
                u.trusted_states.save_promoted(self.new_state)
            return
        with self.assertRaises(Boom), self.uow(checkpoint=checkpoint) as u:
            u.trusted_states.save_promoted(self.new_state)
            u.candidates.save_transition(mark_promoted(self.promotable, self.new_state))

    def assert_nothing_advanced(self) -> None:
        """Read from a brand-new connection, so only committed data counts."""
        self.assertEqual(self.count("trusted_states"), 1)
        self.assertEqual(
            self.count("trusted_states", "state_id = ?", (self.new_state.state_id,)), 0
        )
        self.assertEqual(self.count("invariant_refs"), self.before["invariant_refs"])
        self.assertEqual(self.count("state_resources"), self.before["state_resources"])
        self.assertEqual(self.count("resources"), self.before["resources"])
        self.assertEqual(self.snapshot_counts(), self.before)
        with self.uow() as u:
            current = u.trusted_states.get_current(LINEAGE)
            stored = u.candidates.get(self.promotable.candidate_id)
        self.assertEqual(current, self.v0)
        assert stored is not None
        self.assertEqual(stored.status, CS.PROMOTABLE)

    def test_a_failure_at_every_checkpoint_leaves_no_partial_advancement(self) -> None:
        for name in CHECKPOINTS:
            with self.subTest(checkpoint=name):
                self.fail_at(name)
                self.assert_nothing_advanced()

    def test_the_control_without_a_fault_does_advance(self) -> None:
        """So that the failure tests above are not vacuous."""
        with self.uow() as u:
            u.trusted_states.save_promoted(self.new_state)
            u.candidates.save_transition(mark_promoted(self.promotable, self.new_state))
        after = self.snapshot_counts()
        self.assertEqual(after["trusted_states"], self.before["trusted_states"] + 1)
        self.assertEqual(after["invariant_refs"], self.before["invariant_refs"] + 2)
        self.assertEqual(after["state_resources"], self.before["state_resources"] + len(SAFE))
        with self.uow() as u:
            self.assertEqual(u.trusted_states.get_current(LINEAGE), self.new_state)

    def test_a_fault_swallowed_by_the_caller_does_not_commit_half_a_promotion(self) -> None:
        for name in CHECKPOINTS[:3]:
            with self.subTest(checkpoint=name):
                self.fail_at(name, catch_inside=True)
                self.assert_nothing_advanced()

    def test_a_failure_before_the_candidate_is_marked_promoted_leaves_it_promotable(self) -> None:
        def checkpoint(point: str) -> None:
            if point == "before_commit":
                raise Boom(point)

        with self.assertRaises(Boom), self.uow(checkpoint=checkpoint) as u:
            u.trusted_states.save_promoted(self.new_state)
        self.assert_nothing_advanced()

    def test_a_database_failure_during_the_commit_is_reported_and_rolled_back(self) -> None:
        """Doc 06 §27: a database commit failure means no new current Trusted State."""
        real_open = schema_module.open_connection

        def failing_open(path: Any, *, timeout: float = 5.0) -> _FailingCommit:
            return _FailingCommit(real_open(path, timeout=timeout))

        with (
            mock.patch.object(sqlite_module, "open_connection", failing_open),
            self.assertRaises(PersistenceError) as ctx,
            self.uow() as u,
        ):
            u.trusted_states.save_promoted(self.new_state)
            u.candidates.save_transition(mark_promoted(self.promotable, self.new_state))
        self.assertIn("commit failed", str(ctx.exception))
        self.assert_nothing_advanced()


# --- concurrency ---------------------------------------------------------------------------------


class TestConcurrentPromotion(RepoCase):
    """SM-010 at the database level: two units of work promote from v0 at the same time."""

    def test_exactly_one_of_two_simultaneous_promotions_wins(self) -> None:
        v0 = self.seed()
        first = self.store_stages(v0, SAFE, n=1, sequence=1)[-1]
        second = self.store_stages(v0, SAFE_OTHER, n=2, sequence=2)[-1]
        jobs = [
            (first, promote(first, v0, decision=1)),
            (second, promote(second, v0, decision=2)),
        ]
        barrier = threading.Barrier(len(jobs))
        outcomes: list[BaseException | None] = [None] * len(jobs)

        def run(index: int) -> None:
            candidate, new_state = jobs[index]
            try:
                barrier.wait(timeout=10)
                with SqliteUnitOfWork(self.path, timeout=20.0) as u:
                    u.trusted_states.save_promoted(new_state)
                    u.candidates.save_transition(mark_promoted(candidate, new_state))
            except BaseException as exc:  # reported below, in the main thread
                outcomes[index] = exc

        threads = [threading.Thread(target=run, args=(i,)) for i in range(len(jobs))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
            self.assertFalse(thread.is_alive())

        winners = [i for i, outcome in enumerate(outcomes) if outcome is None]
        losers = [outcome for outcome in outcomes if outcome is not None]
        self.assertEqual(len(winners), 1, outcomes)
        self.assertEqual(len(losers), 1, outcomes)
        self.assertIsInstance(losers[0], StaleParentError | PersistenceError)
        winner_state = jobs[winners[0]][1]
        self.assertEqual(self.count("trusted_states", "version = 1"), 1)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(
            self.scalar("SELECT current_state_id FROM lineage_heads"), winner_state.state_id
        )
        loser_candidate = jobs[1 - winners[0]][0]
        stored = self.read_candidate(loser_candidate.candidate_id)
        assert stored is not None
        self.assertEqual(stored.status, CS.PROMOTABLE)
        with self.uow() as u:
            self.assertEqual(u.trusted_states.get_current(LINEAGE), winner_state)


# --- Doc 06 §30 through the repository -----------------------------------------------------------


class TestCandidateRepository(RepoCase):
    def test_create_accepts_only_a_created_candidate(self) -> None:
        v0 = self.seed()
        steps = stages(v0, SAFE)
        with self.uow() as u:
            u.patches.save(patch_for(v0))
            for later in steps[1:]:
                with self.subTest(status=later.status), self.assertRaises(DomainValidationError):
                    u.candidates.create(later)
            u.candidates.create(steps[0])

    def test_a_candidate_needs_its_parent_and_its_patch_in_the_database(self) -> None:
        v0 = self.seed()
        created = new_candidate(v0)
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.candidates.create(created)  # the patch was never saved
        other_parent = baseline(state_id=uid(90), lineage_id=uid(0xEF))
        orphan = new_candidate(other_parent)
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.patches.save(patch_for(other_parent))  # the patch itself needs a stored parent
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.candidates.create(orphan)
        self.assertEqual(self.count("candidates"), 0)

    def test_a_candidate_is_stored_once(self) -> None:
        v0 = self.seed()
        created = self.store_stages(v0, SAFE, upto=0)[0]
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.candidates.create(created)

    def test_a_lineage_has_one_candidate_per_sequence(self) -> None:
        """C-46."""
        v0 = self.seed()
        self.store_stages(v0, SAFE, n=1, sequence=1, upto=0)
        clash = new_candidate(v0, sequence=1, n=2)
        with self.uow() as u:
            u.patches.save(patch_for(v0, n=2))
            with self.assertRaises(PersistenceError):
                u.candidates.create(clash)

    def test_only_candidates_can_be_saved(self) -> None:
        v0 = self.seed()
        with self.uow() as u:
            with self.assertRaises(DomainValidationError):
                u.candidates.create(v0)  # type: ignore[arg-type]
            with self.assertRaises(DomainValidationError):
                u.candidates.save_transition({"status": "BUILDING"})  # type: ignore[arg-type]
            with self.assertRaises(DomainValidationError):
                u.patches.save(v0)  # type: ignore[arg-type]
            with self.assertRaises(DomainValidationError):
                u.invariants.register_definition(invariant(SEC).to_dict())  # type: ignore[arg-type]

    def test_no_update_or_status_shortcut_exists(self) -> None:
        """Doc 06 §30: no persistence convenience method bypasses lifecycle validation."""
        self.seed()
        with self.uow() as u:
            for name in (
                "update_invariant_lifecycle",
                "update_candidate_status",
                "update_candidate",
                "update",
                "set_status",
                "delete",
                "save_trusted_state",
                "save_invariant",
                "load_invariant",
            ):
                for repository in (u.candidates, u.trusted_states, u.invariants, u.patches):
                    self.assertFalse(hasattr(repository, name), name)

    def test_the_resources_of_a_ready_candidate_are_stored_with_it(self) -> None:
        v0 = self.seed()
        steps = self.store_stages(v0, SAFE, upto=2)
        ready = self.read_candidate(steps[2].candidate_id)
        assert ready is not None
        self.assertEqual(ready.resources, steps[2].resources)
        self.assertEqual(ready.state_hash, steps[2].state_hash)

    def test_a_failed_build_stores_no_resources(self) -> None:
        from core.domain.state import fail_building

        v0 = self.seed()
        created = new_candidate(v0)
        building = start_building(created)
        with self.uow() as u:
            u.patches.save(patch_for(v0))
            u.candidates.create(created)
            u.candidates.save_transition(building)
            u.candidates.save_transition(fail_building(building, "bad"))
        self.assertEqual(self.count("candidate_resources"), 0)


class TestSaveTransitionEnforcesTheLifecycle(RepoCase):
    """Doc 06 §30: ``save_transition`` accepts only a legal successor of the stored candidate."""

    def setUp(self) -> None:
        super().setUp()
        self.v0 = self.seed()
        self.steps = self.store_stages(self.v0, SAFE, upto=2)  # stored as READY
        self.created, self.building, self.ready, self.analyzing, self.promotable = self.steps

    def refused(self, new: CandidateState, error: type[Exception] = IllegalTransitionError) -> Any:
        before = self.snapshot_counts()
        with self.uow() as u, self.assertRaises(error) as ctx:
            u.candidates.save_transition(new)
        self.assertEqual(self.snapshot_counts(), before)
        stored = self.read_candidate(new.candidate_id)
        assert stored is not None
        return ctx.exception, stored

    def test_a_legal_successor_is_stored(self) -> None:
        with self.uow() as u:
            u.candidates.save_transition(self.analyzing)
        self.assertEqual(self.read_candidate(self.analyzing.candidate_id), self.analyzing)

    def test_ready_to_promoted_is_refused(self) -> None:
        promoted = mark_promoted(self.promotable, promote(self.promotable, self.v0))
        exc, stored = self.refused(promoted)
        self.assertEqual(exc.rule, "SM-002")  # type: ignore[attr-defined]
        self.assertEqual(stored.status, CS.READY)

    def test_a_no_op_is_not_a_legal_successor(self) -> None:
        self.refused(self.ready)

    def test_a_status_cannot_be_skipped(self) -> None:
        self.refused(self.promotable)

    def test_the_stored_resources_cannot_change_after_ready(self) -> None:
        other = finish_building(
            start_building(new_candidate(self.v0, n=1)), [resource("aws_instance.other")]
        )  # the same candidate id, other resources, status READY
        changed = transition_candidate(other, CS.ANALYZING)  # READY -> ANALYZING is legal
        exc, stored = self.refused(changed, DomainValidationError)
        self.assertIn("resources", str(exc))
        self.assertEqual(stored.resources, self.ready.resources)
        self.assertEqual(stored.state_hash, self.ready.state_hash)

    def test_identity_fields_cannot_change(self) -> None:
        other = finish_building(start_building(new_candidate(self.v0, sequence=2, n=1)), SAFE)
        self.assertEqual(other.candidate_id, self.ready.candidate_id)
        self.refused(transition_candidate(other, CS.ANALYZING), DomainValidationError)

    def test_no_identity_field_can_change_in_a_successor(self) -> None:
        """Doc 05 §23: candidate semantic content is immutable after construction."""
        changes: dict[str, Any] = {
            "lineage_id": uid(0x5FE),
            "parent_state_id": uid(0x5FD),
            "candidate_sequence": 99,
            "source": CandidateSource.LLM,
            "patch_id": uid(0x5FC),
            "patch_hash": "e" * 64,
            "created_at": at(99),
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                successor = self.analyzing._evolve(**{field: value})
                exc, stored = self.refused(successor, DomainValidationError)
                self.assertIn(field, str(exc))
                self.assertEqual(stored, self.ready)
        # normalization_version is part of the candidate's own hash, so a READY successor with
        # another value cannot even be constructed.
        with self.assertRaises(HashMismatchError):
            self.analyzing._evolve(normalization_version="norm-9")
        # A different candidate_id is simply another candidate, which is not stored.
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.candidates.save_transition(self.analyzing._evolve(candidate_id=uid(0x5FF)))

    def test_an_unknown_candidate_is_refused(self) -> None:
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.candidates.save_transition(start_building(new_candidate(self.v0, n=9, sequence=9)))

    def test_a_rejected_candidate_cannot_change_again(self) -> None:
        rejected = transition_candidate(self.analyzing, CS.REJECTED)
        with self.uow() as u:
            u.candidates.save_transition(self.analyzing)
            u.candidates.save_transition(rejected)
        self.assertEqual(self.read_candidate(rejected.candidate_id), rejected)
        for target in (CS.ANALYZING, CS.PROMOTABLE, CS.RETRY_REQUIRED, CS.ESCALATED, CS.REJECTED):
            with self.subTest(target=target):
                successor = (
                    self.analyzing
                    if target is CS.ANALYZING
                    else transition_candidate(self.analyzing, target)
                )
                _, stored = self.refused(successor)
                self.assertEqual(stored.status, CS.REJECTED)

    def test_promotable_to_promoted_needs_the_promotion_to_be_committed_first(self) -> None:
        with self.uow() as u:
            u.candidates.save_transition(self.analyzing)
            u.candidates.save_transition(self.promotable)
        promoted = mark_promoted(self.promotable, promote(self.promotable, self.v0))
        exc, stored = self.refused(promoted)  # the lineage's head is still v0
        self.assertEqual(exc.rule, "SM-002")  # type: ignore[attr-defined]
        self.assertEqual(stored.status, CS.PROMOTABLE)

    def test_a_promotion_for_another_candidates_state_is_refused(self) -> None:
        other = self.store_stages(self.v0, SAFE_OTHER, n=2, sequence=2)[-1]
        with self.uow() as u:
            u.candidates.save_transition(self.analyzing)
            u.candidates.save_transition(self.promotable)
        v1 = promote(self.promotable, self.v0, decision=1)
        with self.uow() as u:
            u.trusted_states.save_promoted(v1)
            # ``other`` has the same parent but other resources: v1 is not its promotion.
            with self.assertRaises(IllegalTransitionError):
                u.candidates.save_transition(self._promoted_without_checks(other))

    @staticmethod
    def _promoted_without_checks(candidate: CandidateState) -> CandidateState:
        """A PROMOTED object that ``mark_promoted`` would refuse (its hash differs), built through
        the private evolve to play a forger."""
        return candidate._evolve(status=CS.PROMOTED)

    def test_a_stale_rejection_needs_a_stale_parent(self) -> None:
        with self.uow() as u:
            u.candidates.save_transition(self.analyzing)
            u.candidates.save_transition(self.promotable)
        bystander = baseline(state_id=uid(0xB0))  # another state, to satisfy the domain function
        rejected = reject_stale_candidate(self.promotable, bystander)
        exc, stored = self.refused(rejected)  # but v0 is still the lineage's current state
        self.assertEqual(exc.rule, "C-29")  # type: ignore[attr-defined]
        self.assertEqual(stored.status, CS.PROMOTABLE)


# --- shared resource records (13.3) --------------------------------------------------------------


class TestSharedResourceRecords(RepoCase):
    def test_a_record_shared_by_a_candidate_and_its_promoted_state_is_stored_once(self) -> None:
        v0 = self.seed()
        promotable = self.store_stages(v0, SAFE)[-1]
        before = self.count("resources")
        self.promote_stored(promotable, v0)
        self.assertEqual(self.count("resources"), before)
        self.assertEqual(
            self.count("resources", "record_id IN (SELECT record_id FROM state_resources)"),
            len(v0.resources) + len(SAFE),
        )

    def test_two_candidates_may_share_a_record(self) -> None:
        v0 = self.seed()
        self.store_stages(v0, SAFE, n=1, sequence=1)
        self.store_stages(v0, SAFE, n=2, sequence=2)
        self.assertEqual(self.count("resources"), len(v0.resources) + len(SAFE))
        self.assertEqual(self.count("candidate_resources"), 2 * len(SAFE))

    def test_an_existing_record_with_other_content_is_refused(self) -> None:
        v0 = self.seed()
        promotable = self.store_stages(v0, SAFE)[-1]
        clashing = [
            (
                resource(
                    r.address,
                    r.resource_type,
                    attributes={"size": "TAMPERED"},
                    record_id=r.record_id,
                )
                if index == 0
                else r
            )
            for index, r in enumerate(promotable.resources)
        ]
        forged = finish_building(start_building(new_candidate(v0, n=5, sequence=5)), clashing)
        with self.uow() as u:
            u.patches.save(patch_for(v0, n=5))
            u.candidates.create(new_candidate(v0, n=5, sequence=5))
            u.candidates.save_transition(start_building(new_candidate(v0, n=5, sequence=5)))
            before = self.snapshot_counts()
            with self.assertRaises(PersistenceError) as ctx:
                u.candidates.save_transition(forged)
            self.assertIn("13.3", str(ctx.exception))
        # The savepoint undid the failed READY transition; the candidate is still BUILDING.
        stored = self.read_candidate(forged.candidate_id)
        assert stored is not None
        self.assertEqual(stored.status, CS.BUILDING)
        self.assertEqual(self.count("resources"), before["resources"])
        self.assertEqual(self.count("candidate_resources"), before["candidate_resources"])

    def test_a_promotion_whose_record_clashes_with_a_stored_one_writes_nothing(self) -> None:
        v0 = self.seed()
        record = v0.resources[0]
        clash = resource(
            record.address,
            record.resource_type,
            attributes={"size": "TAMPERED"},
            record_id=record.record_id,
        )
        others = [r for r in SAFE if r.address != clash.address]
        promotable = stages(v0, [clash, *others], n=8, sequence=8)[-1]  # in memory only
        v1 = promote(promotable, v0, decision=8)
        before = self.snapshot_counts()
        with self.uow() as u, self.assertRaises(PersistenceError) as ctx:
            u.trusted_states.save_promoted(v1)
        self.assertIn("13.3", str(ctx.exception))
        self.assertEqual(self.snapshot_counts(), before)
        with self.uow() as u:
            self.assertEqual(u.trusted_states.get_current(LINEAGE), v0)

    def test_the_adapter_never_uses_replace_or_ignore(self) -> None:
        pattern = re.compile(r"\bOR\s+(REPLACE|IGNORE)\b|\bREPLACE\s+INTO\b", re.IGNORECASE)
        for module in (sqlite_module, schema_module):
            tree = ast.parse(Path(module.__file__ or "").read_text(encoding="utf-8"))
            docstrings = {
                id(node.body[0].value)
                for node in ast.walk(tree)
                if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef)
                and node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if id(node) in docstrings:
                        continue
                    with self.subTest(module=module.__name__, text=node.value[:40]):
                        self.assertIsNone(pattern.search(node.value))


# --- tamper detection (DATA-INT-010, 13.2) -------------------------------------------------------


class TestTamperDetection(RepoCase):
    """A stored row that fails validation raises ``PersistenceError`` and is never returned."""

    def setUp(self) -> None:
        super().setUp()
        self.v0 = self.seed()
        self.steps = self.store_stages(self.v0, SAFE, upto=2)
        self.ready = self.steps[2]

    def assert_state_refused(self, state_id: str, *, by_hash: bool = False) -> None:
        with self.uow() as u, self.assertRaises(PersistenceError) as ctx:
            u.trusted_states.get(state_id)
        if by_hash:  # the domain's hash re-validation found it, not a column check (DATA-INT-010)
            self.assertIsInstance(ctx.exception.__cause__, HashMismatchError)

    def assert_candidate_refused(self, candidate_id: str, *, by_hash: bool = False) -> None:
        with self.uow() as u, self.assertRaises(PersistenceError) as ctx:
            u.candidates.get(candidate_id)
        if by_hash:
            self.assertIsInstance(ctx.exception.__cause__, HashMismatchError)

    def edit_content(self, table: str, key: str, value: str, mutate: Any) -> None:
        content = json.loads(
            self.scalar(f"SELECT content_json FROM {table} WHERE {key} = ?", (value,))
        )
        mutate(content)
        self.tamper(
            f"UPDATE {table} SET content_json = ? WHERE {key} = ?", (json.dumps(content), value)
        )

    # trusted states

    def test_the_untouched_rows_read_fine(self) -> None:
        self.assertEqual(self.read_state(self.v0.state_id), self.v0)
        self.assertEqual(self.read_candidate(self.ready.candidate_id), self.ready)

    def test_a_tampered_trusted_state_is_caught(self) -> None:
        def mutate(content: dict[str, Any]) -> None:
            content["resources"][0]["attributes"]["size"] = "tampered"

        self.edit_content("trusted_states", "state_id", self.v0.state_id, mutate)
        self.assert_state_refused(self.v0.state_id, by_hash=True)

    def test_a_scalar_column_that_disagrees_with_the_content_is_caught(self) -> None:
        self.tamper("UPDATE trusted_states SET version = 5 WHERE state_id = ?", (self.v0.state_id,))
        self.assert_state_refused(self.v0.state_id)

    def test_content_that_is_not_json_is_caught(self) -> None:
        self.tamper(
            "UPDATE trusted_states SET content_json = 'not json' WHERE state_id = ?",
            (self.v0.state_id,),
        )
        self.assert_state_refused(self.v0.state_id)

    def test_a_stray_invariant_reference_row_is_caught(self) -> None:
        extra = invariant("INV-SEC-002")
        with self.uow() as u:
            u.invariants.register_definition(extra)
        self.tamper(
            "INSERT INTO invariant_refs (state_id, invariant_id, invariant_version, status, "
            "origin, "
            "evidence_ids, last_verified_at) VALUES (?, 'INV-SEC-002', 1, 'PROTECTED', 'BASELINE', "
            "'[]', 't')",
            (self.v0.state_id,),
        )
        self.assert_state_refused(self.v0.state_id)

    def test_a_missing_invariant_reference_row_is_caught(self) -> None:
        self.tamper(
            "DELETE FROM invariant_refs WHERE state_id = ? AND invariant_id = ?",
            (self.v0.state_id, FUNC),
        )
        self.assert_state_refused(self.v0.state_id)

    def test_an_edited_invariant_reference_row_is_caught(self) -> None:
        self.tamper(
            "UPDATE invariant_refs SET status = 'VIOLATED' WHERE state_id = ? AND invariant_id = ?",
            (self.v0.state_id, SEC),
        )
        self.assert_state_refused(self.v0.state_id)
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.invariants.get_state_refs(self.v0.state_id)

    def test_a_stray_state_resource_link_is_caught(self) -> None:
        extra = resource("aws_instance.stray")
        self.tamper(
            "INSERT INTO resources (record_id, fingerprint, address, resource_type, content_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                extra.record_id,
                extra.fingerprint,
                extra.address,
                extra.resource_type,
                json.dumps(extra.to_dict()),
            ),
        )
        self.tamper(
            "INSERT INTO state_resources (state_id, address, record_id) VALUES (?, ?, ?)",
            (self.v0.state_id, extra.address, extra.record_id),
        )
        self.assert_state_refused(self.v0.state_id)

    def test_a_missing_state_resource_link_is_caught(self) -> None:
        self.tamper(
            "DELETE FROM state_resources WHERE state_id = ? AND address = ?",
            (self.v0.state_id, "aws_instance.app"),
        )
        self.assert_state_refused(self.v0.state_id)

    def test_a_tampered_resource_record_is_caught(self) -> None:
        record = self.v0.resources[0]
        self.tamper(
            "UPDATE resources SET content_json = '{}' WHERE record_id = ?", (record.record_id,)
        )
        self.assert_state_refused(self.v0.state_id)

    # candidates

    def test_a_tampered_candidate_resource_is_caught(self) -> None:
        def mutate(content: dict[str, Any]) -> None:
            content["resources"][0]["attributes"]["size"] = "tampered"

        self.edit_content("candidates", "candidate_id", self.ready.candidate_id, mutate)
        self.assert_candidate_refused(self.ready.candidate_id, by_hash=True)

    def test_a_status_edited_only_in_the_content_is_caught(self) -> None:
        def mutate(content: dict[str, Any]) -> None:
            content["status"] = "PROMOTED"

        self.edit_content("candidates", "candidate_id", self.ready.candidate_id, mutate)
        self.assert_candidate_refused(self.ready.candidate_id)

    def test_a_status_edited_only_in_the_column_is_caught(self) -> None:
        """READY -> PROMOTED by raw SQL: no committed state was promoted from this candidate."""
        self.tamper(
            "UPDATE candidates SET status = 'PROMOTED' WHERE candidate_id = ?",
            (self.ready.candidate_id,),
        )
        with self.uow() as u, self.assertRaises(PersistenceError) as ctx:
            u.candidates.get(self.ready.candidate_id)
        self.assertIn("PROMOTED", str(ctx.exception))

    def test_a_scalar_column_that_disagrees_with_the_candidate_is_caught(self) -> None:
        self.tamper(
            "UPDATE candidates SET state_hash = ? WHERE candidate_id = ?",
            ("f" * 64, self.ready.candidate_id),
        )
        self.assert_candidate_refused(self.ready.candidate_id)

    def test_a_stray_candidate_resource_link_is_caught(self) -> None:
        extra = resource("aws_instance.stray")
        self.tamper(
            "INSERT INTO resources (record_id, fingerprint, address, resource_type, content_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                extra.record_id,
                extra.fingerprint,
                extra.address,
                extra.resource_type,
                json.dumps(extra.to_dict()),
            ),
        )
        self.tamper(
            "INSERT INTO candidate_resources (candidate_id, address, record_id) VALUES (?, ?, ?)",
            (self.ready.candidate_id, extra.address, extra.record_id),
        )
        self.assert_candidate_refused(self.ready.candidate_id)

    def test_a_missing_candidate_resource_link_is_caught(self) -> None:
        self.tamper(
            "DELETE FROM candidate_resources WHERE candidate_id = ? AND address = ?",
            (self.ready.candidate_id, "aws_instance.app"),
        )
        self.assert_candidate_refused(self.ready.candidate_id)

    def test_a_candidate_marked_promoted_for_a_state_with_other_resources_is_caught(self) -> None:
        other = self.store_stages(self.v0, SAFE_OTHER, n=2, sequence=2)[-1]
        self.promote_stored(self.store_stages_promotable_first(), self.v0)
        self.tamper(
            "UPDATE candidates SET status = 'PROMOTED' WHERE candidate_id = ?",
            (other.candidate_id,),
        )
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.candidates.get(other.candidate_id)

    def store_stages_promotable_first(self) -> CandidateState:
        with self.uow() as u:
            u.candidates.save_transition(self.steps[3])
            u.candidates.save_transition(self.steps[4])
        return self.steps[4]

    # patches and definitions

    def test_a_tampered_patch_is_caught(self) -> None:
        patch = patch_for(self.v0)

        def mutate(content: dict[str, Any]) -> None:
            content["content"] = 'resource "evil" "x" {}\n'

        self.edit_content("patches", "patch_id", patch.patch_id, mutate)
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.patches.get(patch.patch_id)

    def test_a_tampered_invariant_definition_is_caught(self) -> None:
        def mutate(content: dict[str, Any]) -> None:
            content["description"] = "tampered"

        self.edit_content("invariants", "invariant_id", SEC, mutate)
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.invariants.get_definition(SEC, 1)

    def test_a_definition_stored_under_another_key_is_caught(self) -> None:
        self.tamper(
            "UPDATE invariants SET version = 1, invariant_id = 'INV-SEC-009' "
            "WHERE invariant_id = ?",
            (FUNC,),
        )
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.invariants.get_definition("INV-SEC-009", 1)


# --- definitions ---------------------------------------------------------------------------------


class TestInvariantRepository(RepoCase):
    def test_a_definition_version_is_stored_once(self) -> None:
        with self.uow() as u:
            u.invariants.register_definition(invariant(SEC))
        with self.uow() as u, self.assertRaises(DomainValidationError) as ctx:
            u.invariants.register_definition(invariant(SEC))
        self.assertIn("already registered", str(ctx.exception))

    def test_a_gap_in_versions_is_refused_with_a_clear_error(self) -> None:
        v1 = invariant(SEC)
        v3 = new_version(new_version(v1, now=at(5)), now=at(6))
        with self.uow() as u:
            u.invariants.register_definition(v1)
            with self.assertRaises(DomainValidationError) as ctx:
                u.invariants.register_definition(v3)
        self.assertIn("no gaps", str(ctx.exception))
        self.assertIn("version 2", str(ctx.exception))

    def test_a_first_version_other_than_one_is_refused(self) -> None:
        v2 = new_version(invariant(SEC), now=at(5))
        with self.uow() as u, self.assertRaises(DomainValidationError) as ctx:
            u.invariants.register_definition(v2)
        self.assertIn("version 1", str(ctx.exception))

    def test_a_refused_definition_leaves_the_unit_of_work_usable(self) -> None:
        with self.uow() as u:
            u.invariants.register_definition(invariant(SEC))
            with self.assertRaises(DomainValidationError):
                u.invariants.register_definition(invariant(SEC))
            u.invariants.register_definition(invariant(FUNC, InvariantCategory.FUNCTIONAL))
        self.assertEqual(self.count("invariants"), 2)


if __name__ == "__main__":
    unittest.main()
