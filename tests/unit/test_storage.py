"""Interim local storage: bootstrap, schema versions and the typed API (C-35; P1a step 13).

Standard-library sqlite3 only (ADR-004). P1b replaces this behind repository ports.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from core.domain.enums import CandidateStatus
from core.domain.errors import DomainValidationError, IllegalTransitionError
from core.domain.state import fail_building, finish_building, start_building, transition_candidate
from core.domain.storage import LocalStorage
from tests.domain_builders import (
    LINEAGE,
    SEC,
    baseline,
    canonical_resources,
    invariant,
    new_candidate,
    promotable_candidate,
    promote,
    uid,
)

CS = CandidateStatus


class TestLocalStorageBootstrap(unittest.TestCase):
    """Exercises P0's 'local database/storage setup' deliverable and the exact command the
    bootstrap script (scripts/bootstrap.sh) runs."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_fresh_db_file_does_not_exist_until_initialized(self) -> None:
        self.assertFalse(self.db_path.exists())
        storage = LocalStorage(self.db_path)
        self.assertFalse(self.db_path.exists())  # constructing does not create the file
        storage.initialize_schema()
        self.assertTrue(self.db_path.exists())

    def test_schema_initialization_is_idempotent(self) -> None:
        storage = LocalStorage(self.db_path)
        storage.initialize_schema()
        storage.initialize_schema()  # must not raise on second call
        self.assertEqual(storage.schema_version(), "3")

    def test_creates_parent_directory_if_missing(self) -> None:
        nested = Path(self._tmpdir.name) / "nested" / "dirs" / "test.db"
        storage = LocalStorage(nested)
        storage.initialize_schema()
        self.assertTrue(nested.exists())

    def test_the_same_four_tables_are_created(self) -> None:
        LocalStorage(self.db_path).initialize_schema()
        with closing(sqlite3.connect(self.db_path)) as conn:
            tables = {
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        self.assertEqual(tables, {"trusted_state", "candidate_state", "invariant", "schema_meta"})

    def test_a_schema_version_2_database_is_refused(self) -> None:
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.executescript(
                "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "INSERT INTO schema_meta VALUES ('schema_version', '2');"
                "CREATE TABLE trusted_state (state_id TEXT PRIMARY KEY, content_hash TEXT);"
            )
            conn.commit()
        storage = LocalStorage(self.db_path)
        with self.assertRaises(DomainValidationError) as ctx:
            storage.initialize_schema()
        message = str(ctx.exception)
        self.assertIn("schema version 2", message)
        self.assertIn("delete", message)
        # The refusal changes nothing.
        with closing(sqlite3.connect(self.db_path)) as conn:
            version = conn.execute("SELECT value FROM schema_meta").fetchone()[0]
        self.assertEqual(version, "2")

    def test_domain_tables_without_a_version_are_refused(self) -> None:
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute("CREATE TABLE trusted_state (state_id TEXT PRIMARY KEY)")
            conn.commit()
        with self.assertRaises(DomainValidationError):
            LocalStorage(self.db_path).initialize_schema()


class StorageTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self.storage = LocalStorage(self.db_path)
        self.storage.initialize_schema()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()


class TestLocalStorageTrustedState(StorageTestCase):
    def test_save_and_count_trusted_state(self) -> None:
        self.assertEqual(self.storage.count_trusted_states(), 0)
        v0 = baseline()
        self.storage.save_trusted_state(v0)
        self.assertEqual(self.storage.count_trusted_states(), 1)

    def test_save_multiple_states_in_lineage(self) -> None:
        v0 = baseline()
        self.storage.save_trusted_state(v0)
        v1 = promote(
            promotable_candidate(v0, canonical_resources(ssh_open=False, db_path=True)), v0
        )
        self.storage.save_trusted_state(v1)
        self.assertEqual(self.storage.count_trusted_states(), 2)

    def test_a_duplicate_lineage_and_version_is_rejected(self) -> None:
        v0 = baseline()
        self.storage.save_trusted_state(v0)
        twin = baseline(state_id=uid(2))  # same lineage, version 0, different state id
        with self.assertRaises(sqlite3.IntegrityError):
            self.storage.save_trusted_state(twin)
        self.assertEqual(self.storage.count_trusted_states(), 1)

    def test_the_same_state_cannot_be_saved_twice(self) -> None:
        v0 = baseline()
        self.storage.save_trusted_state(v0)
        with self.assertRaises(sqlite3.IntegrityError):
            self.storage.save_trusted_state(v0)

    def test_the_same_version_in_another_lineage_is_fine(self) -> None:
        self.storage.save_trusted_state(baseline())
        self.storage.save_trusted_state(baseline(lineage_id=uid(0xEE), state_id=uid(2)))
        self.assertEqual(self.storage.count_trusted_states(), 2)

    def test_scalar_columns_mirror_the_state(self) -> None:
        v0 = baseline()
        self.storage.save_trusted_state(v0)
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT lineage_id, version, parent_state_id, state_hash, commit_decision_id "
                "FROM trusted_state WHERE state_id = ?",
                (v0.state_id,),
            ).fetchone()
        self.assertEqual(row, (LINEAGE, 0, None, v0.state_hash, None))

    def test_only_trusted_states_can_be_saved(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.storage.save_trusted_state(baseline().to_dict())  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            self.storage.save_trusted_state(new_candidate(baseline()))  # type: ignore[arg-type]


class TestLocalStorageCandidates(StorageTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.v0 = baseline()
        self.storage.save_trusted_state(self.v0)
        self.resources = canonical_resources(ssh_open=False, db_path=True)

    def test_a_candidate_needs_its_parent_in_the_database(self) -> None:
        other = baseline(state_id=uid(90), lineage_id=uid(0xEF))
        with self.assertRaises(sqlite3.IntegrityError):
            self.storage.save_candidate(new_candidate(other))

    def test_update_follows_the_lifecycle(self) -> None:
        created = new_candidate(self.v0)
        self.storage.save_candidate(created)
        building = start_building(created)
        self.storage.update_candidate(building)
        ready = finish_building(building, self.resources)
        self.storage.update_candidate(ready)
        analyzing = transition_candidate(ready, CS.ANALYZING)
        self.storage.update_candidate(analyzing)
        self.assertEqual(self.storage.load_candidate(created.candidate_id), analyzing)

    def test_a_failed_build_is_stored_with_its_reason(self) -> None:
        created = new_candidate(self.v0)
        self.storage.save_candidate(created)
        building = start_building(created)
        self.storage.update_candidate(building)
        failed = fail_building(building, "syntax error")
        self.storage.update_candidate(failed)
        loaded = self.storage.load_candidate(created.candidate_id)
        assert loaded is not None
        self.assertEqual((loaded.status, loaded.status_reason), (CS.FAILED, "syntax error"))

    def test_update_of_an_unknown_candidate_is_rejected(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.storage.update_candidate(start_building(new_candidate(self.v0)))

    def test_only_candidates_can_be_saved_or_updated(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.storage.save_candidate(self.v0)  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            self.storage.update_candidate({"status": "BUILDING"})  # type: ignore[arg-type]

    def test_a_no_op_update_is_not_a_legal_successor(self) -> None:
        created = new_candidate(self.v0)
        self.storage.save_candidate(created)
        with self.assertRaises(IllegalTransitionError):
            self.storage.update_candidate(created)


class TestLocalStorageInvariantDefinitions(StorageTestCase):
    def test_save_and_load_round_trip(self) -> None:
        inv = invariant(SEC)
        self.storage.save_invariant_definition(inv)
        loaded = self.storage.load_invariant_definition(SEC, 1)
        self.assertEqual(loaded, inv)
        assert loaded is not None
        self.assertEqual(loaded.definition_hash(), inv.definition_hash())

    def test_a_definition_version_is_stored_once(self) -> None:
        self.storage.save_invariant_definition(invariant(SEC))
        with self.assertRaises(sqlite3.IntegrityError):
            self.storage.save_invariant_definition(invariant(SEC))

    def test_versions_coexist(self) -> None:
        from datetime import UTC, datetime

        v1 = invariant(SEC)
        v2 = type(v1).new_version(v1, now=datetime(2026, 10, 2, tzinfo=UTC), description="tighter")
        self.storage.save_invariant_definition(v1)
        self.storage.save_invariant_definition(v2)
        self.assertEqual(self.storage.load_invariant_definition(SEC, 2), v2)
        self.assertEqual(self.storage.load_invariant_definition(SEC, 1), v1)

    def test_old_status_methods_are_gone(self) -> None:
        for name in (
            "update_invariant_lifecycle",
            "update_candidate_status",
            "save_invariant",
            "load_invariant",
        ):
            self.assertFalse(hasattr(self.storage, name), name)

    def test_only_definitions_can_be_saved(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.storage.save_invariant_definition(invariant(SEC).to_dict())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
