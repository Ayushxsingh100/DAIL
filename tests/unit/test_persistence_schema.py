"""Schema v4: every table, constraint and trigger, attacked with raw SQL (Doc 05 §20-§23, §32;
Doc 06 §5, §6, §22, §30; C-42, C-44, C-46; P1b step 4 and 13.1, 13.4).

No domain object is used here. The expectations come from the P1b prompt and the Doc 06 §5
lifecycle, not from the implementation; ``LEGAL`` below is written out by hand from Doc 06 §5. Each
trigger has at least one positive and one negative case, and a refused statement must leave the
database as it was.
"""

from __future__ import annotations

import json
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any

from core.domain.enums import CandidateStatus
from core.domain.errors import PersistenceError
from core.domain.lifecycle import CANDIDATE_TRANSITIONS
from core.persistence.schema import (
    DDL,
    IMMUTABLE_TABLES,
    SCHEMA_VERSION,
    TABLE_NAMES,
    candidate_status_pairs,
    initialize_database,
    open_connection,
    schema_version,
)
from tests.domain_builders import uid

L = uid(0x11)
L2 = uid(0x12)
S0, S1, S2, S3 = uid(0x21), uid(0x22), uid(0x23), uid(0x24)
DEC1, DEC2 = uid(0x31), uid(0x32)
P1, P2, P3 = uid(0x41), uid(0x42), uid(0x43)
C1, C2, C3 = uid(0x51), uid(0x52), uid(0x53)
R1, R2 = uid(0x61), uid(0x62)
H = "a" * 64
INSERT_CANDIDATE = (
    "INSERT INTO candidates (candidate_id, parent_state_id, patch_id, lineage_id, "
    "candidate_sequence, status, patch_hash, content_json) VALUES (?,?,?,?,?,?,?,?)"
)
H2 = "b" * 64
INV = "INV-SEC-001"

# Doc 06 §5, written out by hand: CREATED -> BUILDING -> FAILED | READY -> ANALYZING ->
# REJECTED | RETRY_REQUIRED | ESCALATED | PROMOTABLE -> PROMOTED (PROMOTABLE -> REJECTED: C-29).
LEGAL: dict[str, set[str]] = {
    "CREATED": {"BUILDING"},
    "BUILDING": {"READY", "FAILED"},
    "READY": {"ANALYZING"},
    "ANALYZING": {"REJECTED", "RETRY_REQUIRED", "ESCALATED", "PROMOTABLE"},
    "PROMOTABLE": {"PROMOTED", "REJECTED"},
    "FAILED": set(),
    "REJECTED": set(),
    "RETRY_REQUIRED": set(),
    "ESCALATED": set(),
    "PROMOTED": set(),
}
PATH_TO: dict[str, list[str]] = {
    "CREATED": [],
    "BUILDING": ["BUILDING"],
    "FAILED": ["BUILDING", "FAILED"],
    "READY": ["BUILDING", "READY"],
    "ANALYZING": ["BUILDING", "READY", "ANALYZING"],
    "REJECTED": ["BUILDING", "READY", "ANALYZING", "REJECTED"],
    "RETRY_REQUIRED": ["BUILDING", "READY", "ANALYZING", "RETRY_REQUIRED"],
    "ESCALATED": ["BUILDING", "READY", "ANALYZING", "ESCALATED"],
    "PROMOTABLE": ["BUILDING", "READY", "ANALYZING", "PROMOTABLE"],
    "PROMOTED": [],  # needs a committed promotion; built explicitly where it is used
}

EXPECTED_TABLES = {
    "patches",
    "trusted_states",
    "lineage_heads",
    "candidates",
    "resources",
    "state_resources",
    "candidate_resources",
    "invariants",
    "invariant_refs",
    "schema_meta",
}

EXPECTED_TRIGGERS = {
    # 1. no UPDATE / DELETE
    *(f"{t}_no_update" for t in IMMUTABLE_TABLES),
    *(f"{t}_no_delete" for t in IMMUTABLE_TABLES),
    "candidates_no_delete",
    "lineage_heads_no_delete",
    # no INSERT OR REPLACE (beyond Step 4; see the schema docstring)
    *(
        f"{t}_no_replace"
        for t in (
            "trusted_states",
            "patches",
            "resources",
            "state_resources",
            "candidate_resources",
            "invariants",
            "invariant_refs",
            "candidates",
            "lineage_heads",
        )
    ),
    # 2-7, 13.1, 13.4
    "trusted_states_insert_rules",
    "lineage_heads_insert_rules",
    "lineage_heads_update_rules",
    "candidates_insert_status",
    "candidates_insert_patch",
    "candidates_insert_lineage",
    "candidates_update_status_pairs",
    "candidates_update_identity",
    "candidates_update_content",
    "candidates_update_promoted",
    "candidate_resources_insert_ready",
    "candidate_resources_insert_declared",
    "invariants_insert_version",
    "invariant_refs_insert_attach",
    "state_resources_insert_attach",
}


class DbCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "t.db"
        initialize_database(self.path)
        self.conn = open_connection(self.path)

    def tearDown(self) -> None:
        self.conn.close()
        self._tmp.cleanup()

    # --- helpers --------------------------------------------------------------------------

    def run_sql(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def scalar(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        return self.conn.execute(sql, params).fetchone()[0]

    def count(self, table: str, where: str = "1", params: tuple[Any, ...] = ()) -> int:
        return int(self.scalar(f"SELECT COUNT(*) FROM {table} WHERE {where}", params))

    def refused(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
        contains: str | tuple[str, ...] | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        """The statement is refused. Several triggers can guard one statement and SQLite does not
        say which fires first, so ``contains`` may list alternatives; one of them must appear."""
        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            (conn or self.conn).execute(sql, params)
        if contains is not None:
            wanted = (contains,) if isinstance(contains, str) else contains
            message = str(ctx.exception)
            self.assertTrue(any(w in message for w in wanted), f"{wanted} not in {message!r}")

    def add_state(
        self,
        state_id: str,
        version: int,
        parent: str | None = None,
        decision: str | None = None,
        lineage: str = L,
    ) -> None:
        self.run_sql(
            "INSERT INTO trusted_states (state_id, lineage_id, version, parent_state_id, "
            "state_hash, commit_decision_id, content_json) VALUES (?,?,?,?,?,?,?)",
            (state_id, lineage, version, parent, H, decision, "{}"),
        )

    def add_head(self, lineage: str = L, state: str = S0) -> None:
        self.run_sql(
            "INSERT INTO lineage_heads (lineage_id, current_state_id) VALUES (?,?)",
            (lineage, state),
        )

    def add_patch(self, patch_id: str, parent: str = S0, content_hash: str = H) -> None:
        self.run_sql(
            "INSERT INTO patches (patch_id, parent_state_id, content_hash, content_json) "
            "VALUES (?,?,?,?)",
            (patch_id, parent, content_hash, "{}"),
        )

    def add_candidate(
        self,
        candidate_id: str,
        patch_id: str,
        sequence: int,
        parent: str = S0,
        lineage: str = L,
        patch_hash: str = H,
        status: str = "CREATED",
    ) -> None:
        self.run_sql(
            "INSERT INTO candidates (candidate_id, parent_state_id, patch_id, lineage_id, "
            "candidate_sequence, status, status_reason, patch_hash, state_hash, content_json) "
            "VALUES (?,?,?,?,?,?,NULL,?,NULL,?)",
            (
                candidate_id,
                parent,
                patch_id,
                lineage,
                sequence,
                status,
                patch_hash,
                json.dumps({"resources": []}),
            ),
        )

    def add_resource(self, record_id: str, address: str = "aws_instance.app") -> None:
        self.run_sql(
            "INSERT INTO resources (record_id, fingerprint, address, resource_type, content_json) "
            "VALUES (?,?,?,?,?)",
            (record_id, H, address, "aws_instance", "{}"),
        )

    def add_invariant(self, invariant_id: str = INV, version: int = 1) -> None:
        self.run_sql(
            "INSERT INTO invariants (invariant_id, version, definition_hash, created_at, "
            "content_json) VALUES (?,?,?,?,?)",
            (invariant_id, version, H, "2026-10-02T00:00:00Z", "{}"),
        )

    def add_ref(
        self,
        state: str,
        invariant_id: str = INV,
        version: int = 1,
        status: str = "PROTECTED",
        origin: str = "BASELINE",
    ) -> None:
        self.run_sql(
            "INSERT INTO invariant_refs (state_id, invariant_id, invariant_version, status, "
            "origin, evidence_ids, last_verified_at, invalidated_by_candidate_id, "
            "invalidation_reason) VALUES (?,?,?,?,?,?,?,NULL,NULL)",
            (state, invariant_id, version, status, origin, "[]", "2026-10-02T00:00:00Z"),
        )

    def move(self, candidate_id: str, *statuses: str) -> None:
        for status in statuses:
            self.run_sql(
                "UPDATE candidates SET status = ? WHERE candidate_id = ?", (status, candidate_id)
            )

    def make_ready(self, candidate_id: str, resources: list[tuple[str, str]]) -> None:
        """BUILDING -> READY with the content that declares ``resources`` (address, record_id)."""
        self.run_sql(
            "UPDATE candidates SET status = 'READY', state_hash = ?, content_json = ? "
            "WHERE candidate_id = ?",
            (
                H2,
                json.dumps({"resources": [{"address": a, "record_id": r} for a, r in resources]}),
                candidate_id,
            ),
        )

    def baseline_world(self, resources: list[tuple[str, str]] | None = None) -> None:
        """S0 (version 0) with a patch, an invariant and a reference, and S0 as the lineage head.
        ``resources`` (address, record_id) are attached to S0 first: nothing attaches to a head."""
        self.add_state(S0, 0)
        self.add_invariant()
        self.add_ref(S0)
        for address, record_id in resources or []:
            self.add_resource(record_id, address)
            self.run_sql("INSERT INTO state_resources VALUES (?,?,?)", (S0, address, record_id))
        self.add_head()
        self.add_patch(P1)

    def snapshot(self) -> dict[str, list[tuple[Any, ...]]]:
        return {
            table: self.conn.execute(f"SELECT * FROM {table} ORDER BY 1, 2").fetchall()
            for table in sorted(EXPECTED_TABLES)
        }

    def refused_and_unchanged(
        self, sql: str, params: tuple[Any, ...] = (), contains: str | tuple[str, ...] | None = None
    ) -> None:
        before = self.snapshot()
        self.refused(sql, params, contains)
        self.assertEqual(self.snapshot(), before)


class TestInitialization(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "t.db"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def tables(self) -> set[str]:
        with closing(sqlite3.connect(self.path)) as conn:
            return {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }

    def test_the_file_exists_only_after_initialization(self) -> None:
        self.assertFalse(self.path.exists())
        initialize_database(self.path)
        self.assertTrue(self.path.exists())
        self.assertEqual(schema_version(self.path), "4")
        self.assertEqual(SCHEMA_VERSION, "4")

    def test_initialization_is_idempotent(self) -> None:
        initialize_database(self.path)
        with closing(open_connection(self.path)) as conn:
            before = conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY 2").fetchall()
        initialize_database(self.path)
        with closing(open_connection(self.path)) as conn:
            after = conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY 2").fetchall()
            versions = conn.execute("SELECT * FROM schema_meta").fetchall()
        self.assertEqual(before, after)
        self.assertEqual(versions, [("schema_version", "4")])

    def test_the_parent_directory_is_created(self) -> None:
        nested = Path(self._tmp.name) / "nested" / "dirs" / "t.db"
        initialize_database(nested)
        self.assertTrue(nested.exists())

    def test_exactly_the_step_4_tables_are_created(self) -> None:
        initialize_database(self.path)
        self.assertEqual(self.tables(), EXPECTED_TABLES)
        self.assertEqual(set(TABLE_NAMES), EXPECTED_TABLES)

    def test_exactly_the_expected_triggers_are_created(self) -> None:
        initialize_database(self.path)
        with closing(sqlite3.connect(self.path)) as conn:
            names = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
            }
        self.assertEqual(names, EXPECTED_TRIGGERS)
        self.assertEqual(len(DDL), len(EXPECTED_TABLES) + len(EXPECTED_TRIGGERS))

    def test_connections_have_foreign_keys_on(self) -> None:
        initialize_database(self.path)
        with closing(open_connection(self.path)) as conn:
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)

    def test_a_schema_3_database_is_refused_and_left_unchanged(self) -> None:
        with closing(sqlite3.connect(self.path)) as conn:
            conn.executescript(
                "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "INSERT INTO schema_meta VALUES ('schema_version', '3');"
                "CREATE TABLE trusted_state (state_id TEXT PRIMARY KEY);"
            )
        with self.assertRaises(PersistenceError) as ctx:
            initialize_database(self.path)
        message = str(ctx.exception)
        self.assertIn("schema version 3", message)
        self.assertIn("needs 4", message)
        self.assertIn("C-44", message)
        self.assertIn("delete", message)
        self.assertEqual(self.tables(), {"schema_meta", "trusted_state"})
        self.assertEqual(schema_version(self.path), "3")

    def test_any_other_schema_version_is_refused(self) -> None:
        for version in ("1", "2", "5", "unknown"):
            with self.subTest(version=version):
                path = Path(self._tmp.name) / f"v{version}.db"
                with closing(sqlite3.connect(path)) as conn:
                    conn.executescript(
                        "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
                        f"INSERT INTO schema_meta VALUES ('schema_version', '{version}');"
                    )
                with self.assertRaises(PersistenceError):
                    initialize_database(path)

    def test_a_schema_meta_without_a_version_is_refused(self) -> None:
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        with self.assertRaises(PersistenceError):
            initialize_database(self.path)

    def test_legacy_domain_tables_without_a_version_are_refused(self) -> None:
        for table in ("trusted_state", "candidate_state", "invariant", "trusted_states"):
            with self.subTest(table=table):
                path = Path(self._tmp.name) / f"{table}.db"
                with closing(sqlite3.connect(path)) as conn:
                    conn.execute(f"CREATE TABLE {table} (x TEXT)")
                with self.assertRaises(PersistenceError):
                    initialize_database(path)

    def test_a_database_that_only_holds_evidence_tables_is_accepted(self) -> None:
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("CREATE TABLE evidence_record (x TEXT)")
        initialize_database(self.path)
        self.assertIn("evidence_record", self.tables())
        self.assertIn("trusted_states", self.tables())

    def test_a_dropped_trigger_is_restored_by_initialization(self) -> None:
        initialize_database(self.path)
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("DROP TRIGGER trusted_states_no_update")
        initialize_database(self.path)
        with closing(sqlite3.connect(self.path)) as conn:
            names = {
                r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
            }
        self.assertIn("trusted_states_no_update", names)


class TestTriggerPairListMatchesTheDomain(DbCase):
    def trigger_pairs(self) -> set[tuple[str, str]]:
        sql = self.scalar(
            "SELECT sql FROM sqlite_master WHERE name = 'candidates_update_status_pairs'"
        )
        found = re.findall(r"OLD\.status = '([A-Z_]+)' AND NEW\.status = '([A-Z_]+)'", sql)
        self.assertEqual(len(found), len(set(found)))
        return set(found)

    def test_the_trigger_pair_list_equals_the_domain_table(self) -> None:
        domain = {
            (current.value, target.value)
            for current, targets in CANDIDATE_TRANSITIONS.items()
            for target in targets
        }
        self.assertEqual(self.trigger_pairs(), domain)
        self.assertEqual(set(candidate_status_pairs()), domain)

    def test_the_trigger_pair_list_equals_doc_06_section_5(self) -> None:
        by_hand = {(old, new) for old, news in LEGAL.items() for new in news}
        self.assertEqual(len(by_hand), 10)
        self.assertEqual(self.trigger_pairs(), by_hand)

    def test_every_candidate_status_has_a_check_constraint_value(self) -> None:
        sql = self.scalar("SELECT sql FROM sqlite_master WHERE name = 'candidates'")
        for status in CandidateStatus:
            self.assertIn(f"'{status.value}'", sql)


class TestConstraints(DbCase):
    def test_a_patch_needs_its_parent_state(self) -> None:
        self.refused("INSERT INTO patches VALUES (?,?,?,?)", (P1, S0, H, "{}"), "FOREIGN KEY")

    def test_state_resources_need_their_resource_record(self) -> None:
        self.add_state(S0, 0)
        self.refused("INSERT INTO state_resources VALUES (?,?,?)", (S0, "a.x", R1), "FOREIGN KEY")
        self.add_resource(R1)
        self.run_sql("INSERT INTO state_resources VALUES (?,?,?)", (S0, "aws_instance.app", R1))
        self.assertEqual(self.count("state_resources"), 1)

    def test_candidate_resources_need_their_resource_record(self) -> None:
        self.baseline_world()
        self.add_candidate(C1, P1, 1)
        self.move(C1, "BUILDING")
        self.make_ready(C1, [("aws_instance.app", R1)])
        self.refused(
            "INSERT INTO candidate_resources VALUES (?,?,?)",
            (C1, "aws_instance.app", R1),
            "FOREIGN KEY",
        )

    def test_a_reference_needs_its_state_and_its_definition(self) -> None:
        self.add_state(S0, 0)
        self.refused_and_unchanged(
            "INSERT INTO invariant_refs (state_id, invariant_id, invariant_version, status, "
            "origin, evidence_ids, last_verified_at) VALUES (?,?,?,?,?,?,?)",
            (S0, INV, 1, "PROTECTED", "BASELINE", "[]", "t"),
            "FOREIGN KEY",
        )
        self.add_invariant()
        self.refused(
            "INSERT INTO invariant_refs (state_id, invariant_id, invariant_version, status, "
            "origin, evidence_ids, last_verified_at) VALUES (?,?,?,?,?,?,?)",
            (uid(0x99), INV, 1, "PROTECTED", "BASELINE", "[]", "t"),
            "FOREIGN KEY",
        )
        self.add_ref(S0)
        self.assertEqual(self.count("invariant_refs"), 1)

    def test_a_reference_status_is_protected_violated_or_uncertain(self) -> None:
        self.add_state(S0, 0)
        self.add_invariant()
        for status in ("AFFECTED", "REGISTERED", "VERIFYING", "REVERIFYING", "NOPE"):
            with self.subTest(status=status):
                self.refused(
                    "INSERT INTO invariant_refs (state_id, invariant_id, invariant_version, "
                    "status, origin, evidence_ids, last_verified_at) VALUES (?,?,?,?,?,?,?)",
                    (S0, INV, 1, status, "BASELINE", "[]", "t"),
                    "CHECK",
                )
        for index, status in enumerate(("PROTECTED", "VIOLATED", "UNCERTAIN"), start=2):
            self.add_invariant(f"INV-SEC-00{index}")
            self.add_ref(S0, f"INV-SEC-00{index}", 1, status)
        self.assertEqual(self.count("invariant_refs"), 3)

    def test_a_reference_origin_is_baseline_verified_or_carried_forward(self) -> None:
        self.add_state(S0, 0)
        self.add_invariant()
        self.refused(
            "INSERT INTO invariant_refs (state_id, invariant_id, invariant_version, status, "
            "origin, evidence_ids, last_verified_at) VALUES (?,?,?,?,?,?,?)",
            (S0, INV, 1, "PROTECTED", "FORGED", "[]", "t"),
            "CHECK",
        )
        for index, origin in enumerate(("BASELINE", "VERIFIED", "CARRIED_FORWARD"), start=2):
            self.add_invariant(f"INV-SEC-00{index}")
            self.add_ref(S0, f"INV-SEC-00{index}", 1, "PROTECTED", origin)
        self.assertEqual(self.count("invariant_refs"), 3)

    def test_a_state_holds_one_reference_per_invariant_at_any_version(self) -> None:
        self.add_state(S0, 0)
        self.add_invariant()
        self.add_invariant(version=2)
        self.add_ref(S0, INV, 1)
        self.refused_and_unchanged(
            "INSERT INTO invariant_refs (state_id, invariant_id, invariant_version, status, "
            "origin, evidence_ids, last_verified_at) VALUES (?,?,?,?,?,?,?)",
            (S0, INV, 2, "PROTECTED", "BASELINE", "[]", "t"),
        )

    def test_a_lineage_has_one_state_per_version(self) -> None:
        self.add_state(S0, 0)
        self.refused_and_unchanged(
            "INSERT INTO trusted_states (state_id, lineage_id, version, parent_state_id, "
            "state_hash, commit_decision_id, content_json) VALUES (?,?,?,?,?,?,?)",
            (S1, L, 0, None, H, None, "{}"),
        )
        self.add_state(S2, 0, lineage=L2)  # the same version in another lineage is fine
        self.assertEqual(self.count("trusted_states"), 2)

    def test_a_lineage_has_one_candidate_per_sequence(self) -> None:
        """C-46: UNIQUE(lineage_id, candidate_sequence)."""
        self.baseline_world()
        self.add_patch(P2)
        self.add_candidate(C1, P1, 1)
        self.refused_and_unchanged(
            INSERT_CANDIDATE,
            (C2, S0, P2, L, 1, "CREATED", H, "{}"),
        )
        self.add_candidate(C2, P2, 2)
        self.assertEqual(self.count("candidates"), 2)

    def test_numeric_ranges_are_checked(self) -> None:
        self.refused(  # the SM-001 trigger may speak before the CHECK does
            "INSERT INTO trusted_states VALUES (?,?,?,?,?,?,?)", (S0, L, -1, None, H, None, "{}")
        )
        self.add_state(S0, 0)
        self.add_patch(P1)
        self.refused(
            INSERT_CANDIDATE,
            (C1, S0, P1, L, 0, "CREATED", H, "{}"),
            "CHECK",
        )
        self.refused("INSERT INTO invariants VALUES (?,?,?,?,?)", (INV, 0, H, "t", "{}"))

    def test_a_candidate_cannot_name_another_candidate_as_its_trusted_parent(self) -> None:
        """DATA-INT-002: the parent is a foreign key to trusted_states, so a candidate id is not
        a possible parent."""
        self.baseline_world()
        self.add_candidate(C1, P1, 1)
        self.add_patch(P2, parent=S0)
        self.refused_and_unchanged(
            INSERT_CANDIDATE,
            (C2, C1, P2, L, 2, "CREATED", H, "{}"),
        )


class TestImmutability(DbCase):
    """Trigger 1: no UPDATE or DELETE on immutable tables; no DELETE on candidates or heads."""

    def populate(self) -> None:
        self.baseline_world([("aws_instance.app", R1)])
        self.add_candidate(C1, P1, 1)
        self.move(C1, "BUILDING")
        self.make_ready(C1, [("aws_instance.app", R1)])
        self.run_sql("INSERT INTO candidate_resources VALUES (?,?,?)", (C1, "aws_instance.app", R1))

    COLUMNS = {
        "trusted_states": "state_hash",
        "patches": "content_hash",
        "resources": "fingerprint",
        "state_resources": "record_id",
        "candidate_resources": "record_id",
        "invariants": "definition_hash",
        "invariant_refs": "status",
    }
    NEW_VALUE = {"record_id": uid(0x77), "status": "VIOLATED"}

    def test_an_immutable_row_cannot_be_updated(self) -> None:
        self.populate()
        for table in IMMUTABLE_TABLES:
            column = self.COLUMNS[table]
            value = self.NEW_VALUE.get(column, "f" * 64)
            with self.subTest(table=table):
                self.refused_and_unchanged(
                    f"UPDATE {table} SET {column} = ?",
                    (value,),
                    f"DATA-INT-006: {table} is immutable",
                )

    def test_an_immutable_row_cannot_be_deleted(self) -> None:
        self.populate()
        for table in IMMUTABLE_TABLES:
            with self.subTest(table=table):
                self.refused_and_unchanged(
                    f"DELETE FROM {table}", (), f"DATA-INT-006: {table} is immutable"
                )

    def test_candidates_and_heads_cannot_be_deleted(self) -> None:
        self.populate()
        for table in ("candidates", "lineage_heads"):
            with self.subTest(table=table):
                self.refused_and_unchanged(f"DELETE FROM {table}", (), "DATA-INT-006")

    def test_a_candidate_row_can_still_change_status(self) -> None:
        self.populate()
        self.move(C1, "ANALYZING")
        self.assertEqual(self.scalar("SELECT status FROM candidates"), "ANALYZING")

    def test_insert_or_replace_cannot_rewrite_history(self) -> None:
        """REPLACE deletes a row without a DELETE trigger unless the connection turns on
        recursive_triggers. A plain connection, with no such pragma, must still be refused."""
        self.populate()
        plain = sqlite3.connect(self.path, isolation_level=None)
        plain.execute("PRAGMA foreign_keys = ON")
        try:
            self.assertEqual(plain.execute("PRAGMA recursive_triggers").fetchone()[0], 0)
            replacements = {
                "trusted_states": (
                    "INSERT OR REPLACE INTO trusted_states VALUES (?,?,?,?,?,?,?)",
                    (S0, L, 0, None, "e" * 64, None, "{}"),
                ),
                "patches": ("INSERT OR REPLACE INTO patches VALUES (?,?,?,?)", (P1, S0, H2, "{}")),
                "resources": (
                    "INSERT OR REPLACE INTO resources VALUES (?,?,?,?,?)",
                    (R1, H2, "aws_instance.app", "aws_instance", "{}"),
                ),
                "state_resources": (
                    "INSERT OR REPLACE INTO state_resources VALUES (?,?,?)",
                    (S0, "aws_instance.app", R1),
                ),
                "candidate_resources": (
                    "INSERT OR REPLACE INTO candidate_resources VALUES (?,?,?)",
                    (C1, "aws_instance.app", R1),
                ),
                "invariants": (
                    "INSERT OR REPLACE INTO invariants VALUES (?,?,?,?,?)",
                    (INV, 1, H2, "t", "{}"),
                ),
                "invariant_refs": (
                    "INSERT OR REPLACE INTO invariant_refs (state_id, invariant_id, "
                    "invariant_version, status, origin, evidence_ids, last_verified_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (S0, INV, 1, "VIOLATED", "BASELINE", "[]", "t"),
                ),
                "candidates": (
                    "INSERT OR REPLACE INTO candidates (candidate_id, parent_state_id, patch_id, "
                    "lineage_id, candidate_sequence, status, patch_hash, content_json) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (C1, S0, P1, L, 1, "CREATED", H, "{}"),
                ),
                "lineage_heads": (
                    "INSERT OR REPLACE INTO lineage_heads VALUES (?,?)",
                    (L, S0),
                ),
            }
            self.assertEqual(
                set(replacements), set(IMMUTABLE_TABLES) | {"candidates", "lineage_heads"}
            )
            before = self.snapshot()
            for table, (sql, params) in replacements.items():
                with self.subTest(table=table):
                    self.refused(sql, params, "DATA-INT-006", conn=plain)
            self.assertEqual(self.snapshot(), before)
        finally:
            plain.close()


class TestTrustedStateRules(DbCase):
    """Trigger 2."""

    def test_a_baseline_and_its_child_are_accepted(self) -> None:
        self.add_state(S0, 0)
        self.add_state(S1, 1, parent=S0, decision=DEC1)
        self.assertEqual(self.count("trusted_states"), 2)

    def test_version_zero_has_no_parent_and_no_decision(self) -> None:
        self.add_state(S0, 0)
        self.refused_and_unchanged(
            "INSERT INTO trusted_states VALUES (?,?,?,?,?,?,?)",
            (S1, L2, 0, S0, H, None, "{}"),
            "SM-001",
        )
        self.refused_and_unchanged(
            "INSERT INTO trusted_states VALUES (?,?,?,?,?,?,?)",
            (S1, L2, 0, None, H, DEC1, "{}"),
            "SM-001",
        )

    def test_a_later_version_needs_a_commit_decision(self) -> None:
        self.add_state(S0, 0)
        self.refused_and_unchanged(
            "INSERT INTO trusted_states VALUES (?,?,?,?,?,?,?)",
            (S1, L, 1, S0, H, None, "{}"),
            "SM-001",
        )

    def test_a_later_version_needs_an_existing_parent(self) -> None:
        self.add_state(S0, 0)
        self.refused_and_unchanged(
            "INSERT INTO trusted_states VALUES (?,?,?,?,?,?,?)",
            (S1, L, 1, None, H, DEC1, "{}"),
            "SM-001",
        )
        self.refused_and_unchanged(
            "INSERT INTO trusted_states VALUES (?,?,?,?,?,?,?)",
            (S1, L, 1, S3, H, DEC1, "{}"),
            "SM-001",
        )

    def test_the_parent_must_be_version_minus_one(self) -> None:
        self.add_state(S0, 0)
        self.refused_and_unchanged(
            "INSERT INTO trusted_states VALUES (?,?,?,?,?,?,?)",
            (S2, L, 2, S0, H, DEC1, "{}"),
            "SM-001",
        )

    def test_the_parent_must_be_in_the_same_lineage(self) -> None:
        self.add_state(S0, 0, lineage=L2)
        self.refused_and_unchanged(
            "INSERT INTO trusted_states VALUES (?,?,?,?,?,?,?)",
            (S1, L, 1, S0, H, DEC1, "{}"),
            "SM-001",
        )


class TestLineageHeads(DbCase):
    """Trigger 3: the Doc 06 §6 current pointer."""

    def test_a_lineage_starts_at_a_version_zero_state_of_that_lineage(self) -> None:
        self.add_state(S0, 0)
        self.add_head()
        self.assertEqual(self.scalar("SELECT current_state_id FROM lineage_heads"), S0)

    def test_a_head_cannot_start_at_a_later_version(self) -> None:
        self.add_state(S0, 0)
        self.add_state(S1, 1, parent=S0, decision=DEC1)
        self.refused_and_unchanged("INSERT INTO lineage_heads VALUES (?,?)", (L, S1), "SM-001")

    def test_a_head_cannot_point_into_another_lineage(self) -> None:
        self.add_state(S0, 0, lineage=L2)
        self.refused_and_unchanged("INSERT INTO lineage_heads VALUES (?,?)", (L, S0), "SM-001")

    def test_a_head_cannot_point_at_nothing(self) -> None:
        self.refused("INSERT INTO lineage_heads VALUES (?,?)", (L, S0))

    def test_the_head_advances_to_a_child_of_the_current_state(self) -> None:
        self.add_state(S0, 0)
        self.add_head()
        self.add_state(S1, 1, parent=S0, decision=DEC1)
        self.run_sql("UPDATE lineage_heads SET current_state_id = ? WHERE lineage_id = ?", (S1, L))
        self.assertEqual(self.scalar("SELECT current_state_id FROM lineage_heads"), S1)

    def test_the_head_cannot_skip_a_version(self) -> None:
        self.add_state(S0, 0)
        self.add_head()
        self.add_state(S1, 1, parent=S0, decision=DEC1)
        self.add_state(S2, 2, parent=S1, decision=DEC2)
        self.refused_and_unchanged("UPDATE lineage_heads SET current_state_id = ?", (S2,), "SM-010")

    def test_the_head_cannot_move_back(self) -> None:
        self.add_state(S0, 0)
        self.add_head()
        self.add_state(S1, 1, parent=S0, decision=DEC1)
        self.run_sql("UPDATE lineage_heads SET current_state_id = ?", (S1,))
        self.refused_and_unchanged("UPDATE lineage_heads SET current_state_id = ?", (S0,), "SM-010")

    def test_the_head_cannot_move_to_the_same_state(self) -> None:
        self.add_state(S0, 0)
        self.add_head()
        self.refused_and_unchanged("UPDATE lineage_heads SET current_state_id = ?", (S0,), "SM-010")

    def test_the_head_cannot_move_into_another_lineage(self) -> None:
        self.add_state(S0, 0)
        self.add_head()
        self.add_state(S2, 0, lineage=L2)
        self.refused_and_unchanged("UPDATE lineage_heads SET current_state_id = ?", (S2,), "SM-010")

    def test_the_lineage_of_a_head_cannot_change(self) -> None:
        self.add_state(S0, 0)
        self.add_head()
        self.refused_and_unchanged("UPDATE lineage_heads SET lineage_id = ?", (L2,), "SM-010")


class TestCandidateInsert(DbCase):
    """Trigger 4."""

    def setUp(self) -> None:
        super().setUp()
        self.baseline_world()

    def test_a_created_candidate_with_a_matching_patch_is_accepted(self) -> None:
        self.add_candidate(C1, P1, 1)
        self.assertEqual(self.scalar("SELECT status FROM candidates"), "CREATED")

    def test_a_candidate_must_start_created(self) -> None:
        for status in ("BUILDING", "READY", "PROMOTABLE", "PROMOTED", "REJECTED"):
            with self.subTest(status=status):
                self.refused_and_unchanged(
                    INSERT_CANDIDATE,
                    (C1, S0, P1, L, 1, status, H, "{}"),
                    "Doc 06 §5",
                )

    def test_the_patch_must_be_written_against_the_candidates_parent(self) -> None:
        self.add_state(S1, 1, parent=S0, decision=DEC1)
        self.add_patch(P2, parent=S1)
        self.refused_and_unchanged(
            INSERT_CANDIDATE,
            (C1, S0, P2, L, 1, "CREATED", H, "{}"),
            "DATA-INT-001",
        )

    def test_the_patch_hash_must_equal_the_patch_content_hash(self) -> None:
        self.refused_and_unchanged(
            INSERT_CANDIDATE,
            (C1, S0, P1, L, 1, "CREATED", H2, "{}"),
            "DATA-INT-001",
        )

    def test_the_patch_must_exist(self) -> None:
        self.refused_and_unchanged(
            INSERT_CANDIDATE,
            (C1, S0, P3, L, 1, "CREATED", H, "{}"),
        )

    def test_the_lineage_must_be_the_parents_lineage(self) -> None:
        self.refused_and_unchanged(
            INSERT_CANDIDATE,
            (C1, S0, P1, L2, 1, "CREATED", H, "{}"),
            "DATA-INT-001/002",
        )


class TestCandidateStatusTransitions(DbCase):
    """Trigger 5, every pair, against Doc 06 §5 written out by hand."""

    def setUp(self) -> None:
        super().setUp()
        self.baseline_world()
        self.serial = 0

    def candidate_at(self, status: str) -> str:
        self.serial += 1
        candidate_id = uid(0x500 + self.serial)
        patch_id = uid(0x600 + self.serial)
        self.add_patch(patch_id)
        self.add_candidate(candidate_id, patch_id, 100 + self.serial)
        self.move(candidate_id, *PATH_TO[status])
        return candidate_id

    def test_every_pair_is_checked_against_the_lifecycle(self) -> None:
        statuses = sorted(LEGAL)
        checked = 0
        for old in statuses:
            if old == "PROMOTED":
                continue
            candidate_id = self.candidate_at(old)
            for new in statuses:
                self.run_sql("SAVEPOINT pair")
                try:
                    with self.subTest(old=old, new=new):
                        if new in LEGAL[old] and new != "PROMOTED":
                            self.run_sql(
                                "UPDATE candidates SET status = ? WHERE candidate_id = ?",
                                (new, candidate_id),
                            )
                            self.assertEqual(
                                self.scalar(
                                    "SELECT status FROM candidates WHERE candidate_id = ?",
                                    (candidate_id,),
                                ),
                                new,
                            )
                        elif new == "PROMOTED" and old == "PROMOTABLE":
                            # Legal pair; refused only because no promotion was committed (13.4).
                            self.refused(
                                "UPDATE candidates SET status = 'PROMOTED' WHERE candidate_id = ?",
                                (candidate_id,),
                                "DATA-INT-005",
                            )
                        else:
                            # Into PROMOTED a second trigger (13.4) may speak first.
                            self.refused(
                                "UPDATE candidates SET status = ? WHERE candidate_id = ?",
                                (new, candidate_id),
                                (
                                    None
                                    if new == "PROMOTED"
                                    else "illegal candidate status transition"
                                ),
                            )
                        checked += 1
                finally:
                    self.run_sql("ROLLBACK TO pair")
                    self.run_sql("RELEASE pair")
        self.assertEqual(checked, 9 * 10)

    def test_an_unknown_status_is_refused(self) -> None:
        candidate_id = self.candidate_at("CREATED")
        self.refused(
            "UPDATE candidates SET status = 'DONE' WHERE candidate_id = ?", (candidate_id,)
        )

    def test_a_terminal_status_cannot_change(self) -> None:
        for status in ("FAILED", "REJECTED", "RETRY_REQUIRED", "ESCALATED"):
            candidate_id = self.candidate_at(status)
            for new in sorted(LEGAL):
                with self.subTest(old=status, new=new):
                    self.refused(
                        "UPDATE candidates SET status = ? WHERE candidate_id = ?",
                        (new, candidate_id),
                    )

    def test_the_identity_columns_never_change(self) -> None:
        candidate_id = self.candidate_at("CREATED")
        self.add_patch(P2)
        changes = {
            "candidate_id": uid(0x5FF),
            "parent_state_id": S1,
            "patch_id": P2,
            "patch_hash": H2,
            "lineage_id": L2,
            "candidate_sequence": 99,
        }
        for column, value in changes.items():
            with self.subTest(column=column):
                self.refused_and_unchanged(
                    f"UPDATE candidates SET {column} = ?, status = 'BUILDING' "
                    "WHERE candidate_id = ?",
                    (value, candidate_id),
                    "Doc 05 §23",
                )
        # The same statement with no identity change is accepted.
        self.run_sql(
            "UPDATE candidates SET status = 'BUILDING' WHERE candidate_id = ?", (candidate_id,)
        )

    def test_state_hash_and_content_may_change_only_while_creating_or_building(self) -> None:
        candidate_id = self.candidate_at("CREATED")
        # CREATED -> BUILDING with new content: allowed.
        self.run_sql(
            "UPDATE candidates SET status = 'BUILDING', content_json = ? WHERE candidate_id = ?",
            ('{"resources": [], "note": "interim"}', candidate_id),
        )
        # BUILDING -> READY sets the state hash and the content: allowed.
        self.make_ready(candidate_id, [])
        # READY -> ANALYZING with a changed hash or content: refused.
        for column, value in (
            ("state_hash", "c" * 64),
            ("content_json", '{"resources": [], "x": 1}'),
        ):
            with self.subTest(column=column):
                self.refused_and_unchanged(
                    f"UPDATE candidates SET status = 'ANALYZING', {column} = ? "
                    "WHERE candidate_id = ?",
                    (value, candidate_id),
                    "Doc 05 §8.1",
                )
        self.refused_and_unchanged(
            "UPDATE candidates SET status = 'ANALYZING', state_hash = NULL WHERE candidate_id = ?",
            (candidate_id,),
            "Doc 05 §8.1",
        )
        # The same transition with the content untouched: allowed, and status_reason is free.
        self.run_sql(
            "UPDATE candidates SET status = 'ANALYZING' WHERE candidate_id = ?", (candidate_id,)
        )
        self.run_sql(
            "UPDATE candidates SET status = 'REJECTED', status_reason = 'x' WHERE candidate_id = ?",
            (candidate_id,),
        )


class TestPromotedNeedsACommittedPromotion(DbCase):
    """13.4."""

    def setUp(self) -> None:
        super().setUp()
        self.baseline_world()
        self.add_patch(P2)
        self.add_candidate(C1, P1, 1)
        self.add_candidate(C2, P2, 2)
        for candidate_id in (C1, C2):
            self.move(candidate_id, *PATH_TO["PROMOTABLE"])

    def promote_state(self) -> None:
        self.add_state(S1, 1, parent=S0, decision=DEC1)
        self.run_sql("UPDATE lineage_heads SET current_state_id = ?", (S1,))

    def test_promoted_is_refused_without_a_committed_promotion(self) -> None:
        self.refused_and_unchanged(
            "UPDATE candidates SET status = 'PROMOTED' WHERE candidate_id = ?",
            (C1,),
            "DATA-INT-005",
        )

    def test_promoted_is_accepted_after_the_head_moved_to_a_child_of_the_parent(self) -> None:
        self.promote_state()
        self.run_sql("UPDATE candidates SET status = 'PROMOTED' WHERE candidate_id = ?", (C1,))
        self.assertEqual(
            self.scalar("SELECT status FROM candidates WHERE candidate_id = ?", (C1,)), "PROMOTED"
        )

    def test_a_state_that_is_not_the_head_does_not_count(self) -> None:
        self.add_state(S1, 1, parent=S0, decision=DEC1)  # inserted, but the head did not move
        self.refused_and_unchanged(
            "UPDATE candidates SET status = 'PROMOTED' WHERE candidate_id = ?",
            (C1,),
            "DATA-INT-005",
        )

    def test_only_one_candidate_of_a_parent_can_be_promoted(self) -> None:
        self.promote_state()
        self.run_sql("UPDATE candidates SET status = 'PROMOTED' WHERE candidate_id = ?", (C1,))
        self.refused_and_unchanged(
            "UPDATE candidates SET status = 'PROMOTED' WHERE candidate_id = ?",
            (C2,),
            "DATA-INT-005",
        )

    def test_a_candidate_of_an_older_parent_cannot_use_a_later_promotion(self) -> None:
        self.promote_state()
        self.add_state(S2, 2, parent=S1, decision=DEC2)
        self.run_sql("UPDATE lineage_heads SET current_state_id = ?", (S2,))
        # The head's state S2 has parent S1, not S0: C1's parent S0 was promoted at an earlier head.
        self.refused_and_unchanged(
            "UPDATE candidates SET status = 'PROMOTED' WHERE candidate_id = ?",
            (C1,),
            "DATA-INT-005",
        )


class TestCandidateResources(DbCase):
    """Trigger 6 and 13.1."""

    def setUp(self) -> None:
        super().setUp()
        self.baseline_world()
        self.add_resource(R1, "aws_instance.app")
        self.add_resource(R2, "aws_db_instance.db")
        self.add_candidate(C1, P1, 1)

    def test_a_link_for_a_declared_resource_attaches_to_a_ready_candidate(self) -> None:
        self.move(C1, "BUILDING")
        self.make_ready(C1, [("aws_instance.app", R1), ("aws_db_instance.db", R2)])
        self.run_sql("INSERT INTO candidate_resources VALUES (?,?,?)", (C1, "aws_instance.app", R1))
        self.run_sql(
            "INSERT INTO candidate_resources VALUES (?,?,?)", (C1, "aws_db_instance.db", R2)
        )
        self.assertEqual(self.count("candidate_resources"), 2)

    def test_no_link_attaches_before_ready(self) -> None:
        for status in ("CREATED", "BUILDING"):
            with self.subTest(status=status):
                if status == "BUILDING":
                    self.move(C1, "BUILDING")
                self.refused_and_unchanged(
                    "INSERT INTO candidate_resources VALUES (?,?,?)",
                    (C1, "aws_instance.app", R1),
                    ("READY candidate only", "declared"),
                )

    def test_no_link_attaches_after_ready(self) -> None:
        # Both resources are declared, only one is linked while READY; the other is a declared
        # link that arrives late, after the candidate left READY, and so only the status refuses it.
        self.move(C1, "BUILDING")
        self.make_ready(C1, [("aws_instance.app", R1), ("aws_db_instance.db", R2)])
        self.run_sql("INSERT INTO candidate_resources VALUES (?,?,?)", (C1, "aws_instance.app", R1))
        self.move(C1, "ANALYZING")
        self.refused_and_unchanged(
            "INSERT INTO candidate_resources VALUES (?,?,?)",
            (C1, "aws_db_instance.db", R2),
            "READY candidate only",
        )

    def test_a_failed_candidate_takes_no_links(self) -> None:
        self.move(C1, "BUILDING", "FAILED")
        self.refused_and_unchanged(
            "INSERT INTO candidate_resources VALUES (?,?,?)",
            (C1, "aws_instance.app", R1),
            ("READY candidate only", "declared"),
        )

    def test_a_link_must_match_a_declared_resource(self) -> None:
        self.move(C1, "BUILDING")
        self.make_ready(C1, [("aws_instance.app", R1)])
        # An address the candidate does not declare.
        self.refused_and_unchanged(
            "INSERT INTO candidate_resources VALUES (?,?,?)",
            (C1, "aws_db_instance.db", R2),
            "declared",
        )
        # A declared address with another record.
        self.refused_and_unchanged(
            "INSERT INTO candidate_resources VALUES (?,?,?)",
            (C1, "aws_instance.app", R2),
            "declared",
        )

    def test_a_link_cannot_be_added_twice(self) -> None:
        self.move(C1, "BUILDING")
        self.make_ready(C1, [("aws_instance.app", R1)])
        self.run_sql("INSERT INTO candidate_resources VALUES (?,?,?)", (C1, "aws_instance.app", R1))
        self.refused_and_unchanged(
            "INSERT INTO candidate_resources VALUES (?,?,?)", (C1, "aws_instance.app", R1)
        )


class TestInvariantVersions(DbCase):
    """Trigger 7."""

    def test_versions_start_at_one_and_have_no_gaps(self) -> None:
        self.add_invariant(INV, 1)
        self.add_invariant(INV, 2)
        self.add_invariant(INV, 3)
        self.assertEqual(self.count("invariants"), 3)

    def test_a_first_version_other_than_one_is_refused(self) -> None:
        for version in (2, 3, 0):
            with self.subTest(version=version):
                self.refused_and_unchanged(
                    "INSERT INTO invariants VALUES (?,?,?,?,?)", (INV, version, H, "t", "{}")
                )

    def test_a_gap_is_refused(self) -> None:
        self.add_invariant(INV, 1)
        self.refused_and_unchanged(
            "INSERT INTO invariants VALUES (?,?,?,?,?)", (INV, 3, H, "t", "{}"), "Doc 06 §4.2"
        )

    def test_versions_of_another_invariant_do_not_count(self) -> None:
        self.add_invariant("INV-SEC-002", 1)
        self.refused_and_unchanged(
            "INSERT INTO invariants VALUES (?,?,?,?,?)", (INV, 2, H, "t", "{}"), "Doc 06 §4.2"
        )


class TestNoLateAttachmentToCommittedHistory(DbCase):
    """13.1: invariant_refs and state_resources."""

    REF = (
        "INSERT INTO invariant_refs (state_id, invariant_id, invariant_version, status, origin, "
        "evidence_ids, last_verified_at) VALUES (?,?,?,?,?,?,?)"
    )

    def setUp(self) -> None:
        super().setUp()
        self.add_invariant()
        self.add_invariant("INV-SEC-002")
        self.add_resource(R1, "aws_instance.app")
        self.add_resource(R2, "aws_db_instance.db")

    def test_refs_and_resources_attach_to_a_state_that_is_not_yet_committed(self) -> None:
        self.add_state(S0, 0)  # no head yet, no child
        self.add_ref(S0)
        self.run_sql("INSERT INTO state_resources VALUES (?,?,?)", (S0, "aws_instance.app", R1))
        self.assertEqual((self.count("invariant_refs"), self.count("state_resources")), (1, 1))

    def test_nothing_attaches_to_the_current_state_of_a_lineage(self) -> None:
        self.add_state(S0, 0)
        self.add_ref(S0)
        self.add_head()
        self.refused_and_unchanged(
            self.REF, (S0, "INV-SEC-002", 1, "PROTECTED", "BASELINE", "[]", "t"), "SM-009"
        )
        self.refused_and_unchanged(
            "INSERT INTO state_resources VALUES (?,?,?)", (S0, "aws_instance.app", R1), "SM-009"
        )

    def test_nothing_attaches_to_a_parent_state(self) -> None:
        self.add_state(S0, 0)
        self.add_head()
        self.add_state(S1, 1, parent=S0, decision=DEC1)
        self.run_sql("UPDATE lineage_heads SET current_state_id = ?", (S1,))
        # S0 is no longer the head, but it is S1's parent.
        self.refused_and_unchanged(
            self.REF, (S0, INV, 1, "PROTECTED", "BASELINE", "[]", "t"), "SM-009"
        )
        self.refused_and_unchanged(
            "INSERT INTO state_resources VALUES (?,?,?)", (S0, "aws_instance.app", R1), "SM-009"
        )

    def test_insert_or_replace_cannot_rewrite_the_rows_of_an_uncommitted_state(self) -> None:
        """The attach rule does not cover a state that is neither head nor parent; the REPLACE
        guard must stand on its own there."""
        self.add_state(S0, 0)
        self.add_state(S1, 1, parent=S0, decision=DEC1)  # no head, no child: attach is allowed
        self.add_ref(S1, INV, 1, "PROTECTED", "VERIFIED")
        self.run_sql("INSERT INTO state_resources VALUES (?,?,?)", (S1, "aws_instance.app", R1))
        plain = sqlite3.connect(self.path, isolation_level=None)
        plain.execute("PRAGMA foreign_keys = ON")
        try:
            before = self.snapshot()
            self.refused(
                "INSERT OR REPLACE INTO invariant_refs (state_id, invariant_id, "
                "invariant_version, status, origin, evidence_ids, last_verified_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (S1, INV, 1, "VIOLATED", "VERIFIED", "[]", "t"),
                "REPLACE would rewrite history",
                conn=plain,
            )
            self.refused(
                "INSERT OR REPLACE INTO state_resources VALUES (?,?,?)",
                (S1, "aws_instance.app", R2),
                "REPLACE would rewrite history",
                conn=plain,
            )
            self.assertEqual(self.snapshot(), before)
        finally:
            plain.close()

    def test_the_new_state_of_a_promotion_takes_its_rows_before_the_head_moves(self) -> None:
        self.add_state(S0, 0)
        self.add_head()
        self.add_state(S1, 1, parent=S0, decision=DEC1)
        self.add_ref(S1, INV, 1, "PROTECTED", "VERIFIED")
        self.run_sql("INSERT INTO state_resources VALUES (?,?,?)", (S1, "aws_instance.app", R1))
        self.run_sql("UPDATE lineage_heads SET current_state_id = ?", (S1,))
        self.assertEqual((self.count("invariant_refs"), self.count("state_resources")), (1, 1))


if __name__ == "__main__":
    unittest.main()
