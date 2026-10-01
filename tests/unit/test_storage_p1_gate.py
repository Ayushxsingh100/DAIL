"""P1 exit-gate tests for the interim persistence layer (Doc 05 §22-§23, DATA-INT-001/005/006/010;
C-35; P1a step 13).

Everything here is attacked with raw SQL as well as through the typed API: the database, not
convention, enforces the immutability rules.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any

from core.domain.enums import CandidateStatus
from core.domain.errors import (
    DomainValidationError,
    HashMismatchError,
    IllegalTransitionError,
)
from core.domain.state import (
    CandidateState,
    TrustedState,
    finish_building,
    mark_promoted,
    start_building,
    transition_candidate,
)
from core.domain.storage import LocalStorage
from tests.domain_builders import (
    SEC,
    baseline,
    canonical_resources,
    invariant,
    new_candidate,
    promotable_candidate,
    promote,
    resource,
)

CS = CandidateStatus
SAFE = canonical_resources(ssh_open=False, db_path=True)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "t.db"
        self.storage = LocalStorage(self.db)
        self.storage.initialize_schema()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _raw(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        conn = sqlite3.connect(self.db)
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    def _scalar(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute(sql, params).fetchone()[0]
        finally:
            conn.close()


class TestRoundTrips(_Base):
    def test_trusted_state_round_trip(self) -> None:
        v0 = baseline()
        self.storage.save_trusted_state(v0)
        self.assertEqual(self.storage.load_trusted_state(v0.state_id), v0)

    def test_a_promoted_state_round_trips_with_its_references(self) -> None:
        v0 = baseline()
        self.storage.save_trusted_state(v0)
        v1 = promote(promotable_candidate(v0, SAFE), v0)
        self.storage.save_trusted_state(v1)
        loaded = self.storage.load_trusted_state(v1.state_id)
        self.assertEqual(loaded, v1)
        assert loaded is not None
        self.assertEqual(loaded.state_hash, v1.state_hash)
        self.assertEqual(loaded.invariant_refs, v1.invariant_refs)

    def test_load_missing_returns_none(self) -> None:
        self.assertIsNone(self.storage.load_trusted_state("nope"))
        self.assertIsNone(self.storage.load_candidate("nope"))
        self.assertIsNone(self.storage.load_invariant_definition("INV-NOPE-001", 1))

    def test_candidate_round_trip_and_status_update(self) -> None:
        v0 = baseline()
        self.storage.save_trusted_state(v0)
        c = new_candidate(v0)
        self.storage.save_candidate(c)
        self.assertEqual(self.storage.load_candidate(c.candidate_id), c)
        building = start_building(c)
        self.storage.update_candidate(building)
        ready = finish_building(building, SAFE)
        self.storage.update_candidate(ready)
        rejected = transition_candidate(transition_candidate(ready, CS.ANALYZING), CS.REJECTED)
        self.storage.update_candidate(transition_candidate(ready, CS.ANALYZING))
        self.storage.update_candidate(rejected)
        loaded = self.storage.load_candidate(c.candidate_id)
        assert loaded is not None
        self.assertEqual(loaded.status, CS.REJECTED)
        self.assertEqual(loaded, rejected)

    def test_invariant_definition_round_trip(self) -> None:
        inv = invariant(SEC)
        self.storage.save_invariant_definition(inv)
        loaded = self.storage.load_invariant_definition(SEC, 1)
        assert loaded is not None
        self.assertEqual(loaded.definition_hash(), inv.definition_hash())
        self.assertEqual(loaded, inv)


class TestLineage(_Base):
    def _chain(self, n: int) -> list[TrustedState]:
        states = [baseline()]
        self.storage.save_trusted_state(states[0])
        for i in range(1, n):
            candidate = promotable_candidate(states[-1], SAFE, n=i)
            nxt = promote(candidate, states[-1], decision=i)
            self.storage.save_trusted_state(nxt)
            states.append(nxt)
        return states

    def test_lineage_newest_first_ending_at_version_zero(self) -> None:
        states = self._chain(4)
        lineage = self.storage.trusted_state_lineage(states[-1].state_id)
        self.assertEqual([s.version for s in lineage], [3, 2, 1, 0])
        self.assertIsNone(lineage[-1].parent_state_id)
        self.assertEqual(lineage, list(reversed(states)))

    def test_dangling_parent_is_rejected_by_foreign_key(self) -> None:
        v0 = baseline()
        v1 = promote(promotable_candidate(v0, SAFE), v0)  # its parent v0 was never saved
        with self.assertRaises(sqlite3.IntegrityError):
            self.storage.save_trusted_state(v1)  # DATA-INT-001-style FK

    def test_a_broken_lineage_is_loud(self) -> None:
        states = self._chain(2)
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute("DROP TRIGGER trusted_state_no_delete")
            conn.execute("DELETE FROM trusted_state WHERE state_id = ?", (states[0].state_id,))
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(DomainValidationError):
            self.storage.trusted_state_lineage(states[1].state_id)

    def test_an_unknown_state_has_no_lineage(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.storage.trusted_state_lineage("missing")


class TestImmutability(_Base):
    """DATA-INT-006 and Doc 05 §23, attacked with raw SQL."""

    def setUp(self) -> None:
        super().setUp()
        self.v0 = baseline()
        self.storage.save_trusted_state(self.v0)
        self.c = new_candidate(self.v0)
        self.storage.save_candidate(self.c)

    def test_trusted_state_cannot_be_updated(self) -> None:
        for column in ("state_hash", "version", "content_json", "lineage_id", "committed_at"):
            with self.subTest(column=column), self.assertRaises(sqlite3.DatabaseError):
                self._raw(
                    f"UPDATE trusted_state SET {column}='tampered' WHERE state_id=?",
                    (self.v0.state_id,),
                )

    def test_trusted_state_cannot_be_deleted(self) -> None:
        with self.assertRaises(sqlite3.DatabaseError):
            self._raw("DELETE FROM trusted_state WHERE state_id=?", (self.v0.state_id,))
        self.assertEqual(self.storage.count_trusted_states(), 1)

    def test_candidate_identity_columns_cannot_change(self) -> None:
        for column in (
            "patch_hash",
            "parent_state_id",
            "candidate_id",
            "lineage_id",
            "patch_id",
            "candidate_sequence",
            "source",
            "normalization_version",
            "created_at",
        ):
            value: Any = 99 if column == "candidate_sequence" else "evil"
            with self.subTest(column=column), self.assertRaises(sqlite3.DatabaseError):
                self._raw(
                    f"UPDATE candidate_state SET {column}=? WHERE candidate_id=?",
                    (value, self.c.candidate_id),
                )

    def test_candidate_cannot_be_deleted(self) -> None:
        with self.assertRaises(sqlite3.DatabaseError):
            self._raw("DELETE FROM candidate_state WHERE candidate_id=?", (self.c.candidate_id,))

    def test_candidate_status_may_change(self) -> None:
        self._raw(
            "UPDATE candidate_state SET status='REJECTED' WHERE candidate_id=?",
            (self.c.candidate_id,),
        )  # must NOT raise

    def test_state_hash_may_be_set_while_building_but_never_after_ready(self) -> None:
        building = start_building(self.c)
        self.storage.update_candidate(building)
        self._raw(
            "UPDATE candidate_state SET state_hash='interim' WHERE candidate_id=?",
            (self.c.candidate_id,),
        )  # still BUILDING: allowed
        ready = finish_building(building, SAFE)
        self._raw(
            "UPDATE candidate_state SET state_hash=?, status='READY' WHERE candidate_id=?",
            (ready.state_hash, self.c.candidate_id),
        )  # BUILDING -> READY sets the hash
        with self.assertRaises(sqlite3.DatabaseError):
            self._raw(
                "UPDATE candidate_state SET state_hash='evil' WHERE candidate_id=?",
                (self.c.candidate_id,),
            )
        with self.assertRaises(sqlite3.DatabaseError):
            self._raw(
                "UPDATE candidate_state SET state_hash=NULL WHERE candidate_id=?",
                (self.c.candidate_id,),
            )

    def test_invariant_definitions_cannot_be_updated_or_deleted(self) -> None:
        self.storage.save_invariant_definition(invariant(SEC))
        for column in ("definition_hash", "content_json", "created_at"):
            with self.subTest(column=column), self.assertRaises(sqlite3.DatabaseError):
                self._raw(
                    f"UPDATE invariant SET {column}='x' WHERE invariant_id=? AND version=1",
                    (SEC,),
                )
        with self.assertRaises(sqlite3.DatabaseError):
            self._raw("DELETE FROM invariant WHERE invariant_id=?", (SEC,))
        self.assertIsNotNone(self.storage.load_invariant_definition(SEC, 1))


class TestUpdateCandidateRules(_Base):
    """``update_candidate`` accepts only a legal successor of the stored candidate (Doc 06 §30)."""

    def setUp(self) -> None:
        super().setUp()
        self.v0 = baseline()
        self.storage.save_trusted_state(self.v0)
        created = new_candidate(self.v0)
        self.storage.save_candidate(created)
        building = start_building(created)
        self.storage.update_candidate(building)
        self.ready = finish_building(building, SAFE)
        self.storage.update_candidate(self.ready)

    def test_ready_to_promoted_is_not_a_legal_successor(self) -> None:
        # Craft the same candidate id in PROMOTED state through the legal path elsewhere.
        analyzing = transition_candidate(self.ready, CS.ANALYZING)
        promotable = transition_candidate(analyzing, CS.PROMOTABLE)
        promoted = mark_promoted(promotable, promote(promotable, self.v0))
        with self.assertRaises(IllegalTransitionError):
            self.storage.update_candidate(promoted)  # READY -> PROMOTED skips ANALYZING/PROMOTABLE

    def test_the_stored_resources_cannot_change_after_ready(self) -> None:
        other = finish_building(
            start_building(new_candidate(self.v0, n=1)), [resource("aws_instance.other")]
        )  # same candidate id, different resources, status READY
        changed = transition_candidate(other, CS.ANALYZING)  # READY -> ANALYZING is legal
        with self.assertRaises(DomainValidationError) as ctx:
            self.storage.update_candidate(changed)
        self.assertIn("resources", str(ctx.exception))
        stored = self.storage.load_candidate(self.ready.candidate_id)
        assert stored is not None
        self.assertEqual(stored.resources, self.ready.resources)
        self.assertEqual(stored.state_hash, self.ready.state_hash)

    def test_identity_fields_cannot_change(self) -> None:
        # A candidate with the same id but another patch/sequence is not a successor.
        other = new_candidate(self.v0, sequence=2, n=1)
        self.assertEqual(other.candidate_id, self.ready.candidate_id)
        building = start_building(other)
        ready = finish_building(building, SAFE)
        analyzing = transition_candidate(ready, CS.ANALYZING)
        with self.assertRaises(DomainValidationError):
            self.storage.update_candidate(analyzing)

    def test_a_legal_successor_is_stored(self) -> None:
        analyzing = transition_candidate(self.ready, CS.ANALYZING)
        self.storage.update_candidate(analyzing)
        self.assertEqual(self.storage.load_candidate(analyzing.candidate_id), analyzing)


class TestTamperDetection(_Base):
    """A raw edit of ``content_json`` is caught when the row is loaded: ``from_dict`` recomputes
    every hash (DATA-INT-010)."""

    def setUp(self) -> None:
        super().setUp()
        self.v0 = baseline()
        self.storage.save_trusted_state(self.v0)
        created = new_candidate(self.v0)
        self.storage.save_candidate(created)
        building = start_building(created)
        self.storage.update_candidate(building)
        self.ready = finish_building(building, SAFE)
        self.storage.update_candidate(self.ready)

    def _tamper_candidate_json(self, mutate: Any) -> None:
        content = json.loads(
            self._scalar(
                "SELECT content_json FROM candidate_state WHERE candidate_id=?",
                (self.ready.candidate_id,),
            )
        )
        mutate(content)
        self._raw(
            "UPDATE candidate_state SET content_json=? WHERE candidate_id=?",
            (json.dumps(content), self.ready.candidate_id),
        )

    def test_a_tampered_candidate_resource_is_caught_at_load(self) -> None:
        def mutate(content: dict[str, Any]) -> None:
            content["resources"][0]["attributes"]["size"] = "tampered"

        self._tamper_candidate_json(mutate)
        with self.assertRaises(HashMismatchError):
            self.storage.load_candidate(self.ready.candidate_id)

    def test_a_status_edited_only_in_the_json_is_caught(self) -> None:
        def mutate(content: dict[str, Any]) -> None:
            content["status"] = "PROMOTED"

        self._tamper_candidate_json(mutate)
        with self.assertRaises(DomainValidationError):
            self.storage.load_candidate(self.ready.candidate_id)

    def test_a_status_edited_only_in_the_column_is_caught(self) -> None:
        self._raw(
            "UPDATE candidate_state SET status='PROMOTED' WHERE candidate_id=?",
            (self.ready.candidate_id,),
        )
        with self.assertRaises(DomainValidationError):
            self.storage.load_candidate(self.ready.candidate_id)

    def test_a_tampered_trusted_state_is_caught_at_load(self) -> None:
        content = json.loads(
            self._scalar(
                "SELECT content_json FROM trusted_state WHERE state_id=?", (self.v0.state_id,)
            )
        )
        content["resources"][0]["attributes"]["size"] = "tampered"
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("DROP TRIGGER trusted_state_no_update")  # an attacker with file access
            conn.execute(
                "UPDATE trusted_state SET content_json=? WHERE state_id=?",
                (json.dumps(content), self.v0.state_id),
            )
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(HashMismatchError):
            self.storage.load_trusted_state(self.v0.state_id)

    def test_a_scalar_column_that_disagrees_with_the_json_is_caught(self) -> None:
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("DROP TRIGGER trusted_state_no_update")
            conn.execute("UPDATE trusted_state SET version=5 WHERE state_id=?", (self.v0.state_id,))
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(DomainValidationError):
            self.storage.load_trusted_state(self.v0.state_id)

    def test_a_tampered_invariant_definition_is_caught_at_load(self) -> None:
        self.storage.save_invariant_definition(invariant(SEC))
        content = json.loads(
            self._scalar("SELECT content_json FROM invariant WHERE invariant_id=?", (SEC,))
        )
        content["description"] = "tampered"
        conn = sqlite3.connect(self.db)
        try:
            conn.execute("DROP TRIGGER invariant_no_update")
            conn.execute(
                "UPDATE invariant SET content_json=? WHERE invariant_id=?",
                (json.dumps(content), SEC),
            )
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(HashMismatchError):
            self.storage.load_invariant_definition(SEC, 1)


class TestStoredCandidatesAreNotTrusted(_Base):
    def test_a_stored_candidate_is_never_a_trusted_state(self) -> None:
        v0 = baseline()
        self.storage.save_trusted_state(v0)
        c = new_candidate(v0)
        self.storage.save_candidate(c)
        self.assertIsNone(self.storage.load_trusted_state(c.candidate_id))
        self.assertEqual(self.storage.count_trusted_states(), 1)
        loaded = self.storage.load_candidate(c.candidate_id)
        self.assertIsInstance(loaded, CandidateState)


if __name__ == "__main__":
    unittest.main()
