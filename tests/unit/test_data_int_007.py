"""DATA-INT-007: evidence references must point to existing records (Doc 05 §22; C-47, C-60).

P2 checks existence only: every id in a stored trusted state's ``evidence_refs`` and in every
``invariant_refs.evidence_ids`` must exist in ``evidence_events``. The adapter checks it (A5) and so
do the database triggers (T5). Whether the evidence has the right binding ("generated for the
referenced state", Doc 06 §14) is P6's check (C-60), so evidence bound to something else is accepted
here, and a test says so.
"""

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from typing import Any

from core.domain.errors import PersistenceError
from core.persistence.schema import open_connection
from tests.domain_builders import FUNC, SEC, baseline, promote, proof, uid
from tests.evidence_builders import (
    candidate_submission,
    raw_insert_event,
    state_submission,
    submission,
)
from tests.persistence_builders import SAFE, Boom, RepoCase, seed_evidence

STATE = uid(0x77)
LINEAGE = uid(0xCC)
UNKNOWN = uid(0x6EE)
HASH = "ab" * 32


def new_state() -> Any:
    """A baseline of its own lineage whose two evidence ids (1051, 1052) nothing has stored."""
    return baseline(
        proofs=[proof(SEC, evidence=51), proof(FUNC, evidence=52)],
        state_id=STATE,
        lineage_id=LINEAGE,
    )


class Case(RepoCase):
    seed_bound = False
    hide_seeded_evidence = True

    def setUp(self) -> None:
        super().setUp()
        self.v0 = self.seed()
        self.state = new_state()
        self.ids = list(self.state.evidence_refs)

    def store_evidence(self, *evidence_ids: str, **binding: Any) -> None:
        with self.uow() as u:
            for evidence_id in evidence_ids:
                u.evidence.append(
                    submission(0, evidence_id=evidence_id, payload={"id": evidence_id}, **binding)
                )


class TestTheAdapterChecksExistence(Case):
    """A5: ``save_baseline`` and ``save_promoted`` refuse a state that links to unknown evidence."""

    def test_the_state_links_to_evidence_nothing_has_stored(self) -> None:
        self.assertEqual(len(self.ids), 2)
        with self.uow() as u:
            for evidence_id in self.ids:
                self.assertIsNone(u.evidence.get(evidence_id))

    def test_a_baseline_with_unknown_evidence_is_refused_and_names_the_rule(self) -> None:
        with self.assertRaises(PersistenceError) as caught, self.uow() as u:
            u.trusted_states.save_baseline(self.state)
        message = str(caught.exception)
        self.assertIn("DATA-INT-007", message)
        for evidence_id in self.ids:
            self.assertIn(evidence_id, message)
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 0)
        self.assertEqual(self.count("invariant_refs", "state_id = ?", (STATE,)), 0)

    def test_one_unknown_id_among_known_ones_is_enough_to_refuse(self) -> None:
        self.store_evidence(self.ids[0])
        with self.assertRaises(PersistenceError) as caught, self.uow() as u:
            u.trusted_states.save_baseline(self.state)
        self.assertIn(self.ids[1], str(caught.exception))
        self.assertNotIn(self.ids[0], str(caught.exception))
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 0)

    def test_known_evidence_is_accepted(self) -> None:
        self.store_evidence(*self.ids)
        with self.uow() as u:
            u.trusted_states.save_baseline(self.state)
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 1)

    def test_evidence_written_in_the_same_unit_of_work_is_known(self) -> None:
        with self.uow() as u:
            seed_evidence(u, self.state)
            u.trusted_states.save_baseline(self.state)
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 1)

    def test_existence_is_all_that_p2_checks(self) -> None:
        """C-60: the evidence need not be bound to the state; P6 checks the binding."""
        other = self.store_stages(self.v0, SAFE)[2]
        with self.uow() as u:
            u.evidence.append(
                state_submission(1, self.v0, evidence_id=self.ids[0], payload={"a": 1})
            )  # bound to v0, not to the new state
            u.evidence.append(
                candidate_submission(2, other, evidence_id=self.ids[1], payload={"b": 2})
            )  # bound to a candidate
            u.trusted_states.save_baseline(self.state)
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 1)

    def test_a_promoted_state_with_unknown_evidence_is_refused(self) -> None:
        promotable = self.store_stages(self.v0, SAFE)[-1]
        v1 = promote(promotable, self.v0)
        self.assertFalse(set(v1.evidence_refs) & set(self.seeded_evidence))
        with self.assertRaises(PersistenceError) as caught, self.uow() as u:
            u.trusted_states.save_promoted(v1)
        self.assertIn("DATA-INT-007", str(caught.exception))
        self.assertEqual(self.count("trusted_states"), 1)  # still only v0
        with self.uow() as u:
            seed_evidence(u, v1)
            u.trusted_states.save_promoted(v1)
        self.assertEqual(self.count("trusted_states"), 2)

    def test_a_refused_save_leaves_the_transaction_as_it_was(self) -> None:
        self.store_evidence(self.ids[0])
        with self.uow() as u:
            before = u.evidence.list_for_correlation(uid(0x9003))
            with self.assertRaises(PersistenceError):
                u.trusted_states.save_baseline(self.state)
            self.assertEqual(u.evidence.list_for_correlation(uid(0x9003)), before)
            self.assertIsNone(u.trusted_states.get(STATE))

    def test_a_state_whose_evidence_was_rolled_back_cannot_commit(self) -> None:
        with self.assertRaises(Boom), self.uow() as u:
            for evidence_id in self.ids:
                u.evidence.append(
                    submission(0, evidence_id=evidence_id, payload={"id": evidence_id})
                )
            raise Boom  # the evidence is rolled back
        self.assertEqual(self.count("evidence_events", "evidence_id = ?", (self.ids[0],)), 0)
        with self.assertRaises(PersistenceError) as caught, self.uow() as u:
            u.trusted_states.save_baseline(self.state)
        self.assertIn("DATA-INT-007", str(caught.exception))
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 0)

    def test_evidence_and_its_state_commit_together_and_roll_back_together(self) -> None:
        with self.assertRaises(Boom), self.uow() as u:
            seed_evidence(u, self.state)
            u.trusted_states.save_baseline(self.state)
            raise Boom
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 0)
        self.assertEqual(self.count("evidence_events", "evidence_id = ?", (self.ids[0],)), 0)

    def test_a_state_read_back_still_links_to_stored_evidence(self) -> None:
        self.store_evidence(*self.ids)
        with self.uow() as u:
            u.trusted_states.save_baseline(self.state)
        with self.uow() as u:
            stored = u.trusted_states.get(STATE)
            assert stored is not None
            for evidence_id in stored.evidence_refs:
                self.assertIsNotNone(u.evidence.get(evidence_id))


class TestTheTriggersCheckExistence(Case):
    """T5: the same rule in the database, for statements that bypass the adapter."""

    def setUp(self) -> None:
        super().setUp()
        self._connections: list[sqlite3.Connection] = []

    def tearDown(self) -> None:
        # connections must be closed before the temporary directory is removed (Windows locks it)
        for conn in self._connections:
            conn.close()
        super().tearDown()

    def raw(self) -> sqlite3.Connection:
        conn = open_connection(self.path)
        self._connections.append(conn)
        return conn

    @staticmethod
    def state_row(content: Any, state_id: str = STATE, lineage: str = LINEAGE) -> tuple[Any, ...]:
        return (state_id, lineage, 0, None, HASH, None, json.dumps(content))

    STATE_SQL = "INSERT INTO trusted_states VALUES (?,?,?,?,?,?,?)"
    REF_SQL = (
        "INSERT INTO invariant_refs (state_id, invariant_id, invariant_version, status, origin, "
        "evidence_ids, last_verified_at) VALUES (?,?,?,?,?,?,?)"
    )

    def triggers_other_than(self, table: str, keep: str) -> list[str]:
        with closing(sqlite3.connect(self.path)) as conn:
            return [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)
                )
                if r[0] != keep
            ]

    def test_a_state_row_that_links_to_unknown_evidence_is_refused(self) -> None:
        conn = self.raw()
        with self.assertRaises(sqlite3.DatabaseError) as caught:
            conn.execute(self.STATE_SQL, self.state_row({"evidence_refs": [UNKNOWN]}))
        self.assertIn("DATA-INT-007", str(caught.exception))
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 0)

    def test_a_state_row_with_one_unknown_id_among_known_ones_is_refused(self) -> None:
        self.store_evidence(self.ids[0])
        conn = self.raw()
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute(self.STATE_SQL, self.state_row({"evidence_refs": [self.ids[0], UNKNOWN]}))

    def test_a_state_row_that_links_to_known_evidence_is_accepted(self) -> None:
        self.store_evidence(*self.ids)
        self.raw().execute(self.STATE_SQL, self.state_row({"evidence_refs": self.ids}))
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 1)

    def test_a_state_row_with_no_references_is_accepted(self) -> None:
        for index, content in enumerate(({}, {"evidence_refs": []})):
            with self.subTest(content=content):
                row = self.state_row(content, uid(0x400 + index), uid(0x500 + index))
                self.raw().execute(self.STATE_SQL, row)

    def test_the_state_trigger_alone_refuses_it(self) -> None:
        conn = self.raw()
        for name in self.triggers_other_than(
            "trusted_states", "trusted_states_insert_evidence_refs"
        ):
            conn.execute(f"DROP TRIGGER {name}")
        row = self.state_row({"evidence_refs": [UNKNOWN]})
        with self.assertRaises(sqlite3.DatabaseError) as caught:
            conn.execute(self.STATE_SQL, row)
        self.assertIn("DATA-INT-007", str(caught.exception))
        conn.execute("DROP TRIGGER trusted_states_insert_evidence_refs")
        conn.execute(self.STATE_SQL, row)  # without the trigger the dangling reference is stored
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 1)

    def add_bare_state(self, conn: sqlite3.Connection) -> None:
        conn.execute(self.STATE_SQL, self.state_row({}))

    def ref_row(self, evidence_ids: list[str]) -> tuple[Any, ...]:
        return (STATE, SEC, 1, "PROTECTED", "BASELINE", json.dumps(evidence_ids), "t")

    def test_a_reference_row_with_unknown_evidence_is_refused(self) -> None:
        conn = self.raw()
        self.add_bare_state(conn)
        with self.assertRaises(sqlite3.DatabaseError) as caught:
            conn.execute(self.REF_SQL, self.ref_row([UNKNOWN]))
        self.assertIn("DATA-INT-007", str(caught.exception))
        self.assertEqual(self.count("invariant_refs", "state_id = ?", (STATE,)), 0)

    def test_a_reference_row_with_known_evidence_is_accepted(self) -> None:
        self.store_evidence(*self.ids)
        conn = self.raw()
        self.add_bare_state(conn)
        conn.execute(self.REF_SQL, self.ref_row(self.ids))
        self.assertEqual(self.count("invariant_refs", "state_id = ?", (STATE,)), 1)

    def test_a_reference_row_with_one_unknown_id_is_refused(self) -> None:
        self.store_evidence(self.ids[0])
        conn = self.raw()
        self.add_bare_state(conn)
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute(self.REF_SQL, self.ref_row([self.ids[0], UNKNOWN]))

    def test_the_reference_trigger_alone_refuses_it(self) -> None:
        conn = self.raw()
        self.add_bare_state(conn)
        for name in self.triggers_other_than(
            "invariant_refs", "invariant_refs_insert_evidence_ids"
        ):
            conn.execute(f"DROP TRIGGER {name}")
        with self.assertRaises(sqlite3.DatabaseError) as caught:
            conn.execute(self.REF_SQL, self.ref_row([UNKNOWN]))
        self.assertIn("DATA-INT-007", str(caught.exception))
        conn.execute("DROP TRIGGER invariant_refs_insert_evidence_ids")
        conn.execute(self.REF_SQL, self.ref_row([UNKNOWN]))
        self.assertEqual(self.count("invariant_refs", "state_id = ?", (STATE,)), 1)

    def test_evidence_that_is_stored_but_unbound_still_counts_as_existing(self) -> None:
        conn = self.raw()
        raw_insert_event(conn, submission(5, state_id=None, state_hash=None, evidence_id=UNKNOWN))
        conn.execute(self.STATE_SQL, self.state_row({"evidence_refs": [UNKNOWN]}))
        self.assertEqual(self.count("trusted_states", "state_id = ?", (STATE,)), 1)


if __name__ == "__main__":
    unittest.main()
