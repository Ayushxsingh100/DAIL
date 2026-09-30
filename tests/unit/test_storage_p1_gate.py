"""P1 exit-gate tests for the persistence layer (Doc 05 Sections 22-23)."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from core.domain.enums import InvariantLifecycleState, InvariantType
from core.domain.invariant import Invariant
from core.domain.state import CandidateState, CandidateStatus, TrustedState
from core.domain.storage import LocalStorage


def _inv() -> Invariant:
    return Invariant(
        invariant_id="INV-SEC-001",
        version=1,
        description="no public ssh",
        invariant_type=InvariantType.SECURITY,
        predicate_id="ckv_aws_24",
        scope_id="aws_security_group",
        applicability_rule="always",
        verification_policy_id="default",
        verifier_version="checkov==3.2.526",
    )


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "t.db"
        self.storage = LocalStorage(self.db)
        self.storage.initialize_schema()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _raw(self, sql: str, params: tuple = ()) -> None:
        conn = sqlite3.connect(self.db)
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()


class TestRoundTrips(_Base):
    def test_trusted_state_round_trip(self) -> None:
        s0 = TrustedState.genesis(content_payload={"v": 0}, invariant_registry_version=1)
        self.storage.save_trusted_state(s0)
        self.assertEqual(self.storage.load_trusted_state(s0.state_id), s0)

    def test_load_missing_returns_none(self) -> None:
        self.assertIsNone(self.storage.load_trusted_state("nope"))
        self.assertIsNone(self.storage.load_candidate("nope"))
        self.assertIsNone(self.storage.load_invariant("nope", 1))

    def test_candidate_round_trip_and_status_update(self) -> None:
        s0 = TrustedState.genesis(content_payload={}, invariant_registry_version=1)
        self.storage.save_trusted_state(s0)
        c = CandidateState.build(parent=s0, patch_payload={"p": 1})
        self.storage.save_candidate(c)
        self.assertEqual(self.storage.load_candidate(c.candidate_id), c)
        c.mark_under_verification()
        c.mark_rejected()
        self.storage.update_candidate_status(c)
        loaded = self.storage.load_candidate(c.candidate_id)
        assert loaded is not None
        self.assertEqual(loaded.status, CandidateStatus.REJECTED)

    def test_invariant_round_trip_and_lifecycle_update(self) -> None:
        inv = _inv()
        self.storage.save_invariant(inv)
        inv.transition_to(InvariantLifecycleState.VERIFYING)
        self.storage.update_invariant_lifecycle(inv)
        loaded = self.storage.load_invariant("INV-SEC-001", 1)
        assert loaded is not None
        self.assertEqual(loaded.lifecycle_state, InvariantLifecycleState.VERIFYING)
        self.assertEqual(loaded.content_hash(), inv.content_hash())


class TestLineage(_Base):
    def _chain(self, n: int) -> list[TrustedState]:
        states = [TrustedState.genesis(content_payload={"v": 0}, invariant_registry_version=1)]
        self.storage.save_trusted_state(states[0])
        for i in range(1, n):
            c = CandidateState.build(parent=states[-1], patch_payload={"p": i})
            c.mark_under_verification()
            c.mark_promoted()
            nxt = TrustedState.promoted_from(
                candidate=c,
                parent=states[-1],
                content_payload={"v": i},
                invariant_registry_version=1,
            )
            self.storage.save_trusted_state(nxt)
            states.append(nxt)
        return states

    def test_lineage_newest_first_ending_at_genesis(self) -> None:
        states = self._chain(4)
        lineage = self.storage.trusted_state_lineage(states[-1].state_id)
        self.assertEqual([s.version for s in lineage], [4, 3, 2, 1])
        self.assertIsNone(lineage[-1].parent_state_id)

    def test_dangling_parent_is_rejected_by_foreign_key(self) -> None:
        orphan = TrustedState(
            state_id="state-x",
            version=2,
            content_hash="h",
            invariant_registry_version=1,
            parent_state_id="missing",
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.storage.save_trusted_state(orphan)  # DATA-INT-001-style FK


class TestImmutability(_Base):
    """DATA-INT-006 and Doc 05 Section 23, attacked with raw SQL."""

    def setUp(self) -> None:
        super().setUp()
        self.s0 = TrustedState.genesis(content_payload={}, invariant_registry_version=1)
        self.storage.save_trusted_state(self.s0)
        self.c = CandidateState.build(parent=self.s0, patch_payload={"p": 1})
        self.storage.save_candidate(self.c)

    def test_trusted_state_cannot_be_updated(self) -> None:
        with self.assertRaises(sqlite3.DatabaseError):
            self._raw(
                "UPDATE trusted_state SET content_hash='tampered' WHERE state_id=?",
                (self.s0.state_id,),
            )

    def test_trusted_state_cannot_be_deleted(self) -> None:
        with self.assertRaises(sqlite3.DatabaseError):
            self._raw("DELETE FROM trusted_state WHERE state_id=?", (self.s0.state_id,))

    def test_candidate_patch_hash_cannot_change(self) -> None:
        with self.assertRaises(sqlite3.DatabaseError):
            self._raw(
                "UPDATE candidate_state SET patch_hash='evil' WHERE candidate_id=?",
                (self.c.candidate_id,),
            )

    def test_candidate_parent_cannot_change(self) -> None:
        with self.assertRaises(sqlite3.DatabaseError):
            self._raw(
                "UPDATE candidate_state SET parent_state_id='other' WHERE candidate_id=?",
                (self.c.candidate_id,),
            )

    def test_candidate_cannot_be_deleted(self) -> None:
        with self.assertRaises(sqlite3.DatabaseError):
            self._raw("DELETE FROM candidate_state WHERE candidate_id=?", (self.c.candidate_id,))

    def test_candidate_status_may_change(self) -> None:
        self._raw(
            "UPDATE candidate_state SET status='REJECTED' WHERE candidate_id=?",
            (self.c.candidate_id,),
        )  # must NOT raise


if __name__ == "__main__":
    unittest.main()
