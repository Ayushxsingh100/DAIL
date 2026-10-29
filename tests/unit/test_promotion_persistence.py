"""Schema 6 and the decision repository (P6b step 4; Doc 05 §15, §20-§23, §32; DATA-INT-003 and
004; C-38, C-42, C-44, C-47, C-163, C-165, C-168).

HAND EXPECTATIONS, written before the code (C-165 as amended by C-168, decision (b)):

* ``SCHEMA_VERSION`` is "6"; the first 92 statements (all of schema 5) are byte-identical, pinned
  by a SHA-256 taken from the schema-5 code before it was touched; the new statements are appended.
* ``promotion_decisions`` holds the thirteen fields of ``PromotionDecision``; its triggers refuse
  DELETE and REPLACE, refuse a decision whose parent is not its candidate's parent (DATA-INT-003),
  refuse a row stored with a committed state, and let ``committed_state_id`` change once, from NULL,
  for a PROMOTE, to a state whose ``commit_decision_id`` is that decision and whose parent is the
  decision's parent, with every other column immutable (DATA-INT-004). At most one committed
  decision per candidate, one decision per committed state, one state per commit decision (unique
  indexes, C-163).
* No trigger demands a decision row for a promoted state (C-168, decision (b)).
* The candidate-status trigger of schema 5 is dropped and created again in the appended statements
  with the extra pair PROMOTABLE -> ESCALATED (C-38); nothing else about it changes.
* A database with schema version 5 is refused with the delete-and-retry message (C-44).
"""

from __future__ import annotations

import hashlib
import sqlite3
import unittest
from contextlib import closing
from typing import Any

from core.domain.enums import CandidateStatus as CS
from core.domain.enums import DecisionType
from core.domain.errors import DomainValidationError, PersistenceError
from core.domain.promotion import (
    BlockingCondition,
    ConflictingDuplicateError,
    DecisionReason,
    PromotionDecision,
    ProofSource,
    RequiredCheck,
)
from core.domain.state import transition_candidate
from core.persistence.schema import DDL, SCHEMA_VERSION, initialize_database, open_connection
from tests.domain_builders import uid
from tests.persistence_builders import SAFE, RepoCase

SCHEMA_5_STATEMENTS = 92
SCHEMA_5_DDL_SHA256 = "917394cc04896ec806a305ac5e8ea0a0f58d62b5fd3049969ae3697a9912e4c3"
SCHEMA_6_DDL_SHA256 = "aae75310c5075681a40a46ec5ea1b6a6e50cb9afef533070d0ff090fecc51e93"
D, R = DecisionType, DecisionReason

COLUMNS = [
    "decision_id",
    "candidate_id",
    "parent_state_id",
    "decision",
    "reason",
    "policy_version",
    "attempt_number",
    "required_checks_json",
    "blocking_conditions_json",
    "supporting_results_json",
    "content_hash",
    "created_at",
    "committed_state_id",
]
NEW_TRIGGERS = {
    "promotion_decisions_no_delete",
    "promotion_decisions_no_replace",
    "promotion_decisions_insert_rules",
    "promotion_decisions_insert_uncommitted",
    "promotion_decisions_update_identity",
    "promotion_decisions_update_commit",
}
NEW_INDEXES = {
    "uq_promotion_decisions_committed_candidate",
    "uq_trusted_states_commit_decision",
    "ix_promotion_decisions_candidate",
}


def make_decision(
    candidate: Any,
    *,
    kind: DecisionType = D.PROMOTE,
    decision_id: str | None = None,
    parent_state_id: str | None = None,
    n: int = 1,
) -> PromotionDecision:
    promote = kind is D.PROMOTE
    return PromotionDecision.create(
        decision_id=decision_id or uid(4000 + n),
        candidate_id=candidate.candidate_id,
        parent_state_id=parent_state_id or candidate.parent_state_id,
        decision=kind,
        reason=R.ALL_REQUIRED_PROVEN if promote else R.REQUIRED_CHECK_FAILED,
        policy_version="policy-1",
        attempt_number=1,
        required_checks=[RequiredCheck("CONSISTENCY", "GATE", ProofSource.VERIFIED, uid(7001))],
        blocking_conditions=(
            []
            if promote
            else [BlockingCondition(R.REQUIRED_CHECK_FAILED, kind, "INVARIANT:INV-SEC-001:1", "x")]
        ),
        supporting_results=[uid(7001)],
        created_at=candidate.created_at,
    )


class DecisionCase(RepoCase):
    """A stored baseline v0 and a stored PROMOTABLE candidate of it."""

    def setUp(self) -> None:
        super().setUp()
        self.v0 = self.seed()
        self.steps = self.store_stages(self.v0, SAFE)
        self.promotable = self.steps[4]
        self.connections: list[sqlite3.Connection] = []

    def raw(self) -> sqlite3.Connection:
        conn = open_connection(self.path)
        self.connections.append(conn)
        return conn

    def tearDown(self) -> None:
        for conn in self.connections:  # a Windows file cannot be removed while it is open
            conn.close()
        super().tearDown()

    INSERT = (
        "INSERT INTO promotion_decisions (decision_id, candidate_id, parent_state_id, decision, "
        "reason, policy_version, attempt_number, required_checks_json, blocking_conditions_json, "
        "supporting_results_json, content_hash, created_at, committed_state_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )

    def row(self, decision: PromotionDecision, **override: Any) -> tuple[Any, ...]:
        values = {
            "decision_id": decision.decision_id,
            "candidate_id": decision.candidate_id,
            "parent_state_id": decision.parent_state_id,
            "decision": decision.decision.value,
            "reason": decision.reason.value,
            "policy_version": decision.policy_version,
            "attempt_number": decision.attempt_number,
            "required_checks_json": "[]",
            "blocking_conditions_json": "[]",
            "supporting_results_json": "[]",
            "content_hash": decision.content_hash,
            "created_at": "2026-10-01T09:00:00Z",
            "committed_state_id": None,
        }
        values.update(override)
        return tuple(values[c] for c in COLUMNS)

    def insert_raw(self, decision: PromotionDecision, **override: Any) -> None:
        conn = self.raw()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(self.INSERT, self.row(decision, **override))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    def abort(self, sql: str, params: tuple[Any, ...], needle: str) -> None:
        conn = self.raw()
        with self.assertRaises(sqlite3.Error) as caught:
            conn.execute(sql, params)
        self.assertIn(needle, str(caught.exception))


class TestSchema6(RepoCase):
    def test_the_version_is_six(self) -> None:
        self.assertEqual(SCHEMA_VERSION, "6")
        self.assertEqual(self.scalar("SELECT value FROM schema_meta"), "6")

    def test_the_schema_5_statements_are_byte_identical(self) -> None:
        digest = hashlib.sha256("\n".join(DDL[:SCHEMA_5_STATEMENTS]).encode()).hexdigest()
        self.assertEqual(digest, SCHEMA_5_DDL_SHA256)

    def test_the_schema_6_statements_follow_and_are_pinned(self) -> None:
        self.assertGreater(len(DDL), SCHEMA_5_STATEMENTS)
        self.assertTrue(
            DDL[SCHEMA_5_STATEMENTS].startswith("CREATE TABLE IF NOT EXISTS promotion_decisions")
        )
        self.assertEqual(hashlib.sha256("\n".join(DDL).encode()).hexdigest(), SCHEMA_6_DDL_SHA256)

    def test_the_decision_table_has_the_fields_of_the_decision(self) -> None:
        with closing(open_connection(self.path)) as conn:
            columns = [r[1] for r in conn.execute("PRAGMA table_info(promotion_decisions)")]
        self.assertEqual(columns, COLUMNS)

    def test_the_new_triggers_and_indexes_exist(self) -> None:
        with closing(open_connection(self.path)) as conn:
            triggers = {
                r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
            }
            indexes = {
                r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
            }
        self.assertTrue(triggers >= NEW_TRIGGERS)
        self.assertTrue(indexes >= NEW_INDEXES)
        # no reverse trigger: a promoted state is not required to have a decision row (C-168)
        self.assertNotIn("trusted_states_insert_decision", triggers)

    def test_initialising_twice_changes_nothing(self) -> None:
        before = self.scalar("SELECT count(*) FROM sqlite_master")
        initialize_database(self.path)
        self.assertEqual(self.scalar("SELECT count(*) FROM sqlite_master"), before)


class TestSchema5DatabaseIsRefused(RepoCase):
    def test_a_database_with_schema_5_is_refused_with_the_delete_message(self) -> None:
        old = self.path.with_name("old.db")
        with closing(sqlite3.connect(old)) as conn:
            for statement in DDL[:SCHEMA_5_STATEMENTS]:
                conn.execute(statement)
            conn.execute("INSERT INTO schema_meta VALUES ('schema_version', '5')")
            conn.commit()
        with self.assertRaises(PersistenceError) as caught:
            initialize_database(old)
        message = str(caught.exception)
        self.assertIn("schema version 5", message)
        self.assertIn("needs 6", message)
        self.assertIn("delete", message)
        with closing(sqlite3.connect(old)) as conn:  # and nothing was changed
            names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        self.assertNotIn("promotion_decisions", names)


class TestDecisionTriggers(DecisionCase):
    def test_a_consistent_decision_can_be_inserted(self) -> None:
        self.insert_raw(make_decision(self.promotable))
        self.assertEqual(self.count("promotion_decisions"), 1)

    def test_data_int_003_the_parent_must_be_the_candidates_parent(self) -> None:
        other = make_decision(self.promotable, parent_state_id=uid(77))
        with self.assertRaises(sqlite3.Error) as caught:
            self.insert_raw(other)
        self.assertIn("DATA-INT-003", str(caught.exception))
        self.assertEqual(self.count("promotion_decisions"), 0)

    def test_data_int_003_the_candidate_must_exist(self) -> None:
        ghost = make_decision(self.promotable)
        with self.assertRaises(sqlite3.Error):
            self.insert_raw(ghost, candidate_id=uid(66))

    def test_a_row_is_stored_uncommitted(self) -> None:
        with self.assertRaises(sqlite3.Error) as caught:
            self.insert_raw(make_decision(self.promotable), committed_state_id=self.v0.state_id)
        self.assertIn("DATA-INT-004", str(caught.exception))

    def test_a_decision_is_never_deleted_or_replaced(self) -> None:
        decision = make_decision(self.promotable)
        self.insert_raw(decision)
        self.abort("DELETE FROM promotion_decisions", (), "DATA-INT-004")
        self.abort(
            self.INSERT.replace("INSERT INTO", "INSERT OR REPLACE INTO"),
            self.row(decision, reason="REQUIRED_UNKNOWN"),
            "DATA-INT-006",
        )

    def test_every_column_but_the_committed_state_is_immutable(self) -> None:
        self.insert_raw(make_decision(self.promotable))
        for column, value in (
            ("reason", "REQUIRED_UNKNOWN"),
            ("policy_version", "other"),
            ("attempt_number", 2),
            ("content_hash", "0" * 64),
            ("created_at", "2027-01-01T00:00:00Z"),
            ("required_checks_json", "[1]"),
        ):
            with self.subTest(column=column):
                self.abort(f"UPDATE promotion_decisions SET {column} = ?", (value,), "DATA-INT-006")

    def commit_state(self) -> Any:
        """Promote the stored candidate in the database; return the new state."""
        return self.promote_stored(self.promotable, self.v0)

    def test_the_commit_sets_the_state_from_null_once(self) -> None:
        decision = make_decision(self.promotable)  # uid(4001), the id the helper promotes with
        self.insert_raw(decision)
        state = self.commit_state()
        self.assertEqual(state.commit_decision_id, decision.decision_id)
        conn = self.raw()
        conn.execute("UPDATE promotion_decisions SET committed_state_id = ?", (state.state_id,))
        self.assertEqual(
            self.scalar("SELECT committed_state_id FROM promotion_decisions"), state.state_id
        )
        self.abort("UPDATE promotion_decisions SET committed_state_id = NULL", (), "DATA-INT-004")
        self.abort(
            "UPDATE promotion_decisions SET committed_state_id = ?",
            (self.v0.state_id,),
            "DATA-INT-004",
        )

    def test_the_state_must_name_this_decision_as_its_commit_decision(self) -> None:
        decision = make_decision(self.promotable, decision_id=uid(4099), n=99)
        self.insert_raw(decision)
        state = self.commit_state()  # its commit_decision_id is uid(4001), not uid(4099)
        self.assertNotEqual(state.commit_decision_id, decision.decision_id)
        self.abort(
            "UPDATE promotion_decisions SET committed_state_id = ?",
            (state.state_id,),
            "DATA-INT-004",
        )

    def test_only_a_promote_can_be_committed(self) -> None:
        reject = make_decision(self.promotable, kind=D.REJECT, decision_id=uid(4001))
        self.insert_raw(reject)
        state = self.commit_state()
        self.abort(
            "UPDATE promotion_decisions SET committed_state_id = ?",
            (state.state_id,),
            "DATA-INT-004",
        )

    def test_the_state_must_be_a_child_of_the_decisions_parent(self) -> None:
        # a decision whose parent is v0 cannot be committed to the baseline itself
        decision = make_decision(self.promotable)
        self.insert_raw(decision)
        self.abort(
            "UPDATE promotion_decisions SET committed_state_id = ?",
            (self.v0.state_id,),
            "DATA-INT-004",
        )

    def test_at_most_one_committed_decision_per_candidate(self) -> None:
        # C-163: two decisions of one candidate cannot both be committed. The triggers are dropped
        # (an attacker with file access can), so only the unique partial index is left to refuse.
        first = make_decision(self.promotable)  # uid(4001), the id the helper promotes with
        second = make_decision(self.promotable, decision_id=uid(4002), n=2)
        self.insert_raw(first)
        self.insert_raw(second)
        state = self.commit_state()
        self.tamper(
            "UPDATE promotion_decisions SET committed_state_id = ? WHERE decision_id = ?",
            (state.state_id, first.decision_id),
        )
        self.tamper(
            "INSERT INTO trusted_states (state_id, lineage_id, version, parent_state_id, "
            "state_hash, commit_decision_id, content_json) SELECT ?, lineage_id, 7, "
            "parent_state_id, state_hash, ?, content_json FROM trusted_states WHERE state_id = ?",
            (uid(4300), second.decision_id, state.state_id),
        )
        self.abort(
            "UPDATE promotion_decisions SET committed_state_id = ? WHERE decision_id = ?",
            (uid(4300), second.decision_id),
            "UNIQUE constraint failed: promotion_decisions.candidate_id",
        )

    def test_a_promoted_state_needs_no_decision_row_at_the_database(self) -> None:
        # C-168, decision (b): the reverse direction is enforced by commit_promotion, not here
        self.commit_state()
        self.assertEqual(self.count("promotion_decisions"), 0)
        self.assertEqual(self.count("trusted_states"), 2)


class TestCandidateStatusTrigger(DecisionCase):
    def test_promotable_to_escalated_is_legal_in_the_database(self) -> None:
        conn = self.raw()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE candidates SET status = 'ESCALATED' WHERE candidate_id = ?",
            (self.promotable.candidate_id,),
        )
        conn.execute("COMMIT")
        self.assertEqual(
            self.scalar(
                "SELECT status FROM candidates WHERE candidate_id = ?",
                (self.promotable.candidate_id,),
            ),
            "ESCALATED",
        )

    def test_the_neighbouring_pairs_stay_illegal_in_the_database(self) -> None:
        for target in ("RETRY_REQUIRED", "ANALYZING", "READY", "CREATED", "BUILDING", "FAILED"):
            with self.subTest(target=target):
                self.abort(
                    "UPDATE candidates SET status = ? WHERE candidate_id = ?",
                    (target, self.promotable.candidate_id),
                    "illegal candidate status transition",
                )

    def test_the_repository_stores_the_escalation(self) -> None:
        escalated = transition_candidate(self.promotable, CS.ESCALATED)
        with self.uow() as u:
            u.candidates.save_transition(escalated)
        with self.uow() as u:
            stored = u.candidates.get(self.promotable.candidate_id)
        assert stored is not None
        self.assertIs(stored.status, CS.ESCALATED)


class TestDecisionRepository(DecisionCase):
    def test_every_kind_of_decision_round_trips(self) -> None:
        for n, kind in enumerate(DecisionType, start=1):
            decision = make_decision(self.promotable, kind=kind, n=10 + n)
            with self.uow() as u:
                u.decisions.save(decision)
            with self.uow() as u:
                self.assertEqual(u.decisions.get(decision.decision_id), decision)

    def test_unknown_decisions_are_none_and_the_list_is_in_order(self) -> None:
        with self.uow() as u:
            self.assertIsNone(u.decisions.get(uid(1)))
            self.assertEqual(u.decisions.for_candidate(self.promotable.candidate_id), ())
        first = make_decision(self.promotable, n=21)
        second = make_decision(self.promotable, kind=D.REJECT, n=22)
        with self.uow() as u:
            u.decisions.save(first)
            u.decisions.save(second)
        with self.uow() as u:
            found = u.decisions.for_candidate(self.promotable.candidate_id)
        self.assertEqual([d.decision_id for d in found], [first.decision_id, second.decision_id])

    def test_saving_the_same_decision_again_changes_nothing(self) -> None:
        decision = make_decision(self.promotable)
        with self.uow() as u:
            u.decisions.save(decision)
        with self.uow() as u:
            u.decisions.save(decision)
        self.assertEqual(self.count("promotion_decisions"), 1)

    def test_the_same_id_with_other_content_is_a_conflicting_duplicate(self) -> None:
        decision = make_decision(self.promotable)
        other = PromotionDecision.create(
            decision_id=decision.decision_id,
            candidate_id=decision.candidate_id,
            parent_state_id=decision.parent_state_id,
            decision=D.PROMOTE,
            reason=R.ALL_REQUIRED_PROVEN,
            policy_version="policy-2",
            attempt_number=1,
            required_checks=decision.required_checks,
            blocking_conditions=(),
            supporting_results=decision.supporting_results,
            created_at=decision.created_at,
        )
        with self.uow() as u:
            u.decisions.save(decision)
        with self.uow() as u, self.assertRaises(ConflictingDuplicateError):
            u.decisions.save(other)
        self.assertEqual(self.count("promotion_decisions"), 1)

    def test_a_committed_decision_cannot_be_saved(self) -> None:
        committed = make_decision(self.promotable).committed(uid(555))
        with self.uow() as u, self.assertRaises(DomainValidationError):
            u.decisions.save(committed)

    def test_only_a_decision_object_is_accepted(self) -> None:
        with self.uow() as u, self.assertRaises(DomainValidationError):
            u.decisions.save(make_decision(self.promotable).to_dict())  # type: ignore[arg-type]

    def test_the_commit_sets_the_state_and_returns_the_committed_decision(self) -> None:
        decision = make_decision(self.promotable)
        with self.uow() as u:
            u.decisions.save(decision)
        state = self.promote_stored(self.promotable, self.v0)
        with self.uow() as u:
            done = u.decisions.commit(decision.decision_id, state.state_id)
        self.assertEqual(done, decision.committed(state.state_id))
        with self.uow() as u:
            self.assertEqual(u.decisions.get(decision.decision_id), done)

    def test_a_decision_is_committed_once(self) -> None:
        decision = make_decision(self.promotable)
        with self.uow() as u:
            u.decisions.save(decision)
        state = self.promote_stored(self.promotable, self.v0)
        with self.uow() as u:
            u.decisions.commit(decision.decision_id, state.state_id)
        with self.uow() as u, self.assertRaises((PersistenceError, DomainValidationError)):
            u.decisions.commit(decision.decision_id, state.state_id)

    def test_a_decision_that_is_not_a_promote_cannot_be_committed(self) -> None:
        reject = make_decision(self.promotable, kind=D.REJECT, decision_id=uid(4001))
        with self.uow() as u:
            u.decisions.save(reject)
        state = self.promote_stored(self.promotable, self.v0)
        with self.uow() as u, self.assertRaises((PersistenceError, DomainValidationError)):
            u.decisions.commit(reject.decision_id, state.state_id)

    def test_an_unknown_decision_or_state_cannot_be_committed(self) -> None:
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.decisions.commit(uid(1), uid(2))

    def test_a_save_that_is_rolled_back_leaves_nothing(self) -> None:
        decision = make_decision(self.promotable)
        with self.assertRaises(RuntimeError), self.uow() as u:
            u.decisions.save(decision)
            raise RuntimeError("boom")
        self.assertEqual(self.count("promotion_decisions"), 0)

    def test_a_tampered_row_is_not_returned(self) -> None:
        decision = make_decision(self.promotable)
        with self.uow() as u:
            u.decisions.save(decision)
        for column, value in (
            ("reason", "REQUIRED_UNKNOWN"),
            ("content_hash", "0" * 64),
            ("supporting_results_json", "[]"),
            ("policy_version", "tampered"),
        ):
            with self.subTest(column=column):
                self.tamper(f"UPDATE promotion_decisions SET {column} = ?", (value,))
                with self.uow() as u, self.assertRaises(PersistenceError):
                    u.decisions.get(decision.decision_id)
                self.tamper(
                    f"UPDATE promotion_decisions SET {column} = ?",
                    (
                        {
                            "reason": decision.reason.value,
                            "content_hash": decision.content_hash,
                            "supporting_results_json": '["' + decision.supporting_results[0] + '"]',
                            "policy_version": decision.policy_version,
                        }[column],
                    ),
                )
                with self.uow() as u:
                    self.assertEqual(u.decisions.get(decision.decision_id), decision)


class TestCheckpoints(DecisionCase):
    def setUp(self) -> None:
        super().setUp()
        self.hits: list[str] = []

    def test_a_decision_save_hits_after_decision_insert(self) -> None:
        with self.uow(checkpoint=self.hits.append) as u:
            u.decisions.save(make_decision(self.promotable))
        self.assertEqual(self.hits[0], "after_decision_insert")
        self.assertEqual(self.hits[-1], "before_commit")

    def test_a_candidate_transition_hits_after_candidate_update(self) -> None:
        escalated = transition_candidate(self.promotable, CS.ESCALATED)
        with self.uow(checkpoint=self.hits.append) as u:
            u.candidates.save_transition(escalated)
        self.assertIn("after_candidate_update", self.hits)

    def test_a_decision_commit_hits_after_decision_commit(self) -> None:
        decision = make_decision(self.promotable)
        with self.uow() as u:
            u.decisions.save(decision)
        state = self.promote_stored(self.promotable, self.v0)
        with self.uow(checkpoint=self.hits.append) as u:
            u.decisions.commit(decision.decision_id, state.state_id)
        self.assertEqual(self.hits[0], "after_decision_commit")

    def test_a_fault_at_each_new_checkpoint_rolls_the_unit_back(self) -> None:
        decision = make_decision(self.promotable)

        def boom_at(name: str) -> Any:
            def hook(hit: str) -> None:
                if hit == name:
                    raise RuntimeError(name)

            return hook

        with (
            self.assertRaises(RuntimeError),
            self.uow(checkpoint=boom_at("after_decision_insert")) as u,
        ):
            u.decisions.save(decision)
        self.assertEqual(self.count("promotion_decisions"), 0)
        escalated = transition_candidate(self.promotable, CS.ESCALATED)
        with (
            self.assertRaises(RuntimeError),
            self.uow(checkpoint=boom_at("after_candidate_update")) as u,
        ):
            u.candidates.save_transition(escalated)
        self.assertEqual(
            self.scalar(
                "SELECT status FROM candidates WHERE candidate_id = ?",
                (self.promotable.candidate_id,),
            ),
            "PROMOTABLE",
        )


if __name__ == "__main__":
    unittest.main()
