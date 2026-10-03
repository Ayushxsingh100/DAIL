"""Schema 5 evidence and audit tables: constraints and triggers, tested with raw SQL (Doc 05 §16.2,
§22; Doc 11 §4, §8, §9, §32, §33, §44, §46; C-52, C-53, C-55, C-59; P2-fix step 3).

Every rule is attacked with plain SQL, so the database (and not the domain constructors or the
adapter) is what refuses. Each trigger is also checked in isolation: every other trigger of its
table is dropped, the violating statement is refused by that trigger alone (its message is checked),
and once the trigger is dropped too the same statement is accepted. A refusal therefore cannot come
from anything else, and the rule cannot be silently lost.
"""

from __future__ import annotations

import hashlib
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any

from core.domain.evidence import EvidenceContext, EvidenceKind, EvidenceValidity
from core.persistence.schema import DDL, initialize_database, open_connection
from tests.domain_builders import baseline, uid
from tests.evidence_builders import (
    audit_submission,
    candidate_submission,
    eid,
    raw_insert_artifact,
    raw_insert_audit,
    raw_insert_event,
    raw_insert_supersession,
    raw_insert_transition,
    state_submission,
    submission,
    supersession_request,
    transition_request,
)
from tests.persistence_builders import SAFE, SAFE_OTHER, RepoCase

K = EvidenceKind
V = EvidenceValidity
SCHEMA_4_DDL_SHA256 = "3614feb7c9a7f669b9b4319d9bd4829cc206761fc23d0cac9ecfbd242610a960"
TRANSITIONS = "evidence_validity_transitions"
T3 = f"{TRANSITIONS}_insert_"
HASH = "cd" * 32
RECORD_ROW = {"scope": "RECORD", "context_kind": None, "context_id": None}


def bad_uuids(good: str) -> list[str]:
    """Strings that are not a canonical lowercase UUID (Doc 05 §3; C-55)."""
    return [
        "evd-0123456789abcdef",  # the retired prefixed form
        "A" + good[1:],  # an upper-case hexadecimal digit
        good[:-1],  # 35 characters
        good + "0",  # 37 characters
        good.replace("-", ""),
        "g" + good[1:],
        "",
    ]


class TestGoldenHash(unittest.TestCase):
    def test_the_fifty_schema_4_statements_are_byte_identical(self) -> None:
        digest = hashlib.sha256("\n".join(DDL[:50]).encode()).hexdigest()
        self.assertEqual(digest, SCHEMA_4_DDL_SHA256)

    def test_the_schema_5_statements_follow_them(self) -> None:
        self.assertGreater(len(DDL), 50)
        self.assertTrue(DDL[50].startswith("CREATE TABLE IF NOT EXISTS evidence_artifacts"))


class SchemaCase(RepoCase):
    """v0, two ANALYZING candidates c1 and c2, and (after ``add_evidence``) nine records:

    E1 VERIFICATION about v0       E2 IMPACT for c1        E3 VERIFICATION about v0, UNCERTAIN
    E4 VERIFICATION for c1         E5 IMPACT for c2        E6 VERIFICATION about v0 (newer)
    E7 CONFIGURATION about v0      E8, E9 unbound VERIFICATION
    """

    def setUp(self) -> None:
        super().setUp()
        self._world_n = 0
        self._transition_n = 0
        self._connections: list[sqlite3.Connection] = []
        self.subs: dict[int, Any] = {}
        self._build()

    def tearDown(self) -> None:
        # connections must be closed before the temporary directory is removed (Windows locks it)
        for conn in self._connections:
            conn.close()
        super().tearDown()

    def _build(self) -> None:
        self.v0 = self.seed()
        self.c1 = self.store_stages(self.v0, SAFE, n=1, sequence=1, upto=3)[3]
        self.c2 = self.store_stages(self.v0, SAFE_OTHER, n=2, sequence=2, upto=3)[3]
        self.v0_ctx = EvidenceContext.state(self.v0.state_id)
        self.c1_ctx = EvidenceContext.candidate(self.c1.candidate_id)
        self.c2_ctx = EvidenceContext.candidate(self.c2.candidate_id)

    def new_world(self, *, evidence: bool = False) -> None:
        """Start over in a new database file of the same temporary directory. A case that drops
        triggers and then breaks a rule needs a database of its own; the old file stays where it
        is, so connections still open on it never block the cleanup."""
        self._world_n += 1
        self.path = Path(self._tmp.name) / f"world{self._world_n}.db"
        initialize_database(self.path)
        self._build()
        if evidence:
            self.add_evidence()

    def add_evidence(self) -> None:
        subs = [
            state_submission(1, self.v0),
            candidate_submission(2, self.c1, kind=K.IMPACT),
            state_submission(3, self.v0, validity=V.UNCERTAIN, payload={"v": 3}),
            candidate_submission(4, self.c1),
            candidate_submission(5, self.c2, kind=K.IMPACT),
            state_submission(6, self.v0, payload={"v": 6}),
            state_submission(7, self.v0, kind=K.CONFIGURATION),
            submission(8, state_id=None, state_hash=None),
            submission(9, state_id=None, state_hash=None, payload={"u": 9}),
        ]
        with self.uow() as u:
            for sub in subs:
                u.evidence.append(sub)
        self.subs = {i + 1: sub for i, sub in enumerate(subs)}

    def raw(self) -> sqlite3.Connection:
        """A connection with foreign keys on, in autocommit mode (each statement is committed)."""
        conn = open_connection(self.path)
        self._connections.append(conn)
        return conn

    def checks_only(self) -> sqlite3.Connection:
        """A connection on a database whose triggers are all dropped, so that only the CHECK and
        FOREIGN KEY constraints can refuse a statement (BEFORE triggers fire ahead of CHECKs)."""
        conn = SchemaCase.raw(self)
        for table in (
            "evidence_artifacts",
            "evidence_events",
            TRANSITIONS,
            "evidence_supersessions",
            "audit_events",
        ):
            for name in self.trigger_names(table):
                conn.execute(f"DROP TRIGGER {name}")
        return conn

    def plain(self) -> sqlite3.Connection:
        """A plain ``sqlite3.connect``: recursive_triggers off, foreign keys off."""
        conn = sqlite3.connect(self.path)
        self._connections.append(conn)
        return conn

    def table_state(self, table: str) -> list[tuple[Any, ...]]:
        with closing(sqlite3.connect(self.path)) as conn:
            return [tuple(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]

    def trigger_names(self, table: str) -> list[str]:
        with closing(sqlite3.connect(self.path)) as conn:
            return [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?",
                    (table,),
                )
            ]

    def refused(self, fn: Any, contains: str | None = None) -> None:
        with self.assertRaises(sqlite3.DatabaseError) as caught:
            fn()
        if contains is not None:
            self.assertIn(contains, str(caught.exception))

    def tr(self, conn: sqlite3.Connection, **fields: Any) -> None:
        """A raw transition of E1 in the v0 context unless ``fields`` say otherwise."""
        self._transition_n += 1
        row: dict[str, Any] = {
            "transition_id": uid(0x6300 + self._transition_n),
            "evidence_id": eid(1),
            "context_id": self.v0.state_id,
        }
        row.update(fields)
        raw_insert_transition(conn, **row)

    def check_isolated(
        self,
        table: str,
        trigger: str,
        attempt: Any,
        contains: str,
        prep: Any = None,
        connect: Any = None,
    ) -> None:
        """``attempt(conn)`` is refused by ``trigger`` alone, and accepted without it."""
        if prep is not None:
            prep(self.raw())
        conn = (connect or self.raw)()
        for name in self.trigger_names(table):
            if name != trigger:
                conn.execute(f"DROP TRIGGER {name}")
        before = self.table_state(table)
        self.refused(lambda: attempt(conn), contains)
        self.assertEqual(self.table_state(table), before, "a refused statement changed the table")
        conn.execute(f"DROP TRIGGER {trigger}")
        attempt(conn)  # the trigger is what stopped it
        conn.commit()  # a plain connection holds an implicit transaction
        self.assertNotEqual(self.table_state(table), before)


class TestT1AppendOnly(SchemaCase):
    """D3: no UPDATE, DELETE or INSERT OR REPLACE on any of the five tables, even from a plain
    connection with recursive_triggers off."""

    TABLES = {
        "evidence_artifacts": "payload_json",
        "evidence_events": "event_name",
        TRANSITIONS: "reason",
        "evidence_supersessions": "created_at",
        "audit_events": "actor_id",
    }

    def setUp(self) -> None:
        super().setUp()
        self.add_evidence()
        self.populate()

    def populate(self) -> None:
        """One row in every table: a transition (and its event), a supersession, an event."""
        with self.uow() as u:
            u.evidence.append_transition(
                transition_request(1, eid(1), V.UNCERTAIN, context=self.v0_ctx)
            )
            u.evidence.supersede(supersession_request(2, eid(3), eid(6)))
            u.audit.append(audit_submission(1))

    def replacements(self) -> dict[str, Any]:
        e1 = self.subs[1]
        return {
            "evidence_artifacts": lambda c: c.execute(
                "INSERT OR REPLACE INTO evidence_artifacts (content_hash, payload_json) "
                "VALUES (?, ?)",
                (e1.event.content_hash, '{"rewritten":true}'),
            ),
            "evidence_events": lambda c: raw_insert_event(
                c, e1, verb="INSERT OR REPLACE", event_name="rewritten"
            ),
            TRANSITIONS: lambda c: raw_insert_transition(
                c,
                verb="INSERT OR REPLACE",
                transition_id=uid(0x6101),
                evidence_id=eid(1),
                context_id=self.v0.state_id,
                reason="rewritten",
            ),
            "evidence_supersessions": lambda c: raw_insert_supersession(
                c, eid(3), eid(6), verb="INSERT OR REPLACE"
            ),
            "audit_events": lambda c: raw_insert_audit(
                c, audit_submission(1), verb="INSERT OR REPLACE", event_type="ESCALATED"
            ),
        }

    def test_every_table_has_rows_to_attack(self) -> None:
        for table in self.TABLES:
            self.assertGreaterEqual(self.count(table), 1, table)

    def test_update_is_refused_from_a_plain_connection(self) -> None:
        conn = self.plain()
        for table, column in self.TABLES.items():
            with self.subTest(table=table):
                before = self.table_state(table)
                self.refused(
                    lambda t=table, c=column: conn.execute(f"UPDATE {t} SET {c} = {c}"),
                    "append-only",
                )
                self.assertEqual(self.table_state(table), before)

    def test_delete_is_refused_from_a_plain_connection(self) -> None:
        conn = self.plain()
        for table in self.TABLES:
            with self.subTest(table=table):
                before = self.table_state(table)
                self.refused(lambda t=table: conn.execute(f"DELETE FROM {t}"), "append-only")
                self.assertEqual(self.table_state(table), before)

    def test_insert_or_replace_is_refused_from_a_plain_connection(self) -> None:
        """D3: INSERT OR REPLACE on a plain connection deletes the old row without firing a DELETE
        trigger, so the guard has to be a BEFORE INSERT trigger."""
        conn = self.plain()
        self.assertEqual(conn.execute("PRAGMA recursive_triggers").fetchone()[0], 0)
        for table, attempt in self.replacements().items():
            with self.subTest(table=table):
                before = self.table_state(table)
                # another trigger may refuse the replacement row first; the isolated test below
                # shows that the _no_replace trigger alone refuses it, with its own message
                self.refused(lambda a=attempt: a(conn))
                self.assertEqual(self.table_state(table), before)

    def test_each_replace_guard_is_what_stops_the_rewrite(self) -> None:
        """Without its ``_no_replace`` trigger the same statement rewrites history."""
        for table in self.TABLES:
            with self.subTest(table=table):
                self.new_world(evidence=True)
                self.populate()
                self.check_isolated(
                    table,
                    f"{table}_no_replace",
                    self.replacements()[table],
                    "REPLACE would rewrite history",
                    connect=self.plain,
                )

    def test_the_artifacts_payload_cannot_be_rewritten_by_replace(self) -> None:
        digest = self.subs[1].event.content_hash
        conn = self.plain()
        self.refused(
            lambda: conn.execute(
                "INSERT OR REPLACE INTO evidence_artifacts (content_hash, payload_json) "
                "VALUES (?, ?)",
                (digest, '{"result":"FAIL"}'),
            )
        )
        self.assertEqual(
            self.scalar(
                "SELECT payload_json FROM evidence_artifacts WHERE content_hash = ?", (digest,)
            ),
            self.subs[1].payload_json,
        )


class TestEventConstraints(SchemaCase):
    """The CHECKs, foreign keys and B1 to B4 of ``evidence_events``. The triggers are dropped, so
    each refusal comes from a constraint of the table itself."""

    def raw(self) -> sqlite3.Connection:
        return self.checks_only()

    def test_a_valid_record_is_accepted(self) -> None:
        conn = self.raw()
        raw_insert_event(conn, state_submission(1, self.v0))
        raw_insert_event(conn, candidate_submission(2, self.c1, kind=K.IMPACT))
        raw_insert_event(conn, submission(3, state_id=None, state_hash=None))
        self.assertEqual(self.count("evidence_events"), 3)

    def test_every_id_column_must_be_a_canonical_uuid(self) -> None:
        conn = self.raw()
        state_bound = state_submission(1, self.v0)
        candidate_bound = candidate_submission(2, self.c1)
        cases = {
            "evidence_id": state_bound,
            "run_id": state_bound,
            "correlation_id": state_bound,
            "operation_id": state_bound,
            "state_id": state_bound,
            "attempt_id": candidate_bound,
            "candidate_id": candidate_bound,
            "parent_state_id": candidate_bound,
        }
        for column, sub in cases.items():
            good = sub.event.to_dict()[column]
            for bad in bad_uuids(good):
                with self.subTest(column=column, value=bad):
                    self.refused(
                        lambda s=sub, c=column, b=bad: raw_insert_event(conn, s, **{c: b}),
                        "constraint failed",
                    )
        self.assertEqual(self.count("evidence_events"), 0)

    def test_columns_are_restricted_to_the_taxonomy_and_the_creation_validities(self) -> None:
        conn = self.raw()
        sub = state_submission(1, self.v0)
        bad = {
            "kind": ("ORACLE", "CANDIDATE", "PATCH", "verification", ""),
            "validity": ("INVALID", "SUPERSEDED", "REDACTED", "valid", ""),
            "hash_algorithm": ("md5", "SHA256", ""),
            "event_name": ("",),
            "schema_version": ("",),
            "redaction_policy_version": ("",),
            "state_hash": ("ab" * 31, "AB" * 32, "g" * 64, ""),
            "provenance_json": ("{not json",),
            "content_json": ("{not json",),
        }
        for column, values in bad.items():
            for value in values:
                with self.subTest(column=column, value=value):
                    self.refused(
                        lambda c=column, v=value: raw_insert_event(conn, sub, **{c: v}), "CHECK"
                    )
        self.assertEqual(self.count("evidence_events"), 0)

    def test_payload_ref_must_be_the_kind_and_the_hash(self) -> None:
        conn = self.raw()
        sub = state_submission(1, self.v0)
        digest = sub.event.content_hash
        for ref in (
            f"evidence://impact/{digest}",  # the wrong type
            f"evidence://verification/{HASH}",  # the wrong hash
            f"cas:{digest}",  # the retired form
            f"ext:{digest}",
            f"EVIDENCE://verification/{digest}",
            f"evidence://VERIFICATION/{digest}",
            f"evidence://verification/{digest}/",
            "",
        ):
            with self.subTest(ref=ref):
                self.refused(lambda r=ref: raw_insert_event(conn, sub, payload_ref=r), "CHECK")
        self.assertEqual(self.count("evidence_events"), 0)

    def test_the_payload_must_be_stored_as_an_artifact(self) -> None:
        conn = self.raw()
        sub = state_submission(1, self.v0)
        ref = f"evidence://verification/{HASH}"
        self.refused(
            lambda: raw_insert_event(conn, sub, content_hash=HASH, payload_ref=ref), "FOREIGN KEY"
        )

    def test_a_candidate_must_exist(self) -> None:
        conn = self.raw()
        ghost = candidate_submission(1, self.c1, candidate_id=uid(0xABCD))
        self.refused(lambda: raw_insert_event(conn, ghost), "FOREIGN KEY")
        self.assertEqual(self.count("evidence_events"), 0)

    def test_b1_a_candidate_binding_needs_attempt_and_parent(self) -> None:
        conn = self.raw()
        sub = candidate_submission(1, self.c1)
        self.refused(lambda: raw_insert_event(conn, sub, attempt_id=None), "CHECK")
        self.refused(lambda: raw_insert_event(conn, sub, parent_state_id=None), "CHECK")
        raw_insert_event(conn, sub)

    def test_b2_state_only_evidence_records_the_state_hash(self) -> None:
        conn = self.raw()
        sub = state_submission(1, self.v0)
        self.refused(lambda: raw_insert_event(conn, sub, state_hash=None), "CHECK")
        raw_insert_event(conn, sub)

    def test_b3_unbound_evidence_has_no_state_hash_and_no_parent(self) -> None:
        conn = self.raw()
        sub = submission(1, state_id=None, state_hash=None)
        self.refused(lambda: raw_insert_event(conn, sub, state_hash=HASH), "CHECK")
        self.refused(lambda: raw_insert_event(conn, sub, parent_state_id=self.v0.state_id), "CHECK")
        raw_insert_event(conn, sub)

    def test_b4_impact_and_promotion_bind_to_a_candidate(self) -> None:
        conn = self.raw()
        for kind in ("IMPACT", "PROMOTION"):
            with self.subTest(kind=kind):
                for sub in (
                    state_submission(1, self.v0),  # state-bound only
                    submission(2, state_id=None, state_hash=None),  # unbound
                ):
                    digest = sub.event.content_hash
                    self.refused(
                        lambda s=sub, d=digest, k=kind: raw_insert_event(
                            conn, s, kind=k, payload_ref=f"evidence://{k.lower()}/{d}"
                        ),
                        "CHECK",
                    )
                ok = candidate_submission(3, self.c1)
                raw_insert_event(
                    conn,
                    ok,
                    evidence_id=eid(30 + len(kind)),
                    kind=kind,
                    payload_ref=f"evidence://{kind.lower()}/{ok.event.content_hash}",
                )

    def test_evidence_for_a_missing_state_fails_when_the_transaction_commits(self) -> None:
        """C-59: state_id is DEFERRABLE INITIALLY DEFERRED, so the insert is accepted but the
        commit is refused unless the state exists by then."""
        ghost = baseline(state_id=uid(0x88), lineage_id=uid(0xDD))
        conn = self.raw()
        conn.execute("BEGIN")
        raw_insert_event(conn, state_submission(1, ghost))  # accepted for now
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            conn.execute("COMMIT")
        self.assertIn("FOREIGN KEY", str(caught.exception))
        conn.execute("ROLLBACK")
        self.assertEqual(self.count("evidence_events"), 0)

    def test_evidence_for_an_existing_state_commits(self) -> None:
        conn = self.raw()
        conn.execute("BEGIN")
        raw_insert_event(conn, state_submission(1, self.v0))
        conn.execute("COMMIT")
        self.assertEqual(self.count("evidence_events"), 1)

    def test_the_parent_state_must_exist(self) -> None:
        conn = self.raw()
        sub = candidate_submission(1, self.c1)
        self.refused(lambda: raw_insert_event(conn, sub, parent_state_id=uid(0x99)), "FOREIGN KEY")

    def test_artifact_hashes_and_payloads_are_checked(self) -> None:
        conn = self.raw()
        for digest in ("ab" * 31, "AB" * 32, "g" * 64, ""):
            with self.subTest(hash=digest):
                self.refused(lambda d=digest: raw_insert_artifact(conn, d, "{}"), "CHECK")
        self.refused(lambda: raw_insert_artifact(conn, HASH, "{not json"), "CHECK")
        raw_insert_artifact(conn, HASH, "{}")


class TestT2CandidateBinding(SchemaCase):
    """Doc 11 §9 and §44: candidate-bound evidence names the candidate's parent and state hash."""

    def setUp(self) -> None:
        super().setUp()
        self.other_state = baseline(state_id=uid(0x77), lineage_id=uid(0xCC))
        with self.uow() as u:
            u.trusted_states.save_baseline(self.other_state)

    def test_matching_parent_and_hash_are_accepted(self) -> None:
        raw_insert_event(self.raw(), candidate_submission(1, self.c1))

    def test_a_parent_that_is_not_the_candidates_is_refused(self) -> None:
        sub = candidate_submission(1, self.c1)
        self.check_isolated(
            "evidence_events",
            "evidence_events_insert_candidate_parent",
            lambda c: raw_insert_event(c, sub, parent_state_id=self.other_state.state_id),
            "must name the candidate's parent state",
        )

    def test_a_state_hash_that_is_not_the_candidates_is_refused(self) -> None:
        sub = candidate_submission(1, self.c1)
        self.check_isolated(
            "evidence_events",
            "evidence_events_insert_candidate_hash",
            lambda c: raw_insert_event(c, sub, state_hash=HASH),
            "must carry the candidate's state_hash",
        )

    def test_a_missing_state_hash_is_refused_once_the_candidate_has_one(self) -> None:
        sub = candidate_submission(1, self.c1)
        self.assertIsNotNone(self.c1.state_hash)
        self.check_isolated(
            "evidence_events",
            "evidence_events_insert_candidate_hash",
            lambda c: raw_insert_event(c, sub, state_hash=None),
            "must carry the candidate's state_hash",
        )

    def test_both_hashes_may_be_null_while_the_candidate_has_none(self) -> None:
        created = self.store_stages(self.v0, SAFE, n=3, sequence=3, upto=0)[0]
        self.assertIsNone(created.state_hash)
        conn = self.raw()
        raw_insert_event(conn, candidate_submission(1, created))  # null IS null: accepted
        self.refused(
            lambda: raw_insert_event(conn, candidate_submission(2, created), state_hash=HASH),
            "must carry the candidate's state_hash",
        )


class TestT3TransitionRules(SchemaCase):
    """C-52 in the database: legality of every validity transition."""

    def setUp(self) -> None:
        super().setUp()
        self.add_evidence()

    def test_the_happy_path_is_accepted(self) -> None:
        conn = self.raw()
        self.tr(conn, to_validity="UNCERTAIN")  # E1 VALID -> UNCERTAIN in v0
        self.tr(conn, from_validity="UNCERTAIN", to_validity="VALID")  # resolved, own context
        self.tr(  # INVALID for candidate c1 (foreign context: from UNCERTAIN) with the impact
            conn,
            context_kind="CANDIDATE",
            context_id=self.c1.candidate_id,
            from_validity="UNCERTAIN",
            to_validity="INVALID",
            impact_ref=eid(2),
        )
        self.tr(  # E3 is UNCERTAIN at creation: an integrity failure invalidates the record
            conn,
            evidence_id=eid(3),
            from_validity="UNCERTAIN",
            to_validity="INVALID",
            reason="INTEGRITY: the payload hash differs",
            **RECORD_ROW,
        )
        raw_insert_supersession(conn, eid(1), eid(6))
        self.tr(  # E1 is VALID in v0 again: superseded by E6
            conn,
            from_validity="VALID",
            to_validity="SUPERSEDED",
            superseded_by=eid(6),
            reason="re-verified",
            **RECORD_ROW,
        )
        self.assertEqual(self.count(TRANSITIONS), 5)

    def test_from_validity_must_equal_the_effective_validity(self) -> None:
        self.check_isolated(
            TRANSITIONS,
            T3 + "from",
            lambda c: self.tr(c, from_validity="UNCERTAIN", to_validity="INVALID"),
            "from_validity must equal the effective validity",
        )

    def test_the_pair_must_be_allowed_for_the_scope(self) -> None:
        self.check_isolated(
            TRANSITIONS,
            T3 + "pair",
            lambda c: self.tr(c, from_validity="VALID", to_validity="VALID"),
            "this validity change is not allowed for its scope",
        )

    def test_invalid_is_terminal_in_its_context(self) -> None:
        def prep(conn: sqlite3.Connection) -> None:
            self.tr(conn)  # VALID -> INVALID in v0

        self.check_isolated(
            TRANSITIONS,
            T3 + "pair",
            lambda c: self.tr(c, from_validity="INVALID", to_validity="VALID"),
            "this validity change is not allowed for its scope",
            prep=prep,
        )

    def test_uncertain_to_valid_only_in_an_own_context(self) -> None:
        self.check_isolated(
            TRANSITIONS,
            T3 + "own_context",
            lambda c: self.tr(
                c,
                context_kind="CANDIDATE",
                context_id=self.c2.candidate_id,
                from_validity="UNCERTAIN",
                to_validity="VALID",
            ),
            "UNCERTAIN -> VALID only in a context the record was produced for",
        )

    def test_nothing_follows_a_record_transition(self) -> None:
        def prep(conn: sqlite3.Connection) -> None:
            self.tr(conn, to_validity="INVALID", reason="INTEGRITY: x", **RECORD_ROW)

        self.check_isolated(
            TRANSITIONS,
            T3 + "terminal",
            lambda c: self.tr(c),
            "nothing follows it",
            prep=prep,
        )

    def test_a_second_record_transition_is_refused(self) -> None:
        def prep(conn: sqlite3.Connection) -> None:
            self.tr(conn, to_validity="INVALID", reason="INTEGRITY: x", **RECORD_ROW)

        self.check_isolated(
            TRANSITIONS,
            T3 + "terminal",
            lambda c: self.tr(
                c,
                from_validity="INVALID",
                to_validity="INVALID",
                reason="INTEGRITY: y",
                **RECORD_ROW,
            ),
            "at most one RECORD-scope transition",
            prep=prep,
        )

    def test_superseded_needs_its_supersession_row(self) -> None:
        self.check_isolated(
            TRANSITIONS,
            T3 + "superseded",
            lambda c: self.tr(
                c, to_validity="SUPERSEDED", superseded_by=eid(6), reason="newer", **RECORD_ROW
            ),
            "SUPERSEDED requires superseded_by and its supersession row",
        )

    def test_superseded_names_the_record_that_the_supersession_row_names(self) -> None:
        def prep(conn: sqlite3.Connection) -> None:
            raw_insert_supersession(conn, eid(1), eid(6))

        self.check_isolated(
            TRANSITIONS,
            T3 + "superseded",
            lambda c: self.tr(
                c, to_validity="SUPERSEDED", superseded_by=eid(3), reason="newer", **RECORD_ROW
            ),
            "SUPERSEDED requires superseded_by and its supersession row",
            prep=prep,
        )

    def test_a_record_scope_invalid_is_an_integrity_failure(self) -> None:
        for reason in (
            "impact analysis",
            "integrity: lower case",
            " INTEGRITY: padded",
            "INTEGRITY",
        ):
            with self.subTest(reason=reason):
                self.new_world(evidence=True)
                self.check_isolated(
                    TRANSITIONS,
                    T3 + "integrity",
                    lambda c, r=reason: self.tr(c, to_validity="INVALID", reason=r, **RECORD_ROW),
                    "a RECORD-scope INVALID is an integrity failure",
                )

    def test_invalid_in_a_candidate_context_needs_an_impact_reference(self) -> None:
        def attempt(conn: sqlite3.Connection, impact_ref: str | None) -> None:
            self.tr(
                conn,
                context_kind="CANDIDATE",
                context_id=self.c1.candidate_id,
                from_validity="UNCERTAIN",
                to_validity="INVALID",
                impact_ref=impact_ref,
            )

        cases = {
            "no impact_ref": None,
            "evidence that is not IMPACT": eid(4),
            "IMPACT evidence for another candidate": eid(5),
            "evidence that does not exist": uid(0x5555),
        }
        for label, impact_ref in cases.items():
            with self.subTest(case=label):
                self.new_world(evidence=True)
                conn = self.raw()
                if impact_ref == uid(0x5555):
                    # the foreign key refuses it first; take it away to test the trigger alone
                    conn.execute("PRAGMA foreign_keys = OFF")
                for name in self.trigger_names(TRANSITIONS):
                    if name != T3 + "impact":
                        conn.execute(f"DROP TRIGGER {name}")
                self.refused(lambda c=conn, r=impact_ref: attempt(c, r), "needs an impact_ref")

    def test_invalid_in_a_candidate_context_with_the_right_impact_is_accepted(self) -> None:
        self.tr(
            self.raw(),
            context_kind="CANDIDATE",
            context_id=self.c1.candidate_id,
            from_validity="UNCERTAIN",
            to_validity="INVALID",
            impact_ref=eid(2),
        )

    def test_invalid_in_a_state_context_needs_no_impact_reference(self) -> None:
        self.tr(self.raw())  # VALID -> INVALID in the v0 context

    def test_scope_and_context_columns_agree(self) -> None:
        conn = self.checks_only()
        cases = {
            "RECORD with a context": {"scope": "RECORD"},
            "CONTEXT without a context": {"context_kind": None, "context_id": None},
            "CONTEXT without an id": {"context_id": None},
            "an unknown context kind": {"context_kind": "FILE"},
            "an unknown scope": {"scope": "GLOBAL", "context_kind": None, "context_id": None},
        }
        for label, fields in cases.items():
            with self.subTest(case=label):
                self.refused(lambda f=fields: self.tr(conn, **f), "CHECK")
        self.assertEqual(self.count(TRANSITIONS), 0)

    def test_validity_columns_are_restricted(self) -> None:
        conn = self.checks_only()
        cases = {
            "to REDACTED": {"to_validity": "REDACTED"},
            "to an unknown value": {"to_validity": "MAYBE"},
            "from an unknown value": {"from_validity": "MAYBE"},
            "SUPERSEDED in CONTEXT scope": {"to_validity": "SUPERSEDED", "superseded_by": eid(6)},
            "superseded_by without SUPERSEDED": {"superseded_by": eid(6)},
            "SUPERSEDED without superseded_by": {"to_validity": "SUPERSEDED", **RECORD_ROW},
            "an empty reason": {"reason": ""},
        }
        for label, fields in cases.items():
            with self.subTest(case=label):
                self.refused(lambda f=fields: self.tr(conn, **f), "CHECK")
        self.assertEqual(self.count(TRANSITIONS), 0)

    def test_every_id_column_must_be_a_canonical_uuid(self) -> None:
        conn = self.checks_only()
        for column in (
            "transition_id",
            "evidence_id",
            "context_id",
            "correlation_id",
            "operation_id",
        ):
            good = {"evidence_id": eid(1), "context_id": self.v0.state_id}.get(column, uid(0x6300))
            for bad in bad_uuids(good):
                with self.subTest(column=column, value=bad):
                    self.refused(
                        lambda c=column, b=bad: self.tr(conn, **{c: b}), "constraint failed"
                    )
        self.assertEqual(self.count(TRANSITIONS), 0)

    def test_the_evidence_must_exist(self) -> None:
        self.refused(lambda: self.tr(self.checks_only(), evidence_id=uid(0x7FFF)), "FOREIGN KEY")


class TestT4Supersessions(SchemaCase):
    """C-53 in the database."""

    def setUp(self) -> None:
        super().setUp()
        self.add_evidence()

    def test_a_replacement_for_the_same_thing_is_accepted(self) -> None:
        raw_insert_supersession(self.raw(), eid(1), eid(6))
        self.assertEqual(self.count("evidence_supersessions"), 1)

    def test_old_and_new_must_have_the_same_kind(self) -> None:
        self.check_isolated(
            "evidence_supersessions",
            "evidence_supersessions_insert_same_binding",
            lambda c: raw_insert_supersession(c, eid(1), eid(7)),  # VERIFICATION, CONFIGURATION
            "same kind, state and candidate",
        )

    def test_evidence_about_a_state_is_not_superseded_by_candidate_evidence(self) -> None:
        self.check_isolated(
            "evidence_supersessions",
            "evidence_supersessions_insert_same_binding",
            lambda c: raw_insert_supersession(c, eid(1), eid(4)),  # about v0, about c1
            "same kind, state and candidate",
        )

    def test_evidence_about_one_candidate_is_not_superseded_by_another_candidates(self) -> None:
        with self.uow() as u:
            u.evidence.append(candidate_submission(10, self.c2))  # VERIFICATION for c2
        self.check_isolated(
            "evidence_supersessions",
            "evidence_supersessions_insert_same_binding",
            lambda c: raw_insert_supersession(c, eid(4), eid(10)),
            "same kind, state and candidate",
        )

    def test_both_records_must_be_bound(self) -> None:
        self.check_isolated(
            "evidence_supersessions",
            "evidence_supersessions_insert_same_binding",
            lambda c: raw_insert_supersession(c, eid(8), eid(9)),
            "same kind, state and candidate",
        )

    def test_a_record_cannot_supersede_itself(self) -> None:
        self.refused(lambda: raw_insert_supersession(self.checks_only(), eid(1), eid(1)), "CHECK")

    def test_neither_record_may_already_have_its_record_transition(self) -> None:
        def seal(evidence: str) -> Any:
            return lambda conn: self.tr(
                conn,
                evidence_id=evidence,
                to_validity="INVALID",
                reason="INTEGRITY: x",
                **RECORD_ROW,
            )

        for label, evidence in (("old", eid(1)), ("new", eid(6))):
            with self.subTest(sealed=label):
                self.new_world(evidence=True)
                self.check_isolated(
                    "evidence_supersessions",
                    "evidence_supersessions_insert_open",
                    lambda c: raw_insert_supersession(c, eid(1), eid(6)),
                    "RECORD-scope transition",
                    prep=seal(evidence),
                )

    def test_the_new_record_must_be_valid_in_its_primary_context(self) -> None:
        def invalidate_new(conn: sqlite3.Connection) -> None:
            self.tr(conn, evidence_id=eid(6))  # E6: VALID -> INVALID in v0

        self.check_isolated(
            "evidence_supersessions",
            "evidence_supersessions_insert_new_valid",
            lambda c: raw_insert_supersession(c, eid(1), eid(6)),
            "must be VALID in its primary context",
            prep=invalidate_new,
        )
        self.new_world(evidence=True)
        self.check_isolated(
            "evidence_supersessions",
            "evidence_supersessions_insert_new_valid",
            lambda c: raw_insert_supersession(c, eid(1), eid(3)),  # E3 is UNCERTAIN at creation
            "must be VALID in its primary context",
        )

    def test_a_record_can_replace_only_one_older_record(self) -> None:
        conn = self.raw()
        raw_insert_supersession(conn, eid(1), eid(6))
        self.refused(lambda: raw_insert_supersession(conn, eid(3), eid(6)), "UNIQUE")


class TestAuditConstraints(SchemaCase):
    def raw(self) -> sqlite3.Connection:
        return self.checks_only()

    def test_a_valid_event_is_accepted(self) -> None:
        raw_insert_audit(self.raw(), audit_submission(1))
        self.assertEqual(self.count("audit_events"), 1)

    def test_the_type_columns_are_restricted(self) -> None:
        conn = self.raw()
        sub = audit_submission(1)
        for column, values in {
            "event_type": ("RETRY_REQUESTED", "EVIDENCE_INVALIDATED", "EVIDENCE_SUPERSEDED", ""),
            "actor_type": ("ROBOT", "system", ""),
            "event_version": (0, -1),
            "actor_id": ("",),
        }.items():
            for value in values:
                with self.subTest(column=column, value=value):
                    self.refused(
                        lambda c=column, v=value: raw_insert_audit(conn, sub, **{c: v}), "CHECK"
                    )
        self.assertEqual(self.count("audit_events"), 0)

    def test_every_id_column_must_be_a_canonical_uuid(self) -> None:
        conn = self.raw()
        sub = audit_submission(1, state_id=self.v0.state_id, decision_id=uid(0x31))
        for column in ("event_id", "correlation_id", "operation_id", "state_id", "decision_id"):
            good = {"event_id": sub.event_id, "state_id": self.v0.state_id}.get(column, uid(0x31))
            for bad in bad_uuids(good):
                with self.subTest(column=column, value=bad):
                    self.refused(
                        lambda c=column, b=bad: raw_insert_audit(conn, sub, **{c: b}), "CHECK"
                    )
        self.assertEqual(self.count("audit_events"), 0)

    def test_the_payload_reference_is_the_audit_type_and_the_hash(self) -> None:
        conn = self.raw()
        sub = audit_submission(1)
        for ref in (
            f"evidence://verification/{sub.payload_hash}",
            f"evidence://audit/{HASH}",
            f"cas:{sub.payload_hash}",
            "",
        ):
            with self.subTest(ref=ref):
                self.refused(lambda r=ref: raw_insert_audit(conn, sub, payload_ref=r), "CHECK")

    def test_the_payload_must_be_stored_as_an_artifact(self) -> None:
        sub = audit_submission(1)
        self.refused(
            lambda: raw_insert_audit(
                self.raw(), sub, payload_hash=HASH, payload_ref=f"evidence://audit/{HASH}"
            ),
            "FOREIGN KEY",
        )


if __name__ == "__main__":
    unittest.main()
