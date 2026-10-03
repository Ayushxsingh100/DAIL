"""Adversarial probes of the evidence layer (Doc 11 §2, §4, §8, §9, §28, §32, §38, §45, §46; Doc 14
§2, §23; C-52 to C-56).

Each probe plays the part of an attacker or a buggy caller and expects the system to refuse, to
fail closed, or to leave the record untouched. They run against a real schema-5 database through
the real service and repositories; secrets are built at run time, so no secret-shaped literal sits
in this file.
"""

from __future__ import annotations

import dataclasses
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from core.domain import repositories
from core.domain.audit import AuditEventType, AuditSubmission, ConflictingDuplicateEventError
from core.domain.errors import DomainValidationError, IllegalTransitionError, PersistenceError
from core.domain.evidence import (
    PROOF_KINDS,
    ArtifactRef,
    EvidenceConflictError,
    EvidenceContext,
    EvidenceKind,
    EvidenceSubmission,
    EvidenceValidity,
    IntegrityStatus,
    ProofCheck,
    TransitionScope,
    ValidityTransition,
)
from core.domain.hashing import canonical_json, content_hash
from core.domain.ids import new_uuid
from core.persistence.schema import open_connection
from evidence.ids import CorrelationContext
from evidence.models import LogLevel
from evidence.service import EvidenceService
from evidence.structured_log import StructuredLogger
from tests.domain_builders import baseline, uid
from tests.evidence_builders import (
    audit_submission,
    prov,
    raw_insert_event,
    raw_insert_transition,
    state_submission,
    transition_request,
)
from tests.service_builders import ServiceCase

K = EvidenceKind
V = EvidenceValidity
RECORD = {"scope": "RECORD", "context_kind": None, "context_id": None}

# Secret-shaped values, assembled at run time.
PASSWORD = "hunter2-" + "SUPERSECRET"
API_KEY = "sk-live-" + "fedcba9876543210" * 2
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
BEARER_VALUE = "abc.def-" + "123456"
GITHUB = "ghp_" + "a" * 36
PEM_BODY = "MIIabc" + "SECRETKEYBODY"
SECRETS = (PASSWORD, API_KEY, AWS_KEY, BEARER_VALUE, GITHUB, PEM_BODY)


def secret_payload() -> dict[str, Any]:
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}\n-----END RSA PRIVATE KEY-----"
    return {
        "config": {"password": PASSWORD, "engine": "postgres"},
        "api_key": API_KEY,
        "note": f"key {AWS_KEY} header Authorization: Bearer {BEARER_VALUE}",
        "tokens": [GITHUB],
        "pem": pem,
        "result": "PASS",
    }


class EvidenceAdversarialCase(ServiceCase):
    def setUp(self) -> None:
        self._connections: list[sqlite3.Connection] = []
        super().setUp()

    def tearDown(self) -> None:
        # connections must be closed before the temporary directory is removed (Windows locks it)
        for conn in self._connections:
            conn.close()
        super().tearDown()

    def raw(self) -> sqlite3.Connection:
        """A schema-5 connection: foreign keys on, autocommit."""
        conn = open_connection(self.path)
        self._connections.append(conn)
        return conn

    def plain(self) -> sqlite3.Connection:
        """A plain ``sqlite3.connect`` (recursive_triggers off, foreign keys off), in autocommit
        mode so that a refused statement leaves no transaction open."""
        conn = sqlite3.connect(self.path, isolation_level=None)
        self._connections.append(conn)
        self.assertEqual(conn.execute("PRAGMA recursive_triggers").fetchone()[0], 0)
        return conn

    def database_bytes(self) -> bytes:
        """The database file and any journal or WAL file next to it."""
        return b"".join(p.read_bytes() for p in sorted(Path(self.path).parent.iterdir()))

    def table_rows(self, table: str) -> list[tuple[Any, ...]]:
        with closing(sqlite3.connect(self.path)) as conn:
            return [tuple(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]


class TestProbe1AppendOnlyAgainstAPlainConnection(EvidenceAdversarialCase):
    """1. INSERT OR REPLACE, UPDATE and DELETE on every evidence table, from a plain connection."""

    TABLES = (
        "evidence_artifacts",
        "evidence_events",
        "evidence_validity_transitions",
        "evidence_supersessions",
        "audit_events",
    )

    def setUp(self) -> None:
        super().setUp()
        about_v0 = self.put({"v": 1})
        newer = self.put({"v": 2})
        impact = self.impact_for(self.c1)
        with self.uow() as u:
            self.svc.invalidate(
                u,
                about_v0.evidence_id,
                context=self.c1_ctx,
                reason="affected",
                ctx=self.ctx,
                impact_ref=impact.evidence_id,
            )
            self.svc.supersede(
                u, about_v0.evidence_id, newer.evidence_id, reason="newer", ctx=self.ctx
            )
            self.svc.append_audit_event(
                u, event_type=AuditEventType.LLM_REQUESTED, ctx=self.ctx, payload={"m": 1}
            )

    def columns(self, table: str) -> list[str]:
        with closing(sqlite3.connect(self.path)) as conn:
            return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]

    def test_every_table_holds_rows_to_attack(self) -> None:
        for table in self.TABLES:
            self.assertGreaterEqual(len(self.table_rows(table)), 1, table)

    def test_update_of_every_column_of_every_table_is_refused(self) -> None:
        conn = self.plain()
        for table in self.TABLES:
            for column in self.columns(table):
                with self.subTest(table=table, column=column):
                    before = self.table_rows(table)
                    with self.assertRaises(sqlite3.DatabaseError):
                        conn.execute(f"UPDATE {table} SET {column} = {column}")
                    self.assertEqual(self.table_rows(table), before)

    def test_delete_from_every_table_is_refused(self) -> None:
        conn = self.plain()
        for table in self.TABLES:
            with self.subTest(table=table):
                before = self.table_rows(table)
                with self.assertRaises(sqlite3.DatabaseError):
                    conn.execute(f"DELETE FROM {table}")
                self.assertEqual(self.table_rows(table), before)

    def test_insert_or_replace_of_every_existing_row_is_refused(self) -> None:
        """INSERT OR REPLACE deletes the old row without firing a DELETE trigger when
        recursive_triggers is off, so the guard has to fire before the insert (D3)."""
        conn = self.plain()
        for table in self.TABLES:
            with closing(sqlite3.connect(self.path)) as reader:
                cursor = reader.execute(f"SELECT * FROM {table}")
                names = [d[0] for d in cursor.description]
                rows = cursor.fetchall()
            for row in rows:
                with self.subTest(table=table, key=row[0]):
                    before = self.table_rows(table)
                    marks = ", ".join("?" for _ in names)
                    with self.assertRaises(sqlite3.DatabaseError):
                        conn.execute(
                            f"INSERT OR REPLACE INTO {table} ({', '.join(names)}) VALUES ({marks})",
                            row,
                        )
                    self.assertEqual(self.table_rows(table), before)

    def test_a_replace_that_changes_the_payload_of_an_artifact_is_refused(self) -> None:
        digest = self.table_rows("evidence_artifacts")[0][0]
        conn = self.plain()
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute(
                "INSERT OR REPLACE INTO evidence_artifacts (content_hash, payload_json) "
                "VALUES (?, ?)",
                (digest, '{"result":"FAIL"}'),
            )
        with self.uow() as u:
            for event in u.evidence.list_for_correlation(self.ctx.correlation_id):
                self.assertIs(
                    self.svc.verify_integrity(u, event.evidence_id), IntegrityStatus.VALID
                )


class TestProbe2SecretsNeverReachTheDatabase(EvidenceAdversarialCase):
    """2. A secret appended through the port directly is refused; after the service writes, a byte
    scan of the database finds no secret."""

    def assert_no_secret_on_disk(self) -> None:
        data = self.database_bytes()
        for secret in SECRETS:
            self.assertNotIn(secret.encode(), data, f"{secret[:10]}... reached the database")

    def test_a_secret_payload_cannot_be_built_at_all(self) -> None:
        with self.assertRaises(DomainValidationError) as caught:
            state_submission(1, self.v0, payload=secret_payload())
        self.assertIn("§28", str(caught.exception))

    def test_a_secret_pushed_straight_at_the_port_is_refused(self) -> None:
        clean = state_submission(1, self.v0, payload={"result": "PASS"})
        secret = secret_payload()
        digest = content_hash(secret)
        object.__setattr__(
            clean,
            "event",
            dataclasses.replace(
                clean.event, content_hash=digest, payload_ref=f"evidence://verification/{digest}"
            ),
        )
        object.__setattr__(clean, "payload_json", canonical_json(secret))
        with self.assertRaises(DomainValidationError) as caught, self.uow() as u:
            u.evidence.append(clean)
        self.assertIn("§28", str(caught.exception))
        self.assert_no_secret_on_disk()
        self.assertEqual(self.count("evidence_events"), 0)

    def test_a_secret_audit_payload_pushed_at_the_port_is_refused(self) -> None:
        clean = audit_submission(1, payload={"m": 1})
        secret = secret_payload()
        digest = content_hash(secret)
        object.__setattr__(clean, "payload_hash", digest)
        object.__setattr__(clean, "payload_ref", f"evidence://audit/{digest}")
        object.__setattr__(clean, "payload_json", canonical_json(secret))
        with self.assertRaises(DomainValidationError), self.uow() as u:
            u.audit.append(clean)
        self.assert_no_secret_on_disk()

    def test_a_secret_in_a_validity_reason_is_refused_at_the_port(self) -> None:
        rec = self.put()
        with self.assertRaises(DomainValidationError):
            transition_request(
                1, rec.evidence_id, V.UNCERTAIN, context=self.v0_ctx, reason=f"x {AWS_KEY}"
            )

    def test_what_the_service_writes_is_redacted_everywhere(self) -> None:
        rec = self.put(secret_payload())
        impact = self.impact_for(self.c1)
        with self.uow() as u:
            self.svc.change_validity(
                u,
                rec.evidence_id,
                context=self.v0_ctx,
                to=V.UNCERTAIN,
                reason=f"rechecking with password={PASSWORD} and {AWS_KEY}",
                ctx=self.ctx,
            )
            self.svc.invalidate(
                u,
                rec.evidence_id,
                context=self.c1_ctx,
                reason=f"leaked {AWS_KEY}",
                ctx=self.ctx,
                impact_ref=impact.evidence_id,
            )
            self.svc.append_audit_event(
                u,
                event_type=AuditEventType.LLM_REQUESTED,
                ctx=self.ctx,
                payload={
                    "prompt": f"use {AWS_KEY}",
                    "api_key": API_KEY,
                    "pem": secret_payload()["pem"],
                },
            )
        self.assert_no_secret_on_disk()
        with self.uow() as u:
            stored = self.svc.resolve_payload(u, rec.evidence_id)
        self.assertEqual(stored["config"]["password"], "[REDACTED]")
        self.assertEqual(stored["config"]["engine"], "postgres")  # the non-secret context survives
        self.assertEqual(rec.redaction_policy_version, "redaction-policy-1")

    def test_a_secret_in_structured_log_metadata_is_redacted(self) -> None:
        sink = Path(self.path).parent / "logs" / "dail.jsonl"
        log = StructuredLogger("dail", sink_path=sink)
        log.log(
            LogLevel.INFO,
            component="llm",
            event_name="request",
            ctx=self.ctx,
            status="ok",
            metadata=secret_payload(),
        )
        text = sink.read_text()
        for secret in SECRETS:
            self.assertNotIn(secret, text)


class TestProbe3Tampering(EvidenceAdversarialCase):
    """3. A payload tampered with through ``tamper()`` is TAMPERED, no longer proof, and Doc 11 §46
    is carried out."""

    def setUp(self) -> None:
        super().setUp()
        self.rec = self.put({"result": "FAIL"})
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json = ? WHERE content_hash = ?",
            ('{"result":"PASS"}', self.rec.content_hash),
        )

    def test_the_tampering_is_detected(self) -> None:
        with self.uow() as u:
            self.assertIs(
                self.svc.verify_integrity(u, self.rec.evidence_id), IntegrityStatus.TAMPERED
            )

    def test_tampered_evidence_is_not_proof_in_any_context(self) -> None:
        with self.uow() as u:
            for context in (self.v0_ctx, self.c1_ctx, self.c2_ctx):
                check = self.svc.usable_as_proof(u, self.rec.evidence_id, context)
                self.assertFalse(check.usable)
            check = self.svc.usable_as_proof(u, self.rec.evidence_id, self.v0_ctx)
            self.assertTrue(any(r.startswith("P5") and "TAMPERED" in r for r in check.reasons))

    def test_the_integrity_failure_is_recorded_and_the_evidence_is_invalidated(self) -> None:
        with self.uow() as u:
            status = self.svc.record_integrity_failure(u, self.rec.evidence_id, ctx=self.ctx)
        self.assertIs(status, IntegrityStatus.TAMPERED)
        with self.uow() as u:
            (transition,) = self.svc.validity_history(u, self.rec.evidence_id)
            events = self.svc.events_for_correlation(u, self.ctx.correlation_id)
            for context in (self.v0_ctx, self.c1_ctx, self.c2_ctx):
                self.assertIs(self.svc.validity_in(u, self.rec.evidence_id, context), V.INVALID)
        self.assertIs(transition.scope, TransitionScope.RECORD)
        self.assertIs(transition.to_validity, V.INVALID)
        self.assertTrue(transition.reason.startswith("INTEGRITY:"))
        self.assertIn(AuditEventType.ERROR_OCCURRED, [e.event_type for e in events])
        self.assertEqual(self.count("evidence_events"), 1)  # the record is preserved

    def test_the_failure_cannot_be_undone(self) -> None:
        with self.uow() as u:
            self.svc.record_integrity_failure(u, self.rec.evidence_id, ctx=self.ctx)
        for to in (V.VALID, V.UNCERTAIN):
            with (
                self.subTest(to=to.value),
                self.uow() as u,
                self.assertRaises(IllegalTransitionError),
            ):
                self.svc.change_validity(
                    u,
                    self.rec.evidence_id,
                    context=self.v0_ctx,
                    to=to,
                    reason="it is fine",
                    ctx=self.ctx,
                )
        replacement = self.put({"result": "PASS"})
        with self.uow() as u, self.assertRaises(IllegalTransitionError):  # nor superseded around
            self.svc.supersede(
                u, self.rec.evidence_id, replacement.evidence_id, reason="x", ctx=self.ctx
            )

    def test_a_deleted_artifact_is_missing_not_valid(self) -> None:
        other = self.put({"result": "OTHER"})
        self.tamper("DELETE FROM evidence_artifacts WHERE content_hash = ?", (other.content_hash,))
        with self.uow() as u:
            self.assertIs(
                self.svc.verify_integrity(u, other.evidence_id), IntegrityStatus.MISSING_PAYLOAD
            )
            self.assertFalse(self.svc.usable_as_proof(u, other.evidence_id, self.v0_ctx).usable)


class TestProbe4OnlyProofKindsAreProof(EvidenceAdversarialCase):
    """4. LLM, ERROR and EXPERIMENT evidence are never proof."""

    def test_the_proof_kinds_are_exactly_the_seven(self) -> None:
        self.assertEqual(
            PROOF_KINDS,
            {
                K.STATE,
                K.CONFIGURATION,
                K.IDENTITY,
                K.DEPENDENCY,
                K.IMPACT,
                K.VERIFICATION,
                K.PROMOTION,
            },
        )

    def test_valid_bound_intact_non_proof_evidence_is_still_not_proof(self) -> None:
        for kind in (K.LLM, K.ERROR, K.EXPERIMENT):
            with self.subTest(kind=kind):
                about_state = self.put({"k": kind.value, "s": 1}, kind=kind, event_name="e")
                about_candidate = self.put_for(
                    self.c1, {"k": kind.value, "c": 1}, kind=kind, event_name="e"
                )
                with self.uow() as u:
                    for rec, context in (
                        (about_state, self.v0_ctx),
                        (about_candidate, self.c1_ctx),
                    ):
                        self.assertIs(self.svc.validity_in(u, rec.evidence_id, context), V.VALID)
                        self.assertIs(
                            self.svc.verify_integrity(u, rec.evidence_id), IntegrityStatus.VALID
                        )
                        check = self.svc.usable_as_proof(u, rec.evidence_id, context)
                        self.assertFalse(check.usable)
                        self.assertTrue(
                            any(r.startswith("P2") for r in check.reasons), check.reasons
                        )

    def test_no_transition_turns_it_into_proof(self) -> None:
        rec = self.put({"k": "llm"}, kind=K.LLM, event_name="llm_completed")
        with self.uow() as u:
            self.svc.change_validity(
                u, rec.evidence_id, context=self.v0_ctx, to=V.UNCERTAIN, reason="a", ctx=self.ctx
            )
            self.svc.change_validity(
                u, rec.evidence_id, context=self.v0_ctx, to=V.VALID, reason="b", ctx=self.ctx
            )
            self.assertFalse(self.svc.usable_as_proof(u, rec.evidence_id, self.v0_ctx).usable)

    def test_it_cannot_be_laundered_by_superseding_it_with_proof(self) -> None:
        llm = self.put({"k": "llm"}, kind=K.LLM, event_name="llm_completed")
        proof = self.put({"result": "PASS"})  # VERIFICATION about the same state
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            self.svc.supersede(u, llm.evidence_id, proof.evidence_id, reason="x", ctx=self.ctx)
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            self.svc.supersede(u, proof.evidence_id, llm.evidence_id, reason="x", ctx=self.ctx)

    def test_llm_evidence_about_vn_is_not_superseded_by_another_candidates_verification(
        self,
    ) -> None:
        llm = self.put({"k": "llm"}, kind=K.LLM, event_name="llm_completed")
        other = self.put_for(self.c2, {"result": "PASS"})
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            self.svc.supersede(u, llm.evidence_id, other.evidence_id, reason="x", ctx=self.ctx)


class TestProbe5BindingIsExact(EvidenceAdversarialCase):
    """5. Evidence bound to candidate C is not proof for vN, and the reverse."""

    def check(self, evidence_id: str, context: Any) -> ProofCheck:
        with self.uow() as u:
            return self.svc.usable_as_proof(u, evidence_id, context)

    def test_candidate_evidence_is_not_proof_for_the_parent_state(self) -> None:
        rec = self.put_for(self.c1)
        self.assertTrue(self.check(rec.evidence_id, self.c1_ctx).usable)
        check = self.check(rec.evidence_id, self.v0_ctx)
        self.assertFalse(check.usable)
        self.assertTrue(any(r.startswith("P3") for r in check.reasons))

    def test_state_evidence_is_not_proof_for_a_candidate_of_that_state(self) -> None:
        rec = self.put()
        self.assertTrue(self.check(rec.evidence_id, self.v0_ctx).usable)
        for context in (self.c1_ctx, self.c2_ctx):
            check = self.check(rec.evidence_id, context)
            self.assertFalse(check.usable)
            self.assertTrue(any(r.startswith("P3") for r in check.reasons))

    def test_evidence_for_one_candidate_is_not_proof_for_another(self) -> None:
        rec = self.put_for(self.c1)
        self.assertFalse(self.check(rec.evidence_id, self.c2_ctx).usable)

    def test_a_context_id_cannot_be_borrowed_from_the_other_kind(self) -> None:
        rec = self.put_for(self.c1)
        borrowed = EvidenceContext.state(self.c1.candidate_id)  # a candidate id used as a state id
        self.assertFalse(self.check(rec.evidence_id, borrowed).usable)

    def test_a_state_hash_from_another_state_is_not_proof(self) -> None:
        rec = self.put(state_hash="cd" * 32)
        check = self.check(rec.evidence_id, self.v0_ctx)
        self.assertFalse(check.usable)
        self.assertTrue(any(r.startswith("P6") for r in check.reasons))

    def test_a_candidate_cannot_reuse_evidence_against_a_different_parent(self) -> None:
        """Doc 11 §9: a candidate artifact cannot be reused against a different parent."""
        other_state = baseline(state_id=uid(0x77), lineage_id=uid(0xCC))
        with self.uow() as u:
            u.trusted_states.save_baseline(other_state)
        wrong_parent = {"parent_state_id": other_state.state_id}
        with self.uow() as u, self.assertRaises(PersistenceError) as caught:
            self.svc.record(
                u,
                kind=K.VERIFICATION,
                event_name="v",
                payload={"r": 1},
                ctx=self.attempt_ctx,
                provenance=prov(),
                candidate_id=self.c1.candidate_id,
                state_hash=self.c1.state_hash,
                **wrong_parent,
            )
        self.assertIn("parent", str(caught.exception).lower())


class TestProbe6AThirdCandidateNeverSeesValid(EvidenceAdversarialCase):
    """6. A third candidate C2 sees v0's evidence as UNCERTAIN, never VALID."""

    def setUp(self) -> None:
        super().setUp()
        self.rec = self.put({"result": "PASS"})

    def validity(self, context: Any) -> EvidenceValidity:
        with self.uow() as u:
            return self.svc.validity_in(u, self.rec.evidence_id, context)

    def test_it_is_uncertain_and_not_proof_for_the_other_candidate(self) -> None:
        self.assertIs(self.validity(self.v0_ctx), V.VALID)
        self.assertIs(self.validity(self.c2_ctx), V.UNCERTAIN)
        with self.uow() as u:
            self.assertFalse(self.svc.usable_as_proof(u, self.rec.evidence_id, self.c2_ctx).usable)

    def test_invalidating_it_for_c1_does_not_change_what_c2_sees(self) -> None:
        impact = self.impact_for(self.c1)
        with self.uow() as u:
            self.svc.invalidate(
                u,
                self.rec.evidence_id,
                context=self.c1_ctx,
                reason="affected",
                ctx=self.ctx,
                impact_ref=impact.evidence_id,
            )
        self.assertIs(self.validity(self.c1_ctx), V.INVALID)
        self.assertIs(self.validity(self.c2_ctx), V.UNCERTAIN)
        self.assertIs(self.validity(self.v0_ctx), V.VALID)

    def test_no_transition_can_make_it_valid_for_the_other_candidate(self) -> None:
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            self.svc.change_validity(
                u,
                self.rec.evidence_id,
                context=self.c2_ctx,
                to=V.VALID,
                reason="trust me",
                ctx=self.ctx,
            )
        conn = self.raw()
        with self.assertRaises(sqlite3.DatabaseError):  # and the database refuses it too
            raw_insert_transition(
                conn,
                transition_id=uid(0x7701),
                evidence_id=self.rec.evidence_id,
                context_kind="CANDIDATE",
                context_id=self.c2.candidate_id,
                from_validity="UNCERTAIN",
                to_validity="VALID",
            )
        self.assertIs(self.validity(self.c2_ctx), V.UNCERTAIN)

    def test_it_stays_uncertain_for_every_foreign_context(self) -> None:
        for context in (
            self.c2_ctx,
            EvidenceContext.candidate(uid(0x1234)),
            EvidenceContext.state(uid(0x5678)),
        ):
            with self.subTest(context=str(context)):
                self.assertIs(self.validity(context), V.UNCERTAIN)


class TestProbe7IllegalTransitionsAreRefusedByTheDatabase(EvidenceAdversarialCase):
    """7. Raw inserts of each illegal transition are refused, with every trigger in place."""

    def setUp(self) -> None:
        super().setUp()
        self.e = {n: self.put({"n": n}) for n in range(1, 8)}
        self.impact_c1 = self.impact_for(self.c1)
        self.impact_c2 = self.impact_for(self.c2)
        self.verification_c1 = self.put_for(self.c1, {"v": 1})
        self.n = 0

    def attempt(self, evidence: int, **fields: Any) -> None:
        self.n += 1
        row: dict[str, Any] = {
            "transition_id": uid(0x7800 + self.n),
            "evidence_id": self.e[evidence].evidence_id,
            "context_id": self.v0.state_id,
        }
        row.update(fields)
        raw_insert_transition(self.raw(), **row)

    def refused(self, evidence: int, **fields: Any) -> None:
        before = self.table_rows("evidence_validity_transitions")
        with self.assertRaises(sqlite3.DatabaseError):
            self.attempt(evidence, **fields)
        self.assertEqual(self.table_rows("evidence_validity_transitions"), before)

    def test_a_wrong_from_validity(self) -> None:
        self.refused(1, from_validity="UNCERTAIN", to_validity="INVALID")
        self.refused(1, from_validity="INVALID", to_validity="UNCERTAIN")

    def test_an_illegal_pair(self) -> None:
        self.refused(1, from_validity="VALID", to_validity="VALID")
        self.refused(1, from_validity="VALID", to_validity="REDACTED")
        self.refused(1, from_validity="VALID", to_validity="SUPERSEDED")

    def test_invalid_is_terminal_in_its_context(self) -> None:
        self.attempt(2)  # VALID -> INVALID in the v0 context: legal
        self.refused(2, from_validity="INVALID", to_validity="VALID")
        self.refused(2, from_validity="INVALID", to_validity="UNCERTAIN")
        self.refused(2, from_validity="INVALID", to_validity="INVALID")

    def test_uncertain_to_valid_in_a_foreign_context(self) -> None:
        self.refused(
            3,
            context_kind="CANDIDATE",
            context_id=self.c2.candidate_id,
            from_validity="UNCERTAIN",
            to_validity="VALID",
        )

    def test_a_record_scope_transition_other_than_integrity_or_supersede(self) -> None:
        self.refused(4, from_validity="VALID", to_validity="UNCERTAIN", reason="x", **RECORD)
        self.refused(4, from_validity="VALID", to_validity="VALID", reason="x", **RECORD)
        self.refused(4, to_validity="INVALID", reason="impact analysis", **RECORD)
        self.refused(4, to_validity="INVALID", reason="integrity: lower case", **RECORD)

    def test_superseded_without_the_supersession_row(self) -> None:
        self.refused(
            4,
            to_validity="SUPERSEDED",
            superseded_by=self.e[5].evidence_id,
            reason="newer",
            **RECORD,
        )

    def test_invalid_for_a_candidate_needs_impact_evidence_for_that_candidate(self) -> None:
        candidate = {"context_kind": "CANDIDATE", "context_id": self.c1.candidate_id}
        base = {"from_validity": "UNCERTAIN", "to_validity": "INVALID", **candidate}
        self.refused(5, **base)  # no impact_ref
        self.refused(5, impact_ref=self.verification_c1.evidence_id, **base)  # not IMPACT
        self.refused(5, impact_ref=self.impact_c2.evidence_id, **base)  # another candidate's
        self.attempt(5, impact_ref=self.impact_c1.evidence_id, **base)  # the right one: legal

    def test_nothing_follows_a_record_scope_transition(self) -> None:
        self.attempt(6, to_validity="INVALID", reason="INTEGRITY: x", **RECORD)  # legal
        self.refused(6, to_validity="UNCERTAIN")
        self.refused(
            6, to_validity="INVALID", reason="INTEGRITY: y", **RECORD, from_validity="INVALID"
        )
        self.refused(6, from_validity="INVALID", to_validity="VALID")

    def test_the_terminal_rule_stands_on_its_own(self) -> None:
        """With every other transition trigger dropped, the terminal trigger alone still refuses
        anything after a RECORD-scope transition."""
        self.attempt(6, to_validity="INVALID", reason="INTEGRITY: x", **RECORD)  # legal
        conn = self.raw()
        names = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                "AND tbl_name = 'evidence_validity_transitions'"
            )
        ]
        for name in names:
            if name != "evidence_validity_transitions_insert_terminal":
                conn.execute(f"DROP TRIGGER {name}")
        self.refused(6, from_validity="INVALID", to_validity="UNCERTAIN")
        self.refused(
            6, to_validity="INVALID", reason="INTEGRITY: y", from_validity="INVALID", **RECORD
        )

    def test_the_service_refuses_the_same_transitions_before_the_database_does(self) -> None:
        rec = self.e[7]
        illegal = (
            (self.v0_ctx, V.VALID),  # VALID -> VALID
            (self.v0_ctx, V.SUPERSEDED),
            (self.v0_ctx, V.REDACTED),
            (self.c2_ctx, V.VALID),  # UNCERTAIN -> VALID in a foreign context
            (self.c1_ctx, V.INVALID),  # a candidate context without impact_ref
        )
        for context, to in illegal:
            with (
                self.subTest(context=str(context), to=to.value),
                self.uow() as u,
                self.assertRaises(IllegalTransitionError),
            ):
                self.svc.change_validity(
                    u, rec.evidence_id, context=context, to=to, reason="x", ctx=self.ctx
                )


class TestProbe8RedeliveredInvalidation(EvidenceAdversarialCase):
    """8. Redelivering an invalidation with the same transition_id adds no second row or event."""

    def test_a_redelivery_adds_nothing(self) -> None:
        rec = self.put()
        impact = self.impact_for(self.c1)
        transition_id = uid(0x7900)
        results = []
        for _ in range(3):
            with self.uow() as u:
                results.append(
                    self.svc.invalidate(
                        u,
                        rec.evidence_id,
                        context=self.c1_ctx,
                        reason="affected",
                        ctx=self.ctx,
                        impact_ref=impact.evidence_id,
                        transition_id=transition_id,
                    )
                )
        self.assertEqual([r.duplicate for r in results], [False, True, True])
        self.assertEqual({r.transition.transition_id for r in results}, {transition_id})
        self.assertEqual(self.count("evidence_validity_transitions"), 1)
        self.assertEqual(self.count("audit_events", "event_type = 'EVIDENCE_VALIDITY_CHANGED'"), 1)

    def test_a_redelivery_with_a_changed_field_is_a_conflict(self) -> None:
        rec = self.put()
        impact = self.impact_for(self.c1)
        other = self.put({"other": 1})
        kwargs: dict[str, Any] = dict(
            context=self.c1_ctx,
            reason="affected",
            ctx=self.ctx,
            impact_ref=impact.evidence_id,
            transition_id=uid(0x7901),
        )
        with self.uow() as u:
            self.svc.invalidate(u, rec.evidence_id, **kwargs)
        for label, evidence_id, changed in (
            ("reason", rec.evidence_id, {"reason": "something else"}),
            ("context", rec.evidence_id, {"context": self.c2_ctx}),
            ("evidence", other.evidence_id, {}),
        ):
            with (
                self.subTest(change=label),
                self.uow() as u,
                self.assertRaises(EvidenceConflictError),
            ):
                self.svc.invalidate(u, evidence_id, **{**kwargs, **changed})
        self.assertEqual(self.count("evidence_validity_transitions"), 1)


class TestProbe9ConflictingRedelivery(EvidenceAdversarialCase):
    """9. A redelivered evidence record or event with a changed field raises a conflict."""

    def test_evidence_with_any_changed_field(self) -> None:
        fixed = uid(0x7A00)
        self.put({"result": "PASS"}, evidence_id=fixed)
        before = self.table_rows("evidence_events")
        changes: dict[str, dict[str, Any]] = {
            "payload": {"payload": {"result": "FAIL"}},
            "event_name": {"event_name": "other"},
            "kind": {"kind": K.CONFIGURATION},
            "state_hash": {"state_hash": "cd" * 32},
            "validity": {"validity": V.UNCERTAIN},
            "schema_version": {"schema_version": "2"},
            "run": {"ctx": CorrelationContext.new(new_uuid())},
            "operation": {"ctx": self.ctx.new_operation()},
        }
        for label, change in changes.items():
            with self.subTest(change=label), self.assertRaises(EvidenceConflictError):
                self.put(evidence_id=fixed, **{"payload": {"result": "PASS"}, **change})
        self.assertEqual(self.table_rows("evidence_events"), before)

    def test_audit_event_with_any_changed_field(self) -> None:
        base: dict[str, Any] = dict(
            event_type=AuditEventType.CANDIDATE_REJECTED,
            ctx=self.ctx,
            payload={"reason": "ssh"},
            event_id=uid(0x7A01),
            candidate_id=self.c1.candidate_id,
        )
        with self.uow() as u:
            self.svc.append_audit_event(u, **base)
        changes = {
            "candidate": {"candidate_id": self.c2.candidate_id},
            "state": {"state_id": self.v0.state_id},
            "decision": {"decision_id": uid(0x7A02)},
            "payload": {"payload": {"reason": "other"}},
            "correlation": {"ctx": CorrelationContext.new(new_uuid())},
            "operation": {"ctx": self.ctx.new_operation()},
            "type": {
                "event_type": AuditEventType.ESCALATED,
                "payload": {"reason": "x", "unresolved_conditions": []},
            },
            "version": {"event_version": 2},
        }
        for label, change in changes.items():
            with (
                self.subTest(change=label),
                self.uow() as u,
                self.assertRaises(ConflictingDuplicateEventError),
            ):
                self.svc.append_audit_event(u, **{**base, **change})
        self.assertEqual(self.count("audit_events"), 1)

    def test_an_identical_redelivery_is_still_a_duplicate(self) -> None:
        fixed = uid(0x7A03)
        self.put({"result": "PASS"}, evidence_id=fixed)
        with self.uow() as u:
            result = self.svc.record(
                u,
                kind=K.VERIFICATION,
                event_name="verification_completed",
                payload={"result": "PASS"},
                ctx=self.ctx,
                provenance=state_submission(1, self.v0).event.provenance,
                state_id=self.v0.state_id,
                state_hash=self.v0.state_hash,
                evidence_id=fixed,
            )
        self.assertTrue(result.duplicate)


class TestProbe10ArtifactReferences(EvidenceAdversarialCase):
    """10. A payload_ref with the wrong type or hash is refused."""

    def bad_refs(self, digest: str) -> list[str]:
        other = "ef" * 32
        return [
            f"evidence://impact/{digest}",  # the wrong type
            f"evidence://audit/{digest}",
            f"evidence://verification/{other}",  # the wrong hash
            f"cas:{digest}",  # the retired forms
            f"ext:{digest}",
            f"evidence://VERIFICATION/{digest}",
            f"evidence://verification/{digest.upper()}",
            f"evidence://verification/{digest}/extra",
            f" evidence://verification/{digest}",
            "",
        ]

    def test_the_database_refuses_a_record_with_a_bad_reference(self) -> None:
        sub = state_submission(1, self.v0)
        conn = self.raw()
        for ref in self.bad_refs(sub.event.content_hash):
            with self.subTest(ref=ref), self.assertRaises(sqlite3.DatabaseError):
                raw_insert_event(conn, sub, payload_ref=ref)
        self.assertEqual(self.count("evidence_events"), 0)

    def test_the_domain_refuses_a_record_with_a_bad_reference(self) -> None:
        sub = state_submission(1, self.v0)
        for ref in self.bad_refs(sub.event.content_hash):
            with self.subTest(ref=ref), self.assertRaises(DomainValidationError):
                dataclasses.replace(sub.event, payload_ref=ref)

    def test_a_reference_is_parsed_strictly(self) -> None:
        digest = "ab" * 32
        for ref in self.bad_refs(digest)[3:]:
            with self.subTest(ref=ref), self.assertRaises(DomainValidationError):
                ArtifactRef.parse(ref)

    def test_a_reference_to_nothing_does_not_resolve(self) -> None:
        with self.uow() as u, self.assertRaises(DomainValidationError):
            u.evidence.resolve(ArtifactRef("verification", "ab" * 32))

    def test_an_audit_event_needs_an_audit_reference(self) -> None:
        sub = audit_submission(1)
        for ref in (
            f"evidence://verification/{sub.payload_hash}",
            f"evidence://audit/{'ef' * 32}",
            f"cas:{sub.payload_hash}",
        ):
            with self.subTest(ref=ref), self.assertRaises(DomainValidationError):
                dataclasses.replace(sub, payload_ref=ref)


class TestProbe11ReadResultsAreNotAuthority(EvidenceAdversarialCase):
    """Nothing accepts an EvidenceEvent, a ValidityTransition or a ProofCheck as input."""

    def test_a_stored_record_cannot_be_resubmitted_as_evidence(self) -> None:
        rec = self.put()
        with self.uow() as u:
            for forged in (rec, rec.to_dict(), ProofCheck(True, ())):
                with (
                    self.subTest(forged=type(forged).__name__),
                    self.assertRaises(DomainValidationError),
                ):
                    u.evidence.append(forged)  # type: ignore[arg-type]

    def test_a_stored_transition_cannot_be_replayed_as_a_request(self) -> None:
        rec = self.put()
        impact = self.impact_for(self.c1)
        with self.uow() as u:
            stored: ValidityTransition = self.svc.invalidate(
                u,
                rec.evidence_id,
                context=self.c1_ctx,
                reason="x",
                ctx=self.ctx,
                impact_ref=impact.evidence_id,
            ).transition
        with self.uow() as u:
            for forged in (stored, ProofCheck(True, ())):
                with self.subTest(forged=type(forged).__name__):
                    with self.assertRaises(DomainValidationError):
                        u.evidence.append_transition(forged)  # type: ignore[arg-type]
                    with self.assertRaises(DomainValidationError):
                        u.evidence.supersede(forged)  # type: ignore[arg-type]

    def test_a_stored_audit_event_cannot_be_resubmitted(self) -> None:
        with self.uow() as u:
            event = self.svc.append_audit_event(
                u, event_type=AuditEventType.LLM_REQUESTED, ctx=self.ctx, payload={"m": 1}
            ).event
        with self.uow() as u, self.assertRaises(DomainValidationError):
            u.audit.append(event)  # type: ignore[arg-type]

    def test_a_forged_proof_check_is_not_a_context(self) -> None:
        rec = self.put()
        with self.uow() as u:
            check = self.svc.usable_as_proof(u, rec.evidence_id, ProofCheck(True, ()))  # type: ignore[arg-type]
        self.assertFalse(check.usable)

    def test_no_port_or_service_method_takes_a_read_result(self) -> None:
        read_results = {"EvidenceEvent", "ValidityTransition", "ProofCheck", "AuditEvent"}
        for owner in (
            repositories.EvidenceRepository,
            repositories.AuditRepository,
            EvidenceService,
        ):
            for name, member in vars(owner).items():
                if name.startswith("_") or not callable(member):
                    continue
                for arg, annotation in getattr(member, "__annotations__", {}).items():
                    if arg == "return":
                        continue
                    with self.subTest(owner=owner.__name__, method=name, arg=arg):
                        self.assertNotIn(str(annotation).split(".")[-1].strip("'\""), read_results)

    def test_submissions_are_the_only_way_in(self) -> None:
        self.assertTrue(hasattr(EvidenceSubmission, "create"))
        self.assertTrue(hasattr(AuditSubmission, "create"))


if __name__ == "__main__":
    import unittest

    unittest.main()
