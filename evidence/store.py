"""Evidence store (Doc 11): immutable, hash-protected, append-only.

Integrity model (Doc 11 header): content hashes + immutable lineage +
append-only event semantics. Concretely:

  * Payloads live in a content-addressed table keyed by SHA-256 of their
    canonical JSON, AFTER redaction. The evidence record stores only
    ``payload_ref = cas:<hash>`` and ``content_hash``.
  * evidence_record / evidence_payload / audit_event / validity_transition /
    evidence_supersession are protected by DB triggers: no UPDATE, no
    DELETE. Validity changes are new rows, never edits.
  * ``verify_integrity`` recomputes the hash on read (Doc 11 Section 45):
    a tampered artifact returns TAMPERED and is never usable as proof.
  * Audit events are idempotent by ``event_id`` (Doc 11 Section 38): a
    repeated delivery creates no second row; a *conflicting* reuse of an
    event_id raises.
  * ``usable_as_proof`` fails closed: VALID + correctly bound + intact, or
    it is not proof.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from core.domain.hashing import canonical_json, content_hash
from evidence.ids import CorrelationContext, new_id
from evidence.models import (
    ALLOWED_VALIDITY_TRANSITIONS,
    SCHEMA_VERSION,
    ActorType,
    AuditEvent,
    AuditEventType,
    EvidenceRecord,
    EvidenceType,
    EvidenceValidity,
    ValidityTransition,
)
from evidence.redaction import Redactor

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_payload (
    content_hash  TEXT PRIMARY KEY,
    payload_json  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_record (
    evidence_id                    TEXT PRIMARY KEY,
    evidence_type                  TEXT NOT NULL,
    state_id                       TEXT,
    candidate_id                   TEXT,
    parent_state_id                TEXT,
    state_hash                     TEXT,
    operation_id                   TEXT NOT NULL,
    correlation_id                 TEXT NOT NULL,
    source_component               TEXT NOT NULL,
    source_type                    TEXT NOT NULL,
    content_hash                   TEXT NOT NULL,
    payload_ref                    TEXT NOT NULL,
    created_at                     TEXT NOT NULL,
    algorithm_or_verifier_version  TEXT NOT NULL,
    validity                       TEXT NOT NULL,
    schema_version                 TEXT NOT NULL,
    redaction_policy_version       TEXT
);
CREATE INDEX IF NOT EXISTS ix_evd_state ON evidence_record(state_id);
CREATE INDEX IF NOT EXISTS ix_evd_cand ON evidence_record(candidate_id);
CREATE INDEX IF NOT EXISTS ix_evd_corr ON evidence_record(correlation_id);

CREATE TABLE IF NOT EXISTS validity_transition (
    seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
    transition_id       TEXT NOT NULL UNIQUE,
    evidence_id         TEXT NOT NULL REFERENCES evidence_record(evidence_id),
    from_validity       TEXT NOT NULL,
    to_validity         TEXT NOT NULL,
    reason              TEXT NOT NULL,
    candidate_id        TEXT,
    state_id            TEXT,
    impact_report_ref   TEXT,
    superseded_by       TEXT,
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_supersession (
    old_evidence_id  TEXT PRIMARY KEY REFERENCES evidence_record(evidence_id),
    new_evidence_id  TEXT NOT NULL REFERENCES evidence_record(evidence_id),
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_event (
    sequence        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE,
    event_type      TEXT NOT NULL,
    event_version   INTEGER NOT NULL,
    correlation_id  TEXT NOT NULL,
    operation_id    TEXT NOT NULL,
    actor_type      TEXT NOT NULL,
    actor_id        TEXT,
    state_id        TEXT,
    candidate_id    TEXT,
    decision_id     TEXT,
    timestamp       TEXT NOT NULL,
    payload_hash    TEXT NOT NULL,
    payload_ref     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_aud_corr ON audit_event(correlation_id);
CREATE INDEX IF NOT EXISTS ix_aud_cand ON audit_event(candidate_id);
"""

_IMMUTABLE_TABLES = (
    "evidence_payload",
    "evidence_record",
    "validity_transition",
    "evidence_supersession",
    "audit_event",
)


def _immutability_triggers() -> str:
    out = []
    for t in _IMMUTABLE_TABLES:
        for op in ("UPDATE", "DELETE"):
            out.append(
                f"CREATE TRIGGER IF NOT EXISTS {t}_no_{op.lower()} BEFORE {op} ON {t} "
                f"BEGIN SELECT RAISE(ABORT, '{t} is append-only ({op} forbidden)'); END;"
            )
    return "\n".join(out)


class EvidenceNotFoundError(LookupError):
    pass


class EvidenceConflictError(Exception):
    """Same evidence_id re-submitted with different content."""


class ConflictingDuplicateEventError(Exception):
    """An event_id was reused with different content (Doc 11 Section 38)."""


class InvalidValidityTransition(Exception):
    pass


class IntegrityStatus(str, Enum):
    VALID = "VALID"
    TAMPERED = "TAMPERED"
    MISSING_PAYLOAD = "MISSING_PAYLOAD"


@dataclass(frozen=True)
class AuditAppendResult:
    event: AuditEvent
    duplicate: bool


@dataclass(frozen=True)
class PutEvidenceResult:
    record: EvidenceRecord
    duplicate: bool
    redaction_count: int


@dataclass(frozen=True)
class ProofCheck:
    usable: bool
    reasons: tuple[str, ...]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceStore:
    def __init__(self, db_path: str | Path, redactor: Redactor | None = None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._redactor = redactor or Redactor()

    # --- plumbing ---------------------------------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.executescript(_immutability_triggers())

    @staticmethod
    def _store_payload(conn: sqlite3.Connection, payload: Any) -> tuple[str, str]:
        text = canonical_json(payload)
        digest = content_hash(payload)
        conn.execute(
            "INSERT OR IGNORE INTO evidence_payload (content_hash, payload_json) VALUES (?, ?)",
            (digest, text),
        )
        return digest, f"cas:{digest}"

    # --- evidence ---------------------------------------------------------

    _EVD_COLS = (
        "evidence_id, evidence_type, state_id, candidate_id, parent_state_id, state_hash, "
        "operation_id, correlation_id, source_component, source_type, content_hash, "
        "payload_ref, created_at, algorithm_or_verifier_version, validity, schema_version, "
        "redaction_policy_version"
    )

    @staticmethod
    def _row_to_record(r: tuple[Any, ...]) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=r[0],
            evidence_type=EvidenceType(r[1]),
            state_id=r[2],
            candidate_id=r[3],
            parent_state_id=r[4],
            state_hash=r[5],
            operation_id=r[6],
            correlation_id=r[7],
            source_component=r[8],
            source_type=r[9],
            content_hash=r[10],
            payload_ref=r[11],
            created_at=datetime.fromisoformat(r[12]),
            algorithm_or_verifier_version=r[13],
            validity=EvidenceValidity(r[14]),
            schema_version=r[15],
            redaction_policy_version=r[16],
        )

    def put_evidence(
        self,
        *,
        evidence_type: EvidenceType,
        payload: Any,
        ctx: CorrelationContext,
        source_component: str,
        source_type: str,
        algorithm_or_verifier_version: str,
        state_id: str | None = None,
        candidate_id: str | None = None,
        parent_state_id: str | None = None,
        state_hash: str | None = None,
        evidence_id: str | None = None,
    ) -> PutEvidenceResult:
        """Redact, hash, and persist an evidence record (idempotent by evidence_id).

        The payload is redacted BEFORE hashing/persistence, so a secret is
        never written anywhere, and the content_hash describes exactly
        what was stored.
        """
        red = self._redactor.redact(payload)
        eid = evidence_id or new_id("evd")
        with self._connect() as conn:
            digest, ref = self._store_payload(conn, red.payload)
            existing = conn.execute(
                f"SELECT {self._EVD_COLS} FROM evidence_record WHERE evidence_id = ?", (eid,)
            ).fetchone()
            if existing is not None:
                rec = self._row_to_record(existing)
                if rec.content_hash == digest:
                    return PutEvidenceResult(rec, True, red.redaction_count)
                raise EvidenceConflictError(
                    f"evidence_id {eid!r} already exists with different content"
                )
            rec = EvidenceRecord(
                evidence_id=eid,
                evidence_type=evidence_type,
                operation_id=ctx.operation_id,
                correlation_id=ctx.correlation_id,
                source_component=source_component,
                source_type=source_type,
                content_hash=digest,
                payload_ref=ref,
                algorithm_or_verifier_version=algorithm_or_verifier_version,
                state_id=state_id,
                candidate_id=candidate_id,
                parent_state_id=parent_state_id,
                state_hash=state_hash,
                schema_version=SCHEMA_VERSION,
                redaction_policy_version=red.policy_version if red.redacted else None,
            )
            conn.execute(
                f"INSERT INTO evidence_record ({self._EVD_COLS}) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    rec.evidence_id, rec.evidence_type.value, rec.state_id, rec.candidate_id,
                    rec.parent_state_id, rec.state_hash, rec.operation_id, rec.correlation_id,
                    rec.source_component, rec.source_type, rec.content_hash, rec.payload_ref,
                    rec.created_at.isoformat(), rec.algorithm_or_verifier_version,
                    rec.validity.value, rec.schema_version, rec.redaction_policy_version,
                ),
            )
        return PutEvidenceResult(rec, False, red.redaction_count)

    def get_evidence(self, evidence_id: str) -> EvidenceRecord:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {self._EVD_COLS} FROM evidence_record WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        if row is None:
            raise EvidenceNotFoundError(evidence_id)
        return self._row_to_record(row)

    def resolve_payload(self, record: EvidenceRecord) -> Any:
        """Resolve an artifact reference to its payload (Doc 11: artifact refs)."""
        import json

        if not record.payload_ref.startswith("cas:"):
            raise LookupError(f"payload_ref {record.payload_ref!r} is not a local CAS reference")
        digest = record.payload_ref[len("cas:") :]
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM evidence_payload WHERE content_hash = ?", (digest,)
            ).fetchone()
        if row is None:
            raise LookupError(f"missing payload for {record.payload_ref!r} (broken reference)")
        return json.loads(row[0])

    def verify_integrity(self, record: EvidenceRecord) -> IntegrityStatus:
        """Recompute the hash on read (Doc 11 Section 45)."""
        try:
            payload = self.resolve_payload(record)
        except LookupError:
            return IntegrityStatus.MISSING_PAYLOAD
        if content_hash(payload) != record.content_hash:
            return IntegrityStatus.TAMPERED
        return IntegrityStatus.VALID

    # --- validity ---------------------------------------------------------

    def _current_validity(self, conn: sqlite3.Connection, evidence_id: str) -> EvidenceValidity:
        row = conn.execute(
            "SELECT to_validity FROM validity_transition WHERE evidence_id = ? "
            "ORDER BY seq DESC LIMIT 1",
            (evidence_id,),
        ).fetchone()
        if row is not None:
            return EvidenceValidity(row[0])
        base = conn.execute(
            "SELECT validity FROM evidence_record WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        if base is None:
            raise EvidenceNotFoundError(evidence_id)
        return EvidenceValidity(base[0])

    def current_validity(self, evidence_id: str) -> EvidenceValidity:
        with self._connect() as conn:
            return self._current_validity(conn, evidence_id)

    def validity_history(self, evidence_id: str) -> list[ValidityTransition]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT transition_id, evidence_id, from_validity, to_validity, reason, "
                "candidate_id, state_id, impact_report_ref, superseded_by, created_at "
                "FROM validity_transition WHERE evidence_id = ? ORDER BY seq",
                (evidence_id,),
            ).fetchall()
        return [
            ValidityTransition(
                transition_id=r[0], evidence_id=r[1],
                from_validity=EvidenceValidity(r[2]), to_validity=EvidenceValidity(r[3]),
                reason=r[4], candidate_id=r[5], state_id=r[6], impact_report_ref=r[7],
                superseded_by=r[8], created_at=datetime.fromisoformat(r[9]),
            )
            for r in rows
        ]

    def _change_validity(
        self,
        conn: sqlite3.Connection,
        *,
        evidence_id: str,
        to: EvidenceValidity,
        reason: str,
        ctx: CorrelationContext,
        event_type: AuditEventType,
        candidate_id: str | None = None,
        state_id: str | None = None,
        impact_report_ref: str | None = None,
        superseded_by: str | None = None,
    ) -> ValidityTransition:
        if not reason or not reason.strip():
            raise ValueError("a validity change requires a non-empty reason (Doc 11 Section 32)")
        current = self._current_validity(conn, evidence_id)
        if to not in ALLOWED_VALIDITY_TRANSITIONS[current]:
            raise InvalidValidityTransition(
                f"evidence {evidence_id!r}: illegal validity transition "
                f"{current.value} -> {to.value}"
            )
        tr = ValidityTransition(
            transition_id=new_id("vt"), evidence_id=evidence_id, from_validity=current,
            to_validity=to, reason=reason, candidate_id=candidate_id, state_id=state_id,
            impact_report_ref=impact_report_ref, superseded_by=superseded_by,
        )
        conn.execute(
            "INSERT INTO validity_transition (transition_id, evidence_id, from_validity, "
            "to_validity, reason, candidate_id, state_id, impact_report_ref, superseded_by, "
            "created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                tr.transition_id, tr.evidence_id, tr.from_validity.value, tr.to_validity.value,
                tr.reason, tr.candidate_id, tr.state_id, tr.impact_report_ref,
                tr.superseded_by, tr.created_at.isoformat(),
            ),
        )
        self._append_audit(
            conn,
            event_id=f"evt-{tr.transition_id}",
            event_type=event_type,
            event_version=1,
            ctx=ctx,
            actor_type=ActorType.SYSTEM,
            actor_id=None,
            state_id=state_id,
            candidate_id=candidate_id,
            decision_id=None,
            payload={
                "evidence_id": evidence_id, "from": current.value, "to": to.value,
                "reason": reason, "impact_report_ref": impact_report_ref,
                "superseded_by": superseded_by,
            },
        )
        return tr

    def invalidate(
        self,
        evidence_id: str,
        *,
        reason: str,
        ctx: CorrelationContext,
        candidate_id: str | None = None,
        state_id: str | None = None,
        impact_report_ref: str | None = None,
    ) -> ValidityTransition:
        """Impact analysis invalidates evidence: the original record is
        untouched and a validity-transition event is appended (Doc 11 S.32)."""
        with self._connect() as conn:
            return self._change_validity(
                conn, evidence_id=evidence_id, to=EvidenceValidity.INVALID, reason=reason,
                ctx=ctx, event_type=AuditEventType.EVIDENCE_INVALIDATED,
                candidate_id=candidate_id, state_id=state_id,
                impact_report_ref=impact_report_ref,
            )

    def change_validity(
        self,
        evidence_id: str,
        to: EvidenceValidity,
        *,
        reason: str,
        ctx: CorrelationContext,
        candidate_id: str | None = None,
        state_id: str | None = None,
    ) -> ValidityTransition:
        with self._connect() as conn:
            return self._change_validity(
                conn, evidence_id=evidence_id, to=to, reason=reason, ctx=ctx,
                event_type=AuditEventType.EVIDENCE_VALIDITY_CHANGED,
                candidate_id=candidate_id, state_id=state_id,
            )

    def supersede(
        self, old_id: str, new_id_: str, *, reason: str, ctx: CorrelationContext
    ) -> ValidityTransition:
        """evidence_v1 --SUPERSEDED_BY--> evidence_v2, deleting nothing (S.33)."""
        if old_id == new_id_:
            raise ValueError("evidence cannot supersede itself")
        with self._connect() as conn:
            if self._current_validity(conn, new_id_) is not EvidenceValidity.VALID:
                raise InvalidValidityTransition(
                    f"replacement evidence {new_id_!r} must itself be VALID to supersede"
                )
            tr = self._change_validity(
                conn, evidence_id=old_id, to=EvidenceValidity.SUPERSEDED, reason=reason,
                ctx=ctx, event_type=AuditEventType.EVIDENCE_SUPERSEDED,
                superseded_by=new_id_,
            )
            conn.execute(
                "INSERT INTO evidence_supersession (old_evidence_id, new_evidence_id, "
                "created_at) VALUES (?,?,?)",
                (old_id, new_id_, _now_iso()),
            )
            return tr

    def superseded_by(self, evidence_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT new_evidence_id FROM evidence_supersession WHERE old_evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        return row[0] if row else None

    # --- proof gate -------------------------------------------------------

    def usable_as_proof(
        self,
        evidence_id: str,
        *,
        state_id: str | None = None,
        candidate_id: str | None = None,
    ) -> ProofCheck:
        """May this evidence support a trust decision about the given
        state/candidate? Fails closed (Doc 11 Sections 8, 45, 50): it must be
        VALID, bound to exactly that state/candidate, and hash-intact."""
        reasons: list[str] = []
        if state_id is None and candidate_id is None:
            return ProofCheck(False, ("no expected state/candidate binding supplied",))
        try:
            rec = self.get_evidence(evidence_id)
        except EvidenceNotFoundError:
            return ProofCheck(False, ("evidence not found",))
        validity = self.current_validity(evidence_id)
        if validity is not EvidenceValidity.VALID:
            reasons.append(f"validity is {validity.value}, not VALID")
        if not rec.is_bound:
            reasons.append("evidence has no state/candidate binding")
        if state_id is not None and rec.state_id != state_id:
            reasons.append(f"bound to state {rec.state_id!r}, expected {state_id!r}")
        if candidate_id is not None and rec.candidate_id != candidate_id:
            reasons.append(f"bound to candidate {rec.candidate_id!r}, expected {candidate_id!r}")
        integrity = self.verify_integrity(rec)
        if integrity is not IntegrityStatus.VALID:
            reasons.append(f"integrity check: {integrity.value}")
        return ProofCheck(not reasons, tuple(reasons))

    # --- audit events -----------------------------------------------------

    _AUD_COLS = (
        "sequence, event_id, event_type, event_version, correlation_id, operation_id, "
        "actor_type, actor_id, state_id, candidate_id, decision_id, timestamp, "
        "payload_hash, payload_ref"
    )

    @staticmethod
    def _row_to_event(r: tuple[Any, ...]) -> AuditEvent:
        return AuditEvent(
            sequence=r[0], event_id=r[1], event_type=AuditEventType(r[2]), event_version=r[3],
            correlation_id=r[4], operation_id=r[5], actor_type=ActorType(r[6]), actor_id=r[7],
            state_id=r[8], candidate_id=r[9], decision_id=r[10],
            timestamp=datetime.fromisoformat(r[11]), payload_hash=r[12], payload_ref=r[13],
        )

    def _append_audit(
        self,
        conn: sqlite3.Connection,
        *,
        event_id: str,
        event_type: AuditEventType,
        event_version: int,
        ctx: CorrelationContext,
        actor_type: ActorType,
        actor_id: str | None,
        state_id: str | None,
        candidate_id: str | None,
        decision_id: str | None,
        payload: Any,
    ) -> AuditAppendResult:
        red = self._redactor.redact(payload)
        digest, ref = self._store_payload(conn, red.payload)
        row = conn.execute(
            f"SELECT {self._AUD_COLS} FROM audit_event WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is not None:
            existing = self._row_to_event(row)
            if existing.payload_hash == digest and existing.event_type is event_type:
                # Repeated delivery: no second row, no second state transition.
                return AuditAppendResult(existing, True)
            raise ConflictingDuplicateEventError(
                f"event_id {event_id!r} reused with different content"
            )
        ts = _now_iso()
        cur = conn.execute(
            "INSERT INTO audit_event (event_id, event_type, event_version, correlation_id, "
            "operation_id, actor_type, actor_id, state_id, candidate_id, decision_id, "
            "timestamp, payload_hash, payload_ref) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id, event_type.value, event_version, ctx.correlation_id, ctx.operation_id,
                actor_type.value, actor_id, state_id, candidate_id, decision_id, ts, digest, ref,
            ),
        )
        seq = cur.lastrowid
        stored = conn.execute(
            f"SELECT {self._AUD_COLS} FROM audit_event WHERE sequence = ?", (seq,)
        ).fetchone()
        return AuditAppendResult(self._row_to_event(stored), False)

    def append_audit_event(
        self,
        *,
        event_type: AuditEventType,
        ctx: CorrelationContext,
        payload: Any,
        actor_type: ActorType = ActorType.SYSTEM,
        actor_id: str | None = None,
        state_id: str | None = None,
        candidate_id: str | None = None,
        decision_id: str | None = None,
        event_id: str | None = None,
        event_version: int = 1,
    ) -> AuditAppendResult:
        """Append an audit event. Supply a stable ``event_id`` (idempotency key)
        when the same event may be delivered more than once."""
        with self._connect() as conn:
            return self._append_audit(
                conn, event_id=event_id or new_id("evt"), event_type=event_type,
                event_version=event_version, ctx=ctx, actor_type=actor_type, actor_id=actor_id,
                state_id=state_id, candidate_id=candidate_id, decision_id=decision_id,
                payload=payload,
            )

    # --- lineage queries --------------------------------------------------

    def _evidence_where(self, column: str, value: str) -> list[EvidenceRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._EVD_COLS} FROM evidence_record WHERE {column} = ? ORDER BY rowid",
                (value,),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def evidence_for_state(self, state_id: str) -> list[EvidenceRecord]:
        return self._evidence_where("state_id", state_id)

    def evidence_for_candidate(self, candidate_id: str) -> list[EvidenceRecord]:
        return self._evidence_where("candidate_id", candidate_id)

    def evidence_for_correlation(self, correlation_id: str) -> list[EvidenceRecord]:
        return self._evidence_where("correlation_id", correlation_id)

    def _events_where(self, column: str, value: str) -> list[AuditEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._AUD_COLS} FROM audit_event WHERE {column} = ? ORDER BY sequence",
                (value,),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def events_for_correlation(self, correlation_id: str) -> list[AuditEvent]:
        """A whole workflow, in append order (sequence, not timestamp)."""
        return self._events_where("correlation_id", correlation_id)

    def events_for_candidate(self, candidate_id: str) -> list[AuditEvent]:
        return self._events_where("candidate_id", candidate_id)

    def count_events(self) -> int:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT COUNT(*) FROM audit_event")
            return int(cur.fetchone()[0])
