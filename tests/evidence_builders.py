"""Shared builders for the evidence tests (P2-fix). Not a test module.

``submission`` builds a valid ``EvidenceSubmission``; ``raw_insert_event`` and the other ``raw_*``
helpers write rows with plain SQL so a test can break exactly one column or rule and watch the
database (not the domain constructors) refuse it.
"""

from __future__ import annotations

import dataclasses
import sqlite3
from typing import Any

from core.domain.audit import AuditEventType, AuditSubmission
from core.domain.evidence import (
    EvidenceContext,
    EvidenceEvent,
    EvidenceKind,
    EvidenceSubmission,
    EvidenceValidity,
    SupersessionRequest,
    TransitionRequest,
    TransitionScope,
)
from core.domain.hashing import canonical_json
from tests.domain_builders import at, provenance, uid

# Evidence ids start at 0x7000 so they never collide with the ids the P1 builders use.
RUN = uid(0x9001)
ATTEMPT = uid(0x9002)
CORR = uid(0x9003)
OP = uid(0x9004)
K = EvidenceKind
V = EvidenceValidity


def prov(algorithm_version: str | None = "verifier-1") -> Any:
    return dataclasses.replace(provenance(), algorithm_version=algorithm_version)


def eid(n: int) -> str:
    return uid(0x7000 + n)


def submission(n: int = 1, **overrides: Any) -> EvidenceSubmission:
    """A valid VERIFICATION record with evidence id ``eid(n)``; give ``state_id``/``state_hash`` or
    ``candidate_id``/``attempt_id``/``parent_state_id`` to bind it."""
    fields: dict[str, Any] = {
        "payload": {"result": "PASS", "n": n},
        "evidence_id": eid(n),
        "run_id": RUN,
        "attempt_id": None,
        "correlation_id": CORR,
        "operation_id": OP,
        "kind": K.VERIFICATION,
        "event_name": "verification_completed",
        "provenance": prov(),
        "created_at": at(5),
    }
    fields.update(overrides)
    return EvidenceSubmission.create(**fields)


def state_submission(n: int, state: Any, **overrides: Any) -> EvidenceSubmission:
    """Evidence about a trusted state: bound to it, carrying its state hash (Doc 11 §8)."""
    fields: dict[str, Any] = {"state_id": state.state_id, "state_hash": state.state_hash}
    fields.update(overrides)
    return submission(n, **fields)


def candidate_submission(n: int, candidate: Any, **overrides: Any) -> EvidenceSubmission:
    """Evidence about a candidate: bound to it, with its attempt, parent and state hash (B1, T2)."""
    fields: dict[str, Any] = {
        "candidate_id": candidate.candidate_id,
        "attempt_id": ATTEMPT,
        "parent_state_id": candidate.parent_state_id,
        "state_hash": candidate.state_hash,
    }
    fields.update(overrides)
    return submission(n, **fields)


def audit_submission(
    n: int = 1, event_type: AuditEventType = AuditEventType.LLM_REQUESTED, **overrides: Any
) -> AuditSubmission:
    fields: dict[str, Any] = {
        "event_id": uid(0x8000 + n),
        "event_type": event_type,
        "correlation_id": CORR,
        "operation_id": OP,
        "timestamp": at(6),
        "payload": {"n": n},
    }
    fields.update(overrides)
    return AuditSubmission.create(**fields)


def transition_request(
    n: int,
    evidence_id: str,
    to: EvidenceValidity,
    *,
    scope: TransitionScope = TransitionScope.CONTEXT,
    context: EvidenceContext | None = None,
    reason: str = "because",
    impact_ref: str | None = None,
) -> TransitionRequest:
    return TransitionRequest(
        transition_id=uid(0x6100 + n),
        evidence_id=evidence_id,
        scope=scope,
        context=context,
        to_validity=to,
        reason=reason,
        impact_ref=impact_ref,
        correlation_id=CORR,
        operation_id=OP,
        created_at=at(8),
    )


def supersession_request(
    n: int, old: str, new: str, reason: str = "re-verified"
) -> SupersessionRequest:
    return SupersessionRequest(
        transition_id=uid(0x6200 + n),
        old_evidence_id=old,
        new_evidence_id=new,
        reason=reason,
        correlation_id=CORR,
        operation_id=OP,
        created_at=at(9),
    )


# --- raw SQL ----------------------------------------------------------------------------------


def event_columns(event: EvidenceEvent) -> dict[str, Any]:
    """Every ``evidence_events`` column except ``seq``, from a valid record."""
    data = event.to_dict()
    return {
        "evidence_id": data["evidence_id"],
        "run_id": data["run_id"],
        "attempt_id": data["attempt_id"],
        "correlation_id": data["correlation_id"],
        "operation_id": data["operation_id"],
        "kind": data["kind"],
        "event_name": data["event_name"],
        "state_id": data["state_id"],
        "candidate_id": data["candidate_id"],
        "parent_state_id": data["parent_state_id"],
        "state_hash": data["state_hash"],
        "content_hash": data["content_hash"],
        "hash_algorithm": data["hash_algorithm"],
        "payload_ref": data["payload_ref"],
        "provenance_json": canonical_json(data["provenance"]),
        "validity": data["validity"],
        "schema_version": data["schema_version"],
        "redaction_policy_version": data["redaction_policy_version"],
        "created_at": data["created_at"],
        "content_json": canonical_json(data),
    }


def raw_insert_artifact(conn: sqlite3.Connection, content_hash: str, payload_json: str) -> None:
    if conn.execute(
        "SELECT 1 FROM evidence_artifacts WHERE content_hash = ?", (content_hash,)
    ).fetchone():
        return
    conn.execute(
        "INSERT INTO evidence_artifacts (content_hash, payload_json) VALUES (?, ?)",
        (content_hash, payload_json),
    )


def raw_insert_event(
    conn: sqlite3.Connection,
    sub: EvidenceSubmission,
    *,
    verb: str = "INSERT",
    **overrides: Any,
) -> None:
    """Insert a record with plain SQL, replacing any column by ``overrides`` (a deliberately bad
    value). ``verb`` may be ``INSERT OR REPLACE``."""
    columns = event_columns(sub.event)
    columns.update(overrides)
    raw_insert_artifact(conn, sub.event.content_hash, sub.payload_json)
    names = ", ".join(columns)
    marks = ", ".join("?" for _ in columns)
    conn.execute(f"{verb} INTO evidence_events ({names}) VALUES ({marks})", tuple(columns.values()))


def raw_insert_transition(conn: sqlite3.Connection, *, verb: str = "INSERT", **fields: Any) -> None:
    """Insert a validity transition; ``fields`` override the defaults (a valid VALID->INVALID
    CONTEXT transition in a state context, which the caller must make true for the record)."""
    row: dict[str, Any] = {
        "transition_id": uid(0x6000),
        "evidence_id": eid(1),
        "scope": "CONTEXT",
        "context_kind": "STATE",
        "context_id": uid(1),
        "from_validity": "VALID",
        "to_validity": "INVALID",
        "reason": "because",
        "impact_ref": None,
        "superseded_by": None,
        "correlation_id": CORR,
        "operation_id": OP,
        "created_at": at(7).isoformat(),
    }
    row.update(fields)
    names = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    conn.execute(
        f"{verb} INTO evidence_validity_transitions ({names}) VALUES ({marks})", tuple(row.values())
    )


def raw_insert_supersession(
    conn: sqlite3.Connection, old: str, new: str, *, verb: str = "INSERT"
) -> None:
    conn.execute(
        f"{verb} INTO evidence_supersessions (old_evidence_id, new_evidence_id, created_at) "
        "VALUES (?, ?, ?)",
        (old, new, at(7).isoformat()),
    )


def raw_insert_audit(
    conn: sqlite3.Connection, sub: AuditSubmission, *, verb: str = "INSERT", **overrides: Any
) -> None:
    row: dict[str, Any] = {
        "event_id": sub.event_id,
        "event_type": sub.event_type.value,
        "event_version": sub.event_version,
        "correlation_id": sub.correlation_id,
        "operation_id": sub.operation_id,
        "actor_type": sub.actor_type.value,
        "actor_id": sub.actor_id,
        "state_id": sub.state_id,
        "candidate_id": sub.candidate_id,
        "decision_id": sub.decision_id,
        "timestamp": sub.timestamp.isoformat(),
        "payload_hash": sub.payload_hash,
        "payload_ref": sub.payload_ref,
    }
    row.update(overrides)
    raw_insert_artifact(conn, sub.payload_hash, sub.payload_json)
    names = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    conn.execute(f"{verb} INTO audit_events ({names}) VALUES ({marks})", tuple(row.values()))
