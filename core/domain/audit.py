"""Audit events (Doc 11 §12, §13, §19, §20, §38; Doc 06 §28; C-57; P2-fix step 2).

An audit event is an append-only fact in the lineage of a workflow: it says what happened, to which
state or candidate, in which order (``sequence``, never wall-clock time alone; Doc 11 §19, §20).
Doc 11 §38: "Repeated delivery of the same event must not create contradictory semantic history."

``AuditSubmission`` is what an ``AuditRepository`` accepts; ``AuditEvent`` is the stored form, a
read result. The payload of an event is stored content-addressed (``audit`` artifacts, C-56).

Standard library and ``core.domain`` only (rule R1); nothing here reads the clock or draws a random
number (rule R10).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from core.domain import hashing
from core.domain.errors import DomainValidationError
from core.domain.evidence import (
    ArtifactRef,
    check_payload_json,
    optional_uuid,
    require_sha256,
)
from core.domain.ids import require_uuid
from core.domain.jsonvalue import (
    iso_utc,
    optional_text,
    parse_enum,
    parse_utc,
    require_enum,
    require_int,
    thaw_json,
    utc,
    validate_json,
)
from core.domain.redaction import Redactor


class AuditEventType(StrEnum):
    """C-57: the Doc 11 §12 events, plus INVARIANT_AFFECTED, PROMOTION_DECIDED and PROMOTION_FAILED
    from Doc 06 §28, plus EVIDENCE_VALIDITY_CHANGED, the event Doc 11 §32 says is appended when
    evidence changes validity. RETRY_REQUESTED (Doc 06 §28) is RETRY_SCHEDULED: Doc 11 is the
    dedicated event specification (SPEC_INDEX precedence rule 1)."""

    STATE_CREATED = "STATE_CREATED"
    CANDIDATE_CREATED = "CANDIDATE_CREATED"
    LLM_REQUESTED = "LLM_REQUESTED"
    LLM_COMPLETED = "LLM_COMPLETED"
    PATCH_VALIDATED = "PATCH_VALIDATED"
    IDENTITY_COMPLETED = "IDENTITY_COMPLETED"
    DEPENDENCY_COMPLETED = "DEPENDENCY_COMPLETED"
    IMPACT_COMPLETED = "IMPACT_COMPLETED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    PROMOTION_REQUESTED = "PROMOTION_REQUESTED"
    STATE_PROMOTED = "STATE_PROMOTED"
    CANDIDATE_REJECTED = "CANDIDATE_REJECTED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    ESCALATED = "ESCALATED"
    ERROR_OCCURRED = "ERROR_OCCURRED"
    INVARIANT_AFFECTED = "INVARIANT_AFFECTED"
    PROMOTION_DECIDED = "PROMOTION_DECIDED"
    PROMOTION_FAILED = "PROMOTION_FAILED"
    EVIDENCE_VALIDITY_CHANGED = "EVIDENCE_VALIDITY_CHANGED"


class ActorType(StrEnum):
    """Doc 11 §13: "actor_type may identify system component, user, automation, or provider"."""

    SYSTEM = "SYSTEM"
    USER = "USER"
    AUTOMATION = "AUTOMATION"
    PROVIDER = "PROVIDER"


T = AuditEventType

# Doc 06 §28 minimum fields, as the payload keys each event must carry (P2-fix prompt §4.6).
REQUIRED_PAYLOAD_KEYS: dict[AuditEventType, tuple[str, ...]] = {
    T.STATE_CREATED: ("lineage_id", "version", "parent_state_id", "state_hash"),
    T.CANDIDATE_CREATED: ("parent_state_id", "patch_id", "source"),
    T.INVARIANT_AFFECTED: ("invariant_id", "invariant_version", "reason"),
    T.VERIFICATION_COMPLETED: (
        "verification_id",
        "target",
        "result",
        "verifier_id",
        "verifier_version",
    ),
    T.PROMOTION_DECIDED: ("parent_state_id", "decision", "policy_version"),
    T.STATE_PROMOTED: ("parent_state_id",),
    T.PROMOTION_FAILED: ("parent_state_id", "reason"),
    T.RETRY_SCHEDULED: ("attempt_id", "parent_state_id", "reason"),
    T.ESCALATED: ("reason", "unresolved_conditions"),
    T.EVIDENCE_VALIDITY_CHANGED: (
        "evidence_id",
        "scope",
        "context_kind",
        "context_id",
        "from_validity",
        "to_validity",
        "reason",
        "impact_ref",
        "superseded_by",
    ),
}

# The AuditEvent columns an event type must set (Doc 06 §28: "state_id", "candidate_id", ...).
REQUIRED_COLUMNS: dict[AuditEventType, tuple[str, ...]] = {
    T.STATE_CREATED: ("state_id",),
    T.CANDIDATE_CREATED: ("candidate_id",),
    T.INVARIANT_AFFECTED: ("state_id", "candidate_id"),
    T.PROMOTION_DECIDED: ("decision_id", "candidate_id"),
    T.STATE_PROMOTED: ("state_id", "decision_id"),
    T.PROMOTION_FAILED: ("candidate_id",),
}

# Payload keys whose value may be null. STATE_CREATED's parent_state_id is null exactly when
# version is 0; ESCALATED needs the candidate_id column or the attempt_id key (see below).
NULLABLE_PAYLOAD_KEYS: dict[AuditEventType, frozenset[str]] = {
    T.STATE_CREATED: frozenset({"parent_state_id"}),
    T.EVIDENCE_VALIDITY_CHANGED: frozenset(
        {"context_kind", "context_id", "impact_ref", "superseded_by"}
    ),
}

_VALIDITY_EVENT_NAMESPACE = uuid.UUID("7e5f8a6c-2b1d-4c3e-9a47-5d0b6f1e8c20")


class ConflictingDuplicateEventError(DomainValidationError):
    """An ``event_id`` was reused with different content (Doc 11 §38)."""


def validity_event_id(transition_id: str) -> str:
    """The deterministic id of the EVIDENCE_VALIDITY_CHANGED event for one transition, so a
    redelivered transition names the same event (Doc 11 §38) and creates no second one."""
    require_uuid(transition_id, "transition_id")
    return str(uuid.uuid5(_VALIDITY_EVENT_NAMESPACE, f"evidence-validity-changed:{transition_id}"))


def check_audit_fields(
    event_type: AuditEventType,
    *,
    state_id: str | None,
    candidate_id: str | None,
    decision_id: str | None,
    payload: Any,
) -> None:
    """The columns and payload keys an event of this type must carry (§4.6). Raises
    ``DomainValidationError`` naming the first missing one; a null where none is allowed fails."""
    if not isinstance(payload, Mapping):
        raise DomainValidationError("audit payload: must be a JSON object (Doc 11 §13)")
    columns = {"state_id": state_id, "candidate_id": candidate_id, "decision_id": decision_id}
    for column in REQUIRED_COLUMNS.get(event_type, ()):
        if columns[column] is None:
            raise DomainValidationError(
                f"{event_type.value}: the {column} column is required (Doc 06 §28)"
            )
    nullable = NULLABLE_PAYLOAD_KEYS.get(event_type, frozenset())
    for key in REQUIRED_PAYLOAD_KEYS.get(event_type, ()):
        if key not in payload:
            raise DomainValidationError(
                f"{event_type.value}: the payload key {key!r} is required (Doc 06 §28)"
            )
        if payload[key] is None and key not in nullable:
            raise DomainValidationError(
                f"{event_type.value}: the payload key {key!r} may not be null (Doc 06 §28)"
            )
    if event_type is T.STATE_CREATED:
        version = payload["version"]
        if not isinstance(version, int) or isinstance(version, bool) or version < 0:
            raise DomainValidationError("STATE_CREATED: version must be an integer >= 0")
        if (payload["parent_state_id"] is None) != (version == 0):
            raise DomainValidationError(
                "STATE_CREATED: parent_state_id is null exactly when version is 0 (C-32)"
            )
    if event_type is T.ESCALATED and candidate_id is None and payload.get("attempt_id") is None:
        raise DomainValidationError(
            "ESCALATED: needs the candidate_id column or the attempt_id payload key (Doc 06 §28)"
        )


@dataclass(frozen=True)
class AuditEvent:
    """A stored audit event (Doc 11 §13): a read result, never accepted as input."""

    sequence: int
    event_id: str
    event_type: AuditEventType
    event_version: int
    correlation_id: str
    operation_id: str
    actor_type: ActorType
    actor_id: str | None
    state_id: str | None
    candidate_id: str | None
    decision_id: str | None
    timestamp: datetime
    payload_hash: str
    payload_ref: str

    def __post_init__(self) -> None:
        require_int(self.sequence, "AuditEvent.sequence", 1)
        _check_event_fields(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "event_version": self.event_version,
            "correlation_id": self.correlation_id,
            "operation_id": self.operation_id,
            "actor_type": self.actor_type.value,
            "actor_id": self.actor_id,
            "state_id": self.state_id,
            "candidate_id": self.candidate_id,
            "decision_id": self.decision_id,
            "timestamp": iso_utc(self.timestamp),
            "payload_hash": self.payload_hash,
            "payload_ref": self.payload_ref,
        }

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> AuditEvent:
        """Rebuild a stored event from its column values, with every field re-validated."""
        return cls(
            sequence=row["sequence"],
            event_id=row["event_id"],
            event_type=parse_enum(row["event_type"], AuditEventType, "AuditEvent.event_type"),
            event_version=row["event_version"],
            correlation_id=row["correlation_id"],
            operation_id=row["operation_id"],
            actor_type=parse_enum(row["actor_type"], ActorType, "AuditEvent.actor_type"),
            actor_id=row["actor_id"],
            state_id=row["state_id"],
            candidate_id=row["candidate_id"],
            decision_id=row["decision_id"],
            timestamp=parse_utc(row["timestamp"], "AuditEvent.timestamp"),
            payload_hash=row["payload_hash"],
            payload_ref=row["payload_ref"],
        )

    def same_content_as(self, submission: AuditSubmission) -> bool:
        """Identical to ``submission`` in every field except ``sequence`` and ``timestamp``
        (Doc 11 §38; rule A6). The payload is compared by its hash."""
        return _identity(self) == _identity(submission)


def _identity(item: AuditEvent | AuditSubmission) -> tuple[Any, ...]:
    return (
        item.event_id,
        item.event_type,
        item.event_version,
        item.correlation_id,
        item.operation_id,
        item.actor_type,
        item.actor_id,
        item.state_id,
        item.candidate_id,
        item.decision_id,
        item.payload_hash,
        item.payload_ref,
    )


def _check_event_fields(item: AuditEvent | AuditSubmission) -> None:
    name = type(item).__name__
    for field in ("event_id", "correlation_id", "operation_id"):
        require_uuid(getattr(item, field), f"{name}.{field}")
    for field in ("state_id", "candidate_id", "decision_id"):
        optional_uuid(getattr(item, field), f"{name}.{field}")
    require_enum(item.event_type, AuditEventType, f"{name}.event_type")
    require_enum(item.actor_type, ActorType, f"{name}.actor_type")
    require_int(item.event_version, f"{name}.event_version", 1)
    optional_text(item.actor_id, f"{name}.actor_id")
    object.__setattr__(item, "timestamp", utc(item.timestamp, f"{name}.timestamp"))
    require_sha256(item.payload_hash, f"{name}.payload_hash")
    if item.payload_ref != ArtifactRef("audit", item.payload_hash).uri:
        raise DomainValidationError(
            f"{name}.payload_ref: must be evidence://audit/<payload_hash> (Doc 11 §17)"
        )


@dataclass(frozen=True)
class AuditSubmission:
    """What an ``AuditRepository`` accepts: the event's fields and the text of its payload.

    Like ``EvidenceSubmission`` it re-checks itself: the payload must be canonical JSON that hashes
    to ``payload_hash`` and holds no secret (Doc 11 §28), and the columns and payload keys of the
    event type must be present (C-57)."""

    event_id: str
    event_type: AuditEventType
    event_version: int
    correlation_id: str
    operation_id: str
    actor_type: ActorType
    actor_id: str | None
    state_id: str | None
    candidate_id: str | None
    decision_id: str | None
    timestamp: datetime
    payload_hash: str
    payload_ref: str
    payload_json: str

    def __post_init__(self) -> None:
        _check_event_fields(self)
        payload = check_payload_json(self.payload_json, self.payload_hash)
        check_audit_fields(
            self.event_type,
            state_id=self.state_id,
            candidate_id=self.candidate_id,
            decision_id=self.decision_id,
            payload=payload,
        )

    @classmethod
    def create(
        cls,
        *,
        event_id: str,
        event_type: AuditEventType,
        correlation_id: str,
        operation_id: str,
        timestamp: datetime,
        payload: Any,
        actor_type: ActorType = ActorType.SYSTEM,
        actor_id: str | None = None,
        state_id: str | None = None,
        candidate_id: str | None = None,
        decision_id: str | None = None,
        event_version: int = 1,
    ) -> AuditSubmission:
        validate_json(payload, "AuditSubmission.payload")  # C-33: no floats
        plain = thaw_json(payload)
        if Redactor().contains_secret(plain):
            raise DomainValidationError(
                "AuditSubmission.payload: contains a secret-like value; redact it before "
                "submitting (Doc 11 §28)"
            )
        digest = hashing.content_hash(plain)
        return cls(
            event_id=event_id,
            event_type=event_type,
            event_version=event_version,
            correlation_id=correlation_id,
            operation_id=operation_id,
            actor_type=actor_type,
            actor_id=actor_id,
            state_id=state_id,
            candidate_id=candidate_id,
            decision_id=decision_id,
            timestamp=timestamp,
            payload_hash=digest,
            payload_ref=ArtifactRef("audit", digest).uri,
            payload_json=hashing.canonical_json(plain),
        )


@dataclass(frozen=True)
class AuditAppendResult:
    event: AuditEvent
    duplicate: bool
