"""P2 data contracts, taken from Doc 11.

  EvidenceRecord   Section 6   (immutable; hash-protected)
  Validity states  Section 7   (VALID/INVALID/UNCERTAIN/SUPERSEDED/REDACTED)
  AuditEvent       Section 13  (append-only)
  LogEvent         Section 14  (structured, machine-readable)

Where this file goes beyond a field in the spec, it says so:
  - EvidenceRecord.state_hash and .redaction_policy_version are additions
    required by Doc 11 Section 8 ("state_hash must be recorded whenever
    content depends on semantic state") and Section 28 ("redaction policy
    version must be recorded where transformation occurs").
  - Event taxonomy: the spec table was only partly retrievable while
    building this; the members below are those confirmed in Doc 11
    Section 12 plus the three EVIDENCE_* validity events this module
    itself needs (Section 32-33 require "a validity-transition event is
    appended"). Reconcile against the full Section 12 table in review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1"
_HEX = set("0123456789abcdef")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and set(value) <= _HEX


class EvidenceType(str, Enum):
    STATE = "STATE"
    CANDIDATE = "CANDIDATE"
    PATCH = "PATCH"
    IDENTITY = "IDENTITY"
    DEPENDENCY = "DEPENDENCY"
    IMPACT = "IMPACT"
    VERIFICATION = "VERIFICATION"
    LLM = "LLM"
    PROMOTION = "PROMOTION"
    ERROR = "ERROR"
    EXPERIMENT = "EXPERIMENT"


class EvidenceValidity(str, Enum):
    """Doc 11 Section 7."""

    VALID = "VALID"  # eligible for use under current policy/context
    INVALID = "INVALID"  # retained, but no longer valid for the new-state context
    UNCERTAIN = "UNCERTAIN"  # validity cannot be established safely
    SUPERSEDED = "SUPERSEDED"  # replaced by newer authoritative artifact; auditable
    REDACTED = "REDACTED"  # content only under approved protected storage


# Which validity changes are legal. Design notes (interpretation of Doc 11
# Sections 7, 32, 33 -- the spec names the states but not a full table):
#   * INVALID never returns to VALID. Once impact analysis invalidates
#     evidence, DAIL must produce *new* evidence (a new record) -- this is
#     the paper's "re-establish before trusting" rule. Fail closed.
#   * UNCERTAIN may be resolved either way once safe grounds exist.
#   * SUPERSEDED and REDACTED are terminal.
ALLOWED_VALIDITY_TRANSITIONS: dict[EvidenceValidity, frozenset[EvidenceValidity]] = {
    EvidenceValidity.VALID: frozenset(
        {
            EvidenceValidity.INVALID,
            EvidenceValidity.UNCERTAIN,
            EvidenceValidity.SUPERSEDED,
            EvidenceValidity.REDACTED,
        }
    ),
    EvidenceValidity.UNCERTAIN: frozenset(
        {EvidenceValidity.VALID, EvidenceValidity.INVALID, EvidenceValidity.SUPERSEDED}
    ),
    EvidenceValidity.INVALID: frozenset({EvidenceValidity.SUPERSEDED}),
    EvidenceValidity.SUPERSEDED: frozenset(),
    EvidenceValidity.REDACTED: frozenset(),
}


@dataclass(frozen=True)
class EvidenceRecord:
    """Immutable evidence record (Doc 11 Section 6).

    Payloads live in a content-addressed store; this record carries only
    ``payload_ref`` and ``content_hash``. ``validity`` here is the *initial*
    validity at creation. Later changes are append-only ValidityTransitions;
    the current validity is always derived by the store, never mutated here.
    """

    evidence_id: str
    evidence_type: EvidenceType
    operation_id: str
    correlation_id: str
    source_component: str
    source_type: str
    content_hash: str
    payload_ref: str
    algorithm_or_verifier_version: str
    state_id: str | None = None
    candidate_id: str | None = None
    parent_state_id: str | None = None
    state_hash: str | None = None
    validity: EvidenceValidity = EvidenceValidity.VALID
    schema_version: str = SCHEMA_VERSION
    redaction_policy_version: str | None = None
    created_at: datetime = field(default_factory=_now)

    def __post_init__(self) -> None:
        for name in (
            "evidence_id", "operation_id", "correlation_id", "source_component",
            "source_type", "algorithm_or_verifier_version",
        ):
            if not getattr(self, name):
                raise ValueError(f"EvidenceRecord.{name} must be non-empty")
        if not _is_sha256_hex(self.content_hash):
            raise ValueError("EvidenceRecord.content_hash must be a SHA-256 hex digest")
        if not self.payload_ref.startswith(("cas:", "ext:")):
            raise ValueError("EvidenceRecord.payload_ref must start with 'cas:' or 'ext:'")

    @property
    def is_bound(self) -> bool:
        """Doc 11 Section 8: evidence that can influence trust must identify
        exactly which state/candidate it describes. Unbound evidence may be
        stored but can never serve as promotion proof."""
        return self.state_id is not None or self.candidate_id is not None


class AuditEventType(str, Enum):
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
    # Added by this module (Doc 11 Sections 32-33):
    EVIDENCE_INVALIDATED = "EVIDENCE_INVALIDATED"
    EVIDENCE_SUPERSEDED = "EVIDENCE_SUPERSEDED"
    EVIDENCE_VALIDITY_CHANGED = "EVIDENCE_VALIDITY_CHANGED"


class ActorType(str, Enum):
    """Doc 11 Section 13: system component, user, automation, or provider."""

    SYSTEM = "SYSTEM"
    USER = "USER"
    AUTOMATION = "AUTOMATION"
    PROVIDER = "PROVIDER"


@dataclass(frozen=True)
class AuditEvent:
    """Immutable audit event (Doc 11 Section 13). ``sequence`` is assigned by
    the store on append (a global monotonic counter) and is None beforehand.
    Timestamps alone are never the lineage mechanism (Doc 11 Section 50)."""

    event_id: str
    event_type: AuditEventType
    correlation_id: str
    operation_id: str
    actor_type: ActorType
    payload_hash: str
    payload_ref: str
    event_version: int = 1
    actor_id: str | None = None
    state_id: str | None = None
    candidate_id: str | None = None
    decision_id: str | None = None
    timestamp: datetime = field(default_factory=_now)
    sequence: int | None = None

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("AuditEvent.event_id must be non-empty")
        if self.event_version < 1:
            raise ValueError("AuditEvent.event_version must be >= 1")
        if not _is_sha256_hex(self.payload_hash):
            raise ValueError("AuditEvent.payload_hash must be a SHA-256 hex digest")


@dataclass(frozen=True)
class ValidityTransition:
    """Append-only record that evidence changed validity (Doc 11 Section 32):
    reason, affected candidate/state, and impact-report reference are all
    recorded, and the original evidence payload is never rewritten."""

    transition_id: str
    evidence_id: str
    from_validity: EvidenceValidity
    to_validity: EvidenceValidity
    reason: str
    candidate_id: str | None = None
    state_id: str | None = None
    impact_report_ref: str | None = None
    superseded_by: str | None = None
    created_at: datetime = field(default_factory=_now)


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass(frozen=True)
class LogEvent:
    """Structured, machine-readable log record (Doc 11 Section 14).

    Logs are supplementary, not the audit record (Doc 11 Section 2/50):
    they are never authoritative state and never proof for promotion.
    """

    timestamp: datetime
    level: LogLevel
    service: str
    component: str
    event_name: str
    correlation_id: str
    operation_id: str
    status: str
    candidate_id: str | None = None
    state_id: str | None = None
    duration_ms: float | None = None
    error_code: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.level is LogLevel.ERROR and not self.error_code:
            raise ValueError("ERROR-level LogEvent requires an error_code (Doc 11 Section 15)")

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "service": self.service,
            "component": self.component,
            "event_name": self.event_name,
            "correlation_id": self.correlation_id,
            "operation_id": self.operation_id,
            "candidate_id": self.candidate_id,
            "state_id": self.state_id,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "error_code": self.error_code,
            "metadata": self.metadata,
        }
