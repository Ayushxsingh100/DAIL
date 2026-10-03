"""Evidence model (Doc 05 §16; Doc 11 §5-§9, §16, §17, §28, §32, §33, §45; C-50 to C-56;
P2-fix step 2).

Doc 11 §3: "Evidence is bound to the state context in which it was produced. Evidence has explicit
validity rather than implicit permanence. Historical evidence is retained even after invalidation."

``EvidenceEvent`` is the one evidence record (C-51): the union of Doc 05 §16.1 and Doc 11 §6. It is
immutable. Its ``validity`` is the validity at creation (VALID or UNCERTAIN) and is never updated;
the validity of a record *in a context* is derived from its append-only ``ValidityTransition`` rows
by ``effective_validity`` (C-52), and a transition is legal only if ``check_transition`` says so.
Both are pure functions: the SQLite adapter and the database triggers enforce the same rules.

Nothing here accepts an ``EvidenceEvent``, ``ValidityTransition`` or ``ProofCheck`` as authority.
Evidence is written through an ``EvidenceSubmission``, which refuses an unredacted payload (Doc 11
§28) and recomputes its own hash (Doc 11 §16); the other two are results that are only read.

Standard library and ``core.domain`` only (rule R1). Nothing here reads the clock or draws a random
number (rule R10): every timestamp and every id is passed in.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from core.domain import hashing
from core.domain.errors import (
    DomainValidationError,
    HashMismatchError,
    IllegalTransitionError,
    PersistenceError,
)
from core.domain.ids import require_uuid
from core.domain.jsonvalue import (
    iso_utc,
    optional_text,
    parse_enum,
    parse_utc,
    require_enum,
    require_int,
    require_keys,
    require_text,
    thaw_json,
    utc,
    validate_json,
)
from core.domain.redaction import Redactor
from core.domain.values import Provenance

HASH_ALGORITHM = "sha256"
INTEGRITY_REASON_PREFIX = "INTEGRITY:"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ARTIFACT_TYPE = re.compile(r"[a-z][a-z_]*")
_ARTIFACT_URI = re.compile(r"evidence://([a-z][a-z_]*)/([0-9a-f]{64})")
_ARTIFACT_SCHEME = "evidence://"


# --- Taxonomy and validity (Doc 11 §5, §7; C-54) ---------------------------------------------


class EvidenceKind(StrEnum):
    """Doc 11 §5, exactly. ORACLE is not a kind (ADR-010, Doc 05 §19)."""

    STATE = "STATE"
    CONFIGURATION = "CONFIGURATION"
    IDENTITY = "IDENTITY"
    DEPENDENCY = "DEPENDENCY"
    IMPACT = "IMPACT"
    VERIFICATION = "VERIFICATION"
    LLM = "LLM"
    PROMOTION = "PROMOTION"
    ERROR = "ERROR"
    EXPERIMENT = "EXPERIMENT"


# Doc 11 §4, §27: LLM rationale is generation evidence, not safety proof; ERROR and EXPERIMENT
# evidence describe failures and trials, not the state of the system (C-54).
PROOF_KINDS: frozenset[EvidenceKind] = frozenset(
    {
        EvidenceKind.STATE,
        EvidenceKind.CONFIGURATION,
        EvidenceKind.IDENTITY,
        EvidenceKind.DEPENDENCY,
        EvidenceKind.IMPACT,
        EvidenceKind.VERIFICATION,
        EvidenceKind.PROMOTION,
    }
)

# Doc 11 §9: an impact report or a promotion decision describes exactly one candidate.
CANDIDATE_BOUND_KINDS: frozenset[EvidenceKind] = frozenset(
    {EvidenceKind.IMPACT, EvidenceKind.PROMOTION}
)


class EvidenceValidity(StrEnum):
    """Doc 11 §7."""

    VALID = "VALID"  # eligible for use under current policy/context
    INVALID = "INVALID"  # retained, but no longer valid for the referenced new-state context
    UNCERTAIN = "UNCERTAIN"  # validity cannot be established safely
    SUPERSEDED = "SUPERSEDED"  # replaced by a newer authoritative artifact; auditable
    REDACTED = "REDACTED"  # protected storage; no transition into it exists before P7 (C-52)


# A record is created VALID or UNCERTAIN; every other validity is reached by a transition.
CREATION_VALIDITIES: frozenset[EvidenceValidity] = frozenset(
    {EvidenceValidity.VALID, EvidenceValidity.UNCERTAIN}
)
V = EvidenceValidity
# CONTEXT scope (C-52): the legal (from, to) pairs. UNCERTAIN -> VALID is further limited to a
# context the record was produced for. INVALID is terminal within its context.
CONTEXT_PAIRS: frozenset[tuple[EvidenceValidity, EvidenceValidity]] = frozenset(
    {(V.VALID, V.INVALID), (V.VALID, V.UNCERTAIN), (V.UNCERTAIN, V.INVALID), (V.UNCERTAIN, V.VALID)}
)
# RECORD scope (C-52): only into INVALID (integrity failure) or SUPERSEDED (supersede); a record
# in any of these validities may take its one RECORD transition.
RECORD_FROM: frozenset[EvidenceValidity] = frozenset({V.VALID, V.UNCERTAIN, V.INVALID})
RECORD_TO: frozenset[EvidenceValidity] = frozenset({V.INVALID, V.SUPERSEDED})
# The validities a stored transition can lead to (there is no transition into REDACTED in P2).
TRANSITION_TARGETS: frozenset[EvidenceValidity] = frozenset(
    {V.VALID, V.INVALID, V.UNCERTAIN, V.SUPERSEDED}
)


class TransitionScope(StrEnum):
    CONTEXT = "CONTEXT"  # one state or one candidate
    RECORD = "RECORD"  # every context


class ContextKind(StrEnum):
    STATE = "STATE"
    CANDIDATE = "CANDIDATE"


class IntegrityStatus(StrEnum):
    """Doc 11 §45: recompute the content hash on read; ``VALID`` or ``TAMPERED``. A payload that
    cannot be found at all is reported separately (§17 "evidence references resolve")."""

    VALID = "VALID"
    TAMPERED = "TAMPERED"
    MISSING_PAYLOAD = "MISSING_PAYLOAD"


# --- Errors ----------------------------------------------------------------------------------


class EvidenceNotFoundError(DomainValidationError):
    """An operation named an evidence record that does not exist."""


class BrokenReferenceError(PersistenceError):
    """An ``evidence://`` reference names no stored artifact (Doc 11 §44: references resolve)."""


class EvidenceConflictError(DomainValidationError):
    """An id that is already stored was submitted again with different content (Doc 11 §38)."""


# --- Small validators ------------------------------------------------------------------------


def require_sha256(value: object, field: str) -> str:
    """A 64-character lowercase hexadecimal SHA-256 digest (Doc 11 §16)."""
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DomainValidationError(f"{field}: must be a 64-character lowercase SHA-256 hex digest")
    return value


def optional_uuid(value: object, field: str) -> str | None:
    return None if value is None else require_uuid(value, field)


def optional_sha256(value: object, field: str) -> str | None:
    return None if value is None else require_sha256(value, field)


def require_reason(value: object, field: str) -> str:
    """A reason is free text that is stored in a column and in an audit payload, so it is held to
    the same rule as a payload: no secret-like value (Doc 11 §28). The service redacts it first."""
    text = require_text(value, field)
    if Redactor().contains_secret({"reason": text}):
        raise DomainValidationError(
            f"{field}: contains a secret-like value; redact it first (Doc 11 §28)"
        )
    return text


# --- Contexts and artifact references (Doc 11 §8, §17; C-52, C-56) ---------------------------


@dataclass(frozen=True)
class EvidenceContext:
    """A trusted state or a candidate: the thing a piece of evidence is read against (C-52)."""

    kind: ContextKind
    id: str

    def __post_init__(self) -> None:
        require_enum(self.kind, ContextKind, "EvidenceContext.kind")
        require_uuid(self.id, "EvidenceContext.id")

    @classmethod
    def state(cls, state_id: str) -> EvidenceContext:
        return cls(ContextKind.STATE, state_id)

    @classmethod
    def candidate(cls, candidate_id: str) -> EvidenceContext:
        return cls(ContextKind.CANDIDATE, candidate_id)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "id": self.id}

    def __str__(self) -> str:
        return f"{self.kind.value.lower()} {self.id}"


def artifact_types() -> frozenset[str]:
    """The ``<type>`` segments a reference may carry: a lowercase evidence kind, or ``audit``."""
    return frozenset({kind.value.lower() for kind in EvidenceKind} | {"audit"})


@dataclass(frozen=True)
class ArtifactRef:
    """``evidence://<type>/<content_hash>`` (Doc 11 §17). The logical reference is stable whatever
    the storage backend is; ``<type>`` is the lowercase ``EvidenceKind`` or ``audit`` (C-56)."""

    type: str
    content_hash: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.type, str)
            or _ARTIFACT_TYPE.fullmatch(self.type) is None
            or self.type not in artifact_types()
        ):
            raise DomainValidationError(
                "ArtifactRef.type: must be a lowercase EvidenceKind or 'audit' (Doc 11 §17)"
            )
        require_sha256(self.content_hash, "ArtifactRef.content_hash")

    @property
    def uri(self) -> str:
        return f"{_ARTIFACT_SCHEME}{self.type}/{self.content_hash}"

    @classmethod
    def parse(cls, uri: object) -> ArtifactRef:
        """Rebuild a reference; anything but the exact form is rejected: other schemes (``cas:``,
        ``ext:``), upper case, padding, a second path segment (Doc 11 §17, C-56)."""
        if not isinstance(uri, str):
            raise DomainValidationError("ArtifactRef: the reference must be a string")
        match = _ARTIFACT_URI.fullmatch(uri)
        if match is None:
            raise DomainValidationError(
                f"ArtifactRef: {uri!r} is not evidence://<type>/<64 hex digits> (Doc 11 §17)"
            )
        return cls(match.group(1), match.group(2))


# --- Payloads (Doc 11 §16, §28) --------------------------------------------------------------


def check_payload_json(payload_json: object, expected_hash: str) -> Any:
    """Check the stored form of a payload and return the parsed value.

    The text must be valid JSON with no floats (C-33), be the canonical serialization of its own
    value (Doc 11 §16: deterministic), hash to ``expected_hash`` (SHA-256) and contain no secret
    (Doc 11 §28). The adapter runs the same check on every submission (rules A1)."""
    if not isinstance(payload_json, str):
        raise DomainValidationError("payload_json: must be text")
    try:
        value = json.loads(payload_json)
    except (ValueError, RecursionError):
        raise DomainValidationError("payload_json: not valid JSON") from None
    validate_json(value, "payload")
    if hashing.canonical_json(value) != payload_json:
        raise DomainValidationError(
            "payload_json: not the canonical serialization of its value (Doc 11 §16)"
        )
    if hashing.content_hash(value) != expected_hash:
        raise HashMismatchError(
            "DATA-INT-010: the payload does not hash to the submitted content_hash (Doc 11 §16)"
        )
    if Redactor().contains_secret(value):
        raise DomainValidationError(
            "payload: contains a secret-like value; redact before persisting (Doc 11 §28)"
        )
    return value


# --- The evidence record (Doc 05 §16.1; Doc 11 §6, §8, §9; C-51, C-55) -----------------------


@dataclass(frozen=True)
class EvidenceEvent:
    """One immutable evidence record (C-51).

    ``kind`` is Doc 05's name for Doc 11's ``evidence_type``; ``provenance`` carries Doc 11's
    ``source_component``, ``source_type`` (as ``source_kind``) and
    ``algorithm_or_verifier_version`` (as ``algorithm_version``, never null here).
    """

    evidence_id: str
    run_id: str
    attempt_id: str | None
    correlation_id: str
    operation_id: str
    kind: EvidenceKind
    event_name: str
    state_id: str | None
    candidate_id: str | None
    parent_state_id: str | None
    state_hash: str | None
    content_hash: str
    hash_algorithm: str
    payload_ref: str
    provenance: Provenance
    validity: EvidenceValidity
    schema_version: str
    redaction_policy_version: str | None
    created_at: datetime

    def __post_init__(self) -> None:
        # B7: every id is a canonical UUID.
        for name in ("evidence_id", "run_id", "correlation_id", "operation_id"):
            require_uuid(getattr(self, name), f"EvidenceEvent.{name}")
        for name in ("attempt_id", "state_id", "candidate_id", "parent_state_id"):
            optional_uuid(getattr(self, name), f"EvidenceEvent.{name}")
        require_enum(self.kind, EvidenceKind, "EvidenceEvent.kind")
        require_text(self.event_name, "EvidenceEvent.event_name")
        optional_sha256(self.state_hash, "EvidenceEvent.state_hash")
        require_sha256(self.content_hash, "EvidenceEvent.content_hash")
        if self.hash_algorithm != HASH_ALGORITHM:
            raise DomainValidationError(
                f"EvidenceEvent.hash_algorithm: must be {HASH_ALGORITHM!r} (Doc 11 §16)"
            )
        # B5: the reference is derived from the kind and the hash, so it cannot point elsewhere.
        if self.payload_ref != ArtifactRef(self.kind.value.lower(), self.content_hash).uri:
            raise DomainValidationError(
                "EvidenceEvent.payload_ref: must be evidence://<kind>/<content_hash> (Doc 11 §17)"
            )
        if not isinstance(self.provenance, Provenance):
            raise DomainValidationError("EvidenceEvent.provenance: must be a Provenance (C-51)")
        # B6: Doc 11 §16 requires the hash algorithm/version, and §6 the verifier version.
        if self.provenance.algorithm_version is None:
            raise DomainValidationError(
                "EvidenceEvent.provenance.algorithm_version: required for evidence (Doc 11 §6)"
            )
        require_enum(self.validity, EvidenceValidity, "EvidenceEvent.validity")
        if self.validity not in CREATION_VALIDITIES:
            raise DomainValidationError(
                "EvidenceEvent.validity: the creation validity is VALID or UNCERTAIN; the rest "
                "are reached by a transition (C-51)"
            )
        require_text(self.schema_version, "EvidenceEvent.schema_version")
        optional_text(self.redaction_policy_version, "EvidenceEvent.redaction_policy_version")
        object.__setattr__(self, "created_at", utc(self.created_at, "EvidenceEvent.created_at"))
        # B1: a candidate-bound record names its attempt and the parent it was written against.
        if self.candidate_id is not None and (
            self.attempt_id is None or self.parent_state_id is None
        ):
            raise DomainValidationError(
                "EvidenceEvent: a candidate-bound record needs attempt_id and parent_state_id "
                "(C-55, Doc 11 §9)"
            )
        # B2: evidence about a state records the state hash (Doc 11 §8).
        if self.state_id is not None and self.candidate_id is None and self.state_hash is None:
            raise DomainValidationError(
                "EvidenceEvent.state_hash: required when only state_id is set (Doc 11 §8)"
            )
        # B3: unbound evidence has no state to hash and no parent.
        if (
            self.state_id is None
            and self.candidate_id is None
            and (self.state_hash is not None or self.parent_state_id is not None)
        ):
            raise DomainValidationError(
                "EvidenceEvent: unbound evidence has no state_hash and no parent_state_id "
                "(Doc 11 §8)"
            )
        # B4: impact reports and promotion decisions bind to the exact candidate (Doc 11 §9).
        if self.kind in CANDIDATE_BOUND_KINDS and self.candidate_id is None:
            raise DomainValidationError(
                f"EvidenceEvent: {self.kind.value} evidence must be bound to a candidate "
                "(Doc 11 §9)"
            )

    # --- derived -------------------------------------------------------------------------------

    @property
    def contexts(self) -> tuple[EvidenceContext, ...]:
        """The contexts the record was produced for (C-52): its state and its candidate."""
        found: list[EvidenceContext] = []
        if self.state_id is not None:
            found.append(EvidenceContext.state(self.state_id))
        if self.candidate_id is not None:
            found.append(EvidenceContext.candidate(self.candidate_id))
        return tuple(found)

    @property
    def primary_context(self) -> EvidenceContext | None:
        """The candidate if set, else the state, else ``None`` (C-52)."""
        if self.candidate_id is not None:
            return EvidenceContext.candidate(self.candidate_id)
        if self.state_id is not None:
            return EvidenceContext.state(self.state_id)
        return None

    @property
    def is_bound(self) -> bool:
        """Doc 11 §8: evidence without a state or candidate binding is never promotion proof."""
        return self.state_id is not None or self.candidate_id is not None

    # --- serialization -------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
            "correlation_id": self.correlation_id,
            "operation_id": self.operation_id,
            "kind": self.kind.value,
            "event_name": self.event_name,
            "state_id": self.state_id,
            "candidate_id": self.candidate_id,
            "parent_state_id": self.parent_state_id,
            "state_hash": self.state_hash,
            "content_hash": self.content_hash,
            "hash_algorithm": self.hash_algorithm,
            "payload_ref": self.payload_ref,
            "provenance": self.provenance.to_dict(),
            "validity": self.validity.value,
            "schema_version": self.schema_version,
            "redaction_policy_version": self.redaction_policy_version,
            "created_at": iso_utc(self.created_at),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvidenceEvent:
        fields = require_keys(
            data,
            (
                "evidence_id",
                "run_id",
                "attempt_id",
                "correlation_id",
                "operation_id",
                "kind",
                "event_name",
                "state_id",
                "candidate_id",
                "parent_state_id",
                "state_hash",
                "content_hash",
                "hash_algorithm",
                "payload_ref",
                "provenance",
                "validity",
                "schema_version",
                "redaction_policy_version",
                "created_at",
            ),
            "EvidenceEvent",
        )
        return cls(
            evidence_id=fields["evidence_id"],
            run_id=fields["run_id"],
            attempt_id=fields["attempt_id"],
            correlation_id=fields["correlation_id"],
            operation_id=fields["operation_id"],
            kind=parse_enum(fields["kind"], EvidenceKind, "EvidenceEvent.kind"),
            event_name=fields["event_name"],
            state_id=fields["state_id"],
            candidate_id=fields["candidate_id"],
            parent_state_id=fields["parent_state_id"],
            state_hash=fields["state_hash"],
            content_hash=fields["content_hash"],
            hash_algorithm=fields["hash_algorithm"],
            payload_ref=fields["payload_ref"],
            provenance=Provenance.from_dict(fields["provenance"]),
            validity=parse_enum(fields["validity"], EvidenceValidity, "EvidenceEvent.validity"),
            schema_version=fields["schema_version"],
            redaction_policy_version=fields["redaction_policy_version"],
            created_at=parse_utc(fields["created_at"], "EvidenceEvent.created_at"),
        )

    def same_content_as(self, other: EvidenceEvent) -> bool:
        """Identical in every field except ``created_at`` (Doc 11 §38; rule A6)."""
        mine, theirs = self.to_dict(), other.to_dict()
        del mine["created_at"], theirs["created_at"]
        return mine == theirs


@dataclass(frozen=True)
class EvidenceSubmission:
    """What an ``EvidenceRepository`` accepts: a record and the text of its payload.

    Build one with ``create``, which redacts nothing but refuses a payload that still holds a
    secret (Doc 11 §28; the service redacts first) and derives the hash and the reference. The
    constructor re-checks the same things, so a submission assembled by hand is held to the same
    rules; the adapter checks them once more on append (rules A1).
    """

    event: EvidenceEvent
    payload_json: str

    def __post_init__(self) -> None:
        if not isinstance(self.event, EvidenceEvent):
            raise DomainValidationError("EvidenceSubmission.event: must be an EvidenceEvent")
        check_payload_json(self.payload_json, self.event.content_hash)

    @classmethod
    def create(
        cls,
        *,
        payload: Any,
        evidence_id: str,
        run_id: str,
        attempt_id: str | None,
        correlation_id: str,
        operation_id: str,
        kind: EvidenceKind,
        event_name: str,
        provenance: Provenance,
        created_at: datetime,
        state_id: str | None = None,
        candidate_id: str | None = None,
        parent_state_id: str | None = None,
        state_hash: str | None = None,
        validity: EvidenceValidity = EvidenceValidity.VALID,
        schema_version: str = "1",
        redaction_policy_version: str | None = None,
    ) -> EvidenceSubmission:
        require_enum(kind, EvidenceKind, "EvidenceSubmission.kind")
        validate_json(payload, "EvidenceSubmission.payload")  # C-33: no floats
        plain = thaw_json(payload)
        if Redactor().contains_secret(plain):
            raise DomainValidationError(
                "EvidenceSubmission.payload: contains a secret-like value; redact it before "
                "submitting (Doc 11 §28)"
            )
        digest = hashing.content_hash(plain)
        event = EvidenceEvent(
            evidence_id=evidence_id,
            run_id=run_id,
            attempt_id=attempt_id,
            correlation_id=correlation_id,
            operation_id=operation_id,
            kind=kind,
            event_name=event_name,
            state_id=state_id,
            candidate_id=candidate_id,
            parent_state_id=parent_state_id,
            state_hash=state_hash,
            content_hash=digest,
            hash_algorithm=HASH_ALGORITHM,
            payload_ref=ArtifactRef(kind.value.lower(), digest).uri,
            provenance=provenance,
            validity=validity,
            schema_version=schema_version,
            redaction_policy_version=redaction_policy_version,
            created_at=created_at,
        )
        return cls(event=event, payload_json=hashing.canonical_json(plain))


# --- Validity transitions (Doc 11 §7, §32, §33; C-52) ----------------------------------------


@dataclass(frozen=True)
class TransitionRequest:
    """A request to change one record's validity. It carries no from-validity: the legal origin is
    derived from the record's own transitions (``check_transition``). It is built by the service;
    nothing else in the system can ask for a transition by handing over a stored one."""

    transition_id: str
    evidence_id: str
    scope: TransitionScope
    context: EvidenceContext | None
    to_validity: EvidenceValidity
    reason: str
    impact_ref: str | None
    correlation_id: str
    operation_id: str
    created_at: datetime

    def __post_init__(self) -> None:
        for name in ("transition_id", "evidence_id", "correlation_id", "operation_id"):
            require_uuid(getattr(self, name), f"TransitionRequest.{name}")
        _check_scope_and_context("TransitionRequest", self.scope, self.context)
        require_enum(self.to_validity, EvidenceValidity, "TransitionRequest.to_validity")
        require_reason(self.reason, "TransitionRequest.reason")
        optional_uuid(self.impact_ref, "TransitionRequest.impact_ref")
        object.__setattr__(self, "created_at", utc(self.created_at, "TransitionRequest.created_at"))


@dataclass(frozen=True)
class SupersessionRequest:
    """evidence_v1 --SUPERSEDED_BY--> evidence_v2 (Doc 11 §33; C-53)."""

    transition_id: str
    old_evidence_id: str
    new_evidence_id: str
    reason: str
    correlation_id: str
    operation_id: str
    created_at: datetime

    def __post_init__(self) -> None:
        for name in (
            "transition_id",
            "old_evidence_id",
            "new_evidence_id",
            "correlation_id",
            "operation_id",
        ):
            require_uuid(getattr(self, name), f"SupersessionRequest.{name}")
        require_reason(self.reason, "SupersessionRequest.reason")
        object.__setattr__(
            self, "created_at", utc(self.created_at, "SupersessionRequest.created_at")
        )


@dataclass(frozen=True)
class ValidityTransition:
    """A stored validity change. It is a read result: nothing accepts it as input."""

    seq: int
    transition_id: str
    evidence_id: str
    scope: TransitionScope
    context: EvidenceContext | None
    from_validity: EvidenceValidity
    to_validity: EvidenceValidity
    reason: str
    impact_ref: str | None
    superseded_by: str | None
    correlation_id: str
    operation_id: str
    created_at: datetime

    def __post_init__(self) -> None:
        require_int(self.seq, "ValidityTransition.seq", 1)
        for name in ("transition_id", "evidence_id", "correlation_id", "operation_id"):
            require_uuid(getattr(self, name), f"ValidityTransition.{name}")
        _check_scope_and_context("ValidityTransition", self.scope, self.context)
        require_enum(self.from_validity, EvidenceValidity, "ValidityTransition.from_validity")
        require_enum(self.to_validity, EvidenceValidity, "ValidityTransition.to_validity")
        if self.to_validity not in TRANSITION_TARGETS:
            raise DomainValidationError(
                f"ValidityTransition.to_validity: {self.to_validity.value} is not a transition "
                "target (C-52: no transition into REDACTED in P2)"
            )
        require_reason(self.reason, "ValidityTransition.reason")
        optional_uuid(self.impact_ref, "ValidityTransition.impact_ref")
        optional_uuid(self.superseded_by, "ValidityTransition.superseded_by")
        if (self.to_validity is V.SUPERSEDED) != (self.superseded_by is not None):
            raise DomainValidationError(
                "ValidityTransition.superseded_by: set exactly when the target is SUPERSEDED "
                "(Doc 11 §33)"
            )
        if self.to_validity is V.SUPERSEDED and self.scope is not TransitionScope.RECORD:
            raise DomainValidationError("ValidityTransition: SUPERSEDED has RECORD scope (C-52)")
        object.__setattr__(
            self, "created_at", utc(self.created_at, "ValidityTransition.created_at")
        )


def _check_scope_and_context(
    name: str, scope: TransitionScope, context: EvidenceContext | None
) -> None:
    require_enum(scope, TransitionScope, f"{name}.scope")
    if scope is TransitionScope.RECORD:
        if context is not None:
            raise DomainValidationError(f"{name}.context: a RECORD-scope transition has none")
    elif not isinstance(context, EvidenceContext):
        raise DomainValidationError(f"{name}.context: a CONTEXT-scope transition names one (C-52)")


@dataclass(frozen=True)
class EvidenceAppendResult:
    record: EvidenceEvent
    duplicate: bool


@dataclass(frozen=True)
class TransitionAppendResult:
    transition: ValidityTransition
    duplicate: bool


@dataclass(frozen=True)
class ProofCheck:
    """The outcome of asking whether evidence may serve as proof (C-52, Doc 11 §8, §45).

    ``usable`` and ``reasons`` cannot disagree: a usable check has no failure reasons, and an
    unusable one names at least one. It is a read result; nothing accepts it as authority."""

    usable: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.usable, bool):
            raise DomainValidationError("ProofCheck.usable: must be a bool")
        reasons = tuple(self.reasons)
        object.__setattr__(self, "reasons", reasons)
        if self.usable == bool(reasons):
            raise DomainValidationError(
                "ProofCheck: a usable check has no reasons and an unusable one has at least one"
            )


# --- Pure rules (C-52, C-53) -----------------------------------------------------------------


def _own_transitions(
    event: EvidenceEvent, transitions: Sequence[ValidityTransition]
) -> list[ValidityTransition]:
    for transition in transitions:
        if not isinstance(transition, ValidityTransition):
            raise DomainValidationError("transitions: must be ValidityTransition records")
        if transition.evidence_id != event.evidence_id:
            raise DomainValidationError(
                f"transition {transition.transition_id} belongs to another evidence record"
            )
    return sorted(transitions, key=lambda transition: transition.seq)


def _record_transition(ordered: Sequence[ValidityTransition]) -> ValidityTransition | None:
    found = [t for t in ordered if t.scope is TransitionScope.RECORD]
    if len(found) > 1:
        raise DomainValidationError(
            "C-52: a record has at most one RECORD-scope transition, but several are stored"
        )
    return found[0] if found else None


def effective_validity(
    event: EvidenceEvent, context: EvidenceContext, transitions: Sequence[ValidityTransition]
) -> EvidenceValidity:
    """The validity of ``event`` in ``context`` (C-52), in this order:

    R1  the record's RECORD-scope transition, if it has one;
    R2  otherwise the latest CONTEXT transition for this context;
    R3  otherwise, if the context is one the record was produced for, its creation validity;
    R4  otherwise UNCERTAIN: evidence is never implicitly valid outside the context it was
        produced for (Doc 06 §10). Carry-forward eligibility is P6 policy, not a default here.
    """
    if not isinstance(context, EvidenceContext):
        raise DomainValidationError("effective_validity: context must be an EvidenceContext")
    ordered = _own_transitions(event, transitions)
    record = _record_transition(ordered)
    if record is not None:
        return record.to_validity
    latest: ValidityTransition | None = None
    for transition in ordered:
        if transition.scope is TransitionScope.CONTEXT and transition.context == context:
            latest = transition
    if latest is not None:
        return latest.to_validity
    if context in event.contexts:
        return event.validity
    return EvidenceValidity.UNCERTAIN


def primary_validity(
    event: EvidenceEvent, transitions: Sequence[ValidityTransition]
) -> EvidenceValidity:
    """The validity in the record's primary context, or, for an unbound record, its RECORD-scope
    transition or its creation validity (C-52)."""
    primary = event.primary_context
    if primary is not None:
        return effective_validity(event, primary, transitions)
    record = _record_transition(_own_transitions(event, transitions))
    return event.validity if record is None else record.to_validity


def _illegal(
    current: EvidenceValidity, requested: EvidenceValidity, detail: str
) -> IllegalTransitionError:
    return IllegalTransitionError("evidence validity", current, requested, "C-52", detail)


def check_transition(
    event: EvidenceEvent, request: TransitionRequest, transitions: Sequence[ValidityTransition]
) -> EvidenceValidity:
    """Return the from-validity of the transition ``request`` asks for, or raise
    ``IllegalTransitionError`` (C-52). ``transitions`` are the record's stored transitions.

    CONTEXT scope: the pair must be VALID->INVALID, VALID->UNCERTAIN, UNCERTAIN->INVALID or
    UNCERTAIN->VALID, the last only in a context the record was produced for; INVALID is terminal in
    its context; INVALID in a candidate context needs ``impact_ref`` (Doc 11 §32).
    RECORD scope: only INVALID, with an ``INTEGRITY:`` reason (Doc 11 §46); SUPERSEDED goes through
    ``check_supersession``. A record has at most one RECORD transition and nothing follows it.
    """
    if request.evidence_id != event.evidence_id:
        raise DomainValidationError("check_transition: the request is for another record")
    ordered = _own_transitions(event, transitions)
    target = request.to_validity
    record = _record_transition(ordered)
    if record is not None:
        raise _illegal(
            record.to_validity,
            target,
            "the record already has its RECORD-scope transition, which is terminal",
        )
    if request.scope is TransitionScope.RECORD:
        current = primary_validity(event, ordered)
        if target is V.SUPERSEDED:
            raise _illegal(current, target, "SUPERSEDED is reached only through supersede")
        if target is not V.INVALID:
            raise _illegal(current, target, "a RECORD-scope transition leads to INVALID only")
        if not request.reason.startswith(INTEGRITY_REASON_PREFIX):
            raise _illegal(
                current,
                target,
                f"a RECORD-scope INVALID is an integrity failure; the reason starts with "
                f"{INTEGRITY_REASON_PREFIX!r} (Doc 11 §46)",
            )
        if current not in RECORD_FROM:
            raise _illegal(current, target, "no RECORD-scope transition leaves this validity")
        return current
    assert request.context is not None  # guaranteed by TransitionRequest
    current = effective_validity(event, request.context, ordered)
    if (current, target) not in CONTEXT_PAIRS:
        raise _illegal(current, target, f"not a legal CONTEXT-scope change in {request.context}")
    if current is V.UNCERTAIN and target is V.VALID and request.context not in event.contexts:
        raise _illegal(
            current, target, "UNCERTAIN -> VALID only in a context the record was produced for"
        )
    if (
        target is V.INVALID
        and request.context.kind is ContextKind.CANDIDATE
        and request.impact_ref is None
    ):
        raise _illegal(
            current,
            target,
            "INVALID in a candidate context needs the impact_ref of IMPACT evidence for that "
            "candidate (Doc 11 §32)",
        )
    return current


def check_supersession(
    old: EvidenceEvent,
    new: EvidenceEvent,
    old_transitions: Sequence[ValidityTransition],
    new_transitions: Sequence[ValidityTransition],
) -> EvidenceValidity:
    """C-53: ``new`` may supersede ``old`` only if both describe the same thing. They must differ,
    have the same kind, ``state_id`` and ``candidate_id`` and both be bound; neither may have a
    RECORD-scope transition; ``new`` must be VALID in its primary context. Evidence about one state
    never supersedes evidence about another (Doc 06 §10, §15). Returns ``old``'s from-validity."""
    old_ordered = _own_transitions(old, old_transitions)
    new_ordered = _own_transitions(new, new_transitions)
    current = primary_validity(old, old_ordered)

    def refuse(detail: str) -> IllegalTransitionError:
        return IllegalTransitionError("evidence validity", current, V.SUPERSEDED, "C-53", detail)

    if old.evidence_id == new.evidence_id:
        raise refuse("evidence cannot supersede itself")
    if old.kind is not new.kind:
        raise refuse(f"kinds differ ({old.kind.value} and {new.kind.value})")
    if not old.is_bound or not new.is_bound:
        raise refuse("both records must be bound to a state or a candidate (Doc 11 §8)")
    if old.state_id != new.state_id or old.candidate_id != new.candidate_id:
        raise refuse("the records describe different states or candidates (Doc 06 §10, §15)")
    if _record_transition(old_ordered) is not None:
        raise refuse("the old record already has its RECORD-scope transition")
    if _record_transition(new_ordered) is not None:
        raise refuse("the new record already has its RECORD-scope transition")
    replacement = primary_validity(new, new_ordered)
    if replacement is not V.VALID:
        raise refuse(f"the new record is {replacement.value} in its primary context, not VALID")
    return current


def evaluate_proof(
    event: EvidenceEvent | None,
    expected: EvidenceContext,
    transitions: Sequence[ValidityTransition],
    integrity: IntegrityStatus | None,
    expected_state_hash: str | None,
) -> ProofCheck:
    """May ``event`` serve as proof about ``expected`` (conditions P1 to P6)? Every failed
    condition is listed. Nothing here can raise a record into usability: unknown inputs fail."""
    if event is None:
        return ProofCheck(False, ("P1: the evidence does not exist",))
    reasons: list[str] = []
    if event.kind not in PROOF_KINDS:
        reasons.append(f"P2: {event.kind.value} evidence is never proof (Doc 11 §4, §27)")
    if expected not in event.contexts:
        reasons.append(f"P3: the evidence was not produced for the {expected} (Doc 11 §8, §9)")
    validity = effective_validity(event, expected, transitions)
    if validity is not V.VALID:
        reasons.append(
            f"P4: validity in the {expected} is {validity.value}, not VALID (Doc 06 §10)"
        )
    if integrity is not IntegrityStatus.VALID:
        found = "not checked" if integrity is None else integrity.value
        reasons.append(f"P5: integrity is {found} (Doc 11 §45)")
    if event.state_hash is None:
        reasons.append("P6: the evidence records no state_hash (Doc 11 §8)")
    elif expected_state_hash is None:
        reasons.append(f"P6: the {expected} does not exist or has no state_hash to match")
    elif event.state_hash != expected_state_hash:
        reasons.append(f"P6: the evidence state_hash differs from the {expected} (Doc 11 §44)")
    return ProofCheck(not reasons, tuple(reasons))


def validity_changed_payload(
    *,
    evidence_id: str,
    scope: TransitionScope,
    context: EvidenceContext | None,
    from_validity: EvidenceValidity,
    to_validity: EvidenceValidity,
    reason: str,
    impact_ref: str | None,
    superseded_by: str | None,
) -> dict[str, Any]:
    """The payload of the EVIDENCE_VALIDITY_CHANGED audit event (Doc 11 §32; C-57, §4.6)."""
    return {
        "evidence_id": evidence_id,
        "scope": scope.value,
        "context_kind": None if context is None else context.kind.value,
        "context_id": None if context is None else context.id,
        "from_validity": from_validity.value,
        "to_validity": to_validity.value,
        "reason": reason,
        "impact_ref": impact_ref,
        "superseded_by": superseded_by,
    }
