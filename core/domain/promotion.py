"""Promotion types: the decision, its evidence and the policy (P6a; Doc 05 §15, Doc 06 §16-§21,
Doc 09 §17-§29, Doc 11 §26, §43; C-157 to C-161).

The decision half of the Promotion Controller (``core.promotion.decide``) turns the full evaluation
context into one ``PromotionDecision``: PROMOTE, REJECT, RETRY or ESCALATE. A decision preserves
every blocking reason (Doc 05 §15), and a PROMOTE names every verification result that established
eligibility (Doc 11 §26). ``committed_state_id`` and ``new_state_id`` stay null here; the commit of
P6b is the only thing that sets them (DATA-INT-004).

``PromotionPolicy`` is data: the registry version, the invariant definitions, the non-success table,
the retry budget and the emergency switch are all passed in, so neither this module nor
``core.promotion`` reads configuration (Doc 14 §37). The policy refuses to accept oracle evidence as
proof (ADR-010, C-54).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping
from dataclasses import InitVar, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from core.domain.enums import DecisionType, VerificationResult
from core.domain.errors import (
    DomainValidationError,
    HashMismatchError,
    UnauthorizedConstructionError,
)
from core.domain.hashing import content_hash
from core.domain.ids import require_uuid
from core.domain.invariant import Invariant
from core.domain.jsonvalue import (
    iso_utc,
    parse_enum,
    parse_utc,
    require_enum,
    require_int,
    require_keys,
    require_text,
    utc,
)
from core.domain.verification import EVIDENCE_LEVELS

GATE_STRUCTURAL: Final = "STRUCTURAL"
GATE_CONSISTENCY: Final = "CONSISTENCY"
GATE_TARGETS: Final = (GATE_CONSISTENCY, GATE_STRUCTURAL)
CHECK_KINDS: Final = ("BASELINE", "GATE", "INVARIANT")
SUFFICIENCY_VALUES: Final = ("INSUFFICIENT", "SUFFICIENT")
NON_SUCCESS_RESULTS: Final = (
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
    VerificationResult.VERIFIER_ERROR,
)
NON_PROMOTE: Final = (DecisionType.ESCALATE, DecisionType.REJECT, DecisionType.RETRY)
MAX_ATTEMPTS_LIMIT: Final = 10


# Only ``committed`` and ``with_new_state`` (and ``from_dict``, which rebuilds what they stored) may
# put a state id into a decision or its evidence (DATA-INT-004): the commit of P6b is the one place
# that does. The token is private to this module (R9).
_COMMIT_TOKEN: Final = object()


class ConflictingDuplicateError(DomainValidationError):
    """A ``decision_id`` was submitted again with different content (C-163, Doc 09 §38)."""


class PromotionInputError(DomainValidationError):
    """The arguments of ``decide`` are malformed (wrong types, another lineage, ...). A finding of
    the decision itself is never an error: it is a REJECT, RETRY or ESCALATE (C-157)."""


class DecisionReason(StrEnum):
    """Why a decision was taken: one closed code per reason (C-157, C-158)."""

    STALE_PARENT = "STALE_PARENT"
    STRUCTURAL_FAILURE = "STRUCTURAL_FAILURE"
    INCONSISTENT_REPORTS = "INCONSISTENT_REPORTS"
    REQUIRED_CHECK_FAILED = "REQUIRED_CHECK_FAILED"
    REQUIRED_UNKNOWN = "REQUIRED_UNKNOWN"
    REQUIRED_UNSUPPORTED = "REQUIRED_UNSUPPORTED"
    VERIFIER_ERROR = "VERIFIER_ERROR"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EVIDENCE_NOT_SUFFICIENT = "EVIDENCE_NOT_SUFFICIENT"
    EVIDENCE_STALE = "EVIDENCE_STALE"
    EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"
    RETRY_BUDGET_EXHAUSTED = "RETRY_BUDGET_EXHAUSTED"
    POLICY_REGISTRY_REGRESSION = "POLICY_REGISTRY_REGRESSION"
    AUTOMATIC_PROMOTION_DISABLED = "AUTOMATIC_PROMOTION_DISABLED"
    DECISION_INCOMPLETE = "DECISION_INCOMPLETE"
    ALL_REQUIRED_PROVEN = "ALL_REQUIRED_PROVEN"


class ProofSource(StrEnum):
    """What proves a required invariant (C-159): a fresh verification, or the parent's reference."""

    VERIFIED = "VERIFIED"
    CARRIED_FORWARD = "CARRIED_FORWARD"


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise DomainValidationError(f"{name}: must be a boolean")
    return value


def _texts(value: object, name: str, *, allowed: frozenset[str] | None = None) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise DomainValidationError(f"{name}: must be a list of texts")
    items = tuple(require_text(item, f"{name}[]") for item in value)
    if len(set(items)) != len(items):
        raise DomainValidationError(f"{name}: duplicate entry")
    if allowed is not None and not set(items) <= allowed:
        raise DomainValidationError(f"{name}: names something that is not defined")
    return tuple(sorted(items))


def _uuids(value: object, name: str) -> tuple[str, ...]:
    """A strictly sorted tuple of canonical UUIDs."""
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise DomainValidationError(f"{name}: must be a list of UUIDs")
    items = tuple(require_uuid(item, f"{name}[]") for item in value)
    if list(items) != sorted(set(items)):
        raise DomainValidationError(f"{name}: must be sorted and without duplicates")
    return items


def _objects[T](value: object, kind: type[T], name: str) -> tuple[T, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise DomainValidationError(f"{name}: must be a list")
    items = tuple(value)
    if not all(isinstance(item, kind) for item in items):
        raise DomainValidationError(f"{name}: must hold {kind.__name__} objects")
    return items


def _list_of(value: object, name: str) -> list[Any]:
    if not isinstance(value, list | tuple):
        raise DomainValidationError(f"{name}: must be a list")
    return list(value)


# --- required checks and blocking conditions ------------------------------------------------------


@dataclass(frozen=True)
class RequiredCheck:
    """One thing the decision required, and what proved it (C-159).

    ``source`` is None when nothing proved it. A VERIFIED check names the verification result that
    did (``verification_id``); a CARRIED_FORWARD one (invariants only) names none: its evidence is
    the parent reference's, listed in the ``ProofPlanEntry``.
    """

    target_id: str
    kind: str
    source: ProofSource | None
    verification_id: str | None

    def __post_init__(self) -> None:
        require_text(self.target_id, "RequiredCheck.target_id")
        if self.kind not in CHECK_KINDS:
            raise DomainValidationError(f"RequiredCheck.kind: must be one of {CHECK_KINDS}")
        if self.source is not None:
            require_enum(self.source, ProofSource, "RequiredCheck.source")
        if (self.source is ProofSource.VERIFIED) != (self.verification_id is not None):
            raise DomainValidationError(
                "RequiredCheck: a VERIFIED check names its result, and only a VERIFIED one does"
            )
        if self.verification_id is not None:
            require_uuid(self.verification_id, "RequiredCheck.verification_id")
        if self.source is ProofSource.CARRIED_FORWARD and self.kind != "INVARIANT":
            raise DomainValidationError("RequiredCheck: only an invariant can be carried forward")

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "kind": self.kind,
            "source": None if self.source is None else self.source.value,
            "verification_id": self.verification_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RequiredCheck:
        fields = require_keys(data, ("target_id", "kind", "source", "verification_id"), "check")
        source = fields["source"]
        return cls(
            target_id=fields["target_id"],
            kind=fields["kind"],
            source=None if source is None else parse_enum(source, ProofSource, "check.source"),
            verification_id=fields["verification_id"],
        )


@dataclass(frozen=True)
class BlockingCondition:
    """One reason a decision is not a PROMOTE. ``decision`` is the class of the condition: what
    this condition alone would give (REJECT, RETRY or ESCALATE, never PROMOTE)."""

    code: DecisionReason
    decision: DecisionType
    target: str
    detail: str

    def __post_init__(self) -> None:
        require_enum(self.code, DecisionReason, "BlockingCondition.code")
        require_enum(self.decision, DecisionType, "BlockingCondition.decision")
        if self.decision not in NON_PROMOTE:
            raise DomainValidationError("BlockingCondition: a blocking condition is not a PROMOTE")
        if self.code is DecisionReason.ALL_REQUIRED_PROVEN:
            raise DomainValidationError("BlockingCondition: ALL_REQUIRED_PROVEN blocks nothing")
        require_text(self.target, "BlockingCondition.target")
        require_text(self.detail, "BlockingCondition.detail")

    def sort_key(self) -> tuple[str, str, str, str]:
        return (self.code.value, self.target, self.detail, self.decision.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "decision": self.decision.value,
            "target": self.target,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BlockingCondition:
        fields = require_keys(data, ("code", "decision", "target", "detail"), "blocking condition")
        return cls(
            code=parse_enum(fields["code"], DecisionReason, "condition.code"),
            decision=parse_enum(fields["decision"], DecisionType, "condition.decision"),
            target=fields["target"],
            detail=fields["detail"],
        )


def _checks(value: object) -> tuple[RequiredCheck, ...]:
    checks = _objects(value, RequiredCheck, "required_checks")
    keys = [check.target_id for check in checks]
    if keys != sorted(set(keys)):
        raise DomainValidationError(
            "required_checks: must be sorted by target, one check per target"
        )
    return checks


# --- the decision ---------------------------------------------------------------------------------


_DECISION_KEYS = (
    "decision_id",
    "candidate_id",
    "parent_state_id",
    "decision",
    "reason",
    "policy_version",
    "attempt_number",
    "required_checks",
    "blocking_conditions",
    "supporting_results",
    "created_at",
    "committed_state_id",
    "content_hash",
)


@dataclass(frozen=True)
class PromotionDecision:
    """The decision of the Promotion Controller about one candidate (Doc 05 §15).

    Beyond the fields of Doc 05 §15 it records the ``reason`` (the highest-severity blocking
    condition, or ALL_REQUIRED_PROVEN) and the ``attempt_number`` (C-157). Create it with
    ``create``; the constructor recomputes ``content_hash``, which excludes the id and the clock.
    """

    decision_id: str
    candidate_id: str
    parent_state_id: str
    decision: DecisionType
    reason: DecisionReason
    policy_version: str
    attempt_number: int
    required_checks: tuple[RequiredCheck, ...]
    blocking_conditions: tuple[BlockingCondition, ...]
    supporting_results: tuple[str, ...]
    created_at: datetime
    committed_state_id: str | None
    content_hash: str
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        name = "PromotionDecision"
        require_uuid(self.decision_id, f"{name}.decision_id")
        require_uuid(self.candidate_id, f"{name}.candidate_id")
        require_uuid(self.parent_state_id, f"{name}.parent_state_id")
        require_enum(self.decision, DecisionType, f"{name}.decision")
        require_enum(self.reason, DecisionReason, f"{name}.reason")
        require_text(self.policy_version, f"{name}.policy_version")
        require_int(self.attempt_number, f"{name}.attempt_number", 1)
        if self.committed_state_id is not None:
            if _token is not _COMMIT_TOKEN:
                raise UnauthorizedConstructionError(
                    f"{name}.committed_state_id: only PromotionDecision.committed sets it, at the "
                    "commit (DATA-INT-004)"
                )
            if self.decision is not DecisionType.PROMOTE:
                raise DomainValidationError(
                    f"{name}.committed_state_id: only a committed PROMOTE names a state "
                    "(DATA-INT-004)"
                )
            require_uuid(self.committed_state_id, f"{name}.committed_state_id")
        object.__setattr__(self, "created_at", utc(self.created_at, f"{name}.created_at"))
        checks = _checks(self.required_checks)
        conditions = _objects(self.blocking_conditions, BlockingCondition, "blocking_conditions")
        if [c.sort_key() for c in conditions] != sorted({c.sort_key() for c in conditions}):
            raise DomainValidationError(
                f"{name}.blocking_conditions: must be sorted and without duplicates"
            )
        results = _uuids(self.supporting_results, f"{name}.supporting_results")
        self._check_decision(conditions, results)
        object.__setattr__(self, "required_checks", checks)
        object.__setattr__(self, "blocking_conditions", conditions)
        object.__setattr__(self, "supporting_results", results)
        if self.content_hash != self.compute_hash():
            raise HashMismatchError(
                f"DATA-INT-010: PromotionDecision {self.decision_id} content_hash does not "
                "match its content"
            )

    def _check_decision(
        self, conditions: tuple[BlockingCondition, ...], results: tuple[str, ...]
    ) -> None:
        name = "PromotionDecision"
        if self.decision is DecisionType.PROMOTE:
            if self.reason is not DecisionReason.ALL_REQUIRED_PROVEN or conditions:
                raise DomainValidationError(
                    f"{name}: a PROMOTE is ALL_REQUIRED_PROVEN and has no blocking condition"
                )
            if not results:
                raise DomainValidationError(
                    f"{name}: a PROMOTE must reference the evidence that satisfied the policy "
                    "(Doc 05 §15)"
                )
            return
        if self.reason is DecisionReason.ALL_REQUIRED_PROVEN:
            raise DomainValidationError(f"{name}: only a PROMOTE has everything proven")
        if not conditions:
            raise DomainValidationError(
                f"{name}: a {self.decision.value} must preserve its blocking reasons (Doc 05 §15)"
            )
        if self.reason not in {c.code for c in conditions}:
            raise DomainValidationError(f"{name}: the reason is not among the blocking conditions")

    def _payload(self) -> dict[str, Any]:
        data = self.to_dict()
        for key in ("decision_id", "created_at", "content_hash"):
            del data[key]
        return data

    def compute_hash(self) -> str:
        return content_hash(self._payload())

    def committed(self, state_id: str) -> PromotionDecision:
        """The same PROMOTE once it is committed to ``state_id`` (DATA-INT-004). Returned as a new
        object with its hash recomputed; allowed once, and only for a PROMOTE."""
        if self.decision is not DecisionType.PROMOTE or self.committed_state_id is not None:
            raise DomainValidationError(
                "PromotionDecision.committed: only a PROMOTE that is not yet committed can be "
                "committed (DATA-INT-004)"
            )
        require_uuid(state_id, "PromotionDecision.committed.state_id")
        digest = content_hash({**self._payload(), "committed_state_id": state_id})
        return dataclasses.replace(
            self, committed_state_id=state_id, content_hash=digest, _token=_COMMIT_TOKEN
        )

    @classmethod
    def create(
        cls,
        *,
        decision_id: str,
        candidate_id: str,
        parent_state_id: str,
        decision: DecisionType,
        reason: DecisionReason,
        policy_version: str,
        attempt_number: int,
        required_checks: Iterable[RequiredCheck],
        blocking_conditions: Iterable[BlockingCondition],
        supporting_results: Iterable[str],
        created_at: datetime,
    ) -> PromotionDecision:
        """Build the decision and its hash (the constructor then checks both)."""
        probe = {
            "candidate_id": candidate_id,
            "parent_state_id": parent_state_id,
            "decision": getattr(decision, "value", decision),
            "reason": getattr(reason, "value", reason),
            "policy_version": policy_version,
            "attempt_number": attempt_number,
            "required_checks": [c.to_dict() for c in required_checks],
            "blocking_conditions": [c.to_dict() for c in blocking_conditions],
            "supporting_results": list(supporting_results),
            "committed_state_id": None,
        }
        return cls(
            decision_id=decision_id,
            candidate_id=candidate_id,
            parent_state_id=parent_state_id,
            decision=decision,
            reason=reason,
            policy_version=policy_version,
            attempt_number=attempt_number,
            required_checks=tuple(required_checks),
            blocking_conditions=tuple(blocking_conditions),
            supporting_results=tuple(supporting_results),
            created_at=created_at,
            committed_state_id=None,
            content_hash=content_hash(probe),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "candidate_id": self.candidate_id,
            "parent_state_id": self.parent_state_id,
            "decision": self.decision.value,
            "reason": self.reason.value,
            "policy_version": self.policy_version,
            "attempt_number": self.attempt_number,
            "required_checks": [c.to_dict() for c in self.required_checks],
            "blocking_conditions": [c.to_dict() for c in self.blocking_conditions],
            "supporting_results": list(self.supporting_results),
            "created_at": iso_utc(self.created_at),
            "committed_state_id": self.committed_state_id,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PromotionDecision:
        fields = require_keys(data, _DECISION_KEYS, "PromotionDecision")
        return cls(
            decision_id=fields["decision_id"],
            candidate_id=fields["candidate_id"],
            parent_state_id=fields["parent_state_id"],
            decision=parse_enum(fields["decision"], DecisionType, "decision"),
            reason=parse_enum(fields["reason"], DecisionReason, "reason"),
            policy_version=fields["policy_version"],
            attempt_number=fields["attempt_number"],
            required_checks=tuple(
                RequiredCheck.from_dict(item)
                for item in _list_of(fields["required_checks"], "required_checks")
            ),
            blocking_conditions=tuple(
                BlockingCondition.from_dict(item)
                for item in _list_of(fields["blocking_conditions"], "blocking_conditions")
            ),
            supporting_results=tuple(_list_of(fields["supporting_results"], "supporting_results")),
            created_at=parse_utc(fields["created_at"], "PromotionDecision.created_at"),
            committed_state_id=fields["committed_state_id"],
            content_hash=fields["content_hash"],
            _token=_COMMIT_TOKEN,
        )


# --- the evidence of a decision -------------------------------------------------------------------


_EVIDENCE_KEYS = (
    "decision_id",
    "candidate_id",
    "parent_state_id",
    "required_checks",
    "verification_refs",
    "evidence_sufficiency",
    "policy_version",
    "decision",
    "reason",
    "new_state_id",
    "content_hash",
)


@dataclass(frozen=True)
class PromotionEvidence:
    """What a decision rests on (Doc 11 §26). A PROMOTE references every mandatory verification
    result used; ``new_state_id`` stays null until P6b creates the state."""

    decision_id: str
    candidate_id: str
    parent_state_id: str
    required_checks: tuple[RequiredCheck, ...]
    verification_refs: tuple[str, ...]
    evidence_sufficiency: str
    policy_version: str
    decision: DecisionType
    reason: DecisionReason
    new_state_id: str | None
    content_hash: str
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        name = "PromotionEvidence"
        require_uuid(self.decision_id, f"{name}.decision_id")
        require_uuid(self.candidate_id, f"{name}.candidate_id")
        require_uuid(self.parent_state_id, f"{name}.parent_state_id")
        require_text(self.policy_version, f"{name}.policy_version")
        require_enum(self.decision, DecisionType, f"{name}.decision")
        require_enum(self.reason, DecisionReason, f"{name}.reason")
        if self.evidence_sufficiency not in SUFFICIENCY_VALUES:
            raise DomainValidationError(
                f"{name}.evidence_sufficiency: must be one of {SUFFICIENCY_VALUES}"
            )
        if self.new_state_id is not None:
            if _token is not _COMMIT_TOKEN:
                raise UnauthorizedConstructionError(
                    f"{name}.new_state_id: only PromotionEvidence.with_new_state sets it, at the "
                    "commit (DATA-INT-004)"
                )
            if self.decision is not DecisionType.PROMOTE:
                raise DomainValidationError(
                    f"{name}.new_state_id: only a PROMOTE names a new state (DATA-INT-004)"
                )
            require_uuid(self.new_state_id, f"{name}.new_state_id")
        checks = _checks(self.required_checks)
        refs = _uuids(self.verification_refs, f"{name}.verification_refs")
        if self.decision is DecisionType.PROMOTE and (
            not refs or self.evidence_sufficiency != "SUFFICIENT"
        ):
            raise DomainValidationError(
                f"{name}: a PROMOTE references every result it used and its evidence is "
                "SUFFICIENT (Doc 11 §26)"
            )
        object.__setattr__(self, "required_checks", checks)
        object.__setattr__(self, "verification_refs", refs)
        if self.content_hash != self.compute_hash():
            raise HashMismatchError(
                f"DATA-INT-010: PromotionEvidence of decision {self.decision_id} content_hash "
                "does not match its content"
            )

    def _payload(self) -> dict[str, Any]:
        data = self.to_dict()
        del data["decision_id"]
        del data["content_hash"]
        return data

    def compute_hash(self) -> str:
        return content_hash(self._payload())

    def with_new_state(self, state_id: str) -> PromotionEvidence:
        """The same evidence once the state exists (DATA-INT-004); allowed once, for a PROMOTE."""
        if self.decision is not DecisionType.PROMOTE or self.new_state_id is not None:
            raise DomainValidationError(
                "PromotionEvidence.with_new_state: only the evidence of a PROMOTE that names no "
                "state yet can name one (DATA-INT-004)"
            )
        require_uuid(state_id, "PromotionEvidence.with_new_state.state_id")
        digest = content_hash({**self._payload(), "new_state_id": state_id})
        return dataclasses.replace(
            self, new_state_id=state_id, content_hash=digest, _token=_COMMIT_TOKEN
        )

    @classmethod
    def create(
        cls,
        *,
        decision_id: str,
        candidate_id: str,
        parent_state_id: str,
        required_checks: Iterable[RequiredCheck],
        verification_refs: Iterable[str],
        evidence_sufficiency: str,
        policy_version: str,
        decision: DecisionType,
        reason: DecisionReason,
    ) -> PromotionEvidence:
        probe = {
            "candidate_id": candidate_id,
            "parent_state_id": parent_state_id,
            "required_checks": [c.to_dict() for c in required_checks],
            "verification_refs": list(verification_refs),
            "evidence_sufficiency": evidence_sufficiency,
            "policy_version": policy_version,
            "decision": getattr(decision, "value", decision),
            "reason": getattr(reason, "value", reason),
            "new_state_id": None,
        }
        return cls(
            decision_id=decision_id,
            candidate_id=candidate_id,
            parent_state_id=parent_state_id,
            required_checks=tuple(required_checks),
            verification_refs=tuple(verification_refs),
            evidence_sufficiency=evidence_sufficiency,
            policy_version=policy_version,
            decision=decision,
            reason=reason,
            new_state_id=None,
            content_hash=content_hash(probe),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "candidate_id": self.candidate_id,
            "parent_state_id": self.parent_state_id,
            "required_checks": [c.to_dict() for c in self.required_checks],
            "verification_refs": list(self.verification_refs),
            "evidence_sufficiency": self.evidence_sufficiency,
            "policy_version": self.policy_version,
            "decision": self.decision.value,
            "reason": self.reason.value,
            "new_state_id": self.new_state_id,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PromotionEvidence:
        fields = require_keys(data, _EVIDENCE_KEYS, "PromotionEvidence")
        return cls(
            decision_id=fields["decision_id"],
            candidate_id=fields["candidate_id"],
            parent_state_id=fields["parent_state_id"],
            required_checks=tuple(
                RequiredCheck.from_dict(item)
                for item in _list_of(fields["required_checks"], "required_checks")
            ),
            verification_refs=tuple(_list_of(fields["verification_refs"], "verification_refs")),
            evidence_sufficiency=fields["evidence_sufficiency"],
            policy_version=fields["policy_version"],
            decision=parse_enum(fields["decision"], DecisionType, "decision"),
            reason=parse_enum(fields["reason"], DecisionReason, "reason"),
            new_state_id=fields["new_state_id"],
            content_hash=fields["content_hash"],
            _token=_COMMIT_TOKEN,
        )


# --- the plan, the outcome and the oracle's verdict -----------------------------------------------


@dataclass(frozen=True)
class ProofPlanEntry:
    """Which source proves one required invariant (C-159), for the commit of P6b.

    VERIFIED: ``verification_id`` is the result that proves it. CARRIED_FORWARD: ``source_state_id``
    is the state whose reference is copied and ``evidence_ids`` are that reference's evidence."""

    invariant_id: str
    invariant_version: int
    source: ProofSource
    verification_id: str | None
    source_state_id: str | None
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text(self.invariant_id, "ProofPlanEntry.invariant_id")
        require_int(self.invariant_version, "ProofPlanEntry.invariant_version", 1)
        require_enum(self.source, ProofSource, "ProofPlanEntry.source")
        verified = self.source is ProofSource.VERIFIED
        if (self.verification_id is not None) != verified:
            raise DomainValidationError(
                "ProofPlanEntry: a VERIFIED entry names its result, a carried one does not"
            )
        if (self.source_state_id is not None) == verified:
            raise DomainValidationError(
                "ProofPlanEntry: a carried entry names its source state, a verified one does not"
            )
        if self.verification_id is not None:
            require_uuid(self.verification_id, "ProofPlanEntry.verification_id")
        if self.source_state_id is not None:
            require_uuid(self.source_state_id, "ProofPlanEntry.source_state_id")
        object.__setattr__(
            self,
            "evidence_ids",
            tuple(require_uuid(e, "ProofPlanEntry.evidence_ids[]") for e in self.evidence_ids),
        )

    @property
    def target_id(self) -> str:
        return f"INVARIANT:{self.invariant_id}:{self.invariant_version}"


@dataclass(frozen=True)
class DecisionOutcome:
    """What ``decide`` returns: the decision, the proof plan and the evidence (C-157)."""

    decision: PromotionDecision
    proof_plan: tuple[ProofPlanEntry, ...]
    evidence: PromotionEvidence

    def __post_init__(self) -> None:
        if not isinstance(self.decision, PromotionDecision):
            raise DomainValidationError("DecisionOutcome.decision: expected a PromotionDecision")
        if not isinstance(self.evidence, PromotionEvidence):
            raise DomainValidationError("DecisionOutcome.evidence: expected a PromotionEvidence")
        plan = _objects(self.proof_plan, ProofPlanEntry, "DecisionOutcome.proof_plan")
        if self.evidence.decision_id != self.decision.decision_id:
            raise DomainValidationError("DecisionOutcome: the evidence belongs to another decision")
        object.__setattr__(self, "proof_plan", plan)


@dataclass(frozen=True)
class OracleVerdict:
    """What the independent oracle said about one invariant (Doc 09 §16). Evidence, not proof."""

    invariant_id: str
    invariant_version: int
    result: VerificationResult
    oracle_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.invariant_id, str) or not self.invariant_id.startswith("INV-"):
            raise DomainValidationError("OracleVerdict.invariant_id: must be an INV-... id")
        require_int(self.invariant_version, "OracleVerdict.invariant_version", 1)
        require_enum(self.result, VerificationResult, "OracleVerdict.result")
        require_text(self.oracle_version, "OracleVerdict.oracle_version")


# --- the policy -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class PromotionPolicy:
    """The promotion policy (C-158 to C-161). Frozen data: nothing here reads configuration.

    ``non_success`` is the closed table of Doc 09 §20 (UNKNOWN, UNSUPPORTED, VERIFIER_ERROR to
    REJECT, RETRY or ESCALATE); it never maps to PROMOTE. ``accept_oracle_for_unknown`` exists only
    so that the refusal is explicit: oracle evidence is never proof (C-160). ``gate_verifiers``
    names the verifier each mandatory gate item must come from.
    """

    policy_version: str
    invariant_registry_version: int
    invariants: tuple[Invariant, ...]
    extra_required: tuple[str, ...]
    min_evidence_level: str
    carry_forward_enabled: bool
    non_success: tuple[tuple[VerificationResult, DecisionType], ...]
    transient_errors: tuple[str, ...]
    max_attempts: int
    conflict_decision: DecisionType
    automatic_enabled: bool
    accept_oracle_for_unknown: bool
    gate_verifiers: tuple[tuple[str, str, str], ...]
    _by_id: dict[str, Invariant] = field(
        init=False, repr=False, compare=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        name = "PromotionPolicy"
        require_text(self.policy_version, f"{name}.policy_version")
        require_int(self.invariant_registry_version, f"{name}.invariant_registry_version", 1)
        definitions = _objects(self.invariants, Invariant, f"{name}.invariants")
        by_id = {d.invariant_id: d for d in definitions}
        if not definitions or len(by_id) != len(definitions):
            raise DomainValidationError(
                f"{name}.invariants: one definition per invariant id, at least one (C-41)"
            )
        object.__setattr__(
            self, "invariants", tuple(sorted(definitions, key=lambda d: d.invariant_id))
        )
        object.__setattr__(self, "_by_id", by_id)
        object.__setattr__(
            self,
            "extra_required",
            _texts(self.extra_required, f"{name}.extra_required", allowed=frozenset(by_id)),
        )
        if self.min_evidence_level not in EVIDENCE_LEVELS:
            raise DomainValidationError(
                f"{name}.min_evidence_level: must be one of {EVIDENCE_LEVELS}"
            )
        _bool(self.carry_forward_enabled, f"{name}.carry_forward_enabled")
        _bool(self.automatic_enabled, f"{name}.automatic_enabled")
        if _bool(self.accept_oracle_for_unknown, f"{name}.accept_oracle_for_unknown"):
            raise DomainValidationError(
                f"{name}: oracle evidence is never proof, so accept_oracle_for_unknown must be "
                "False (ADR-010, C-54, C-160)"
            )
        object.__setattr__(self, "non_success", self._table(self.non_success))
        object.__setattr__(
            self, "transient_errors", _texts(self.transient_errors, f"{name}.transient_errors")
        )
        if require_int(self.max_attempts, f"{name}.max_attempts", 1) > MAX_ATTEMPTS_LIMIT:
            raise DomainValidationError(f"{name}.max_attempts: at most {MAX_ATTEMPTS_LIMIT}")
        require_enum(self.conflict_decision, DecisionType, f"{name}.conflict_decision")
        if self.conflict_decision not in (DecisionType.REJECT, DecisionType.ESCALATE):
            raise DomainValidationError(f"{name}.conflict_decision: REJECT or ESCALATE, never else")
        object.__setattr__(self, "gate_verifiers", self._gates(self.gate_verifiers))

    @staticmethod
    def _table(
        value: object,
    ) -> tuple[tuple[VerificationResult, DecisionType], ...]:
        name = "PromotionPolicy.non_success"
        if isinstance(value, str) or not isinstance(value, Iterable):
            raise DomainValidationError(f"{name}: must be a list of pairs")
        pairs = []
        for item in value:
            if not isinstance(item, tuple) or len(item) != 2:
                raise DomainValidationError(f"{name}: must be a list of pairs")
            result = require_enum(item[0], VerificationResult, f"{name} key")
            decision = require_enum(item[1], DecisionType, f"{name} value")
            if decision not in NON_PROMOTE:
                raise DomainValidationError(f"{name}: a non-success never maps to PROMOTE")
            pairs.append((result, decision))
        if sorted(r.value for r, _ in pairs) != sorted(r.value for r in NON_SUCCESS_RESULTS):
            raise DomainValidationError(
                f"{name}: exactly one entry for each of UNKNOWN, UNSUPPORTED, VERIFIER_ERROR"
            )
        return tuple(sorted(pairs, key=lambda pair: pair[0].value))

    @staticmethod
    def _gates(value: object) -> tuple[tuple[str, str, str], ...]:
        name = "PromotionPolicy.gate_verifiers"
        if isinstance(value, str) or not isinstance(value, Iterable):
            raise DomainValidationError(f"{name}: must be a list of triples")
        triples = []
        for item in value:
            if not isinstance(item, tuple) or len(item) != 3:
                raise DomainValidationError(f"{name}: must be a list of triples")
            triples.append(tuple(require_text(part, f"{name}[]") for part in item))
        if sorted(t[0] for t in triples) != sorted(GATE_TARGETS):
            raise DomainValidationError(f"{name}: exactly one verifier for each gate item")
        return tuple(sorted((t[0], t[1], t[2]) for t in triples))

    def definition(self, invariant_id: str) -> Invariant | None:
        """The definition of ``invariant_id`` at the policy's registry version, if it has one."""
        return self._by_id.get(invariant_id)

    def gate_verifier(self, target_id: str) -> tuple[str, str]:
        for target, verifier_id, verifier_version in self.gate_verifiers:
            if target == target_id:
                return verifier_id, verifier_version
        raise DomainValidationError(f"PromotionPolicy: {target_id!r} is not a gate item")

    def non_success_decision(
        self, result: VerificationResult, error_type: str | None = None
    ) -> DecisionType:
        """What a non-success result of a required item gives (C-158). A VERIFIER_ERROR of a
        listed transient type is retried; an unlisted one follows the table."""
        if result not in NON_SUCCESS_RESULTS:
            raise DomainValidationError(f"non_success_decision: {result} is not a non-success")
        if result is VerificationResult.VERIFIER_ERROR and error_type in self.transient_errors:
            return DecisionType.RETRY
        return dict(self.non_success)[result]
