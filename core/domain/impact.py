"""Impact reports (Doc 08 §23-§27, §31-§32; C-138; P4 step 3).

Doc 08 §3: impact decides what must be checked again, never what is true.

    AFFECTED != VIOLATED     AFFECTED != UNKNOWN
    NO EDGE != NO DEPENDENCY NO PRIOR EVIDENCE != PASS

An ``ImpactReport`` says, per protected invariant, whether it is AFFECTED or UNCERTAIN (one
``ImpactedInvariant`` with its reasons, paths and invalidated evidence) or unaffected (an
``UnaffectedInvariant`` that says whether carrying prior evidence forward is eligible), and lists
the verification work the candidate owes. Names follow Doc 08 §23-§25; where Doc 05 differs,
Doc 08 wins.

Vocabularies are closed (C-138): ``ReasonCode`` has one member per reason, split into the codes that
make an invariant AFFECTED, the codes that make it UNCERTAIN and the codes of an unaffected
record. Priority is part of the work item, but it never decides whether a check is mandatory
(Doc 08 §26).

The ``content_hash`` covers everything except ``report_id`` and ``created_at``; the constructor
recomputes it (``HashMismatchError``) and checks every derived part and every ordering, so a report
that was edited after the fact cannot be built. ``carry_forward_ok`` is the single query P6 needs
(C-141): it is true only for an eligible unaffected invariant of this exact candidate and parent.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from core.domain.enums import ChangeType, DependencyStatus, ImpactStatus
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.evidence import EvidenceValidity
from core.domain.graph import Relationship
from core.domain.hashing import content_hash
from core.domain.ids import new_uuid, require_uuid
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

IMPACT_ALGORITHM_VERSION: Final = "dail-impact-1"

_HASH_TEXT = re.compile(r"[0-9a-f]{64}")


class ImpactType(StrEnum):
    """Doc 08 §24. A record holds the set of types that apply (Doc 08 §31 merges them)."""

    DIRECT = "DIRECT"
    DEPENDENCY = "DEPENDENCY"
    IDENTITY = "IDENTITY"
    UNCERTAINTY = "UNCERTAINTY"
    BASELINE = "BASELINE"


class ReasonCode(StrEnum):
    """The closed vocabulary of impact reasons (C-138). A new code needs a register row."""

    SCOPE_RESOURCE_CHANGED = "SCOPE_RESOURCE_CHANGED"
    SCOPE_TYPE_CHANGED = "SCOPE_TYPE_CHANGED"
    FOOTPRINT_MEMBER_CHANGED = "FOOTPRINT_MEMBER_CHANGED"
    CREATED_IN_SCOPE = "CREATED_IN_SCOPE"
    DELETED_IN_SCOPE = "DELETED_IN_SCOPE"
    REPLACED_IN_SCOPE = "REPLACED_IN_SCOPE"
    IDENTITY_UNCERTAIN = "IDENTITY_UNCERTAIN"
    UNRESOLVED_CONTENT = "UNRESOLVED_CONTENT"
    WALK_INCOMPLETE = "WALK_INCOMPLETE"
    ENDPOINT_ABSENT = "ENDPOINT_ABSENT"
    CREATED_BASELINE = "CREATED_BASELINE"
    NO_CHANGE_IN_FOOTPRINT = "NO_CHANGE_IN_FOOTPRINT"
    NO_PRIOR_EVIDENCE = "NO_PRIOR_EVIDENCE"
    INVARIANT_VERSION_CHANGED = "INVARIANT_VERSION_CHANGED"
    VERIFIER_CHANGED = "VERIFIER_CHANGED"


AFFECTED_CODES: Final = frozenset(
    {
        ReasonCode.SCOPE_RESOURCE_CHANGED,
        ReasonCode.SCOPE_TYPE_CHANGED,
        ReasonCode.FOOTPRINT_MEMBER_CHANGED,
        ReasonCode.CREATED_IN_SCOPE,
        ReasonCode.DELETED_IN_SCOPE,
        ReasonCode.REPLACED_IN_SCOPE,
    }
)
UNCERTAIN_CODES: Final = frozenset(
    {
        ReasonCode.IDENTITY_UNCERTAIN,
        ReasonCode.UNRESOLVED_CONTENT,
        ReasonCode.WALK_INCOMPLETE,
        ReasonCode.ENDPOINT_ABSENT,
    }
)
UNCERTAINTY_CODES: Final = frozenset(
    {ReasonCode.UNRESOLVED_CONTENT, ReasonCode.WALK_INCOMPLETE, ReasonCode.ENDPOINT_ABSENT}
)
UNAFFECTED_CODES: Final = frozenset(
    {
        ReasonCode.NO_CHANGE_IN_FOOTPRINT,
        ReasonCode.NO_PRIOR_EVIDENCE,
        ReasonCode.INVARIANT_VERSION_CHANGED,
        ReasonCode.VERIFIER_CHANGED,
    }
)

REASON_DEFINITIONS: Final[Mapping[ReasonCode, str]] = MappingProxyType(
    {
        ReasonCode.SCOPE_RESOURCE_CHANGED: "A resource named by the invariant scope is modified.",
        ReasonCode.SCOPE_TYPE_CHANGED: "A resource of a scoped type is modified.",
        ReasonCode.FOOTPRINT_MEMBER_CHANGED: "A resource the footprint walk reaches is modified.",
        ReasonCode.CREATED_IN_SCOPE: "A resource in the footprint is created (baseline work).",
        ReasonCode.DELETED_IN_SCOPE: "A resource in the footprint is deleted.",
        ReasonCode.REPLACED_IN_SCOPE: "A resource in the footprint is replaced.",
        ReasonCode.IDENTITY_UNCERTAIN: "A resource in the footprint has an uncertain identity.",
        ReasonCode.UNRESOLVED_CONTENT: (
            "A footprint resource has unresolved content, so equal fingerprints prove nothing "
            "(registry 2.9, C-117)."
        ),
        ReasonCode.WALK_INCOMPLETE: (
            "The footprint is not fully known and a resource of a walkable type changed."
        ),
        ReasonCode.ENDPOINT_ABSENT: "A scope endpoint is absent from a state.",
        ReasonCode.CREATED_BASELINE: "A created resource owes baseline verification.",
        ReasonCode.NO_CHANGE_IN_FOOTPRINT: "No change reaches the footprint; proof may carry.",
        ReasonCode.NO_PRIOR_EVIDENCE: "No prior proof exists to carry forward.",
        ReasonCode.INVARIANT_VERSION_CHANGED: "Only a proof of another invariant version exists.",
        ReasonCode.VERIFIER_CHANGED: "The prior proof was made by another verifier or version.",
    }
)


class WorkPriority(StrEnum):
    """Doc 08 §26. Priority never changes whether a required invariant is mandatory."""

    BLOCKING = "BLOCKING"
    HIGH = "HIGH"
    NORMAL = "NORMAL"
    ADVISORY = "ADVISORY"


class WorkTargetType(StrEnum):
    INVARIANT = "INVARIANT"
    RESOURCE = "RESOURCE"


class StepDirection(StrEnum):
    """FORWARD: a step goes from the edge's source to its target; REVERSE: the other way."""

    FORWARD = "FORWARD"
    REVERSE = "REVERSE"


class ChangeFlag(StrEnum):
    """Flags of a changed resource, from the identity evidence (C-117, C-122)."""

    UNRESOLVED_CONTENT = "UNRESOLVED_CONTENT"
    UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"


# --- helpers --------------------------------------------------------------------------------------


def _text_list(
    value: object, field: str, *, sort: bool = True, empty_ok: bool = True
) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, list | tuple):
        raise DomainValidationError(f"{field}: must be a list of text")
    items = tuple(require_text(item, f"{field}[{i}]") for i, item in enumerate(value))
    if not empty_ok and not items:
        raise DomainValidationError(f"{field}: must not be empty")
    if sort and list(items) != sorted(set(items)):
        raise DomainValidationError(f"{field}: must be sorted and free of duplicates (Doc 08 §32)")
    return items


def _objects[T](value: object, kind: type[T], field: str) -> tuple[T, ...]:
    if isinstance(value, str) or not isinstance(value, list | tuple):
        raise DomainValidationError(f"{field}: must be a list")
    if not all(isinstance(item, kind) for item in value):
        raise DomainValidationError(f"{field}: must hold {kind.__name__} objects")
    return tuple(value)


def _sorted_unique[T](items: tuple[T, ...], key: Callable[[T], Any], field: str) -> None:
    keys = [key(item) for item in items]
    if keys != sorted(keys):
        raise DomainValidationError(f"{field}: must be sorted (Doc 08 §32)")
    if len(keys) != len(set(map(repr, keys))):
        raise DomainValidationError(f"{field}: duplicate entry")


def _hash_text(value: object, field: str) -> str:
    text = require_text(value, field)
    if _HASH_TEXT.fullmatch(text) is None:
        raise DomainValidationError(f"{field}: must be a SHA-256 hex digest")
    return text


def _list_of(value: object, field: str) -> list[Any]:
    if not isinstance(value, list | tuple):
        raise DomainValidationError(f"{field}: must be a list")
    return list(value)


# --- changed resources ----------------------------------------------------------------------------


@dataclass(frozen=True)
class ChangedResource:
    """A resource that is a change source (Doc 08 §6): any change but UNCHANGED, or an UNCHANGED
    resource with unresolved content, which is carried as UNCERTAIN with the flag (C-117)."""

    address: str
    trusted_ref: str | None
    candidate_ref: str | None
    resource_type: str
    change_type: ChangeType
    flags: tuple[ChangeFlag, ...]

    def __post_init__(self) -> None:
        require_text(self.address, "ChangedResource.address")
        require_text(self.resource_type, "ChangedResource.resource_type")
        for name in ("trusted_ref", "candidate_ref"):
            value = getattr(self, name)
            if value is not None:
                require_text(value, f"ChangedResource.{name}")
        if self.trusted_ref is None and self.candidate_ref is None:
            raise DomainValidationError("ChangedResource: at least one ref is required")
        if self.address != (self.candidate_ref or self.trusted_ref):
            raise DomainValidationError(
                "ChangedResource.address: must be the candidate ref, else the trusted ref"
            )
        require_enum(self.change_type, ChangeType, "ChangedResource.change_type")
        if self.change_type is ChangeType.UNCHANGED:
            raise DomainValidationError("ChangedResource: UNCHANGED is not a change")
        if self.change_type is ChangeType.CREATED and self.trusted_ref is not None:
            raise DomainValidationError("ChangedResource: a CREATED resource has no trusted ref")
        if self.change_type is ChangeType.DELETED and self.candidate_ref is not None:
            raise DomainValidationError("ChangedResource: a DELETED resource has no candidate ref")
        flags = tuple(require_enum(f, ChangeFlag, "ChangedResource.flags") for f in self.flags)
        if list(flags) != sorted(set(flags)):
            raise DomainValidationError("ChangedResource.flags: must be sorted and unique")
        object.__setattr__(self, "flags", flags)

    def refs(self) -> tuple[str, ...]:
        return tuple(r for r in (self.trusted_ref, self.candidate_ref) if r is not None)

    def sort_key(self) -> tuple[str, str, str]:
        return (self.address, self.trusted_ref or "", self.candidate_ref or "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "trusted_ref": self.trusted_ref,
            "candidate_ref": self.candidate_ref,
            "resource_type": self.resource_type,
            "change_type": self.change_type.value,
            "flags": [f.value for f in self.flags],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ChangedResource:
        fields = require_keys(
            data,
            ("address", "trusted_ref", "candidate_ref", "resource_type", "change_type", "flags"),
            "ChangedResource",
        )
        return cls(
            address=fields["address"],
            trusted_ref=fields["trusted_ref"],
            candidate_ref=fields["candidate_ref"],
            resource_type=fields["resource_type"],
            change_type=parse_enum(
                fields["change_type"], ChangeType, "ChangedResource.change_type"
            ),
            flags=tuple(
                parse_enum(f, ChangeFlag, "ChangedResource.flags")
                for f in _list_of(fields["flags"], "ChangedResource.flags")
            ),
        )


# --- paths and reasons ----------------------------------------------------------------------------


@dataclass(frozen=True)
class ImpactStep:
    """One edge of a dependency path, from the changed resource towards the scope seed."""

    edge_key: str
    from_node: str
    to_node: str
    relationship: Relationship
    direction: StepDirection
    status: DependencyStatus

    def __post_init__(self) -> None:
        _hash_text(self.edge_key, "ImpactStep.edge_key")
        require_text(self.from_node, "ImpactStep.from_node")
        require_text(self.to_node, "ImpactStep.to_node")
        require_enum(self.relationship, Relationship, "ImpactStep.relationship")
        require_enum(self.direction, StepDirection, "ImpactStep.direction")
        require_enum(self.status, DependencyStatus, "ImpactStep.status")

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_key": self.edge_key,
            "from_node": self.from_node,
            "to_node": self.to_node,
            "relationship": self.relationship.value,
            "direction": self.direction.value,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ImpactStep:
        fields = require_keys(
            data,
            ("edge_key", "from_node", "to_node", "relationship", "direction", "status"),
            "ImpactStep",
        )
        return cls(
            edge_key=fields["edge_key"],
            from_node=fields["from_node"],
            to_node=fields["to_node"],
            relationship=parse_enum(
                fields["relationship"], Relationship, "ImpactStep.relationship"
            ),
            direction=parse_enum(fields["direction"], StepDirection, "ImpactStep.direction"),
            status=parse_enum(fields["status"], DependencyStatus, "ImpactStep.status"),
        )


@dataclass(frozen=True)
class ImpactPath:
    """How a changed resource reaches the scope of an invariant (empty steps: it is a seed)."""

    changed_ref: str
    steps: tuple[ImpactStep, ...]

    def __post_init__(self) -> None:
        require_text(self.changed_ref, "ImpactPath.changed_ref")
        steps = _objects(self.steps, ImpactStep, "ImpactPath.steps")
        for first, second in zip(steps, steps[1:], strict=False):
            if first.to_node != second.from_node:
                raise DomainValidationError("ImpactPath.steps: the steps do not form a chain")
        object.__setattr__(self, "steps", steps)

    def sort_key(self) -> tuple[str, int, tuple[str, ...]]:
        return (self.changed_ref, len(self.steps), tuple(s.edge_key for s in self.steps))

    def to_dict(self) -> dict[str, Any]:
        return {"changed_ref": self.changed_ref, "steps": [s.to_dict() for s in self.steps]}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ImpactPath:
        fields = require_keys(data, ("changed_ref", "steps"), "ImpactPath")
        return cls(
            changed_ref=fields["changed_ref"],
            steps=tuple(
                ImpactStep.from_dict(s) for s in _list_of(fields["steps"], "ImpactPath.steps")
            ),
        )


@dataclass(frozen=True)
class ImpactReason:
    """One reason an invariant is impacted. ``changed_ref`` is null for a reason about the walk."""

    code: ReasonCode
    changed_ref: str | None
    scope_element: str
    detail: str

    def __post_init__(self) -> None:
        require_enum(self.code, ReasonCode, "ImpactReason.code")
        if self.code not in AFFECTED_CODES | UNCERTAIN_CODES:
            raise DomainValidationError(f"ImpactReason: {self.code.value} is not an impact reason")
        if self.changed_ref is not None:
            require_text(self.changed_ref, "ImpactReason.changed_ref")
        require_text(self.scope_element, "ImpactReason.scope_element")
        require_text(self.detail, "ImpactReason.detail")

    def sort_key(self) -> tuple[str, str, str, str]:
        return (self.code.value, self.changed_ref or "", self.scope_element, self.detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "changed_ref": self.changed_ref,
            "scope_element": self.scope_element,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ImpactReason:
        fields = require_keys(
            data, ("code", "changed_ref", "scope_element", "detail"), "ImpactReason"
        )
        return cls(
            code=parse_enum(fields["code"], ReasonCode, "ImpactReason.code"),
            changed_ref=fields["changed_ref"],
            scope_element=fields["scope_element"],
            detail=fields["detail"],
        )


# --- impacted invariants --------------------------------------------------------------------------


@dataclass(frozen=True)
class ImpactedInvariant:
    """An invariant that must be checked again (Doc 08 §24, §31): AFFECTED or UNCERTAIN."""

    invariant_id: str
    invariant_version: int
    status: ImpactStatus
    impact_types: tuple[ImpactType, ...]
    changed_resource_refs: tuple[str, ...]
    dependency_paths: tuple[ImpactPath, ...]
    reasons: tuple[ImpactReason, ...]
    prior_evidence_ids: tuple[str, ...]
    evidence_validity: EvidenceValidity

    def __post_init__(self) -> None:
        require_text(self.invariant_id, "ImpactedInvariant.invariant_id")
        require_int(self.invariant_version, "ImpactedInvariant.invariant_version", 1)
        require_enum(self.status, ImpactStatus, "ImpactedInvariant.status")
        if self.status is ImpactStatus.UNAFFECTED:
            raise DomainValidationError("ImpactedInvariant: UNAFFECTED is not an impact")
        require_enum(
            self.evidence_validity, EvidenceValidity, "ImpactedInvariant.evidence_validity"
        )
        wanted = (
            EvidenceValidity.INVALID
            if self.status is ImpactStatus.AFFECTED
            else EvidenceValidity.UNCERTAIN
        )
        if self.evidence_validity is not wanted:
            raise DomainValidationError(
                f"ImpactedInvariant: {self.status.value} needs evidence validity {wanted.value} "
                "(Doc 08 §21)"
            )
        types = tuple(
            require_enum(t, ImpactType, "ImpactedInvariant.impact_types") for t in self.impact_types
        )
        if not types or list(types) != sorted(set(types)):
            raise DomainValidationError(
                "ImpactedInvariant.impact_types: must be a non-empty sorted set"
            )
        refs = _text_list(self.changed_resource_refs, "ImpactedInvariant.changed_resource_refs")
        paths = _objects(self.dependency_paths, ImpactPath, "ImpactedInvariant.dependency_paths")
        reasons = _objects(self.reasons, ImpactReason, "ImpactedInvariant.reasons")
        _sorted_unique(paths, ImpactPath.sort_key, "ImpactedInvariant.dependency_paths")
        _sorted_unique(reasons, ImpactReason.sort_key, "ImpactedInvariant.reasons")
        if not reasons:
            raise DomainValidationError(
                "ImpactedInvariant.reasons: at least one reason is required"
            )
        evidence = _text_list(self.prior_evidence_ids, "ImpactedInvariant.prior_evidence_ids")
        known_refs = set(refs)
        for path in paths:
            if path.changed_ref not in known_refs:
                raise DomainValidationError(
                    "ImpactedInvariant: a path starts at an unlisted resource"
                )
        for reason in reasons:
            if reason.changed_ref is not None and reason.changed_ref not in known_refs:
                raise DomainValidationError(
                    "ImpactedInvariant: a reason names an unlisted resource"
                )
        codes = {r.code for r in reasons}
        if (self.status is ImpactStatus.AFFECTED) != bool(codes & AFFECTED_CODES):
            raise DomainValidationError(
                "ImpactedInvariant.status: AFFECTED exactly when a reason makes it affected"
            )
        for impact, member in (
            (ImpactType.IDENTITY, bool(codes & {ReasonCode.IDENTITY_UNCERTAIN})),
            (ImpactType.UNCERTAINTY, bool(codes & UNCERTAINTY_CODES)),
            (ImpactType.BASELINE, ReasonCode.CREATED_IN_SCOPE in codes),
        ):
            if (impact in types) != member:
                raise DomainValidationError(
                    f"ImpactedInvariant.impact_types: {impact.value} must match the reasons (C-138)"
                )
        if (
            not set(types) & {ImpactType.DIRECT, ImpactType.DEPENDENCY}
            and not codes <= UNCERTAIN_CODES
        ):
            raise DomainValidationError(
                "ImpactedInvariant.impact_types: an affected invariant is DIRECT or DEPENDENCY"
            )
        object.__setattr__(self, "impact_types", types)
        object.__setattr__(self, "changed_resource_refs", refs)
        object.__setattr__(self, "dependency_paths", paths)
        object.__setattr__(self, "reasons", reasons)
        object.__setattr__(self, "prior_evidence_ids", evidence)

    def key(self) -> tuple[str, int]:
        return (self.invariant_id, self.invariant_version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "invariant_version": self.invariant_version,
            "status": self.status.value,
            "impact_types": [t.value for t in self.impact_types],
            "changed_resource_refs": list(self.changed_resource_refs),
            "dependency_paths": [p.to_dict() for p in self.dependency_paths],
            "reasons": [r.to_dict() for r in self.reasons],
            "prior_evidence_ids": list(self.prior_evidence_ids),
            "evidence_validity": self.evidence_validity.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ImpactedInvariant:
        fields = require_keys(
            data,
            (
                "invariant_id",
                "invariant_version",
                "status",
                "impact_types",
                "changed_resource_refs",
                "dependency_paths",
                "reasons",
                "prior_evidence_ids",
                "evidence_validity",
            ),
            "ImpactedInvariant",
        )
        return cls(
            invariant_id=fields["invariant_id"],
            invariant_version=fields["invariant_version"],
            status=parse_enum(fields["status"], ImpactStatus, "ImpactedInvariant.status"),
            impact_types=tuple(
                parse_enum(t, ImpactType, "ImpactedInvariant.impact_types")
                for t in _list_of(fields["impact_types"], "ImpactedInvariant.impact_types")
            ),
            changed_resource_refs=tuple(_list_of(fields["changed_resource_refs"], "refs")),
            dependency_paths=tuple(
                ImpactPath.from_dict(p) for p in _list_of(fields["dependency_paths"], "paths")
            ),
            reasons=tuple(
                ImpactReason.from_dict(r) for r in _list_of(fields["reasons"], "reasons")
            ),
            prior_evidence_ids=tuple(_list_of(fields["prior_evidence_ids"], "prior_evidence_ids")),
            evidence_validity=parse_enum(
                fields["evidence_validity"], EvidenceValidity, "ImpactedInvariant.evidence_validity"
            ),
        )


@dataclass(frozen=True)
class UncertaintyRecord:
    """An uncertainty the report keeps (Doc 08 §20), tied to an impacted invariant."""

    invariant_id: str
    invariant_version: int
    code: ReasonCode
    detail: str

    def __post_init__(self) -> None:
        require_text(self.invariant_id, "UncertaintyRecord.invariant_id")
        require_int(self.invariant_version, "UncertaintyRecord.invariant_version", 1)
        require_enum(self.code, ReasonCode, "UncertaintyRecord.code")
        if self.code not in UNCERTAIN_CODES:
            raise DomainValidationError(
                f"UncertaintyRecord: {self.code.value} is not an uncertainty"
            )
        require_text(self.detail, "UncertaintyRecord.detail")

    def sort_key(self) -> tuple[str, int, str, str]:
        return (self.invariant_id, self.invariant_version, self.code.value, self.detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "invariant_version": self.invariant_version,
            "code": self.code.value,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UncertaintyRecord:
        fields = require_keys(
            data, ("invariant_id", "invariant_version", "code", "detail"), "UncertaintyRecord"
        )
        return cls(
            invariant_id=fields["invariant_id"],
            invariant_version=fields["invariant_version"],
            code=parse_enum(fields["code"], ReasonCode, "UncertaintyRecord.code"),
            detail=fields["detail"],
        )


@dataclass(frozen=True)
class UnaffectedInvariant:
    """An invariant no change reaches, and whether prior evidence may be carried forward.

    ``carry_forward_eligible`` is true only with a prior proof of the same invariant version made by
    the same verifier (Doc 08 §22). Otherwise ``reason`` says why not. Eligible is a precondition,
    not a decision: P6's policy still has to permit carrying it (C-141).
    """

    invariant_id: str
    invariant_version: int
    prior_evidence_ids: tuple[str, ...]
    carry_forward_eligible: bool
    reason: ReasonCode

    def __post_init__(self) -> None:
        require_text(self.invariant_id, "UnaffectedInvariant.invariant_id")
        require_int(self.invariant_version, "UnaffectedInvariant.invariant_version", 1)
        evidence = _text_list(self.prior_evidence_ids, "UnaffectedInvariant.prior_evidence_ids")
        if not isinstance(self.carry_forward_eligible, bool):
            raise DomainValidationError(
                "UnaffectedInvariant.carry_forward_eligible: must be a bool"
            )
        require_enum(self.reason, ReasonCode, "UnaffectedInvariant.reason")
        if self.reason not in UNAFFECTED_CODES:
            raise DomainValidationError(
                f"UnaffectedInvariant: {self.reason.value} is not a reason here"
            )
        if self.carry_forward_eligible:
            if self.reason is not ReasonCode.NO_CHANGE_IN_FOOTPRINT or not evidence:
                raise DomainValidationError(
                    "UnaffectedInvariant: eligible needs NO_CHANGE_IN_FOOTPRINT and prior evidence"
                )
        elif self.reason is ReasonCode.NO_CHANGE_IN_FOOTPRINT:
            raise DomainValidationError("UnaffectedInvariant: not eligible needs a reason why")
        object.__setattr__(self, "prior_evidence_ids", evidence)

    def key(self) -> tuple[str, int]:
        return (self.invariant_id, self.invariant_version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "invariant_version": self.invariant_version,
            "prior_evidence_ids": list(self.prior_evidence_ids),
            "carry_forward_eligible": self.carry_forward_eligible,
            "reason": self.reason.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UnaffectedInvariant:
        fields = require_keys(
            data,
            (
                "invariant_id",
                "invariant_version",
                "prior_evidence_ids",
                "carry_forward_eligible",
                "reason",
            ),
            "UnaffectedInvariant",
        )
        return cls(
            invariant_id=fields["invariant_id"],
            invariant_version=fields["invariant_version"],
            prior_evidence_ids=tuple(_list_of(fields["prior_evidence_ids"], "prior_evidence_ids")),
            carry_forward_eligible=fields["carry_forward_eligible"],
            reason=parse_enum(fields["reason"], ReasonCode, "UnaffectedInvariant.reason"),
        )


@dataclass(frozen=True)
class CarryForwardCandidate:
    """An unaffected invariant whose prior evidence is eligible (the subset of ``unaffected``)."""

    invariant_id: str
    invariant_version: int
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text(self.invariant_id, "CarryForwardCandidate.invariant_id")
        require_int(self.invariant_version, "CarryForwardCandidate.invariant_version", 1)
        object.__setattr__(
            self,
            "evidence_ids",
            _text_list(self.evidence_ids, "CarryForwardCandidate.evidence_ids", empty_ok=False),
        )

    def key(self) -> tuple[str, int]:
        return (self.invariant_id, self.invariant_version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "invariant_version": self.invariant_version,
            "evidence_ids": list(self.evidence_ids),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CarryForwardCandidate:
        fields = require_keys(
            data, ("invariant_id", "invariant_version", "evidence_ids"), "CarryForwardCandidate"
        )
        return cls(
            invariant_id=fields["invariant_id"],
            invariant_version=fields["invariant_version"],
            evidence_ids=tuple(_list_of(fields["evidence_ids"], "evidence_ids")),
        )


# --- work -----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationWorkItem:
    """Verification the candidate owes (Doc 08 §25-§26)."""

    target_id: str
    target_type: WorkTargetType
    reason: ReasonCode
    scope: tuple[str, ...]
    required_evidence: str
    priority: WorkPriority

    def __post_init__(self) -> None:
        require_text(self.target_id, "VerificationWorkItem.target_id")
        require_enum(self.target_type, WorkTargetType, "VerificationWorkItem.target_type")
        require_enum(self.reason, ReasonCode, "VerificationWorkItem.reason")
        require_enum(self.priority, WorkPriority, "VerificationWorkItem.priority")
        require_text(self.required_evidence, "VerificationWorkItem.required_evidence")
        object.__setattr__(
            self, "scope", _text_list(self.scope, "VerificationWorkItem.scope", empty_ok=False)
        )
        prefix = "INVARIANT:" if self.target_type is WorkTargetType.INVARIANT else "RESOURCE:"
        if not self.target_id.startswith(prefix):
            raise DomainValidationError(
                f"VerificationWorkItem: a {self.target_type.value} target starts with {prefix}"
            )
        is_baseline = self.reason is ReasonCode.CREATED_BASELINE
        if is_baseline != (self.target_type is WorkTargetType.RESOURCE):
            raise DomainValidationError(
                "VerificationWorkItem: CREATED_BASELINE is exactly the reason of resource work"
            )
        if not is_baseline and self.reason not in AFFECTED_CODES | UNCERTAIN_CODES:
            raise DomainValidationError(f"VerificationWorkItem: bad reason {self.reason.value}")

    def sort_key(self) -> tuple[str, str]:
        return (self.target_type.value, self.target_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_type": self.target_type.value,
            "reason": self.reason.value,
            "scope": list(self.scope),
            "required_evidence": self.required_evidence,
            "priority": self.priority.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VerificationWorkItem:
        fields = require_keys(
            data,
            ("target_id", "target_type", "reason", "scope", "required_evidence", "priority"),
            "VerificationWorkItem",
        )
        return cls(
            target_id=fields["target_id"],
            target_type=parse_enum(fields["target_type"], WorkTargetType, "target_type"),
            reason=parse_enum(fields["reason"], ReasonCode, "VerificationWorkItem.reason"),
            scope=tuple(_list_of(fields["scope"], "VerificationWorkItem.scope")),
            required_evidence=fields["required_evidence"],
            priority=parse_enum(fields["priority"], WorkPriority, "VerificationWorkItem.priority"),
        )


# --- report ---------------------------------------------------------------------------------------

_PAYLOAD_PARTS: Final = (
    "parent_state_id",
    "candidate_id",
    "changed_resources",
    "affected_invariants",
    "verification_work",
    "uncertainty",
    "unaffected",
    "carry_forward_candidates",
    "reasons",
    "algorithm_version",
    "graph_version",
    "trusted_graph_hash",
    "candidate_graph_hash",
    "identity_report_hash",
)


def _derived_reasons(
    affected: Iterable[ImpactedInvariant],
    uncertainty: Iterable[UncertaintyRecord],
    unaffected: Iterable[UnaffectedInvariant],
    work: Iterable[VerificationWorkItem],
) -> tuple[ReasonCode, ...]:
    used: set[ReasonCode] = set()
    for item in affected:
        used.update(r.code for r in item.reasons)
    used.update(r.code for r in uncertainty)
    used.update(u.reason for u in unaffected)
    used.update(w.reason for w in work)
    return tuple(sorted(used, key=lambda c: c.value))


def _carry_forward(unaffected: Iterable[UnaffectedInvariant]) -> tuple[CarryForwardCandidate, ...]:
    return tuple(
        CarryForwardCandidate(u.invariant_id, u.invariant_version, u.prior_evidence_ids)
        for u in sorted(unaffected, key=UnaffectedInvariant.key)
        if u.carry_forward_eligible
    )


@dataclass(frozen=True)
class ImpactReport:
    """Which protected invariants must be checked again, and why (Doc 08 §23). Create it with
    ``ImpactReport.create``; the constructor checks everything ``create`` derives."""

    report_id: str
    parent_state_id: str
    candidate_id: str
    changed_resources: tuple[ChangedResource, ...]
    affected_invariants: tuple[ImpactedInvariant, ...]
    verification_work: tuple[VerificationWorkItem, ...]
    uncertainty: tuple[UncertaintyRecord, ...]
    unaffected: tuple[UnaffectedInvariant, ...]
    carry_forward_candidates: tuple[CarryForwardCandidate, ...]
    reasons: tuple[ReasonCode, ...]
    algorithm_version: str
    graph_version: str
    trusted_graph_hash: str
    candidate_graph_hash: str
    identity_report_hash: str
    created_at: datetime
    content_hash: str

    def __post_init__(self) -> None:
        require_uuid(self.report_id, "ImpactReport.report_id")
        require_uuid(self.parent_state_id, "ImpactReport.parent_state_id")
        require_uuid(self.candidate_id, "ImpactReport.candidate_id")
        require_text(self.algorithm_version, "ImpactReport.algorithm_version")
        require_text(self.graph_version, "ImpactReport.graph_version")
        for name in ("trusted_graph_hash", "candidate_graph_hash", "identity_report_hash"):
            _hash_text(getattr(self, name), f"ImpactReport.{name}")
        object.__setattr__(self, "created_at", utc(self.created_at, "ImpactReport.created_at"))
        changed = _objects(
            self.changed_resources, ChangedResource, "ImpactReport.changed_resources"
        )
        affected = _objects(self.affected_invariants, ImpactedInvariant, "affected_invariants")
        work = _objects(self.verification_work, VerificationWorkItem, "verification_work")
        uncertainty = _objects(self.uncertainty, UncertaintyRecord, "uncertainty")
        unaffected = _objects(self.unaffected, UnaffectedInvariant, "unaffected")
        candidates = _objects(self.carry_forward_candidates, CarryForwardCandidate, "candidates")
        _sorted_unique(changed, ChangedResource.sort_key, "ImpactReport.changed_resources")
        _sorted_unique(affected, ImpactedInvariant.key, "ImpactReport.affected_invariants")
        _sorted_unique(work, VerificationWorkItem.sort_key, "ImpactReport.verification_work")
        _sorted_unique(uncertainty, UncertaintyRecord.sort_key, "ImpactReport.uncertainty")
        _sorted_unique(unaffected, UnaffectedInvariant.key, "ImpactReport.unaffected")
        _sorted_unique(
            candidates, CarryForwardCandidate.key, "ImpactReport.carry_forward_candidates"
        )
        self._check_consistency(changed, affected, work, uncertainty, unaffected, candidates)
        expected_reasons = _derived_reasons(affected, uncertainty, unaffected, work)
        if tuple(self.reasons) != expected_reasons:
            raise DomainValidationError(
                "ImpactReport.reasons: must be the sorted distinct reason codes the report uses"
            )
        for field, value in (
            ("changed_resources", changed),
            ("affected_invariants", affected),
            ("verification_work", work),
            ("uncertainty", uncertainty),
            ("unaffected", unaffected),
            ("carry_forward_candidates", candidates),
            ("reasons", expected_reasons),
        ):
            object.__setattr__(self, field, value)
        if self.content_hash != self.compute_hash():
            raise HashMismatchError(
                f"DATA-INT-010: ImpactReport {self.report_id} content_hash does not "
                "match its content"
            )

    @staticmethod
    def _check_consistency(
        changed: tuple[ChangedResource, ...],
        affected: tuple[ImpactedInvariant, ...],
        work: tuple[VerificationWorkItem, ...],
        uncertainty: tuple[UncertaintyRecord, ...],
        unaffected: tuple[UnaffectedInvariant, ...],
        candidates: tuple[CarryForwardCandidate, ...],
    ) -> None:
        affected_keys = {item.key() for item in affected}
        unaffected_keys = {item.key() for item in unaffected}
        if affected_keys & unaffected_keys:
            raise DomainValidationError(
                "ImpactReport: an invariant is both impacted and unaffected (Doc 08 §31)"
            )
        for record in uncertainty:
            if (record.invariant_id, record.invariant_version) not in affected_keys:
                raise DomainValidationError(
                    "ImpactReport.uncertainty: names an unimpacted invariant"
                )
        if candidates != _carry_forward(unaffected):
            raise DomainValidationError(
                "ImpactReport.carry_forward_candidates: must be the eligible unaffected invariants"
            )
        created = {c.address for c in changed if c.change_type is ChangeType.CREATED}
        seen_invariants: set[tuple[str, int]] = set()
        seen_resources: set[str] = set()
        for item in work:
            if item.target_type is WorkTargetType.INVARIANT:
                _, _, rest = item.target_id.partition(":")
                invariant_id, _, version = rest.rpartition(":")
                key = (invariant_id, int(version) if version.isdigit() else 0)
                if key not in affected_keys or key in seen_invariants:
                    raise DomainValidationError(
                        f"ImpactReport.verification_work: {item.target_id} is not one "
                        "impacted invariant"
                    )
                seen_invariants.add(key)
            else:
                address = item.target_id.removeprefix("RESOURCE:")
                if address not in created or address in seen_resources:
                    raise DomainValidationError(
                        f"ImpactReport.verification_work: {item.target_id} is not one "
                        "created resource"
                    )
                seen_resources.add(address)
        if seen_invariants != affected_keys:
            raise DomainValidationError(
                "ImpactReport.verification_work: every impacted invariant owes one work item"
            )
        if seen_resources != created:
            raise DomainValidationError(
                "ImpactReport.verification_work: every created resource owes one baseline item"
            )

    def _payload(self) -> dict[str, Any]:
        data = self.to_dict()
        return {name: data[name] for name in _PAYLOAD_PARTS}

    def compute_hash(self) -> str:
        return content_hash(self._payload())

    @classmethod
    def create(
        cls,
        *,
        parent_state_id: str,
        candidate_id: str,
        changed_resources: Iterable[ChangedResource],
        affected_invariants: Iterable[ImpactedInvariant],
        verification_work: Iterable[VerificationWorkItem],
        uncertainty: Iterable[UncertaintyRecord],
        unaffected: Iterable[UnaffectedInvariant],
        graph_version: str,
        trusted_graph_hash: str,
        candidate_graph_hash: str,
        identity_report_hash: str,
        now: datetime,
        report_id: str | None = None,
        algorithm_version: str = IMPACT_ALGORITHM_VERSION,
    ) -> ImpactReport:
        """Sort everything, derive ``reasons`` and ``carry_forward_candidates``, hash."""
        changed = tuple(sorted(changed_resources, key=ChangedResource.sort_key))
        affected = tuple(sorted(affected_invariants, key=ImpactedInvariant.key))
        work = tuple(sorted(verification_work, key=VerificationWorkItem.sort_key))
        records = tuple(sorted(set(uncertainty), key=UncertaintyRecord.sort_key))
        kept = tuple(sorted(unaffected, key=UnaffectedInvariant.key))
        candidates = _carry_forward(kept)
        reasons = _derived_reasons(affected, records, kept, work)
        probe = {
            "parent_state_id": parent_state_id,
            "candidate_id": candidate_id,
            "changed_resources": [c.to_dict() for c in changed],
            "affected_invariants": [a.to_dict() for a in affected],
            "verification_work": [w.to_dict() for w in work],
            "uncertainty": [r.to_dict() for r in records],
            "unaffected": [u.to_dict() for u in kept],
            "carry_forward_candidates": [c.to_dict() for c in candidates],
            "reasons": [r.value for r in reasons],
            "algorithm_version": algorithm_version,
            "graph_version": graph_version,
            "trusted_graph_hash": trusted_graph_hash,
            "candidate_graph_hash": candidate_graph_hash,
            "identity_report_hash": identity_report_hash,
        }
        return cls(
            report_id=new_uuid() if report_id is None else report_id,
            parent_state_id=parent_state_id,
            candidate_id=candidate_id,
            changed_resources=changed,
            affected_invariants=affected,
            verification_work=work,
            uncertainty=records,
            unaffected=kept,
            carry_forward_candidates=candidates,
            reasons=reasons,
            algorithm_version=algorithm_version,
            graph_version=graph_version,
            trusted_graph_hash=trusted_graph_hash,
            candidate_graph_hash=candidate_graph_hash,
            identity_report_hash=identity_report_hash,
            created_at=now,
            content_hash=content_hash(probe),
        )

    # --- queries ---

    def affected_for(self, invariant_id: str, invariant_version: int) -> ImpactedInvariant | None:
        return next(
            (a for a in self.affected_invariants if a.key() == (invariant_id, invariant_version)),
            None,
        )

    def carry_forward_ok(
        self,
        invariant_id: str,
        invariant_version: int,
        *,
        candidate_id: str,
        parent_state_id: str,
    ) -> bool:
        """The single query P6 needs (C-141): true only when this report is for exactly this
        candidate and parent, its hash still recomputes, and the invariant is an eligible
        carry-forward candidate. Anything else is False."""
        if candidate_id != self.candidate_id or parent_state_id != self.parent_state_id:
            return False
        if self.content_hash != self.compute_hash():
            return False
        return any(
            c.key() == (invariant_id, invariant_version) for c in self.carry_forward_candidates
        )

    # --- serialization ---

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "parent_state_id": self.parent_state_id,
            "candidate_id": self.candidate_id,
            "changed_resources": [c.to_dict() for c in self.changed_resources],
            "affected_invariants": [a.to_dict() for a in self.affected_invariants],
            "verification_work": [w.to_dict() for w in self.verification_work],
            "uncertainty": [r.to_dict() for r in self.uncertainty],
            "unaffected": [u.to_dict() for u in self.unaffected],
            "carry_forward_candidates": [c.to_dict() for c in self.carry_forward_candidates],
            "reasons": [r.value for r in self.reasons],
            "algorithm_version": self.algorithm_version,
            "graph_version": self.graph_version,
            "trusted_graph_hash": self.trusted_graph_hash,
            "candidate_graph_hash": self.candidate_graph_hash,
            "identity_report_hash": self.identity_report_hash,
            "created_at": iso_utc(self.created_at),
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ImpactReport:
        fields = require_keys(
            data,
            (
                "report_id",
                *_PAYLOAD_PARTS,
                "created_at",
                "content_hash",
            ),
            "ImpactReport",
        )
        return cls(
            report_id=fields["report_id"],
            parent_state_id=fields["parent_state_id"],
            candidate_id=fields["candidate_id"],
            changed_resources=tuple(
                ChangedResource.from_dict(c)
                for c in _list_of(fields["changed_resources"], "changed")
            ),
            affected_invariants=tuple(
                ImpactedInvariant.from_dict(a) for a in _list_of(fields["affected_invariants"], "a")
            ),
            verification_work=tuple(
                VerificationWorkItem.from_dict(w)
                for w in _list_of(fields["verification_work"], "w")
            ),
            uncertainty=tuple(
                UncertaintyRecord.from_dict(r)
                for r in _list_of(fields["uncertainty"], "uncertainty")
            ),
            unaffected=tuple(
                UnaffectedInvariant.from_dict(u)
                for u in _list_of(fields["unaffected"], "unaffected")
            ),
            carry_forward_candidates=tuple(
                CarryForwardCandidate.from_dict(c)
                for c in _list_of(fields["carry_forward_candidates"], "candidates")
            ),
            reasons=tuple(
                parse_enum(r, ReasonCode, "ImpactReport.reasons")
                for r in _list_of(fields["reasons"], "reasons")
            ),
            algorithm_version=fields["algorithm_version"],
            graph_version=fields["graph_version"],
            trusted_graph_hash=fields["trusted_graph_hash"],
            candidate_graph_hash=fields["candidate_graph_hash"],
            identity_report_hash=fields["identity_report_hash"],
            created_at=parse_utc(fields["created_at"], "ImpactReport.created_at"),
            content_hash=fields["content_hash"],
        )
