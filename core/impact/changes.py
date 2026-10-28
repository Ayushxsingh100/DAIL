"""The changed set (Doc 08 §6; registry §2.7, §2.9; C-117; C-140 item 1, C-143).

Every identity match that is not UNCHANGED is a change source, with its change type and the flags
the identity evidence carries (``UNRESOLVED_CONTENT``, ``UNSUPPORTED_TYPE``). An UNCHANGED match is
**also** a change source when the resource carries unresolved content: equal fingerprints do not
prove an unresolved element unchanged (registry §2.9 treats "unresolved on both sides" as changed;
C-117). Such a source is carried with change type UNCERTAIN and the flag ``UNRESOLVED_CONTENT``, and
the engine uses it only for invariants whose footprint contains the resource. It can only add
UNCERTAIN; it never removes anything.

What counts as unresolved content (C-143, option A): an Unknown or Unsupported canonical value
in the resource, a security-group direction in the form ``unresolved``, ``dynamic`` or ``mixed``,
and a reference whose resolution is UNKNOWN or UNSUPPORTED **except** a reference to a tolerated
type. ``aws_db_subnet_group`` is tolerated, not relevant (registry §2.7, C-15): the RDS placement is
assumed away, and an UNSUPPORTED reference to it is a fact of every database that names a subnet
group, not an unresolved footprint element. The test is made on the resources, not on the identity
evidence flag, because that flag does not make the exception.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from core.domain.enums import ChangeType, ReferenceResolution
from core.domain.identity import EvidenceType, IdentityMatch, IdentityReport
from core.domain.impact import ChangedResource, ChangeFlag
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.impact.addresses import type_of
from core.impact.errors import ImpactInputError

_TAG = "$dail"
_UNRESOLVED_TAGS: Final = frozenset({"unknown", "unsupported"})
_UNRESOLVED_FORMS: Final = frozenset({"unresolved", "dynamic", "mixed"})
_UNRESOLVED_REFERENCES: Final = frozenset(
    {ReferenceResolution.UNKNOWN, ReferenceResolution.UNSUPPORTED}
)
# Registry §2.7 "Tolerated type" and C-15. A test compares this with the front end's own table.
TOLERATED_TYPES: Final = frozenset({"aws_db_subnet_group"})
_FLAG_OF: Final = {
    EvidenceType.UNRESOLVED_CONTENT: ChangeFlag.UNRESOLVED_CONTENT,
    EvidenceType.UNSUPPORTED_TYPE: ChangeFlag.UNSUPPORTED_TYPE,
}


class Origin(StrEnum):
    """Why a resource is a change source."""

    IDENTITY = "IDENTITY"  # the identity match is not UNCHANGED
    UNRESOLVED = "UNRESOLVED"  # UNCHANGED, but with unresolved content (C-117)


@dataclass(frozen=True)
class ChangeSource:
    changed: ChangedResource
    origin: Origin


def _contains_unresolved(value: Any) -> bool:
    if isinstance(value, dict):
        if value.get(_TAG) in _UNRESOLVED_TAGS:
            return True
        return any(_contains_unresolved(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_unresolved(item) for item in value)
    return False


def unresolved_reasons(resource: Resource) -> list[str]:
    """Why the resource has unresolved content (C-117, C-143); empty when it has none."""
    reasons: list[str] = []
    for name, part in (
        ("attributes", resource.attributes),
        ("security_attributes", resource.security_attributes),
        ("semantic_attributes", resource.semantic_attributes),
    ):
        if _contains_unresolved(thaw_json(part)):
            reasons.append(f"an unknown or unsupported value in {name}")
    forms = resource.security_attributes.get("forms")
    if isinstance(forms, Mapping):
        reasons.extend(
            f"the {name} rules are of form {form}"
            for name, form in sorted(forms.items())
            if form in _UNRESOLVED_FORMS
        )
    for reference in resource.references:
        if (
            reference.resolution_status in _UNRESOLVED_REFERENCES
            and type_of(reference.target_address) not in TOLERATED_TYPES
        ):
            reasons.append(
                f"{reference.source_attribute} refers to {reference.target_address} "
                f"({reference.resolution_status.value})"
            )
    return reasons


def has_unresolved_content(resource: Resource) -> bool:
    return bool(unresolved_reasons(resource))


def _flags(identity: IdentityReport, match: IdentityMatch) -> tuple[ChangeFlag, ...]:
    found = {
        _FLAG_OF[e.evidence_type]
        for e in identity.evidence_for(match)
        if e.evidence_type in _FLAG_OF
    }
    return tuple(sorted(found))


def change_sources(
    identity: IdentityReport,
    trusted: Mapping[str, Resource],
    candidate: Mapping[str, Resource],
) -> tuple[ChangeSource, ...]:
    """The change sources of an identity report, sorted by address (Doc 08 §32)."""
    sources: list[ChangeSource] = []
    for match in identity.resource_matches:
        trusted_ref, candidate_ref = match.trusted_resource_ref, match.candidate_resource_ref
        if trusted_ref is not None and trusted_ref not in trusted:
            raise ImpactInputError(f"identity ref {trusted_ref!r} is not a trusted resource")
        if candidate_ref is not None and candidate_ref not in candidate:
            raise ImpactInputError(f"identity ref {candidate_ref!r} is not a candidate resource")
        sides = [
            r
            for r in (
                trusted.get(trusted_ref) if trusted_ref is not None else None,
                candidate.get(candidate_ref) if candidate_ref is not None else None,
            )
            if r is not None
        ]
        resource_type = sides[-1].resource_type
        flags = _flags(identity, match)
        address = candidate_ref if candidate_ref is not None else trusted_ref
        if address is None:
            raise ImpactInputError("an identity match has no ref")
        if match.change_type is not ChangeType.UNCHANGED:
            sources.append(
                ChangeSource(
                    ChangedResource(
                        address=address,
                        trusted_ref=trusted_ref,
                        candidate_ref=candidate_ref,
                        resource_type=resource_type,
                        change_type=match.change_type,
                        flags=flags,
                    ),
                    Origin.IDENTITY,
                )
            )
        elif any(has_unresolved_content(r) for r in sides):
            sources.append(
                ChangeSource(
                    ChangedResource(
                        address=address,
                        trusted_ref=trusted_ref,
                        candidate_ref=candidate_ref,
                        resource_type=resource_type,
                        change_type=ChangeType.UNCERTAIN,
                        flags=tuple(sorted({*flags, ChangeFlag.UNRESOLVED_CONTENT})),
                    ),
                    Origin.UNRESOLVED,
                )
            )
    return tuple(sorted(sources, key=lambda s: s.changed.sort_key()))
