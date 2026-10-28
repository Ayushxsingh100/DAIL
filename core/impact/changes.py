"""The changed set (Doc 08 §6; registry §2.9; C-117; C-140 item 1).

Every identity match that is not UNCHANGED is a change source, with its change type and the flags
the identity evidence carries (``UNRESOLVED_CONTENT``, ``UNSUPPORTED_TYPE``). An UNCHANGED match is
**also** a change source when the resource carries unresolved content: equal fingerprints do not
prove an unresolved element unchanged (registry §2.9 treats "unresolved on both sides" as changed;
C-117). Such a source is carried with change type UNCERTAIN and the flag ``UNRESOLVED_CONTENT``, and
the engine uses it only for invariants whose footprint contains the resource. It can only add
UNCERTAIN; it never removes anything.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from core.domain.enums import ChangeType
from core.domain.identity import EvidenceType, IdentityMatch, IdentityReport
from core.domain.impact import ChangedResource, ChangeFlag
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.impact.errors import ImpactInputError

_TAG = "$dail"
_UNRESOLVED_TAGS = frozenset({"unknown", "unsupported"})
_FLAG_OF = {
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


def has_unresolved_content(resource: Resource) -> bool:
    """Whether any canonical value of the resource is Unknown or Unsupported (C-112, C-117)."""
    return any(
        _contains_unresolved(thaw_json(part))
        for part in (
            resource.attributes,
            resource.security_attributes,
            resource.semantic_attributes,
        )
    )


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
        resource_type = (sides[-1]).resource_type
        flags = _flags(identity, match)
        address = candidate_ref if candidate_ref is not None else trusted_ref
        assert address is not None
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
        elif ChangeFlag.UNRESOLVED_CONTENT in flags or any(
            has_unresolved_content(r) for r in sides
        ):
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
