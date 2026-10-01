"""The normalized Terraform resource (Doc 05 §5.1, §5.2, §28; Doc 04 §6; C-33; P1a step 8).

This replaces the earlier change-record class. A ``Resource`` is one resource in
a normalized state. The change-record concept (before/after, identity outcome)
returns in P3b as ``IdentityMatch``.

Doc 05 §5.2:
- ``record_id`` is database/domain-record identity and is never semantic identity.
- ``address`` is source-level identity within a configuration context.
- ``fingerprint`` represents canonical supported semantic content.

The fingerprint (C-33) is the SHA-256 of the canonical JSON over
{resource_type, logical_identity, attributes, security_attributes,
semantic_attributes, references}. It excludes ``address``, ``record_id``,
``provenance`` and ``support_status``, so renaming a resource, regenerating a
record or re-parsing does not change it (Doc 04 §6.1, Doc 12 §17).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from core.domain.enums import ResourceSupport
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.hashing import canonical_json as canonicalize
from core.domain.hashing import content_hash
from core.domain.ids import new_uuid, require_uuid
from core.domain.jsonvalue import (
    freeze_json,
    parse_enum,
    require_enum,
    require_keys,
    require_text,
    thaw_json,
    validate_json,
)
from core.domain.values import Provenance, Reference

_PAYLOAD_FIELDS = ("logical_identity", "attributes", "security_attributes", "semantic_attributes")


def _reference_sort_key(ref: Reference) -> tuple[str, str, str, str]:
    return (
        ref.source_attribute,
        ref.target_address,
        ref.reference_type,
        ref.resolution_status.value,
    )


def _fingerprint_payload(
    resource_type: str,
    logical_identity: Mapping[str, Any],
    attributes: Mapping[str, Any],
    security_attributes: Mapping[str, Any],
    semantic_attributes: Mapping[str, Any],
    references: Iterable[Reference],
) -> dict[str, Any]:
    """The C-33 canonical content. ``source_address`` is left out of each reference because
    it always equals the resource address, which the fingerprint excludes."""
    return {
        "resource_type": resource_type,
        "logical_identity": thaw_json(logical_identity),
        "attributes": thaw_json(attributes),
        "security_attributes": thaw_json(security_attributes),
        "semantic_attributes": thaw_json(semantic_attributes),
        "references": [
            {
                "source_attribute": ref.source_attribute,
                "target_address": ref.target_address,
                "reference_type": ref.reference_type,
                "resolution_status": ref.resolution_status.value,
            }
            for ref in references
        ],
    }


@dataclass(frozen=True)
class Resource:
    """One normalized resource (Doc 05 §5.1). Create it with ``Resource.create``."""

    record_id: str
    address: str
    resource_type: str
    logical_identity: Mapping[str, Any]
    attributes: Mapping[str, Any]
    security_attributes: Mapping[str, Any]
    semantic_attributes: Mapping[str, Any]
    references: tuple[Reference, ...]
    provenance: Provenance
    canonical_json: str
    fingerprint: str
    support_status: ResourceSupport

    def __post_init__(self) -> None:
        require_uuid(self.record_id, "Resource.record_id")
        require_text(self.address, "Resource.address")
        require_text(self.resource_type, "Resource.resource_type")
        for name in _PAYLOAD_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise DomainValidationError(f"Resource.{name}: must be a JSON object (Doc 05 §5.1)")
            validate_json(value, f"Resource.{name}")
            object.__setattr__(self, name, freeze_json(value))
        refs = self.references
        if not isinstance(refs, list | tuple) or not all(isinstance(r, Reference) for r in refs):
            raise DomainValidationError("Resource.references: must be a list of Reference objects")
        for ref in refs:
            if ref.source_address != self.address:
                raise DomainValidationError(
                    f"Resource.references: reference from {ref.source_address!r} does not "
                    f"belong to resource {self.address!r} (Doc 05 §5.3)"
                )
        object.__setattr__(self, "references", tuple(sorted(refs, key=_reference_sort_key)))
        if not isinstance(self.provenance, Provenance):
            raise DomainValidationError("Resource.provenance: must be a Provenance (Doc 05 §6)")
        require_enum(self.support_status, ResourceSupport, "Resource.support_status")
        expected = canonicalize(self.fingerprint_payload())
        if self.canonical_json != expected:
            raise HashMismatchError(
                f"DATA-INT-010: Resource {self.address!r} canonical_json does not match its content"
            )
        if self.fingerprint != content_hash(self.fingerprint_payload()):
            raise HashMismatchError(
                f"DATA-INT-010: Resource {self.address!r} fingerprint does not match its content"
            )

    def fingerprint_payload(self) -> dict[str, Any]:
        return _fingerprint_payload(
            self.resource_type,
            self.logical_identity,
            self.attributes,
            self.security_attributes,
            self.semantic_attributes,
            self.references,
        )

    @classmethod
    def create(
        cls,
        *,
        address: str,
        resource_type: str,
        logical_identity: Mapping[str, Any],
        attributes: Mapping[str, Any],
        security_attributes: Mapping[str, Any],
        semantic_attributes: Mapping[str, Any],
        references: Iterable[Reference],
        provenance: Provenance,
        support_status: ResourceSupport,
        record_id: str | None = None,
    ) -> Resource:
        """Build a resource and compute its canonical JSON and fingerprint (C-33)."""
        for name, value in (
            ("logical_identity", logical_identity),
            ("attributes", attributes),
            ("security_attributes", security_attributes),
            ("semantic_attributes", semantic_attributes),
        ):
            if not isinstance(value, Mapping):
                raise DomainValidationError(f"Resource.{name}: must be a JSON object (Doc 05 §5.1)")
            validate_json(value, f"Resource.{name}")
        if isinstance(references, str) or not isinstance(references, Iterable):
            raise DomainValidationError("Resource.references: must be a list of Reference objects")
        refs = tuple(references)
        if not all(isinstance(r, Reference) for r in refs):
            raise DomainValidationError("Resource.references: must be a list of Reference objects")
        payload = _fingerprint_payload(
            resource_type,
            logical_identity,
            attributes,
            security_attributes,
            semantic_attributes,
            sorted(refs, key=_reference_sort_key),
        )
        return cls(
            record_id=new_uuid() if record_id is None else record_id,
            address=address,
            resource_type=resource_type,
            logical_identity=logical_identity,
            attributes=attributes,
            security_attributes=security_attributes,
            semantic_attributes=semantic_attributes,
            references=refs,
            provenance=provenance,
            canonical_json=canonicalize(payload),
            fingerprint=content_hash(payload),
            support_status=support_status,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "address": self.address,
            "resource_type": self.resource_type,
            "logical_identity": thaw_json(self.logical_identity),
            "attributes": thaw_json(self.attributes),
            "security_attributes": thaw_json(self.security_attributes),
            "semantic_attributes": thaw_json(self.semantic_attributes),
            "references": [ref.to_dict() for ref in self.references],
            "provenance": self.provenance.to_dict(),
            "canonical_json": self.canonical_json,
            "fingerprint": self.fingerprint,
            "support_status": self.support_status.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Resource:
        fields = require_keys(
            data,
            (
                "record_id",
                "address",
                "resource_type",
                *_PAYLOAD_FIELDS,
                "references",
                "provenance",
                "canonical_json",
                "fingerprint",
                "support_status",
            ),
            "Resource",
        )
        raw_references = fields["references"]
        if not isinstance(raw_references, list | tuple):
            raise DomainValidationError("Resource.references: must be a list")
        return cls(
            record_id=fields["record_id"],
            address=fields["address"],
            resource_type=fields["resource_type"],
            logical_identity=fields["logical_identity"],
            attributes=fields["attributes"],
            security_attributes=fields["security_attributes"],
            semantic_attributes=fields["semantic_attributes"],
            references=tuple(Reference.from_dict(item) for item in raw_references),
            provenance=Provenance.from_dict(fields["provenance"]),
            canonical_json=fields["canonical_json"],
            fingerprint=fields["fingerprint"],
            support_status=parse_enum(
                fields["support_status"], ResourceSupport, "Resource.support_status"
            ),
        )
