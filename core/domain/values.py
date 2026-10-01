"""Reference and Provenance value objects (Doc 05 §5.3, §6; Doc 11 §21; C-34; P1a step 7).

Both are frozen, validate in ``__post_init__`` and round-trip through
``to_dict`` / ``from_dict`` (which re-validates). Doc 05 §6: "Provenance is not
decorative metadata. It is required to explain where a semantic fact originated
and to support reproducibility."
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from core.domain.enums import ProvenanceSourceKind, ReferenceResolution
from core.domain.errors import DomainValidationError
from core.domain.jsonvalue import (
    iso_utc,
    optional_text,
    parse_enum,
    parse_utc,
    require_enum,
    require_keys,
    require_text,
    utc,
)


@dataclass(frozen=True)
class Reference:
    """A directed reference between resources (Doc 05 §5.3)."""

    source_address: str
    source_attribute: str
    target_address: str
    reference_type: str
    resolution_status: ReferenceResolution

    def __post_init__(self) -> None:
        for name in ("source_address", "source_attribute", "target_address", "reference_type"):
            require_text(getattr(self, name), f"Reference.{name}")
        require_enum(self.resolution_status, ReferenceResolution, "Reference.resolution_status")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_address": self.source_address,
            "source_attribute": self.source_attribute,
            "target_address": self.target_address,
            "reference_type": self.reference_type,
            "resolution_status": self.resolution_status.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Reference:
        fields = require_keys(
            data,
            (
                "source_address",
                "source_attribute",
                "target_address",
                "reference_type",
                "resolution_status",
            ),
            "Reference",
        )
        return cls(
            source_address=fields["source_address"],
            source_attribute=fields["source_attribute"],
            target_address=fields["target_address"],
            reference_type=fields["reference_type"],
            resolution_status=parse_enum(
                fields["resolution_status"], ReferenceResolution, "Reference.resolution_status"
            ),
        )


_OPTIONAL_PROVENANCE_TEXT = (
    "tool_name",
    "tool_version",
    "parser_version",
    "normalization_version",
    "algorithm_version",
)


@dataclass(frozen=True)
class Provenance:
    """Where a semantic fact came from (C-34: the union of Doc 05 §6 and Doc 11 §21).

    ``source_kind``, ``source_component``, ``source_reference`` and ``observed_at``
    are required. The remaining text fields use explicit null; an empty string is
    rejected rather than read as null. ``transformation_steps`` defaults to an
    empty tuple.
    """

    source_kind: ProvenanceSourceKind
    source_component: str
    source_reference: str
    observed_at: datetime
    tool_name: str | None = None
    tool_version: str | None = None
    parser_version: str | None = None
    normalization_version: str | None = None
    algorithm_version: str | None = None
    transformation_steps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_enum(self.source_kind, ProvenanceSourceKind, "Provenance.source_kind")
        require_text(self.source_component, "Provenance.source_component")
        require_text(self.source_reference, "Provenance.source_reference")
        object.__setattr__(self, "observed_at", utc(self.observed_at, "Provenance.observed_at"))
        for name in _OPTIONAL_PROVENANCE_TEXT:
            optional_text(getattr(self, name), f"Provenance.{name}")
        steps = self.transformation_steps
        if not isinstance(steps, list | tuple):
            raise DomainValidationError("Provenance.transformation_steps: must be a list of text")
        object.__setattr__(
            self,
            "transformation_steps",
            tuple(
                require_text(step, f"Provenance.transformation_steps[{index}]")
                for index, step in enumerate(steps)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "source_kind": self.source_kind.value,
            "source_component": self.source_component,
            "source_reference": self.source_reference,
            "observed_at": iso_utc(self.observed_at),
        }
        for name in _OPTIONAL_PROVENANCE_TEXT:
            data[name] = getattr(self, name)
        data["transformation_steps"] = list(self.transformation_steps)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Provenance:
        fields = require_keys(
            data,
            (
                "source_kind",
                "source_component",
                "source_reference",
                "observed_at",
                *_OPTIONAL_PROVENANCE_TEXT,
                "transformation_steps",
            ),
            "Provenance",
        )
        return cls(
            source_kind=parse_enum(
                fields["source_kind"], ProvenanceSourceKind, "Provenance.source_kind"
            ),
            source_component=fields["source_component"],
            source_reference=fields["source_reference"],
            observed_at=parse_utc(fields["observed_at"], "Provenance.observed_at"),
            tool_name=fields["tool_name"],
            tool_version=fields["tool_version"],
            parser_version=fields["parser_version"],
            normalization_version=fields["normalization_version"],
            algorithm_version=fields["algorithm_version"],
            transformation_steps=fields["transformation_steps"],
        )
