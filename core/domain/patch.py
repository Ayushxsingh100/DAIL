"""Patch (Doc 05 §9, §23, §25; C-33; P1a step 9).

Doc 05 §9: "The patch is the proposed transition input. It must be retained
independently of the resulting candidate state so that the candidate can be
reconstructed or audited." Patch content is immutable after creation (§23); its
``content_hash`` is SHA-256 of the UTF-8 content with line endings normalized
to LF (C-33, ``core.domain.hashing.sha256_text``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from core.domain.enums import CandidateSource, PatchFormat
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.hashing import sha256_text
from core.domain.ids import new_uuid, require_uuid
from core.domain.jsonvalue import (
    freeze_json,
    iso_utc,
    parse_enum,
    parse_utc,
    require_enum,
    require_keys,
    thaw_json,
    utc,
    validate_json,
)


@dataclass(frozen=True)
class Patch:
    """A proposed change to HCL, bound to the trusted state it was written against."""

    patch_id: str
    source: CandidateSource
    content: str
    format: PatchFormat
    parent_state_id: str
    llm_request_id: str | None
    created_at: datetime
    content_hash: str
    metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        require_uuid(self.patch_id, "Patch.patch_id")
        require_enum(self.source, CandidateSource, "Patch.source")
        if not isinstance(self.content, str) or self.content == "":
            raise DomainValidationError("Patch.content: must be a non-empty string (Doc 05 §9)")
        require_enum(self.format, PatchFormat, "Patch.format")
        require_uuid(self.parent_state_id, "Patch.parent_state_id")
        # Derived rule: an LLM patch is traceable to its request; a fixed patch has none.
        if self.source is CandidateSource.LLM:
            if self.llm_request_id is None:
                raise DomainValidationError("Patch.llm_request_id: required when source is LLM")
            require_uuid(self.llm_request_id, "Patch.llm_request_id")
        elif self.llm_request_id is not None:
            raise DomainValidationError("Patch.llm_request_id: must be null for a FIXED_PATCH")
        object.__setattr__(self, "created_at", utc(self.created_at, "Patch.created_at"))
        if not isinstance(self.metadata, Mapping):
            raise DomainValidationError("Patch.metadata: must be a JSON object (Doc 05 §9)")
        validate_json(self.metadata, "Patch.metadata")
        object.__setattr__(self, "metadata", freeze_json(self.metadata))
        if self.content_hash != sha256_text(self.content):
            raise HashMismatchError(
                f"DATA-INT-010: Patch {self.patch_id} content_hash does not match its content"
            )

    @classmethod
    def create(
        cls,
        *,
        source: CandidateSource,
        content: str,
        parent_state_id: str,
        now: datetime,
        llm_request_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        patch_id: str | None = None,
    ) -> Patch:
        if not isinstance(content, str):
            raise DomainValidationError("Patch.content: must be a non-empty string (Doc 05 §9)")
        return cls(
            patch_id=new_uuid() if patch_id is None else patch_id,
            source=source,
            content=content,
            format=PatchFormat.TERRAFORM_HCL,
            parent_state_id=parent_state_id,
            llm_request_id=llm_request_id,
            created_at=now,
            content_hash=sha256_text(content),
            metadata={} if metadata is None else metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "source": self.source.value,
            "content": self.content,
            "format": self.format.value,
            "parent_state_id": self.parent_state_id,
            "llm_request_id": self.llm_request_id,
            "created_at": iso_utc(self.created_at),
            "content_hash": self.content_hash,
            "metadata": thaw_json(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Patch:
        fields = require_keys(
            data,
            (
                "patch_id",
                "source",
                "content",
                "format",
                "parent_state_id",
                "llm_request_id",
                "created_at",
                "content_hash",
                "metadata",
            ),
            "Patch",
        )
        return cls(
            patch_id=fields["patch_id"],
            source=parse_enum(fields["source"], CandidateSource, "Patch.source"),
            content=fields["content"],
            format=parse_enum(fields["format"], PatchFormat, "Patch.format"),
            parent_state_id=fields["parent_state_id"],
            llm_request_id=fields["llm_request_id"],
            created_at=parse_utc(fields["created_at"], "Patch.created_at"),
            content_hash=fields["content_hash"],
            metadata=fields["metadata"],
        )
