"""Builders for the INV-FUNC-001 tests (P5b): the canonical configuration and asserted text edits.

Every F-vector is "a minimal configuration difference from the canonical topology" (registry §8).
The canonical text is the fixture ``canonical_regression/patch_safe`` (SSH fixed, path kept); an
edit is a replacement that is asserted to apply exactly once, so a no-op edit cannot pass silently.
Standard library plus ``core.*`` (tests may import every package). Not a test module.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource

ROOT = Path(__file__).resolve().parents[1]
CANONICAL_PATH = ROOT / "fixtures" / "canonical_regression" / "patch_safe" / "main.tf"
SOURCE = "aws_instance.app"
DESTINATION = "aws_db_instance.database"


def canonical() -> str:
    """The canonical configuration text (a PASS for INV-FUNC-001, registry F1)."""
    return CANONICAL_PATH.read_text(encoding="utf-8")


def edit(text: str, old: str, new: str) -> str:
    """Replace ``old`` by ``new``; the old text must occur exactly once."""
    count = text.count(old)
    if count != 1:
        raise AssertionError(f"the edit target occurs {count} times, not once: {old[:80]!r}")
    return text.replace(old, new)


def edits(text: str, *pairs: tuple[str, str]) -> str:
    for old, new in pairs:
        text = edit(text, old, new)
    return text


def with_attributes(resource: Resource, attributes: Mapping[str, Any]) -> Resource:
    """The same resource with other stored ``attributes`` (hash recomputed): a damaged record."""
    return Resource.create(
        address=resource.address,
        resource_type=resource.resource_type,
        logical_identity=thaw_json(resource.logical_identity),
        attributes=attributes,
        security_attributes=thaw_json(resource.security_attributes),
        semantic_attributes=thaw_json(resource.semantic_attributes),
        references=resource.references,
        provenance=resource.provenance,
        support_status=resource.support_status,
    )


def attribute(value: Any) -> dict[str, Any]:
    """An ATTRIBUTE-form argument in the stored encoding."""
    return {"form": "ATTRIBUTE", "value": value}
