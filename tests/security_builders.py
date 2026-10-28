"""Builders for the security predicate tests (P5a): Terraform text to resources and identity.

Standard library plus ``core.domain``, ``core.identity`` and ``core.terraform_model`` (tests may
import them; ``core.verification`` may not, R17). Not a test module.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from core.domain.identity import IdentityReport
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.identity.engine import compare
from tests.identity_builders import CANDIDATE, NOW, PARENT, normalize

VARS = 'variable "u" {}\nvariable "ssh_cidr" {}\n'
APP = "aws_security_group.app"


def resources_of(text: str, variables: Mapping[str, object] | None = None) -> tuple[Resource, ...]:
    return normalize(text, variables).resources


def sg(name: str = "app", body: str = "") -> str:
    return f'resource "aws_security_group" "{name}" {{\n{body}\n}}\n'


def hcl(value: object) -> str:
    """An HCL literal for a list or scalar of plain values (JSON is valid HCL for these)."""
    return json.dumps(value)


def fields(
    protocol: str, low: int, high: int, v4: Iterable[str] | str | None, v6: Iterable[str] | None
) -> str:
    lines = [f"  protocol = {hcl(protocol)}", f"  from_port = {low}", f"  to_port = {high}"]
    if isinstance(v4, str):  # a raw HCL expression such as var.ssh_cidr
        lines.append(f"  cidr_blocks = {v4}")
    elif v4 is not None:
        lines.append(f"  cidr_blocks = {hcl(list(v4))}")
    if v6 is not None:
        lines.append(f"  ipv6_cidr_blocks = {hcl(list(v6))}")
    return "\n".join(lines) + "\n"


def inline(
    direction: str,
    protocol: str,
    low: int,
    high: int,
    v4: Iterable[str] | str | None = None,
    v6: Iterable[str] | None = None,
) -> str:
    """One inline block, to go in the body of ``sg``."""
    return f"  {direction} {{\n{fields(protocol, low, high, v4, v6)}  }}\n"


def rule(
    name: str,
    direction: str,
    protocol: str,
    low: int,
    high: int,
    v4: Iterable[str] | str | None = None,
    v6: Iterable[str] | None = None,
    *,
    target: str = "aws_security_group.app.id",
    extra: str = "",
) -> str:
    """One ``aws_security_group_rule`` resource; ``direction`` may be an HCL expression."""
    kind = direction if direction.startswith("var.") else hcl(direction)
    return (
        f'resource "aws_security_group_rule" "{name}" {{\n  type = {kind}\n'
        f"  security_group_id = {target}\n{fields(protocol, low, high, v4, v6)}{extra}}}\n"
    )


@dataclass(frozen=True)
class Pair:
    parent: tuple[Resource, ...]
    candidate: tuple[Resource, ...]
    identity: IdentityReport


def pair(parent_text: str, candidate_text: str) -> Pair:
    """Normalize both texts and compare them (the candidate's ``moved`` blocks are its moves)."""
    before, after = normalize(parent_text), normalize(candidate_text)
    report = compare(
        before.resources,
        after.resources,
        list(after.moves),
        parent_state_id=PARENT,
        candidate_id=CANDIDATE,
        now=NOW,
    )
    return Pair(before.resources, after.resources, report)


def with_security(resource: Resource, security: Mapping[str, Any]) -> Resource:
    """The same resource with another stored ``security_attributes`` (hash recomputed)."""
    return Resource.create(
        address=resource.address,
        resource_type=resource.resource_type,
        logical_identity=thaw_json(resource.logical_identity),
        attributes=thaw_json(resource.attributes),
        security_attributes=security,
        semantic_attributes=thaw_json(resource.semantic_attributes),
        references=resource.references,
        provenance=resource.provenance,
        support_status=resource.support_status,
    )
