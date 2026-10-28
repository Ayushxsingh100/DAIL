"""The inputs of a verification run (C-144; P5a step 5).

``VerificationInputs`` is what the engine is given for one candidate: its resources, the parent's
resources and the identity, impact and graph reports computed from them (all optional for a
baseline), the invariant definitions, the candidate's state hash and the construction status
(whether the configuration could be built at all, registry §2.8).

The constructor checks types and shape and raises ``VerificationInputError``; it does not check that
the reports agree with the resources, which is what the structural and consistency gate does and
records as findings. Lists are stored as tuples.

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from core.domain.errors import DomainValidationError
from core.domain.graph import DependencyGraph
from core.domain.identity import IdentityReport
from core.domain.ids import require_uuid
from core.domain.impact import ImpactReport
from core.domain.invariant import Invariant
from core.domain.resource import Resource
from core.domain.verification import ConstructionStatus
from core.verification.errors import VerificationInputError

_HASH = re.compile(r"[0-9a-f]{64}")


def _fail(message: str) -> VerificationInputError:
    return VerificationInputError(f"VerificationInputs: {message}")


def _tuple_of(value: object, kind: type, field: str) -> tuple[Any, ...]:
    if isinstance(value, str | bytes) or not isinstance(value, Iterable):
        raise _fail(f"{field} must be a list of {kind.__name__}")
    items = tuple(value)
    if not all(isinstance(item, kind) for item in items):
        raise _fail(f"{field} must hold only {kind.__name__} objects")
    return items


def _optional(value: object, kind: type, field: str) -> None:
    if value is not None and not isinstance(value, kind):
        raise _fail(f"{field} must be a {kind.__name__} or None")


@dataclass(frozen=True)
class VerificationInputs:
    candidate_resources: tuple[Resource, ...]
    parent_resources: tuple[Resource, ...] | None
    candidate_state_hash: str
    normalization_version: str
    candidate_id: str
    parent_state_id: str | None
    identity: IdentityReport | None
    impact: ImpactReport | None
    candidate_graph: DependencyGraph | None
    trusted_graph: DependencyGraph | None
    invariants: tuple[Invariant, ...]
    construction: ConstructionStatus
    construction_note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "candidate_resources",
            _tuple_of(self.candidate_resources, Resource, "candidate_resources"),
        )
        if self.parent_resources is not None:
            object.__setattr__(
                self,
                "parent_resources",
                _tuple_of(self.parent_resources, Resource, "parent_resources"),
            )
        if not isinstance(self.candidate_state_hash, str) or not _HASH.fullmatch(
            self.candidate_state_hash
        ):
            raise _fail("candidate_state_hash must be a SHA-256 hex digest")
        if not isinstance(self.normalization_version, str) or not self.normalization_version:
            raise _fail("normalization_version must be non-empty text")
        try:
            require_uuid(self.candidate_id, "candidate_id")
            if self.parent_state_id is not None:
                require_uuid(self.parent_state_id, "parent_state_id")
        except DomainValidationError as error:
            raise _fail(str(error)) from None
        if (self.parent_resources is None) != (self.parent_state_id is None):
            raise _fail("parent_resources and parent_state_id are given together or not at all")
        _optional(self.identity, IdentityReport, "identity")
        _optional(self.impact, ImpactReport, "impact")
        _optional(self.candidate_graph, DependencyGraph, "candidate_graph")
        _optional(self.trusted_graph, DependencyGraph, "trusted_graph")
        definitions = _tuple_of(self.invariants, Invariant, "invariants")
        keys = [(item.invariant_id, item.version) for item in definitions]
        if len(set(keys)) != len(keys):
            raise _fail("invariants hold the same id and version twice")
        object.__setattr__(
            self,
            "invariants",
            tuple(sorted(definitions, key=lambda i: (i.invariant_id, i.version))),
        )
        if not isinstance(self.construction, ConstructionStatus):
            raise _fail("construction must be a ConstructionStatus")
        if not isinstance(self.construction_note, str):
            raise _fail("construction_note must be text")

    def invariant(self, invariant_id: str, version: int) -> Invariant | None:
        """The definition with this id and version, or ``None``."""
        for item in self.invariants:
            if item.invariant_id == invariant_id and item.version == version:
                return item
        return None
