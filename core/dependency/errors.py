"""Dependency engine errors (C-131)."""

from __future__ import annotations

from core.domain.errors import DomainValidationError


class DependencyInputError(DomainValidationError):
    """The inputs of the dependency engine are inconsistent, so no graph can be built.

    Raised for resources without one normalization version, duplicate addresses or invariant
    ids, a binding for an invariant that is not given, a start node that is not in the graph, and
    a malformed address. It is a refusal, never a graph with a silent gap (Doc 07 §24).
    """
