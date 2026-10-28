"""``build_graph``: one normalized state and the declared invariants to a ``DependencyGraph``
(Doc 07 §20, §31; C-131 to C-135).

Steps, in the order of Doc 07 §31: check the inputs; add a node for every resource, sorted by
canonical address; add a reference edge for every reference; add the typed relationships and the
explicit edges of the slots that cannot be resolved; add the invariant nodes with their scope and
semantic edges; sort nodes and edges by their stable ids and compute the structural hash.

The function is pure: the same resources, invariants and bindings give the same graph hash, whatever
the input order, the hash seed or the clock (``graph_id`` and ``created_at`` are outside the hash).
It decides no impact (Doc 07 §25).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from core.dependency.edges import Parts, finalize
from core.dependency.errors import DependencyInputError
from core.dependency.index import StateIndex
from core.dependency.infrastructure import add_infrastructure_edges
from core.dependency.invariants import SemanticBinding, add_invariant_edges, check_invariants
from core.dependency.nodes import resource_node
from core.dependency.references import add_reference_edges
from core.dependency.versions import GRAPH_ALGORITHM_VERSION
from core.domain.graph import DependencyGraph
from core.domain.invariant import Invariant
from core.domain.resource import Resource


def _normalization_version(resources: tuple[Resource, ...], given: str | None) -> str:
    """The one normalization version of the state (Doc 07 §29, C-131)."""
    versions = {resource.provenance.normalization_version for resource in resources}
    if None in versions:
        raise DependencyInputError(
            "a resource has no normalization_version in its provenance (Doc 07 §29)"
        )
    if len(versions) > 1:
        raise DependencyInputError(
            f"the resources carry more than one normalization version: {sorted(map(str, versions))}"
        )
    if not versions:
        if given is None:
            raise DependencyInputError(
                "an empty state has no normalization version; pass normalization_version"
            )
        return given
    (version,) = versions
    assert version is not None
    if given is not None and given != version:
        raise DependencyInputError(
            f"normalization_version {given!r} differs from the resources' {version!r}"
        )
    return version


def build_graph(
    resources: Iterable[Resource],
    invariants: Iterable[Invariant],
    bindings: Iterable[SemanticBinding] = (),
    *,
    state_id: str,
    now: datetime,
    normalization_version: str | None = None,
) -> DependencyGraph:
    """The dependency graph of one state.

    ``normalization_version`` is only needed for an empty state; otherwise it is read from the
    resources, which must all carry the same one.
    """
    if isinstance(resources, str):
        raise DependencyInputError("resources must be a collection of Resource objects")
    index = StateIndex.of(resources)
    ordered_invariants, ordered_bindings = check_invariants(invariants, bindings)
    version = _normalization_version(index.sorted_resources(), normalization_version)
    parts = Parts()
    for resource in index.sorted_resources():
        parts.add_node(resource_node(resource))
    for resource in index.sorted_resources():
        add_reference_edges(resource, index, parts)
        add_infrastructure_edges(resource, index, parts)
    add_invariant_edges(ordered_invariants, ordered_bindings, index, parts, now=now)
    return DependencyGraph.create(
        state_id=state_id,
        nodes=parts.nodes,
        edges=finalize(parts.drafts),
        normalization_version=version,
        algorithm_version=GRAPH_ALGORITHM_VERSION,
        now=now,
    )
