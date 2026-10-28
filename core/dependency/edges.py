"""Edge drafts, status ordering and the collapse of duplicate edges (C-133 items 2 and 6).

A producer (references, slots, invariants) adds ``EdgeDraft`` objects and the nodes they need to a
``Parts`` accumulator. ``finalize`` turns the drafts into ``GraphEdge`` objects: drafts with the
same edge key collapse to one, the evidence of the first (by derivation rule and facts) is kept
and the **worst** status wins, because the status is not part of the key and uncertainty must
never be lost.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from core.dependency.errors import DependencyInputError
from core.domain.enums import DependencyStatus, ReferenceResolution, ResourceSupport
from core.domain.graph import (
    DependencyEvidence,
    DerivationRule,
    EdgeType,
    GraphEdge,
    GraphNode,
    Relationship,
    edge_key_of,
)
from core.domain.jsonvalue import freeze_json
from core.domain.values import Provenance

_RANK: Final[Mapping[DependencyStatus, int]] = {
    DependencyStatus.KNOWN: 0,
    DependencyStatus.UNCERTAIN: 1,
    DependencyStatus.UNSUPPORTED: 2,
}

_FROM_RESOLUTION: Final[Mapping[ReferenceResolution, DependencyStatus]] = {
    ReferenceResolution.SUPPORTED: DependencyStatus.KNOWN,
    ReferenceResolution.UNKNOWN: DependencyStatus.UNCERTAIN,
    ReferenceResolution.UNSUPPORTED: DependencyStatus.UNSUPPORTED,
}

_FROM_SUPPORT: Final[Mapping[ResourceSupport, DependencyStatus]] = {
    ResourceSupport.SUPPORTED: DependencyStatus.KNOWN,
    ResourceSupport.UNKNOWN: DependencyStatus.UNCERTAIN,
    ResourceSupport.UNSUPPORTED: DependencyStatus.UNSUPPORTED,
}


def worst(*statuses: DependencyStatus) -> DependencyStatus:
    """The worst of the statuses, KNOWN < UNCERTAIN < UNSUPPORTED (the order P3a uses)."""
    return max(statuses, key=_RANK.__getitem__, default=DependencyStatus.KNOWN)


def status_of_resolution(resolution: ReferenceResolution) -> DependencyStatus:
    return _FROM_RESOLUTION[resolution]


def status_of_support(support: ResourceSupport) -> DependencyStatus:
    return _FROM_SUPPORT[support]


@dataclass(frozen=True)
class EdgeDraft:
    """An edge before duplicates are collapsed."""

    source_node_id: str
    target_node_id: str
    edge_type: EdgeType
    relationship: Relationship
    status: DependencyStatus
    attributes: Mapping[str, Any]
    rule: DerivationRule
    source_fact: str
    target_fact: str
    provenance: tuple[Provenance, ...]

    def key(self) -> str:
        return edge_key_of(
            self.source_node_id,
            self.edge_type,
            self.relationship,
            self.target_node_id,
            freeze_json(self.attributes),
        )

    def order(self) -> tuple[str, str, str]:
        """Which draft of one key supplies the evidence: the first in this order."""
        return (self.rule.value, self.source_fact, self.target_fact)


class Parts:
    """The nodes and edge drafts a build collects."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._drafts: list[EdgeDraft] = []

    def add_node(self, node: GraphNode) -> None:
        """Add a node. The same node again is harmless; a different one under its id is not."""
        known = self._nodes.get(node.node_id)
        if known is None:
            self._nodes[node.node_id] = node
        elif known != node:
            raise DependencyInputError(f"two different nodes with the id {node.node_id!r}")

    def add_edge(self, draft: EdgeDraft) -> None:
        self._drafts.append(draft)

    @property
    def nodes(self) -> tuple[GraphNode, ...]:
        return tuple(self._nodes[node_id] for node_id in sorted(self._nodes))

    @property
    def drafts(self) -> tuple[EdgeDraft, ...]:
        return tuple(self._drafts)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes


def finalize(drafts: Iterable[EdgeDraft]) -> tuple[GraphEdge, ...]:
    """The edges of the drafts, duplicates collapsed, sorted by edge key."""
    groups: dict[str, list[EdgeDraft]] = {}
    for draft in drafts:
        groups.setdefault(draft.key(), []).append(draft)
    edges: list[GraphEdge] = []
    for key in sorted(groups):
        group = sorted(groups[key], key=EdgeDraft.order)
        first = group[0]
        status = worst(*(draft.status for draft in group))
        edges.append(
            GraphEdge.create(
                source_node_id=first.source_node_id,
                target_node_id=first.target_node_id,
                edge_type=first.edge_type,
                relationship=first.relationship,
                status=status,
                attributes=first.attributes,
                evidence=DependencyEvidence(
                    source=first.source_node_id,
                    target=first.target_node_id,
                    edge_type=first.edge_type,
                    relationship=first.relationship,
                    source_fact=first.source_fact,
                    target_fact=first.target_fact,
                    derivation_rule=first.rule,
                    status=status,
                ),
                provenance=first.provenance,
            )
        )
    return tuple(edges)
