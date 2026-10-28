"""Hand-built graph objects for the dependency tests (P3c). Not a test module.

Everything is deterministic: ids come from ``tests.domain_builders.uid`` and timestamps from ``at``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from core.domain.enums import DependencyStatus
from core.domain.graph import (
    DependencyEvidence,
    DependencyGraph,
    DerivationRule,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    Relationship,
    invariant_node_id,
    resource_node_id,
    semantic_node_id,
)
from tests.domain_builders import at, provenance, uid

NORMALIZATION = "dail-tf-norm-1"
ALGORITHM = "dail-graph-1"
NOW = at(0)
STATE = uid(1)


def rnode(address: str, **attributes: Any) -> GraphNode:
    base = {
        "kind": "resource",
        "resource_type": address.split(".")[0],
        "support_status": "SUPPORTED",
    }
    return GraphNode(
        node_id=resource_node_id(address),
        node_type=NodeType.RESOURCE,
        ref_id=address,
        attributes={**base, **attributes},
    )


def inode(invariant_id: str = "INV-SEC-001", version: int = 1) -> GraphNode:
    return GraphNode(
        node_id=invariant_node_id(invariant_id, version),
        node_type=NodeType.INVARIANT,
        ref_id=invariant_id,
        attributes={"category": "SECURITY", "name": invariant_id},
    )


def snode(token: str, kind: str = "unresolved") -> GraphNode:
    return GraphNode(
        node_id=semantic_node_id(token),
        node_type=NodeType.SEMANTIC,
        ref_id=token,
        attributes={"kind": kind},
    )


def edge(
    source: str,
    target: str,
    *,
    edge_type: EdgeType = EdgeType.TERRAFORM_REFERENCE,
    relationship: Relationship = Relationship.REFERENCE,
    status: DependencyStatus = DependencyStatus.KNOWN,
    attributes: Mapping[str, Any] | None = None,
    rule: DerivationRule = DerivationRule.REFERENCE,
    source_fact: str = "a = b",
    target_fact: str = "b is SUPPORTED",
) -> GraphEdge:
    """An edge between two node ids."""
    return GraphEdge.create(
        source_node_id=source,
        target_node_id=target,
        edge_type=edge_type,
        relationship=relationship,
        status=status,
        attributes={"source_attribute": "x"} if attributes is None else attributes,
        evidence=DependencyEvidence(
            source=source,
            target=target,
            edge_type=edge_type,
            relationship=relationship,
            source_fact=source_fact,
            target_fact=target_fact,
            derivation_rule=rule,
            status=status,
        ),
        provenance=(provenance(),),
    )


def ref_edge(source: str, target: str, **kwargs: Any) -> GraphEdge:
    """A TERRAFORM_REFERENCE edge between two resource addresses."""
    return edge(resource_node_id(source), resource_node_id(target), **kwargs)


def graph(
    nodes: Iterable[GraphNode],
    edges: Iterable[GraphEdge],
    *,
    state_id: str = STATE,
    normalization_version: str = NORMALIZATION,
    algorithm_version: str = ALGORITHM,
    now: datetime = NOW,
    graph_id: str | None = None,
) -> DependencyGraph:
    return DependencyGraph.create(
        state_id=state_id,
        nodes=nodes,
        edges=edges,
        normalization_version=normalization_version,
        algorithm_version=algorithm_version,
        now=now,
        graph_id=graph_id,
    )


def triangle() -> DependencyGraph:
    """a -> b, b -> c, c -> a: a cycle, which the type allows."""
    return graph(
        [rnode("t.a"), rnode("t.b"), rnode("t.c")],
        [ref_edge("t.a", "t.b"), ref_edge("t.b", "t.c"), ref_edge("t.c", "t.a")],
    )
