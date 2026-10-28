"""Hand-built graph objects for the dependency tests (P3c). Not a test module.

Everything is deterministic: ids come from ``tests.domain_builders.uid`` and timestamps from ``at``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from core.dependency.edges import Parts, finalize
from core.dependency.index import StateIndex
from core.dependency.nodes import resource_node
from core.dependency.references import add_reference_edges
from core.domain.enums import (
    DependencyStatus,
    ProvenanceSourceKind,
    ReferenceResolution,
    ResourceSupport,
)
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
from core.domain.resource import Resource
from core.domain.values import Provenance, Reference
from core.terraform_model.normalization import normalize_directory
from tests.domain_builders import at, provenance, uid
from tests.identity_builders import normalize, resources_of

__all__ = ["normalize", "resources_of"]

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


def hand_provenance() -> Provenance:
    """Provenance with the normalization version that ``build_graph`` requires."""
    return Provenance(
        source_kind=ProvenanceSourceKind.TERRAFORM_CONFIG,
        source_component="fixture",
        source_reference="main.tf",
        observed_at=at(0),
        normalization_version=NORMALIZATION,
    )


def hand_ref(
    source: str,
    target: str,
    attribute: str = "x",
    resolution: ReferenceResolution = ReferenceResolution.SUPPORTED,
    reference_type: str = "ATTRIBUTE_REFERENCE",
) -> Reference:
    return Reference(
        source_address=source,
        source_attribute=attribute,
        target_address=target,
        reference_type=reference_type,
        resolution_status=resolution,
    )


def hand_resource(
    address: str,
    resource_type: str | None = None,
    *,
    references: Iterable[Reference] = (),
    support: ResourceSupport = ResourceSupport.SUPPORTED,
    attributes: Mapping[str, Any] | None = None,
    security_attributes: Mapping[str, Any] | None = None,
) -> Resource:
    """A resource built by hand, for cases the Terraform front end cannot produce."""
    return Resource.create(
        address=address,
        resource_type=resource_type or address.split(".")[0],
        logical_identity={},
        attributes={} if attributes is None else attributes,
        security_attributes={} if security_attributes is None else security_attributes,
        semantic_attributes={},
        references=references,
        provenance=hand_provenance(),
        support_status=support,
    )


def reference_edges_of(resources: Iterable[Resource]) -> tuple[Parts, tuple[GraphEdge, ...]]:
    """Only the reference edges (step 3): the nodes and the finalized edges."""
    index = StateIndex.of(resources)
    parts = Parts()
    for item in index.sorted_resources():
        parts.add_node(resource_node(item))
    for item in index.sorted_resources():
        add_reference_edges(item, index, parts)
    return parts, finalize(parts.drafts)


FIXTURE_ROOT = Path(__file__).resolve().parents[1]
BASELINE = "fixtures/canonical_regression/baseline"

K, U = DependencyStatus.KNOWN, DependencyStatus.UNSUPPORTED

# The reference edges of the canonical baseline, derived by hand from the .tf text (Doc 07 §15):
# (source, target, status). The subnet group is an unsupported (tolerated) type, so the three
# edges that touch it are UNSUPPORTED (C-133 item 2); the others are KNOWN.
BASELINE_REFERENCE_EDGES: tuple[tuple[str, str, DependencyStatus], ...] = (
    ("aws_subnet.app", "aws_vpc.main", K),
    ("aws_subnet.db_a", "aws_vpc.main", K),
    ("aws_subnet.db_b", "aws_vpc.main", K),
    ("aws_internet_gateway.igw", "aws_vpc.main", K),
    ("aws_route_table.public", "aws_vpc.main", K),
    ("aws_route_table.public", "aws_internet_gateway.igw", K),
    ("aws_route_table_association.app", "aws_subnet.app", K),
    ("aws_route_table_association.app", "aws_route_table.public", K),
    ("aws_security_group.app", "aws_vpc.main", K),
    ("aws_security_group.db", "aws_vpc.main", K),
    ("aws_security_group_rule.app_ssh_public", "aws_security_group.app", K),
    ("aws_security_group_rule.app_egress_all", "aws_security_group.app", K),
    ("aws_security_group_rule.app_to_db_5432", "aws_security_group.db", K),
    ("aws_security_group_rule.app_to_db_5432", "aws_security_group.app", K),
    ("aws_instance.app", "aws_subnet.app", K),
    ("aws_instance.app", "aws_security_group.app", K),
    ("aws_db_subnet_group.db", "aws_subnet.db_a", U),
    ("aws_db_subnet_group.db", "aws_subnet.db_b", U),
    ("aws_db_instance.database", "aws_db_subnet_group.db", U),
    ("aws_db_instance.database", "aws_security_group.db", K),
)

_FIXTURE_CACHE: dict[str, tuple[Resource, ...]] = {}


def fixture_resources(folder: str) -> tuple[Resource, ...]:
    """The normalized resources of a fixture folder (cached; tests only)."""
    if folder not in _FIXTURE_CACHE:
        outcome = normalize_directory(FIXTURE_ROOT / folder, None, now=NOW)
        _FIXTURE_CACHE[folder] = outcome.resources
    return _FIXTURE_CACHE[folder]
