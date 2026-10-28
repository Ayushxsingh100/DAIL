"""Dependency graph nodes, edges, evidence and the graph itself (Doc 05 §11, Doc 07 §14, §20-§22,
§27-§29; C-132; P3c step 2).

Doc 05 §11: "The graph is a derived artifact. It must be reproducible from normalized resources,
supported rules, and invariant definitions." Doc 07 §24: NO EDGE is not NO DEPENDENCY, so the graph
type carries UNCERTAIN and UNSUPPORTED edges as first-class values (``DependencyStatus``).

Names (C-132):

| Concept | Field | Values |
|---|---|---|
| node | ``node_id`` | ``RESOURCE:<address>``, ``INVARIANT:<id>:<version>``, ``SEMANTIC:<token>`` |
| edge class | ``edge_type`` | Doc 05's four values (``EdgeType``) |
| typed relationship | ``relationship`` | Doc 07 §16 names, ``REFERENCE``, ``SCOPE``, ... |
| edge identity | ``edge_key`` | SHA-256 of source, class, relationship, target, attributes |

Doc 05's UUID ``edge_id`` is a persistence identifier (Doc 07 §21) and is not created here: nothing
persists graphs, and ``edge_key`` is the semantic identity. The status of an edge is **not** part of
its key (Doc 07 §22), so one relationship cannot appear twice with two statuses.

``DependencyGraph`` is frozen. Nodes are sorted by ``node_id`` and edges by ``edge_key`` (Doc 07
§28). ``graph_hash`` is structural: it covers the algorithm version, the normalization version, the
nodes and the edges (key, endpoints, class, relationship, status, attributes) and nothing else, so
``graph_id``, ``state_id``, ``created_at``, provenance and evidence text never reach it (Doc 05
§27). The constructor recomputes every ``edge_key`` and the ``graph_hash`` (``HashMismatchError``).
Cycles are allowed: the type describes configuration evidence, and the traversal must survive them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from core.domain.enums import DependencyStatus
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.hashing import content_hash
from core.domain.ids import new_uuid, require_uuid
from core.domain.jsonvalue import (
    freeze_json,
    iso_utc,
    parse_enum,
    parse_utc,
    require_enum,
    require_keys,
    require_text,
    thaw_json,
    utc,
    validate_json,
)
from core.domain.values import Provenance


class NodeType(StrEnum):
    """Doc 05 §11."""

    RESOURCE = "RESOURCE"
    INVARIANT = "INVARIANT"
    SEMANTIC = "SEMANTIC"


class EdgeType(StrEnum):
    """The edge class (Doc 05 §11, Doc 07 §14)."""

    TERRAFORM_REFERENCE = "TERRAFORM_REFERENCE"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    INVARIANT_SCOPE = "INVARIANT_SCOPE"
    INVARIANT_SEMANTIC = "INVARIANT_SEMANTIC"


class Relationship(StrEnum):
    """The typed relationship of an edge (C-132): the nine Doc 07 §16 types, the RDS subnet
    placement of C-136 (not a §16 row) and the generic ones."""

    REFERENCE = "REFERENCE"
    SUBNET_BELONGS_TO_VPC = "SUBNET_BELONGS_TO_VPC"
    ROUTE_TABLE_BELONGS_TO_VPC = "ROUTE_TABLE_BELONGS_TO_VPC"
    ASSOCIATES_SUBNET = "ASSOCIATES_SUBNET"
    ASSOCIATES_ROUTE_TABLE = "ASSOCIATES_ROUTE_TABLE"
    IGW_ATTACHED_TO_VPC = "IGW_ATTACHED_TO_VPC"
    INSTANCE_IN_SUBNET = "INSTANCE_IN_SUBNET"
    INSTANCE_USES_SECURITY_GROUP = "INSTANCE_USES_SECURITY_GROUP"
    DB_USES_SECURITY_GROUP = "DB_USES_SECURITY_GROUP"
    RULE_BELONGS_TO_SECURITY_GROUP = "RULE_BELONGS_TO_SECURITY_GROUP"
    DB_SUBNET_PLACEMENT = "DB_SUBNET_PLACEMENT"
    SCOPE = "SCOPE"
    SOURCE = "SOURCE"
    DESTINATION = "DESTINATION"
    PROTOCOL_PORT = "PROTOCOL_PORT"
    BINDING = "BINDING"


INFRASTRUCTURE_RELATIONSHIPS: Final = frozenset(
    {
        Relationship.SUBNET_BELONGS_TO_VPC,
        Relationship.ROUTE_TABLE_BELONGS_TO_VPC,
        Relationship.ASSOCIATES_SUBNET,
        Relationship.ASSOCIATES_ROUTE_TABLE,
        Relationship.IGW_ATTACHED_TO_VPC,
        Relationship.INSTANCE_IN_SUBNET,
        Relationship.INSTANCE_USES_SECURITY_GROUP,
        Relationship.DB_USES_SECURITY_GROUP,
        Relationship.RULE_BELONGS_TO_SECURITY_GROUP,
        Relationship.DB_SUBNET_PLACEMENT,
    }
)

RELATIONSHIPS_BY_TYPE: Final[Mapping[EdgeType, frozenset[Relationship]]] = MappingProxyType(
    {
        EdgeType.TERRAFORM_REFERENCE: frozenset({Relationship.REFERENCE}),
        EdgeType.INFRASTRUCTURE: INFRASTRUCTURE_RELATIONSHIPS,
        EdgeType.INVARIANT_SCOPE: frozenset({Relationship.SCOPE}),
        EdgeType.INVARIANT_SEMANTIC: frozenset(
            {
                Relationship.SOURCE,
                Relationship.DESTINATION,
                Relationship.PROTOCOL_PORT,
                Relationship.BINDING,
            }
        ),
    }
)


class DerivationRule(StrEnum):
    """The closed vocabulary of ``DependencyEvidence.derivation_rule`` (C-133 item 7)."""

    REFERENCE = "REFERENCE"
    BLOCK_FANOUT = "BLOCK_FANOUT"
    SLOT_REFERENCE = "SLOT_REFERENCE"
    SLOT_UNKNOWN_VALUE = "SLOT_UNKNOWN_VALUE"
    SLOT_UNSUPPORTED_VALUE = "SLOT_UNSUPPORTED_VALUE"
    EXTERNAL_OBJECT = "EXTERNAL_OBJECT"
    UNSET = "UNSET"
    TYPE_MISMATCH = "TYPE_MISMATCH"
    SCOPE_RESOURCE = "SCOPE_RESOURCE"
    SCOPE_TYPE = "SCOPE_TYPE"
    SEMANTIC_BINDING = "SEMANTIC_BINDING"
    BINDING_MISSING = "BINDING_MISSING"


DERIVATION_DEFINITIONS: Final[Mapping[DerivationRule, str]] = MappingProxyType(
    {
        DerivationRule.REFERENCE: "An explicit Terraform reference of the source resource.",
        DerivationRule.BLOCK_FANOUT: (
            "The target names a resource block whose instance could not be fixed; one edge per "
            "instance in the state."
        ),
        DerivationRule.SLOT_REFERENCE: "A relationship slot holds a reference to a typed target.",
        DerivationRule.SLOT_UNKNOWN_VALUE: "A relationship slot holds a value that is unknown.",
        DerivationRule.SLOT_UNSUPPORTED_VALUE: (
            "A relationship slot holds a value that DAIL does not support."
        ),
        DerivationRule.EXTERNAL_OBJECT: (
            "A relationship slot holds a literal identifier of an object outside the model."
        ),
        DerivationRule.UNSET: "A relationship slot is unset, so the relationship is not visible.",
        DerivationRule.TYPE_MISMATCH: "A relationship slot references a resource of another type.",
        DerivationRule.SCOPE_RESOURCE: "The invariant scope names this resource address.",
        DerivationRule.SCOPE_TYPE: "The invariant scope names this resource type.",
        DerivationRule.SEMANTIC_BINDING: "A semantic binding of the invariant names this endpoint.",
        DerivationRule.BINDING_MISSING: "A functional invariant has no semantic binding.",
    }
)

_INVARIANT_NODE_ID = re.compile(r"INVARIANT:(.+):([1-9][0-9]*)")


def resource_node_id(address: str) -> str:
    return f"RESOURCE:{address}"


def invariant_node_id(invariant_id: str, version: int) -> str:
    return f"INVARIANT:{invariant_id}:{version}"


def semantic_node_id(token: str) -> str:
    return f"SEMANTIC:{token}"


def _json_object(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DomainValidationError(f"{field}: must be a JSON object (Doc 05 §11)")
    validate_json(value, field)
    frozen = freeze_json(value)
    assert isinstance(frozen, Mapping)
    return frozen


# --- Node -----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphNode:
    """One node (Doc 05 §11). ``node_id`` is semantic; database UUIDs are not (Doc 07 §21)."""

    node_id: str
    node_type: NodeType
    ref_id: str
    attributes: Mapping[str, Any]

    def __post_init__(self) -> None:
        require_text(self.node_id, "GraphNode.node_id")
        require_enum(self.node_type, NodeType, "GraphNode.node_type")
        require_text(self.ref_id, "GraphNode.ref_id")
        self._check_id_format()
        object.__setattr__(
            self, "attributes", _json_object(self.attributes, "GraphNode.attributes")
        )

    def _check_id_format(self) -> None:
        if self.node_type is NodeType.RESOURCE:
            expected = resource_node_id(self.ref_id)
        elif self.node_type is NodeType.SEMANTIC:
            expected = semantic_node_id(self.ref_id)
        else:
            match = _INVARIANT_NODE_ID.fullmatch(self.node_id)
            if match is None or match.group(1) != self.ref_id:
                raise DomainValidationError(
                    f"GraphNode: {self.node_id!r} is not INVARIANT:{self.ref_id}:<version> "
                    "(Doc 07 §21)"
                )
            return
        if self.node_id != expected:
            raise DomainValidationError(
                f"GraphNode: node_id {self.node_id!r} does not match {self.node_type.value} "
                f"ref_id {self.ref_id!r} (Doc 07 §21)"
            )

    def sort_key(self) -> str:
        return self.node_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "ref_id": self.ref_id,
            "attributes": thaw_json(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GraphNode:
        fields = require_keys(data, ("node_id", "node_type", "ref_id", "attributes"), "GraphNode")
        return cls(
            node_id=fields["node_id"],
            node_type=parse_enum(fields["node_type"], NodeType, "GraphNode.node_type"),
            ref_id=fields["ref_id"],
            attributes=fields["attributes"],
        )


# --- Evidence -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DependencyEvidence:
    """Why an edge exists (Doc 07 §27): the source fact, the target fact and the derivation rule.

    The two facts are short, stable text. ``derivation_rule`` comes from the closed vocabulary
    ``DerivationRule``.
    """

    source: str
    target: str
    edge_type: EdgeType
    relationship: Relationship
    source_fact: str
    target_fact: str
    derivation_rule: DerivationRule
    status: DependencyStatus

    def __post_init__(self) -> None:
        for name in ("source", "target", "source_fact", "target_fact"):
            require_text(getattr(self, name), f"DependencyEvidence.{name}")
        require_enum(self.edge_type, EdgeType, "DependencyEvidence.edge_type")
        require_enum(self.relationship, Relationship, "DependencyEvidence.relationship")
        require_enum(self.derivation_rule, DerivationRule, "DependencyEvidence.derivation_rule")
        require_enum(self.status, DependencyStatus, "DependencyEvidence.status")

    def sort_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.derivation_rule.value,
            self.source_fact,
            self.target_fact,
            self.source,
            self.target,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type.value,
            "relationship": self.relationship.value,
            "source_fact": self.source_fact,
            "target_fact": self.target_fact,
            "derivation_rule": self.derivation_rule.value,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DependencyEvidence:
        fields = require_keys(
            data,
            (
                "source",
                "target",
                "edge_type",
                "relationship",
                "source_fact",
                "target_fact",
                "derivation_rule",
                "status",
            ),
            "DependencyEvidence",
        )
        return cls(
            source=fields["source"],
            target=fields["target"],
            edge_type=parse_enum(fields["edge_type"], EdgeType, "DependencyEvidence.edge_type"),
            relationship=parse_enum(
                fields["relationship"], Relationship, "DependencyEvidence.relationship"
            ),
            source_fact=fields["source_fact"],
            target_fact=fields["target_fact"],
            derivation_rule=parse_enum(
                fields["derivation_rule"], DerivationRule, "DependencyEvidence.derivation_rule"
            ),
            status=parse_enum(fields["status"], DependencyStatus, "DependencyEvidence.status"),
        )


# --- Edge -----------------------------------------------------------------------------------------


def edge_key_of(
    source_node_id: str,
    edge_type: EdgeType,
    relationship: Relationship,
    target_node_id: str,
    attributes: Mapping[str, Any],
) -> str:
    """Doc 07 §22: SHA-256 of source, class, relationship, target and attributes (C-132)."""
    return content_hash(
        {
            "source_node_id": source_node_id,
            "edge_type": edge_type.value,
            "relationship": relationship.value,
            "target_node_id": target_node_id,
            "attributes": thaw_json(attributes),
        }
    )


@dataclass(frozen=True)
class GraphEdge:
    """One directed edge, source "depends on" target (Doc 05 §11). Create it with ``create``."""

    edge_key: str
    source_node_id: str
    target_node_id: str
    edge_type: EdgeType
    relationship: Relationship
    status: DependencyStatus
    attributes: Mapping[str, Any]
    evidence: DependencyEvidence
    provenance: tuple[Provenance, ...]

    def __post_init__(self) -> None:
        require_text(self.source_node_id, "GraphEdge.source_node_id")
        require_text(self.target_node_id, "GraphEdge.target_node_id")
        require_enum(self.edge_type, EdgeType, "GraphEdge.edge_type")
        require_enum(self.relationship, Relationship, "GraphEdge.relationship")
        require_enum(self.status, DependencyStatus, "GraphEdge.status")
        if self.relationship not in RELATIONSHIPS_BY_TYPE[self.edge_type]:
            raise DomainValidationError(
                f"GraphEdge: relationship {self.relationship.value} does not belong to edge "
                f"type {self.edge_type.value} (C-132)"
            )
        object.__setattr__(
            self, "attributes", _json_object(self.attributes, "GraphEdge.attributes")
        )
        if not isinstance(self.evidence, DependencyEvidence):
            raise DomainValidationError("GraphEdge.evidence: must be a DependencyEvidence")
        self._check_evidence()
        if isinstance(self.provenance, str) or not isinstance(self.provenance, list | tuple):
            raise DomainValidationError("GraphEdge.provenance: must be a list of Provenance")
        if len(self.provenance) == 0 or not all(isinstance(p, Provenance) for p in self.provenance):
            raise DomainValidationError(
                "GraphEdge.provenance: must hold at least one Provenance (Doc 05 §6)"
            )
        object.__setattr__(self, "provenance", tuple(self.provenance))
        expected = edge_key_of(
            self.source_node_id,
            self.edge_type,
            self.relationship,
            self.target_node_id,
            self.attributes,
        )
        if self.edge_key != expected:
            raise HashMismatchError(
                f"DATA-INT-010: GraphEdge {self.source_node_id} -> {self.target_node_id} "
                "edge_key does not match its content"
            )

    def _check_evidence(self) -> None:
        evidence = self.evidence
        if (
            evidence.source != self.source_node_id
            or evidence.target != self.target_node_id
            or evidence.edge_type is not self.edge_type
            or evidence.relationship is not self.relationship
            or evidence.status is not self.status
        ):
            raise DomainValidationError(
                f"GraphEdge: the evidence of {self.source_node_id} -> {self.target_node_id} "
                "does not describe this edge (Doc 07 §27)"
            )

    @classmethod
    def create(
        cls,
        *,
        source_node_id: str,
        target_node_id: str,
        edge_type: EdgeType,
        relationship: Relationship,
        status: DependencyStatus,
        attributes: Mapping[str, Any],
        evidence: DependencyEvidence,
        provenance: Iterable[Provenance],
    ) -> GraphEdge:
        """Build an edge and compute its key."""
        require_enum(edge_type, EdgeType, "GraphEdge.edge_type")
        require_enum(relationship, Relationship, "GraphEdge.relationship")
        frozen = _json_object(attributes, "GraphEdge.attributes")
        return cls(
            edge_key=edge_key_of(source_node_id, edge_type, relationship, target_node_id, frozen),
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            edge_type=edge_type,
            relationship=relationship,
            status=status,
            attributes=frozen,
            evidence=evidence,
            provenance=tuple(provenance),
        )

    def sort_key(self) -> str:
        return self.edge_key

    def structural(self) -> dict[str, Any]:
        """The part of the edge that reaches the graph hash (no evidence, no provenance)."""
        return {
            "edge_key": self.edge_key,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "edge_type": self.edge_type.value,
            "relationship": self.relationship.value,
            "status": self.status.value,
            "attributes": thaw_json(self.attributes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.structural(),
            "evidence": self.evidence.to_dict(),
            "provenance": [item.to_dict() for item in self.provenance],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GraphEdge:
        fields = require_keys(
            data,
            (
                "edge_key",
                "source_node_id",
                "target_node_id",
                "edge_type",
                "relationship",
                "status",
                "attributes",
                "evidence",
                "provenance",
            ),
            "GraphEdge",
        )
        raw_provenance = fields["provenance"]
        if not isinstance(raw_provenance, list | tuple):
            raise DomainValidationError("GraphEdge.provenance: must be a list")
        return cls(
            edge_key=fields["edge_key"],
            source_node_id=fields["source_node_id"],
            target_node_id=fields["target_node_id"],
            edge_type=parse_enum(fields["edge_type"], EdgeType, "GraphEdge.edge_type"),
            relationship=parse_enum(fields["relationship"], Relationship, "GraphEdge.relationship"),
            status=parse_enum(fields["status"], DependencyStatus, "GraphEdge.status"),
            attributes=fields["attributes"],
            evidence=DependencyEvidence.from_dict(fields["evidence"]),
            provenance=tuple(Provenance.from_dict(item) for item in raw_provenance),
        )


# --- Graph ----------------------------------------------------------------------------------------


def _hash_payload(
    algorithm_version: str,
    normalization_version: str,
    nodes: Iterable[GraphNode],
    edges: Iterable[GraphEdge],
) -> dict[str, Any]:
    return {
        "algorithm_version": algorithm_version,
        "normalization_version": normalization_version,
        "nodes": [node.to_dict() for node in nodes],
        "edges": [edge.structural() for edge in edges],
    }


@dataclass(frozen=True)
class DependencyGraph:
    """The dependency graph of one state (Doc 05 §11). Create it with ``DependencyGraph.create``."""

    graph_id: str
    state_id: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    graph_version: str
    normalization_version: str
    algorithm_version: str
    created_at: datetime
    graph_hash: str

    def __post_init__(self) -> None:
        require_uuid(self.graph_id, "DependencyGraph.graph_id")
        require_uuid(self.state_id, "DependencyGraph.state_id")
        require_text(self.graph_version, "DependencyGraph.graph_version")
        require_text(self.normalization_version, "DependencyGraph.normalization_version")
        require_text(self.algorithm_version, "DependencyGraph.algorithm_version")
        if self.graph_version != self.algorithm_version:
            raise DomainValidationError(
                "DependencyGraph.graph_version: must equal algorithm_version (C-132)"
            )
        object.__setattr__(self, "created_at", utc(self.created_at, "DependencyGraph.created_at"))
        nodes = self._checked_tuple(self.nodes, GraphNode, "nodes")
        edges = self._checked_tuple(self.edges, GraphEdge, "edges")
        self._check_nodes(nodes)
        self._check_edges(nodes, edges)
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)
        expected = content_hash(
            _hash_payload(self.algorithm_version, self.normalization_version, nodes, edges)
        )
        if self.graph_hash != expected:
            raise HashMismatchError(
                f"DATA-INT-010: DependencyGraph {self.graph_id} graph_hash does not match "
                "its content"
            )

    @staticmethod
    def _checked_tuple[T](value: object, kind: type[T], name: str) -> tuple[T, ...]:
        if isinstance(value, str) or not isinstance(value, list | tuple):
            raise DomainValidationError(f"DependencyGraph.{name}: must be a list")
        if not all(isinstance(item, kind) for item in value):
            raise DomainValidationError(
                f"DependencyGraph.{name}: must hold {kind.__name__} objects"
            )
        return tuple(value)

    @staticmethod
    def _check_nodes(nodes: tuple[GraphNode, ...]) -> None:
        ids = [node.node_id for node in nodes]
        if len(ids) != len(set(ids)):
            raise DomainValidationError("DependencyGraph.nodes: duplicate node_id")
        if ids != sorted(ids):
            raise DomainValidationError(
                "DependencyGraph.nodes: must be sorted by node_id (Doc 07 §28)"
            )

    @staticmethod
    def _check_edges(nodes: tuple[GraphNode, ...], edges: tuple[GraphEdge, ...]) -> None:
        keys = [edge.edge_key for edge in edges]
        if len(keys) != len(set(keys)):
            raise DomainValidationError("DependencyGraph.edges: duplicate edge_key")
        if keys != sorted(keys):
            raise DomainValidationError(
                "DependencyGraph.edges: must be sorted by edge_key (Doc 07 §28)"
            )
        by_id = {node.node_id: node for node in nodes}
        for edge in edges:
            for role, node_id in (("source", edge.source_node_id), ("target", edge.target_node_id)):
                if node_id not in by_id:
                    raise DomainValidationError(
                        f"DependencyGraph.edges: the {role} {node_id!r} of an edge is not a node"
                    )
            wanted = (
                NodeType.RESOURCE
                if edge.edge_type in (EdgeType.TERRAFORM_REFERENCE, EdgeType.INFRASTRUCTURE)
                else NodeType.INVARIANT
            )
            if by_id[edge.source_node_id].node_type is not wanted:
                raise DomainValidationError(
                    f"DependencyGraph.edges: a {edge.edge_type.value} edge must start at a "
                    f"{wanted.value} node, not {edge.source_node_id!r}"
                )

    @classmethod
    def create(
        cls,
        *,
        state_id: str,
        nodes: Iterable[GraphNode],
        edges: Iterable[GraphEdge],
        normalization_version: str,
        algorithm_version: str,
        now: datetime,
        graph_id: str | None = None,
    ) -> DependencyGraph:
        """Sort the nodes and the edges and compute the structural hash."""
        ordered_nodes = tuple(sorted(nodes, key=GraphNode.sort_key))
        ordered_edges = tuple(sorted(edges, key=GraphEdge.sort_key))
        digest = content_hash(
            _hash_payload(algorithm_version, normalization_version, ordered_nodes, ordered_edges)
        )
        return cls(
            graph_id=new_uuid() if graph_id is None else graph_id,
            state_id=state_id,
            nodes=ordered_nodes,
            edges=ordered_edges,
            graph_version=algorithm_version,
            normalization_version=normalization_version,
            algorithm_version=algorithm_version,
            created_at=now,
            graph_hash=digest,
        )

    def node(self, node_id: str) -> GraphNode | None:
        return next((node for node in self.nodes if node.node_id == node_id), None)

    def edges_from(self, node_id: str) -> tuple[GraphEdge, ...]:
        return tuple(edge for edge in self.edges if edge.source_node_id == node_id)

    def edges_to(self, node_id: str) -> tuple[GraphEdge, ...]:
        return tuple(edge for edge in self.edges if edge.target_node_id == node_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "state_id": self.state_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "graph_version": self.graph_version,
            "normalization_version": self.normalization_version,
            "algorithm_version": self.algorithm_version,
            "created_at": iso_utc(self.created_at),
            "graph_hash": self.graph_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DependencyGraph:
        fields = require_keys(
            data,
            (
                "graph_id",
                "state_id",
                "nodes",
                "edges",
                "graph_version",
                "normalization_version",
                "algorithm_version",
                "created_at",
                "graph_hash",
            ),
            "DependencyGraph",
        )
        raw_nodes, raw_edges = fields["nodes"], fields["edges"]
        if not isinstance(raw_nodes, list | tuple) or not isinstance(raw_edges, list | tuple):
            raise DomainValidationError("DependencyGraph: nodes and edges are lists")
        return cls(
            graph_id=fields["graph_id"],
            state_id=fields["state_id"],
            nodes=tuple(GraphNode.from_dict(item) for item in raw_nodes),
            edges=tuple(GraphEdge.from_dict(item) for item in raw_edges),
            graph_version=fields["graph_version"],
            normalization_version=fields["normalization_version"],
            algorithm_version=fields["algorithm_version"],
            created_at=parse_utc(fields["created_at"], "DependencyGraph.created_at"),
            graph_hash=fields["graph_hash"],
        )
