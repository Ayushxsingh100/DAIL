"""Invariant scope and semantic edges (Doc 07 §19, §23; C-134).

Each ``Invariant`` is a node ``INVARIANT:<id>:<version>``. Scope edges connect it to every resource
it names: by address (``scope.resources``) or by type (``scope.resource_types``), unsupported
resources and placeholders of a scoped type included. An address that the state does not hold
(the endpoint of INV-FUNC-001 after a candidate deletes the database) is an UNCERTAIN edge to an
``absent`` node, never silence. Semantic edges connect a functional invariant to the source and
destination of its ``SemanticBinding`` and to ``SEMANTIC:<PROTOCOL>/<port>``.

The network and security context of INV-FUNC-001 (subnet, VPC, security groups, rules, routes) is
not materialised here: it is reachable from the endpoints through the reference and infrastructure
edges, and which of it matters is Impact's policy (C-134, Doc 08 §10, §15). No edge carries an
impact flag.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from core.dependency.edges import EdgeDraft, Parts, status_of_support, worst
from core.dependency.errors import DependencyInputError
from core.dependency.index import StateIndex
from core.dependency.nodes import invariant_node, outside_node, port_node, unresolved_node
from core.dependency.references import target_fact
from core.dependency.versions import GRAPH_ALGORITHM_VERSION
from core.domain.enums import DependencyStatus, InvariantCategory, ProvenanceSourceKind
from core.domain.graph import (
    DerivationRule,
    EdgeType,
    Relationship,
    invariant_node_id,
    resource_node_id,
)
from core.domain.invariant import Invariant
from core.domain.values import Provenance

_PROTOCOL: Final = re.compile(r"[A-Z0-9]+")
_MAX_PORT: Final = 65535


@dataclass(frozen=True)
class SemanticBinding:
    """The endpoints and port of a functional invariant (the ``S``/``D`` of ``expected.json``).

    ``invariant_id`` applies to every given version of that invariant. ``protocol`` is the
    canonical upper-case protocol token (``TCP``), ``port`` the destination port.
    """

    invariant_id: str
    source: str
    destination: str
    protocol: str
    port: int

    def __post_init__(self) -> None:
        for name in ("invariant_id", "source", "destination"):
            value = getattr(self, name)
            if not isinstance(value, str) or value == "" or value != value.strip():
                raise DependencyInputError(f"SemanticBinding.{name}: must be non-empty text")
        if not isinstance(self.protocol, str) or _PROTOCOL.fullmatch(self.protocol) is None:
            raise DependencyInputError(
                "SemanticBinding.protocol: must be an upper-case token such as TCP"
            )
        if (
            not isinstance(self.port, int)
            or isinstance(self.port, bool)
            or not 0 <= self.port <= _MAX_PORT
        ):
            raise DependencyInputError(f"SemanticBinding.port: must be 0..{_MAX_PORT}")

    def sort_key(self) -> tuple[str, str, str, str, int]:
        return (self.invariant_id, self.source, self.destination, self.protocol, self.port)


def check_invariants(
    invariants: Iterable[Invariant], bindings: Iterable[SemanticBinding]
) -> tuple[tuple[Invariant, ...], tuple[SemanticBinding, ...]]:
    """The invariants and bindings, sorted, after the C-131 checks: every item has its type,
    ``(invariant_id, version)`` is unique, and every binding names a given invariant."""
    given = tuple(invariants)
    bound = tuple(bindings)
    if not all(isinstance(item, Invariant) for item in given):
        raise DependencyInputError("the invariants must be Invariant objects")
    if not all(isinstance(item, SemanticBinding) for item in bound):
        raise DependencyInputError("the bindings must be SemanticBinding objects")
    keys = [(item.invariant_id, item.version) for item in given]
    if len(keys) != len(set(keys)):
        raise DependencyInputError("duplicate (invariant_id, version) among the invariants")
    ids = {item.invariant_id for item in given}
    for binding in bound:
        if binding.invariant_id not in ids:
            raise DependencyInputError(
                f"a binding names {binding.invariant_id!r}, which is not a given invariant"
            )
    ordered = tuple(sorted(given, key=lambda item: (item.invariant_id, item.version)))
    return ordered, tuple(sorted(set(bound), key=SemanticBinding.sort_key))


class _Emitter:
    def __init__(
        self, invariant: Invariant, index: StateIndex, parts: Parts, now: datetime
    ) -> None:
        self.invariant = invariant
        self.index = index
        self.parts = parts
        self.node_id = invariant_node_id(invariant.invariant_id, invariant.version)
        self.provenance = Provenance(
            source_kind=ProvenanceSourceKind.DERIVED,
            source_component="core.dependency",
            source_reference=self.node_id,
            observed_at=now,
            algorithm_version=GRAPH_ALGORITHM_VERSION,
            transformation_steps=("invariant_definition", "dependency_graph"),
        )

    def label(self) -> str:
        return f"{self.invariant.invariant_id} v{self.invariant.version}"

    def edge(
        self,
        edge_type: EdgeType,
        relationship: Relationship,
        target_id: str,
        status: DependencyStatus,
        rule: DerivationRule,
        source_fact: str,
        target_text: str,
    ) -> None:
        self.parts.add_edge(
            EdgeDraft(
                source_node_id=self.node_id,
                target_node_id=target_id,
                edge_type=edge_type,
                relationship=relationship,
                status=status,
                attributes={},
                rule=rule,
                source_fact=source_fact,
                target_fact=target_text,
                provenance=(self.provenance,),
            )
        )

    def to_address(
        self,
        edge_type: EdgeType,
        relationship: Relationship,
        address: str,
        rule: DerivationRule,
        source_fact: str,
    ) -> None:
        """An edge to a resource address named by the invariant: the resource, its instances when
        the address is a block, or an ``absent`` node."""
        found = self.index.by_address.get(address)
        if found is not None:
            self.edge(
                edge_type,
                relationship,
                resource_node_id(address),
                status_of_support(found.support_status),
                rule,
                source_fact,
                target_fact(address, self.index),
            )
            return
        instances = self.index.instances_of(address)
        if instances:
            for instance in instances:
                status = worst(
                    DependencyStatus.UNCERTAIN,
                    status_of_support(self.index.by_address[instance].support_status),
                )
                self.edge(
                    edge_type,
                    relationship,
                    resource_node_id(instance),
                    status,
                    DerivationRule.BLOCK_FANOUT,
                    source_fact,
                    f"instance of {address}: {target_fact(instance, self.index)}",
                )
            return
        self.parts.add_node(outside_node(address))
        self.edge(
            edge_type,
            relationship,
            resource_node_id(address),
            DependencyStatus.UNCERTAIN,
            rule,
            source_fact,
            target_fact(address, self.index),
        )


def _scope_edges(emitter: _Emitter) -> None:
    scope = emitter.invariant.scope
    name = emitter.label()
    for address in scope.resources:
        emitter.to_address(
            EdgeType.INVARIANT_SCOPE,
            Relationship.SCOPE,
            address,
            DerivationRule.SCOPE_RESOURCE,
            f"{name} scope.resources names {address}",
        )
    wanted = set(scope.resource_types)
    for resource in emitter.index.sorted_resources():
        if resource.resource_type in wanted:
            emitter.edge(
                EdgeType.INVARIANT_SCOPE,
                Relationship.SCOPE,
                resource_node_id(resource.address),
                status_of_support(resource.support_status),
                DerivationRule.SCOPE_TYPE,
                f"{name} scope.resource_types includes {resource.resource_type}",
                target_fact(resource.address, emitter.index),
            )


def _semantic_edges(emitter: _Emitter, bindings: tuple[SemanticBinding, ...]) -> None:
    name = emitter.label()
    mine = [b for b in bindings if b.invariant_id == emitter.invariant.invariant_id]
    for binding in mine:
        for relationship, address in (
            (Relationship.SOURCE, binding.source),
            (Relationship.DESTINATION, binding.destination),
        ):
            emitter.to_address(
                EdgeType.INVARIANT_SEMANTIC,
                relationship,
                address,
                DerivationRule.SEMANTIC_BINDING,
                f"{name} binding {relationship.value.lower()} is {address}",
            )
        port = port_node(binding.protocol, binding.port)
        emitter.parts.add_node(port)
        emitter.edge(
            EdgeType.INVARIANT_SEMANTIC,
            Relationship.PROTOCOL_PORT,
            port.node_id,
            DependencyStatus.KNOWN,
            DerivationRule.SEMANTIC_BINDING,
            f"{name} binding protocol and port are {binding.protocol}/{binding.port}",
            "protocol and port semantics",
        )
    if not mine and emitter.invariant.category is InvariantCategory.FUNCTIONAL:
        missing = unresolved_node(emitter.invariant.invariant_id, "binding")
        emitter.parts.add_node(missing)
        emitter.edge(
            EdgeType.INVARIANT_SEMANTIC,
            Relationship.BINDING,
            missing.node_id,
            DependencyStatus.UNCERTAIN,
            DerivationRule.BINDING_MISSING,
            f"{name} is functional and has no semantic binding",
            "endpoints, protocol and port are not known",
        )


def add_invariant_edges(
    invariants: tuple[Invariant, ...],
    bindings: tuple[SemanticBinding, ...],
    index: StateIndex,
    parts: Parts,
    *,
    now: datetime,
) -> None:
    """Add the invariant nodes and their scope and semantic edges. Inputs are already checked."""
    for invariant in invariants:
        parts.add_node(invariant_node(invariant))
        emitter = _Emitter(invariant, index, parts, now)
        _scope_edges(emitter)
        _semantic_edges(emitter, bindings)
