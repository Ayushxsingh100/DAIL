"""Reference edges: every ``Reference`` of every resource is an edge (Doc 07 §15; C-133 items 1-3).

"References are not silently discarded." A reference whose target is a data source, a module object
or an address the state does not hold still gets an edge to a node of that kind. A reference to a
block whose instance could not be fixed fans out to every instance in the state, so the dependency
is never hidden behind a dangling key-less node (Doc 07 §24).
"""

from __future__ import annotations

from typing import Any, NamedTuple

from core.dependency.edges import (
    EdgeDraft,
    Parts,
    status_of_resolution,
    status_of_support,
    worst,
)
from core.dependency.index import StateIndex
from core.dependency.nodes import outside_node
from core.domain.enums import DependencyStatus
from core.domain.graph import DerivationRule, EdgeType, Relationship, resource_node_id
from core.domain.resource import Resource
from core.domain.values import Reference


class _Planned(NamedTuple):
    address: str
    rule: DerivationRule
    attributes: dict[str, Any]
    status: DependencyStatus


def target_fact(address: str, index: StateIndex) -> str:
    """Short stable text of what a target address is in the state."""
    found = index.by_address.get(address)
    if found is not None:
        return f"resource {found.resource_type}, {found.support_status.value}"
    node = outside_node(address)
    return f"{node.attributes['kind']} {node.attributes['resource_type']}, not in the state"


def source_fact(reference: Reference) -> str:
    return (
        f"{reference.source_address}.{reference.source_attribute} -> {reference.target_address} "
        f"({reference.reference_type}, {reference.resolution_status.value})"
    )


def _plan(
    resource: Resource, reference: Reference, index: StateIndex, parts: Parts
) -> list[_Planned]:
    """The edges one reference gives: one to its target, one per instance of a block-level target,
    or one to a node for a target that the state does not hold."""
    attributes = {
        "source_attribute": reference.source_attribute,
        "reference_type": reference.reference_type,
    }
    base = worst(
        status_of_resolution(reference.resolution_status),
        status_of_support(resource.support_status),
    )
    address = reference.target_address
    found = index.by_address.get(address)
    if found is not None:
        status = worst(base, status_of_support(found.support_status))
        return [_Planned(address, DerivationRule.REFERENCE, attributes, status)]
    instances = index.instances_of(address)
    if instances:
        fanned = {**attributes, "via_block": address}
        return [
            _Planned(
                instance,
                DerivationRule.BLOCK_FANOUT,
                fanned,
                worst(
                    base,
                    DependencyStatus.UNCERTAIN,
                    status_of_support(index.by_address[instance].support_status),
                ),
            )
            for instance in instances
        ]
    parts.add_node(outside_node(address))
    status = worst(base, DependencyStatus.UNCERTAIN)
    return [_Planned(address, DerivationRule.REFERENCE, attributes, status)]


def add_reference_edges(resource: Resource, index: StateIndex, parts: Parts) -> None:
    """Add the TERRAFORM_REFERENCE edges of one resource (and the nodes they end at)."""
    for reference in resource.references:
        for planned in _plan(resource, reference, index, parts):
            parts.add_edge(
                EdgeDraft(
                    source_node_id=resource_node_id(resource.address),
                    target_node_id=resource_node_id(planned.address),
                    edge_type=EdgeType.TERRAFORM_REFERENCE,
                    relationship=Relationship.REFERENCE,
                    status=planned.status,
                    attributes=planned.attributes,
                    rule=planned.rule,
                    source_fact=source_fact(reference),
                    target_fact=target_fact(planned.address, index),
                    provenance=(resource.provenance,),
                )
            )
