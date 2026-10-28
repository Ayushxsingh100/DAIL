"""Typed infrastructure edges and the explicit handling of unresolved slots (Doc 07 §16, §23-§24;
C-133 items 4, 5 and 7).

For each slot of each resource of the slot's source type (``slots.SLOTS``), every element of the
argument's canonical value is classified:

- S1 a ``Ref`` of the target type: INFRASTRUCTURE edge to it (SLOT_REFERENCE), status by C-133
  item 2.
- S2 an unknown value that is not a ``Ref``: edge to ``SEMANTIC:UNRESOLVED:<addr>#<arg>``,
  UNCERTAIN (SLOT_UNKNOWN_VALUE); an unsupported one: the same node, UNSUPPORTED
  (SLOT_UNSUPPORTED_VALUE).
- S3 a known literal: edge to ``SEMANTIC:EXTERNAL:<addr>#<arg>``, UNSUPPORTED (EXTERNAL_OBJECT).
- S4 nothing in the slot (absent, null or empty): edge to the unresolved node of the slot, UNCERTAIN
  (UNSET).
- A ``Ref`` of another type: no typed edge, an UNCERTAIN edge to the unresolved node
  (TYPE_MISMATCH).

NO EDGE is not NO DEPENDENCY (Doc 07 §24): a slot never ends without an edge. A placeholder source
(unknown instance count) gets S4 edges for every slot of its type; an UNSUPPORTED resource has no
slots. The reference edge of a ``Ref`` always exists as well (``references.py``).
"""

from __future__ import annotations

from collections.abc import Mapping

from core.dependency.addresses import type_of
from core.dependency.edges import (
    EdgeDraft,
    Parts,
    status_of_resolution,
    status_of_support,
    worst,
)
from core.dependency.encoded import (
    Element,
    ElementKind,
    elements_of,
    read_argument,
    render,
    top_level,
)
from core.dependency.index import StateIndex
from core.dependency.nodes import external_node, outside_node, unresolved_node
from core.dependency.references import target_fact
from core.dependency.slots import Slot, reference_arguments_for, slots_for
from core.domain.enums import DependencyStatus, ResourceSupport
from core.domain.graph import (
    DerivationRule,
    EdgeType,
    GraphNode,
    Relationship,
    resource_node_id,
)
from core.domain.resource import Resource

_UNRESOLVED_TARGET = "relationship not visible in the configuration"
_EXTERNAL_TARGET = "object outside the configuration, not in the model"


class _Emitter:
    """Adds the drafts of one resource."""

    def __init__(self, resource: Resource, index: StateIndex, parts: Parts) -> None:
        self.resource = resource
        self.index = index
        self.parts = parts
        self.own = status_of_support(resource.support_status)
        self.references: dict[tuple[str, str], DependencyStatus] = {}
        for reference in resource.references:
            key = (top_level(reference.source_attribute), reference.target_address)
            status = status_of_resolution(reference.resolution_status)
            self.references[key] = worst(status, self.references.get(key, status))

    def draft(
        self,
        *,
        edge_type: EdgeType,
        relationship: Relationship,
        target: GraphNode | str,
        status: DependencyStatus,
        attributes: Mapping[str, object],
        rule: DerivationRule,
        source_fact: str,
        target_fact: str,
    ) -> None:
        if isinstance(target, GraphNode):
            self.parts.add_node(target)
            target_id = target.node_id
        else:
            target_id = target
        self.parts.add_edge(
            EdgeDraft(
                source_node_id=resource_node_id(self.resource.address),
                target_node_id=target_id,
                edge_type=edge_type,
                relationship=relationship,
                status=worst(status, self.own),
                attributes=dict(attributes),
                rule=rule,
                source_fact=source_fact,
                target_fact=target_fact,
                provenance=(self.resource.provenance,),
            )
        )

    def fact(self, argument: str, element: Element) -> str:
        return f"{self.resource.address}.{argument} = {render(element)}"


# --- Typed slots ----------------------------------------------------------------------------------


def _typed_reference(emitter: _Emitter, slot: Slot, argument: str, element: Element) -> None:
    address = element.address
    found = type_of(address)
    fact = emitter.fact(argument, element)
    if found != slot.target_type:
        emitter.draft(
            edge_type=EdgeType.INFRASTRUCTURE,
            relationship=slot.relationship,
            target=unresolved_node(emitter.resource.address, argument),
            status=DependencyStatus.UNCERTAIN,
            attributes={"argument": argument, "reason": f"type_mismatch:{found}"},
            rule=DerivationRule.TYPE_MISMATCH,
            source_fact=fact,
            target_fact=f"expected {slot.target_type}, found {found}",
        )
        return
    target = emitter.index.by_address.get(address)
    if target is None:
        emitter.parts.add_node(outside_node(address))
        target_status = DependencyStatus.UNCERTAIN
    else:
        target_status = status_of_support(target.support_status)
    # the matching Reference decides how well the reference resolved; none means DAIL cannot confirm
    resolved = emitter.references.get((argument, address), DependencyStatus.UNCERTAIN)
    emitter.draft(
        edge_type=EdgeType.INFRASTRUCTURE,
        relationship=slot.relationship,
        target=resource_node_id(address),
        status=worst(resolved, target_status),
        attributes={"argument": argument},
        rule=DerivationRule.SLOT_REFERENCE,
        source_fact=fact,
        target_fact=target_fact(address, emitter.index),
    )


def _typed_unresolved(emitter: _Emitter, slot: Slot, argument: str, element: Element) -> None:
    unsupported = element.kind is ElementKind.UNSUPPORTED
    emitter.draft(
        edge_type=EdgeType.INFRASTRUCTURE,
        relationship=slot.relationship,
        target=unresolved_node(emitter.resource.address, argument),
        status=DependencyStatus.UNSUPPORTED if unsupported else DependencyStatus.UNCERTAIN,
        attributes={"argument": argument, "reason": element.detail},
        rule=(
            DerivationRule.SLOT_UNSUPPORTED_VALUE
            if unsupported
            else DerivationRule.SLOT_UNKNOWN_VALUE
        ),
        source_fact=emitter.fact(argument, element),
        target_fact=f"unresolved: {element.detail}",
    )


def _typed_external(emitter: _Emitter, slot: Slot, argument: str, element: Element) -> None:
    emitter.draft(
        edge_type=EdgeType.INFRASTRUCTURE,
        relationship=slot.relationship,
        target=external_node(emitter.resource.address, argument),
        status=DependencyStatus.UNSUPPORTED,
        attributes={"argument": argument, "reason": element.detail},
        rule=DerivationRule.EXTERNAL_OBJECT,
        source_fact=emitter.fact(argument, element),
        target_fact=_EXTERNAL_TARGET,
    )


def _typed_unset(emitter: _Emitter, slot: Slot, reason: str, fact: str) -> None:
    emitter.draft(
        edge_type=EdgeType.INFRASTRUCTURE,
        relationship=slot.relationship,
        target=unresolved_node(emitter.resource.address, slot.label),
        status=DependencyStatus.UNCERTAIN,
        attributes={"argument": slot.label, "reason": reason},
        rule=DerivationRule.UNSET,
        source_fact=fact,
        target_fact=_UNRESOLVED_TARGET,
    )


def _slot_edges(emitter: _Emitter, slot: Slot) -> None:
    address = emitter.resource.address
    contributed = False
    reasons: set[str] = set()
    for name in slot.arguments:
        argument = read_argument(emitter.resource.attributes, name)
        if not argument.present:
            reasons.add("unset")
            continue
        if argument.form != "ATTRIBUTE":
            contributed = True
            element = Element(ElementKind.UNSUPPORTED, None, f"form:{argument.form}")
            _typed_unresolved(emitter, slot, name, element)
            continue
        elements = elements_of(argument.value)
        live = [element for element in elements if element.kind is not ElementKind.NULL]
        if not live:
            reasons.add("empty" if not elements else "null")
            continue
        contributed = True
        for element in live:
            if element.kind is ElementKind.REF:
                _typed_reference(emitter, slot, name, element)
            elif element.kind is ElementKind.LITERAL:
                _typed_external(emitter, slot, name, element)
            else:
                _typed_unresolved(emitter, slot, name, element)
    if not contributed:
        reason = "+".join(sorted(reasons))
        _typed_unset(emitter, slot, reason, f"{address}.{slot.label} is {reason}")


# --- Arguments that hold a reference but have no Doc 07 §16 type ----------------------------------


def _reference_argument_edges(emitter: _Emitter, name: str) -> None:
    argument = read_argument(emitter.resource.attributes, name)
    if not argument.present:
        return  # absent is not an edge: a rule may use cidr_blocks instead (C-133 item 5)
    if argument.form != "ATTRIBUTE":
        elements = [Element(ElementKind.UNSUPPORTED, None, f"form:{argument.form}")]
    else:
        elements = elements_of(argument.value)
    for element in elements:
        if element.kind in (ElementKind.REF, ElementKind.NULL):
            continue  # a Ref is the reference edge already; null is unset
        attributes = {
            "source_attribute": name,
            "reference_type": "ATTRIBUTE_REFERENCE",
            "reason": element.detail,
        }
        if element.kind is ElementKind.LITERAL:
            emitter.draft(
                edge_type=EdgeType.TERRAFORM_REFERENCE,
                relationship=Relationship.REFERENCE,
                target=external_node(emitter.resource.address, name),
                status=DependencyStatus.UNSUPPORTED,
                attributes=attributes,
                rule=DerivationRule.EXTERNAL_OBJECT,
                source_fact=emitter.fact(name, element),
                target_fact=_EXTERNAL_TARGET,
            )
            continue
        unsupported = element.kind is ElementKind.UNSUPPORTED
        emitter.draft(
            edge_type=EdgeType.TERRAFORM_REFERENCE,
            relationship=Relationship.REFERENCE,
            target=unresolved_node(emitter.resource.address, name),
            status=DependencyStatus.UNSUPPORTED if unsupported else DependencyStatus.UNCERTAIN,
            attributes=attributes,
            rule=(
                DerivationRule.SLOT_UNSUPPORTED_VALUE
                if unsupported
                else DerivationRule.SLOT_UNKNOWN_VALUE
            ),
            source_fact=emitter.fact(name, element),
            target_fact=f"unresolved: {element.detail}",
        )


def add_infrastructure_edges(resource: Resource, index: StateIndex, parts: Parts) -> None:
    """Add the typed edges, and the explicit unresolved/external edges, of one resource."""
    if resource.support_status is ResourceSupport.UNSUPPORTED:
        return  # an unsupported type has no slots; its reference edges are already there
    emitter = _Emitter(resource, index, parts)
    if resource.support_status is ResourceSupport.UNKNOWN:
        for slot in slots_for(resource.resource_type):
            _typed_unset(
                emitter,
                slot,
                "placeholder",
                f"{resource.address} has an unknown number of instances",
            )
        return
    for slot in slots_for(resource.resource_type):
        _slot_edges(emitter, slot)
    for item in reference_arguments_for(resource.resource_type):
        _reference_argument_edges(emitter, item.argument)
