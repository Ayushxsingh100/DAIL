"""The footprint of an invariant in one dependency graph (Doc 08 §9-§13; registry §2.9, §6.6; C-139,
C-140; P4 step 4).

A footprint is the set of resources whose change can change an invariant's result, found from the
invariant's own declaration and nothing else:

- **Seeds:** the targets of the invariant node's scope edges (scope resources, scope-type matches)
  and of its source and destination edges. Scope edges terminate the walk: nothing is followed out
  of an invariant node (Doc 08 §10).
- **Walk:** breadth-first from the seeds, with a mandatory visited set, following only the edges
  whose (relationship, direction) token is in ``scope.relationships`` (the grammar of C-139:
  ``<RELATIONSHIP>:<direction>`` or ``REFERENCE[<source_type>.<argument>]:<direction>``). FORWARD
  follows an edge from its source to its target, REVERSE from its target to its source. KNOWN,
  UNCERTAIN and UNSUPPORTED edges to a real resource are followed (over-approximation, Doc 08 §13).
- **Canonical path:** each member keeps the shortest path from a seed; among equal-length paths the
  one with the smallest sequence of edge keys, so the result never depends on input order.

NO EDGE is not NO DEPENDENCY (Doc 08 §3): where the graph cannot say what a relationship leads to,
the footprint says it is **incomplete** and why. That happens for an absent seed, a missing
binding, a followed edge that is not KNOWN, a token edge that ends at an unresolved or external
node or at an absent object, a REVERSE-token resource whose edge of that relationship ends in an
unresolved node (it is added as a member: registry §6.6 "or is unresolved"), and a member with an
outgoing edge into an unresolved or external node (except the RDS placement, which C-15 assumes
away). The engine decides what an incomplete footprint means for a change (C-140 item 5).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from core.domain.enums import DependencyStatus
from core.domain.graph import (
    DependencyGraph,
    DerivationRule,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    Relationship,
    invariant_node_id,
)
from core.domain.impact import StepDirection
from core.domain.invariant import Invariant
from core.impact.addresses import block_of, same_object, type_of
from core.impact.errors import ImpactInputError

# The source and target type of each named relationship (the dependency slot table of P3c, repeated
# because the engines may not import each other; a test compares the two).
RELATIONSHIP_TYPES: Final[Mapping[str, tuple[str, str]]] = {
    "SUBNET_BELONGS_TO_VPC": ("aws_subnet", "aws_vpc"),
    "ROUTE_TABLE_BELONGS_TO_VPC": ("aws_route_table", "aws_vpc"),
    "ASSOCIATES_SUBNET": ("aws_route_table_association", "aws_subnet"),
    "ASSOCIATES_ROUTE_TABLE": ("aws_route_table_association", "aws_route_table"),
    "IGW_ATTACHED_TO_VPC": ("aws_internet_gateway", "aws_vpc"),
    "INSTANCE_IN_SUBNET": ("aws_instance", "aws_subnet"),
    "INSTANCE_USES_SECURITY_GROUP": ("aws_instance", "aws_security_group"),
    "DB_USES_SECURITY_GROUP": ("aws_db_instance", "aws_security_group"),
    "RULE_BELONGS_TO_SECURITY_GROUP": ("aws_security_group_rule", "aws_security_group"),
    "DB_SUBNET_PLACEMENT": ("aws_db_instance", "aws_db_subnet_group"),
}
# The target type of a REFERENCE[<source_type>.<argument>] token. A token that is not listed has an
# unknown target type, which makes every type walkable (fail closed, C-140 item 5).
REFERENCE_TARGET_TYPES: Final[Mapping[str, str]] = {"aws_security_group.vpc_id": "aws_vpc"}

_REFERENCE_PREFIX: Final = "REFERENCE["
_UNRESOLVED_KINDS: Final = frozenset({"unresolved", "external"})
_NOT_A_RESOURCE_KINDS: Final = frozenset({"absent", "data", "module"})


class IncompleteCode(StrEnum):
    """Why a footprint is not fully known (recorded, never silent)."""

    ABSENT_SEED = "ABSENT_SEED"
    MISSING_BINDING = "MISSING_BINDING"
    TOKEN_EDGE_NOT_KNOWN = "TOKEN_EDGE_NOT_KNOWN"
    UNRESOLVED_TOKEN_EDGE = "UNRESOLVED_TOKEN_EDGE"
    ABSENT_TARGET = "ABSENT_TARGET"
    UNRESOLVED_REVERSE_MEMBER = "UNRESOLVED_REVERSE_MEMBER"
    UNRESOLVED_MEMBER_EDGE = "UNRESOLVED_MEMBER_EDGE"


@dataclass(frozen=True)
class Token:
    """One parsed entry of ``scope.relationships``."""

    text: str
    relationship: str  # a Relationship name, or REFERENCE
    source_type: str | None  # for REFERENCE tokens
    argument: str | None
    direction: StepDirection

    @property
    def target_types(self) -> tuple[str, ...]:
        """The types this token can lead to; empty means unknown (every type is walkable)."""
        if self.source_type is not None:
            target = REFERENCE_TARGET_TYPES.get(f"{self.source_type}.{self.argument}")
            return () if target is None else (target,)
        return (RELATIONSHIP_TYPES[self.relationship][1],)

    @property
    def types(self) -> tuple[str, ...]:
        """Source and target types of the token (a REFERENCE token with no known target gives only
        its source type; ``fail_closed`` tells the caller)."""
        if self.source_type is not None:
            return (self.source_type, *self.target_types)
        return RELATIONSHIP_TYPES[self.relationship]

    @property
    def fail_closed(self) -> bool:
        return self.source_type is not None and not self.target_types


def parse_token(text: str) -> Token:
    """Parse ``<RELATIONSHIP>:<direction>`` or ``REFERENCE[<type>.<argument>]:<direction>``."""
    if not isinstance(text, str) or ":" not in text:
        raise ImpactInputError(f"walk token {text!r} is not <relationship>:<direction>")
    head, _, direction_text = text.rpartition(":")
    try:
        direction = StepDirection(direction_text)
    except ValueError:
        raise ImpactInputError(
            f"walk token {text!r}: direction must be FORWARD or REVERSE"
        ) from None
    if head.startswith(_REFERENCE_PREFIX) and head.endswith("]"):
        inner = head[len(_REFERENCE_PREFIX) : -1]
        source_type, dot, argument = inner.partition(".")
        if not dot or not source_type or not argument:
            raise ImpactInputError(f"walk token {text!r}: expected REFERENCE[<type>.<argument>]")
        return Token(text, "REFERENCE", source_type, argument, direction)
    if head not in RELATIONSHIP_TYPES:
        raise ImpactInputError(f"walk token {text!r}: {head!r} is not a followable relationship")
    return Token(text, head, None, None, direction)


def parse_tokens(texts: Iterable[str]) -> tuple[Token, ...]:
    return tuple(parse_token(text) for text in texts)


@dataclass(frozen=True)
class WalkStep:
    """One edge of a canonical path, in walk orientation (from the seed outwards)."""

    edge_key: str
    from_node: str
    to_node: str
    relationship: Relationship
    direction: StepDirection
    status: DependencyStatus


@dataclass(frozen=True)
class Member:
    """A resource of the footprint. ``seed`` is true for a scope element (DIRECT); otherwise the
    member was reached by the walk (DEPENDENCY) and ``path`` is its canonical path from a seed.
    ``unresolved`` marks a REVERSE-token member added because its edge ends in an unresolved node.
    """

    address: str
    resource_type: str
    seed: bool
    scope_elements: tuple[str, ...]
    path: tuple[WalkStep, ...]
    unresolved: bool = False

    @property
    def node_id(self) -> str:
        return f"RESOURCE:{self.address}"


@dataclass(frozen=True)
class Incompleteness:
    code: IncompleteCode
    detail: str

    def sort_key(self) -> tuple[str, str]:
        return (self.code.value, self.detail)


@dataclass(frozen=True)
class Footprint:
    """The footprint of one invariant in one graph."""

    invariant_id: str
    invariant_version: int
    members: tuple[Member, ...]
    absent_seeds: tuple[str, ...]
    incomplete: tuple[Incompleteness, ...]

    @property
    def complete(self) -> bool:
        return not self.incomplete

    def addresses(self) -> tuple[str, ...]:
        return tuple(member.address for member in self.members)

    def find(self, ref: str) -> tuple[Member, ...]:
        """The members a ref names: the same address, or a key-less block against its instances."""
        return tuple(member for member in self.members if same_object(ref, member.address))

    def absent_match(self, ref: str) -> bool:
        return any(same_object(ref, address) for address in self.absent_seeds)


# --- the graph index ------------------------------------------------------------------------------


class _Index:
    """Edges by node, each list in edge-key order (``graph.edges`` is sorted by key already)."""

    def __init__(self, graph: DependencyGraph) -> None:
        self.nodes: dict[str, GraphNode] = {node.node_id: node for node in graph.nodes}
        self.out: dict[str, list[GraphEdge]] = defaultdict(list)
        self.into: dict[str, list[GraphEdge]] = defaultdict(list)
        for edge in graph.edges:
            self.out[edge.source_node_id].append(edge)
            self.into[edge.target_node_id].append(edge)

    def kind(self, node_id: str) -> str:
        return str(self.nodes[node_id].attributes.get("kind", ""))

    def is_resource(self, node_id: str) -> bool:
        node = self.nodes[node_id]
        return node.node_type is NodeType.RESOURCE and self.kind(node_id) == "resource"

    def is_unresolved(self, node_id: str) -> bool:
        node = self.nodes[node_id]
        return node.node_type is NodeType.SEMANTIC and self.kind(node_id) in _UNRESOLVED_KINDS

    def resource_type(self, node_id: str) -> str:
        return str(self.nodes[node_id].attributes.get("resource_type", ""))


def _top_level(attribute: str) -> str:
    cut = len(attribute)
    for mark in ("[", "."):
        found = attribute.find(mark)
        if found != -1:
            cut = min(cut, found)
    return attribute[:cut]


def _matches(edge: GraphEdge, token: Token, index: _Index) -> bool:
    if token.source_type is not None:
        return (
            edge.edge_type is EdgeType.TERRAFORM_REFERENCE
            and index.resource_type(edge.source_node_id) == token.source_type
            and _top_level(str(edge.attributes.get("source_attribute", ""))) == token.argument
        )
    return (
        edge.edge_type is EdgeType.INFRASTRUCTURE and edge.relationship.value == token.relationship
    )


def _step(edge: GraphEdge, token: Token) -> WalkStep:
    forward = token.direction is StepDirection.FORWARD
    return WalkStep(
        edge_key=edge.edge_key,
        from_node=edge.source_node_id if forward else edge.target_node_id,
        to_node=edge.target_node_id if forward else edge.source_node_id,
        relationship=edge.relationship,
        direction=token.direction,
        status=edge.status,
    )


# --- seeds ----------------------------------------------------------------------------------------


def _element(edge: GraphEdge, node: GraphNode) -> str:
    """The scope element an edge from the invariant node stands for."""
    if edge.edge_type is EdgeType.INVARIANT_SEMANTIC:
        return f"binding:{edge.relationship.value}"
    rule = edge.evidence.derivation_rule
    if rule is DerivationRule.SCOPE_TYPE:
        return f"resource_types:{node.attributes.get('resource_type', '')}"
    if rule is DerivationRule.BLOCK_FANOUT:
        return f"resources:{block_of(node.ref_id)}"
    return f"resources:{node.ref_id}"


@dataclass
class _Seeds:
    elements: dict[str, set[str]]
    absent: set[str]
    incomplete: list[Incompleteness]


def _seeds(index: _Index, invariant_node: str) -> _Seeds:
    found = _Seeds({}, set(), [])
    for edge in index.out.get(invariant_node, ()):
        target = index.nodes[edge.target_node_id]
        if target.node_type is NodeType.RESOURCE:
            kind = index.kind(target.node_id)
            if kind == "resource":
                found.elements.setdefault(target.ref_id, set()).add(_element(edge, target))
            elif kind == "absent":
                found.absent.add(target.ref_id)
                found.incomplete.append(
                    Incompleteness(
                        IncompleteCode.ABSENT_SEED,
                        f"{target.ref_id} is named by the invariant and is absent from the state",
                    )
                )
        elif edge.relationship is Relationship.BINDING:
            found.incomplete.append(
                Incompleteness(
                    IncompleteCode.MISSING_BINDING,
                    f"{invariant_node} has no semantic binding, so its endpoints are unknown",
                )
            )
    return found


# --- the walk -------------------------------------------------------------------------------------


def footprint(graph: DependencyGraph, invariant: Invariant) -> Footprint:
    """The footprint of ``invariant`` in ``graph``; see the module docstring."""
    node_id = invariant_node_id(invariant.invariant_id, invariant.version)
    index = _Index(graph)
    if node_id not in index.nodes:
        raise ImpactInputError(f"{node_id} is not a node of the graph")
    tokens = parse_tokens(invariant.scope.relationships)
    seeds = _seeds(index, node_id)
    incomplete: list[Incompleteness] = list(seeds.incomplete)
    recorded_edges: set[str] = set()

    members: dict[str, Member] = {}
    for address in sorted(seeds.elements):
        members[address] = Member(
            address=address,
            resource_type=index.resource_type(f"RESOURCE:{address}"),
            seed=True,
            scope_elements=tuple(sorted(seeds.elements[address])),
            path=(),
        )

    # a REVERSE token also reaches a resource whose edge of that relationship ends in an unresolved
    # node: its target may be a member (registry 6.6 "or is unresolved")
    for token in tokens:
        if token.direction is not StepDirection.REVERSE:
            continue
        for edge in graph.edges:
            if _matches(edge, token, index) and index.is_unresolved(edge.target_node_id):
                source = edge.source_node_id
                if not index.is_resource(source):
                    continue
                recorded_edges.add(edge.edge_key)
                incomplete.append(
                    Incompleteness(
                        IncompleteCode.UNRESOLVED_REVERSE_MEMBER,
                        f"{token.text}: {index.nodes[source].ref_id} has an edge that ends at "
                        f"{edge.target_node_id}",
                    )
                )
                address = index.nodes[source].ref_id
                if address not in members:
                    members[address] = Member(
                        address=address,
                        resource_type=index.resource_type(source),
                        seed=False,
                        scope_elements=(f"walk:{token.text}:unresolved",),
                        path=(),
                        unresolved=True,
                    )

    visited = set(members)
    frontier = sorted(members)
    while frontier:
        candidates: dict[str, tuple[tuple[str, ...], tuple[WalkStep, ...], str]] = {}
        for address in frontier:
            here = f"RESOURCE:{address}"
            for token in tokens:
                forward = token.direction is StepDirection.FORWARD
                edges = index.out.get(here, ()) if forward else index.into.get(here, ())
                for edge in edges:
                    if not _matches(edge, token, index):
                        continue
                    other = edge.target_node_id if forward else edge.source_node_id
                    if index.is_unresolved(other):
                        recorded_edges.add(edge.edge_key)
                        incomplete.append(
                            Incompleteness(
                                IncompleteCode.UNRESOLVED_TOKEN_EDGE,
                                f"{token.text}: {address} has an edge that ends at {other}",
                            )
                        )
                        continue
                    if not index.is_resource(other):
                        recorded_edges.add(edge.edge_key)
                        incomplete.append(
                            Incompleteness(
                                IncompleteCode.ABSENT_TARGET,
                                f"{token.text}: {address} leads to {other}, which is not a "
                                "resource of the state",
                            )
                        )
                        continue
                    if edge.status is not DependencyStatus.KNOWN:
                        incomplete.append(
                            Incompleteness(
                                IncompleteCode.TOKEN_EDGE_NOT_KNOWN,
                                f"{token.text}: {address} to {index.nodes[other].ref_id} is "
                                f"{edge.status.value}",
                            )
                        )
                    neighbour = index.nodes[other].ref_id
                    if neighbour in visited:
                        continue
                    steps = (*members[address].path, _step(edge, token))
                    keys = tuple(step.edge_key for step in steps)
                    current = candidates.get(neighbour)
                    if current is None or keys < current[0]:
                        candidates[neighbour] = (keys, steps, token.text)
        frontier = sorted(candidates)
        for address in frontier:
            visited.add(address)
            _, steps, token_text = candidates[address]
            members[address] = Member(
                address=address,
                resource_type=index.resource_type(f"RESOURCE:{address}"),
                seed=False,
                scope_elements=(f"walk:{token_text}",),
                path=steps,
            )

    # a member with an outgoing edge into an unresolved or external node: its relationships are not
    # fully known (the RDS placement is assumed away by C-15)
    for address in sorted(members):
        for edge in index.out.get(f"RESOURCE:{address}", ()):
            if edge.edge_key in recorded_edges or not index.is_unresolved(edge.target_node_id):
                continue
            if edge.relationship is Relationship.DB_SUBNET_PLACEMENT:
                continue
            incomplete.append(
                Incompleteness(
                    IncompleteCode.UNRESOLVED_MEMBER_EDGE,
                    f"{address} has a {edge.relationship.value} edge that ends at "
                    f"{edge.target_node_id}",
                )
            )

    unique = {(item.code, item.detail): item for item in incomplete}
    return Footprint(
        invariant_id=invariant.invariant_id,
        invariant_version=invariant.version,
        members=tuple(members[address] for address in sorted(members)),
        absent_seeds=tuple(sorted(seeds.absent)),
        incomplete=tuple(sorted(unique.values(), key=Incompleteness.sort_key)),
    )


# --- walkable types -------------------------------------------------------------------------------


def walkable_types(invariant: Invariant, footprints: Sequence[Footprint]) -> frozenset[str] | None:
    """The resource types whose change could matter to ``invariant`` when its footprint is
    incomplete (C-140 item 5): the types of the seeds and members (in the footprints given, one per
    graph), the scope types, the types of absent scope addresses and the source and target types of
    every token. ``None`` means every type (a REFERENCE token with no known target type)."""
    types: set[str] = set(invariant.scope.resource_types)
    types.update(type_of(address) for address in invariant.scope.resources)
    for item in footprints:
        types.update(member.resource_type for member in item.members)
        types.update(type_of(address) for address in item.absent_seeds)
    for token in parse_tokens(invariant.scope.relationships):
        if token.fail_closed:
            return None
        types.update(token.types)
    return frozenset(types)
