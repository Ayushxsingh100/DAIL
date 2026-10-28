"""A cycle-safe traversal over a ``DependencyGraph`` (Doc 07 §25, Doc 08 §11-§12; C-135).

``reachable`` is breadth-first with a mandatory visited set, so a cycle ends. It follows edges
forward (source to target, "depends on") or in reverse (the reverse adjacency Doc 08 §11 asks for,
"affects"). Neighbours are taken in ``edge_key`` order, so among equal-length paths the one found
first in that order wins and nothing depends on input or hash order.

The helper decides no depth and no impact: UNCERTAIN and UNSUPPORTED edges are traversed unless the
caller's ``edge_filter`` says otherwise (Doc 07 §24: no edge is not no dependency).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from core.dependency.errors import DependencyInputError
from core.domain.graph import DependencyGraph, GraphEdge


class Direction(StrEnum):
    """FORWARD follows source to target ("depends on"); REVERSE the other way ("affects")."""

    FORWARD = "FORWARD"
    REVERSE = "REVERSE"


@dataclass(frozen=True)
class Reachability:
    """What a traversal found: the visited nodes and how each was first reached."""

    direction: Direction
    start_nodes: tuple[str, ...]
    visited: tuple[str, ...]
    via: Mapping[str, str]  # node id -> key of the edge that first reached it (not for starts)
    edges: Mapping[str, GraphEdge]  # edge key -> edge, for the edges in ``via``

    def path_to(self, node_id: str) -> tuple[GraphEdge, ...]:
        """The edges from a start node to ``node_id`` in traversal order (empty for a start)."""
        if node_id not in self.visited:
            raise DependencyInputError(f"{node_id!r} was not reached by this traversal")
        path: list[GraphEdge] = []
        current = node_id
        while current in self.via:
            edge = self.edges[self.via[current]]
            path.append(edge)
            current = (
                edge.source_node_id if self.direction is Direction.FORWARD else edge.target_node_id
            )
        path.reverse()
        return tuple(path)


def _adjacency(graph: DependencyGraph, direction: Direction) -> Mapping[str, tuple[GraphEdge, ...]]:
    """Edges by the node they are followed from; ``graph.edges`` is sorted by key already."""
    lists: dict[str, list[GraphEdge]] = {}
    for edge in graph.edges:
        origin = edge.source_node_id if direction is Direction.FORWARD else edge.target_node_id
        lists.setdefault(origin, []).append(edge)
    return MappingProxyType({node: tuple(edges) for node, edges in lists.items()})


def reachable(
    graph: DependencyGraph,
    start_nodes: Iterable[str],
    *,
    direction: Direction,
    edge_filter: Callable[[GraphEdge], bool] | None = None,
) -> Reachability:
    """Breadth-first closure from ``start_nodes``. A start node that is not in the graph raises
    ``DependencyInputError``; ``edge_filter`` (default: all edges) says which edges are followed."""
    if isinstance(start_nodes, str):
        raise DependencyInputError("start_nodes must be a collection of node ids, not one string")
    if not isinstance(direction, Direction):
        raise DependencyInputError("direction must be a Direction")
    starts = tuple(sorted(set(start_nodes)))
    known = {node.node_id for node in graph.nodes}
    for node_id in starts:
        if node_id not in known:
            raise DependencyInputError(f"start node {node_id!r} is not in the graph")
    adjacency = _adjacency(graph, direction)
    visited = set(starts)
    via: dict[str, str] = {}
    followed: dict[str, GraphEdge] = {}
    queue: deque[str] = deque(starts)
    while queue:
        current = queue.popleft()
        for edge in adjacency.get(current, ()):
            if edge_filter is not None and not edge_filter(edge):
                continue
            neighbour = (
                edge.target_node_id if direction is Direction.FORWARD else edge.source_node_id
            )
            if neighbour in visited:
                continue
            visited.add(neighbour)
            via[neighbour] = edge.edge_key
            followed[edge.edge_key] = edge
            queue.append(neighbour)
    return Reachability(
        direction=direction,
        start_nodes=starts,
        visited=tuple(sorted(visited)),
        via=MappingProxyType(via),
        edges=MappingProxyType(followed),
    )
