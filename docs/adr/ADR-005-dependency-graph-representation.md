# ADR-005: Dependency graph representation; NetworkX deferred

**Status:** Proposed (C-131, P3c). The authors decide after the P3c report.

**Context.** Doc 02 §26 lists "NetworkX for the dependency graph" as ADR-005, and ADR-002, `CLAUDE.md`
and `pyproject.toml` (the `graph` extra) name `networkx` as the one known future third-party import in
`core/`. The P3c dependency engine builds the typed graph of Doc 07 §14-§31 for one normalized state
and offers a small traversal. Doc 07 §28 asks for an ordering that is controlled end to end: nodes and
edges sorted by stable semantic ids, a canonical hash, and no result that depends on iteration order.
The graph has a few hundred nodes at most, and impact policy (traversal depth, invalidation) belongs to
P4 (Doc 07 §25).

**Decision.** The graph is a frozen value (`core.domain.graph.DependencyGraph`: tuples of
`GraphNode` and `GraphEdge`, sorted by `node_id` and `edge_key`). `core.dependency.traversal` builds a
plain adjacency index from it (forward and reverse, neighbours in `edge_key` order) and runs a
breadth-first search with a mandatory visited set. NetworkX is **not** used in P3c.

Reasons: (a) the ordering and the hash are ours to define and test, which NetworkX's insertion-order
iteration would not give for free; (b) it avoids the first third-party package in `core` (contract rule
R7, `requirements/dev.lock`, `pip-audit`) for a problem this small; (c) P3c only constructs the graph
and a traversal; closure policy is P4's.

**Consequences.** This **deviates from the ADR list of Doc 02 §26**, which names NetworkX. The R7
allowlist stays empty, and `core.dependency` is standard library plus `core.domain` (rule R15). The
stale mentions of the NetworkX exception (`CLAUDE.md`, ADR-002, `pyproject.toml`) are left for the
authors to remove, or to keep if the decision is reversed.

**Revisit when** P4 shows a need that the small traversal cannot meet (for example algorithms on large
graphs); then NetworkX returns with its own ADR, a pinned version, and a deterministic ordering wrapper.
