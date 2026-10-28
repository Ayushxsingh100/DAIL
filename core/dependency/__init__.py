"""Dependency engine: what is connected to what.

Owning spec sections: Doc 07 §14-31 (reference extraction, infrastructure and invariant edges,
edge status, the no-edge rule, the canonical graph hash). Built in: P3c (C-131 to C-135).

``build_graph`` turns one normalized state (``core.domain.resource.Resource`` objects) and the
declared invariants into a ``core.domain.graph.DependencyGraph``. NO EDGE is not NO DEPENDENCY
(Doc 07 §24): a relationship that cannot be resolved leaves an UNCERTAIN or UNSUPPORTED edge, never
silence. The engine constructs the graph only; impact policy is P4's (Doc 07 §25).

Import restrictions (tests/contract/test_architecture_boundaries.py, rule R15): the standard
library, ``core.domain.*`` and this package only. ``networkx`` is deferred (ADR-005, C-131).
"""
