"""Dependency engine: what is connected to what.

Owning spec sections: Doc 07 §15-31 (reference extraction, infrastructure and
invariant edges, edge status, no-edge rule, canonical graph hash).
Built in: P3c.

Import restrictions (tests/contract/test_architecture_boundaries.py):
must not import ``core.promotion`` (R5) or ``core.application`` (R2); must not
import ``llm``, ``experiments``, ``scripts``, ``apps``, ``benchmark`` or
``oracle`` (R3). Standard library only (R7); the ``networkx`` exception is
added in P3c with ADR-005. No code yet.
"""
