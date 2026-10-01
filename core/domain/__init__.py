"""The DAIL domain model (P1a; Docs 05 and 06).

Value objects and entities: ``Reference``, ``Provenance``, the normalized ``Resource``, ``Patch``,
``TrustedState``, ``CandidateState``, the versioned ``Invariant`` definition with its
``InvariantRegistry``, the state-scoped ``InvariantRef`` and the candidate-scoped
``InvariantEvaluation``.

Lifecycles: explicit transition tables and functions (``lifecycle``, ``state``) that reject every
transition the specification forbids, including SM-001 to SM-010. Lifecycle-bearing objects can
be created only through those functions, so ``dataclasses.replace`` and direct constructor calls
cannot skip a transition.

Hashing: canonical content and SHA-256 hashes, stable under reordering and excluding timestamps
and record ids (C-33). Interim local storage (``storage``) is replaced behind repository ports in
P1b (C-35).

Standard library only (ADR-004); contract rules R1 and R8-R10 are checked by
``tests/contract/test_architecture_boundaries.py``. See docs/SPEC_INDEX.md, docs/PHASE_GATES.md
and docs/DECISIONS_REGISTER.md (C-29 to C-38).
"""
