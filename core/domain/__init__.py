"""The DAIL domain model (P1a; Docs 05 and 06).

Value objects and entities: ``Reference``, ``Provenance``, the normalized ``Resource``, ``Patch``,
``TrustedState``, ``CandidateState``, the versioned ``Invariant`` definition with its
``InvariantRegistry``, the state-scoped ``InvariantRef`` and the candidate-scoped
``InvariantEvaluation``.

Identity (P3b; Doc 07, C-122): ``identity`` holds ``IdentityEvidence``, ``IdentityMatch`` and
``IdentityReport``, the answer to "what changed between the trusted and the candidate state?".

Dependency (P3c; Doc 07, C-132): ``graph`` holds ``GraphNode``, ``GraphEdge``,
``DependencyEvidence`` and ``DependencyGraph``, the typed "what is connected to what" of one state,
with UNCERTAIN and UNSUPPORTED edges as first-class values and a structural graph hash.

Impact (P4; Doc 08, C-138, C-139): ``impact`` holds ``ImpactReport``, ``ImpactedInvariant``,
``VerificationWorkItem`` and their closed vocabularies (reasons, impact types, priorities), and
``carry_forward_ok``, the single query P6 needs; ``registry_v1`` builds the four registry-v1.0
invariants, with the walk policy of INV-FUNC-001, as data.

Verification (P5a; Doc 09, C-145): ``verification`` holds ``VerificationRequest``,
``VerificationResultRecord`` and ``VerificationReport``, the closed vocabularies of classes and
reasons, and the three pure functions P6 needs (``sufficient``, ``fresh``, ``aggregate``), which
never count anything doubtful as proof.

Lifecycles: explicit transition tables and functions (``lifecycle``, ``state``) that reject every
transition the specification forbids, including SM-001 to SM-010. Lifecycle-bearing objects can
be created only through those functions, so ``dataclasses.replace`` and direct constructor calls
cannot skip a transition.

Hashing: canonical content and SHA-256 hashes, stable under reordering and excluding timestamps
and record ids (C-33). Persistence: the repository ports (``repositories``, Doc 05 §26) and the
adapter's way back into the domain (``codec``, C-48); the SQLite adapter itself is
``core.persistence``, which this package never imports.

Evidence (P2-fix; Doc 11, C-50 to C-57): ``evidence`` holds the single evidence record, its
per-context validity rules and the proof checks; ``audit`` the append-only audit events;
``redaction`` the deterministic secret redaction that lets the domain refuse an unredacted
payload.

Standard library only (ADR-004); contract rules R1 and R8-R10 are checked by
``tests/contract/test_architecture_boundaries.py``. See docs/SPEC_INDEX.md, docs/PHASE_GATES.md
and docs/DECISIONS_REGISTER.md (C-29 to C-48).
"""
