"""Deterministic verification: structural, security, functional, baseline.

Owning spec sections: Doc 09 §3-18 (result semantics, verification classes, predicates, evidence
sufficiency and freshness, aggregation), registry-v1.0 §2-§5 (the predicates).
Built in: P5a (structural and consistency gate, the security predicates, baseline, aggregation;
C-144 to C-149) and P5b (the functional predicate; INV-FUNC-001 is UNSUPPORTED
``verifier.not_available`` until then).

Verification never mutates state and never decides promotion. Every error fails closed:

    PASS may satisfy a requirement     FAIL blocks it     UNKNOWN / UNSUPPORTED are lack of proof
    VERIFIER_ERROR is a tool failure: never property evidence, never converted to PASS or FAIL

Import restrictions (tests/contract/test_architecture_boundaries.py, rule R17): the standard
library, ``core.domain.*`` and this package only; never ``core.terraform_model`` (the verifier has
its own read side of the stored view), ``core.dependency``, ``core.identity``, ``core.impact``,
``core.persistence``, ``core.application`` or ``core.promotion``.
"""
