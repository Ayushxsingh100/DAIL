"""Deterministic verification: structural, security, functional, baseline.

Owning spec sections: Doc 09 §3-18 (result semantics, verification classes, predicates, evidence
sufficiency and freshness, aggregation), registry-v1.0 §2-§5 (the predicates).
Built in P5a (C-144 to C-150): the structural and consistency gate, the security predicates
(INV-SEC-001, INV-SEC-002, INV-SEC-003), baseline verification of created resources and the engine.
INV-FUNC-001 is built in P5b; until then it is UNSUPPORTED ``verifier.not_available``, never PASS.

    values, views    the verifier's own reader of the stored security view (C-112, C-149)
    cidr, ports      interval-union coverage and the port logic of registry §2.5, §3.3
    retention        RETAINED-INLINE: the parent counterpart, through the identity report
    public_ingress   PIP(22) and PIP(5432)          rds_public_flag   INV-SEC-003
    structural       the mandatory STRUCTURAL and CONSISTENCY items (closed finding codes)
    baseline         the RESOURCE items P4 emits for created resources
    dispatch         the table from a definition's verifier id and version to a function
    engine           run_work_set, verify_work_item, to_evidence_submission
    inputs, errors   VerificationInputs and VerificationInputError

Verification never mutates state and never decides promotion. Every error fails closed:

    PASS may satisfy a requirement     FAIL blocks it     UNKNOWN / UNSUPPORTED are lack of proof
    VERIFIER_ERROR is a tool failure: never property evidence, never converted to PASS or FAIL

Import restrictions (tests/contract/test_architecture_boundaries.py, rule R17): the standard
library, ``core.domain.*`` and this package only; never ``core.terraform_model`` (the verifier has
its own read side of the stored view), ``core.dependency``, ``core.identity``, ``core.impact``,
``core.persistence``, ``core.application`` or ``core.promotion``.
"""
