# ADR-008: Explicit uncertainty result semantics
**Status:** Accepted (1 Oct 2026).

**Context.** DAIL is a safety gate: a result that is not a proven PASS must
never promote a candidate. Doc 05 §4.1 defines `VerificationResult` as PASS,
FAIL, UNKNOWN, UNSUPPORTED and VERIFIER_ERROR, and `InvariantStatus` as
REGISTERED, VERIFYING, PROTECTED, AFFECTED, REVERIFYING, VIOLATED and
UNCERTAIN. Doc 05 §29 says unknown and unsupported "are domain states, not
missing database values" and that the data model "must preserve these
distinctions so downstream policy can make conservative decisions". Doc 05 §39
forbids collapsing a critical distinction "into a generic string, null,
boolean, or overloaded record". Doc 09 §4 and §37 say UNKNOWN, UNSUPPORTED and
VERIFIER_ERROR do not satisfy required proof, that a verifier exception is
not converted to FAIL unless the verifier defines that, and that an error is
never converted to PASS. The earlier code mixed results into statuses
(VERIFIED, PASS, FAIL) and used ERROR and UNCERTAIN as results.

**Decision.**
1. Results and statuses are separate enums. A status never holds a result.
2. `VerificationResult.is_pass` is the single question code may ask about
   whether a result satisfies proof; it is true only for PASS.
3. Results map to invariant statuses only through
   `core.domain.lifecycle.apply_verification_result` (C-30):
   PASS to PROTECTED; FAIL to VIOLATED; UNKNOWN, UNSUPPORTED and
   VERIFIER_ERROR to UNCERTAIN. That function accepts only a VERIFYING or
   REVERIFYING invariant, so PROTECTED, VIOLATED and UNCERTAIN are reachable
   only by applying a result.
4. The originating result is kept on the candidate-scoped evaluation
   (`InvariantEvaluation.last_result`), so UNKNOWN, UNSUPPORTED and
   VERIFIER_ERROR stay distinguishable even though they share the UNCERTAIN
   status (Doc 05 §29).
5. The uncertain values in IdentityStatus, ChangeType, ImpactStatus,
   ResourceSupport, ReferenceResolution and DependencyStatus are first-class
   and are never coerced to a definite value by domain code.

**Consequences.** Uncertainty fails closed: no UNKNOWN, UNSUPPORTED or
VERIFIER_ERROR result can produce a PROTECTED status or a reference that
satisfies proof (SM-006, SM-007, SM-008). Doc 06 leaves VERIFIER_ERROR
unmapped, so C-30 records the mapping. UNPROVEN (Doc 06 §8) is not a Doc 05
§4.1 status and is not defined. Revisit if a later specification adds a
distinct status for unproven invariants.
