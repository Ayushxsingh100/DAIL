# ADR-003: Verification is state-indexed
**Status:** Proposed-default (must be settled before P5)

**Context.** An external audit noted `V(C_t, i)` is ill-defined under
frozen-candidate replay: the same patch applied to different base states
can verify differently. Doc 09 Sec. 19 also requires "candidate parent is
current Trusted State" and Doc 12 requires "wrong candidate hash -> result
rejected as stale".

**Decision.** Every verifier has the signature
`verify(trusted_state, candidate, invariant) -> VerificationResult`, and a
result carries `state_id`, `candidate_hash`, `invariant_id/version`,
`verifier_version`. Results bound to a different (state, candidate) pair are
rejected as stale, never reused.

**Consequences.** Matches paper notation V(S_t, C_t, i). Cheap to do now,
expensive to retrofit after P5.
