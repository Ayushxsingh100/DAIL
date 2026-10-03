# Phase Gate Status

A gate is PASSED only when the Claude review has audited every Doc 15 exit criterion against the spec text. A green test suite is evidence, not a gate pass.

## Withdrawn claims

An earlier version of this file marked P1 and P2 as PASSED. Those claims were withdrawn on 29 Sep 2026 after a spec audit.

## P0 — Project Bootstrap — PASSED (external review, 30 Sep 2026)

| Exit criterion (Doc 15 §7.3) | Status | Evidence |
|---|---|---|
| Fresh clone can bootstrap | PASS | Fresh clones of `c08f8e5`: `scripts/dev.py bootstrap` exit 0 on Windows 11 (Python 3.12.10) and on Linux (Python 3.12.3); 211 tests OK; health 4 PASS, llm_provider SKIPPED |
| CI runs successfully | PASS | Run 36722784541 on `main` (`c08f8e5`, push): quality, secrets, terraform all success |
| Unit test command works | PASS | `python -m unittest discover -s tests -p "test_*.py"`: 211 tests OK with no third-party packages |
| No secrets required for core tests | PASS | The CI quality job uses no secrets; the only secret reference in ci.yml is GITHUB_TOKEN for gitleaks |
| Main branch protected | PASS | PR required; strict required checks quality/secrets/terraform; admins included; no force-push or deletion (API read-back, 30 Sep 2026) |

Carried forward: required approvals = 0 (C-28, Accepted 30 Sep 2026: each PR description links its external review verdict as the approval record). Doc 14 §23's safety-regression and adversarial test gates are empty at P0; they must hold real tests from P3a onward and must not pass empty at later gates.

## P1 — Domain Foundation — PASSED (external review, 2 Oct 2026, P1b merged at 549e48d; follow-up F1/F2 in this PR)

P1a mini-gate: PASSED (external review, 1 Oct 2026, PR #3). Gaps 1–7 and 9 closed at domain level; gap 8 and database-level enforcement remain for P1b.

Rewrite delivered as P1a and P1b. Gaps recorded before the rewrite:

1. `InvariantStatus` must be exactly REGISTERED, VERIFYING, PROTECTED, AFFECTED, REVERIFYING, VIOLATED, UNCERTAIN (Doc 05 §4.1). The code mixes verification results into statuses.
2. `VerificationResult` must be PASS, FAIL, UNKNOWN, UNSUPPORTED, VERIFIER_ERROR (Doc 05 §4.1). The code has ERROR and UNCERTAIN instead.
3. The candidate lifecycle must follow Doc 06 §5: CREATED → BUILDING → FAILED | READY → ANALYZING → REJECTED | RETRY_REQUIRED | ESCALATED | PROMOTABLE → PROMOTED.
4. `InvariantRef` is missing (Doc 06 §14). Invariant definitions must become immutable and versioned.
5. `Resource` has the wrong shape. Doc 05 §5.1 defines a normalized resource; the current class is a change record and moves to P3 as `IdentityMatch`.
6. Missing fields and entities:
   - `TrustedState`: lineage_id, normalization_version, commit_decision_id, committed_at.
   - `CandidateState`: lineage_id, candidate_sequence, source, patch_id, state_hash.
   - The `Patch` entity (Doc 05 §9), and `Reference` and `Provenance` (Doc 05 §5.3, §6).
7. The forbidden transitions SM-001 to SM-010 (Doc 06 §22) are not encoded.
8. The repository interfaces of Doc 05 §26 are missing.
9. The lifecycle tests must be rewritten from the Doc 06 §31 test matrix.

## P2 — Evidence Foundation — PASSED (external review, 4 Oct 2026, PR #6 at 5488079)

Gaps 1–6 recorded before P2-fix are closed by P2-fix (PR #6, C-50 to C-61): per-context evidence validity, the Doc 11 §5 taxonomy, `run_id` and `attempt_id` binding, `evidence://<type>/<content_hash>` references, one `Provenance` class, and the Doc 11 §15 log levels with the unified event and replay-mode enums.

| Exit criterion (Doc 15 §9.2) | Status | Evidence |
|---|---|---|
| Evidence persists and resolves | PASS | `test_persistence_evidence` (round trip, artifact resolve, broken reference, deferred state foreign key: commit together, rollback together); `test_data_int_007` (DATA-INT-007 in the adapter and in triggers T5); `test_evidence_schema` (missing state fails at commit) |
| Hashes verify | PASS | `test_evidence_domain` (hash stability, redacted payload hashes differently); `test_evidence_service::TestHashesVerify` and `TestCanonicalTextIsPartOfIntegrity` (VALID, TAMPERED, MISSING_PAYLOAD); append-time recompute (A1); adversarial probe 3 (a tampered record is unusable as proof and Doc 11 §46 is carried out) |
| Lineage queries work | PASS | `list_for_attempt`, `_run`, `_state`, `_candidate`, `_correlation`; `events_for_correlation` in sequence order; `validity_history`; `supersession_chain`; `test_p2_gate` (Doc 11 §41 and §42 chains, ordered reconstruction from one correlation id, join to `trusted_states.lineage`) |
| Invalidation preserves history | PASS | per-context validity (C-52): v0's evidence is INVALID for c1 and still VALID for v0 (`test_p2fix_reproducer`, `test_p2_gate`); append-only tables including REPLACE from a plain connection (`test_evidence_schema::TestT1AppendOnly`, adversarial probes 1 and 7) |
| Redaction tests pass | PASS | `test_redaction` (13); secrets refused at the port and absent from the database bytes (adversarial probe 2); log metadata redacted; the policy version is recorded iff something was redacted |
| Duplicate events are handled | PASS | evidence, audit and transition idempotency including two-connection races (`test_persistence_evidence::TestIdempotency`); conflicting redelivery raises (adversarial probes 8 and 9) |

Suite at the reviewed commit: 1194 tests, black, ruff and mypy clean (venv modules; `dev.py lint` cannot run on the author's Windows machine).

Carried forward:

- C-60: DATA-INT-007 checks existence only in P2; P6 adds the binding and proof-type checks.
- C-62 (supersession subject identity, before P5) and C-63 (redaction coverage, before P7a) are Open.
- C-37 input from the P2-fix report goes to the P6a prompt.
- The Doc 11 §40 queries that need dependency, impact, verification or LLM data are deferred to P3c–P7.
- The REDACTED transition and the Doc 11 §18 hash chain are not implemented.

M1 (Doc 15 §21): not declared — 'Basic fixture loading works' is pending (D2/P3a).

## P3–P10 — NOT STARTED

## Temporary exceptions

None.
