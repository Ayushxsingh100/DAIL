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

Carried forward: required approvals = 0 (C-28, Open). Doc 14 §23's safety-regression and adversarial test gates are empty at P0; they must hold real tests from P3a onward and must not pass empty at later gates.

## P1 — Domain Foundation — NOT PASSED

Rewrite scheduled as P1a and P1b. Known gaps:

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

## P2 — Evidence Foundation — NOT PASSED

Reconciliation scheduled as P2-fix. Known gaps:

1. Evidence invalidation is global but must be per context. Doc 11 §7 defines INVALID as "no longer valid for the referenced new-state context", and Doc 06 §15 says a rejected candidate leaves vN's evidence valid for vN. `EvidenceStore.current_validity(evidence_id)` takes no context.
2. The evidence type taxonomy must follow Doc 11 §5.
3. `run_id` and `attempt_id` binding is missing (Doc 05 §16.1, Doc 11 §10).
4. Artifact references must use `evidence://<type>/<content_hash>` (Doc 11 §17).
5. The `Provenance` object is missing; it must be the union of Doc 05 §6 and Doc 11 §21.
6. Log levels must be ERROR, WARN, INFO, DEBUG, TRACE (Doc 11 §15), and the lifecycle events of Doc 06 §28 must be added to the Doc 11 §12 taxonomy.

## P3–P10 — NOT STARTED

## Temporary exceptions

None.
