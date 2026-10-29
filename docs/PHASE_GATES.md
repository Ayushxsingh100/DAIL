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

M1 (Doc 15 §21): COMPLETE (external review, 24 Oct 2026). Basic fixture loading works: D2 PR #13 (20 fixtures, tests/fixture_catalog.py, CI validates every fixture root).

## P3a — Terraform parsing, evaluation, normalization

```text
P3a mini-gate: PASSED (external review, 28 Oct 2026, PR #16 at 0ca0b37, merged at 7def9f8).
Suite: 2163 tests on every one of the 11 commits (Python 3.12); final tree 2163 OK on Python 3.13
(1 skip by design: the Unicode-table equality test runs only when the interpreter has Unicode 15.0).
black, ruff, mypy clean. 31 adversarial probes passed. Mutation checks: always-determinate rule
(25 tests fail), `unresolved` direction read as absent (1 test fails), reference to an unsupported
target reported SUPPORTED (4 fail), `$dail` escape disabled (68 fail).
Notes carried forward (none blocks):
1. Duplicate CIDRs change the fingerprint by design (C-112); the rule view deduplicates.
2. The `unresolved` direction form (C-120(c)) needs an invariant-level test in P5 showing UNSUPPORTED, never "no rules" (P5 gate item).
3. C-117 (fingerprint equality is not "unchanged" when unresolved; P4 gate item) and C-45 (carry_forward needs the P4 UNAFFECTED verdict) stay open.
Terraform was not run in the reviewer's environment; C-99 stays a P7 gate item.
```

## P3b — Identity engine

```text
P3b mini-gate: PASSED (external review, 28 Oct 2026, PR #17 at 1f23d4c, merged at bf4c8e5).
Suite: 2395 tests on every one of the 9 commits (Python 3.12, 2163 up to 2395); final tree 2395 OK on
Python 3.13 (1 skip by design). black, ruff, mypy clean. 55 adversarial probes passed. Mutation
checks (6 rules broken in a scratch copy, all caught): RT-1 undecided case dropped (5 tests fail),
REPLACED on one-side-known (2 fail, 8 errors), UNRESOLVED_CONTENT never attached (4 fail, 2 errors),
symmetric AMB-1 removed (2 fail), REPLACED allowed for unsupported types (1 fail), partition check
removed (1 fail, 1 error).
Notes carried forward (none blocks):
1. C-129: a move that only changes the instance key is MODIFIED (conservative; accepted).
2. C-128 (key-less to keyed explicit move is UNSUPPORTED in the pipeline) stays Open; decide before D4.
3. C-130 (one-field RT-1 list vs the provider's ForceNew arguments) stays Open; decide before D5.
4. P4 must use the UNRESOLVED_CONTENT and UNSUPPORTED_TYPE evidence (C-117); restructuring
   (inline rule vs separate rule resource) is decided from rule_index in P4/P5.
Terraform was not run in the reviewer's environment; C-99 stays a P7 gate item.
```

## P3c — Dependency graph, and the P3 gate

```text
P3c mini-gate: PASSED (external review, 28 Oct 2026; PR #18 at e6cf95a, follow-up PR #19 at 0edffed).
Suite: 2663 tests on Python 3.12 and 3.13 (skipped=1); black, ruff and mypy clean.
The RDS subnet-placement gap was closed by C-136 (a placement edge that is always UNSUPPORTED).
P3 gate (P3a + P3b + P3c): PASSED on the Doc 15 §10.3 criteria (canonical fixtures pass; ambiguity
is conservative; graph output is deterministic; no silent missing dependencies).
Both PRs were merged before the verdict was issued (C-28 process lapse, recorded).
Carried forward: C-45 (decided as a proposal in C-141, P4); C-117 (P4 gate item); C-120(c) (P5 gate
item); C-128 before D4; C-130 before D5; C-131 to C-136 Proposed.
```

## P4 — Impact and invalidation

```text
P4 gate: PASSED (external review, 28 Oct 2026; PR #20 at d3170e9, merged before the verdict, C-28
process lapse recorded a third time). Suite: 2941 tests on Python 3.12 and 3.13 (skipped=1);
black, ruff and mypy clean. Recall 18 of 18 transition fixtures (affected ⊇ required_affected, 0
extras against required); 5 extras against the field-level oracle (R1, resource-level impact).
Steps 5-6 were drafted before their tests (disclosed, accepted).
Carry-forward: C-143 option B (identity cleanup before D4); C-45 enforcement in P6 (blocker);
C-120(c) is decided (unresolved direction form is UNSUPPORTED) and is a P5 gate item; C-128 before
D4; C-130 before D5; C-137 to C-143 Proposed.
```

## P5a — Verification, part 1 (security predicates)

```text
P5a mini-gate: PASSED (external review, 29 Oct 2026; PR #21 at 247a6c6, merged before the
verdict, C-28 process lapse recorded a fourth time). Suite passes on Python 3.12 and 3.13
(skipped=1); black, ruff and mypy clean. 60 of 60 SEC fixture cells equal expected.json (Claude
Code report); reviewer probes (about 40) found no unsound result other than C-150.
Carry-forward: (1) add CIDR boundary tests (one-address gap, uncovered last address, single-address
member advancing the cursor); three mutants of covers() survive; fix in P5b step 0 or P5b step 1,
no behaviour change. (2) C-150 Open: registry v1.1 amendment before D4, SEC-001/002 version bump,
oracle must match; limitation stated until then. (3) index_rules placeholder hazard: cleanup
with C-143 option B before D4. C-148 NOT_APPLICABLE question goes to the authors. C-144 to C-148
Proposed; C-149, C-150 Open. C-120(c) verified in source; probe in the P5 gate.
```

## P5b — Verification, part 2 (INV-FUNC-001)

```text
P5 gate: NOT PASSED YET (external review, 29 Oct 2026; PR #22 at 20def0d, merged before the verdict,
C-28 process lapse recorded a fifth time). Suite passes on Python 3.12 and 3.13 (skipped=1); black,
ruff and mypy clean. Carry-forward 1 of the P5a verdict is closed: the three covers() mutants are
killed by the new boundary tests. About 100 reviewer probes of INV-FUNC-001 and 7 mutations of the
reviewer's own were all as the registry says, except one soundness defect: an unresolved entry in
vpc_security_group_ids (for example [aws_security_group.db.id, var.u]) gives PASS when the path
is otherwise established, although E3 requires every entry to be resolved and row 4 gives UNKNOWN.
Fix package: P5b-fix (feature/p5b-fix). The P5 gate and milestone M2 are decided after it.
Carry-forward: C-150 and C-155 for registry v1.1 before D4; index_rules placeholder hazard with
C-143 option B before D4; C-148 NOT_APPLICABLE question goes to the authors.
```

## P5 — Verification

```text
P5 gate: PASSED (external review, 29 Oct 2026; PR #23 at c3524ef, merged before the verdict, C-28
process lapse recorded a sixth time). Milestone M2 reached. Suite passes on Python 3.12 and 3.13
(skipped=1); black, ruff and mypy clean. The P5b defect (an unresolved vpc_security_group_ids
entry gave PASS) is fixed (C-156); reviewer reproductions, about 100 FUNC probes and 3 mutations
of the fix all as the registry says. CIDR boundary mutants of covers() killed. Limits: the
20-fixture FUNC table and F4/F8 were not independently re-run by the reviewer.
Carry-forward: registry v1.1 amendment before D4 for C-150 and C-155 (including item 13 and engine
casing); index_rules placeholder hazard with C-143 option B before D4; C-148 NOT_APPLICABLE
question to the authors; the unused row 7 branch of sg_s.unresolved in _possible is dead code,
clean up later. C-45 enforcement in P6 (blocker). C-144 to C-148, C-151 to C-156 Proposed;
C-149, C-150, C-155 Open.
```

## P6a — Promotion decision

```text
P6a mini-gate: PASSED WITH ONE BLOCKING CONDITION (external review, 29 Oct 2026; PR #24 at
a7ca8af, merged before the verdict, C-28 process lapse recorded a seventh time). Suite passes on
Python 3.12 and 3.13 (3724 tests); black, ruff and mypy clean. 16 of 20 reviewer mutations of
decide() killed; the 3 survivors are redundant checks and one is an equivalent mutant. Limits: the
fixture table and the 37 author mutations were not independently re-run in full.
Blocking condition (MEDIUM, fix in P6b Step 1, before the P6 gate): a second result for the same
target id under another target type hides a FAIL (PROMOTE reproduced). Carry-forward: C-162;
ambiguous_identity_uncertain carries FUNC (P4 question to the authors); severity order, retry
budget in the core and violated-baseline INSUFFICIENT_EVIDENCE for the authors. C-157 to C-161
Proposed; C-37 and C-41 Decided. C-45 enforced in carry_forward and in decide.
```

## P6b — Promotion commit

```text
P6b mini-gate: PASSED (external review, 29 Oct 2026; PR #25 at b9b270a, merged before the
verdict, C-28 process lapse recorded an eighth time). Suite passes on Python 3.12 and 3.13 (3941
tests); black, ruff and mypy clean. C-162 fixed (the P6a blocking condition). Reviewer probes: forged
evidence and a candidate that is not PROMOTABLE are refused and escalated, nothing committed;
15 of 18 reviewer mutations of commit.py and binding.py killed, the 3 survivors are redundant
checks. Limits: concurrency schedules and the fault table were not re-run by the reviewer beyond
the suite; most P6b tests were written after the code (author's disclosure).
Carry-forward: "no promoted state without its decision" is enforced in commit_promotion and
check_database, not by a trigger (C-168 b): P6c adds a test that only the commit module calls
save_promoted. C-169 (one PROMOTION_FAILED event per decision and kind) Open for the authors;
decision reports are not persisted (recorded limit for P8). C-162 to C-167 Proposed; C-38 and C-168
Decided.
```

## P6c–P10 — NOT STARTED

## Temporary exceptions

None.
