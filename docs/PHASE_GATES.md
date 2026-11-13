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

## P6 — Promotion (pending external review)

```text
P6 gate (Doc 15 §13.3) and milestone M3 (Doc 15 §23): NOT DECIDED. Status written by the P6c author
as an input to the external review; no gate and no milestone is claimed. P6c mini-gate: NOT DECIDED.

Evidence map (commands: py -3.12 -m unittest <module>; ids are in docs/DECISIONS_REGISTER.md):
  safe candidate promotes ........ tests.unit.test_e2e_lifecycles (steps 7-9, third candidate to v2),
                                   tests.unit.test_e2e_chains.TestSafePromotion
  unsafe candidate rejects ....... tests.unit.test_e2e_lifecycles (steps 2-6),
                                   tests.unit.test_e2e_chains.TestRejectedCandidate,
                                   tests.unit.test_e2e_fixtures (18 fixtures vs the P6a pipeline)
  stale candidate rejects ........ tests.unit.test_e2e_lifecycles (steps 10-11),
                                   tests.unit.test_e2e_chains.TestStaleParent,
                                   tests.unit.test_e2e_concurrency (28 schedules)
  evidence chain complete ........ tests.unit.test_chain (one test per rule of C-172),
                                   tests.unit.test_e2e_chains (six chains of Doc 11 §51.3),
                                   tests.unit.test_e2e_properties
  valid candidate advances once .. tests.unit.test_e2e_idempotency (reruns, a fault after every stage
                                   and at every unit-of-work commit), tests.unit.test_e2e_concurrency,
                                   P6b: tests.unit.test_promotion_commit*, test_promotion_concurrency
  no unsafe candidate can advance  the emergency switch (test_e2e_chains.TestEmergencySwitch),
                                   test_e2e_properties (switch off: nothing promoted), the AST test
                                   that the orchestrator holds no decision logic, C-175 sole callers
                                   (tests.contract.test_architecture_boundaries)
Limits: impact and verification reports are not persisted (P8); fixed patches only, the patch text is
not applied to the directory (C-174, P7b); one SQLite file, the MVP's single promotion worker (Doc 09
§39), nothing is claimed for several processes beyond the concurrency tests; the baseline acceptance
protocol is conservative and for the authors (C-171); hashed evidence carries the candidate's
creation instant, audit timestamps are live (C-170 (4)).
Carry-forward: C-169 Open (for the authors). C-170 to C-176 Proposed (C-173 decided by the user on
the stale route). C-176: baseline evidence is built in core.application.baseline because
to_evidence_submission stamps the resource-set hash, not the state's. Construction failure stores
no decision (C-170 (3), for the authors). 18 fixtures have a parent, the prompt said 17.
```
P6c mini-gate: PASSED. P6 gate: PASSED WITH LIMITS. M3 (Trust Transition Complete): reached for
fixed patches (external review, 29 Oct 2026; PR #26 at d7c0333, merged before the verdict, C-28
process lapse recorded a ninth time). Suite passes on Python 3.12 and 3.13 (4106 tests); black, ruff
and mypy clean; no passed package, fixture or requirement changed. Reviewer probes: conflicting
reruns refused, emergency switch turns a PROMOTE into an audited ESCALATE with no state change;
6 of 6 reviewer mutations of the orchestrator killed.
Limits: reports are not persisted (P8); fixed patches only, patch text not applied (P7b); one
SQLite file; Step 5 suites written after the code; author's 38 mutations and the C-176 probe not
re-run by the reviewer.
Carry-forward: a second attempt on the same terminal candidate returns the first decision without
deciding (MEDIUM; reject or document in P7/P8); C-173 Proposed until the authors confirm; C-169 Open;
C-170 to C-176 Proposed.

## P6d — Every move is a change, and invariant registry v1.1 — passed with limits (external review, 11 Nov 2026; merged as 1c3d72b, tagged registry-v1.1)

```text
Verdict (external review, 11 Nov 2026, PR #27 at 8c5ca0a): APPROVED WITH LIMITS. Merged as 1c3d72b,
tagged registry-v1.1. Limits carried forward (not blocking), from the verdict:
1. The pipeline still defaults to registry v1.0. The end-to-end tests run v1.0 definitions; v1.1 is
   exercised in tests/unit/test_registry_v1_1.py. P8 must make v1.1 the default for every
   experiment condition, so that DAIL is evaluated under the decided rules.
2. Version encoding (C-180). Registry 1.1 is stored as the integer 2, and the verifier version stays
   "1" while its §3.3 behaviour depends on the definition's registry. The mapping "stored 2 =
   registry 1.1" must be stated wherever evidence is reported (P8 reports, the paper).
3. C-181 (implementation readings) is Proposed; the authors must decide it. [Decided by the
   authors on 11 Nov 2026, recorded in P7a.]
4. Equivalence evidence gap. In tp-v1-F3-0278 the oracle archive does not record the sources of 2
   indeterminate rules; the conclusion relies on reading that scenario's .tf. Record in
   TerraPreserve's v1.1 notes: the oracle evidence should record rule sources.
5. Stale mentions of P9 remain in CLAUDE.md and README.md; update them in P7a. [Done in P7a.]
6. C-155 readings stay DAIL implementation choices outside the registry; DAIL-oracle differences
   on those cases are to be measured in P8.
```

The P6d author's input to the review, as written before the verdict:

```text
P6d mini-gate: NOT DECIDED. Status written by the P6d author as an input to the external review.
What changed:
  Moves (C-177, supersedes C-129's resource-level clause): a pair made by a moved block or by the
  implicit count move is never UNCHANGED; with equal fingerprints it is MODIFIED, the match carries
  moved = true and the move evidence decides; impact carries it with the flag MOVED. No new
  ChangeType. AddressOnlyIdentity (C-127) is unchanged. tests.unit.test_moves_are_changes.
  Registry v1.1 (C-178 to C-181): docs/specs/INVARIANT_REGISTRY_v1.1.md, the v1.0 text with the
  §3.3 possible clause (C-150 closed), the §2.9 wording and the versions; INVARIANT_REGISTRY_v1.md
  unchanged (sha256 pinned by a test). INV-SEC-001/002 version 2, INV-SEC-003 and INV-FUNC-001
  version 1; DAIL stores registry 1.1 as invariant_registry_version 2 (C-180). The verifier reads
  the definition's predicate.registry; SEC evidence of version 2 cites registry-v1.1. Version 1
  evidence is not carried forward to version 2 (C-62). tests.unit.test_registry_v1_1,
  tests.unit.test_verification_public_ingress.TestRegistryGap.
Equivalence on TerraPreserve v1.0 (read-only; archive sha256 equal to TerraPreserve
docs/D6_FREEZE.md at 8ec1931): indeterminate SEC-001/002 ingress rules that v1.1 makes possible
and v1.0 does not: dev primary 0, dev alternate 0, test primary 0, test alternate 0.
TerraPreserve v1.0 labels are identical under registry v1.0 and v1.1.
  How: the test split records no indeterminate SEC ingress rule. The dev split records two
  (tp-v1-F3-0278, aws_security_group.ec2_sg.ingress[0] and [1], both value sets, steps 0 and 1,
  reason "security-group sources unresolved"); the archive does not record their sources, so the
  scenario's Terraform (scenarios/dev/tp-v1-F3-0278, steps 0 and 1) was read, not run (user's
  decision, 11 Nov 2026): neither rule has cidr_blocks, ipv6_cidr_blocks or prefix_list_ids, and
  the clause records no violation, so neither is possible under v1.1.
Limits: the oracle itself is not changed (TerraPreserve is read only); C-155's readings stay DAIL
choices (P8 measures them); the verifier version stays "1" (C-180, question for the reviewer);
the test pipeline still defaults to the v1.0 definitions, and the canonical scenario is run under
v1.1 by tests.unit.test_registry_v1_1. Carry-forward: C-181 Proposed; the user tags registry-v1.1
after the verdict and the merge.
```

## P7a — The LLM channel — passed with limits (verdict on PR #28)

```text
P7a: passed with limits (verdict on PR #28). Recorded in P8a (C-199); limits recorded in P8a-2.
Limits of the verdict (open items, with the package that closes each):
1. C-183 to C-187 Proposed (now Decided in P7b). Closed.
2. Provider interface differs from Doc 10 §30 (ADR-006): state as a deviation in the paper.
   Open (paper).
3. Scope check refused new-address repairs. Closed in P7b (C-190).
4. Ollama 400/404 map to UNSUPPORTED, not retried: P10 counts them separately from model failures.
   Open (P10).
5. Token budget is an estimate (ceil(characters / 4)): P10 reports it as an estimate and checks the
   model's real context window. Open (P10).
6. The wiring check proves the plumbing only; model and licence checked by the author. Open (P10
   model choice).
7. Weak red run, compensated by mutations. Closed.
8. Remove llm.api_key_ref (kept by C-194) and the Pydantic line in CLAUDE.md (done in P7b). Closed.
9. Ollama left running on the author's machine; the installer can be deleted. Open (user).
```

The P7a author's input to the review, as written before the verdict:

```text
P7a mini-gate: NOT DECIDED. Status written by the P7a author as an input to the external review.
What exists (llm/, standard library only, C-183; ADR-006 Proposed):
  provider seam and failure classes (llm/adapter/provider.py, Doc 10 §24, §30); FakeProvider
  (scripted, no network) and OllamaProvider (urllib, loopback only, digest pin; C-182, C-185);
  context builder (§6-§8: impact neighbourhood only, secrets redacted before the prompt, unknown
  values marked); budget (§18-§19: deterministic reduction 7..3, omissions recorded,
  CONTEXT_INSUFFICIENT without a provider call); prompts dail-repair-prompt-1 (system and task
  layers, infrastructure as data between <<<DAIL_DATA and DAIL_DATA>>>, template hash pinned);
  strict parser dail-llm-parser-1 (§11, §22, §25; no tolerant parser); retries (§23, the four
  classes, bounded); request and response records and observability (§16-§17, §20-§21, §32-§34);
  the emergency switch llm.generation_enabled (off: no provider call); config llm.provider accepts
  "ollama". Tests: tests.unit.test_llm_parser, test_llm_context, test_llm_generate, test_llm_ollama.
Wiring check (11 Nov 2026, the author's machine: Intel Core Ultra 5 125H, 15.7 GB RAM, CPU only):
  Ollama 0.40.16 for Windows (official installer, signed by Ollama Inc.); model qwen2.5-coder:1.5b,
  digest d7372fd828518a4d38b1eb196c673c31a85f2ed302b3d1e406c4c2d1b64a0668, Q4_K_M, 1.5B,
  986 MB; licence Apache-2.0 (ollama.com/library/qwen2.5-coder:1.5b, licence blob 832dd9e00a68,
  and `ollama show --license`). One run of the canonical objective (Doc 10 §36) with the
  canonical regression context: status PATCH, parse errors none, latency 31.7 s, tokens in 2381 /
  out 184, attempts 1. The patch was not turned into a candidate (P7b) and its quality was not
  judged; this model is for wiring only, never for results (C-186).
Limits: patch validation beyond the parser (Doc 10 §13), HCL parsing of the patch and candidate
construction are P7b; a repair that adds a resource at a new address is refused by the scope check
(C-187 (3)); the token estimate is characters/4, not a tokenizer; the Ollama unit tests use a
loopback fake server, not the real one; the wiring check ran once on one machine.
Carry-forward: C-183 to C-187 Proposed; ADR-006 Proposed.
```

## P7b — From LLM patch to Candidate State — passed with limits (verdict on PR #29)

```text
P7b: passed with limits (verdict on PR #29). Recorded in P8a (C-199); limits recorded in P8a-2.
Limits of the verdict (open items, with the package that closes each):
1. C-189 to C-193 and C-195 Proposed: the authors decide. Open.
2. Untested branch: a non-var. reference as a credential value (for example password = local.x ->
   POLICY_VIOLATION) needs a test. Open (add it in this fix round, see Step 4). [Test added in
   P8a-2: tests.unit.test_llm_patch_validator.TestCredentialsAndIds
   .test_a_secret_argument_from_a_local_value_is_a_policy_violation.]
3. The invented-id check sees whole string literals only (an id split inside a template passes).
   Open (stated limit).
4. A MODIFY may drop the parent's lifecycle block. 14 of the 288 dev scenarios have a lifecycle
   block in S0. Open (P10 decides).
5. The tree hash is checked when the request is built, not at evaluation time: P10 builds and
   evaluates each LLM candidate in one step and deletes the build. Open (P10).
6. The candidate directory copies every parent file: P10 passes configuration-only parents.
   Open (P10).
7. Experiment scope for LLM candidates not fixed yet: one scope per scenario, the same for every
   condition, recorded in advance. Open (P10).
8. The wiring run proves the path only (the 1.5B model kept public SSH; DAIL rejected it). Open
   (P10 model choice).
9. Delete-only patches need a comment as patch text: P10 reports how often models fail on this.
   Open (P10).
10. llm.api_key_ref stays (C-194). Open (unused).
```

The P7b author's input to the review, as written before the verdict:

```text
P7b mini-gate: NOT DECIDED. Status written by the P7b author as an input to the external review.
What exists:
  The meaning of an LLM patch (C-188, Decided) and the application rules (C-189): complete resource
  blocks; MODIFY replaces the parent block's bytes, DELETE removes them, CREATE writes
  dail_llm_patch.tf; everything else copied byte for byte; built in a fresh directory under the
  caller's work root; the parent directory is never written.
  llm/validation/patch.py dail-patch-validator-1: the Doc 10 §13 checks in order, failure classes
  as C-192; scope (C-190, core/domain/change_scope.py AllowedChangeScope) and the operation check
  after DAIL's own identity (C-191); readings in C-195.
  Parser dail-llm-parser-2 (format only); prompt dail-repair-prompt-2 (the patch format), version 1
  reproducible (C-193). Generator validates every attempt; INVALID_OUTPUT is retried within
  max_attempts, POLICY_VIOLATION and UNSUPPORTED are not.
  Entry path: core.application.orchestrator.LLMEvaluationRequest (an LLM Patch, its built directory
  and the tree hash the validator recorded; core/application/candidate_tree.py).
Wiring check (12 Nov 2026, the author's machine, CPU only): Ollama 0.40.16, qwen2.5-coder:1.5b,
  digest d7372fd828518a4d38b1eb196c673c31a85f2ed302b3d1e406c4c2d1b64a0668, Q4_K_M, Apache-2.0
  (as P7a). One run end to end on the canonical objective from v0 = the canonical baseline:
  generation PATCH, parse and validation passed, candidate built, DAIL decision REJECT (the
  model's patch did not repair INV-SEC-001); 1 attempt, 23.0 s, tokens in 2083 / out 176; the
  Trusted State unchanged. The model was not judged and is for wiring only (C-186).
Mutation checks: 12 of 12 validator and entry-path rules broken in a scratch copy were caught
  (one, the reference check, only after the tests were made to require that check 9 reports).
Limits: the validator copies the whole parent directory; .tf.json parent blocks cannot be edited
(UNSUPPORTED); the operation check uses the default scope of the tests (all four operations),
experiment scopes are P8; the token estimate stays characters/4; the wiring check ran once on one
machine with one small model.
Carry-forward: C-189 to C-193 and C-195 Proposed; ADR-006 Proposed. The P7a mini-gate status above
is unchanged: no verdict text for P7a was pasted in this package.
```

## P7 — LLM Integration — passed with limits (verdict on PR #29)

```text
P7 gate (Doc 15 §14.2) and milestone M4 (Doc 15 §24): passed with limits (verdict on PR #29).
Recorded in P8a (C-199). The limits are those of the P7b verdict, listed in the P7b section.
```

The gate map written by the P7b author as an input to the review:

```text
P7 gate (Doc 15 §14.2) and milestone M4 (Doc 15 §24): NOT DECIDED. Each item and the tests that
bear on it (commands: py -3.12 -m unittest <module>):
§14.2 "Malformed output rejected" ......... tests.unit.test_llm_parser.TestInvalidOutput,
    tests.unit.test_llm_patch_validator.TestSyntaxAndBlocks.test_hcl_syntax_error_is_invalid_output,
    tests.unit.test_llm_patch_validator.TestBoundaries
§14.2 "Forbidden operations rejected" ...... test_llm_patch_validator.TestSyntaxAndBlocks
    (top-level blocks, provisioner, connection, lifecycle), TestScope (scope and the operation
    check: REPLACED and UNCERTAIN pairs, DELETE), TestCredentialsAndIds,
    test_llm_candidate_e2e.TestSecurity.test_infrastructure_blocks_are_policy_violations_with_no_candidate,
    test_a_local_exec_provisioner_is_a_policy_violation,
    test_a_verifier_file_as_a_changed_address_is_invalid_output
§14.2 "Prompt injection fixtures pass" ..... test_llm_context.TestPrompts
    .test_an_injected_instruction_stays_inside_the_data_delimiter,
    test_llm_candidate_e2e.TestSecurity.test_an_injected_description_in_the_trusted_state_stays_data,
    test_a_confident_unsafe_reply_is_rejected_by_verification
§14.2 "LLM confidence cannot promote" ...... test_llm_candidate_e2e.TestSecurity
    .test_a_confident_unsafe_reply_is_rejected_by_verification, test_llm_parser.TestConfidence
§14.2 "LLM cannot mutate Trusted State" .... test_llm_candidate_e2e (every failed or rejected
    attempt checks the current state and the lineage), TestRecords
    .test_a_tampered_candidate_directory_is_refused, test_llm_patch_validator (tearDown: the parent
    directory is byte-identical), tests.contract.test_architecture_boundaries (C-175 sole callers)
§14.2 "Valid patch reaches Candidate State only" test_llm_candidate_e2e.TestEndToEnd
    (.test_the_safe_repair_is_promoted, .test_the_candidate_lineage_points_to_one_parent,
    .test_no_solution_and_uncertain_create_no_candidate)
M4 "LLM generates structured candidate" ..... test_llm_generate.TestProviderInterface,
    test_llm_patch_validator.TestApplication, the wiring checks of P7a and P7b
M4 "Patch validation works" .................. test_llm_patch_validator (all classes)
M4 "LLM failures are isolated" ............... test_llm_generate.TestProviderInterface
    .test_each_failure_class_maps, TestRetry, test_llm_candidate_e2e.TestRetryThroughValidation,
    test_llm_ollama.TestFailures
M4 "Candidate enters deterministic DAIL pipeline" test_llm_candidate_e2e.TestEndToEnd (PROMOTE and
    REJECT through the EvaluationOrchestrator over a real database)
M4 "No model output can bypass promotion" ..... test_llm_candidate_e2e.TestSecurity
    .test_a_confident_unsafe_reply_is_rejected_by_verification, TestRecords
    .test_a_tampered_candidate_directory_is_refused, tests.unit.test_orchestrator (a FIXED_PATCH
    request refuses an LLM patch), tests.contract.test_architecture_boundaries
No item is marked passed here; the external review decides.
```

## P8a — The experiment harness — passed with limits (verdict on PR #30)

```text
P8a: passed with limits (verdict on PR #30). Verdict: APPROVED WITH LIMITS (external review,
12 Nov 2026 at d75b55e and 13 Nov 2026 at 68772e9; merged as 2db255b, whose message is the C-28
approval record). The P8 gate and milestone M5 wait for P8b.
Limits carried forward (not blocking), from the verdict, with the package that closes each:
1. C-200 to C-204 and C-207 are Proposed. The authors must decide them. [Closed: Decided by the
   authors on 13 Nov 2026, "accepted as built after external review", recorded in P8b.]
2. parent_refs defaults to empty. A caller that does not pass it gets impact's work set only. That
   fails closed (INSUFFICIENT_EVIDENCE, never a wrong PROMOTE), and the orchestrator passes it (the
   author's mutant U5 is caught). Open (stated limit).
3. Condition A is narrow by design (C-205, C-206). A's lineage tracks only the repair target, and a
   change-request scenario under A starts from a baseline with no invariant. The paper must define
   A exactly this way. Open (paper).
4. Automatic promotion is enabled only for the harness (C-207 (3)), through the reviewed file
   experiments/config/promotion.toml, whose hash every definition pins. It must never be used
   outside experiments/. Open (standing rule).
5. U_t items count as DAIL work (C-210). The paper's W must say so. Open (paper).
6. The dev-run counts are harness counts, not results. For example, C' rejects 4 more F5
   transitions than C. That gets explained only by P8b's scoring. Open (P8b).
7. For P8b, all from immutable records and never by hand: score every transition against the
   labels; report DAIL-oracle disagreements at S0 and per step (C-155); impact precision and recall
   against oracle_affected; H3 identity errors against mutation_record; the common-prefix analysis
   for the 7 truncations per condition; the Doc 13 §49 check "no unsafe promotion" under C. On dev,
   a failure is a defect to investigate, not to tune around. Open (P8b, this package).
```

The P8a author's input to the review, as written before the verdict:

```text
P8a mini-gate: NOT DECIDED. Status written by the P8a author as an input to the external review.
What exists:
  experiments/ (standard library, mypy-checked): loader (TerraPreserve read only; manifest pin
  665b326a..., every scenario_json_sha256 and step content_hash recomputed; the test split refused;
  execution fields only), definition (Experiment §5, Trial §6, lifecycle §7, deterministic ids),
  conditions (C-198), trial (one attempt: fresh store and lineage, S0 through the baseline flow,
  each step a FIXED_PATCH through EvaluationOrchestrator, early termination C-200), records,
  write-once artifacts (§41 plus an attempts level), runner (plan, run, resume, failure classes),
  CLI python -m experiments run|summary. README in experiments/.
  core/promotion: decide(open_targets=...) and check_open_targets (C-196); explicit required set
  (PromotionPolicy.explicit_required_set, stateless_policy, rules dail-stateless-1, C-205); the
  open target's FAIL is VERIFIED evidence through proofs, binding and commit; PromotionEvidence
  records open_targets (absent from the record when empty, so existing hashes are unchanged).
  core/application: StatefulFullScopePolicy and StatelessScopePolicy; EvaluationRequest.open_targets;
  EvaluationOrchestrator(identity_strategy=DEFAULT_STRATEGY) (C-208); EvaluationResult.identity and
  .work; BaselineRequest.allow_no_invariants (C-206). core/domain: TrustedState.establish_baseline
  (allow_no_invariants=False) (C-206).
Dev run (12 Nov 2026, the author's machine): experiment p8a-dev-harness-check version 1,
  protocol_version draft, id fdbef60c-9b45-53dd-8e6a-5c6b765505cc; DAIL e8f43c3 (clean tree);
  TerraPreserve terrapreserve-v1.0 (27f0ee4), manifest sha256 665b326a... verified; registry v1.1
  (stored version 2); Python 3.12.10, Windows 11. 224 dev targets x A, B, C, C' = 896 trials,
  896 COMPLETED, 0 FAILED, 0 harness or input failures; wall time 903 s.
  Transitions evaluated / TRUNCATED: A 280 / 0, B 273 / 7, C 224 / 56, C' 224 / 56.
  Transitions with an open target: A 56, B 56, C 28, C' 28.
  Work (gate, invariant, applicable baseline, not-applicable baseline): A 560, 140, 0, 0;
  B 546, 1092, 56, 10; C 448, 510, 56, 10; C' 448, 510, 62, 16.
  Decisions per condition and family (PROMOTE/REJECT; no RETRY or ESCALATE occurred):
  A: F1 28/0, F2 14/14, F3 28/0, F4 28/0, F5 28/0, F6 28/0, F7 28/0, F8 84/0.
  B: F1 14/14, F2 14/14, F3 11/17, F4 14/14, F5 13/15, F6 9/19, F7 14/14, F8 63/14.
  C: F1 14/14, F2 14/14, F3 11/17, F4 14/14, F5 13/15, F6 9/19, F7 14/14, F8 0/28.
  C': F1 14/14, F2 14/14, F3 11/17, F4 14/14, F5 9/19, F6 9/19, F7 14/14, F8 0/28.
  These are harness counts, not results; no label was opened and nothing was scored (P8b).
Second dev run (P8a-2, 13 Nov 2026, after C-210 and C-211): experiment p8a-dev-harness-check-2
  version 1, protocol_version draft, id ec2b4fa8-4398-5f70-be4c-5edf9cd1e0ef (the first run is kept
  as it is); DAIL e1bde5e (clean tree); TerraPreserve and manifest as above; scope policies
  dail-scope-2, stateful-full-scope-2, stateless-scope-2. 896 trials, 896 COMPLETED, 0 FAILED,
  0 harness or input failures; wall time 330 s.
  Transitions evaluated / TRUNCATED: A 280 / 0, B 273 / 7, C 273 / 7, C' 273 / 7.
  Transitions with an open target: A 56, B 56, C 56, C' 56.
  Work (gate, invariant, applicable baseline, not-applicable baseline; of the invariant items,
  NOT_PROTECTED_IN_PARENT): A 560, 140, 0, 0, 0; B 546, 1092, 56, 10, 0; C 546, 681, 56, 10, 54;
  C' 546, 681, 62, 16, 54 (U_t items in 53 transitions each under C and C').
  Decisions per condition and family (PROMOTE/REJECT; no RETRY or ESCALATE): A and B as in the
  first run; C and C' as in the first run except F8: C 63/14, C' 63/14.
  Changed against the first run (same scenario, condition and step; counts only): A 0, B 0,
  C 77, C' 77, all in F8: REJECT -> PROMOTE 28, TRUNCATED -> PROMOTE 35, TRUNCATED -> REJECT 14,
  for each of C and C'. Nothing was tuned to the outcome.
Mechanism found in the first run (C-209, closed by C-210): under C and C' every F8 trajectory is rejected at step 1 with
  INSUFFICIENT_EVIDENCE on the open target, because impact does not list it and a VIOLATED
  reference cannot carry; C-196's stated purpose is not reached there. Nothing was tuned.
Tests: tests.unit.test_p8a_open_targets, test_p8a_open_targets_e2e, test_p8a_conditions,
  test_experiment_loader, test_experiment_harness, test_experiment_terrapreserve (opt-in,
  TERRAPRESERVE_ROOT), tests.contract.test_experiment_blinding; test_identity_strategy amended
  (C-208). Mutation checks: 18 of 18 harness, loader and promotion mutants caught (M5 only after a
  test was added), and 2 of 2 for the amended identity test.
Limits: the open-target rule blocked C and C' on F8 (C-209, closed by C-210 in P8a-2); condition-added work items
  carry a stand-in reason code (C-207 (1)); automatic promotion is enabled by the reviewed
  experiments/config/promotion.toml in the harness's copy of the configuration only (C-207 (3));
  repetition 1, no seeds; one machine.
Carry-forward: C-200 to C-204 and C-207 Proposed; C-209 closed by C-210; P8b scores the stored records.
```

## P8b — Scoring, metrics and the dev report (pending external review)

```text
P8b mini-gate: NOT DECIDED. Status written by the P8b author as an input to the external review.
What exists:
  experiments/scoring (the only label reader: labels with the manifest and scenario hash checks,
  per-transition truth, the identity truth table identity-truth-1 written from D4_OPERATORS.md,
  the reproducibility selection); experiments/metrics (the extractor metrics-draft-1: MetricRecords
  of Appendix B with scope, stratum and Wilson 95%; TrialOutcome of §31); experiments/report (the
  ExperimentReport of §33 and its Markdown); python -m experiments.report extract|select|compare.
  Blinding contract: (a) no module outside experiments/scoring names a label field; (b) no execution
  module imports experiments.scoring, .metrics or .report (both shown failing on a mutant).
Dev report (13 Nov 2026): docs/P8_DEV_PILOT.md, generated from p8a-dev-harness-check-2
  (ec2b4fa8...), 896 trials, 1120 transitions, 1835 metric records; metric_records.json sha256
  9f4d3d65..., report.json sha256 6fd62e2d...; a second extract wrote byte-identical files.
  Headline (all evaluated transitions; numerator / denominator): unsafe promoted / promoted
  A 105/266, B 0/152, C 0/152, C' 0/148; missed regressions / regressions A 98/98, B 0/98,
  C 0/98, C' 0/98; false rejections / safe A 0/161, B 9/161, C 9/161, C' 13/161; W total A 700,
  B 1694, C 1283, C' 1289; Save(C vs B) on the common prefix (273) = 1 - 1283/1694; TRUNCATED
  A 0/280, B, C, C' 7/280. Unsafe promotions under C: none. Truth changes outside the verified
  set: 0. DAIL-oracle disagreements under B: 6 (all DAIL UNSUPPORTED, oracle PASS; 2 scenarios).
  Identity errors / true pairs: C 3/80, C' 23/80 (40 pairs excluded per condition).
  These are dev numbers of a draft protocol, not findings (C-214).
Reproducibility: p8b-repro-check (308471ba...), 20 scenarios x 4 conditions = 80 trials on the
  same code; 136 transitions in common with run 2, 0 decision and 0 invariant-result differences.
Tests: tests.unit.test_p8b_metrics (hand-computed record set), test_p8b_scoring_report,
  tests.contract.test_experiment_blinding. Mutation checks: 12 of 12 metric mutants caught (3 only
  after tests were added for the cases the record set lacked), 2 of 2 blinding mutants.
Limits: metrics-draft-1 is a draft (P10 freezes the definitions before the test split); the
  identity table covers only what the catalogue states (5 operators excluded); evidence-transfer
  error is the author's reading (C-215 (1)); descriptive statistics only.
Carry-forward: C-212 to C-215 Proposed.
```

## P8 — Experiment Harness (pending external review)

```text
P8 gate (Doc 15 §15.3) and milestone M5 (Doc 15 §25): NOT DECIDED. Each item and what bears on it:
§15.3 "Trials are reproducible" ........ tests.unit.test_experiment_harness.TestReproducibility
    (records identical across runs, concurrency, corrupted labels); the 20-trial re-run
    (P8_DEV_PILOT.md section 13); the reviewer's independent re-run of both dev runs (PR #30).
§15.3 "All compared conditions share compatible fixtures" .. the one fixture_set of every
    definition; test_experiment_harness.TestConditions.test_baselines_agree_across_conditions;
    the common prefixes of the report (sections 1-2).
§15.3 "Metrics have frozen definitions" .. metrics-draft-1 is versioned and every record names it
    (C-212; tests.unit.test_p8b_metrics.TestRecords); it is a draft for the dev pilot, and P10
    freezes the final definitions before the test split is opened.
§15.3 "Failed/excluded trials remain visible" .. experiments.report.build failures and
    excluded_count; P8_DEV_PILOT.md section 12; test_p8b_scoring_report.TestReport;
    test_experiment_harness.TestFailures.
§15.3 "Reports derive from persisted evidence" .. python -m experiments.report extract reads only
    the stored records; test_p8b_scoring_report.TestDevPilotDocument; the byte-identical second
    extract.
M5 "Experiments run reproducibly" ...... as §15.3 "Trials are reproducible".
M5 "Baselines work" .................... conditions A and B (tests.unit.test_p8a_conditions,
    test_experiment_harness.TestConditions; P8_DEV_PILOT.md section 1).
M5 "Metrics generated" ................. metric_records.json (1835 records) of run 2.
M5 "Trial artifacts linked" ............ correlation ids and artifact_refs
    (test_experiment_harness.TestConditions.test_a_transition_records_what_section_4_3_lists,
    report artifact_refs).
M5 "Comparison report generated" ....... docs/P8_DEV_PILOT.md.
No item is marked passed here; the external review decides.
```

## P10 — NOT STARTED

P9 (AWS integration) and milestone M6 (AWS Demonstration) are removed (C-71, Decided by the advisor,
11 Nov 2026): AWS stays fully offline, with no deployment, no AWS account and no calibration against
live AWS; the oracle and DAIL are configuration-level only. The packages after P6c are P6d, P7a, P7b,
P8a, P8b and P10.

## Temporary exceptions

None.
