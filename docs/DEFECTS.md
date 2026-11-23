# Defect list (Doc 12 §38)

A severity-rated list of the defects recorded in this repository. Written in P10g (23 Nov 2026). Every severity
below is **proposed (P10g); the review decides**. Nothing here is invented: the closed defects are only those that
`docs/DECISIONS_REGISTER.md` records as found and fixed, and each entry cites its rows.

## Severity levels (Doc 12 §38, quoted)

| Severity | Definition |
|---|---|
| S0 | "Potential unsafe promotion, trust-boundary bypass, or corruption of authoritative state." |
| S1 | "Safety-critical verifier/impact/lifecycle defect affecting required behavior." |
| S2 | "Major functional/observability defect without direct trust bypass." |
| S3 | "Minor defect, usability, documentation, or non-critical diagnostics." |

## Open defects

None open after P10g (D-1 is closed by this package once its test is green; see below).

## Closed defects

| Id | Register rows | Defect | Proposed severity (P10g; the review decides) | Reason for the severity | How it was fixed |
|---|---|---|---|---|---|
| D-1 | C-258 | `tests/unit/test_p10e_lock_order.py::TestTheCommand::test_every_step_is_refused_off_the_tag_and_writes_nothing` assumed that HEAD is not tagged `protocol-v1`; at the tag, 3 of its 4 subtests failed (QA report 1, BLOCK). | S3 | A defect in a test's premise, not in the product: the guard it tests refused every step at the tag with rc 2 and wrote nothing (QA report 1, scratch run). No promotion, verifier, impact or lifecycle behaviour was affected; it is a non-critical diagnostic defect that blocked a QA run. | P10g step 1: the test patches `experiments.split_guard._git` so that `describe` reports no tag and every other git call is passed through; the assertions are unchanged. Red at `protocol-v1` (3 subtests), green at `protocol-v1` with only the new test file and at the branch head; the fixed test fails again when the guard's tag check is removed (scratch worktree). Test-only; no code changed (C-258). **Closed by P10g** once the suite is green (QA report 2). |
| D-2 | C-99, C-227 | The pinned `terraform validate` gate was missing for LLM candidates: C-99 requires every candidate to pass it before it enters DAIL, but P7b's patch validator did not run it, so a Terraform-invalid LLM patch could become a Candidate State. Found by TerraPreserve's oracle labels (TP-L1, 20 Nov 2026). | S0 | A required admission gate was absent, so a configuration Terraform rejects could reach evaluation and, if DAIL's own parser accepted it (the "second line", C-99), be promoted into Trusted State: a potential corruption of authoritative state. Uncertainty fails closed, so the higher level is proposed. | P10c (C-227): the patch validator runs the pinned `terraform validate` on the built candidate directory, after the build and before normalization; a failure refuses the patch (INVALID_OUTPUT) and no candidate exists; validator version 3; with no runner, generation refuses to start. For fixed patches C-99 was already enforced by the P8 harness. |
| D-3 | C-209, C-210 | Under C and C′, the open target of C-196 rejected every F8 trajectory at step 1 (`INSUFFICIENT_EVIDENCE`): the work set did not schedule a fresh result for an invariant that was not PROTECTED in the parent, so the rule could not reach its purpose. Found in the P8a dev-run harness check. | S1 | A defect in the verification work set (impact/verification scope) that broke required behaviour (C-159 requires a fresh result for every non-PROTECTED reference; R(C_t) = G_gate ∪ U_t ∪ I_t ∪ B). It failed closed (REJECT, never PROMOTE), so there was no trust bypass; S0 is not proposed. | P8a-2 (C-210): `DailScopePolicy` version `dail-scope-2` adds one item, reason `NOT_PROTECTED_IN_PARENT`, for every invariant not PROTECTED in the parent that impact did not list; `VerificationScopePolicy.select` takes `parent_refs`. |
| D-4 | C-216 | Baseline items under registry v1.1 looked up the version-1 definition (`core/verification/baseline.py`), so a baseline item and its invariant item could use different rules. Found by the external review of PR #31; it affected every run under registry v1.1. | S1 | A verifier defect affecting required behaviour (a baseline item must apply the same §3.3 clause as its invariant). | P8b-2 (C-216): baseline items use the definition the run holds for their invariant (the highest version if more than one), record its id and version, and apply that registry's clause; with no definition the item stays UNSUPPORTED `invariant.unknown`. |
| D-5 | C-111 | Two value-model defects: `normalize_number` rounded a `Decimal` to 28 digits, silently changing a long decimal; `known_set` treated `Known(True)` and `Known(1)` as equal. Found and fixed in P3a-2 step 3. | S1 | The value model feeds identity and verification; a silent change or a false equality of values can change a verifier's input and so its result, which is required behaviour. No promotion was recorded as affected, so S0 is not proposed. | P3a-2 step 3 (C-111): a number that cannot be kept exactly now raises; `known_set` compares sort keys. Regression tests in `tests/unit/test_terraform_values.py`. |
| D-6 | C-156 | INV-FUNC-001: an unresolved entry of `vpc_security_group_ids` (a variable, a `concat` with a variable, a group of unknown `count`) reached row 6 and gave **PASS** when the known groups established the path, where registry §6.4 row 4 requires UNKNOWN. Found by the external review of PR #22. | S0 | A required verifier returned an incorrect PASS on an indeterminate input: a potential unsafe promotion. | P5b-fix (C-156): such an entry (and one referencing a placeholder group) is added to the row 4 reasons, so the result is UNKNOWN (`attribute.unresolved`); `engine` is compared exactly with `postgres`. Two P5b tests that asserted the superseded results were changed in the commit that changed the code. |
| D-7 | C-162 | A STRUCTURAL-typed PASS with an INVARIANT target id hid an invariant FAIL in `decide`: reproduced in the P6a review on INV-SEC-001, INV-FUNC-001 and a `RESOURCE:` item, each giving PROMOTE (the P6a blocking condition). | S0 | Reproduced PROMOTE over a FAIL: an unsafe promotion path in the Promotion Controller's decision. | P6b step 1 (C-162): `VerificationReport` rejects two results with the same `target_id` whatever their type; `decide` looks up each required item by `(target_type, target_id)` and examines every result with a required id; a second result or a wrong type is `INCONSISTENT_REPORTS` (REJECT) and a FAIL among them stays blocking. |

Not listed: register rows that record a design choice, a reading of a spec, or a known gap closed by new behaviour
rather than a defect found and fixed (for example C-136, which closes the recorded RDS placement gap). The review may
add rows; P10g adds none beyond the register.

## Effect on the release blockers (Doc 15 §36, "an open S0 or S1 defect")

No defect above is open after P10g. The three S0 and three S1 defects proposed above were fixed in merged packages
before `protocol-v1`, each with tests that are part of the suite run in QA report 2.
