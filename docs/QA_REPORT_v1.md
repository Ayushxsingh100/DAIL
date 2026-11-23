# QA report v1 (Doc 12 §44 QAReport)

Release candidate `protocol-v1` (`c5f32de`). Written in P10f (23 Nov 2026), after the single analysis of the main
run. The external review decides any gate; this report does not mark one passed.

## QAReport

| Field | Value |
|---|---|
| `run_id` | `p10f-qa-2026-11-23` (suite run at the tag in `X:\DAIL-ref`, 23 Nov 2026; logs `p10f-devtest.log`, `p10f-lint.log`, `p10f-pytest.log` in `X:\DAIL-mainrun-logs`). Main-run experiment `a502ee87-1ebd-597e-8c6d-7134042f2438`. |
| `release_candidate` | `protocol-v1`, `c5f32deb9f9341f422f8f00eff50c942a384c085`; `docs/PROTOCOL_v1.md` SHA-256 `f860c4c624080730b3164d56ec9adf3a30e1a5426c5a25a3028185563321bcaa` |
| `pass_count` | `dev.py test` (stdlib unittest): 4,689 of 4,702 tests (4,702 run, 3 failures, 10 skipped). `pytest`: 4,693 passed (and 81,284 subtests). `dev.py lint`: black, ruff and mypy all pass (390 files, 192 source files). |
| `fail_count` | 3: `dev.py test` `FAILED (failures=3, skipped=10)`; `pytest` `3 failed, 4693 passed, 10 skipped`. |
| `skipped_count` | 10 (reasons below). |
| `safety_failures[]` | none (see the release blockers below) |
| `regression_failures[]` | the 3 failures below |
| `coverage_summary` | the 19 Doc 12 Appendix A families below |
| `environment` | Windows 11 Home 10.0.26300; Python 3.12.10 (`py -3.12` and the venv `.venv`); Terraform 1.15.8 and `hashicorp/aws` 6.53.0 (offline mirror); Ollama server 0.40.17 with the three §8 models (digests match); TerraPreserve `terrapreserve-v1.0` (`27f0ee4`) as `TERRAPRESERVE_ROOT`; no AWS account or credentials (C-71). |
| `decision` | **BLOCK** (the authors' decision, 23 Nov 2026: three failures at the release candidate count as a regression failure; uncertainty fails closed) |

### `regression_failures[]`

All three are subtests of one test, `tests/unit/test_p10e_lock_order.py::TestTheCommand::test_every_step_is_refused_off_the_tag_and_writes_nothing`, with `argv` = `['reference']`, `['reference', '--resume']` and `['generate']` (the `['analyse']` subtest passes):

```
AssertionError: Regex didn't match: 'protocol-v1|no main run' not found in
'error: the test split is refused: no V1_MANIFEST_PRIVATE.json in the private directory\n'
```

The test's class docstring says it runs "on this repository, which is not at `protocol-v1`". At the tag the guard's
tag check passes, so the guard refuses at its next check (the private manifest) and the expected message is not
printed; the command still returns 2. Because the regex assertion failed, the test's next assertion ("writes
nothing") was not reached for those three subtests. A scratch run of the same body at the tag (no file edited)
showed every step refused with return code 2 and nothing written under `DAIL_EXPERIMENT_ROOT`:

```
['reference'] rc 2 | root after: [] | error: the test split is refused: no V1_MANIFEST_PRIVATE.json in the private directory
['reference', '--resume'] rc 2 | root after: [] | error: the test split is refused: no V1_MANIFEST_PRIVATE.json in the private directory
['generate'] rc 2 | root after: [] | error: the test split is refused: no V1_MANIFEST_PRIVATE.json in the private directory
['analyse'] rc 2 | root after: [] | error: no main run to resume: no main-run.lock
```

The test was not changed: nothing may change at the release candidate, and a test is never changed to match the
code. A follow-up package can fix the test's premise in a new commit; QA is then rerun.

### Skips (10, `pytest -ra`)

| Test | Reason |
|---|---|
| `tests/unit/test_experiment_terrapreserve.py:28`, `:38` | set `TERRAPRESERVE_ROOT` to a TerraPreserve v1.0 checkout |
| `tests/unit/test_llm_candidate_e2e.py:306` | opt-in: `DAIL_OLLAMA_TEST=1` |
| `tests/unit/test_llm_ollama.py:291` | opt-in: `DAIL_OLLAMA_TEST=1` |
| `tests/unit/test_p10a_wiring.py:31` | opt-in: `DAIL_OLLAMA_TEST=1`, `TERRAPRESERVE_ROOT` and `DAIL_TERRAFORM_MIRROR` (C-227) |
| `tests/unit/test_p10c_validate_gate.py:305` | opt-in: `DAIL_TERRAFORM_TEST=1` and `DAIL_TERRAFORM_MIRROR` |
| `tests/unit/test_p10d_metrics_final.py:365` | set `TERRAPRESERVE_ROOT` to check the catalogue |
| `tests/unit/test_p10e_guard.py:213` | set `TERRAPRESERVE_ROOT` to check `V1_MANIFEST.sha256` at the tag |
| `tests/unit/test_p8b_scoring_report.py:116` | set `TERRAPRESERVE_ROOT` to check the sentences against the catalogue |
| `tests/unit/test_terraform_config.py:774` | this system does not allow creating symbolic links |

### `coverage_summary`: the 19 mandatory families (Doc 12 Appendix A)

Each family maps to named tests in the suite above (all of them ran and passed at the tag; none is among the
failures or skips).

| Family | Tests |
|---|---|
| baseline establishment | `tests/unit/test_baseline.py::TestTheCanonicalBaseline`; `test_baseline.py::test_a_refused_baseline_can_be_established_once_the_cause_is_gone`; `test_registry_v1.py::TestOnTheCanonicalBaselineGraph` |
| public SSH violation | `test_p5_gate_probes.py::test_the_trusted_state_has_public_ssh_open`; `test_promotion_fixtures.py::test_v0_has_public_ssh_open_and_the_database_path_protected`; `test_terraform_normalization_fixtures.py::test_the_public_ssh_predicate_is_machine_detectable_from_the_index` |
| public SSH repair | `test_orchestrator.py::test_the_safe_repair_is_promoted_into_version_one`; `test_p5_gate_probes.py::test_the_ssh_fix_that_keeps_the_path_aggregates_to_pass`; `test_promotion_decide.py::test_the_canonical_safe_repair_is_promoted` |
| EC2→RDS reachable | `test_promotion_fixtures.py::test_v0_has_public_ssh_open_and_the_database_path_protected`; `test_reachability_predicate.py::TestParameters`; `test_p5_gate_probes.py::test_the_ssh_fix_that_keeps_the_path_aggregates_to_pass` |
| EC2→RDS broken | `test_verification_fixtures.py::test_the_repair_that_breaks_the_database_path_aggregates_to_fail`; `test_promotion_fixtures.py::test_the_repair_that_breaks_the_database_path_is_rejected`; `test_registry_v1_1.py::test_the_repair_that_breaks_the_database_path_is_rejected` |
| security repair breaks function | `test_orchestrator.py::test_the_regression_is_rejected_and_version_zero_stays`; `test_p5_gate_probes.py::test_the_ssh_fix_that_breaks_the_path_aggregates_to_fail`; `test_llm_candidate_e2e.py::test_the_repair_that_breaks_the_database_path_is_rejected`; `test_p8a_conditions.py::test_the_same_regression_is_rejected_under_b_and_c` |
| safe repair | `test_promotion_fixtures.py::test_the_safe_repair_is_promoted`; `test_promotion_pipeline6.py::test_the_safe_repair_becomes_version_one`; `test_experiment_harness.py::test_the_safe_repair_is_promoted_by_every_condition`; `test_llm_candidate_e2e.py::test_the_safe_repair_is_promoted` |
| created resource | `test_identity_engine.py::test_a_candidate_resource_with_no_trusted_counterpart_is_created`; `test_dependency_fixtures.py::test_sg_created_has_the_new_group_in_the_sec_001_scope` |
| deleted dependency | `test_identity_engine.py::test_a_trusted_resource_with_no_candidate_is_deleted`; `test_dependency_fixtures.py::test_rds_deleted_binding_ends_at_an_absent_node`; `test_dependency_fixtures.py::test_an_empty_state_with_a_deleted_endpoint_still_has_uncertain_edges` |
| replacement | `test_identity_engine.py::TestReplacement`; `test_identity_engine.py::test_a_known_name_change_is_replacement`; `test_identity_engine.py::test_replaced_is_never_concluded_for_an_unsupported_type` |
| ambiguous identity | `test_identity_fixtures.py::test_ambiguous_identity_uncertain_v1`; `test_identity_engine.py::test_cyclic_ambiguous_moves_are_refused`; `test_dependency_fixtures.py::test_ambiguous_identity_graphs_differ_in_structure` |
| unknown dependency | `test_dependency_fixtures.py::test_unknown_dependency_gives_an_uncertain_edge_and_an_indeterminate_rule`; `test_dependency_infrastructure.py::test_s2_an_unknown_value_is_an_uncertain_edge_to_the_unresolved_node`; `test_baseline.py::test_an_unknown_result_gives_an_uncertain_reference_never_protected` |
| unsupported relationship | `test_dependency_fixtures.py::test_unsupported_relationship_keeps_the_acl_as_an_unsupported_node`; `test_dependency_fixtures.py::test_unsupported_relationship_has_no_typed_edge_from_the_acl`; `test_dependency_infrastructure.py::test_s3_a_literal_id_is_an_unsupported_edge_to_the_external_node` |
| stale parent | `tests/adversarial/test_state_machine_rules.py::test_a_stale_candidate_cannot_promote`; `test_state_machine_rules.py::test_staleness_never_changes_the_current_state`; `tests/unit/test_chain.py::test_a_stale_candidate_ends_with_a_stale_parent_rejection` |
| verifier error | `tests/adversarial/test_state_machine_rules.py::test_verifier_error_is_neither_pass_nor_fail`; `test_e2e_chains.py::test_a_verifier_error_is_an_escalation_and_nothing_is_promoted`; `test_orchestrator.py::test_a_crashing_verifier_is_a_verifier_error_and_an_escalate` |
| evidence tampering | `tests/adversarial/test_evidence_rules.py::TestProbe3Tampering`; `test_evidence_rules.py::test_tampered_evidence_is_not_proof_in_any_context`; `test_chain.py::test_a_tampered_payload_is_found`; `test_codec.py::test_a_tampered_trusted_state_is_refused_by_its_hash` |
| LLM malformed output | `test_llm_parser.py::test_malformed_json`; `test_llm_parser.py::test_a_malformed_address_is_invalid_output`; `test_llm_ollama.py::test_a_malformed_body_is_invalid_output` |
| prompt injection | `test_llm_context.py::test_an_injected_instruction_stays_inside_the_data_delimiter`; `test_llm_candidate_e2e.py::test_an_injected_description_in_the_trusted_state_stays_data` |
| duplicate promotion | `test_promotion_commit.py::test_the_same_decision_again_returns_the_same_state_and_writes_nothing`; `test_promotion_commit.py::test_recording_the_same_decision_twice_changes_nothing`; `test_e2e_idempotency.py::test_a_crash_after_a_non_promote_decision_is_a_duplicate_on_rerun` |

Test paths are under `tests/unit/` unless written with `tests/adversarial/`.

## Release blockers (Doc 15 §36)

| Blocker | Holds? | Evidence |
|---|---|---|
| an unsafe promotion observed under C | no | `docs/P10_RESULTS.json` `other.C.unsafe_promotions_per_promotion` 0/63 and `unsafe_promotions_per_evaluated` 0/113; the extraction list `unsafe_promotions_c` is empty (stopping rule, protocol §7: none); LLM track `any_unsafe_promoted_at_k` under C 0/36 for each of the three models |
| a required verifier returning an incorrect PASS | no | κ per invariant (`kappa.json`, quoted in `docs/P10_RESULTS.md` §8): 1.0 for all four invariants; the six DAIL–oracle disagreements are all DAIL UNSUPPORTED against oracle PASS, none a DAIL PASS against an oracle FAIL; `truth_recall_misses` empty |
| a promotion bypass | no | the main run promoted only through the Promotion Controller (no other path exists: architecture tests in `tests/contract/` pass at the tag); `tests/adversarial/test_state_machine_rules.py::test_replace_cannot_promote_a_candidate` and the duplicate-promotion tests above pass |
| an evidence-integrity failure affecting proof | no | the tampering tests above pass; the canonical chain tests (`test_orchestrator.py::TestTheCanonicalDecisions::test_the_chains_are_complete`) pass at the tag and in the clean clone |
| a stale candidate accepted | no | the stale-parent tests above pass |
| secret leakage | no | gitleaks passes in CI on `main` at `c5f32de` (required check); no secret was printed or committed in P10e-run, TP-L2 or P10f |
| critical state corruption | no | trials by status at the main run: 384 COMPLETED, 0 FAILED, 0 ABORTED, one attempt each; the main-run ledger shows reference, generation and analysis each started and completed once; no power interruption was recorded (64 polls, no power event) |
| an open S0 or S1 defect | no recorded one | the repository keeps no severity-rated defect list; `docs/DECISIONS_REGISTER.md` has five Open rows (C-128, C-130, C-149, C-155, C-169) and `docs/PHASE_GATES.md` lists open limits (for example P7b limits 3 to 6); none is recorded as S0 or S1 |
| a core regression failure | **yes (authors' decision)** | the 3 failures above. The test covers the main-run guard (`experiments/mainrun`, not `core/`) and the guarded behaviour holds at the tag (scratch run above), but the authors decided on 23 Nov 2026 that three failures at the release candidate block it |

Decision: **BLOCK**.

## Clean-environment demo (Doc 15 §17.2 "Demo is repeatable from clean environment")

A fresh clone from GitHub into a new folder, `X:\DAIL-clean-demo-p10f` (23 Nov 2026; full log
`X:\DAIL-mainrun-logs\p10f-demo.log`). Output quoted (the test dots and fuzz case lists shortened):

```
$ git clone --branch protocol-v1 https://github.com/Ayushxsingh100/DAIL.git X:/DAIL-clean-demo-p10f
$ git describe --exact-match --tags HEAD; git rev-parse HEAD
protocol-v1
c5f32deb9f9341f422f8f00eff50c942a384c085
$ py -3.12 scripts/dev.py bootstrap
== Python 3.12.10
== Loading configuration (environment: dev)
   config_hash 0db2f412c20f0b64648c7d440151bff12f8bc991a9822672d4afa0f93a7ab8d9; safety flags {'llm.generation_enabled': False, 'promotion.automatic_enabled': False}
== Creating .local/ and the artifact root
== Initializing the local database (schema 5: domain, evidence and audit tables)
== Running tests (standard library unittest, no secrets, no network)
FAIL: test_every_step_is_refused_off_the_tag_and_writes_nothing (...) (argv=['reference'])
FAIL: test_every_step_is_refused_off_the_tag_and_writes_nothing (...) (argv=['reference', '--resume'])
FAIL: test_every_step_is_refused_off_the_tag_and_writes_nothing (...) (argv=['generate'])
Ran 4702 tests in 786.357s
FAILED (failures=3, skipped=10)
bootstrap FAILED
== Health checks
liveness: PASS - process is running
readiness: PASS - configuration loaded and validated (environment dev, schema version 1)
database: PASS - .local/dail.db: opened read-only, integrity ok, 16 expected tables present
artifact_store: PASS - .local/artifacts: directory exists and is writable
llm_provider: SKIPPED - LLM generation disabled (llm.generation_enabled = false)
bootstrap rc=1
$ py -3.12 -m unittest -v tests.unit.test_orchestrator.TestTheCanonicalDecisions tests.unit.test_llm_candidate_e2e.TestEndToEnd
test_every_decision_is_stored ... ok
test_the_chains_are_complete ... ok
test_the_regression_is_rejected_and_version_zero_stays ... ok
test_the_result_carries_the_reports_for_the_caller ... ok
test_the_safe_repair_is_promoted_into_version_one ... ok
test_no_solution_and_uncertain_create_no_candidate ... ok
test_the_candidate_lineage_points_to_one_parent ... ok
test_the_repair_that_breaks_the_database_path_is_rejected ... ok
test_the_safe_repair_is_promoted ... ok
Ran 9 tests in 3.183s
OK
```

`bootstrap` fails in the clean clone for the same 3 failures as above (the clone is at the tag). The health checks
pass, and the canonical end-to-end tests pass: the unsafe candidate (the repair that breaks the database path) is
REJECTED and version 0 stays, the safe candidate is PROMOTED into version 1, and the evidence chains are complete.
The clone was not deleted by this session (a safety check stopped the removal); the user deletes it.
