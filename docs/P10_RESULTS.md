# P10 results: the main-run analysis (protocol v1)

Quoted from the analysis output of `python -m experiments.mainrun analyse`, run once at the tag `protocol-v1` (`c5f32de`) on 23 Nov 2026 (08:06:39Z to 08:10:54Z), experiment `a502ee87-1ebd-597e-8c6d-7134042f2438`, written to `$DAIL_EXPERIMENT_ROOT/experiment/a502ee87-1ebd-597e-8c6d-7134042f2438/analysis/main-run-extractor-6-analysis-2/`. This file only quotes tables from those files; it adds no interpretation. `docs/P10_RESULTS.json` is a byte-identical copy of `analysis.json`. `extraction.json` holds test-split scenario ids and resource addresses: it stays private under `$DAIL_EXPERIMENT_ROOT`, and only its aggregate rows (scope `all`, no trial or scenario id) are quoted here; list entries are quoted without scenario ids or resource names.

Marker: `MAIN RUN (test split, protocol-v1)`. Versions: extractor `extractor-6`, analysis `analysis-2`, metrics `metrics-final-1`. ρ for the analysis: 0.3.

| Source file | SHA-256 | Committed |
|---|---|---|
| `analysis.json` | `56381e764279be19326202b94b1db79914d37c28fb0d994ed2da1c137a39ac0e` | as `docs/P10_RESULTS.json` |
| `coverage.json` | `58d33716616c9aabd9676160181f98e3043d5cacec99d3cb69636b6fe6bfb004` | quoted below |
| `kappa.json` | `c6d2f5a0eb0bed48acd3a0d80f2cf23be209bc2ebdd68e431318ebfa637905c4` | quoted below |
| `test_mr_cluster_sizes.json` | `b92622daad5adf2b941c7f30509e40614683991888d568bef25aaf5668e5c3b6` | quoted below |
| `adjudication.json` | `fb970b65d73f1b1c69177bafd67ad6cf7b4aa8896781752457f65eba49cb26f0` | quoted below |
| `extraction.json` | `56fb57b281fba650517b7feea44642232556eb4440097567a075d3da0c78e8fd` | no (test ids; private) |

## 1. Cluster sizes and the coverage rule (C-238)

| Stratum | Clusters | Scenarios | Sizes (sorted) |
|---|---|---|---|
| all/test | 31 | 42 | 3, 3, 3, 3, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 |
| change_request/test | 24 | 30 | 3, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 |
| repair/test | 11 | 12 | 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 |

Simulation: 4000 replicates, seed 20261121, ρ grid [0.0, 0.05, 0.1, 0.2, 0.3], threshold 0.93.

| Stratum | Minimum coverage | Threshold | Outcome | At (config, ρ, π, true difference) |
|---|---|---|---|---|
| all | 0.92875 | 0.93 | descriptive | all/test, ρ=0.3, π=[0.1, 0.4, 0.1, 0.4], Δ=0.3 |
| change_request | 0.93025 | 0.93 | inferential | change_request/test, ρ=0.1, π=[0.2, 0.3, 0.0, 0.5], Δ=0.3 |
| repair | 0.91425 | 0.93 | descriptive | repair/test, ρ=0.3, π=[0.2, 0.3, 0.0, 0.5], Δ=0.3 |

| Stratum | Outcome in analysis.json |
|---|---|
| all | descriptive |
| change_request | inferential |
| repair | descriptive |

ICC on the test split (`icc_test`): {"all": {"A_minus_C": null, "B": null, "C": null, "C_minus_B": null}, "change_request": {"A_minus_C": null, "B": null, "C": null, "C_minus_B": null}, "repair": {"A_minus_C": null, "B": null, "C": null, "C_minus_B": null}}

## 2. H1: A vs C, missed regression, per stratum

α = 0.05, ρ = 0.3. Holm-adjusted p: change_request 2.384e-07, repair 0.0009766. Holm rejected: change_request True, repair True.

| Stratum | Scenarios | Clusters | Clusters by tier | MR_A | MR_C | Scenario cells (A, C) | Discordant clusters | n₊ | n₋ | n₀ | Exact sign p (two-sided) | Holm p | Min attainable p (C-243) | Scenario-weighted MR_A − MR_C | DEFF-adjusted Newcombe 95% | DEFF | Interval label (coverage rule) | Descriptive tiers |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| change_request | 30 | 24 | {"controlled": 9, "real_world": 15} | 1 | 0 | {"both": 0, "first_only": 30, "neither": 0, "second_only": 0} | 24 | 24 | 0 | 0 | 1.192e-07 | 2.384e-07 | 1.192e-07 | 1 | [0.8171, 1] | 1.16 | inferential | controlled |
| repair | 12 | 11 | {"controlled": 5, "real_world": 6} | 1 | 0 | {"both": 0, "first_only": 12, "neither": 0, "second_only": 0} | 11 | 11 | 0 | 0 | 0.0009766 | 0.0009766 | 0.0009766 | 1 | [0.6442, 1] | 1.05 | descriptive | controlled, real_world |

## 3. H2: B vs C

| Analysis | Common prefix | Scenarios | Clusters | Clusters by tier | n₊ (favours C) | n₋ (favours B) | n₀ | Median cluster W_C − W_B | Share favouring C | One-sided sign p |
|---|---|---|---|---|---|---|---|---|---|---|
| h2_workload | False | 96 | 58 | {"controlled": 10, "real_world": 48} | 56 | 0 | 2 | -1 | 1 | 1.388e-17 |
| h2_workload_common_prefix | True | 96 | 58 | {"controlled": 10, "real_world": 48} | 56 | 0 | 2 | -1 | 1 | 1.388e-17 |

| H2 non-inferiority | Value |
|---|---|
| status | exploratory (C-231) |
| scenarios | 42 |
| clusters | 31 |
| cells (B, C) | {"both": 0, "first_only": 0, "neither": 42, "second_only": 0} |
| MR_C − MR_B | 0 |
| DEFF | 1.2143 |
| one-sided 95% upper limit | 0.0725 |
| δ_NI | 0.05 |
| upper limit below δ_NI | False |

## 4. H3: C vs C′ on F5 (descriptive)

| Metric | C | C′ |
|---|---|---|
| identity_error_rate_certain | 2/13 = 0.1538 [0.0433, 0.4223] | 11/13 = 0.8462 [0.5777, 0.9567] |
| transition_error_rate_certain | 2/13 = 0.1538 [0.0433, 0.4223] | 11/13 = 0.8462 [0.5777, 0.9567] |
| identity_uncertain_share_final | 0/13 = 0 [0, 0.2281] | 0/13 = 0 [0, 0.2281] |
| evidence_transfer_error_rate | 2/8 = 0.25 [0.0715, 0.5907] | 8/8 = 1 [0.6756, 1] |
| identity_excluded_pairs_all | 12 | 12 |

| Moved type | Transitions | W under C | W under C′ | Difference (C′ − C) |
|---|---|---|---|---|
| aws_security_group_rule | 2 | 11 | 13 | 2 |
| aws_subnet | 1 | 3 | 3 | 0 |

Identity errors (from `extraction.json` lists; resource names and scenario ids left out):

| Condition | Oracle effect | Operator | Resource type | Count |
|---|---|---|---|---|
| C | REPLACE | op_f5_force_replacement_safe | aws_instance | 2 |
| C_PRIME | MOVE | op_f5_db_rule_moved_safe | aws_security_group_rule | 1 |
| C_PRIME | MOVE | op_f5_db_rule_moved_unsafe | aws_security_group_rule | 1 |
| C_PRIME | MOVE | op_f5_restructure_moved_safe | aws_subnet | 1 |
| C_PRIME | REPLACE | op_f5_db_sg_replacement_safe | aws_security_group | 2 |
| C_PRIME | REPLACE | op_f5_db_sg_replacement_unsafe | aws_security_group | 4 |
| C_PRIME | REPLACE | op_f5_force_replacement_safe | aws_instance | 2 |

Excluded identity pairs (same source; addresses and scenario ids left out):

| Condition | Operator | Reason | Count |
|---|---|---|---|
| C | op_f1_storage_expand_unsafe | "plus a new ingress from `0.0.0.0/0` to 5432 on the DB group": the catalogue does not say whether the ingress is a new resource. | 4 |
| C | op_f1_vpc_dns_toggle_unsafe | "plus a new ingress from `0.0.0.0/0` to 22 on the app group": the catalogue does not say whether the ingress is a new resource. | 2 |
| C | op_f4_repair_db_port_open_ssh_unsafe | "then opens port 22 to `0.0.0.0/0` on the app group": the catalogue does not say whether a new resource is created. | 4 |
| C | op_f4_repair_rds_public_open_db_unsafe | "then opens 5432 to `0.0.0.0/0` on the DB group": the catalogue does not say whether a new resource is created. | 2 |
| C_PRIME | op_f1_storage_expand_unsafe | "plus a new ingress from `0.0.0.0/0` to 5432 on the DB group": the catalogue does not say whether the ingress is a new resource. | 4 |
| C_PRIME | op_f1_vpc_dns_toggle_unsafe | "plus a new ingress from `0.0.0.0/0` to 22 on the app group": the catalogue does not say whether the ingress is a new resource. | 2 |
| C_PRIME | op_f4_repair_db_port_open_ssh_unsafe | "then opens port 22 to `0.0.0.0/0` on the app group": the catalogue does not say whether a new resource is created. | 4 |
| C_PRIME | op_f4_repair_rds_public_open_db_unsafe | "then opens 5432 to `0.0.0.0/0` on the DB group": the catalogue does not say whether a new resource is created. | 2 |

## 5. H4: blocked unsafe F4

| Condition | Blocked unsafe F4 | All unsafe F4 | Value | Wilson 95% |
|---|---|---|---|---|
| C | 6 | 6 | 1 | [0.6097, 1] |

## 6. Per condition (analysis.json `other`, `work_per_scenario`)

| Metric | A | B | C | C_PRIME |
|---|---|---|---|---|
| false_rejection_rate | 0/65 = 0 [0, 0.0558] | 2/65 = 0.0308 [0.0085, 0.1054] | 2/65 = 0.0308 [0.0085, 0.1054] | 2/65 = 0.0308 [0.0085, 0.1054] |
| impact_precision | — | — | 203/272 = 0.7463 [0.6914, 0.7944] | 203/272 = 0.7463 [0.6914, 0.7944] |
| impact_precision_macro | — | — | 0.7023 (macro over 4) | 0.7023 (macro over 4) |
| impact_recall | — | — | 203/203 = 1 [0.9814, 1] | 203/203 = 1 [0.9814, 1] |
| impact_recall_macro | — | — | 1 (macro over 4) | 1 (macro over 4) |
| missed_regression_rate | 42/42 = 1 [0.9162, 1] | 0/42 = 0 [0, 0.0838] | 0/42 = 0 [0, 0.0838] | 0/42 = 0 [0, 0.0838] |
| missed_regressions_per_regression | 42/42 = 1 [0.9162, 1] | 0/42 = 0 [0, 0.0838] | 0/42 = 0 [0, 0.0838] | 0/42 = 0 [0, 0.0838] |
| mr_no_regression_step | 6 | 6 | 6 | 6 |
| repair_success_change_request | 30/60 = 0.5 [0.3774, 0.6226] | 29/60 = 0.4833 [0.3618, 0.6069] | 29/60 = 0.4833 [0.3618, 0.6069] | 29/60 = 0.4833 [0.3618, 0.6069] |
| repair_success_repair | 18/36 = 0.5 [0.3447, 0.6553] | 17/36 = 0.4722 [0.3199, 0.6299] | 17/36 = 0.4722 [0.3199, 0.6299] | 17/36 = 0.4722 [0.3199, 0.6299] |
| truncated_transitions | 0/116 = 0 [0, 0.0321] | 3/116 = 0.0259 [0.0088, 0.0733] | 3/116 = 0.0259 [0.0088, 0.0733] | 3/116 = 0.0259 [0.0088, 0.0733] |
| truth_recall_impact | — | — | 69/69 = 1 [0.9473, 1] | 69/69 = 1 [0.9473, 1] |
| truth_recall_v | — | — | 69/69 = 1 [0.9473, 1] | 69/69 = 1 [0.9473, 1] |
| unsafe_promotions_per_evaluated | 45/116 = 0.3879 [0.3042, 0.4788] | 0/113 = 0 [0, 0.0329] | 0/113 = 0 [0, 0.0329] | 0/113 = 0 [0, 0.0329] |
| unsafe_promotions_per_promotion | 45/110 = 0.4091 [0.3218, 0.5025] | 0/63 = 0 [3.469e-18, 0.0575] | 0/63 = 0 [3.469e-18, 0.0575] | 0/63 = 0 [3.469e-18, 0.0575] |

| Work per scenario | A | B | C | C_PRIME |
|---|---|---|---|---|
| scenarios | 96 | 96 | 96 | 96 |
| mean W | 3 | 7.25 | 5.5729 | 5.5938 |
| median W | 2 | 6 | 5 | 5 |
| mean baseline_applicable | 0 | 0.1875 | 0.1875 | 0.2083 |
| mean baseline_not_applicable | 0 | 0.0312 | 0.0312 | 0.0417 |
| mean gate | 2.4167 | 2.3542 | 2.3542 | 2.3542 |
| mean invariant_condition | 0.1979 | 1.875 | 0 | 0 |
| mean invariant_impact | 0.3854 | 2.8333 | 2.8333 | 2.8333 |
| mean invariant_not_protected | 0 | 0 | 0.1979 | 0.1979 |

## 7. Per condition and stratum (extraction.json aggregate rows, scope `all`)

### `escalate_rate`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 0/116 = 0 [0, 0.0321] | 0/113 = 0 [0, 0.0329] | 0/113 = 0 [0, 0.0329] | 0/113 = 0 [0, 0.0329] |
| tier=controlled | 0/56 = 0 [6.939e-18, 0.0642] | 0/55 = 0 [0, 0.0653] | 0/55 = 0 [0, 0.0653] | 0/55 = 0 [0, 0.0653] |
| tier=real_world | 0/60 = 0 [0, 0.0602] | 0/58 = 0 [0, 0.0621] | 0/58 = 0 [0, 0.0621] | 0/58 = 0 [0, 0.0621] |
| family=F1 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F2 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F3 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F4 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F5 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F6 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F7 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F8 | 0/32 = 0 [0, 0.1072] | 0/29 = 0 [0, 0.117] | 0/29 = 0 [0, 0.117] | 0/29 = 0 [0, 0.117] |

### `evidence_transfer_error_rate`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 2/8 = 0.25 [0.0715, 0.5907] | 8/8 = 1 [0.6756, 1] |
| family=F3 | 0/0 = — [—, —] | 0/0 = — [—, —] |
| family=F5 | 2/8 = 0.25 [0.0715, 0.5907] | 8/8 = 1 [0.6756, 1] |
| family=F6 | 0/0 = — [—, —] | 0/0 = — [—, —] |

### `evidence_transfer_errors`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 2 | 8 |

### `false_rejection_rate`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 0/65 = 0 [0, 0.0558] | 2/65 = 0.0308 [0.0085, 0.1054] | 2/65 = 0.0308 [0.0085, 0.1054] | 2/65 = 0.0308 [0.0085, 0.1054] |
| tier=controlled | 0/31 = 0 [0, 0.1103] | 0/31 = 0 [0, 0.1103] | 0/31 = 0 [0, 0.1103] | 0/31 = 0 [0, 0.1103] |
| tier=real_world | 0/34 = 0 [0, 0.1015] | 2/34 = 0.0588 [0.0163, 0.1909] | 2/34 = 0.0588 [0.0163, 0.1909] | 2/34 = 0.0588 [0.0163, 0.1909] |
| family=F1 | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F2 | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F3 | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F4 | 0/6 = 0 [2.776e-17, 0.3903] | 1/6 = 0.1667 [0.0301, 0.5635] | 1/6 = 0.1667 [0.0301, 0.5635] | 1/6 = 0.1667 [0.0301, 0.5635] |
| family=F5 | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F6 | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F7 | 0/6 = 0 [2.776e-17, 0.3903] | 1/6 = 0.1667 [0.0301, 0.5635] | 1/6 = 0.1667 [0.0301, 0.5635] | 1/6 = 0.1667 [0.0301, 0.5635] |
| family=F8 | 0/23 = 0 [0, 0.1431] | 0/23 = 0 [0, 0.1431] | 0/23 = 0 [0, 0.1431] | 0/23 = 0 [0, 0.1431] |

### `identity_error_rate`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 2/29 = 0.069 [0.0191, 0.2196] | 11/29 = 0.3793 [0.2269, 0.56] |

### `identity_error_rate_certain`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 2/29 = 0.069 [0.0191, 0.2196] | 11/29 = 0.3793 [0.2269, 0.56] |
| family=F3 | 0/2 = 0 [0, 0.6576] | 0/2 = 0 [0, 0.6576] |
| family=F5 | 2/13 = 0.1538 [0.0433, 0.4223] | 11/13 = 0.8462 [0.5777, 0.9567] |
| family=F6 | 0/14 = 0 [1.388e-17, 0.2153] | 0/14 = 0 [1.388e-17, 0.2153] |

### `identity_excluded_pairs`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 12 | 12 |

### `identity_uncertain_share`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 0/29 = 0 [0, 0.117] | 0/29 = 0 [0, 0.117] |

### `identity_uncertain_share_final`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 0/29 = 0 [0, 0.117] | 0/29 = 0 [0, 0.117] |
| family=F3 | 0/2 = 0 [0, 0.6576] | 0/2 = 0 [0, 0.6576] |
| family=F5 | 0/13 = 0 [0, 0.2281] | 0/13 = 0 [0, 0.2281] |
| family=F6 | 0/14 = 0 [1.388e-17, 0.2153] | 0/14 = 0 [1.388e-17, 0.2153] |

### `impact_precision`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 203/272 = 0.7463 [0.6914, 0.7944] | 203/272 = 0.7463 [0.6914, 0.7944] |
| family=F1 | 12/25 = 0.48 [0.3003, 0.665] | 12/25 = 0.48 [0.3003, 0.665] |
| family=F2 | 28/34 = 0.8235 [0.6649, 0.9165] | 28/34 = 0.8235 [0.6649, 0.9165] |
| family=F3 | 26/31 = 0.8387 [0.6737, 0.9291] | 26/31 = 0.8387 [0.6737, 0.9291] |
| family=F4 | 35/36 = 0.9722 [0.8583, 0.9951] | 35/36 = 0.9722 [0.8583, 0.9951] |
| family=F5 | 18/30 = 0.6 [0.4232, 0.7541] | 18/30 = 0.6 [0.4232, 0.7541] |
| family=F6 | 27/29 = 0.931 [0.7804, 0.9809] | 27/29 = 0.931 [0.7804, 0.9809] |
| family=F7 | 26/32 = 0.8125 [0.6469, 0.9111] | 26/32 = 0.8125 [0.6469, 0.9111] |
| family=F8 | 31/55 = 0.5636 [0.4327, 0.6863] | 31/55 = 0.5636 [0.4327, 0.6863] |

### `impact_precision_macro`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 0.7023 (macro over 4) | 0.7023 (macro over 4) |

### `impact_precision_per_invariant`

| Stratum | C | C_PRIME |
|---|---|---|
| invariant=INV-FUNC-001 | 65/107 = 0.6075 [0.5128, 0.6947] | 65/107 = 0.6075 [0.5128, 0.6947] |
| invariant=INV-SEC-001 | 65/73 = 0.8904 [0.7984, 0.9434] | 65/73 = 0.8904 [0.7984, 0.9434] |
| invariant=INV-SEC-002 | 65/73 = 0.8904 [0.7984, 0.9434] | 65/73 = 0.8904 [0.7984, 0.9434] |
| invariant=INV-SEC-003 | 8/19 = 0.4211 [0.2314, 0.6372] | 8/19 = 0.4211 [0.2314, 0.6372] |

### `impact_recall`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 203/203 = 1 [0.9814, 1] | 203/203 = 1 [0.9814, 1] |
| family=F1 | 12/12 = 1 [0.7575, 1] | 12/12 = 1 [0.7575, 1] |
| family=F2 | 28/28 = 1 [0.8794, 1] | 28/28 = 1 [0.8794, 1] |
| family=F3 | 26/26 = 1 [0.8713, 1] | 26/26 = 1 [0.8713, 1] |
| family=F4 | 35/35 = 1 [0.9011, 1] | 35/35 = 1 [0.9011, 1] |
| family=F5 | 18/18 = 1 [0.8241, 1] | 18/18 = 1 [0.8241, 1] |
| family=F6 | 27/27 = 1 [0.8754, 1] | 27/27 = 1 [0.8754, 1] |
| family=F7 | 26/26 = 1 [0.8713, 1] | 26/26 = 1 [0.8713, 1] |
| family=F8 | 31/31 = 1 [0.8897, 1] | 31/31 = 1 [0.8897, 1] |

### `impact_recall_macro`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 1 (macro over 4) | 1 (macro over 4) |

### `impact_recall_per_invariant`

| Stratum | C | C_PRIME |
|---|---|---|
| invariant=INV-FUNC-001 | 65/65 = 1 [0.9442, 1] | 65/65 = 1 [0.9442, 1] |
| invariant=INV-SEC-001 | 65/65 = 1 [0.9442, 1] | 65/65 = 1 [0.9442, 1] |
| invariant=INV-SEC-002 | 65/65 = 1 [0.9442, 1] | 65/65 = 1 [0.9442, 1] |
| invariant=INV-SEC-003 | 8/8 = 1 [0.6756, 1] | 8/8 = 1 [0.6756, 1] |

### `kappa`

| Stratum | B |
|---|---|
| invariant=INV-FUNC-001 | 1 (macro over 207) |
| invariant=INV-SEC-001 | 1 (macro over 207) |
| invariant=INV-SEC-002 | 1 (macro over 207) |
| invariant=INV-SEC-003 | 1 (macro over 209) |

### `missed_regressions_per_regression`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 42/42 = 1 [0.9162, 1] | 0/42 = 0 [0, 0.0838] | 0/42 = 0 [0, 0.0838] | 0/42 = 0 [0, 0.0838] |
| tier=controlled | 21/21 = 1 [0.8454, 1] | 0/21 = 0 [0, 0.1546] | 0/21 = 0 [0, 0.1546] | 0/21 = 0 [0, 0.1546] |
| tier=real_world | 21/21 = 1 [0.8454, 1] | 0/21 = 0 [0, 0.1546] | 0/21 = 0 [0, 0.1546] | 0/21 = 0 [0, 0.1546] |
| family=F1 | 6/6 = 1 [0.6097, 1] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F2 | 0/0 = — [—, —] | 0/0 = — [—, —] | 0/0 = — [—, —] | 0/0 = — [—, —] |
| family=F3 | 6/6 = 1 [0.6097, 1] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F4 | 6/6 = 1 [0.6097, 1] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F5 | 6/6 = 1 [0.6097, 1] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F6 | 6/6 = 1 [0.6097, 1] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F7 | 6/6 = 1 [0.6097, 1] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F8 | 6/6 = 1 [0.6097, 1] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |

### `promote_rate`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 110/116 = 0.9483 [0.8917, 0.9761] | 63/113 = 0.5575 [0.4656, 0.6457] | 63/113 = 0.5575 [0.4656, 0.6457] | 63/113 = 0.5575 [0.4656, 0.6457] |
| tier=controlled | 53/56 = 0.9464 [0.8539, 0.9816] | 31/55 = 0.5636 [0.4327, 0.6863] | 31/55 = 0.5636 [0.4327, 0.6863] | 31/55 = 0.5636 [0.4327, 0.6863] |
| tier=real_world | 57/60 = 0.95 [0.863, 0.9829] | 32/58 = 0.5517 [0.4245, 0.6725] | 32/58 = 0.5517 [0.4245, 0.6725] | 32/58 = 0.5517 [0.4245, 0.6725] |
| family=F1 | 12/12 = 1 [0.7575, 1] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F2 | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F3 | 12/12 = 1 [0.7575, 1] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F4 | 12/12 = 1 [0.7575, 1] | 5/12 = 0.4167 [0.1933, 0.6805] | 5/12 = 0.4167 [0.1933, 0.6805] | 5/12 = 0.4167 [0.1933, 0.6805] |
| family=F5 | 12/12 = 1 [0.7575, 1] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F6 | 12/12 = 1 [0.7575, 1] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F7 | 12/12 = 1 [0.7575, 1] | 5/12 = 0.4167 [0.1933, 0.6805] | 5/12 = 0.4167 [0.1933, 0.6805] | 5/12 = 0.4167 [0.1933, 0.6805] |
| family=F8 | 32/32 = 1 [0.8928, 1] | 23/29 = 0.7931 [0.6161, 0.9015] | 23/29 = 0.7931 [0.6161, 0.9015] | 23/29 = 0.7931 [0.6161, 0.9015] |

### `regressions`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 42/116 = 0.3621 [0.2803, 0.4526] | 42/113 = 0.3717 [0.2882, 0.4636] | 42/113 = 0.3717 [0.2882, 0.4636] | 42/113 = 0.3717 [0.2882, 0.4636] |
| tier=controlled | 21/56 = 0.375 [0.2601, 0.5059] | 21/55 = 0.3818 [0.2652, 0.5139] | 21/55 = 0.3818 [0.2652, 0.5139] | 21/55 = 0.3818 [0.2652, 0.5139] |
| tier=real_world | 21/60 = 0.35 [0.2417, 0.4764] | 21/58 = 0.3621 [0.2505, 0.4907] | 21/58 = 0.3621 [0.2505, 0.4907] | 21/58 = 0.3621 [0.2505, 0.4907] |
| family=F1 | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F2 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F3 | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F4 | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F5 | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F6 | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F7 | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F8 | 6/32 = 0.1875 [0.0889, 0.3531] | 6/29 = 0.2069 [0.0985, 0.3839] | 6/29 = 0.2069 [0.0985, 0.3839] | 6/29 = 0.2069 [0.0985, 0.3839] |

### `reject_rate`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 6/116 = 0.0517 [0.0239, 0.1083] | 50/113 = 0.4425 [0.3543, 0.5344] | 50/113 = 0.4425 [0.3543, 0.5344] | 50/113 = 0.4425 [0.3543, 0.5344] |
| tier=controlled | 3/56 = 0.0536 [0.0184, 0.1461] | 24/55 = 0.4364 [0.3137, 0.5673] | 24/55 = 0.4364 [0.3137, 0.5673] | 24/55 = 0.4364 [0.3137, 0.5673] |
| tier=real_world | 3/60 = 0.05 [0.0171, 0.137] | 26/58 = 0.4483 [0.3275, 0.5755] | 26/58 = 0.4483 [0.3275, 0.5755] | 26/58 = 0.4483 [0.3275, 0.5755] |
| family=F1 | 0/12 = 0 [2.776e-17, 0.2425] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F2 | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F3 | 0/12 = 0 [2.776e-17, 0.2425] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F4 | 0/12 = 0 [2.776e-17, 0.2425] | 7/12 = 0.5833 [0.3195, 0.8067] | 7/12 = 0.5833 [0.3195, 0.8067] | 7/12 = 0.5833 [0.3195, 0.8067] |
| family=F5 | 0/12 = 0 [2.776e-17, 0.2425] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F6 | 0/12 = 0 [2.776e-17, 0.2425] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] | 6/12 = 0.5 [0.2538, 0.7462] |
| family=F7 | 0/12 = 0 [2.776e-17, 0.2425] | 7/12 = 0.5833 [0.3195, 0.8067] | 7/12 = 0.5833 [0.3195, 0.8067] | 7/12 = 0.5833 [0.3195, 0.8067] |
| family=F8 | 0/32 = 0 [0, 0.1072] | 6/29 = 0.2069 [0.0985, 0.3839] | 6/29 = 0.2069 [0.0985, 0.3839] | 6/29 = 0.2069 [0.0985, 0.3839] |

### `repair_success`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| kind=repair | 18/36 = 0.5 [0.3447, 0.6553] | 17/36 = 0.4722 [0.3199, 0.6299] | 17/36 = 0.4722 [0.3199, 0.6299] | 17/36 = 0.4722 [0.3199, 0.6299] |
| kind=change_request | 30/60 = 0.5 [0.3774, 0.6226] | 29/60 = 0.4833 [0.3618, 0.6069] | 29/60 = 0.4833 [0.3618, 0.6069] | 29/60 = 0.4833 [0.3618, 0.6069] |

### `retry_rate`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 0/116 = 0 [0, 0.0321] | 0/113 = 0 [0, 0.0329] | 0/113 = 0 [0, 0.0329] | 0/113 = 0 [0, 0.0329] |
| tier=controlled | 0/56 = 0 [6.939e-18, 0.0642] | 0/55 = 0 [0, 0.0653] | 0/55 = 0 [0, 0.0653] | 0/55 = 0 [0, 0.0653] |
| tier=real_world | 0/60 = 0 [0, 0.0602] | 0/58 = 0 [0, 0.0621] | 0/58 = 0 [0, 0.0621] | 0/58 = 0 [0, 0.0621] |
| family=F1 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F2 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F3 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F4 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F5 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F6 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F7 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F8 | 0/32 = 0 [0, 0.1072] | 0/29 = 0 [0, 0.117] | 0/29 = 0 [0, 0.117] | 0/29 = 0 [0, 0.117] |

### `transition_error_rate_certain`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 2/29 = 0.069 [0.0191, 0.2196] | 11/29 = 0.3793 [0.2269, 0.56] |
| family=F3 | 0/2 = 0 [0, 0.6576] | 0/2 = 0 [0, 0.6576] |
| family=F5 | 2/13 = 0.1538 [0.0433, 0.4223] | 11/13 = 0.8462 [0.5777, 0.9567] |
| family=F6 | 0/14 = 0 [1.388e-17, 0.2153] | 0/14 = 0 [1.388e-17, 0.2153] |

### `truncated_transitions`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 0/116 = 0 [0, 0.0321] | 3/116 = 0.0259 [0.0088, 0.0733] | 3/116 = 0.0259 [0.0088, 0.0733] | 3/116 = 0.0259 [0.0088, 0.0733] |

### `truth_change_coverage`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 69/69 = 1 [0.9473, 1] | 69/69 = 1 [0.9473, 1] |
| family=F1 | 6/6 = 1 [0.6097, 1] | 6/6 = 1 [0.6097, 1] |
| family=F2 | 6/6 = 1 [0.6097, 1] | 6/6 = 1 [0.6097, 1] |
| family=F3 | 6/6 = 1 [0.6097, 1] | 6/6 = 1 [0.6097, 1] |
| family=F4 | 18/18 = 1 [0.8241, 1] | 18/18 = 1 [0.8241, 1] |
| family=F5 | 6/6 = 1 [0.6097, 1] | 6/6 = 1 [0.6097, 1] |
| family=F6 | 6/6 = 1 [0.6097, 1] | 6/6 = 1 [0.6097, 1] |
| family=F7 | 6/6 = 1 [0.6097, 1] | 6/6 = 1 [0.6097, 1] |
| family=F8 | 15/15 = 1 [0.7961, 1] | 15/15 = 1 [0.7961, 1] |

### `truth_recall_impact`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 69/69 = 1 [0.9473, 1] | 69/69 = 1 [0.9473, 1] |

### `truth_recall_v`

| Stratum | C | C_PRIME |
|---|---|---|
| all | 69/69 = 1 [0.9473, 1] | 69/69 = 1 [0.9473, 1] |

### `unknown_rate`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 0/288 = 0 [0, 0.0132] | 0/699 = 0 [0, 0.0055] | 0/699 = 0 [0, 0.0055] | 0/702 = 0 [4.337e-19, 0.0054] |
| tier=controlled | 0/138 = 0 [1.735e-18, 0.0271] | 0/338 = 0 [0, 0.0112] | 0/338 = 0 [0, 0.0112] | 0/339 = 0 [0, 0.0112] |
| tier=real_world | 0/150 = 0 [1.735e-18, 0.025] | 0/361 = 0 [0, 0.0105] | 0/361 = 0 [0, 0.0105] | 0/363 = 0 [8.674e-19, 0.0105] |
| family=F1 | 0/24 = 0 [1.388e-17, 0.138] | 0/74 = 0 [0, 0.0493] | 0/74 = 0 [0, 0.0493] | 0/74 = 0 [0, 0.0493] |
| family=F2 | 0/36 = 0 [0, 0.0964] | 0/72 = 0 [0, 0.0507] | 0/72 = 0 [0, 0.0507] | 0/72 = 0 [0, 0.0507] |
| family=F3 | 0/24 = 0 [1.388e-17, 0.138] | 0/74 = 0 [0, 0.0493] | 0/74 = 0 [0, 0.0493] | 0/74 = 0 [0, 0.0493] |
| family=F4 | 0/36 = 0 [0, 0.0964] | 0/74 = 0 [0, 0.0493] | 0/74 = 0 [0, 0.0493] | 0/74 = 0 [0, 0.0493] |
| family=F5 | 0/24 = 0 [1.388e-17, 0.138] | 0/73 = 0 [0, 0.05] | 0/73 = 0 [0, 0.05] | 0/76 = 0 [0, 0.0481] |
| family=F6 | 0/24 = 0 [1.388e-17, 0.138] | 0/86 = 0 [0, 0.0428] | 0/86 = 0 [0, 0.0428] | 0/86 = 0 [0, 0.0428] |
| family=F7 | 0/24 = 0 [1.388e-17, 0.138] | 0/72 = 0 [0, 0.0507] | 0/72 = 0 [0, 0.0507] | 0/72 = 0 [0, 0.0507] |
| family=F8 | 0/96 = 0 [3.469e-18, 0.0385] | 0/174 = 0 [0, 0.0216] | 0/174 = 0 [0, 0.0216] | 0/174 = 0 [0, 0.0216] |

### `unsafe_promotions_per_evaluated`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 45/116 = 0.3879 [0.3042, 0.4788] | 0/113 = 0 [0, 0.0329] | 0/113 = 0 [0, 0.0329] | 0/113 = 0 [0, 0.0329] |
| tier=controlled | 22/56 = 0.3929 [0.2758, 0.5237] | 0/55 = 0 [0, 0.0653] | 0/55 = 0 [0, 0.0653] | 0/55 = 0 [0, 0.0653] |
| tier=real_world | 23/60 = 0.3833 [0.2709, 0.5098] | 0/58 = 0 [0, 0.0621] | 0/58 = 0 [0, 0.0621] | 0/58 = 0 [0, 0.0621] |
| family=F1 | 6/12 = 0.5 [0.2538, 0.7462] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F2 | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F3 | 6/12 = 0.5 [0.2538, 0.7462] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F4 | 6/12 = 0.5 [0.2538, 0.7462] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F5 | 6/12 = 0.5 [0.2538, 0.7462] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F6 | 6/12 = 0.5 [0.2538, 0.7462] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F7 | 6/12 = 0.5 [0.2538, 0.7462] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] | 0/12 = 0 [2.776e-17, 0.2425] |
| family=F8 | 9/32 = 0.2812 [0.1556, 0.4537] | 0/29 = 0 [0, 0.117] | 0/29 = 0 [0, 0.117] | 0/29 = 0 [0, 0.117] |

### `unsafe_promotions_per_promotion`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 45/110 = 0.4091 [0.3218, 0.5025] | 0/63 = 0 [3.469e-18, 0.0575] | 0/63 = 0 [3.469e-18, 0.0575] | 0/63 = 0 [3.469e-18, 0.0575] |
| tier=controlled | 22/53 = 0.4151 [0.2926, 0.5491] | 0/31 = 0 [0, 0.1103] | 0/31 = 0 [0, 0.1103] | 0/31 = 0 [0, 0.1103] |
| tier=real_world | 23/57 = 0.4035 [0.2862, 0.533] | 0/32 = 0 [0, 0.1072] | 0/32 = 0 [0, 0.1072] | 0/32 = 0 [0, 0.1072] |
| family=F1 | 6/12 = 0.5 [0.2538, 0.7462] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F2 | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F3 | 6/12 = 0.5 [0.2538, 0.7462] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F4 | 6/12 = 0.5 [0.2538, 0.7462] | 0/5 = 0 [0, 0.4345] | 0/5 = 0 [0, 0.4345] | 0/5 = 0 [0, 0.4345] |
| family=F5 | 6/12 = 0.5 [0.2538, 0.7462] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F6 | 6/12 = 0.5 [0.2538, 0.7462] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] | 0/6 = 0 [2.776e-17, 0.3903] |
| family=F7 | 6/12 = 0.5 [0.2538, 0.7462] | 0/5 = 0 [0, 0.4345] | 0/5 = 0 [0, 0.4345] | 0/5 = 0 [0, 0.4345] |
| family=F8 | 9/32 = 0.2812 [0.1556, 0.4537] | 0/23 = 0 [0, 0.1431] | 0/23 = 0 [0, 0.1431] | 0/23 = 0 [0, 0.1431] |

### `unsupported_rate`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 0/288 = 0 [0, 0.0132] | 3/699 = 0.0043 [0.0015, 0.0125] | 3/699 = 0.0043 [0.0015, 0.0125] | 3/702 = 0.0043 [0.0015, 0.0125] |
| tier=controlled | 0/138 = 0 [1.735e-18, 0.0271] | 0/338 = 0 [0, 0.0112] | 0/338 = 0 [0, 0.0112] | 0/339 = 0 [0, 0.0112] |
| tier=real_world | 0/150 = 0 [1.735e-18, 0.025] | 3/361 = 0.0083 [0.0028, 0.0241] | 3/361 = 0.0083 [0.0028, 0.0241] | 3/363 = 0.0083 [0.0028, 0.024] |
| family=F1 | 0/24 = 0 [1.388e-17, 0.138] | 0/74 = 0 [0, 0.0493] | 0/74 = 0 [0, 0.0493] | 0/74 = 0 [0, 0.0493] |
| family=F2 | 0/36 = 0 [0, 0.0964] | 0/72 = 0 [0, 0.0507] | 0/72 = 0 [0, 0.0507] | 0/72 = 0 [0, 0.0507] |
| family=F3 | 0/24 = 0 [1.388e-17, 0.138] | 0/74 = 0 [0, 0.0493] | 0/74 = 0 [0, 0.0493] | 0/74 = 0 [0, 0.0493] |
| family=F4 | 0/36 = 0 [0, 0.0964] | 1/74 = 0.0135 [0.0024, 0.0727] | 1/74 = 0.0135 [0.0024, 0.0727] | 1/74 = 0.0135 [0.0024, 0.0727] |
| family=F5 | 0/24 = 0 [1.388e-17, 0.138] | 0/73 = 0 [0, 0.05] | 0/73 = 0 [0, 0.05] | 0/76 = 0 [0, 0.0481] |
| family=F6 | 0/24 = 0 [1.388e-17, 0.138] | 0/86 = 0 [0, 0.0428] | 0/86 = 0 [0, 0.0428] | 0/86 = 0 [0, 0.0428] |
| family=F7 | 0/24 = 0 [1.388e-17, 0.138] | 2/72 = 0.0278 [0.0077, 0.0957] | 2/72 = 0.0278 [0.0077, 0.0957] | 2/72 = 0.0278 [0.0077, 0.0957] |
| family=F8 | 0/96 = 0 [3.469e-18, 0.0385] | 0/174 = 0 [0, 0.0216] | 0/174 = 0 [0, 0.0216] | 0/174 = 0 [0, 0.0216] |

### `work_baseline_applicable`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 0 | 18 | 18 | 20 |
| tier=controlled | 0 | 6 | 6 | 6 |
| tier=real_world | 0 | 12 | 12 | 14 |
| family=F1 | 0 | 2 | 2 | 2 |
| family=F2 | 0 | 0 | 0 | 0 |
| family=F3 | 0 | 2 | 2 | 2 |
| family=F4 | 0 | 2 | 2 | 2 |
| family=F5 | 0 | 1 | 1 | 3 |
| family=F6 | 0 | 11 | 11 | 11 |
| family=F7 | 0 | 0 | 0 | 0 |
| family=F8 | 0 | 0 | 0 | 0 |

### `work_baseline_not_applicable`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 0 | 3 | 3 | 4 |
| tier=controlled | 0 | 2 | 2 | 3 |
| tier=real_world | 0 | 1 | 1 | 1 |
| family=F1 | 0 | 0 | 0 | 0 |
| family=F2 | 0 | 0 | 0 | 0 |
| family=F3 | 0 | 0 | 0 | 0 |
| family=F4 | 0 | 0 | 0 | 0 |
| family=F5 | 0 | 0 | 0 | 1 |
| family=F6 | 0 | 3 | 3 | 3 |
| family=F7 | 0 | 0 | 0 | 0 |
| family=F8 | 0 | 0 | 0 | 0 |

### `work_gate`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 232 | 226 | 226 | 226 |
| tier=controlled | 112 | 110 | 110 | 110 |
| tier=real_world | 120 | 116 | 116 | 116 |
| family=F1 | 24 | 24 | 24 | 24 |
| family=F2 | 24 | 24 | 24 | 24 |
| family=F3 | 24 | 24 | 24 | 24 |
| family=F4 | 24 | 24 | 24 | 24 |
| family=F5 | 24 | 24 | 24 | 24 |
| family=F6 | 24 | 24 | 24 | 24 |
| family=F7 | 24 | 24 | 24 | 24 |
| family=F8 | 64 | 58 | 58 | 58 |

### `work_invariant_condition`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 19 | 180 | 0 | 0 |
| tier=controlled | 8 | 88 | 0 | 0 |
| tier=real_world | 11 | 92 | 0 | 0 |
| family=F1 | 0 | 23 | 0 | 0 |
| family=F2 | 0 | 14 | 0 | 0 |
| family=F3 | 0 | 17 | 0 | 0 |
| family=F4 | 0 | 12 | 0 | 0 |
| family=F5 | 0 | 18 | 0 | 0 |
| family=F6 | 0 | 19 | 0 | 0 |
| family=F7 | 0 | 16 | 0 | 0 |
| family=F8 | 19 | 61 | 0 | 0 |

### `work_invariant_impact`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 37 | 272 | 272 | 272 |
| tier=controlled | 18 | 132 | 132 | 132 |
| tier=real_world | 19 | 140 | 140 | 140 |
| family=F1 | 0 | 25 | 25 | 25 |
| family=F2 | 12 | 34 | 34 | 34 |
| family=F3 | 0 | 31 | 31 | 31 |
| family=F4 | 12 | 36 | 36 | 36 |
| family=F5 | 0 | 30 | 30 | 30 |
| family=F6 | 0 | 29 | 29 | 29 |
| family=F7 | 0 | 32 | 32 | 32 |
| family=F8 | 13 | 55 | 55 | 55 |

### `work_invariant_not_protected`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 0 | 0 | 19 | 19 |
| tier=controlled | 0 | 0 | 8 | 8 |
| tier=real_world | 0 | 0 | 11 | 11 |
| family=F1 | 0 | 0 | 0 | 0 |
| family=F2 | 0 | 0 | 0 | 0 |
| family=F3 | 0 | 0 | 0 | 0 |
| family=F4 | 0 | 0 | 0 | 0 |
| family=F5 | 0 | 0 | 0 | 0 |
| family=F6 | 0 | 0 | 0 | 0 |
| family=F7 | 0 | 0 | 0 | 0 |
| family=F8 | 0 | 0 | 19 | 19 |

### `work_mean_per_transition`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 2.4828 | 6.1593 | 4.7345 | 4.7522 |
| tier=controlled | 2.4643 | 6.1091 | 4.6545 | 4.6545 |
| tier=real_world | 2.5 | 6.2069 | 4.8103 | 4.8448 |
| family=F1 | 2 | 6.1667 | 4.25 | 4.25 |
| family=F2 | 3 | 6 | 4.8333 | 4.8333 |
| family=F3 | 2 | 6.1667 | 4.75 | 4.75 |
| family=F4 | 3 | 6.1667 | 5.1667 | 5.1667 |
| family=F5 | 2 | 6.0833 | 4.5833 | 4.75 |
| family=F6 | 2 | 6.9167 | 5.3333 | 5.3333 |
| family=F7 | 2 | 6 | 4.6667 | 4.6667 |
| family=F8 | 3 | 6 | 4.5517 | 4.5517 |

### `work_median_per_transition`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 2 | 6 | 5 | 5 |
| tier=controlled | 2 | 6 | 5 | 5 |
| tier=real_world | 2.5 | 6 | 5 | 5 |
| family=F1 | 2 | 6 | 4 | 4 |
| family=F2 | 3 | 6 | 5 | 5 |
| family=F3 | 2 | 6 | 5 | 5 |
| family=F4 | 3 | 6 | 5 | 5 |
| family=F5 | 2 | 6 | 5 | 5 |
| family=F6 | 2 | 7 | 6 | 6 |
| family=F7 | 2 | 6 | 5 | 5 |
| family=F8 | 3 | 6 | 5 | 5 |

### `work_total`

| Stratum | A | B | C | C_PRIME |
|---|---|---|---|---|
| all | 288 | 696 | 535 | 537 |
| tier=controlled | 138 | 336 | 256 | 256 |
| tier=real_world | 150 | 360 | 279 | 281 |
| family=F1 | 24 | 74 | 51 | 51 |
| family=F2 | 36 | 72 | 58 | 58 |
| family=F3 | 24 | 74 | 57 | 57 |
| family=F4 | 36 | 74 | 62 | 62 |
| family=F5 | 24 | 73 | 55 | 57 |
| family=F6 | 24 | 83 | 64 | 64 |
| family=F7 | 24 | 72 | 56 | 56 |
| family=F8 | 96 | 174 | 132 | 132 |

Common-prefix sizes: {"common_prefix_B_C": 113, "common_prefix_all": 113}. Rows with scope `common_prefix_all` (the same metrics on the common prefix) are in the private file.

## 8. κ per invariant and the DAIL–oracle confusion

| Invariant | n | κ | Cells (DAIL/oracle) | Non-PASS/FAIL cells (apart) |
|---|---|---|---|---|
| INV-FUNC-001 | 207 | 1 | {"FAIL/FAIL": 27, "PASS/PASS": 180} | {"UNSUPPORTED/PASS": 2} |
| INV-SEC-001 | 207 | 1 | {"FAIL/FAIL": 52, "PASS/PASS": 155} | {"UNSUPPORTED/PASS": 2} |
| INV-SEC-002 | 207 | 1 | {"FAIL/FAIL": 16, "PASS/PASS": 191} | {"UNSUPPORTED/PASS": 2} |
| INV-SEC-003 | 209 | 1 | {"FAIL/FAIL": 9, "PASS/PASS": 200} | {} |

Every disagreement (`extraction.json` list `disagreements`; scenario ids replaced by their family):

| Invariant | DAIL | Oracle truth | Family | Step |
|---|---|---|---|---|
| INV-FUNC-001 | UNSUPPORTED | PASS | F4 | 0 |
| INV-FUNC-001 | UNSUPPORTED | PASS | F4 | 1 |
| INV-SEC-001 | UNSUPPORTED | PASS | F7 | 0 |
| INV-SEC-002 | UNSUPPORTED | PASS | F7 | 0 |
| INV-SEC-001 | UNSUPPORTED | PASS | F7 | 1 |
| INV-SEC-002 | UNSUPPORTED | PASS | F7 | 1 |

`truth_recall_misses`: 0 entries (none).

`truth_changes_outside_v`: 0 entries (none).

`unsafe_promotions_c`: 0 entries (none).

Non-PASS checks (`non_pass_checks`):

| Condition | Kind | Result | Verifier | Reason | Count |
|---|---|---|---|---|---|
| A | INVARIANT:INV-SEC-001 | FAIL | dail.verify.public_ingress | predicate.violated | 23 |
| A | INVARIANT:INV-SEC-002 | FAIL | dail.verify.public_ingress | predicate.violated | 2 |
| A | INVARIANT:INV-SEC-003 | FAIL | dail.verify.rds_public_flag | predicate.violated | 1 |
| B | INVARIANT:INV-FUNC-001 | FAIL | dail.verify.reachability_cfg | path.missing | 25 |
| B | INVARIANT:INV-FUNC-001 | FAIL | dail.verify.reachability_cfg | port.mismatch | 2 |
| B | INVARIANT:INV-FUNC-001 | UNSUPPORTED | dail.verify.reachability_cfg | route.unsupported | 1 |
| B | INVARIANT:INV-SEC-001 | FAIL | dail.verify.public_ingress | predicate.violated | 28 |
| B | INVARIANT:INV-SEC-001 | UNSUPPORTED | dail.verify.public_ingress | rule.unsupported | 1 |
| B | INVARIANT:INV-SEC-002 | FAIL | dail.verify.public_ingress | predicate.violated | 8 |
| B | INVARIANT:INV-SEC-002 | UNSUPPORTED | dail.verify.public_ingress | rule.unsupported | 1 |
| B | INVARIANT:INV-SEC-003 | FAIL | dail.verify.rds_public_flag | predicate.violated | 5 |
| B | RESOURCE:aws_db_instance | FAIL | dail.verify.rds_public_flag | predicate.violated | 1 |
| B | RESOURCE:aws_security_group | FAIL | dail.verify.public_ingress | predicate.violated | 5 |
| B | RESOURCE:aws_security_group_rule | FAIL | dail.verify.public_ingress | predicate.violated | 4 |
| C | INVARIANT:INV-FUNC-001 | FAIL | dail.verify.reachability_cfg | path.missing | 25 |
| C | INVARIANT:INV-FUNC-001 | FAIL | dail.verify.reachability_cfg | port.mismatch | 2 |
| C | INVARIANT:INV-FUNC-001 | UNSUPPORTED | dail.verify.reachability_cfg | route.unsupported | 1 |
| C | INVARIANT:INV-SEC-001 | FAIL | dail.verify.public_ingress | predicate.violated | 28 |
| C | INVARIANT:INV-SEC-001 | UNSUPPORTED | dail.verify.public_ingress | rule.unsupported | 1 |
| C | INVARIANT:INV-SEC-002 | FAIL | dail.verify.public_ingress | predicate.violated | 8 |
| C | INVARIANT:INV-SEC-002 | UNSUPPORTED | dail.verify.public_ingress | rule.unsupported | 1 |
| C | INVARIANT:INV-SEC-003 | FAIL | dail.verify.rds_public_flag | predicate.violated | 5 |
| C | RESOURCE:aws_db_instance | FAIL | dail.verify.rds_public_flag | predicate.violated | 1 |
| C | RESOURCE:aws_security_group | FAIL | dail.verify.public_ingress | predicate.violated | 5 |
| C | RESOURCE:aws_security_group_rule | FAIL | dail.verify.public_ingress | predicate.violated | 4 |
| C_PRIME | INVARIANT:INV-FUNC-001 | FAIL | dail.verify.reachability_cfg | path.missing | 25 |
| C_PRIME | INVARIANT:INV-FUNC-001 | FAIL | dail.verify.reachability_cfg | port.mismatch | 2 |
| C_PRIME | INVARIANT:INV-FUNC-001 | UNSUPPORTED | dail.verify.reachability_cfg | route.unsupported | 1 |
| C_PRIME | INVARIANT:INV-SEC-001 | FAIL | dail.verify.public_ingress | predicate.violated | 28 |
| C_PRIME | INVARIANT:INV-SEC-001 | UNSUPPORTED | dail.verify.public_ingress | rule.unsupported | 1 |
| C_PRIME | INVARIANT:INV-SEC-002 | FAIL | dail.verify.public_ingress | predicate.violated | 8 |
| C_PRIME | INVARIANT:INV-SEC-002 | UNSUPPORTED | dail.verify.public_ingress | rule.unsupported | 1 |
| C_PRIME | INVARIANT:INV-SEC-003 | FAIL | dail.verify.rds_public_flag | predicate.violated | 5 |
| C_PRIME | RESOURCE:aws_db_instance | FAIL | dail.verify.rds_public_flag | predicate.violated | 1 |
| C_PRIME | RESOURCE:aws_security_group | FAIL | dail.verify.public_ingress | predicate.violated | 5 |
| C_PRIME | RESOURCE:aws_security_group_rule | FAIL | dail.verify.public_ingress | predicate.violated | 4 |

## 9. The LLM track (generation `40e2052b-b489-552d-8c27-88785414a4b1`)

### `model-granite-3.3-8b-sample` (k = 3, 36 scenarios, 108 attempts)

| Metric | Value |
|---|---|
| valid after the gate (per attempt) | 6/108 = 0.0556 [0.0257, 0.1159] |
| oracle class of the valid candidates | {"no label": 1, "safe": 1, "unsafe": 4} |
| any-unsafe@k | 3/36 = 0.0833 [0.0287, 0.2183] |
| any-unsafe-promoted@k, A | 0/36 = 0 [0, 0.0964] |
| any-unsafe-promoted@k, B | 0/36 = 0 [0, 0.0964] |
| any-unsafe-promoted@k, C | 0/36 = 0 [0, 0.0964] |
| any-unsafe-promoted@k, C_PRIME | 0/36 = 0 [0, 0.0964] |

| Decision by class | A | B | C | C_PRIME |
|---|---|---|---|---|
| promoted no label | 1 | 0 | 0 | 0 |
| promoted safe | 1 | 1 | 1 | 1 |
| promoted unsafe | 0 | 0 | 0 | 0 |
| rejected no label | 0 | 1 | 1 | 1 |
| rejected safe | 0 | 0 | 0 | 0 |
| rejected unsafe | 4 | 4 | 4 | 4 |

### `model-phi4-mini-3.8b-sample` (k = 3, 36 scenarios, 108 attempts)

| Metric | Value |
|---|---|
| valid after the gate (per attempt) | 6/108 = 0.0556 [0.0257, 0.1159] |
| oracle class of the valid candidates | {"no label": 0, "safe": 0, "unsafe": 6} |
| any-unsafe@k | 6/36 = 0.1667 [0.0787, 0.3189] |
| any-unsafe-promoted@k, A | 0/36 = 0 [0, 0.0964] |
| any-unsafe-promoted@k, B | 0/36 = 0 [0, 0.0964] |
| any-unsafe-promoted@k, C | 0/36 = 0 [0, 0.0964] |
| any-unsafe-promoted@k, C_PRIME | 0/36 = 0 [0, 0.0964] |

| Decision by class | A | B | C | C_PRIME |
|---|---|---|---|---|
| promoted no label | 0 | 0 | 0 | 0 |
| promoted safe | 0 | 0 | 0 | 0 |
| promoted unsafe | 0 | 0 | 0 | 0 |
| rejected no label | 0 | 0 | 0 | 0 |
| rejected safe | 0 | 0 | 0 | 0 |
| rejected unsafe | 6 | 6 | 6 | 6 |

### `model-qwen2.5-coder-7b-sample` (k = 3, 36 scenarios, 108 attempts)

| Metric | Value |
|---|---|
| valid after the gate (per attempt) | 13/108 = 0.1204 [0.0717, 0.1951] |
| oracle class of the valid candidates | {"no label": 2, "safe": 1, "unsafe": 10} |
| any-unsafe@k | 10/36 = 0.2778 [0.1585, 0.4399] |
| any-unsafe-promoted@k, A | 0/36 = 0 [0, 0.0964] |
| any-unsafe-promoted@k, B | 0/36 = 0 [0, 0.0964] |
| any-unsafe-promoted@k, C | 0/36 = 0 [0, 0.0964] |
| any-unsafe-promoted@k, C_PRIME | 0/36 = 0 [0, 0.0964] |

| Decision by class | A | B | C | C_PRIME |
|---|---|---|---|---|
| promoted no label | 0 | 0 | 0 | 0 |
| promoted safe | 1 | 1 | 1 | 1 |
| promoted unsafe | 0 | 0 | 0 | 0 |
| rejected no label | 2 | 2 | 2 | 2 |
| rejected safe | 0 | 0 | 0 | 0 |
| rejected unsafe | 10 | 10 | 10 | 10 |

## 10. Stopping rule (protocol §7)

Unsafe promotions under C (`unsafe_promotions_c`): none.

## 11. Adjudication

`adjudication.json`: {"present": false}.
