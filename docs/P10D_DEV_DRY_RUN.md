# P10d dev dry run (DEV DRY RUN, NOT RESULTS)

> **DEV DRY RUN, NOT RESULTS.** The whole analysis of the frozen protocol, run on dev data (reference track: experiment `c4c20b99-0324-58e0-937e-dba26ad5cf0b`, `p8b-dev-run-3`; LLM track: the P10c scoring inputs) as if it were the test split, to check the code and the protocol before the freeze. Nothing here is a finding, and no hypothesis is tested on dev (C-214). Versions: `metrics-final-1`, `extractor-5`, `analysis-1`; seed 20261121, 4000 coverage and 2000 power replications per cell. Generated from `P10D_DEV_DRY_RUN.json` by `experiments.stats.render`.

## 1. ρ, the ICC of the paired MR outcome (P10d-2) — DEV DRY RUN, NOT RESULTS

| stratum | B | C | C − B | A − C |
|---|---|---|---|---|
| repair | undefined | undefined | undefined | undefined |
| change_request | undefined | undefined | undefined | undefined |
| all | undefined | undefined | undefined | undefined |

ρ put into DEFF by the analysis (C-241 (5)): **0.30**.

## 2. Coverage of the one-sided 95% upper limit (P10d-1) — DEV DRY RUN, NOT RESULTS

Minimum simulated coverage over the grid of true values, per configuration and ρ:

| configuration | sizes | ρ = 0.0 | ρ = 0.05 | ρ = 0.1 | ρ = 0.2 | ρ = 0.3 |
|---|---|---|---|---|---|---|
| repair/dev | 28 in 24 (20×1, 4×2) | 0.943 | 0.947 | 0.943 | 0.944 | 0.942 |
| change_request/dev | 70 in 55 (42×1, 11×2, 2×3) | 0.948 | 0.938 | 0.947 | 0.937 | 0.937 |
| all/dev | 98 in 71 (50×1, 15×2, 6×3) | 0.952 | 0.953 | 0.944 | 0.939 | 0.937 |
| repair/test-even | 12 in 12 (12×1) | 0.926 | 0.919 | 0.924 | 0.923 | 0.925 |
| repair/test-uneven | 12 in 6 (6×2) | 0.958 | 0.957 | 0.952 | 0.941 | 0.939 |
| change_request/test-even | 30 in 25 (20×1, 5×2) | 0.930 | 0.935 | 0.932 | 0.926 | 0.923 |
| change_request/test-uneven | 30 in 11 (1×1, 7×2, 3×5) | 0.976 | 0.971 | 0.963 | 0.944 | 0.936 |
| all/test-even | 42 in 31 (21×1, 9×2, 1×3) | 0.949 | 0.945 | 0.944 | 0.945 | 0.930 |
| all/test-uneven | 42 in 17 (7×1, 7×2, 3×7) | 0.983 | 0.978 | 0.969 | 0.958 | 0.939 |

| stratum | minimum | at | outcome (C-235) |
|---|---|---|---|
| all (dev and test bounds) | 0.930 | all/test-even, ρ = 0.3, π = [0.2, 0.1, 0.0, 0.7] | **inferential** |
| change_request (dev and test bounds) | 0.923 | change_request/test-even, ρ = 0.3, π = [0.2, 0.3, 0.0, 0.5] | **descriptive** |
| repair (dev and test bounds) | 0.919 | repair/test-even, ρ = 0.05, π = [0.2, 0.3, 0.0, 0.5] | **descriptive** |
| all (dev only) | 0.937 | all/dev, ρ = 0.3, π = [0.2, 0.1, 0.0, 0.7] | **inferential** |
| change_request (dev only) | 0.937 | change_request/dev, ρ = 0.2, π = [0.2, 0.1, 0.0, 0.7] | **inferential** |
| repair (dev only) | 0.942 | repair/dev, ρ = 0.3, π = [0.2, 0.1, 0.0, 0.7] | **inferential** |
| all (test bounds only) | 0.930 | all/test-even, ρ = 0.3, π = [0.2, 0.1, 0.0, 0.7] | **inferential** |
| change_request (test bounds only) | 0.923 | change_request/test-even, ρ = 0.3, π = [0.2, 0.3, 0.0, 0.5] | **descriptive** |
| repair (test bounds only) | 0.919 | repair/test-even, ρ = 0.05, π = [0.2, 0.3, 0.0, 0.5] | **descriptive** |

## 3. Power (H1: two-sided cluster sign test, Holm; H2: one-sided sign test) — DEV DRY RUN, NOT RESULTS

C's dev MR per stratum, used as MR_C: {'repair': 0.0, 'change_request': 0.0}.

| test sizes | ρ | power at effect 0.10 (repair, change_request) | smallest effect with power ≥ 0.80 (repair, change_request) |
|---|---|---|---|
| test-even | 0.0 | 0.000, 0.019 | 0.6, 0.3 |
| test-even | 0.05 | 0.000, 0.019 | 0.6, 0.4 |
| test-even | 0.1 | 0.000, 0.018 | 0.6, 0.4 |
| test-even | 0.2 | 0.000, 0.016 | 0.6, 0.4 |
| test-even | 0.3 | 0.001, 0.023 | 0.6, 0.4 |
| test-uneven | 0.0 | 0.000, 0.004 | 0.9, 0.5 |
| test-uneven | 0.05 | 0.000, 0.002 | 0.9, 0.5 |
| test-uneven | 0.1 | 0.000, 0.001 | 0.9, 0.5 |
| test-uneven | 0.2 | 0.000, 0.004 | 0.9, 0.5 |
| test-uneven | 0.3 | 0.000, 0.001 | 1.0, 0.5 |

| H2 test sizes | power |
|---|---|
| test-even | 1.000 |
| test-uneven | 1.000 |

## 4. H1: A vs C (DEV DRY RUN, NOT RESULTS)

| stratum | MR scenarios | clusters (by tier) | descriptive tiers | n+ / n− / n0 | p (two-sided) | Holm | MR_A − MR_C [95% CI, DEFF] |
|---|---|---|---|---|---|---|---|
| repair | 28 | 24 {'controlled': 10, 'real_world': 14} | none | 24 / 0 / 0 | 0.0000 | 0.0000 | 1.0000 [0.8167, 1.0000], DEFF 1.086 |
| change_request | 70 | 55 {'controlled': 21, 'real_world': 34} | none | 55 / 0 / 0 | 0.0000 | 0.0000 | 1.0000 [0.9163, 1.0000], DEFF 1.146 |

## 5. H2: B vs C (DEV DRY RUN, NOT RESULTS)

| workload | value |
|---|---|
| all steps | 132 clusters {'controlled': 23, 'real_world': 109}; favour C 126, favour B 0, zero 6; median cluster W_C − W_B -1.0000; one-sided p 0.0000; P(favours C | non-zero) 1.0000 |
| common prefix | 132 clusters {'controlled': 23, 'real_world': 109}; favour C 126, favour B 0, zero 6; median cluster W_C − W_B -1.0000; one-sided p 0.0000; P(favours C | non-zero) 1.0000 |

Non-inferiority (exploratory (C-231)): cells {'both': 0, 'first_only': 0, 'second_only': 0, 'neither': 98}, MR_C − MR_B 0.0000, one-sided 95% upper limit 0.0321 (DEFF 1.202) against δ_NI = 0.05.

## 6. H3: C vs C′ on F5 (DEV DRY RUN, NOT RESULTS)

| condition | identity error (UNCERTAIN excluded) | transition error | UNCERTAIN share | evidence-transfer error rate | excluded pairs (all families) |
|---|---|---|---|---|---|
| C | 3 / 33 = 0.0909 [0.0314, 0.2357] | 3 / 33 = 0.0909 [0.0314, 0.2357] | 0 / 33 = 0.0000 [0.0000, 0.1043] | 3 / 13 = 0.2308 [0.0818, 0.5026] | 38 |
| C_PRIME | 25 / 33 = 0.7576 [0.5898, 0.8717] | 25 / 33 = 0.7576 [0.5898, 0.8717] | 0 / 33 = 0.0000 [0.0000, 0.1043] | 13 / 13 = 1.0000 [0.7719, 1.0000] | 38 |

Work on F5 by moved resource type (C′ − C):

| type | transitions | W C | W C′ | difference |
|---|---|---|---|---|
| aws_instance | 2 | 6 | 6 | 0 |
| aws_security_group_rule | 6 | 34 | 40 | 6 |
| aws_subnet | 4 | 12 | 12 | 0 |

## 7. H4 (DEV DRY RUN, NOT RESULTS)

Blocked unsafe F4 scenarios under C: 14 / 14 = 1.0000 [0.7847, 1.0000].

## 8. Other metrics (DEV DRY RUN, NOT RESULTS)

| metric | A | B | C | C_PRIME |
|---|---|---|---|---|
| unsafe_promotions_per_promotion | 105 / 266 = 0.3947 [0.3379, 0.4546] | 0 / 159 = 0.0000 [0.0000, 0.0236] | 0 / 159 = 0.0000 [0.0000, 0.0236] | 0 / 157 = 0.0000 [0.0000, 0.0239] |
| unsafe_promotions_per_evaluated | 105 / 280 = 0.3750 [0.3203, 0.4330] | 0 / 273 = 0.0000 [0.0000, 0.0139] | 0 / 273 = 0.0000 [0.0000, 0.0139] | 0 / 273 = 0.0000 [0.0000, 0.0139] |
| false_rejection_rate | 0 / 161 = 0.0000 [0.0000, 0.0233] | 2 / 161 = 0.0124 [0.0034, 0.0442] | 2 / 161 = 0.0124 [0.0034, 0.0442] | 4 / 161 = 0.0248 [0.0097, 0.0621] |
| missed_regressions_per_regression | 98 / 98 = 1.0000 [0.9623, 1.0000] | 0 / 98 = 0.0000 [0.0000, 0.0377] | 0 / 98 = 0.0000 [0.0000, 0.0377] | 0 / 98 = 0.0000 [0.0000, 0.0377] |
| missed_regression_rate | 98 / 98 = 1.0000 [0.9623, 1.0000] | 0 / 98 = 0.0000 [0.0000, 0.0377] | 0 / 98 = 0.0000 [0.0000, 0.0377] | 0 / 98 = 0.0000 [0.0000, 0.0377] |
| mr_no_regression_step | 14 | 14 | 14 | 14 |
| repair_success_repair | 42 / 84 = 0.5000 [0.3954, 0.6046] | 42 / 84 = 0.5000 [0.3954, 0.6046] | 42 / 84 = 0.5000 [0.3954, 0.6046] | 42 / 84 = 0.5000 [0.3954, 0.6046] |
| repair_success_change_request | 70 / 140 = 0.5000 [0.4183, 0.5817] | 68 / 140 = 0.4857 [0.4044, 0.5678] | 68 / 140 = 0.4857 [0.4044, 0.5678] | 66 / 140 = 0.4714 [0.3906, 0.5538] |
| truncated_transitions | 0 / 280 = 0.0000 [0.0000, 0.0135] | 7 / 280 = 0.0250 [0.0122, 0.0507] | 7 / 280 = 0.0250 [0.0122, 0.0507] | 7 / 280 = 0.0250 [0.0122, 0.0507] |
| impact_precision_micro | - | - | 462 / 627 = 0.7368 [0.7010, 0.7698] | 462 / 627 = 0.7368 [0.7010, 0.7698] |
| impact_recall_micro | - | - | 462 / 462 = 1.0000 [0.9918, 1.0000] | 462 / 462 = 1.0000 [0.9918, 1.0000] |
| impact_precision_macro | - | - | 0.7254 | 0.7254 |
| impact_recall_macro | - | - | 1.0000 | 1.0000 |
| truth_recall_impact | - | - | 161 / 161 = 1.0000 [0.9767, 1.0000] | 161 / 161 = 1.0000 [0.9767, 1.0000] |
| truth_recall_v | - | - | 161 / 161 = 1.0000 [0.9767, 1.0000] | 161 / 161 = 1.0000 [0.9767, 1.0000] |

W per scenario (W_{X,s}, executed steps):

| condition | scenarios | mean | median | mean by kind |
|---|---|---|---|---|
| A | 224 | 3.12 | 2.0 | baseline_applicable 0.00, baseline_not_applicable 0.00, gate 2.50, invariant_condition 0.23, invariant_impact 0.39, invariant_not_protected 0.00 |
| B | 224 | 7.56 | 6.0 | baseline_applicable 0.25, baseline_not_applicable 0.04, gate 2.44, invariant_condition 2.08, invariant_impact 2.80, invariant_not_protected 0.00 |
| C | 224 | 5.73 | 5.0 | baseline_applicable 0.25, baseline_not_applicable 0.04, gate 2.44, invariant_condition 0.00, invariant_impact 2.80, invariant_not_protected 0.24 |
| C_PRIME | 224 | 5.75 | 5.0 | baseline_applicable 0.28, baseline_not_applicable 0.07, gate 2.44, invariant_condition 0.00, invariant_impact 2.80, invariant_not_protected 0.24 |

## 9. DAIL–oracle κ under B (P10d-3) — DEV DRY RUN, NOT RESULTS

| invariant | PASS/FAIL cells | other results (apart) | n | κ |
|---|---|---|---|---|
| INV-FUNC-001 | {'FAIL/FAIL': 61, 'PASS/PASS': 434} | {'UNSUPPORTED/PASS': 2} | 495 | 1.0000 |
| INV-SEC-001 | {'FAIL/FAIL': 119, 'PASS/PASS': 376} | {'UNSUPPORTED/PASS': 2} | 495 | 1.0000 |
| INV-SEC-002 | {'FAIL/FAIL': 37, 'PASS/PASS': 458} | {'UNSUPPORTED/PASS': 2} | 495 | 1.0000 |
| INV-SEC-003 | {'FAIL/FAIL': 35, 'PASS/PASS': 462} | - | 497 | 1.0000 |

## 10. LLM track (descriptive, C-228) — DEV DRY RUN, NOT RESULTS

| generation | model | k | attempts | valid after gate | safe / unsafe / no label | any-unsafe@k | any-unsafe promoted@k (A, B, C, C′) |
|---|---|---|---|---|---|---|---|
| `77da54da` | granite3_3-8b-k3 | 3 | 36 | 2 / 36 = 0.0556 [0.0154, 0.1814] | 0 / 2 / 0 | 2 / 12 = 0.1667 [0.0470, 0.4480] | 0, 0, 0, 0 of 12 |
| `77da54da` | phi4-mini-3_8b-k3 | 3 | 36 | 0 / 36 = 0.0000 [0.0000, 0.0964] | 0 / 0 / 0 | 0 / 12 = 0.0000 [0.0000, 0.2425] | 0, 0, 0, 0 of 12 |
| `77da54da` | qwen2_5-coder-7b-k3 | 3 | 36 | 2 / 36 = 0.0556 [0.0154, 0.1814] | 0 / 2 / 0 | 2 / 12 = 0.1667 [0.0470, 0.4480] | 0, 0, 0, 0 of 12 |
| `7fe30836` | granite3_3-8b | 1 | 12 | 1 / 12 = 0.0833 [0.0149, 0.3539] | 0 / 0 / 1 | 0 / 12 = 0.0000 [0.0000, 0.2425] | 0, 0, 0, 0 of 12 |
| `7fe30836` | phi4-mini-3_8b | 1 | 12 | 0 / 12 = 0.0000 [0.0000, 0.2425] | 0 / 0 / 0 | 0 / 12 = 0.0000 [0.0000, 0.2425] | 0, 0, 0, 0 of 12 |
| `7fe30836` | qwen2_5-coder-7b | 1 | 12 | 0 / 12 = 0.0000 [0.0000, 0.2425] | 0 / 0 / 0 | 0 / 12 = 0.0000 [0.0000, 0.2425] | 0, 0, 0, 0 of 12 |
| `d4507101` | granite3_3-8b | 1 | 12 | 2 / 12 = 0.1667 [0.0470, 0.4480] | 0 / 0 / 2 | 0 / 12 = 0.0000 [0.0000, 0.2425] | 0, 0, 0, 0 of 12 |
| `d4507101` | phi4-mini-3_8b | 1 | 12 | 1 / 12 = 0.0833 [0.0149, 0.3539] | 0 / 1 / 0 | 1 / 12 = 0.0833 [0.0149, 0.3539] | 0, 0, 0, 0 of 12 |
| `d4507101` | qwen2_5-coder-7b | 1 | 12 | 0 / 12 = 0.0000 [0.0000, 0.2425] | 0 / 0 / 0 | 0 / 12 = 0.0000 [0.0000, 0.2425] | 0, 0, 0, 0 of 12 |
