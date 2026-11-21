"""The whole analysis of the frozen protocol, run on dev records as if they were the test split
(P10d Step 4). Every output is marked ``DEV DRY RUN, NOT RESULTS``; nothing here is a finding.

Inputs: the ``metrics-final-1`` extraction of a reference-track experiment (its
``scenario_outcomes`` and metric records) and the LLM candidate rows
(``experiments.scoring.llm_pilot.candidate_rows``).

* **ρ** (P10d-2, C-236): ``analysis.icc_estimates``. The ρ the analysis puts into DEFF
  (``analysis_rho``, C-241 (5)) is the dev estimate of the paired C - B outcome over both strata
  if it is defined and not negative, else the top of the P10d-1 range, 0.30.
* **Coverage** (P10d-1, C-235): ``simulate.coverage_table`` for ρ in ``RHOS`` on the dev MR cluster
  sizes of each stratum (``repair``, ``change_request``, and ``all`` for the non-inferiority
  limit) and on the public bounds of the test sizes (``test_size_bounds``, C-238), over
  ``pi_grid``; ``analysis.coverage_decision`` with threshold 0.93 gives each stratum's outcome.
  At unblinding the same code runs on the actual test sizes before any outcome is read (C-238).
* **Power**: H1 per stratum on the test bounds, MR_C = the larger of C's dev MRs of the two
  strata, effect 0.10 (and the
  effects 0.1 to 1.0, to show the smallest with power 0.80), Holm, every ρ in ``RHOS``; H2 with
  the dev cluster means of W_C - W_B drawn per tier, 10 controlled and 48 real-world test clusters
  (41 with the pairs bound).
* **The analysis**: H1, H2 (workload, also on the common prefix; non-inferiority, exploratory), H3
  (C vs C' on F5), H4, and the other metrics of Section 3; the LLM track (descriptive).
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any, Final

from experiments.metrics.llm_final import llm_metrics
from experiments.stats import analysis
from experiments.stats.simulate import Pi, coverage_table, h1_power, h2_power

MARKER: Final = "DEV DRY RUN, NOT RESULTS"
ANALYSIS_VERSION: Final = "analysis-2"
RHOS: Final = (0.0, 0.05, 0.10, 0.20, 0.30)
THRESHOLD: Final = 0.93
SEED: Final = 20261121
COVERAGE_REPS: Final = 4000
POWER_REPS: Final = 2000
EFFECTS: Final = tuple(round(0.1 * i, 1) for i in range(1, 11))
TEST_CLUSTERS_H2: Final = {"test-even": (10, 48), "test-uneven": (10, 41)}


def test_size_bounds() -> dict[str, list[int]]:
    """The public bounds of the test MR cluster sizes (C-238; see the module's tests for the
    sources): controlled most even and most uneven, real-world singletons or pairs."""
    return {
        "repair/test-even": [1] * 6 + [1] * 6,
        "repair/test-uneven": [2] * 3 + [2] * 3,
        "change_request/test-even": [2] * 5 + [1] * 5 + [1] * 15,
        "change_request/test-uneven": [5] * 3 + [2] * 7 + [1],
        "all/test-even": [3] + [2] * 9 + [1] * 21,
        "all/test-uneven": [7] * 3 + [2] * 7 + [1] * 7,
    }


def pi_grid() -> list[Pi]:
    """True paired-cell probabilities (both, first only, second only, neither): the second
    condition's MR in {0, 0.05, 0.10, 0.20}, the difference in {0, 0.10, 0.30}, the two outcomes
    independent or nested (the first misses whatever the second misses); C-241 (4)."""
    found: list[Pi] = []
    for second in (0.0, 0.05, 0.10, 0.20):
        for diff in (0.0, 0.10, 0.30):
            first = second + diff
            for nested in (False, True):
                both = second if nested else first * second
                pi = (both, first - both, second - both, 1 - first - second + both)
                pi = tuple(round(p, 12) for p in pi)  # type: ignore[assignment]
                if pi not in found:
                    found.append(pi)
    return found


def analysis_rho(estimate: float | None) -> float:
    if estimate is None or estimate < 0:
        return RHOS[-1]
    return estimate


def _record(metrics: Sequence[Mapping[str, Any]], name: str, condition: str, **where: str) -> Any:
    scope, stratum = where.get("scope", "all"), where.get("stratum", "all")
    for r in metrics:
        if (r["metric_name"], r["condition_id"], r["scope"], r["stratum"]) == (
            name,
            condition,
            scope,
            stratum,
        ):
            return {k: r[k] for k in ("numerator", "denominator", "value", "wilson95") if k in r}
    return None


def _per_scenario_work(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    by: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for r in rows:
        by[r["condition"]].append(r)
    found = {}
    for condition, mine in sorted(by.items()):
        kinds = sorted({k for r in mine for k in r["work"]})
        found[condition] = {
            "scenarios": len(mine),
            "mean_w": statistics.fmean(r["work_w"] for r in mine),
            "median_w": statistics.median(r["work_w"] for r in mine),
            "mean_by_kind": {k: statistics.fmean(r["work"].get(k, 0) for r in mine) for k in kinds},
        }
    return found


def dry_run(
    extraction: Mapping[str, Any],
    llm_rows: Sequence[Mapping[str, Any]],
    *,
    coverage_reps: int = COVERAGE_REPS,
    power_reps: int = POWER_REPS,
    seed: int = SEED,
) -> dict[str, Any]:
    rows = extraction["lists"]["scenario_outcomes"]
    metrics = extraction["metrics"]
    icc = analysis.icc_estimates(rows)
    rho = analysis_rho(icc["all"]["C_minus_B"])
    configs: dict[str, list[int]] = {}
    for stratum in ("repair", "change_request", None):
        configs[f"{stratum or 'all'}/dev"] = analysis.mr_cluster_sizes(rows, "C", stratum)
    configs.update(test_size_bounds())
    table = coverage_table(configs, RHOS, rho, pi_grid(), reps=coverage_reps, seed=seed)
    mr_c = {
        s: (_record(metrics, "missed_regression_rate", "C", scope="scenario", stratum=f"kind={s}")
            or {}).get("value") or 0.0
        for s in analysis.STRATA
    }  # fmt: skip
    h1_rows = []
    for variant in ("test-even", "test-uneven"):
        strata = {s: test_size_bounds()[f"{s}/{variant}"] for s in analysis.STRATA}
        for r in RHOS:
            for effect in EFFECTS:
                cell_seed = seed + int(effect * 10) + int(r * 1000)
                power = h1_power(strata, max(mr_c.values()), effect, r, alpha=0.05,
                                 reps=power_reps, seed=cell_seed)  # fmt: skip
                h1_rows.append({"variant": variant, "rho": r, "effect": effect, "power": power})
    by_tier: dict[str, dict[tuple[str, str], list[float]]] = defaultdict(lambda: defaultdict(list))
    b = {x["scenario_id"]: x for x in rows if x["condition"] == "B"}
    for x in rows:
        if x["condition"] == "C" and x["scenario_id"] in b:
            by_tier[x["tier"]][(x["tier"], x["cluster"])].append(
                x["work_w"] - b[x["scenario_id"]]["work_w"]
            )
    means = {t: [statistics.fmean(v) for v in d.values()] for t, d in sorted(by_tier.items())}
    h2_power_rows = {
        variant: h2_power(
            {"controlled": (means.get("controlled", [0.0]), ctl),
             "real_world": (means.get("real_world", [0.0]), rw)},
            alpha=0.05, reps=power_reps, seed=seed,
        )
        for variant, (ctl, rw) in TEST_CLUSTERS_H2.items()
    }  # fmt: skip
    conditions = sorted({r["condition"] for r in rows})
    wanted = {
        "unsafe_promotions_per_promotion": ("unsafe_promotions_per_promotion", {}),
        "unsafe_promotions_per_evaluated": ("unsafe_promotions_per_evaluated", {}),
        "false_rejection_rate": ("false_rejection_rate", {}),
        "missed_regressions_per_regression": ("missed_regressions_per_regression", {}),
        "missed_regression_rate": ("missed_regression_rate", {"scope": "scenario"}),
        "mr_no_regression_step": ("mr_no_regression_step", {"scope": "scenario"}),
        "repair_success_repair": ("repair_success", {"stratum": "kind=repair"}),
        "repair_success_change_request": ("repair_success", {"stratum": "kind=change_request"}),
        "truncated_transitions": ("truncated_transitions", {}),
        "impact_precision_micro": ("impact_precision", {}),
        "impact_recall_micro": ("impact_recall", {}),
        "impact_precision_macro": ("impact_precision_macro", {}),
        "impact_recall_macro": ("impact_recall_macro", {}),
        "truth_recall_impact": ("truth_recall_impact", {}),
        "truth_recall_v": ("truth_recall_v", {}),
    }
    other = {
        c: {key: _record(metrics, name, c, **where) for key, (name, where) in wanted.items()}
        for c in conditions
    }
    h3 = {
        c: {
            name: _record(metrics, name, c, stratum="family=F5")
            for name in (
                "identity_error_rate_certain",
                "transition_error_rate_certain",
                "identity_uncertain_share_final",
                "evidence_transfer_error_rate",
            )
        }
        | {"identity_excluded_pairs_all": _record(metrics, "identity_excluded_pairs", c)}
        for c in ("C", "C_PRIME")
        if c in conditions
    }
    return {
        "marker": MARKER,
        "analysis_version": ANALYSIS_VERSION,
        "metrics_version": extraction["metrics_version"],
        "extractor_version": extraction["extractor_version"],
        "experiment_id": extraction["experiment_id"],
        "seed": seed,
        "coverage_reps": coverage_reps,
        "power_reps": power_reps,
        "icc": icc,
        "rho_analysis": rho,
        "coverage": {
            "rhos": list(RHOS),
            "configs": configs,
            "pi_grid": [list(p) for p in pi_grid()],
            "table": table,
            "decision": analysis.coverage_decision(table, threshold=THRESHOLD),
            "decision_dev_only": analysis.coverage_decision(
                [r for r in table if r["config"].endswith("/dev")], threshold=THRESHOLD
            ),
            "decision_test_bounds_only": analysis.coverage_decision(
                [r for r in table if "/test-" in r["config"]], threshold=THRESHOLD
            ),
        },
        "power": {
            "h1": {"mr_c_dev": mr_c, "rows": h1_rows},
            "h2": {"dev_cluster_means_by_tier": {t: len(v) for t, v in means.items()},
                   "power": h2_power_rows},
        },  # fmt: skip
        "h1": analysis.h1(rows, rho=rho),
        "h2_workload": analysis.h2_workload(rows),
        "h2_workload_common_prefix": analysis.h2_workload(rows, common_prefix=True),
        "h2_noninferiority": analysis.h2_noninferiority(rows, rho=rho),
        "h3": h3,
        "h3_work_difference_f5": extraction["lists"].get("work_difference_f5", {}),
        "h4": analysis.h4(rows),
        "other": other,
        "work_per_scenario": _per_scenario_work(rows),
        "kappa": extraction["lists"].get("kappa", []),
        "llm": llm_metrics(llm_rows),
    }
