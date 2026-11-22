"""The main run's analysis, in the order of protocol §9 (P10e-prep decision 5; C-238, C-249).

``unblind`` runs, in this order, and writes each result before the next starts:

1. ``test_mr_cluster_sizes``: the actual test MR cluster sizes per stratum, from the truth only
   (an unsafe scenario with a regression-inducing step, C-232, C-239; clusters (tier, template or
   lineage), sorted as ``experiments.stats.analysis.mr_cluster_sizes`` sorts them). No outcome is
   read.
2. ``coverage``: the coverage simulation of the frozen code (``coverage_table`` with the frozen
   ``RHOS``, ``pi_grid``, seed and replications) on the dev sizes of the dry run and the actual
   test sizes, and the rule of P10d-1 (``coverage_decision``, threshold 0.93) per stratum.
3. The outcomes (``read_outcomes``: the ``metrics-final-1`` extraction of the main run's records)
   are read for the first time.
4. ``kappa``: the extractor's κ per invariant (C-237), written before any adjudication is read.
5. ``adjudication``: the adjudication file, if there is one (read only now).
6. ``analysis``: H1, H2 (workload, common prefix, exploratory non-inferiority), H3, H4, the other
   metrics and the LLM track, with the coverage outcome per stratum beside them. The power
   simulations are not rerun: the protocol reports the pre-freeze ones (C-242).

``simulate`` and ``analyse`` exist so the order can be tested without the simulation's cost; the
main-run command passes neither.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from experiments.metrics.llm_final import llm_metrics
from experiments.scoring.labels import ScenarioLabels
from experiments.scoring.truth import scenario_truth
from experiments.stats import analysis
from experiments.stats.dry_run import (
    ANALYSIS_VERSION,
    COVERAGE_REPS,
    RHOS,
    SEED,
    THRESHOLD,
    _per_scenario_work,
    _record,
    pi_grid,
)
from experiments.stats.simulate import coverage_table

MARKER: Final = "MAIN RUN (test split, protocol-v1)"
Write = Callable[[str, Any], object]


def actual_test_sizes(scored: Mapping[str, ScenarioLabels]) -> dict[str, list[int]]:
    sizes: dict[str, dict[tuple[str, str], int]] = {
        s: defaultdict(int) for s in ("repair", "change_request", "all")
    }
    for sid in sorted(scored):
        scenario = scored[sid]
        truth = scenario_truth(scenario)
        if not truth.unsafe or truth.first_regression_step is None:
            continue
        key = (scenario.tier, scenario.cluster)
        sizes["all"][key] += 1
        if scenario.kind in sizes:
            sizes[scenario.kind][key] += 1
    return {f"{s}/test": [found[k] for k in sorted(found)] for s, found in sizes.items()}


def _simulate(rho: float) -> Callable[[dict[str, list[int]]], list[dict[str, Any]]]:
    def run(configs: dict[str, list[int]]) -> list[dict[str, Any]]:
        return coverage_table(configs, RHOS, rho, pi_grid(), reps=COVERAGE_REPS, seed=SEED)

    return run


def main_analysis(
    extraction: Mapping[str, Any],
    llm_rows: Sequence[Mapping[str, Any]],
    rho: float,
    coverage: Mapping[str, Any],
) -> dict[str, Any]:
    rows = extraction["lists"]["scenario_outcomes"]
    metrics = extraction["metrics"]
    conditions = sorted({r["condition"] for r in rows})
    names = (
        "unsafe_promotions_per_promotion",
        "unsafe_promotions_per_evaluated",
        "false_rejection_rate",
        "missed_regressions_per_regression",
        "truncated_transitions",
        "impact_precision",
        "impact_recall",
        "impact_precision_macro",
        "impact_recall_macro",
        "truth_recall_impact",
        "truth_recall_v",
    )
    other = {
        c: {n: _record(metrics, n, c) for n in names}
        | {
            "missed_regression_rate": _record(
                metrics, "missed_regression_rate", c, scope="scenario"
            ),
            "mr_no_regression_step": _record(metrics, "mr_no_regression_step", c, scope="scenario"),
            "repair_success_repair": _record(metrics, "repair_success", c, stratum="kind=repair"),
            "repair_success_change_request": _record(
                metrics, "repair_success", c, stratum="kind=change_request"
            ),
        }
        for c in conditions
    }
    h3 = {
        c: {
            n: _record(metrics, n, c, stratum="family=F5")
            for n in (
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
        "rho_analysis": rho,
        "coverage_outcome": {s: d["outcome"] for s, d in coverage["decision"].items()},
        "h1": analysis.h1(rows, rho=rho),
        "h2_workload": analysis.h2_workload(rows),
        "h2_workload_common_prefix": analysis.h2_workload(rows, common_prefix=True),
        "h2_noninferiority": analysis.h2_noninferiority(rows, rho=rho),
        "h3": h3,
        "h3_work_difference_f5": extraction["lists"].get("work_difference_f5", {}),
        "h4": analysis.h4(rows),
        "icc_test": analysis.icc_estimates(rows),
        "other": other,
        "work_per_scenario": _per_scenario_work(rows),
        "llm": llm_metrics(llm_rows),
    }


def unblind(
    scored: Mapping[str, ScenarioLabels],
    *,
    read_outcomes: Callable[[], Mapping[str, Any]],
    read_adjudication: Callable[[], Any],
    read_llm_rows: Callable[[], Sequence[Mapping[str, Any]]],
    dev_sizes: Mapping[str, list[int]],
    rho: float,
    write: Write,
    simulate: Callable[[dict[str, list[int]]], list[dict[str, Any]]] | None = None,
    analyse: Callable[..., Any] | None = None,
) -> None:
    sizes = actual_test_sizes(scored)
    write("test_mr_cluster_sizes", sizes)
    configs = {**dict(dev_sizes), **sizes}
    table = (simulate or _simulate(rho))(configs)
    coverage = {
        "rhos": list(RHOS),
        "rho_analysis": rho,
        "threshold": THRESHOLD,
        "seed": SEED,
        "reps": COVERAGE_REPS,
        "configs": configs,
        "table": table,
        "decision": analysis.coverage_decision(table, threshold=THRESHOLD),
    }
    write("coverage", coverage)
    extraction = read_outcomes()
    write("kappa", extraction["lists"].get("kappa", []))
    write("adjudication", read_adjudication())
    llm_rows = read_llm_rows()
    if analyse is None:
        result = main_analysis(extraction, llm_rows, rho, coverage)
    else:
        result = analyse(extraction, llm_rows, rho)
    write("analysis", result)
