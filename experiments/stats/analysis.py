"""The analysis of the frozen protocol on the extractor's scenario outcome rows (P10d Section 3,
from the paper's §IV-H; C-231, C-232, C-235 to C-241).

Rows are ``lists["scenario_outcomes"]`` of ``metrics-final-1``. A cluster is (tier, cluster id):
the template for the controlled tier, the lineage for the real-world tier. The H1 strata tests and
the H2 workload test pool the clusters of both tiers and are inferential whatever the number of
clusters; results reported per tier with fewer than 10 clusters are descriptive (C-243). MR
scenarios are the rows whose ``mr`` is ``caught`` or ``missed``
(C-232, C-239).

* **H1** (A vs C), per stratum (``repair``: target-bearing; ``change_request``): the exact cluster
  sign test (two-sided) on the cluster MR differences MR_A - MR_C (each cluster weighted equally;
  for single-scenario clusters it is exact McNemar), with the smallest two-sided p it can reach
  with the stratum's discordant clusters (C-243), Holm across the two strata at alpha = 0.05;
  and the scenario-weighted MR_A - MR_C with Newcombe's method-10 95% interval, each cell divided
  by DEFF for the stratum's MR cluster sizes and ρ.
* **H2 workload** (confirmatory): per cluster the mean per-scenario W_C - W_B over every scenario
  with both; the one-sided exact sign test that clusters favour C (W_C < W_B), with n_favour_c,
  n_favour_b, n_zero, the median and the estimate P(cluster favours C | non-zero difference).
  ``common_prefix=True`` counts only the steps both conditions executed (the sensitivity analysis).
* **H2 non-inferiority** (exploratory, C-231): the one-sided 95% upper limit of MR_C - MR_B
  (the upper end of the nominal 90% method-10 interval with DEFF) against δ_NI = 0.05.
* **H4**: blocked unsafe F4 scenarios / unsafe F4 scenarios under C, Wilson 95%.
* **ICC** (P10d-2, C-236): the ANOVA estimator over the MR clusters of the missed indicator under
  B, under C, of the paired difference C - B and of A - C (H1's), per stratum and over both.
* **Coverage decision** (P10d-1, C-235): a stratum is descriptive when any simulated coverage of
  its configurations falls below 0.93; a configuration is named ``<stratum>/<sizes>``.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from experiments.stats.procedures import (
    deff,
    holm,
    icc_anova,
    min_p_two_sided,
    newcombe10,
    one_sided_upper_95,
    sign_test,
    wilson,
)

STRATA: Final = ("repair", "change_request")
MIN_CLUSTERS: Final = 10
DELTA_NI: Final = 0.05
Row = Mapping[str, Any]


def _by(rows: Iterable[Row], condition: str) -> dict[str, Row]:
    return {r["scenario_id"]: r for r in rows if r["condition"] == condition}


def _mr_rows(rows: Iterable[Row], condition: str, stratum: str | None) -> dict[str, Row]:
    return {
        sid: r
        for sid, r in _by(rows, condition).items()
        if r["mr"] in ("caught", "missed") and (stratum is None or r["kind"] == stratum)
    }


def _key(row: Row) -> tuple[str, str]:
    return (row["tier"], row["cluster"])


def mr_cluster_sizes(rows: Iterable[Row], condition: str, stratum: str | None) -> list[int]:
    sizes: dict[tuple[str, str], int] = defaultdict(int)
    for r in _mr_rows(list(rows), condition, stratum).values():
        sizes[_key(r)] += 1
    return [sizes[k] for k in sorted(sizes)]


def _paired(
    rows: Sequence[Row], first: str, second: str, stratum: str | None
) -> tuple[dict[str, int], dict[tuple[str, str], list[tuple[int, int]]]]:
    one, two = _mr_rows(rows, first, stratum), _mr_rows(rows, second, stratum)
    cells = {"both": 0, "first_only": 0, "second_only": 0, "neither": 0}
    clusters: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
    for sid in sorted(set(one) & set(two)):
        x, y = int(one[sid]["mr"] == "missed"), int(two[sid]["mr"] == "missed")
        cells[{(1, 1): "both", (1, 0): "first_only", (0, 1): "second_only", (0, 0): "neither"}[
            (x, y)
        ]] += 1  # fmt: skip
        clusters[_key(one[sid])].append((x, y))
    return cells, clusters


def _tiers(clusters: Iterable[tuple[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for tier, _ in clusters:
        counts[tier] += 1
    return dict(sorted(counts.items()))


def h1(rows: Sequence[Row], *, rho: float, alpha: float = 0.05) -> dict[str, Any]:
    strata: dict[str, Any] = {}
    for stratum in STRATA:
        cells, clusters = _paired(rows, "A", "C", stratum)
        diffs = [
            sum(x for x, _ in pairs) / len(pairs) - sum(y for _, y in pairs) / len(pairs)
            for pairs in clusters.values()
        ]
        plus, minus = sum(d > 0 for d in diffs), sum(d < 0 for d in diffs)
        n = sum(cells.values())
        design = deff([len(p) for p in clusters.values()], rho)
        scaled = [cells[k] / design for k in ("both", "first_only", "second_only", "neither")]
        tiers = _tiers(clusters)
        strata[stratum] = {
            "scenarios": n,
            "clusters": len(clusters),
            "clusters_by_tier": tiers,
            "descriptive_tiers": [t for t, c in tiers.items() if c < MIN_CLUSTERS],
            "n_plus": plus,
            "n_minus": minus,
            "n_zero": len(diffs) - plus - minus,
            "p_two_sided": sign_test(plus, minus, alternative="two-sided"),
            "discordant_clusters": plus + minus,
            "min_attainable_p_two_sided": min_p_two_sided(plus + minus),
            "cells": cells,
            "mr_a": None if n == 0 else (cells["both"] + cells["first_only"]) / n,
            "mr_c": None if n == 0 else (cells["both"] + cells["second_only"]) / n,
            "difference": (None if n == 0 else (cells["first_only"] - cells["second_only"]) / n),
            "deff": design,
            "interval95": list(newcombe10(*scaled)),
        }
    adjusted, rejected = holm({s: strata[s]["p_two_sided"] for s in STRATA}, alpha=alpha)
    return {
        "alpha": alpha,
        "rho": rho,
        "strata": strata,
        "holm_adjusted": adjusted,
        "holm_rejected": rejected,
    }


def h2_workload(rows: Sequence[Row], *, common_prefix: bool = False) -> dict[str, Any]:
    b, c = _by(rows, "B"), _by(rows, "C")
    per_cluster: dict[tuple[str, str], list[float]] = defaultdict(list)
    for sid in sorted(set(b) & set(c)):
        if common_prefix:
            shared = set(b[sid]["work_by_step"]) & set(c[sid]["work_by_step"])
            wc = sum(c[sid]["work_by_step"][s] for s in shared)
            wb = sum(b[sid]["work_by_step"][s] for s in shared)
        else:
            wc, wb = c[sid]["work_w"], b[sid]["work_w"]
        per_cluster[_key(c[sid])].append(wc - wb)
    means = [statistics.fmean(v) for _, v in sorted(per_cluster.items())]
    favour_c, favour_b = sum(m < 0 for m in means), sum(m > 0 for m in means)
    nonzero = favour_c + favour_b
    return {
        "common_prefix": common_prefix,
        "scenarios": sum(len(v) for v in per_cluster.values()),
        "clusters": len(means),
        "clusters_by_tier": _tiers(per_cluster),
        "n_favour_c": favour_c,
        "n_favour_b": favour_b,
        "n_zero": len(means) - nonzero,
        "median_cluster_difference": statistics.median(means) if means else None,
        "p_one_sided": sign_test(favour_c, favour_b, alternative="greater"),
        "estimate_p_favours_c": None if nonzero == 0 else favour_c / nonzero,
    }


def h2_noninferiority(rows: Sequence[Row], *, rho: float) -> dict[str, Any]:
    cells, clusters = _paired(rows, "C", "B", None)
    design = deff([len(p) for p in clusters.values()], rho)
    upper = one_sided_upper_95(
        cells["both"], cells["first_only"], cells["second_only"], cells["neither"],
        deff_value=design,
    )  # fmt: skip
    n = sum(cells.values())
    return {
        "scenarios": n,
        "clusters": len(clusters),
        "cells": cells,
        "difference_c_minus_b": (
            None if n == 0 else (cells["first_only"] - cells["second_only"]) / n
        ),
        "deff": design,
        "upper95_one_sided": upper,
        "margin": DELTA_NI,
        "upper_below_margin": upper is not None and upper < DELTA_NI,
        "status": "exploratory (C-231)",
    }


def h4(rows: Sequence[Row], condition: str = "C") -> dict[str, Any]:
    unsafe = [r for r in _by(rows, condition).values() if r["family"] == "F4" and r["unsafe"]]
    blocked = sum(bool(r["blocked"]) for r in unsafe)
    return {
        "condition": condition,
        "numerator": blocked,
        "denominator": len(unsafe),
        "value": None if not unsafe else blocked / len(unsafe),
        "wilson95": list(wilson(blocked, len(unsafe))),
    }


def icc_estimates(rows: Sequence[Row]) -> dict[str, dict[str, float | None]]:
    found: dict[str, dict[str, float | None]] = {}
    for stratum in (*STRATA, None):
        groups: dict[str, dict[tuple[str, str], list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        a, b, c = (_mr_rows(rows, x, stratum) for x in ("A", "B", "C"))
        for sid in sorted(set(b) & set(c)):
            yb, yc = int(b[sid]["mr"] == "missed"), int(c[sid]["mr"] == "missed")
            key = _key(c[sid])
            groups["B"][key].append(yb)
            groups["C"][key].append(yc)
            groups["C_minus_B"][key].append(yc - yb)
        for sid in sorted(set(a) & set(c)):
            ya, yc = int(a[sid]["mr"] == "missed"), int(c[sid]["mr"] == "missed")
            groups["A_minus_C"][_key(c[sid])].append(ya - yc)
        found[stratum or "all"] = {
            name: icc_anova(list(groups[name].values()))
            for name in ("B", "C", "C_minus_B", "A_minus_C")
        }
    return found


def coverage_decision(
    table: Iterable[Mapping[str, Any]], *, threshold: float = 0.93
) -> dict[str, dict[str, Any]]:
    worst: dict[str, Mapping[str, Any]] = {}
    for row in table:
        stratum = row["config"].split("/", 1)[0]
        if stratum not in worst or row["coverage"] < worst[stratum]["coverage"]:
            worst[stratum] = row
    return {
        stratum: {
            "minimum": row["coverage"],
            "at": {k: row[k] for k in row if k != "coverage"},
            "threshold": threshold,
            "outcome": "inferential" if row["coverage"] >= threshold else "descriptive",
        }
        for stratum, row in sorted(worst.items())
    }
