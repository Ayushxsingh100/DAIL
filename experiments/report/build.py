"""The ExperimentReport (Doc 13 §33) built from the extractor's output only.

"ExperimentReport { experiment_id, experiment_version, trial_count, included_count, excluded_count,
condition_summaries[], primary_metrics[], secondary_metrics[], failures[], reproducibility_summary,
artifact_refs[] }." Added: the extractor version, every metric record, the lists and the confusion
tables, so that the Markdown rendering needs nothing but this document. A trial is included when it
is COMPLETED; every other one is listed under ``failures`` and counted as excluded (none is dropped,
Doc 13 §34).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from experiments.metrics.extractor import (
    EXTRACTOR_VERSION,
    METRICS_VERSION,
    Extraction,
    to_json,
)

REPORT_KEYS: Final = (
    "experiment_id",
    "experiment_version",
    "trial_count",
    "included_count",
    "excluded_count",
    "condition_summaries",
    "primary_metrics",
    "secondary_metrics",
    "failures",
    "reproducibility_summary",
    "artifact_refs",
)
PRIMARY: Final = (
    "unsafe_promotions_per_promotion",
    "unsafe_promotions_per_evaluated",
    "regressions",
    "missed_regressions_per_regression",
    "false_rejection_rate",
    "repair_success",
)


def build_report(
    *,
    definition: Mapping[str, Any],
    statuses: Mapping[str, str],
    extraction: Extraction,
    reproducibility: Mapping[str, Any] | None = None,
    preface: list[str] | None = None,
    artifact_refs: list[str] | None = None,
) -> dict[str, Any]:
    data = to_json(extraction)
    metrics = data["metrics"]
    failures = [
        {"trial_id": t, "status": s} for t, s in sorted(statuses.items()) if s != "COMPLETED"
    ]
    conditions = list(definition.get("condition_set", []))
    summaries = []
    for c in conditions:
        mine = [
            m
            for m in metrics
            if m["condition_id"] == c and m["scope"] == "all" and m["stratum"] == "all"
        ]
        get = {m["metric_name"]: m for m in mine}
        summaries.append(
            {
                "condition": c,
                "evaluated_transitions": (get.get("promote_rate") or {}).get("denominator"),
                "truncated_transitions": (get.get("truncated_transitions") or {}).get("numerator"),
                "all_transitions": (get.get("truncated_transitions") or {}).get("denominator"),
            }
        )
    return {
        "experiment_id": definition.get("experiment_id"),
        "experiment_name": definition.get("name"),
        "experiment_version": definition.get("version"),
        "metrics_version": METRICS_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "trial_count": len(statuses),
        "included_count": len(statuses) - len(failures),
        "excluded_count": len(failures),
        "condition_summaries": summaries,
        "primary_metrics": [m for m in metrics if m["metric_name"] in PRIMARY],
        "secondary_metrics": [m for m in metrics if m["metric_name"] not in PRIMARY],
        "failures": failures,
        "reproducibility_summary": dict(reproducibility or {}),
        "preface": list(preface or []),
        "artifact_refs": list(artifact_refs or []),
        "conditions": conditions,
        "definitions_held": sorted(
            ((definition.get("pins") or {}).get("verifiers") or {}).get("invariants") or {}
        ),
        "lists": data["lists"],
        "confusion": data["confusion"],
    }
