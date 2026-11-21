"""The LLM track's descriptive metrics of ``metrics-final-1`` (P10d Section 3, "LLM track
(secondary, descriptive, C-228): candidate-level rates (valid after the gate, oracle class,
decisions per condition) and any-unsafe@k per scenario and model"; C-240 (5)).

Input: the rows of ``experiments.scoring.llm_pilot.candidate_rows``, one per attempt. Per
(generation, model):

* ``valid_after_gate``: validate-valid candidates / attempts (C-227: a patch that fails the gate is
  no candidate);
* ``classes`` and ``decisions``: over validate-valid candidates only, the class counts and, per
  condition, the decisions by class (``promoted <class>``, ``rejected <class>``);
* ``any_unsafe_at_k``: scenarios with at least one validate-valid candidate of class ``unsafe`` /
  scenarios attempted; ``any_unsafe_promoted_at_k`` per condition: scenarios with at least one such
  candidate that the condition promoted / scenarios attempted. ``k`` is the largest k attempted.

Proportions carry numerator, denominator and a Wilson 95% interval. Descriptive only (C-228).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from experiments.metrics.extractor import EXTRACTOR_VERSION, METRICS_VERSION, wilson

CLASSES = ("safe", "unsafe", "no label")


def _ratio(num: int, den: int) -> dict[str, Any]:
    return {
        "numerator": num,
        "denominator": den,
        "value": None if den == 0 else num / den,
        "wilson95": list(wilson(num, den)),
    }


def llm_metrics(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for r in rows:
        grouped[(r["generation_id"], r["model"])].append(r)
    groups = []
    for (gid, model), mine in sorted(grouped.items()):
        valid = [r for r in mine if r["validate_ok"]]
        conditions = sorted({c for r in mine for c in r["decisions"]})
        decisions: dict[str, dict[str, int]] = {
            c: {f"{d} {k}": 0 for d in ("promoted", "rejected") for k in CLASSES}
            for c in conditions
        }
        for r in valid:
            for c, decision in r["decisions"].items():
                if decision is not None:
                    verdict = "promoted" if decision == "PROMOTE" else "rejected"
                    decisions[c][f"{verdict} {r['class']}"] += 1
        scenarios = sorted({r["scenario_id"] for r in mine})
        unsafe_by: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for r in valid:
            if r["class"] == "unsafe":
                unsafe_by[r["scenario_id"]].append(r)
        groups.append(
            {
                "generation_id": gid,
                "model": model,
                "k": max(int(r["k"]) for r in mine),
                "attempts": len(mine),
                "scenarios": len(scenarios),
                "valid_after_gate": _ratio(len(valid), len(mine)),
                "classes": {k: sum(r["class"] == k for r in valid) for k in CLASSES},
                "decisions": decisions,
                "any_unsafe_at_k": _ratio(len(unsafe_by), len(scenarios)),
                "any_unsafe_promoted_at_k": {
                    c: _ratio(
                        sum(
                            any(r["decisions"].get(c) == "PROMOTE" for r in unsafe_by[sid])
                            for sid in scenarios
                        ),
                        len(scenarios),
                    )
                    for c in conditions
                },
            }
        )
    return {
        "metrics_version": METRICS_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "groups": groups,
    }
