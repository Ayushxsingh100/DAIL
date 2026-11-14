"""The second dev model pilot report (P10b Section 3; ``docs/P10B_MODEL_PILOT.md``).

Read from the stored records only (``experiments.report.pilot.collect_pilot`` for each generation):
Run A (prompt v3, k = 1, temperature 0) side by side with the P10a pilot (prompt v2, the same 12
scenarios and models), and Run B (prompt v3, k = 3, temperature 0.7, top_p 0.95, C-225). No label is
read and no model's safety is judged.

For each model and run: valid patches, failure classes by source, DAIL decisions under A, B, C and
C', and the reasons for C's rejections (``experiments.metrics.generation.rejection_reasons``). Run B
adds the distinct valid patches per scenario (by hash), latency, and the projection for 36 test
repair scenarios x 3 models x k = 3 (mean wall time per attempt of Run B).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from experiments.metrics.extractor import EXTRACTOR_VERSION, METRICS_VERSION
from experiments.metrics.generation import (
    distinct_patches,
    experiment_projection,
    model_metrics,
    rejection_reasons,
)

CONDITIONS = ("A", "B", "C", "C_PRIME")
K3_SUFFIX = "-k3"


def base_key(key: str) -> str:
    return key.removesuffix(K3_SUFFIX)


def _run(collected: Mapping[str, Any]) -> dict[str, Any]:
    replays = collected["replay"]["results"]
    full = _full_replays(collected)
    metrics = model_metrics(
        collected["attempts"], collected["responses"], collected["timings"], replays
    )
    definition = collected["definition"]
    return {
        "generation_id": collected["generation_id"],
        "generation_name": definition["name"],
        "prompt_version": definition["prompt_version"],
        "repetitions": definition["repetitions"],
        "candidates_manifest_sha256": collected["manifest_sha256"],
        "replay_sha256": collected["replay_sha256"],
        "environment": definition["environment"],
        "models": {
            base_key(key): {
                "key": key,
                "pin": collected["models"][key]["pin"],
                "installed": collected["models"][key]["installed"],
                "metrics": metrics[key],
            }
            for key in sorted(metrics)
        },
        "c_rejection_reasons": {base_key(k): v for k, v in rejection_reasons(full, "C").items()},
    }


def _full_replays(collected: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The replay results with their transitions (``collect_pilot`` keeps them in
    ``replay_full``)."""
    return list(collected.get("replay_full") or [])


def build_p10b(
    *,
    run_a: Mapping[str, Any],
    run_b: Mapping[str, Any],
    p10a: Mapping[str, Any],
    interruptions: Mapping[str, Any],
) -> dict[str, Any]:
    a, b, before = _run(run_a), _run(run_b), _run(p10a)
    distinct = {base_key(k): v for k, v in distinct_patches(run_b["attempts"]).items()}
    means = {m: v["metrics"]["wall_seconds"]["mean_per_attempt"] for m, v in b["models"].items()}
    scenarios = run_a["definition"]["scenarios"]
    return {
        "record": "p10b_model_pilot",
        "metrics_version": METRICS_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "scenarios": [
            {"scenario_id": s["scenario_id"], "family": s["family"],
             "target_invariant_id": s["target_invariant_id"]}
            for s in scenarios
        ],  # fmt: skip
        "p10a": before,
        "run_a": a,
        "run_b": b,
        "run_b_distinct": distinct,
        "projection": experiment_projection(means, scenarios=36, k=3),
        "interruptions": dict(interruptions),
    }


def _n(value: Any, digits: int = 1) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _table(head: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    return lines + ["| " + " | ".join(row) + " |" for row in rows]


def _valid(m: Mapping[str, Any] | None) -> str:
    if m is None:
        return "n/a"
    rate = m["metrics"]["valid_patch_rate"]
    return f"{rate['numerator']} / {rate['denominator']}"


def _failures(m: Mapping[str, Any] | None) -> str:
    if m is None:
        return "n/a"
    parts = []
    for source, cells in m["metrics"]["failure_classes"].items():
        parts += [f"{source} {k} {v}" for k, v in sorted(cells.items())]
    return ", ".join(parts) or "none"


def _decisions(m: Mapping[str, Any] | None, condition: str) -> str:
    if m is None:
        return "n/a"
    cells = m["metrics"]["decisions"].get(condition, {})
    return ", ".join(f"{k} {v}" for k, v in sorted(cells.items())) or "none"


def _reasons(rows: Sequence[Mapping[str, Any]]) -> str:
    return (
        "; ".join(f"{r['verifier_id']} {r['result']} {r['reason']} {r['count']}" for r in rows)
        or "none"
    )


def render_p10b(report: Mapping[str, Any]) -> str:
    a, b, before = report["run_a"], report["run_b"], report["p10a"]
    models = sorted(a["models"])
    env = a["environment"]
    lines = [
        "# P10b second dev model pilot",
        "",
        "Generated by `python -m experiments.report pilot-b` from the frozen candidate records and",
        "the replays; do not edit by hand. Dev split only. There are still no oracle labels for",
        "these candidates, so no model's safety is judged or ranked. Nothing but the prompt (v3,",
        "C-223) and, for Run B, the sampling (C-225) changed against the P10a pilot.",
        "",
        f"- Run A: `{a['generation_name']}` (`{a['generation_id']}`), prompt "
        f"`{a['prompt_version']}`,"
        f" k = {a['repetitions']}, temperature 0; manifest sha256 "
        f"`{a['candidates_manifest_sha256']}`",
        f"- Run B: `{b['generation_name']}` (`{b['generation_id']}`), prompt "
        f"`{b['prompt_version']}`,"
        f" k = {b['repetitions']}, temperature 0.7, top_p 0.95; manifest sha256 "
        f"`{b['candidates_manifest_sha256']}`",
        f"- P10a (compared): `{before['generation_name']}` (`{before['generation_id']}`), prompt "
        f"`{before['prompt_version']}`",
        f"- DAIL `{env.get('dail_commit')}` (clean tree: {env.get('dail_worktree_clean')}); "
        f"TerraPreserve `{env.get('terrapreserve_tag')}`; Ollama {env.get('ollama_version')}",
        f"- Metric definitions `{report['metrics_version']}`, extractor "
        f"`{report['extractor_version']}`",
        "- Interruptions: " + str(report["interruptions"].get("summary", "not checked")),
        "",
        "## 1. Run A against P10a: valid patches and failures",
        "",
    ]
    lines += _table(
        ["Model", "Valid (P10a, v2)", "Valid (Run A, v3)", "Failures (P10a)", "Failures (Run A)"],
        [
            [m, _valid(before["models"].get(m)), _valid(a["models"][m]),
             _failures(before["models"].get(m)), _failures(a["models"][m])]
            for m in models
        ],
    )  # fmt: skip
    lines += ["", "## 2. Run A against P10a: DAIL decisions on the valid candidates", ""]
    head = ["Model"]
    for c in CONDITIONS:
        head += [f"{c} (P10a)", f"{c} (Run A)"]
    rows = []
    for m in models:
        row = [m]
        for c in CONDITIONS:
            row += [_decisions(before["models"].get(m), c), _decisions(a["models"][m], c)]
        rows.append(row)
    lines += _table(head, rows)
    lines += [
        "",
        "## 3. Reasons for C's rejections (verifier, result, reason, count)",
        "",
        "Each required check that did not PASS in a candidate C rejected, counted once per",
        "candidate.",
        "",
    ]
    lines += _table(
        ["Model", "P10a (v2)", "Run A (v3)"],
        [
            [m, _reasons(before["c_rejection_reasons"].get(m, [])),
             _reasons(a["c_rejection_reasons"].get(m, []))]
            for m in models
        ],
    )  # fmt: skip
    lines += ["", "## 4. Run A: latency and wall time", ""]
    lines += _table(
        ["Model", "Calls", "Latency per call, mean / max (s)", "Wall time total (s)"],
        [
            [
                m,
                str(a["models"][m]["metrics"]["calls"]),
                f"{_n(_s(a['models'][m]['metrics']['latency_ms']['mean']))} / "
                f"{_n(_s(a['models'][m]['metrics']['latency_ms']['max']))}",
                _n(a["models"][m]["metrics"]["wall_seconds"]["total"]),
            ]
            for m in models
        ],
    )
    lines += ["", "## 5. Run B (k = 3, sampling): validity, distinct samples, latency", ""]
    bm = sorted(b["models"])
    lines += _table(
        ["Model", "Valid", "Failures", "Distinct valid patches per scenario (scenarios)",
         "Mean distinct", "Latency per call, mean / max (s)", "Per attempt, mean (s)"],
        [
            [
                m,
                _valid(b["models"][m]),
                _failures(b["models"][m]),
                ", ".join(f"{n}: {c}" for n, c in
                          report["run_b_distinct"][m]["scenarios_by_distinct"].items()),
                _n(report["run_b_distinct"][m]["mean_distinct"], 2),
                f"{_n(_s(b['models'][m]['metrics']['latency_ms']['mean']))} / "
                f"{_n(_s(b['models'][m]['metrics']['latency_ms']['max']))}",
                _n(b["models"][m]["metrics"]["wall_seconds"]["mean_per_attempt"]),
            ]
            for m in bm
        ],
    )  # fmt: skip
    lines += [
        "",
        "Distinct: the number of different valid patches (by SHA-256 of the patch text) among a",
        "scenario's 3 samples; the cell lists how many scenarios have 0, 1, 2 or 3.",
        "",
        "Run B's DAIL decisions on its valid candidates:",
        "",
    ]
    lines += _table(
        ["Model", *CONDITIONS],
        [[m, *[_decisions(b["models"][m], c) for c in CONDITIONS]] for m in bm],
    )
    projection = report["projection"]
    lines += [
        "",
        "## 6. Projection for the main run",
        "",
        f"{projection['scenarios']} test repair scenarios x 3 models x k = {projection['k']}, one",
        "model at a time on this machine, from Run B's mean wall time per attempt:",
        "",
    ]
    lines += _table(
        ["Model", "Hours"],
        [[m, _n(None if v is None else v / 3600, 2)]
         for m, v in projection["per_model_seconds"].items()]
        + [["Total", _n(projection["total_seconds"] / 3600, 2)]],
    )  # fmt: skip
    lines += [
        "",
        "It assumes the test scenarios are like these 12 dev scenarios in size.",
        "",
    ]
    return "\n".join(lines)


def _s(ms: float | None) -> float | None:
    return None if ms is None else ms / 1000
