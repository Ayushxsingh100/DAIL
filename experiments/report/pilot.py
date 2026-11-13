"""The dev model pilot report (P10a Step 6; ``docs/P10A_MODEL_PILOT.md``).

``collect_pilot`` reads the frozen records of one generation and one replay under
``$DAIL_EXPERIMENT_ROOT/candidates/<generation_id>/`` (the manifest, every ``attempt.json`` with its
response records and ``timing.json``, each model's ``model.json``, and
``replay/<name>/replay.json``) and nothing else: no label, no oracle. ``build_pilot`` adds the
generation metrics of ``experiments.metrics.generation`` and the licence checks, and
``render_pilot`` writes the Markdown. The JSON is the record; the Markdown is its rendering (a test
renders the committed JSON and compares).

Step 6: "Do not rank the models' safety. There are no labels yet, and the pilot only sizes the main
run." The report says so, and orders models by their key only.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from experiments.artifacts import read_record
from experiments.metrics.extractor import EXTRACTOR_VERSION, METRICS_VERSION
from experiments.metrics.generation import PROJECTION_K, PROJECTION_SCENARIOS, model_metrics


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_pilot(root: Path, generation_id: str, replay_name: str) -> dict[str, Any]:
    base = Path(root) / "candidates" / generation_id
    manifest_path = base / "candidates_manifest.json"
    manifest = read_record(manifest_path)
    definition = read_record(base / "definition.json")
    attempts: list[dict[str, Any]] = []
    responses: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    timings: dict[tuple[str, str, int], dict[str, Any]] = {}
    for row in manifest["attempts"]:
        key = (row["model_key"], row["scenario_id"], int(row["k"]))
        folder = base / row["model_key"] / row["scenario_id"] / str(row["k"])
        attempts.append(read_record(folder / "attempt.json"))
        records = folder / "records"
        responses[key] = (
            [
                read_record(records / f"response-{n}.json")
                for n in range(1, len(list(records.glob("response-*.json"))) + 1)
            ]
            if records.exists()
            else []
        )
        timings[key] = read_record(folder / "timing.json")
    models = {p.parent.name: read_record(p) for p in sorted(base.glob("*/model.json"))}
    replay_path = base / "replay" / replay_name / "replay.json"
    replay = read_record(replay_path)
    return {
        "generation_id": generation_id,
        "definition": definition,
        "manifest_sha256": _sha(manifest_path),
        "replay_name": replay_name,
        "replay_sha256": _sha(replay_path),
        "attempts": attempts,
        "responses": responses,
        "timings": timings,
        "models": models,
        "replay": replay,
    }


def build_pilot(
    collected: Mapping[str, Any], licence_checks: Mapping[str, Mapping[str, str]]
) -> dict[str, Any]:
    """The pilot report as JSON. ``licence_checks`` holds, per model key, what the author checked on
    the day (the Ollama library page and ``ollama show --license``)."""
    metrics = model_metrics(
        collected["attempts"],
        collected["responses"],
        collected["timings"],
        collected["replay"]["results"],
    )
    definition = collected["definition"]
    models = []
    for key in sorted(metrics):
        stored = collected["models"][key]
        models.append(
            {
                "key": key,
                "pin": stored["pin"],
                "installed": stored["installed"],
                "licence_check": dict(licence_checks.get(key, {})),
                "metrics": metrics[key],
            }
        )
    scenarios = definition["scenarios"]
    return {
        "record": "p10a_model_pilot",
        "metrics_version": METRICS_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "generation_id": collected["generation_id"],
        "generation_name": definition["name"],
        "generation_version": definition["version"],
        "candidates_manifest_sha256": collected["manifest_sha256"],
        "replay_name": collected["replay_name"],
        "replay_sha256": collected["replay_sha256"],
        "environment": definition["environment"],
        "prompt_version": definition["prompt_version"],
        "parser_version": definition["parser_version"],
        "validator_version": definition["validator_version"],
        "retry_policy": definition["retry_policy"],
        "repetitions": definition["repetitions"],
        "scenarios": [
            {"scenario_id": s["scenario_id"], "family": s["family"],
             "target_invariant_id": s["target_invariant_id"]}
            for s in scenarios
        ],  # fmt: skip
        "conditions": collected["replay"]["conditions"],
        "models": models,
    }


def _n(value: Any, digits: int = 1) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _classes(cells: Mapping[str, Mapping[str, int]], source: str) -> str:
    found = cells.get(source) or {}
    return ", ".join(f"{k} {v}" for k, v in found.items()) or "none"


def _table(head: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return lines


def render_pilot(report: Mapping[str, Any]) -> str:
    env = report["environment"]
    models = report["models"]
    lines = [
        "# P10a dev model pilot",
        "",
        "Generated by `python -m experiments.report pilot` from the frozen candidate records and",
        "the replay; do not edit by hand. Dev split only. It sizes the main run and is not a",
        "result: there are no oracle labels for these candidates yet, so no model's safety is",
        "judged or ranked (P10a Step 6). The authors choose the models and k at the protocol",
        "freeze (P10b).",
        "",
        f"- Generation: `{report['generation_name']}` version {report['generation_version']}, id "
        f"`{report['generation_id']}`; candidates manifest sha256 "
        f"`{report['candidates_manifest_sha256']}`",
        f"- Replay: `{report['replay_name']}` (sha256 `{report['replay_sha256']}`), conditions "
        + ", ".join(report["conditions"]),
        f"- DAIL `{env.get('dail_commit')}` (clean tree: {env.get('dail_worktree_clean')}); "
        f"TerraPreserve `{env.get('terrapreserve_tag')}`; Ollama {env.get('ollama_version')}",
        f"- Prompt `{report['prompt_version']}`, parser `{report['parser_version']}`, validator "
        f"`{report['validator_version']}`; retry policy `{report['retry_policy']['policy_id']}` "
        f"(at most {report['retry_policy']['max_attempts']} calls, again only after "
        + ", ".join(report["retry_policy"]["retry_on"])
        + ")",
        f"- Metric definitions `{report['metrics_version']}`, extractor "
        f"`{report['extractor_version']}`",
        f"- Scenarios: {len(report['scenarios'])} dev repair scenarios, k = "
        f"{report['repetitions']}: "
        + ", ".join(
            f"{s['scenario_id']} ({s['target_invariant_id']})" for s in report["scenarios"]
        ),
        "",
        "## 1. Models",
        "",
    ]
    lines += _table(
        ["Model", "Tag", "Digest", "Quantization", "Size", "Licence", "Licence checked"],
        [
            [
                m["key"],
                f"`{m['pin']['tag']}`",
                f"`{m['pin']['digest']}`",
                m["pin"]["quantization"],
                m["pin"]["size"],
                m["pin"]["licence"],
                m["pin"]["licence_source"],
            ]
            for m in models
        ],
    )
    lines += [
        "",
        "Settings: "
        + "; ".join(
            f"{m['key']}: temperature {m['pin']['temperature']}, top_p {m['pin']['top_p']}, seed "
            f"{m['pin']['seed']}, max_output_tokens {m['pin']['max_output_tokens']}, num_ctx "
            f"{m['pin']['num_ctx']}, timeout {m['pin']['timeout_seconds']} s"
            for m in models
        ),
        "",
        "## 2. Validity, failures and retries",
        "",
    ]
    lines += _table(
        ["Model", "Valid patches", "Failures: model", "Failures: provider", "Failures: budget",
         "Calls", "Retries"],
        [
            [
                m["key"],
                f"{m['metrics']['valid_patch_rate']['numerator']} / "
                f"{m['metrics']['valid_patch_rate']['denominator']}",
                _classes(m["metrics"]["failure_classes"], "model"),
                _classes(m["metrics"]["failure_classes"], "provider"),
                _classes(m["metrics"]["failure_classes"], "budget"),
                str(m["metrics"]["calls"]),
                str(m["metrics"]["retries"]),
            ]
            for m in models
        ],
    )  # fmt: skip
    lines += [
        "",
        "Provider failures (no reply: connection, timeout, Ollama 400/404 as UNSUPPORTED) are kept",
        "apart from model failures (a reply the parser or validator 2 refused) (P7a limit 4).",
        "",
        "## 3. Latency, tokens and wall time",
        "",
    ]
    lines += _table(
        ["Model", "Latency per call, mean (s)", "max (s)", "Tokens in / out per call (server)",
         "Input estimate, mean / max", "Wall time total (s)", "per attempt, mean (s)"],
        [
            [
                m["key"],
                _n(None if m["metrics"]["latency_ms"]["mean"] is None
                   else m["metrics"]["latency_ms"]["mean"] / 1000),
                _n(None if m["metrics"]["latency_ms"]["max"] is None
                   else m["metrics"]["latency_ms"]["max"] / 1000),
                f"{_n(m['metrics']['tokens']['provider_input_mean_per_call'], 0)} / "
                f"{_n(m['metrics']['tokens']['provider_output_mean_per_call'], 0)}",
                f"{_n(m['metrics']['tokens']['estimated_input_mean'], 0)} / "
                f"{_n(m['metrics']['tokens']['estimated_input_max'])}",
                _n(m["metrics"]["wall_seconds"]["total"]),
                _n(m["metrics"]["wall_seconds"]["mean_per_attempt"]),
            ]
            for m in models
        ],
    )  # fmt: skip
    lines += [
        "",
        "Token counts per call are the local server's (`prompt_eval_count`, `eval_count`). The",
        "input estimate is the budget's estimate, ceil(characters / 4) of the rendered prompt",
        "(P7a limit 5), not a tokenizer count. Wall time is the frozen duration of each attempt",
        "(calls, validation and build).",
        "",
        "## 4. DAIL decisions on the valid candidates",
        "",
    ]
    conditions = report["conditions"]
    lines += _table(
        ["Model", *conditions],
        [
            [
                m["key"],
                *[
                    ", ".join(f"{k} {v}" for k, v in m["metrics"]["decisions"].get(c, {}).items())
                    or "none"
                    for c in conditions
                ],
            ]
            for m in models
        ],
    )
    lines += [
        "",
        "Each valid candidate is evaluated once per condition as a one-step candidate from S0.",
        "These are DAIL's decisions, not judgements of the candidates: without oracle labels a",
        "PROMOTE is",
        "not known to be safe, and a REJECT is not known to be right.",
        "",
        f"## 5. Projection for {PROJECTION_SCENARIOS} test repair scenarios",
        "",
    ]
    lines += _table(
        ["Model", *[f"k = {k} (hours)" for k in PROJECTION_K]],
        [
            [
                m["key"],
                *[
                    _n(None if v is None else v / 3600, 2)
                    for v in m["metrics"]["projection_seconds"].values()
                ],
            ]
            for m in models
        ],
    )
    lines += [
        "",
        f"Projection = mean wall time per attempt here x {PROJECTION_SCENARIOS} x k, one model",
        "at a time on this machine; it assumes the test scenarios are like these dev scenarios",
        "in size.",
        "",
        "## 6. Licence checks",
        "",
    ]
    for m in models:
        check = m["licence_check"]
        lines.append(
            f"- {m['key']}: {m['pin']['licence']}. "
            + "; ".join(f"{k}: {v}" for k, v in sorted(check.items()))
        )
    lines.append("")
    return "\n".join(lines)
