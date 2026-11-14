"""Generation metrics of frozen LLM candidates (P10a Section 3.3 "Generation metrics"; Doc 13 §26;
P7a verdict limits 4 and 5; metric definitions ``metrics-draft-1``, extractor ``extractor-2``).

"Generation metrics (in the extractor, under ``metrics-draft-1``): valid patch rate per model
(Doc 13 §26), failure classes per model (with Ollama UNSUPPORTED kept apart from model failures,
P7a limit 4), retries, latency, and token counts (marked as estimates where they come from
``ceil(characters / 4)``, P7a limit 5). Repair metrics that need truth wait for the oracle labels."

Input: the frozen attempt records (``attempt.json``), their response records and timings, and the
replay results; nothing else, and no label. Per model:

* ``valid_patch_rate``: attempts whose status is PATCH (parsed and passed validator 2, so a
  candidate was built) / attempts (one attempt = one scenario and one ``k``), with Wilson 95%;
* failure classes by source: ``provider`` (no reply: connection, timeout, Ollama 400/404 as
  UNSUPPORTED), ``budget`` (CONTEXT_INSUFFICIENT, no call), ``model`` (the reply was refused by the
  parser or the validator);
* calls (provider requests, retries included) and retries (calls - attempts that made a call);
* latency per call in ms (mean, max) from the response records (calls with a reply);
* tokens: ``provider`` counts as the local server reported them (``prompt_eval_count``,
  ``eval_count``), and the budget's ``estimate`` of the input (``ceil(characters / 4)``), labelled
  as such;
* wall time: the sum of the frozen ``timing.json`` durations (generation, validation and build of
  every attempt), its mean per attempt, and the projection mean x scenarios x k;
* DAIL decisions per condition from the replay (PROMOTE, REJECT, ..., or NO DECISION when the
  rebuild did not match).
"""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from experiments.metrics.extractor import EXTRACTOR_VERSION, METRICS_VERSION, wilson

ESTIMATE_RULE: Final = "ceil(characters / 4)"
PROJECTION_SCENARIOS: Final = 36
PROJECTION_K: Final = (1, 3, 5)
NO_DECISION: Final = "NO DECISION"


def _mean(values: Sequence[float]) -> float | None:
    return statistics.fmean(values) if values else None


def model_metrics(
    attempts: Sequence[Mapping[str, Any]],
    responses: Mapping[tuple[str, str, int], Sequence[Mapping[str, Any]]],
    timings: Mapping[tuple[str, str, int], Mapping[str, Any]],
    replays: Iterable[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Per model key (see the module docstring). ``responses`` and ``timings`` are keyed by
    (model key, scenario id, k)."""
    out: dict[str, dict[str, Any]] = {}
    keys = sorted({a["model_key"] for a in attempts})
    replay_list = list(replays)
    for key in keys:
        mine = [a for a in attempts if a["model_key"] == key]
        n = len(mine)
        valid = sum(a["status"] == "PATCH" for a in mine)
        sources: dict[str, Counter[str]] = {
            "provider": Counter(),
            "budget": Counter(),
            "model": Counter(),
        }
        statuses: Counter[str] = Counter(a["status"] for a in mine)
        for a in mine:
            if a["failure_class"] is not None:
                sources[a["failure_source"]][a["failure_class"]] += 1
        calls: list[Mapping[str, Any]] = []
        for a in mine:
            calls += list(responses.get((key, a["scenario_id"], int(a["k"])), ()))
        made_a_call = sum(1 for a in mine if responses.get((key, a["scenario_id"], int(a["k"]))))
        latencies = [float(r["latency_ms"]) for r in calls if r.get("latency_ms") is not None]
        tokens_in = [int(r["token_usage"]["input"]) for r in calls if "input" in r["token_usage"]]
        tokens_out = [
            int(r["token_usage"]["output"]) for r in calls if "output" in r["token_usage"]
        ]
        estimates = [
            int(a["observability"]["budget"]["estimated_input_tokens"])
            for a in mine
            if a["observability"]["budget"].get("estimated_input_tokens") is not None
        ]
        walls = [
            float(t["wall_seconds"])
            for a in mine
            if (t := timings.get((key, a["scenario_id"], int(a["k"])))) is not None
        ]
        per_attempt = _mean(walls)
        decisions: dict[str, dict[str, int]] = {}
        for r in replay_list:
            if r["model_key"] == key:
                cell = decisions.setdefault(r["condition"], {})
                label = r["decision"] or NO_DECISION
                cell[label] = cell.get(label, 0) + 1
        low, high = wilson(valid, n)
        out[key] = {
            "metrics_version": METRICS_VERSION,
            "extractor_version": EXTRACTOR_VERSION,
            "attempts": n,
            "statuses": dict(sorted(statuses.items())),
            "valid_patch_rate": {
                "numerator": valid,
                "denominator": n,
                "value": valid / n if n else None,
                "wilson95": [low, high],
            },
            "failure_classes": {s: dict(sorted(c.items())) for s, c in sources.items()},
            "calls": len(calls),
            "retries": len(calls) - made_a_call,
            "latency_ms": {
                "calls_with_a_reply": len(latencies),
                "mean": _mean(latencies),
                "max": max(latencies) if latencies else None,
            },
            "tokens": {
                "provider_input_total": sum(tokens_in),
                "provider_output_total": sum(tokens_out),
                "provider_input_mean_per_call": _mean(tokens_in),
                "provider_output_mean_per_call": _mean(tokens_out),
                "provider_source": "the local server's prompt_eval_count and eval_count",
                "estimated_input_mean": _mean(estimates),
                "estimated_input_max": max(estimates) if estimates else None,
                "estimate_rule": f"estimate: {ESTIMATE_RULE} of the rendered prompt",
            },
            "wall_seconds": {
                "total": sum(walls),
                "mean_per_attempt": per_attempt,
                "max_per_attempt": max(walls) if walls else None,
            },
            "projection_seconds": {
                f"{PROJECTION_SCENARIOS} scenarios x k={k}": (
                    None if per_attempt is None else per_attempt * PROJECTION_SCENARIOS * k
                )
                for k in PROJECTION_K
            },
            "decisions": dict(sorted(decisions.items())),
        }
    return out


# --- P10b (extractor-3) ---------------------------------------------------------------


def rejection_reasons(
    replays: Iterable[Mapping[str, Any]], condition: str
) -> dict[str, list[dict[str, Any]]]:
    """Per model: the required checks that did not PASS in the candidates ``condition`` rejected,
    counted by (verifier, result, reason), most frequent first (P10b Run A)."""
    counts: dict[str, Counter[tuple[str, str, str | None]]] = {}
    for r in replays:
        if r["condition"] != condition or r["decision"] != "REJECT" or r["transition"] is None:
            continue
        required = {c["target_id"] for c in r["transition"]["required"]}
        cell = counts.setdefault(r["model_key"], Counter())
        for w in r["transition"]["work"]:
            if w["target_id"] in required and w["result"] not in (None, "PASS"):
                cell[(w["verifier_id"], w["result"], w["reason"])] += 1
    return {
        model: [
            {"verifier_id": v, "result": res, "reason": why, "count": n}
            for (v, res, why), n in sorted(
                cell.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1], str(kv[0][2]))
            )
        ]
        for model, cell in sorted(counts.items())
    }


def distinct_patches(attempts: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per model: how many distinct valid patches (by ``patch_sha256``) each scenario's samples gave
    (P10b Run B)."""
    out: dict[str, dict[str, Any]] = {}
    for model in sorted({a["model_key"] for a in attempts}):
        mine = [a for a in attempts if a["model_key"] == model]
        per: dict[str, set[str]] = {}
        samples: Counter[str] = Counter()
        for a in mine:
            samples[a["scenario_id"]] += 1
            found = per.setdefault(a["scenario_id"], set())
            if a["status"] == "PATCH" and a["patch_sha256"] is not None:
                found.add(a["patch_sha256"])
        counts = {sid: len(found) for sid, found in sorted(per.items())}
        by = Counter(str(n) for n in counts.values())
        out[model] = {
            "per_scenario": counts,
            "scenarios_by_distinct": dict(sorted(by.items())),
            "samples_per_scenario": max(samples.values()) if samples else 0,
            "mean_distinct": _mean([float(n) for n in counts.values()]),
        }
    return out


def experiment_projection(
    mean_seconds_per_attempt: Mapping[str, float | None], *, scenarios: int, k: int
) -> dict[str, Any]:
    """The time of ``scenarios`` x every model x ``k``, one model at a time (P10b Run B)."""
    per = {
        m: None if v is None else v * scenarios * k
        for m, v in sorted(mean_seconds_per_attempt.items())
    }
    return {
        "scenarios": scenarios,
        "k": k,
        "per_model_seconds": per,
        "total_seconds": sum(v for v in per.values() if v is not None),
        "models_without_a_mean": [m for m, v in per.items() if v is None],
    }
