"""The report command line (P8b Steps 4-5).

    python -m experiments.report extract --name NAME [--version V] [--doc docs/P8_DEV_PILOT]
    python -m experiments.report select --name NAME [--version V]
    python -m experiments.report compare --name NAME --other OTHER [--version V]
    python -m experiments.report pilot --name GENERATION [--version V] --replay-name R
                                       --licence-checks FILE.json [--doc docs/P10A_MODEL_PILOT]

``extract`` reads the stored records of the experiment under ``$DAIL_EXPERIMENT_ROOT`` and the dev
labels under ``$TERRAPRESERVE_ROOT`` (through ``experiments.scoring``), runs the extractor and
writes ``report/<extractor version>/{metric_records.json, report.json, report.md}`` once: run again,
it checks that what it would write is byte-identical to what is stored (Doc 13 §30) and fails if
not. With ``--doc`` it also writes ``<doc>.json`` and ``<doc>.md``. ``select`` prints the scenario
ids of the reproducibility re-run. ``compare`` compares the decisions and invariant results of two
experiments on their common (scenario, condition, step) and prints the counts. ``pilot`` (P10a
Step 6) reads one frozen generation and its replay and writes the model pilot report once, under
``candidates/<generation_id>/pilot_report/<replay name>/`` (and with ``--doc`` beside the docs).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from experiments.artifacts import ArtifactError, dumps, read_record, write_or_same
from experiments.definition import experiment_id_for, name_id
from experiments.metrics.extractor import EXTRACTOR_VERSION, dumps_metrics, extract
from experiments.metrics.model import Transition, transitions_from_result, trial_outcome
from experiments.report.build import build_report
from experiments.report.pilot import build_pilot, collect_pilot, render_pilot
from experiments.report.render import render_markdown
from experiments.runner import Layout, read_events, read_result
from experiments.scoring.identity import load_identity_table
from experiments.scoring.labels import load_labels
from experiments.scoring.selection import reproducibility_selection


def _env(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"set {name}")
    return Path(value)


def collect(
    layout: Layout,
) -> tuple[
    dict[str, Any],
    dict[str, str],
    list[Transition],
    dict[tuple[str, str], dict[str, str]],
    list[str],
]:
    """The definition, the trial statuses, the transitions, DAIL's S0 results and the record
    paths."""
    definition = read_record(layout.definition_path)
    statuses: dict[str, str] = {}
    transitions: list[Transition] = []
    baselines: dict[tuple[str, str], dict[str, str]] = {}
    refs = [layout.definition_path.relative_to(layout.experiment_dir).as_posix()]
    for trial in definition["trials"]:
        tid = trial["trial_id"]
        events = read_events(layout, tid)
        statuses[tid] = events[-1]["status"] if events else "NOT_STARTED"
        try:
            result = read_result(layout, tid)
        except Exception:
            continue
        attempt = layout.attempt_dir(tid, result["attempt"])
        refs.append((attempt / "result.json").relative_to(layout.experiment_dir).as_posix())
        timing = read_record(attempt / "timing.json")
        transitions += transitions_from_result(result, timing.get("durations_seconds"))
        baseline_file = attempt / "baseline" / "baseline.json"
        if baseline_file.exists():
            stored = read_record(baseline_file)
            results = (stored.get("verification") or {}).get("results") or []
            baselines[(result["scenario_id"], result["condition"])] = {
                r["target_id"].split(":")[1]: r["result"]
                for r in results
                if r["target_id"].startswith("INVARIANT:")
            }
    return definition, statuses, transitions, baselines, refs


def cmd_extract(args: argparse.Namespace) -> int:
    root, tp = _env("DAIL_EXPERIMENT_ROOT"), _env("TERRAPRESERVE_ROOT")
    layout = Layout(root, experiment_id_for(args.name, args.version))
    definition, statuses, transitions, baselines, refs = collect(layout)
    scored = load_labels(tp, {t.scenario_id for t in transitions})
    extraction = extract(
        experiment_id=layout.experiment_id,
        transitions=transitions,
        scored=scored,
        baselines=baselines,
        identity=load_identity_table(),
    )
    extraction.outcomes = [
        {
            "trial_id": t.trial_id,
            "condition": t.condition,
            "scenario_id": t.scenario_id,
            "step": t.step,
            **trial_outcome(t),
        }
        for t in sorted(transitions, key=lambda t: (t.condition, t.scenario_id, t.step))
    ]
    reproducibility = {
        "extractor": (
            f"{EXTRACTOR_VERSION}; a second run of `extract` must write byte-identical records "
            "(it fails otherwise)"
        ),
    }
    if args.repro:
        reproducibility.update(json.loads(Path(args.repro).read_text(encoding="utf-8")))
    report = build_report(
        definition=definition,
        statuses=statuses,
        extraction=extraction,
        reproducibility=reproducibility,
        artifact_refs=refs[:1] + [f"{len(refs) - 1} trial result records under trials/"],
        preface=(
            Path(args.preface).read_text(encoding="utf-8").splitlines() if args.preface else None
        ),
    )
    out = layout.experiment_dir / "report" / EXTRACTOR_VERSION
    out.mkdir(parents=True, exist_ok=True)
    metrics_path = out / "metric_records.json"
    if metrics_path.exists() and metrics_path.read_bytes() != dumps_metrics(extraction):
        raise SystemExit(f"{metrics_path}: the extractor's output differs from the stored records")
    if not metrics_path.exists():
        metrics_path.write_bytes(dumps_metrics(extraction))
    try:
        write_or_same(out / "report.json", report)
    except ArtifactError as changed:
        raise SystemExit(str(changed)) from None
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")
    if args.doc:
        Path(f"{args.doc}.json").write_bytes(dumps(report))
        Path(f"{args.doc}.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")
    print(
        json.dumps(
            {
                "experiment_id": layout.experiment_id,
                "metrics": len(extraction.metrics),
                "report": str(out),
            }
        )
    )
    return 0


def cmd_select(args: argparse.Namespace) -> int:
    root, tp = _env("DAIL_EXPERIMENT_ROOT"), _env("TERRAPRESERVE_ROOT")
    layout = Layout(root, experiment_id_for(args.name, args.version))
    definition = read_record(layout.definition_path)
    scored = load_labels(tp, definition["fixture_set"])
    print(",".join(reproducibility_selection(scored)))
    return 0


def _decisions(layout: Layout) -> dict[tuple[str, str, int], tuple[Any, ...]]:
    definition = read_record(layout.definition_path)
    found: dict[tuple[str, str, int], tuple[Any, ...]] = {}
    for trial in definition["trials"]:
        result = read_result(layout, trial["trial_id"])
        for t in result["transitions"]:
            results = tuple(sorted((w["target_id"], w["result"]) for w in t["work"]))
            decision = None if t["decision"] is None else t["decision"]["type"]
            found[(result["scenario_id"], result["condition"], t["step_index"])] = (
                t["status"],
                decision,
                results,
            )
    return found


def cmd_compare(args: argparse.Namespace) -> int:
    root = _env("DAIL_EXPERIMENT_ROOT")
    one = _decisions(Layout(root, experiment_id_for(args.name, args.version)))
    two = _decisions(Layout(root, experiment_id_for(args.other, args.version)))
    common = sorted(set(one) & set(two))
    decision_diff = [k for k in common if one[k][:2] != two[k][:2]]
    result_diff = [k for k in common if one[k][2] != two[k][2]]
    print(
        json.dumps(
            {
                "common_transitions": len(common),
                "trials": len({(k[0], k[1]) for k in common}),
                "decision_or_status_differences": len(decision_diff),
                "invariant_result_differences": len(result_diff),
                "examples": [list(k) for k in (decision_diff + result_diff)[:10]],
            },
            indent=1,
        )
    )
    return 0 if not decision_diff and not result_diff else 1


def cmd_pilot(args: argparse.Namespace) -> int:
    root = _env("DAIL_EXPERIMENT_ROOT")
    generation_id = name_id("generation", args.name, args.version)
    collected = collect_pilot(root, generation_id, args.replay_name)
    checks = json.loads(Path(args.licence_checks).read_text(encoding="utf-8"))
    report = build_pilot(collected, checks)
    out = root / "candidates" / generation_id / "pilot_report" / args.replay_name
    try:
        write_or_same(out / "pilot.json", report)
    except ArtifactError as changed:
        raise SystemExit(str(changed)) from None
    (out / "pilot.md").write_text(render_pilot(report), encoding="utf-8", newline="\n")
    if args.doc:
        Path(f"{args.doc}.json").write_bytes(dumps(report))
        Path(f"{args.doc}.md").write_text(render_pilot(report), encoding="utf-8", newline="\n")
    print(json.dumps({"generation_id": generation_id, "pilot_report": str(out)}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m experiments.report")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("extract", "select", "compare", "pilot"):
        command = commands.add_parser(name)
        command.add_argument("--name", required=True)
        command.add_argument("--version", default="1")
        if name == "extract":
            command.add_argument("--doc", default="")
            command.add_argument("--repro", default="", help="a JSON file of reproducibility facts")
            command.add_argument("--preface", default="", help="a text file shown at the top")
        if name == "compare":
            command.add_argument("--other", required=True)
        if name == "pilot":
            command.add_argument("--replay-name", required=True)
            command.add_argument("--licence-checks", required=True)
            command.add_argument("--doc", default="")
    args = parser.parse_args(argv)
    handler = {
        "extract": cmd_extract,
        "select": cmd_select,
        "compare": cmd_compare,
        "pilot": cmd_pilot,
    }[args.command]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
