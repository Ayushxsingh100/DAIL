"""The experiment harness command line (P8a; C-204).

    python -m experiments run --name NAME [--version V] [--protocol-version draft]
                              [--conditions A,B,C,C_PRIME] [--only ID,...] [--workers N]
    python -m experiments summary --name NAME [--version V]

``TERRAPRESERVE_ROOT`` names a TerraPreserve checkout, read only; it must be at tag
``terrapreserve-v1.0`` (checked with ``git describe``) and its manifest must have the pinned hash.
``DAIL_EXPERIMENT_ROOT`` is where output goes; it must be outside this repository and outside the
TerraPreserve checkout, and it is never committed. The test split is never read.

``summary`` prints counts read from the stored records, never a label: trials by status, decisions
per condition and family, transitions evaluated and TRUNCATED per condition, transitions with an
open target, work counts per condition, harness and input failures, and wall time.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from experiments.artifacts import read_record
from experiments.definition import Condition, ExperimentSpec, experiment_id_for
from experiments.loader import TERRAPRESERVE_TAG, load
from experiments.runner import REPO_ROOT, Layout, plan, read_events, read_result, run_experiment


class CommandError(Exception):
    pass


def _env_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise CommandError(f"set {name}")
    return Path(value).resolve()


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _git(root: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    if done.returncode != 0:
        raise CommandError(f"git {' '.join(args)} failed in {root}: {done.stderr.strip()}")
    return done.stdout.strip()


def _roots() -> tuple[Path, Path]:
    terrapreserve = _env_path("TERRAPRESERVE_ROOT")
    output = _env_path("DAIL_EXPERIMENT_ROOT")
    for root in (REPO_ROOT.resolve(), terrapreserve):
        if _inside(output, root):
            raise CommandError(f"DAIL_EXPERIMENT_ROOT must be outside {root}")
    return terrapreserve, output


def _environment(terrapreserve: Path) -> dict[str, str]:
    tag = _git(terrapreserve, "describe", "--tags", "--exact-match")
    if tag != TERRAPRESERVE_TAG:
        raise CommandError(f"TerraPreserve is at {tag!r}, not {TERRAPRESERVE_TAG}")
    return {
        "dail_commit": _git(REPO_ROOT, "rev-parse", "HEAD"),
        "dail_worktree_clean": str(_git(REPO_ROOT, "status", "--porcelain") == "").lower(),
        "terrapreserve_tag": tag,
        "terrapreserve_commit": _git(terrapreserve, "rev-parse", "HEAD"),
    }


def _spec(args: argparse.Namespace) -> ExperimentSpec:
    return ExperimentSpec(
        name=args.name,
        version=args.version,
        protocol_version=args.protocol_version,
        objective="P8a harness check on the TerraPreserve v1.0 dev targets (no result is claimed)",
        hypotheses=("none: a harness check, not an experiment result",),
        conditions=tuple(Condition(c) for c in args.conditions.split(",")),
    )


def cmd_run(args: argparse.Namespace) -> int:
    terrapreserve, output = _roots()
    environment = _environment(terrapreserve)
    loaded = load(terrapreserve)
    only = None if not args.only else args.only.split(",")
    experiment = plan(
        _spec(args), loaded, environment=environment, created_at=datetime.now(UTC), only=only
    )
    summary = run_experiment(experiment, loaded, output, workers=args.workers)
    counts = Counter(s.value for s in summary.statuses.values())
    print(json.dumps({"experiment_id": experiment.experiment_id, "statuses": counts}, indent=1))
    for trial_id, message in summary.failures.items():
        print(f"FAILED {trial_id}: {message}")
    return 0 if not summary.failures else 1


def summarize(layout: Layout) -> dict[str, Any]:
    """Counts from the stored records of an experiment (no label is read)."""
    definition = read_record(layout.definition_path)
    trials = definition["trials"]
    statuses: Counter[str] = Counter()
    decisions: dict[str, Counter[str]] = defaultdict(Counter)
    transitions: dict[str, Counter[str]] = defaultdict(Counter)
    work: dict[str, Counter[str]] = defaultdict(Counter)
    opened: Counter[str] = Counter()
    failures: list[dict[str, Any]] = []
    wall = 0.0
    for trial in trials:
        tid, condition = trial["trial_id"], trial["condition"]
        events = read_events(layout, tid)
        statuses[events[-1]["status"] if events else "NOT_STARTED"] += 1
        try:
            result = read_result(layout, tid)
        except Exception:  # not run yet
            continue
        attempt = layout.attempt_dir(tid, result["attempt"])
        timing = read_record(attempt / "timing.json")
        wall += float(timing["durations_seconds"]["total"])
        if result["failure"] is not None:
            failures.append(
                {"trial_id": tid, "scenario_id": result["scenario_id"], **result["failure"]}
            )
        if result["baseline"] is not None and result["baseline"]["outcome"] == "REFUSED":
            decisions[f"{condition}|{result['family']}"]["BASELINE_REFUSED"] += 1
        for t in result["transitions"]:
            transitions[condition][t["status"]] += 1
            if t["status"] != "EVALUATED":
                continue
            decisions[f"{condition}|{result['family']}"][t["decision"]["type"]] += 1
            if t["open_targets"]:
                opened[condition] += 1
            for key, value in t["work_counts"].items():
                work[condition][key] += value
    return {
        "experiment_id": layout.experiment_id,
        "trials": len(trials),
        "trials_by_status": dict(statuses),
        "decisions_by_condition_and_family": {k: dict(v) for k, v in sorted(decisions.items())},
        "transitions_by_condition": {k: dict(v) for k, v in sorted(transitions.items())},
        "open_target_transitions_by_condition": dict(sorted(opened.items())),
        "work_counts_by_condition": {k: dict(v) for k, v in sorted(work.items())},
        "failures": failures,
        "trial_wall_time_seconds_sum": round(wall, 1),
    }


def cmd_summary(args: argparse.Namespace) -> int:
    output = _env_path("DAIL_EXPERIMENT_ROOT")
    layout = Layout(output, experiment_id_for(args.name, args.version))
    print(json.dumps(summarize(layout), indent=1, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m experiments")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "summary"):
        command = commands.add_parser(name)
        command.add_argument("--name", required=True)
        command.add_argument("--version", default="1")
        if name == "run":
            command.add_argument("--protocol-version", default="draft")
            command.add_argument("--conditions", default="A,B,C,C_PRIME")
            command.add_argument("--only", default="")
            command.add_argument("--workers", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        return cmd_run(args) if args.command == "run" else cmd_summary(args)
    except CommandError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
