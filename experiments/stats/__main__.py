"""The statistics command line (P10d Step 4).

    python -m experiments.stats dry-run --name p8b-dev-run-3 [--version 1]
        --generations p10a-dev-pilot,p10b-run-a,p10b-run-b --tp-commit <TerraPreserve commit>
        --gate-name gate-1 [--replay-name replay-1] [--doc docs/P10D_DEV_DRY_RUN]

Reads the stored records of the reference-track experiment under ``$DAIL_EXPERIMENT_ROOT`` and
the dev labels under ``$TERRAPRESERVE_ROOT`` (through ``experiments.scoring``), extracts the
``metrics-final-1`` records, reads the LLM candidate rows (TP-L1 labels at ``--tp-commit``), runs
``experiments.stats.dry_run`` and writes ``analysis/<extractor version>-<analysis version>/
dry_run.json`` once (a second run must give byte-identical output, or it fails) and its Markdown;
with ``--doc`` also ``<doc>.json`` and ``<doc>.md``. Dev only: the loader refuses the test split.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from experiments.artifacts import ArtifactError, dumps, write_or_same
from experiments.definition import experiment_id_for, name_id
from experiments.metrics.extractor import EXTRACTOR_VERSION, extract, to_json
from experiments.report.__main__ import collect
from experiments.runner import Layout
from experiments.scoring.identity import load_identity_table
from experiments.scoring.labels import load_labels
from experiments.scoring.llm_pilot import candidate_rows
from experiments.stats.dry_run import ANALYSIS_VERSION, dry_run
from experiments.stats.render import render


def _env(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"set {name}")
    return Path(value)


def cmd_dry_run(args: argparse.Namespace) -> int:
    root, tp = _env("DAIL_EXPERIMENT_ROOT"), _env("TERRAPRESERVE_ROOT")
    layout = Layout(root, experiment_id_for(args.name, args.version))
    _, _, transitions, baselines, _ = collect(layout)
    scored = load_labels(tp, {t.scenario_id for t in transitions})
    extraction = extract(
        experiment_id=layout.experiment_id,
        transitions=transitions,
        scored=scored,
        baselines=baselines,
        identity=load_identity_table(),
    )
    rows = candidate_rows(
        root=root,
        generations=[name_id("generation", n, "1") for n in args.generations.split(",")],
        tp_root=tp,
        tp_commit=args.tp_commit,
        gate_name=args.gate_name,
        replay_name=args.replay_name,
    )
    report = dry_run(json.loads(json.dumps(to_json(extraction))), rows)
    report["tp_commit"] = args.tp_commit
    out = layout.experiment_dir / "analysis" / f"{EXTRACTOR_VERSION}-{ANALYSIS_VERSION}"
    try:
        write_or_same(out / "dry_run.json", report)
    except ArtifactError as changed:
        raise SystemExit(str(changed)) from None
    (out / "dry_run.md").write_text(render(report), encoding="utf-8", newline="\n")
    if args.doc:
        Path(f"{args.doc}.json").write_bytes(dumps(report))
        Path(f"{args.doc}.md").write_text(render(report), encoding="utf-8", newline="\n")
    print(json.dumps({"dry_run": str(out)}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m experiments.stats")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("dry-run")
    command.add_argument("--name", required=True)
    command.add_argument("--version", default="1")
    for flag in ("--generations", "--tp-commit", "--gate-name"):
        command.add_argument(flag, required=True)
    command.add_argument("--replay-name", default="replay-1")
    command.add_argument("--doc", default="")
    args = parser.parse_args(argv)
    return {"dry-run": cmd_dry_run}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
