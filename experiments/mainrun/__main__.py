"""The main-run command (P10e-prep; C-246 to C-250; protocol §9). Run only on the commit tagged
``protocol-v1``, with a clean tree.

    python -m experiments.mainrun reference [--resume] [--workers N]
    python -m experiments.mainrun generate [--resume]
    python -m experiments.mainrun analyse

``TERRAPRESERVE_ROOT`` (the public checkout at ``terrapreserve-v1.0``), ``TERRAPRESERVE_PRIVATE``
(the private package: the test split) and ``DAIL_EXPERIMENT_ROOT`` (outside both repositories);
``generate`` also needs the local Ollama server with the pinned models, Terraform on PATH and
``DAIL_TERRAFORM_MIRROR`` (C-227).

1. ``reference``: the power preflight; the test split through the guard; the lock (or, with
   ``--resume``, the locked experiment); the 96 test targets under A, B, C and C' (P8a's runner:
   an interrupted trial is re-run as a new attempt, nothing is overwritten); the power monitor
   writes ``main-run.interruptions.jsonl`` beside the lock.
2. ``generate``: the preflight; the 36 test repair scenarios, the three ``-sample`` pins, k = 3
   (C-224, C-225); then the validate gate (``gate-1``), the replay under A, B, C and C'
   (``replay-1``) and the export for the oracle. Each part whose output exists is skipped (each is
   written once); an interrupted generation attempt is refused by the generation code, as in P10a.
3. Stop: TerraPreserve labels the exported candidates (TP-L2) into
   ``$TERRAPRESERVE_PRIVATE/llm_candidates/test/<generation id>/`` (C-252 (3)).
4. ``analyse``: once; the order of ``experiments.mainrun.unblind``; every result is written once
   under ``<experiment>/analysis/main-run-<extractor version>-<analysis version>/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from experiments.__main__ import CommandError, _environment, _roots
from experiments.artifacts import Layout, write_record
from experiments.definition import Condition, ExperimentSpec
from experiments.loader import LoadedSet, LoaderError, load_test
from experiments.mainrun.lock import LockError
from experiments.mainrun.order import OrderError
from experiments.mainrun.power import PowerMonitor, PreflightError, preflight, utc_now
from experiments.mainrun.run import (
    EXPERIMENT_NAME,
    EXPERIMENT_VERSION,
    GATE_NAME,
    GENERATION_ID,
    GENERATION_NAME,
    GENERATION_VERSION,
    REPLAY_NAME,
    MainRun,
)
from experiments.split_guard import MAIN_RUN_COMMAND, PROTOCOL_TAG, REPO_ROOT, tp_l2_dir

MODEL_KEYS: Final = (
    "model-granite-3.3-8b-sample",
    "model-phi4-mini-3.8b-sample",
    "model-qwen2.5-coder-7b-sample",
)
K: Final = 3
CONDITIONS: Final = ("A", "B", "C", "C_PRIME")
INTERRUPTIONS: Final = "main-run.interruptions.jsonl"
PROTOCOL_PATH: Final = "docs/PROTOCOL_v1.md"


def _git(*args: str) -> bytes:
    done = subprocess.run(["git", "-C", str(REPO_ROOT), *args], capture_output=True, check=False)
    if done.returncode != 0:
        raise CommandError(f"git {' '.join(args)} failed: {done.stderr.decode(errors='replace')}")
    return done.stdout


def _private() -> Path:
    value = os.environ.get("TERRAPRESERVE_PRIVATE")
    if not value:
        raise CommandError("set TERRAPRESERVE_PRIVATE")
    return Path(value).resolve()


def _main_run(output: Path) -> MainRun:
    commit = _git("rev-parse", "HEAD").decode().strip()
    protocol = hashlib.sha256(_git("show", f"HEAD:{PROTOCOL_PATH}")).hexdigest()
    return MainRun(root=output, dail_commit=commit, protocol_sha256=protocol, clock=utc_now)


def _test_split() -> LoadedSet:
    return load_test(_private(), command=MAIN_RUN_COMMAND)


def _preflight() -> None:
    print(json.dumps({"power_preflight_ac": preflight()}))


def _monitored(output: Path, work: Any) -> Any:
    monitor = PowerMonitor(output / INTERRUPTIONS, since=utc_now())
    monitor.start()
    try:
        return work()
    finally:
        monitor.stop()
        print(json.dumps({"interruptions": monitor.interruptions(), "file": str(monitor.path)}))


def cmd_reference(args: argparse.Namespace) -> int:
    from experiments.runner import plan, run_experiment

    terrapreserve, output = _roots()
    _preflight()
    loaded = _test_split()
    environment = _environment(terrapreserve)
    spec = ExperimentSpec(
        name=EXPERIMENT_NAME,
        version=EXPERIMENT_VERSION,
        protocol_version=PROTOCOL_TAG,
        objective="The main run of experiment protocol v1 on the TerraPreserve v1.0 test targets",
        hypotheses=("H1", "H2", "H3 (exploratory)", "H4 (descriptive)"),
        conditions=tuple(Condition(c) for c in CONDITIONS),
    )

    def step(experiment_id: str) -> None:
        experiment = plan(
            spec, loaded, environment=environment, created_at=datetime.now(UTC), only=None
        )
        if experiment.experiment_id != experiment_id:
            raise CommandError("the planned experiment is not the locked one")
        summary = _monitored(
            output, lambda: run_experiment(experiment, loaded, output, workers=args.workers)
        )
        for trial_id, message in summary.failures.items():
            print(f"FAILED {trial_id}: {message}")

    _main_run(output).reference(step, resume=args.resume)
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    from experiments.generation.__main__ import terraform_runner
    from experiments.generation.export import export_for_oracle
    from experiments.generation.models import load_pins
    from experiments.generation.readmit import readmit
    from experiments.generation.replay import replay_candidates
    from experiments.generation.run import GenerationSpec, generate_candidates, generation_config
    from experiments.generation.task import REPAIR, generation_input
    from experiments.runner import experiment_config
    from llm.adapter.ollama import OllamaProvider

    terrapreserve, output = _roots()
    _preflight()
    loaded = _test_split()
    environment = _environment(terrapreserve)
    inputs = [generation_input(s) for s in loaded.scenarios if s.target_kind == REPAIR]
    base = output / "candidates" / GENERATION_ID

    def step(experiment_id: str) -> None:
        del experiment_id
        terraform = terraform_runner(output)
        if not (base / "candidates_manifest.json").exists():
            pins = load_pins()
            models = []
            for key in MODEL_KEYS:
                pin = pins[key]
                provider = OllamaProvider(expected_digest=pin.digest)
                models.append((pin, provider, provider.model_facts(pin.tag)))
            env = {**environment, "ollama_version": models[0][1].server_version()}
            _monitored(
                output,
                lambda: generate_candidates(
                    spec=GenerationSpec(name=GENERATION_NAME, version=GENERATION_VERSION),
                    inputs=inputs,
                    models=models,
                    k=K,
                    root=output,
                    generation_enabled=generation_config().get("llm.generation_enabled") is True,
                    environment=env,
                    terraform=terraform,
                ),
            )
        if not (base / "validate_gate" / GATE_NAME).exists():
            readmit(
                root=output,
                generation_id=GENERATION_ID,
                inputs={g.scenario_id: g for g in inputs},
                terraform=terraform,
                name=GATE_NAME,
            )
        if not (base / "replay" / REPLAY_NAME).exists():
            replay_candidates(
                root=output,
                generation_id=GENERATION_ID,
                scenarios={s.scenario_id: s for s in loaded.scenarios},
                conditions=CONDITIONS,
                config=experiment_config(),
                replay_name=REPLAY_NAME,
            )
        if not (base / "oracle_export" / "oracle_export.json").exists():
            print(export_for_oracle(root=output, generation_id=GENERATION_ID, inputs=inputs))

    _main_run(output).generation(step, resume=args.resume)
    return 0


def cmd_analyse(args: argparse.Namespace) -> int:
    del args
    from experiments.mainrun.unblind import unblind
    from experiments.metrics.extractor import EXTRACTOR_VERSION, extract, to_json
    from experiments.report.__main__ import collect
    from experiments.scoring.identity import load_identity_table
    from experiments.scoring.labels import load_test_labels
    from experiments.scoring.llm_pilot import main_run_candidate_rows
    from experiments.stats.dry_run import ANALYSIS_VERSION

    _, output = _roots()
    private = _private()
    frozen = json.loads((REPO_ROOT / "docs" / "PROTOCOL_v1.json").read_text(encoding="utf-8"))
    rho = float(frozen["pre_freeze"]["rho_analysis"])
    dry = json.loads((REPO_ROOT / "docs" / "P10D_DEV_DRY_RUN.json").read_text(encoding="utf-8"))
    dev_sizes = {k: v for k, v in dry["coverage"]["configs"].items() if k.endswith("/dev")}
    files = {GENERATION_ID: tp_l2_dir(private, GENERATION_ID) / "labels.json"}

    def step(experiment_id: str) -> None:
        layout = Layout(output, experiment_id)
        out = (
            layout.experiment_dir / "analysis" / f"main-run-{EXTRACTOR_VERSION}-{ANALYSIS_VERSION}"
        )
        scored = load_test_labels(private, command=MAIN_RUN_COMMAND)

        def read_outcomes() -> Any:
            _, _, transitions, baselines, _ = collect(layout)
            extraction = extract(
                experiment_id=experiment_id,
                transitions=transitions,
                scored={t.scenario_id: scored[t.scenario_id] for t in transitions},
                baselines=baselines,
                identity=load_identity_table(),
            )
            found = json.loads(json.dumps(to_json(extraction)))
            write_record(out / "extraction.json", found)
            return found

        def read_adjudication() -> Any:
            path = layout.experiment_dir / "adjudication.json"
            if not path.is_file():
                return {"present": False}
            return {"present": True, "content": json.loads(path.read_text(encoding="utf-8"))}

        unblind(
            scored,
            read_outcomes=read_outcomes,
            read_adjudication=read_adjudication,
            read_llm_rows=lambda: main_run_candidate_rows(
                root=output,
                generations=[GENERATION_ID],
                private_root=private,
                gate_name=GATE_NAME,
                replay_name=REPLAY_NAME,
                command=MAIN_RUN_COMMAND,
            ),
            dev_sizes=dev_sizes,
            rho=rho,
            write=lambda name, value: write_record(out / f"{name}.json", value),
        )
        print(json.dumps({"analysis": str(out)}))

    _main_run(output).analysis(step, truth_files=files)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m experiments.mainrun")
    commands = parser.add_subparsers(dest="command", required=True)
    reference = commands.add_parser("reference")
    reference.add_argument("--resume", action="store_true")
    reference.add_argument("--workers", type=int, default=1)
    generate = commands.add_parser("generate")
    generate.add_argument("--resume", action="store_true")
    commands.add_parser("analyse")
    args = parser.parse_args(argv)
    handler = {"reference": cmd_reference, "generate": cmd_generate, "analyse": cmd_analyse}
    try:
        return int(handler[args.command](args))
    except (CommandError, LoaderError, LockError, OrderError, PreflightError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
