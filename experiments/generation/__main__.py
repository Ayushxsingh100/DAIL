"""The candidate generation command line (P10a; C-218 to C-221).

    python -m experiments.generation generate --name NAME [--version V] --models KEY,...
            [--k K] (--only ID,... | --per-family N [--families F2,F4,F8])
    python -m experiments.generation replay --name NAME [--version V] --replay-name R
            [--conditions A,B,C,C_PRIME]
    python -m experiments.generation export --name NAME [--version V]

``TERRAPRESERVE_ROOT`` and ``DAIL_EXPERIMENT_ROOT`` as for ``python -m experiments`` (C-204): the
checkout at ``terrapreserve-v1.0``, the dev split only (the loader refuses the test split), the
output outside both repositories. Models are the pins of the reviewed
``experiments/config/models.toml``; each is served by the local Ollama server only (C-71, C-218)
and refused unless its installed digest is the pinned one. ``--per-family N`` takes the N lowest
scenario ids of each repair family (F2, F4, F8). Generation is switched on by the reviewed
``experiments/config/llm.toml`` only (``generation_config``).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from experiments.__main__ import CommandError, _environment, _roots
from experiments.definition import Condition
from experiments.generation.export import export_for_oracle
from experiments.generation.models import load_pins
from experiments.generation.replay import replay_candidates
from experiments.generation.run import (
    GenerationSpec,
    generate_candidates,
    generation_config,
)
from experiments.generation.task import REPAIR, GenerationInput, generation_input
from experiments.loader import ScenarioInput, load
from experiments.runner import experiment_config
from llm.adapter.ollama import OllamaProvider

REPAIR_FAMILIES = ("F2", "F4", "F8")


def choose(
    scenarios: Sequence[ScenarioInput],
    *,
    only: Sequence[str] | None,
    per_family: int | None,
    families: Sequence[str],
) -> list[GenerationInput]:
    repairs = [s for s in scenarios if s.target_kind == REPAIR]
    if only:
        by_id = {s.scenario_id: s for s in repairs}
        missing = [sid for sid in only if sid not in by_id]
        if missing:
            raise CommandError(f"not repair scenarios of the dev split: {missing}")
        return [generation_input(by_id[sid]) for sid in sorted(only)]
    if per_family is None:
        raise CommandError("give --only or --per-family")
    chosen: list[GenerationInput] = []
    for family in families:
        mine = sorted((s for s in repairs if s.family == family), key=lambda s: s.scenario_id)
        chosen += [generation_input(s) for s in mine[:per_family]]
    return chosen


def _spec(args: argparse.Namespace) -> GenerationSpec:
    return GenerationSpec(name=args.name, version=args.version)


def cmd_generate(args: argparse.Namespace) -> int:
    terrapreserve, output = _roots()
    environment = _environment(terrapreserve)
    loaded = load(terrapreserve)
    inputs = choose(
        loaded.scenarios,
        only=args.only.split(",") if args.only else None,
        per_family=args.per_family,
        families=args.families.split(","),
    )
    pins = load_pins()
    models = []
    for key in args.models.split(","):
        if key not in pins:
            raise CommandError(f"no pin {key!r} in experiments/config/models.toml")
        pin = pins[key]
        provider = OllamaProvider(expected_digest=pin.digest)
        installed = provider.model_facts(pin.tag)
        models.append((pin, provider, installed))
    environment = {**environment, "ollama_version": models[0][1].server_version()}
    switch = generation_config().get("llm.generation_enabled")
    summary = generate_candidates(
        spec=_spec(args),
        inputs=inputs,
        models=models,
        k=args.k,
        root=output,
        generation_enabled=switch is True,
        environment=environment,
    )
    counts: dict[str, dict[str, int]] = {}
    for row in summary.attempts:
        mine = counts.setdefault(row["model_key"], {})
        key = row["status"] if row["failure_class"] is None else row["failure_class"]
        mine[key] = mine.get(key, 0) + 1
    print(
        json.dumps(
            {
                "generation_id": summary.generation_id,
                "candidates_manifest": str(summary.manifest_path),
                "candidates_manifest_sha256": summary.manifest_sha256,
                "attempts": counts,
            },
            indent=1,
        )
    )
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    terrapreserve, output = _roots()
    loaded = load(terrapreserve)
    summary = replay_candidates(
        root=output,
        generation_id=_spec(args).generation_id,
        scenarios={s.scenario_id: s for s in loaded.scenarios},
        conditions=[Condition(c).value for c in args.conditions.split(",")],
        config=experiment_config(),
        replay_name=args.replay_name,
    )
    decisions: dict[str, dict[str, int]] = {}
    for result in summary.results:
        mine = decisions.setdefault(result["condition"], {})
        key = result["decision"] or "NO DECISION"
        mine[key] = mine.get(key, 0) + 1
    print(
        json.dumps(
            {
                "replay": str(summary.path),
                "decisions": decisions,
                "generation_failures": len(summary.generation_failures),
            },
            indent=1,
        )
    )
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    terrapreserve, output = _roots()
    loaded = load(terrapreserve)
    inputs = [generation_input(s) for s in loaded.scenarios if s.target_kind == REPAIR]
    path = export_for_oracle(root=output, generation_id=_spec(args).generation_id, inputs=inputs)
    print(str(path))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m experiments.generation")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("generate", "replay", "export"):
        command = sub.add_parser(name)
        command.add_argument("--name", required=True)
        command.add_argument("--version", default="1")
        if name == "generate":
            command.add_argument("--models", required=True)
            command.add_argument("--k", type=int, default=1)
            command.add_argument("--only")
            command.add_argument("--per-family", type=int)
            command.add_argument("--families", default=",".join(REPAIR_FAMILIES))
        if name == "replay":
            command.add_argument("--replay-name", required=True)
            command.add_argument("--conditions", default="A,B,C,C_PRIME")
    args = parser.parse_args(argv)
    handler: Any = {"generate": cmd_generate, "replay": cmd_replay, "export": cmd_export}
    try:
        return int(handler[args.command](args))
    except CommandError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
