"""Replay frozen LLM candidates under A, B, C and C' (P10a Section 3.3 "Replay"; P7b verdict limit
5).

"A frozen valid patch is evaluated as a one-step candidate from S0 under A, B, C and C' through
``LLMEvaluationRequest``. The directory is rebuilt by the validator from the frozen patch in the
same call, then deleted (P7b limit 5). Each run checks that the rebuilt tree hash equals the frozen
one. Invalid attempts are recorded as generation failures, never as decisions."

For one candidate and one condition: a fresh store and lineage, S0 through the harness's baseline
flow for that condition (``experiments.trial``, C-198, C-202, C-203) from the scenario's first step
only; the frozen reply is parsed again (P7's parser) and the patch validator rebuilds the candidate
from the configuration-only copy of S0 with the decision-5 scope of that condition's S0; the rebuilt
tree hash is compared with the frozen one. Only when they are equal is the candidate evaluated, by
the condition's ``EvaluationOrchestrator`` with an ``LLMEvaluationRequest`` (no open target: one
step). The build is deleted in the same call, whatever happened. A mismatch, or a rebuild the
validator refuses, is recorded with no decision.

Output, written once under ``<root>/candidates/<generation_id>/replay/<replay_name>/``:
``<model>/<scenario_id>/<k>/<condition>/`` with the attempt's store and records, and
``replay.json`` listing every result and every generation failure.
"""

from __future__ import annotations

import dataclasses
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.application.orchestrator import EvaluationOrchestrator, LLMEvaluationRequest
from core.domain.repositories import UnitOfWork
from core.persistence.schema import initialize_database
from core.persistence.sqlite import SqliteUnitOfWork
from experiments import records
from experiments.artifacts import ATTEMPT_DIRS, read_record, write_record
from experiments.conditions import setup_for
from experiments.definition import Condition, name_id
from experiments.generation.parent import config_only_copy
from experiments.generation.run import (
    attempt_dir,
    frozen_response_text,
    generation_dir,
    read_manifest,
)
from experiments.generation.task import GenerationError, change_scope, scope_record
from experiments.loader import D6_VALIDATE_EVIDENCE, ScenarioInput
from experiments.trial import DAIL_CLOCK_BASE, STORE_NAME, TrialInputs, _Attempt
from llm.validation.parser import parse_response
from llm.validation.patch import PatchValidator


@dataclass(frozen=True)
class ReplaySummary:
    path: Path
    results: list[dict[str, Any]]
    generation_failures: list[dict[str, Any]]


def s0_only(scenario: ScenarioInput) -> ScenarioInput:
    """The scenario with its first step only: replay never opens a later step."""
    return dataclasses.replace(scenario, steps=scenario.steps[:1])


def _replay_one(
    *,
    generation_id: str,
    replay_name: str,
    row: Mapping[str, Any],
    frozen: Mapping[str, Any],
    reply: str,
    request_id: str,
    scenario: ScenarioInput,
    condition: Condition,
    folder: Path,
    config: Any,
) -> dict[str, Any]:
    trial_id = name_id(
        "p10a-replay", generation_id, replay_name, row["model_key"], row["scenario_id"],
        row["k"], condition.value,
    )  # fmt: skip
    inputs = TrialInputs(
        trial_id=trial_id,
        experiment_id=generation_id,
        scenario=scenario,
        condition=condition,
        repetition=int(row["k"]),
        attempt=1,
        admission_evidence=D6_VALIDATE_EVIDENCE,
    )
    attempt = _Attempt(inputs, folder, config, None)
    setup = setup_for(condition, scenario, DAIL_CLOCK_BASE)
    for name in ATTEMPT_DIRS:
        (folder / name).mkdir(parents=True, exist_ok=True)
    store = folder / "store" / STORE_NAME
    store.parent.mkdir(parents=True, exist_ok=True)
    initialize_database(store)

    def factory() -> UnitOfWork:
        return SqliteUnitOfWork(store)

    trial: dict[str, Any] = {}
    parent = attempt._baseline(factory, setup, trial)
    result: dict[str, Any] = {
        "record": "llm_candidate_replay",
        "generation_id": generation_id,
        "replay_name": replay_name,
        "trial_id": trial_id,
        "condition": condition.value,
        "model_key": row["model_key"],
        "scenario_id": row["scenario_id"],
        "family": row["family"],
        "k": row["k"],
        "versions": setup.versions(),
        "baseline": trial.get("baseline"),
        "frozen_tree_hash": frozen["candidate_tree_hash"],
        "rebuilt_tree_hash": None,
        "tree_hash_matches": False,
        "scope": None,
        "scope_matches_frozen": False,
        "rebuild_failure": None,
        "decision": None,
        "result_kind": None,
        "build_dir": None,
        "transition": None,
    }
    if parent is None:
        result["rebuild_failure"] = "the condition's S0 baseline was refused"
        return result
    scope = change_scope(parent.resources)
    result["scope"] = scope_record(scope)
    result["scope_matches_frozen"] = result["scope"] == frozen["scope"]
    parsed = parse_response(reply)
    if parsed.response is None or parsed.failure_class is not None:
        result["rebuild_failure"] = f"the frozen reply does not parse: {list(parsed.errors)}"
        return result
    with tempfile.TemporaryDirectory(prefix="dail-p10a-replay-") as tmp:
        work = Path(tmp)
        validator = PatchValidator(
            parent_dir=config_only_copy(scenario.steps[0].directory, work / "s0"),
            trusted=parent,
            scope=scope,
            work_root=work / "builds",
            variables=dict(scenario.variable_values),
            now=attempt.clock(),
        )
        outcome = validator.validate(
            parsed.response, request_id=request_id, patch_id=attempt.id("patch", 1)
        )
        build = outcome.build
        if build is None:
            result["rebuild_failure"] = (
                f"{None if outcome.failure_class is None else outcome.failure_class.value}: "
                f"{list(outcome.errors)}"
            )
            return result
        result["build_dir"] = str(build.candidate_dir)
        result["rebuilt_tree_hash"] = build.tree_hash
        result["tree_hash_matches"] = build.tree_hash == frozen["candidate_tree_hash"]
        try:
            if not result["tree_hash_matches"] or not result["scope_matches_frozen"]:
                return result
            orchestrator = EvaluationOrchestrator(
                factory,
                config=config,
                scope_policy=setup.scope_policy,
                clock=attempt.clock,
                policy_version=setup.policy_version,
                policy_factory=setup.policy_factory,
                identity_strategy=setup.identity_strategy,
            )
            request = LLMEvaluationRequest(
                lineage_id=attempt.lineage_id,
                candidate_id=attempt.id("candidate", 1),
                candidate_sequence=1,
                attempt_number=1,
                patch=build.patch,
                candidate_dir=build.candidate_dir,
                variables=dict(scenario.variable_values),
                definitions=setup.definitions,
                bindings=setup.bindings,
                context=attempt.context(1),
                built_tree_hash=build.tree_hash,
            )
            evaluated = orchestrator.evaluate(request)
        finally:
            shutil.rmtree(build.candidate_dir.parent, ignore_errors=True)
    admission = {
        "step": 1,
        "llm_candidate": f"{row['model_key']}/{row['scenario_id']}/{row['k']}",
        "patch_sha256": frozen["patch_sha256"],
        "tree_hash": result["rebuilt_tree_hash"],
        "tree_hash_matches_frozen": True,
    }
    transition = records.transition_record(
        base=attempt.base,
        step=1,
        admission=admission,
        parent=parent,
        open_targets=(),
        result=evaluated,
    )
    result["transition"] = transition
    result["result_kind"] = evaluated.kind.value
    result["decision"] = None if evaluated.decision is None else evaluated.decision.decision.value
    return result


def replay_candidates(
    *,
    root: Path,
    generation_id: str,
    scenarios: Mapping[str, ScenarioInput],
    conditions: Sequence[str],
    config: Any,
    replay_name: str,
) -> ReplaySummary:
    """Replay every valid frozen candidate of ``generation_id`` (see the module docstring)."""
    manifest = read_manifest(root, generation_id)
    base = generation_dir(root, generation_id)
    out = base / "replay" / replay_name
    if out.exists():
        raise GenerationError(f"{out} exists; a replay is written once")
    out.mkdir(parents=True)
    chosen = [Condition(c) for c in conditions]
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for row in manifest["attempts"]:
        if row["status"] != "PATCH":
            failures.append(
                {
                    key: row[key]
                    for key in ("model_key", "scenario_id", "k", "status", "failure_class")
                }
                | {"failure_source": row["failure_source"]}
            )
            continue
        scenario = scenarios.get(row["scenario_id"])
        if scenario is None:
            raise GenerationError(f"{row['scenario_id']}: not in the loaded scenarios")
        folder = attempt_dir(base, row["model_key"], row["scenario_id"], int(row["k"]))
        frozen = read_record(folder / "attempt.json")
        reply, request_id = frozen_response_text(folder, frozen)
        for condition in chosen:
            target = out / row["model_key"] / row["scenario_id"] / str(row["k"]) / condition.value
            result = _replay_one(
                generation_id=generation_id,
                replay_name=replay_name,
                row=row,
                frozen=frozen,
                reply=reply,
                request_id=request_id,
                scenario=s0_only(scenario),
                condition=condition,
                folder=target,
                config=config,
            )
            write_record(target / "result.json", result)
            results.append(result)
    path = write_record(
        out / "replay.json",
        {
            "record": "llm_candidate_replay_set",
            "generation_id": generation_id,
            "replay_name": replay_name,
            "conditions": [c.value for c in chosen],
            "results": [
                {k: v for k, v in r.items() if k not in ("transition", "baseline")} for r in results
            ],
            "generation_failures": failures,
        },
    )
    return ReplaySummary(path, results, failures)
