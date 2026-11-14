"""Generate and freeze LLM candidates (P10a Section 3.3 "Generation" and "Freezing"; C-218 to
C-220).

For each scenario (a ``GenerationInput``: S0 only) the parent is built once (``parent.s0_parent``);
then, for each pinned model and each repetition ``k``, one ``Generator.generate`` call through
``llm/adapter/generate.py`` (prompt ``dail-repair-prompt-2``, parser 2, validator 2), so every
request and response record, retry and failure class is P7's. The context is P7's ``build_context``
with the target invariant as the repair target, the focus of ``task.focus_for`` and the scope of
decision 5; the objective is the fixed task of decision 4.

**Switch.** ``generation_enabled`` is the caller's; the command line takes it from
``generation_config()``, the repository configuration with the reviewed
``experiments/config/llm.toml`` in place of ``config/base/llm.toml``, loaded for the ``experiment``
environment with no environment variable (as C-207 (3) does for promotion). ``config/`` keeps it
off.

**Model check.** Before anything is written, every model's installed facts are checked against its
pin (``models.check_installed``): one refusal stops the run.

**Freezing (layout)**, under ``<root>/candidates/<generation_id>/``::

    definition.json                    what was asked (write once; a changed request is refused)
    <model>/model.json                 the pin and the installed facts
    <model>/<scenario_id>/<k>/
        records/request-<n>.json       P7's LLMRequest of attempt n
        records/response-<n>.json      P7's LLMResponse of attempt n (raw reply redacted, §33)
        patch.tf                       the patch text of a valid candidate (PATCH) only
        timing.json                    wall-clock time of the call
        attempt.json                   status, failure class and its source, validator outcome,
                                       parent, scope, context and prompt hashes, written last
    candidates_manifest.json           every attempt with the SHA-256 of each of its files

Every file is written once (``experiments.artifacts.write_record``); an attempt directory without
its ``attempt.json`` (an interrupted call) is never overwritten or completed, and a generation whose
manifest exists is frozen: it is never regenerated or edited. A REGENERATE (Doc 13 §47) is a new
``generation_id`` (a new name or version).

**Failure source.** A failed attempt's class comes from the provider when the provider gave no reply
(``raw_response`` is null: a connection failure, a timeout, Ollama's 400/404 as UNSUPPORTED), from
the budget for CONTEXT_INSUFFICIENT (no call was made), and from the model otherwise (the parser or
the validator refused its reply). P7a verdict limit 4: provider UNSUPPORTED is kept apart.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from core.application.config import ResolvedConfig, load_config
from experiments.artifacts import ArtifactError, read_record, write_or_same, write_record
from experiments.definition import name_id
from experiments.generation.models import (
    RETRY_POLICY,
    ModelPin,
    budget_for,
    check_installed,
    llm_config,
    seed_for,
)
from experiments.generation.parent import Parent, s0_parent
from experiments.generation.task import (
    TASK_TEMPLATE,
    GenerationError,
    GenerationInput,
    change_scope,
    config_address,
    focus_for,
    objective_for,
    scope_record,
)
from experiments.trial import DAIL_CLOCK_BASE
from llm.adapter.context import CONTEXT_VERSION, ContextInputs, LLMContext, build_context
from llm.adapter.generate import Generator
from llm.adapter.provider import LLMProvider
from llm.prompts.templates import PROMPT_VERSION, template_hash
from llm.schemas.records import FailureClass, GenerationResult, GenerationStatus
from llm.validation.parser import PARSER_VERSION
from llm.validation.patch import VALIDATOR_VERSION, PatchValidator

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
EXPERIMENT_LLM_FILE: Final = REPO_ROOT / "experiments" / "config" / "llm.toml"
MANIFEST: Final = "candidates_manifest.json"
SCOPE_RULE: Final = (
    "decision 5 (C-220): every resource address of S0, every supported type, no attribute "
    "restriction, all four operations; the same for every condition"
)
ModelEntry = tuple[ModelPin, LLMProvider, Mapping[str, Any]]

__all__ = [
    "EXPERIMENT_LLM_FILE",
    "GenerationError",
    "GenerationSpec",
    "GenerationSummary",
    "generate_candidates",
    "generation_config",
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generation_config() -> ResolvedConfig:
    """The repository configuration with the reviewed ``experiments/config/llm.toml`` in place of
    ``config/base/llm.toml``; refuses to start if generation is not on there."""
    with tempfile.TemporaryDirectory(prefix="dail-generation-config-") as tmp:
        root = Path(tmp) / "config"
        shutil.copytree(REPO_ROOT / "config", root)
        shutil.copyfile(EXPERIMENT_LLM_FILE, root / "base" / "llm.toml")
        config = load_config(root, "experiment", environ={})
    if config.get("llm.generation_enabled") is not True:
        raise GenerationError("the generation configuration must enable llm.generation_enabled")
    return config


@dataclass(frozen=True)
class GenerationSpec:
    name: str
    version: str

    @property
    def generation_id(self) -> str:
        return name_id("generation", self.name, self.version)


@dataclass(frozen=True)
class GenerationSummary:
    generation_id: str
    manifest_path: Path
    manifest_sha256: str
    attempts: list[dict[str, Any]]


def generation_dir(root: Path, generation_id: str) -> Path:
    return Path(root) / "candidates" / generation_id


def attempt_dir(base: Path, model_key: str, scenario_id: str, k: int) -> Path:
    return base / model_key / scenario_id / str(k)


def _wall() -> datetime:
    return datetime.now(UTC)


def failure_source(result: GenerationResult) -> str | None:
    if result.failure_class is None or result.status is GenerationStatus.DISABLED:
        return None
    if result.status is GenerationStatus.CONTEXT_INSUFFICIENT or not result.attempts:
        return "budget"
    if result.attempts[-1].response.raw_response is None:
        return "provider"
    return "model"


def _context(given: GenerationInput, parent: Parent) -> tuple[LLMContext, dict[str, Any]]:
    state = parent.state
    (target,) = (d for d in parent.definitions if d.invariant_id == given.target_invariant_id)
    scope = change_scope(state.resources)
    focus = focus_for(target, state.resources)
    objective = objective_for(target)
    context = build_context(
        ContextInputs(
            parent_state_id=state.state_id,
            trusted_state_hash=state.state_hash,
            resources=tuple(state.resources),
            invariants=parent.definitions,
            statuses={r.invariant_id: r.status.value for r in state.invariant_refs},
            objective=objective,
            repair_targets=(target.invariant_id,),
            scope=scope,
            focus=focus,
        )
    )
    facts = {
        "parent": {
            "state_id": state.state_id,
            "state_hash": state.state_hash,
            "resource_set_hash": state.resource_set_hash(),
            "resource_addresses": sorted({config_address(r.address) for r in state.resources}),
            "s0_content_hash": given.s0_content_hash,
            "configuration_files": sorted(p.name for p in parent.directory.iterdir()),
            "invariants": {
                r.invariant_id: {"version": r.invariant_version, "status": r.status.value}
                for r in state.invariant_refs
            },
        },
        "scope": scope_record(scope),
        "objective": objective,
        "focus": list(focus),
        "target_invariant_id": target.invariant_id,
    }
    return context, facts


def _definition(
    spec: GenerationSpec,
    inputs: Sequence[GenerationInput],
    models: Sequence[ModelEntry],
    k: int,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "record": "generation_definition",
        "generation_id": spec.generation_id,
        "name": spec.name,
        "version": spec.version,
        "task_template": TASK_TEMPLATE,
        "scope_rule": SCOPE_RULE,
        "context_version": CONTEXT_VERSION,
        "prompt_version": PROMPT_VERSION,
        "template_hash": template_hash(PROMPT_VERSION),
        "parser_version": PARSER_VERSION,
        "validator_version": VALIDATOR_VERSION,
        "retry_policy": RETRY_POLICY.to_dict(),
        "repetitions": k,
        "seed_rule": "seed + k - 1",
        "scenarios": [g.to_dict() for g in inputs],
        "models": [pin.to_dict() for pin, _, _ in models],
        "experiment_llm_config_sha256": sha256_file(EXPERIMENT_LLM_FILE),
        "environment": dict(environment),
    }


def _attempt_record(
    *,
    spec: GenerationSpec,
    pin: ModelPin,
    given: GenerationInput,
    k: int,
    result: GenerationResult,
    facts: Mapping[str, Any],
    context: LLMContext,
) -> dict[str, Any]:
    final = result.attempts[-1].response if result.attempts else None
    build = result.build
    return {
        "record": "llm_candidate_attempt",
        "generation_id": spec.generation_id,
        "model_key": pin.key,
        "model_tag": pin.tag,
        "model_digest": pin.digest,
        "scenario_id": given.scenario_id,
        "family": given.family,
        "k": k,
        "seed": seed_for(pin, k),
        "status": result.status.value,
        "failure_class": None if result.failure_class is None else result.failure_class.value,
        "failure_source": failure_source(result),
        "detail": result.detail,
        **facts,
        "context_version": context.context_version,
        "context_hash": context.context_hash,
        "observability": result.observability(),
        "config": result.config.to_dict(),
        "parsed_status": None if final is None else final.parsed_status,
        "parse_errors": [] if final is None else list(final.parse_errors),
        "validation_errors": [] if final is None else list(final.validation_errors),
        "patch_sha256": (
            None if result.patch is None else hashlib.sha256(result.patch.encode()).hexdigest()
        ),
        "patch_id": None if final is None else final.patch_id,
        "final_request_id": None if not result.attempts else result.attempts[-1].request.request_id,
        "candidate_tree_hash": None if build is None else build.tree_hash,
        "candidate_resource_set_hash": None if build is None else build.resource_set_hash,
    }


def _one(
    *,
    spec: GenerationSpec,
    entry: ModelEntry,
    given: GenerationInput,
    parent: Parent,
    context: LLMContext,
    facts: Mapping[str, Any],
    k: int,
    folder: Path,
    work: Path,
    generation_enabled: bool,
) -> dict[str, Any]:
    pin, provider, _ = entry
    validator = PatchValidator(
        parent_dir=parent.directory,
        trusted=parent.state,
        scope=change_scope(parent.state.resources),
        work_root=work / "builds",
        variables=dict(given.variable_values),
        now=DAIL_CLOCK_BASE,
    )
    generator = Generator(
        provider=provider,
        config=llm_config(pin, provider.name, k),
        retry_policy=RETRY_POLICY,
        budget=budget_for(pin),
        generation_enabled=generation_enabled,
        clock=_wall,
        validator=validator,
    )
    folder.mkdir(parents=True)
    started_at, started = _wall(), time.perf_counter()
    result = generator.generate(context)
    seconds = time.perf_counter() - started
    try:
        for attempt in result.attempts:
            n = attempt.request.attempt_number
            write_record(folder / "records" / f"request-{n}.json", attempt.request.to_dict())
            write_record(folder / "records" / f"response-{n}.json", attempt.response.to_dict())
        if result.status is GenerationStatus.PATCH and result.patch is not None:
            path = folder / "patch.tf"
            with path.open("xb") as handle:
                handle.write(result.patch.encode("utf-8"))
        write_record(
            folder / "timing.json",
            {
                "started_at": started_at.isoformat(),
                "completed_at": _wall().isoformat(),
                "wall_seconds": seconds,
            },
        )
        record = _attempt_record(
            spec=spec, pin=pin, given=given, k=k, result=result, facts=facts, context=context
        )
        write_record(folder / "attempt.json", record)
    finally:
        if result.build is not None:  # the build is not kept: replay and export rebuild it
            shutil.rmtree(result.build.candidate_dir.parent, ignore_errors=True)
    return record


def _manifest_row(base: Path, folder: Path, record: Mapping[str, Any]) -> dict[str, Any]:
    files = {
        p.relative_to(base).as_posix(): sha256_file(p)
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    }
    return {
        "model_key": record["model_key"],
        "scenario_id": record["scenario_id"],
        "family": record["family"],
        "k": record["k"],
        "status": record["status"],
        "failure_class": record["failure_class"],
        "failure_source": record["failure_source"],
        "patch_sha256": record["patch_sha256"],
        "candidate_tree_hash": record["candidate_tree_hash"],
        "files": files,
    }


def generate_candidates(
    *,
    spec: GenerationSpec,
    inputs: Sequence[GenerationInput],
    models: Sequence[ModelEntry],
    k: int,
    root: Path,
    generation_enabled: bool,
    environment: Mapping[str, str],
) -> GenerationSummary:
    """Generate, freeze and list every attempt (see the module docstring)."""
    if k < 1 or not inputs or not models:
        raise GenerationError("generation needs k >= 1, at least one scenario and one model")
    base = generation_dir(root, spec.generation_id)
    if (base / MANIFEST).exists():
        raise GenerationError(
            f"generation {spec.generation_id} is frozen; a REGENERATE is a new generation_id "
            "(Doc 13 §47)"
        )
    for pin, _, installed in models:
        check_installed(pin, installed)
    planned = [(given, entry, n) for given in inputs for entry in models for n in range(1, k + 1)]
    for given, (pin, _, _), n in planned:
        folder = attempt_dir(base, pin.key, given.scenario_id, n)
        if folder.exists() and not (folder / "attempt.json").exists():
            raise GenerationError(
                f"{folder} is an interrupted attempt; it is never overwritten (a REGENERATE is a "
                "new generation_id)"
            )
    try:
        write_or_same(base / "definition.json", _definition(spec, inputs, models, k, environment))
        for pin, provider, installed in models:
            write_or_same(
                base / pin.key / "model.json",
                {"pin": pin.to_dict(), "installed": dict(installed), "provider": provider.name},
            )
    except ArtifactError as changed:
        raise GenerationError(f"the generation request changed: {changed}") from None
    rows: list[dict[str, Any]] = []
    for given in inputs:
        with tempfile.TemporaryDirectory(prefix="dail-p10a-generation-") as tmp:
            work = Path(tmp)
            parent = s0_parent(given, work / "parent", "generation")
            context, facts = _context(given, parent)
            for entry in models:
                pin = entry[0]
                for n in range(1, k + 1):
                    folder = attempt_dir(base, pin.key, given.scenario_id, n)
                    if (folder / "attempt.json").exists():
                        record = read_record(folder / "attempt.json")
                    else:
                        record = _one(
                            spec=spec,
                            entry=entry,
                            given=given,
                            parent=parent,
                            context=context,
                            facts=facts,
                            k=n,
                            folder=folder,
                            work=work,
                            generation_enabled=generation_enabled,
                        )
                    rows.append(_manifest_row(base, folder, record))
    manifest = {
        "record": "candidates_manifest",
        "generation_id": spec.generation_id,
        "definition_sha256": sha256_file(base / "definition.json"),
        "attempts": rows,
    }
    path = write_record(base / MANIFEST, manifest)
    return GenerationSummary(spec.generation_id, path, sha256_file(path), rows)


def read_manifest(root: Path, generation_id: str) -> dict[str, Any]:
    path = generation_dir(root, generation_id) / MANIFEST
    if not path.exists():
        raise GenerationError(f"generation {generation_id} has no manifest: it is not frozen")
    data = read_record(path)
    assert isinstance(data, dict)
    return data


def frozen_response_text(folder: Path, record: Mapping[str, Any]) -> tuple[str, str]:
    """(the reply text of the final attempt, its request id), as frozen."""
    n = len(record["observability"]["request_ids"])
    response = read_record(folder / "records" / f"response-{n}.json")
    if not isinstance(response, dict) or not isinstance(response.get("raw_response"), str):
        raise GenerationError(f"{folder}: no frozen reply text")
    return response["raw_response"], response["request_id"]


def failure_classes() -> tuple[str, ...]:
    return tuple(c.value for c in FailureClass)
