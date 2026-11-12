"""Plan, run and resume an experiment (P8a; Doc 13 §5-§7, §39, §43-§48, §50; C-200 to C-207).

``plan`` turns an ``ExperimentSpec`` and a verified ``LoadedSet`` into an ``Experiment``: ids,
fixture and baseline sets, the planned trials (every target scenario under every condition,
repetition 1) and the pins of §46 (DAIL commit, TerraPreserve tag and manifest hash, registry,
policy, scope, identity and verifier versions, Python version and platform).

``run_experiment`` writes the definition and the fixture hashes once (a stored definition that
differs is refused: a change needs a new experiment version, §39, §48), then runs every planned
trial that is not finished:

* a trial whose last event is COMPLETED or FAILED is skipped (a FAILED trial is not retried here;
  its error is in its record);
* a trial left INITIALIZED or EXECUTING by an interrupted run is marked ABORTED and re-run as a new
  attempt in a new directory: nothing stored is overwritten (§47);
* a PLANNED (or ABORTED) trial runs its next attempt.

Failure classes (§43-§44): an ``AdmissionError`` is an INPUT_FAILURE and any other ``Exception`` a
HARNESS_FAILURE; either marks the trial FAILED with the error and never becomes a decision. A
``BaseException`` that is not an ``Exception`` (the process is being stopped) is not caught: the
trial stays EXECUTING and the next run resumes it.

Trials are independent (C-202), so ``workers > 1`` runs them in threads; each has its own store.
"""

from __future__ import annotations

import platform
import shutil
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from core.application.config import ResolvedConfig, load_config
from core.domain.registry_v1_1 import REGISTRY_TAG_V1_1, REGISTRY_VERSION_V1_1
from core.identity.strategy import ADDRESS_ONLY_ALGORITHM_VERSION, IDENTITY_ALGORITHM_VERSION
from core.terraform_model.normalize import NORMALIZATION_VERSION
from core.verification.engine import VERIFIER_SET_VERSION
from experiments import records
from experiments.artifacts import (
    ArtifactError,
    Layout,
    append_event,
    read_record,
    write_or_same,
    write_record,
)
from experiments.artifacts import read_events as _read_events
from experiments.conditions import setup_for
from experiments.definition import (
    TERMINAL,
    Condition,
    Experiment,
    ExperimentSpec,
    TrialStatus,
    check_transition,
    experiment_id_for,
    planned_trials,
)
from experiments.loader import LoadedSet, ScenarioInput, sha256_hex
from experiments.trial import (
    DAIL_CLOCK_BASE,
    AdmissionError,
    TrialInputs,
    correlation_id_for,
    run_attempt,
)

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
EXPERIMENT_PROMOTION_FILE: Final = REPO_ROOT / "experiments" / "config" / "promotion.toml"
S = TrialStatus
Hook = Callable[[str, str], None]

__all__ = [
    "ExperimentError",
    "Layout",
    "RunSummary",
    "experiment_config",
    "plan",
    "read_events",
    "read_result",
    "run_experiment",
]


class ExperimentError(Exception):
    """The experiment cannot run as asked (a changed definition, a mismatch with the input)."""


@dataclass(frozen=True)
class RunSummary:
    statuses: Mapping[str, TrialStatus]
    attempted: tuple[str, ...]
    skipped: tuple[str, ...]
    failures: Mapping[str, str] = field(default_factory=dict)


# --- configuration --------------------------------------------------------------------------------


def experiment_config() -> ResolvedConfig:
    """The repository configuration with the reviewed experiment promotion file in place of
    ``config/base/promotion.toml`` (C-207), loaded for the ``experiment`` environment with no
    environment variables. Refuses to start if automatic promotion is not on."""
    with tempfile.TemporaryDirectory(prefix="dail-experiment-config-") as tmp:
        root = Path(tmp) / "config"
        shutil.copytree(REPO_ROOT / "config", root)
        shutil.copyfile(EXPERIMENT_PROMOTION_FILE, root / "base" / "promotion.toml")
        config = load_config(root, "experiment", environ={})
    if config.get("promotion.automatic_enabled") is not True:
        raise ExperimentError("the experiment configuration must enable automatic promotion")
    return config


# --- plan -----------------------------------------------------------------------------------------


def _verifiers(scenario: ScenarioInput) -> dict[str, Any]:
    setup = setup_for(Condition.C, scenario, DAIL_CLOCK_BASE)
    return {
        "verifier_set_version": VERIFIER_SET_VERSION,
        "invariants": {
            d.invariant_id: {
                "version": d.version,
                "verifier_id": d.verifier_id,
                "verifier_version": d.verifier_version,
            }
            for d in setup.definitions
        },
    }


def plan(
    spec: ExperimentSpec,
    loaded: LoadedSet,
    *,
    environment: Mapping[str, str],
    created_at: datetime,
    only: Iterable[str] | None = None,
) -> Experiment:
    """The experiment of ``spec`` over ``loaded`` (every target, or the ids in ``only``)."""
    by_id = {s.scenario_id: s for s in loaded.scenarios}
    chosen = sorted(by_id) if only is None else sorted(set(only))
    missing = [sid for sid in chosen if sid not in by_id]
    if missing or not chosen:
        raise ExperimentError(f"no such scenario in the loaded set: {missing or 'none chosen'}")
    experiment_id = experiment_id_for(spec.name, spec.version)
    first = by_id[chosen[0]]
    pins: dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        **dict(environment),
        "terrapreserve_manifest_sha256": loaded.manifest_sha256,
        "terrapreserve_split": loaded.split,
        "invariant_registry": {
            "tag": REGISTRY_TAG_V1_1,
            "stored_invariant_registry_version": REGISTRY_VERSION_V1_1,
        },
        "policies": {
            c.value: setup_for(c, first, DAIL_CLOCK_BASE).versions() for c in spec.conditions
        },
        "identity": {
            "evidence": IDENTITY_ALGORITHM_VERSION,
            "address_only": ADDRESS_ONLY_ALGORITHM_VERSION,
        },
        "normalization_version": NORMALIZATION_VERSION,
        "verifiers": _verifiers(first),
        "dail_clock": f"logical: {DAIL_CLOCK_BASE.isoformat()} plus one second per call (C-207)",
        "experiment_promotion_config_sha256": sha256_hex(EXPERIMENT_PROMOTION_FILE.read_bytes()),
        "admission_evidence": loaded.admission_evidence,
    }
    fixtures = tuple(f for f in loaded.fixtures if f.scenario_id in set(chosen))
    return Experiment(
        experiment_id=experiment_id,
        name=spec.name,
        version=spec.version,
        objective=spec.objective,
        hypothesis=spec.hypotheses,
        protocol_version=spec.protocol_version,
        fixture_set=tuple(chosen),
        baseline_set=tuple((sid, by_id[sid].steps[0].content_hash) for sid in chosen),
        condition_set=spec.conditions,
        repetitions=spec.repetitions,
        created_at=created_at,
        pins=pins,
        fixtures=fixtures,
        planned=planned_trials(experiment_id, chosen, spec.conditions),
    )


# --- reading back ---------------------------------------------------------------------------------


def read_events(layout: Layout, trial_id: str) -> list[dict[str, Any]]:
    return _read_events(layout.events_path(trial_id))


def read_result(layout: Layout, trial_id: str) -> dict[str, Any]:
    """The result of the trial's latest attempt that has one."""
    for attempt in reversed(layout.attempts(trial_id)):
        path = layout.attempt_dir(trial_id, attempt) / "result.json"
        if path.exists():
            data = read_record(path)
            assert isinstance(data, dict)
            return data
    raise ExperimentError(f"trial {trial_id} has no stored result")


# --- run ------------------------------------------------------------------------------------------


def _definition_without_clock(data: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k != "created_at"}


def _write_definition(layout: Layout, experiment: Experiment) -> None:
    wanted = experiment.to_dict()
    path = layout.definition_path
    if path.exists():
        stored = read_record(path)
        if not isinstance(stored, dict) or _definition_without_clock(
            stored
        ) != _definition_without_clock(wanted):
            raise ExperimentError(
                f"{path} holds another definition of experiment {experiment.experiment_id}; a "
                "changed experiment needs a new version (Doc 13 §39, §48)"
            )
    else:
        write_record(path, wanted)
    try:
        write_or_same(layout.fixtures_path, experiment.fixtures_dict())
    except ArtifactError as changed:
        raise ExperimentError(f"the fixtures changed: {changed}") from None


def _wall() -> str:
    return datetime.now(UTC).isoformat()


class _TrialRun:
    def __init__(
        self,
        layout: Layout,
        experiment: Experiment,
        trial_id: str,
        scenario: ScenarioInput,
        condition: Condition,
        repetition: int,
        evidence: str,
    ) -> None:
        self.layout = layout
        self.experiment = experiment
        self.trial_id = trial_id
        self.scenario = scenario
        self.condition = condition
        self.repetition = repetition
        self.evidence = evidence
        self.path = layout.events_path(trial_id)

    def event(
        self, attempt: int, status: TrialStatus, last: TrialStatus | None, **extra: Any
    ) -> None:
        if last is not None:
            check_transition(last, status)
        append_event(
            self.path,
            {
                "trial_id": self.trial_id,
                "correlation_id": correlation_id_for(self.trial_id),
                "attempt": attempt,
                "status": status.value,
                "at": _wall(),
                **extra,
            },
        )

    def state(self) -> tuple[TrialStatus | None, int]:
        events = _read_events(self.path)
        if not events:
            return None, 0
        return TrialStatus(events[-1]["status"]), max(int(e["attempt"]) for e in events)

    def run(self, config: Any, hook: Hook | None) -> tuple[TrialStatus, bool, str | None]:
        """(status, attempted, failure message)."""
        last, attempt = self.state()
        if last is None:
            self.event(0, S.PLANNED, None)
            last = S.PLANNED
        if last in TERMINAL:
            return last, False, None
        if last in (S.INITIALIZED, S.EXECUTING):  # an interrupted run (§50)
            self.event(attempt, S.ABORTED, last, reason="interrupted run; re-run as a new attempt")
            last = S.ABORTED
        number = max(attempt, *self.layout.attempts(self.trial_id), 0) + 1
        directory = self.layout.attempt_dir(self.trial_id, number)
        if directory.exists():
            raise ExperimentError(f"{directory} exists; a stored attempt is never overwritten")
        self.event(number, S.INITIALIZED, last)
        directory.mkdir(parents=True)
        started_wall, started = _wall(), time.perf_counter()
        if hook is not None:
            hook(self.trial_id, "initialized")
        self.event(number, S.EXECUTING, S.INITIALIZED)
        inputs = TrialInputs(
            trial_id=self.trial_id,
            experiment_id=self.experiment.experiment_id,
            scenario=self.scenario,
            condition=self.condition,
            repetition=self.repetition,
            attempt=number,
            admission_evidence=self.evidence,
        )
        failure: dict[str, Any] | None = None
        durations: dict[str, float] = {}
        try:
            outcome = run_attempt(inputs, directory, config=config, hook=hook)
            result, durations = outcome.result, outcome.durations
        except Exception as error:  # classified; never a decision (§43-§44)
            failure = {
                "class": (
                    records.INPUT_FAILURE
                    if isinstance(error, AdmissionError)
                    else records.HARNESS_FAILURE
                ),
                "type": type(error).__name__,
                "message": str(error)[:2000],
            }
            result = {
                "record": "trial_result",
                "trial_id": self.trial_id,
                "correlation_id": correlation_id_for(self.trial_id),
                "experiment_id": self.experiment.experiment_id,
                "condition": self.condition.value,
                "scenario_id": self.scenario.scenario_id,
                "family": self.scenario.family,
                "repetition": self.repetition,
                "attempt": number,
                "status": "FAILED",
                "failure": failure,
                "baseline": None,
                "transitions": [],
            }
        status = S.FAILED if failure is not None else S.COMPLETED
        elapsed = time.perf_counter() - started
        write_record(directory / "result.json", result)
        baseline = result.get("baseline") or {}
        write_record(
            directory / "timing.json",
            {
                "trial": {
                    "trial_id": self.trial_id,
                    "experiment_id": self.experiment.experiment_id,
                    "condition_id": self.condition.value,
                    "fixture_id": self.scenario.scenario_id,
                    "baseline_id": baseline.get("baseline_id"),
                    "repetition": self.repetition,
                    "seed": None,
                    "parent_state_id": baseline.get("state_id"),
                    "status": status.value,
                    "started_at": started_wall,
                    "completed_at": _wall(),
                    "artifact_refs": sorted(
                        p.relative_to(directory).as_posix()
                        for p in directory.rglob("*.json")
                        if p.name != "timing.json"
                    ),
                    "attempt": number,
                },
                "durations_seconds": {"total": elapsed, **durations},
            },
        )
        self.event(number, status, S.EXECUTING)
        message = None if failure is None else f"{failure['type']}: {failure['message']}"
        return status, True, message


def run_experiment(
    experiment: Experiment,
    loaded: LoadedSet,
    output_root: Path,
    *,
    hook: Hook | None = None,
    workers: int = 1,
    config: Any = None,
) -> RunSummary:
    """Run every unfinished planned trial of ``experiment`` (see the module docstring)."""
    by_id = {s.scenario_id: s for s in loaded.scenarios}
    stored = {f.scenario_id: f for f in loaded.fixtures}
    for fixture in experiment.fixtures:
        if stored.get(fixture.scenario_id) != fixture:
            raise ExperimentError(
                f"{fixture.scenario_id}: the loaded fixture is not the experiment's"
            )
    layout = Layout(Path(output_root), experiment.experiment_id)
    _write_definition(layout, experiment)
    chosen_config = config if config is not None else experiment_config()
    runs = [
        _TrialRun(
            layout,
            experiment,
            t.trial_id,
            by_id[t.scenario_id],
            t.condition,
            t.repetition,
            loaded.admission_evidence,
        )
        for t in experiment.planned
    ]
    statuses: dict[str, TrialStatus] = {}
    attempted: list[str] = []
    skipped: list[str] = []
    failures: dict[str, str] = {}

    def collect(item: _TrialRun, outcome: tuple[TrialStatus, bool, str | None]) -> None:
        status, ran, message = outcome
        statuses[item.trial_id] = status
        (attempted if ran else skipped).append(item.trial_id)
        if message is not None:
            failures[item.trial_id] = message

    if workers <= 1:
        for item in runs:
            collect(item, item.run(chosen_config, hook))
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [(item, pool.submit(item.run, chosen_config, hook)) for item in runs]
            for item, future in futures:
                collect(item, future.result())
    order = {t.trial_id: n for n, t in enumerate(experiment.planned)}
    return RunSummary(
        statuses=dict(sorted(statuses.items(), key=lambda kv: order[kv[0]])),
        attempted=tuple(sorted(attempted, key=order.__getitem__)),
        skipped=tuple(sorted(skipped, key=order.__getitem__)),
        failures=failures,
    )
