"""One attempt of one trial (P8a; Doc 13 Appendix A, §13, §20, §40; C-196, C-200 to C-203).

    initialize: a fresh store (its own SQLite file), a fresh lineage (C-202)
    baseline:   S0 through the existing baseline flow (P6c) with the scenario's bindings and primary
                variable values; DAIL's own S0 results are recorded as they are
    for step k = 1..n: admit the step (its content hash, C-201), evaluate it as a FIXED_PATCH
                candidate against the trial's current Trusted State through the real
                ``EvaluationOrchestrator``; stop at the first decision that is not PROMOTE and
                record the rest as TRUNCATED (C-200)

Nothing here decides anything: every transition is one ``evaluate`` call, and the stores of two
trials have nothing in common but the read-only scenario files. No experiment lineage is ever the
authoritative lineage (Doc 13 §20): the store lives under the attempt's own directory.

Time (C-207): everything DAIL hashes uses a logical clock that starts at ``DAIL_CLOCK_BASE`` and
moves one second per call, so a re-run of the same trial stores the same records. The wall clock is
kept apart in ``timing.json``. Ids are name-based from the trial id and the attempt number.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

from core.application.baseline import BaselineRefused, BaselineRequest, establish_baseline
from core.application.orchestrator import EvaluationOrchestrator, EvaluationRequest
from core.domain.enums import CandidateSource, DecisionType
from core.domain.patch import Patch
from core.domain.registry_v1_1 import REGISTRY_VERSION_V1_1
from core.domain.repositories import UnitOfWork
from core.domain.state import TrustedState
from core.persistence.schema import initialize_database
from core.persistence.sqlite import SqliteUnitOfWork
from core.promotion.commit import PromotionContext
from experiments import records
from experiments.artifacts import ATTEMPT_DIRS, write_record
from experiments.conditions import REGISTRY_RECORD, ConditionSetup, setup_for
from experiments.definition import Condition, name_id
from experiments.loader import ScenarioInput, StepInput, step_content_hash

DAIL_CLOCK_BASE: Final = datetime(2026, 1, 1, tzinfo=UTC)
STORE_NAME: Final = "dail.sqlite"
Hook = Callable[[str, str], None]


class AdmissionError(Exception):
    """A step's content hash is not the verified one (an input failure, C-201)."""


class LogicalClock:
    """``DAIL_CLOCK_BASE`` plus one second per call (C-207)."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return DAIL_CLOCK_BASE + timedelta(seconds=self.calls)


@dataclass(frozen=True)
class TrialInputs:
    trial_id: str
    experiment_id: str
    scenario: ScenarioInput
    condition: Condition
    repetition: int
    attempt: int
    admission_evidence: str


@dataclass
class AttemptOutcome:
    """What an attempt produced: the result record (no wall clock) and the durations."""

    result: dict[str, Any]
    durations: dict[str, float]


def correlation_id_for(trial_id: str) -> str:
    return name_id("correlation", trial_id)


def _admit(step: StepInput, evidence: str) -> dict[str, Any]:
    recomputed = step_content_hash(step.directory)
    if recomputed != step.content_hash:
        raise AdmissionError(
            f"step {step.index} ({step.directory}): content hash {recomputed} is not the "
            f"manifest's {step.content_hash}"
        )
    return {
        "step": step.index,
        "content_hash": recomputed,
        "content_hash_matches_manifest": True,
        "terraform_validate": evidence,
    }


class _Attempt:
    def __init__(self, inputs: TrialInputs, attempt_dir: Path, config: Any, hook: Hook | None):
        self.i = inputs
        self.dir = attempt_dir
        self.config = config
        self.hook = hook
        self.clock = LogicalClock()
        self.correlation_id = correlation_id_for(inputs.trial_id)
        self.lineage_id = self.id("lineage")
        self.durations: dict[str, float] = {}
        self.base: dict[str, Any] = {
            "trial_id": inputs.trial_id,
            "correlation_id": self.correlation_id,
            "condition": inputs.condition.value,
            "scenario_id": inputs.scenario.scenario_id,
        }

    def id(self, *parts: object) -> str:
        return name_id("trial-attempt", self.i.trial_id, self.i.attempt, *parts)

    def at(self, stage: str) -> None:
        if self.hook is not None:
            self.hook(self.i.trial_id, stage)

    def context(self, step: int) -> PromotionContext:
        return PromotionContext(
            run_id=self.id("run"),
            correlation_id=self.correlation_id,
            operation_id=self.id("operation", step),
            attempt_id=self.id("attempt"),
            actor_id=None,
        )

    def write(self, folder: str, name: str, data: Mapping[str, Any]) -> None:
        write_record(self.dir / folder / name, {**self.base, **data})

    # --- the attempt --------------------------------------------------------------------------

    def run(self) -> AttemptOutcome:
        scenario = self.i.scenario
        setup = setup_for(self.i.condition, scenario, DAIL_CLOCK_BASE)
        for name in ATTEMPT_DIRS:
            (self.dir / name).mkdir(parents=True, exist_ok=True)
        store = self.dir / "store" / STORE_NAME
        store.parent.mkdir(parents=True, exist_ok=True)
        initialize_database(store)

        def factory() -> UnitOfWork:
            return SqliteUnitOfWork(store)

        result: dict[str, Any] = {
            **self.base,
            "record": "trial_result",
            "experiment_id": self.i.experiment_id,
            "family": scenario.family,
            "repetition": self.i.repetition,
            "attempt": self.i.attempt,
            "lineage_id": self.lineage_id,
            "versions": setup.versions(),
            "registry": dict(REGISTRY_RECORD),
            "protected_invariants": setup.protected_mapping,
            "status": "COMPLETED",
            "failure": None,
            "baseline": None,
            "transitions": [],
        }
        self.at("baseline")
        started = time.perf_counter()
        parent = self._baseline(factory, setup, result)
        self.durations["baseline"] = time.perf_counter() - started
        if parent is None:
            result["transitions"] = [
                records.truncated_record(base=self.base, step=k)
                for k in range(1, scenario.transitions + 1)
            ]
            return AttemptOutcome(result, self.durations)
        orchestrator = EvaluationOrchestrator(
            factory,
            config=self.config,
            scope_policy=setup.scope_policy,
            clock=self.clock,
            policy_version=setup.policy_version,
            policy_factory=setup.policy_factory,
            identity_strategy=setup.identity_strategy,
        )
        transitions: list[dict[str, Any]] = result["transitions"]
        for step in scenario.steps[1:]:
            self.at(f"step-{step.index}")
            started = time.perf_counter()
            state, record = self._step(orchestrator, setup, parent, step)
            self.durations[f"step-{step.index}"] = time.perf_counter() - started
            transitions.append(record)
            if state is None:
                transitions.extend(
                    records.truncated_record(base=self.base, step=later.index)
                    for later in scenario.steps[step.index + 1 :]
                )
                break
            parent = state
        return AttemptOutcome(result, self.durations)

    def _baseline(
        self, factory: Callable[[], UnitOfWork], setup: ConditionSetup, result: dict[str, Any]
    ) -> TrustedState | None:
        scenario = self.i.scenario
        admission = _admit(scenario.steps[0], self.i.admission_evidence)
        with factory() as uow:  # earlier versions first: no gaps (Doc 06 §4.2, C-203)
            for definition in setup.history:
                uow.invariants.register_definition(definition)
        request = BaselineRequest(
            baseline_id=self.id("baseline"),
            lineage_id=self.lineage_id,
            baseline_dir=scenario.steps[0].directory,
            variables=dict(scenario.variable_values),
            definitions=setup.baseline_definitions,
            bindings=setup.baseline_bindings,
            context=self.context(0),
            now=self.clock(),
            eligible=True,
            registry_version=REGISTRY_VERSION_V1_1,
            allow_no_invariants=setup.allow_no_invariants,
        )
        try:
            made = establish_baseline(factory, request)
        except BaselineRefused as refused:
            summary: dict[str, Any] = {
                "outcome": "REFUSED",
                "reasons": list(refused.reasons),
                "admission": admission,
                "invariants": {},
                "state_id": None,
                "state_hash": None,
            }
            result["baseline"] = summary
            self.write("baseline", "baseline.json", {"record": "baseline", **summary})
            return None
        summary = {
            "outcome": "ESTABLISHED",
            "reasons": [],
            "admission": admission,
            **records.state_summary(made.state),
            "baseline_id": request.baseline_id,
            "registry": dict(REGISTRY_RECORD),
        }
        result["baseline"] = summary
        self.write(
            "baseline",
            "baseline.json",
            {
                "record": "baseline",
                **summary,
                "verification": records.stable(made.report.to_dict()),
            },
        )
        return made.state

    def _step(
        self,
        orchestrator: EvaluationOrchestrator,
        setup: ConditionSetup,
        parent: TrustedState,
        step: StepInput,
    ) -> tuple[TrustedState | None, dict[str, Any]]:
        scenario = self.i.scenario
        admission = _admit(step, self.i.admission_evidence)
        opened = setup.open_targets(scenario, step.index)
        patch = Patch.create(
            source=CandidateSource.FIXED_PATCH,
            content=(
                f"TerraPreserve {scenario.scenario_id} step {step.index} "
                f"({step.content_hash})\n"
            ),
            parent_state_id=parent.state_id,
            now=self.clock(),
            patch_id=self.id("patch", step.index),
        )
        request = EvaluationRequest(
            lineage_id=self.lineage_id,
            candidate_id=self.id("candidate", step.index),
            candidate_sequence=step.index,
            attempt_number=1,
            patch=patch,
            candidate_dir=step.directory,
            variables=dict(scenario.variable_values),
            definitions=setup.definitions,
            bindings=setup.bindings,
            context=self.context(step.index),
            open_targets=opened,
        )
        evaluated = orchestrator.evaluate(request)
        record = records.transition_record(
            base=self.base,
            step=step.index,
            admission=admission,
            parent=parent,
            open_targets=opened,
            result=evaluated,
        )
        name = f"step-{step.index}.json"
        self.write(
            "generation",
            name,
            {"record": "fixed_patch", "patch": patch.to_dict(), "admission": admission},
        )
        self.write(
            "analysis",
            name,
            {
                "record": "analysis",
                "identity": (
                    None
                    if evaluated.identity is None
                    else records.stable(evaluated.identity.to_dict())
                ),
                "impact": (
                    None if evaluated.impact is None else records.stable(evaluated.impact.to_dict())
                ),
                "registry": dict(REGISTRY_RECORD),
            },
        )
        self.write(
            "verification",
            name,
            {
                "record": "verification",
                "work": records.work_items(evaluated.work, evaluated.impact),
                "report": (
                    None
                    if evaluated.verification is None
                    else records.stable(evaluated.verification.to_dict())
                ),
                "registry": dict(REGISTRY_RECORD),
            },
        )
        self.write(
            "decision",
            name,
            {
                "transition": record,
                "decision": None if evaluated.decision is None else evaluated.decision.to_dict(),
                "evidence": (
                    None if evaluated.outcome is None else evaluated.outcome.evidence.to_dict()
                ),
            },
        )
        promoted = (
            evaluated.decision is not None
            and evaluated.decision.decision is DecisionType.PROMOTE
            and evaluated.state is not None
        )
        return (evaluated.state if promoted else None), record


def run_attempt(
    inputs: TrialInputs, attempt_dir: Path, *, config: Any, hook: Hook | None = None
) -> AttemptOutcome:
    """Run one attempt (see the module docstring). Exceptions propagate to the runner, which
    classifies them; nothing here turns an exception into a decision."""
    return _Attempt(inputs, attempt_dir, config, hook).run()


def setup_versions(condition: Condition, scenario: ScenarioInput) -> dict[str, Any]:
    return setup_for(condition, scenario, DAIL_CLOCK_BASE).versions()
