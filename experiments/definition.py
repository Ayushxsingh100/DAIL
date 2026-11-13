"""Experiment and trial records (P8a; Doc 13 §5-§7, §39, §46, §48; C-198, C-200).

Doc 13 §5 "Experiment { experiment_id, name, version, objective, hypothesis[], protocol_version,
fixture_set[], baseline_set[], condition_set[], repetitions, seed_policy, metrics[],
stopping_policy, created_at }. An experiment definition becomes immutable once trials begin.
Changes create a new experiment version." §6 "Trial { trial_id, experiment_id, condition_id,
fixture_id, baseline_id, repetition, seed | null, parent_state_id, status, started_at,
completed_at, artifact_refs[] }."
§7 "PLANNED -> INITIALIZED -> EXECUTING -> (FAILED | ABORTED | COMPLETED) -> ANALYZED -> INCLUDED."

Ids are deterministic (name-based UUIDs): the experiment id from its name and version, a trial id
from the experiment id, the scenario id, the condition and the repetition. Two readings of §7, for
the authors (C-207): a trial interrupted before it began executing may go from INITIALIZED to
ABORTED (stale-run handling, §50), and an ABORTED trial is re-run as a new attempt, which starts
again at INITIALIZED (§47: a re-run never overwrites the original). ``pins`` holds what §46 asks
to pin.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from experiments.loader import FixtureRecord

NAMESPACE: Final = uuid.uuid5(uuid.NAMESPACE_URL, "dail/experiments/p8a")
SEED_POLICY: Final = "none: fixed patches are deterministic, repetition 1 (C-200)"
STOPPING_POLICY: Final = (
    "every planned trial runs once; a trajectory stops at the first decision other than PROMOTE "
    "and the rest of its steps are TRUNCATED (C-200)"
)


class Condition(StrEnum):
    """The four conditions of P8 (C-198)."""

    A = "A"
    B = "B"
    C = "C"
    C_PRIME = "C_PRIME"


CONDITION_NAMES: Final = {
    Condition.A: "Stateless",
    Condition.B: "Stateful Full",
    Condition.C: "DAIL",
    Condition.C_PRIME: "DAIL without identity evidence",
}


class TrialStatus(StrEnum):
    """Doc 13 §7."""

    PLANNED = "PLANNED"
    INITIALIZED = "INITIALIZED"
    EXECUTING = "EXECUTING"
    FAILED = "FAILED"
    ABORTED = "ABORTED"
    COMPLETED = "COMPLETED"
    ANALYZED = "ANALYZED"
    INCLUDED = "INCLUDED"


S = TrialStatus
_NEXT: Final[Mapping[TrialStatus, frozenset[TrialStatus]]] = {
    S.PLANNED: frozenset({S.INITIALIZED}),
    S.INITIALIZED: frozenset({S.EXECUTING, S.ABORTED}),
    S.EXECUTING: frozenset({S.FAILED, S.ABORTED, S.COMPLETED}),
    S.ABORTED: frozenset({S.INITIALIZED}),  # a new attempt (§47)
    S.FAILED: frozenset(),
    S.COMPLETED: frozenset({S.ANALYZED}),
    S.ANALYZED: frozenset({S.INCLUDED}),
    S.INCLUDED: frozenset(),
}
TERMINAL: Final = frozenset({S.FAILED, S.COMPLETED, S.ANALYZED, S.INCLUDED})


class TransitionError(Exception):
    """A trial status change that Doc 13 §7 does not allow."""


def check_transition(before: TrialStatus, after: TrialStatus) -> None:
    if after not in _NEXT[before]:
        raise TransitionError(f"a trial cannot go from {before.value} to {after.value}")


def name_id(*parts: object) -> str:
    return str(uuid.uuid5(NAMESPACE, "/".join(str(part) for part in parts)))


def experiment_id_for(name: str, version: str) -> str:
    return name_id("experiment", name, version)


def trial_id_for(
    experiment_id: str, scenario_id: str, condition: Condition, repetition: int
) -> str:
    return name_id("trial", experiment_id, scenario_id, condition.value, repetition)


@dataclass(frozen=True)
class ExperimentSpec:
    """What the caller asks for; ``plan`` turns it into an ``Experiment``."""

    name: str
    version: str
    protocol_version: str
    objective: str
    hypotheses: tuple[str, ...]
    conditions: tuple[Condition, ...]
    repetitions: int = 1

    def __post_init__(self) -> None:
        for key in ("name", "version", "protocol_version", "objective"):
            value = getattr(self, key)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"ExperimentSpec.{key} must be text")
        conditions = tuple(Condition(c) for c in self.conditions)
        if not conditions or len(set(conditions)) != len(conditions):
            raise ValueError("ExperimentSpec.conditions: at least one, each once")
        if self.repetitions != 1:
            raise ValueError("ExperimentSpec.repetitions: fixed patches run once (C-200)")
        object.__setattr__(self, "conditions", tuple(sorted(conditions)))
        object.__setattr__(self, "hypotheses", tuple(self.hypotheses))


@dataclass(frozen=True)
class PlannedTrial:
    trial_id: str
    scenario_id: str
    condition: Condition
    repetition: int


@dataclass(frozen=True)
class Experiment:
    """Doc 13 §5, with the pins of §46 and the fixture hashes of §40."""

    experiment_id: str
    name: str
    version: str
    objective: str
    hypothesis: tuple[str, ...]
    protocol_version: str
    fixture_set: tuple[str, ...]
    baseline_set: tuple[tuple[str, str], ...]
    condition_set: tuple[Condition, ...]
    repetitions: int
    created_at: datetime
    pins: Mapping[str, Any]
    fixtures: tuple[FixtureRecord, ...]
    seed_policy: str = SEED_POLICY
    metrics: tuple[str, ...] = ()
    stopping_policy: str = STOPPING_POLICY
    planned: tuple[PlannedTrial, ...] = field(default=())

    def trial_id(self, scenario_id: str, condition: Condition, repetition: int = 1) -> str:
        return trial_id_for(self.experiment_id, scenario_id, condition, repetition)

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "name": self.name,
            "version": self.version,
            "objective": self.objective,
            "hypothesis": list(self.hypothesis),
            "protocol_version": self.protocol_version,
            "fixture_set": list(self.fixture_set),
            "baseline_set": [{"scenario_id": s, "step_0": h} for s, h in self.baseline_set],
            "condition_set": [c.value for c in self.condition_set],
            "repetitions": self.repetitions,
            "seed_policy": self.seed_policy,
            "metrics": list(self.metrics),
            "stopping_policy": self.stopping_policy,
            "created_at": self.created_at.isoformat(),
            "pins": dict(self.pins),
            "trials": [
                {
                    "trial_id": t.trial_id,
                    "scenario_id": t.scenario_id,
                    "condition": t.condition.value,
                    "repetition": t.repetition,
                }
                for t in self.planned
            ],
        }

    def fixtures_dict(self) -> dict[str, Any]:
        return {"fixtures": [f.to_dict() for f in self.fixtures]}


def planned_trials(
    experiment_id: str, scenario_ids: Iterable[str], conditions: Iterable[Condition]
) -> tuple[PlannedTrial, ...]:
    chosen = tuple(conditions)
    return tuple(
        PlannedTrial(trial_id_for(experiment_id, sid, c, 1), sid, c, 1)
        for sid in sorted(scenario_ids)
        for c in chosen
    )
