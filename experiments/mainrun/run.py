"""The main run's steps, with the lock and the ledger (P10e-prep decisions 1, 3 and 5; C-247,
C-249).

There is one main run: the experiment ``main-run`` version 1 (``EXPERIMENT_ID``) and one LLM
generation ``main-run-llm`` version 1 (``GENERATION_ID``), both under ``$DAIL_EXPERIMENT_ROOT``.

* ``reference``: without ``resume`` it takes the lock (refused if one exists); with ``resume`` it
  takes the locked experiment id (same commit and protocol). Then the ledger's ``reference`` step.
* ``generation``: the lock must exist (the same run); then the ledger's ``generation`` step.
* ``analysis``: the lock must exist; the ledger checks TP-L2's files and that the analysis never
  ran.

Each step function receives the experiment id. What it runs (the runner, generation, the gate,
replay, export, the analysis) is in ``experiments.mainrun.__main__``; this module holds the rules.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from experiments.definition import experiment_id_for, name_id
from experiments.mainrun.lock import acquire, resume_experiment
from experiments.mainrun.order import Ledger

EXPERIMENT_NAME: Final = "main-run"
EXPERIMENT_VERSION: Final = "1"
EXPERIMENT_ID: Final = experiment_id_for(EXPERIMENT_NAME, EXPERIMENT_VERSION)
GENERATION_NAME: Final = "main-run-llm"
GENERATION_VERSION: Final = "1"
GENERATION_ID: Final = name_id("generation", GENERATION_NAME, GENERATION_VERSION)
GATE_NAME: Final = "gate-1"
REPLAY_NAME: Final = "replay-1"

Step = Callable[[str], Any]


@dataclass
class MainRun:
    root: Path
    dail_commit: str
    protocol_sha256: str
    clock: Callable[[], str]

    @property
    def ledger(self) -> Ledger:
        return Ledger(self.root)

    def _locked(self) -> str:
        return resume_experiment(
            self.root, dail_commit=self.dail_commit, protocol_sha256=self.protocol_sha256
        )

    def reference(self, step: Step, *, resume: bool) -> str:
        if resume:
            experiment_id = self._locked()
        else:
            acquire(
                self.root,
                experiment_id=EXPERIMENT_ID,
                dail_commit=self.dail_commit,
                protocol_sha256=self.protocol_sha256,
                started_at=self.clock(),
            )
            experiment_id = EXPERIMENT_ID
        self.ledger.begin("reference", resume=resume, at=self.clock())
        step(experiment_id)
        self.ledger.complete("reference", at=self.clock())
        return experiment_id

    def generation(self, step: Step, *, resume: bool) -> str:
        experiment_id = self._locked()
        self.ledger.begin("generation", resume=resume, at=self.clock())
        step(experiment_id)
        self.ledger.complete("generation", at=self.clock())
        return experiment_id

    def analysis(self, step: Step, *, truth_files: Mapping[str, Path]) -> str:
        experiment_id = self._locked()
        self.ledger.begin_analysis(truth_files, at=self.clock())
        step(experiment_id)
        self.ledger.complete("analysis", at=self.clock())
        return experiment_id
