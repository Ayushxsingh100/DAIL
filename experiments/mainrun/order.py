"""The order of the unblinding (P10e-prep decision 5; protocol §9; C-249).

An append-only ledger, ``$DAIL_EXPERIMENT_ROOT/main-run.steps.jsonl``, records every step: one
JSON line per event (``started``, ``resumed``, ``completed``; ``present`` for TP-L2's files).

* ``reference`` (the 96 test targets under A, B, C and C'), then ``generation`` (the 36 test repair
  scenarios, 3 models, k = 3, the gate, the replay and the export for the oracle); a step starts
  only after the one before it completed, and a completed step is never run again; a step that
  started and did not complete runs again only as a resumption (``resume=True``), which is
  recorded.
* Stop: TerraPreserve labels the exported candidates (TP-L2).
* ``analysis``: only after ``generation`` completed and when TP-L2's file exists for every
  generation (their SHA-256 are recorded); it runs once: any earlier analysis event, even one that
  did not complete, refuses it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

LEDGER_NAME: Final = "main-run.steps.jsonl"
STEPS: Final = ("reference", "generation")
BEFORE: Final = {"reference": None, "generation": "reference"}


class OrderError(Exception):
    """A step is out of order or would run again."""


class Ledger:
    def __init__(self, root: Path) -> None:
        self.path = Path(root) / LEDGER_NAME

    def events(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        return [json.loads(x) for x in self.path.read_text(encoding="utf-8").splitlines() if x]

    def _append(self, step: str, event: str, at: str, **extra: Any) -> None:
        line = json.dumps({"step": step, "event": event, "at": at, **extra}, sort_keys=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as out:
            out.write(line + "\n")

    def status(self, step: str) -> str:
        seen = {e["event"] for e in self.events() if e["step"] == step}
        if "completed" in seen:
            return "completed"
        return "started" if seen else "not started"

    def begin(self, step: str, *, resume: bool, at: str) -> None:
        if step not in STEPS:
            raise OrderError(f"no step {step!r}")
        before = BEFORE[step]
        if before is not None and self.status(before) != "completed":
            raise OrderError(f"{step} needs the {before} step completed first")
        state = self.status(step)
        if state == "completed":
            raise OrderError(f"the {step} step completed; it is never run again")
        if state == "started" and not resume:
            raise OrderError(f"the {step} step was interrupted: resume it")
        if state == "not started" and resume:
            raise OrderError(f"the {step} step never started: nothing to resume")
        self._append(step, "resumed" if resume else "started", at)

    def complete(self, step: str, *, at: str) -> None:
        self._append(step, "completed", at)

    def begin_analysis(self, files: Mapping[str, Path], *, at: str) -> None:
        if self.status("generation") != "completed":
            raise OrderError("the analysis needs the generation step completed first")
        if any(e["step"] == "analysis" for e in self.events()):
            raise OrderError("the analysis runs once: it already ran on this experiment")
        if not files:
            raise OrderError("the analysis needs TP-L2's files: none is named")
        missing = sorted(g for g, p in files.items() if not Path(p).is_file())
        if missing:
            raise OrderError(f"the analysis needs TP-L2's files: none for {missing}")
        digests = {
            g: {"sha256": hashlib.sha256(Path(p).read_bytes()).hexdigest()}
            for g, p in sorted(files.items())
        }
        self._append("tp_l2", "present", at, files=digests)
        self._append("analysis", "started", at)
