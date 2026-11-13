"""Write-once experiment artifacts (P8a; Doc 13 §40, §41, §47; C-202, C-204).

Layout (§41), under ``$DAIL_EXPERIMENT_ROOT``::

    experiment/<experiment_id>/
        definition/experiment.json          the definition and its pins (§5, §46)
        fixtures/fixtures.json              scenario and step hashes (§40)
        trials/<trial_id>/
            events.jsonl                    the trial's lifecycle (§7), append-only, wall clock
            attempts/<n>/                   one attempt (§47: a re-run is a new attempt)
                store/dail.sqlite           the attempt's own DAIL store (C-202)
                baseline/ generation/ analysis/ verification/ decision/ metrics/
                result.json                 the trial result (no wall clock)
                timing.json                 the Trial record of §6 with its wall-clock times
        report/                             P8b

§41 names ``trials/<trial_id>/{baseline/ ...}``; the attempts level is added so that a re-run never
overwrites the original (§47) (C-207). Every file is written once: ``write_record`` refuses a path
that exists, and ``append_event`` only appends. JSON is written with sorted keys, so the same record
gives the same bytes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final

ATTEMPT_DIRS: Final = ("baseline", "generation", "analysis", "verification", "decision", "metrics")


class ArtifactError(Exception):
    """A record would be overwritten, or a stored record cannot be read."""


def dumps(data: Any) -> bytes:
    return (json.dumps(data, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def write_record(path: Path, data: Any) -> Path:
    """Write ``data`` to ``path`` once; an existing path is never overwritten."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(dumps(data))
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise ArtifactError(f"{path} exists; a stored record is never overwritten") from None
    return path


def write_or_same(path: Path, data: Any) -> bool:
    """Write ``data`` once, or check that the stored record is the same. True if written."""
    if path.exists():
        if path.read_bytes() != dumps(data):
            raise ArtifactError(f"{path} holds another record")
        return False
    write_record(path, data)
    return True


def read_record(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError) as error:
        raise ArtifactError(f"{path}: {error}") from None


def append_event(path: Path, event: dict[str, Any]) -> None:
    """Append one line to an append-only JSON-lines file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n"
    with path.open("ab") as handle:
        handle.write(line.encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except ValueError as error:
            raise ArtifactError(f"{path} line {number}: {error}") from None
    return events


class Layout:
    """The paths of one experiment under an output root."""

    def __init__(self, root: Path, experiment_id: str) -> None:
        self.root = Path(root)
        self.experiment_id = experiment_id
        self.experiment_dir = self.root / "experiment" / experiment_id

    @property
    def definition_path(self) -> Path:
        return self.experiment_dir / "definition" / "experiment.json"

    @property
    def fixtures_path(self) -> Path:
        return self.experiment_dir / "fixtures" / "fixtures.json"

    def trial_dir(self, trial_id: str) -> Path:
        return self.experiment_dir / "trials" / trial_id

    def events_path(self, trial_id: str) -> Path:
        return self.trial_dir(trial_id) / "events.jsonl"

    def attempt_dir(self, trial_id: str, attempt: int) -> Path:
        return self.trial_dir(trial_id) / "attempts" / str(attempt)

    def attempts(self, trial_id: str) -> list[int]:
        base = self.trial_dir(trial_id) / "attempts"
        if not base.is_dir():
            return []
        return sorted(int(p.name) for p in base.iterdir() if p.is_dir() and p.name.isdigit())
