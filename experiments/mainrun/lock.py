"""One main run (P10e-prep decision 3; C-247).

The main-run command writes ``$DAIL_EXPERIMENT_ROOT/main-run.lock`` (the experiment id, the start
time, the DAIL commit and the SHA-256 of the protocol) when the run starts, and refuses to start
if one exists, whatever experiment it names. An interrupted run is resumed: ``resume_experiment``
gives the locked experiment id, only on the same DAIL commit and protocol; it never gives a new
one. The lock is created exclusively and is never rewritten or removed by DAIL.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final

LOCK_NAME: Final = "main-run.lock"


class LockError(Exception):
    """The main run may not start or resume."""


def acquire(
    root: Path, *, experiment_id: str, dail_commit: str, protocol_sha256: str, started_at: str
) -> dict[str, str]:
    lock = {
        "experiment_id": experiment_id,
        "started_at": started_at,
        "dail_commit": dail_commit,
        "protocol_sha256": protocol_sha256,
    }
    path = Path(root) / LOCK_NAME
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise LockError(
            f"{path} exists: a main run was started; resume it, a new one is never started"
        ) from None
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
        out.write(json.dumps(lock, indent=1, sort_keys=True) + "\n")
    return lock


def read_lock(root: Path) -> dict[str, Any] | None:
    path = Path(root) / LOCK_NAME
    if not path.is_file():
        return None
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def resume_experiment(root: Path, *, dail_commit: str, protocol_sha256: str) -> str:
    lock = read_lock(root)
    if lock is None:
        raise LockError("no main run to resume: no main-run.lock")
    if lock["dail_commit"] != dail_commit:
        raise LockError(f"the main run was started on commit {lock['dail_commit']}, not this one")
    if lock["protocol_sha256"] != protocol_sha256:
        raise LockError("the main run was started under another protocol hash")
    return str(lock["experiment_id"])
