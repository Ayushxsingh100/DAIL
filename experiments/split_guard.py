"""The test-split guard (P10e-prep decision 2; C-246).

The test split is opened only if all four hold, checked in this order:

1. the command is the main-run command (``python -m experiments.mainrun``; ``MAIN_RUN_COMMAND``);
2. ``git describe --exact-match --tags HEAD`` of the DAIL repository is ``protocol-v1``;
3. the working tree is clean (``git status --porcelain`` prints nothing);
4. ``$TERRAPRESERVE_PRIVATE`` holds ``V1_MANIFEST_PRIVATE.json`` whose SHA-256 is the pin
   (``PRIVATE_MANIFEST_SHA256``, TerraPreserve's ``scenarios/V1_MANIFEST.sha256`` at
   ``terrapreserve-v1.0``).

Otherwise ``GuardRefused`` is raised and nothing is read: checks 1 to 3 touch nothing under the
private directory, and check 4 reads only the manifest's bytes to hash them. On success the
verified bytes are handed back (``SplitAccess``), so the caller parses exactly what was checked.

The private directory is laid out as TerraPreserve's private package (D6-04): the manifest at its
root, with the key ``test``, and each scenario in ``<scenario_id>/`` at its root. TP-L2's labels of
the main run's LLM candidates are read from ``llm_candidates/test/<generation_id>/`` under it
(``tp_l2_dir``; C-252 (3)).

``repo_root`` and ``manifest_sha256`` exist for tests with a fake repository and a fake private
directory; the main-run command passes neither.
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

MAIN_RUN_COMMAND: Final = "main-run"
PROTOCOL_TAG: Final = "protocol-v1"
TEST_SPLIT: Final = "test"
PRIVATE_MANIFEST_NAME: Final = "V1_MANIFEST_PRIVATE.json"
PRIVATE_MANIFEST_SHA256: Final = "14ca1fff3af778a81d43f90e70a14cb7b56d6ebf5474648514169e8c2d376efe"
REPO_ROOT: Final = Path(__file__).resolve().parents[1]


class GuardRefused(Exception):
    """The test split may not be opened: nothing was read."""


@dataclass(frozen=True)
class SplitAccess:
    private_root: Path
    manifest_raw: bytes
    manifest_sha256: str
    dail_commit: str


def _read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def _git(repo: Path, *args: str) -> tuple[int, str]:
    try:
        done = subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
        )
    except OSError as error:
        return 1, str(error)
    return done.returncode, done.stdout.strip()


def _refuse(reason: str) -> GuardRefused:
    return GuardRefused(f"the test split is refused: {reason}")


def open_test_split(
    private_root: Path,
    *,
    command: str | None,
    repo_root: Path | None = None,
    manifest_sha256: str = PRIVATE_MANIFEST_SHA256,
) -> SplitAccess:
    if command != MAIN_RUN_COMMAND:
        raise _refuse(f"the command is {command!r}, not the main-run command")
    repo = REPO_ROOT if repo_root is None else Path(repo_root)
    code, tag = _git(repo, "describe", "--exact-match", "--tags", "HEAD")
    if code != 0 or tag != PROTOCOL_TAG:
        raise _refuse(f"HEAD is not tagged {PROTOCOL_TAG} ({tag if code == 0 else 'no tag'})")
    code, status = _git(repo, "status", "--porcelain")
    if code != 0 or status:
        raise _refuse("the working tree is not clean")
    path = Path(private_root) / PRIVATE_MANIFEST_NAME
    if not path.is_file():
        raise _refuse(f"no {PRIVATE_MANIFEST_NAME} in the private directory")
    raw = _read_bytes(path)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != manifest_sha256:
        raise _refuse(f"the private manifest sha256 {digest} is not the pin")
    code, commit = _git(repo, "rev-parse", "HEAD")
    if code != 0:
        raise _refuse("the DAIL commit cannot be read")
    return SplitAccess(Path(private_root), raw, digest, commit)


def tp_l2_dir(private_root: Path, generation_id: str) -> Path:
    """Where TP-L2 puts its labels of one main-run generation (C-252 (3))."""
    return Path(private_root) / "llm_candidates" / TEST_SPLIT / generation_id
