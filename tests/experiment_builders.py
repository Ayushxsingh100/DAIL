"""Builders for the experiment-harness tests (P8a). Not a test module.

``mini_root`` writes a small TerraPreserve-layout tree into a temporary directory from the spec in
``tests/fixtures/terrapreserve_mini/scenarios.json``: ``scenarios/V1_MANIFEST.json`` and
``scenarios/dev/<scenario_id>/{scenario.json, step_0/, step_1/, ...}``. Step directories are copied
from DAIL's canonical fixtures (``main.tf`` and ``versions.tf`` only) with the spec's text edits.

The hashes are computed here, from the definition the work package quotes (D4-09): a step's
``content_hash`` is the SHA-256 of the newline-joined, path-sorted lines
``"<relative POSIX path>:<sha256 of the file's bytes>"``; ``scenario_json_sha256`` is the SHA-256 of
the file's bytes; the manifest pin is the SHA-256 of the manifest's bytes. Nothing is copied from
TerraPreserve.

The manifest also has a ``test`` list whose entry points at a directory that does not exist: a
loader that read the test split would fail. Label fields are filled with junk values; ``corrupt``
changes every one of them, for the blinding test.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tests.fixture_catalog import REPO_ROOT

SPEC = REPO_ROOT / "tests" / "fixtures" / "terrapreserve_mini" / "scenarios.json"
COPIED = ("main.tf", "versions.tf")
F2, F8, F1, F4, RESERVE, F8_BROKEN = (
    "tp-mini-F2-0001",
    "tp-mini-F8-0002",
    "tp-mini-F1-0003",
    "tp-mini-F4-0004",
    "tp-mini-F2-0005",
    "tp-mini-F8-0006",
)
TARGETS = (F1, F2, F4, F8, F8_BROKEN)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash(directory: Path) -> str:
    """D4-09, written from the quoted definition (independently of experiments.loader)."""
    files = sorted(
        (p.relative_to(directory).as_posix(), p) for p in directory.rglob("*") if p.is_file()
    )
    lines = [f"{rel}:{sha256(path.read_bytes())}" for rel, path in files]
    return sha256("\n".join(lines).encode("utf-8"))


def _labels(scenario: dict[str, Any], marker: str) -> dict[str, Any]:
    """Junk values in every field execution must never read."""
    steps = len(scenario["steps"])
    return {
        "labels": [
            {
                "step": k,
                "invariant_truth": {"INV-SEC-001": marker, "INV-FUNC-001": marker},
                "oracle_affected": [marker],
                "target_safe": marker,
            }
            for k in range(steps)
        ],
        "gt_class": f"gt-{marker}",
        "oracle": {"versions": {"oracle": marker}, "disagreements": [marker]},
        "mutation_record": [{"step": 1, "operator": marker}],
        "intent": {"class": marker, "breaks": [marker], "preserves": [marker]},
        "variable_values_alt": {"db_password": f"alt-{marker}"},
    }


@dataclass(frozen=True)
class MiniRoot:
    root: Path
    manifest_sha256: str


def mini_root(
    directory: Path,
    *,
    corrupt: bool = False,
    edit: Callable[[dict[str, Any]], None] | None = None,
) -> MiniRoot:
    """Write the mini TerraPreserve tree under ``directory`` and return its root and manifest pin.
    ``edit`` may change each scenario dict before it is written (and hashed)."""
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    dev = directory / "scenarios" / "dev"
    entries = []
    for item in spec["scenarios"]:
        sid = item["scenario_id"]
        base = dev / sid
        steps = []
        for k, step in enumerate(item["steps"]):
            target = base / f"step_{k}"
            target.mkdir(parents=True)
            for name in COPIED:
                text = (REPO_ROOT / step["from"] / name).read_text(encoding="utf-8")
                for old, new in step["edits"]:
                    if name == "main.tf":
                        assert text.count(old) == 1, (sid, k, old)
                        text = text.replace(old, new)
                (target / name).write_bytes(text.replace("\r\n", "\n").encode("utf-8"))
            steps.append(
                {
                    "step": k,
                    "terraform_dir": f"step_{k}",
                    "content_hash": content_hash(target),
                    "diff_from_previous": None,
                }
            )
        scenario: dict[str, Any] = {
            "dataset_version": "1.0",
            "scenario_id": sid,
            "family": item["family"],
            "split": "dev",
            "template_id": item["template_id"],
            "v1_role": item["v1_role"],
            "target": item["target"],
            "protected_invariants": [
                {"invariant_id": i, "version": "1.0"}
                for i in ("INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001")
            ],
            "endpoints": spec["endpoints"],
            "variable_values": {},
            "steps": steps,
            **_labels(item, "corrupted" if corrupt else "junk"),
        }
        if edit is not None:
            edit(scenario)
        raw = json.dumps(scenario, indent=1, sort_keys=True).encode("utf-8")
        (base / "scenario.json").write_bytes(raw)
        entries.append(
            {
                "scenario_id": sid,
                "scenario_json_sha256": sha256(raw),
                "steps": [{"step": s["step"], "content_hash": s["content_hash"]} for s in steps],
                "v1_role": item["v1_role"],
            }
        )
    manifest = {
        "dataset_version": "1.0",
        "decision": "P8a test data",
        "dev": entries,
        "test": [
            {
                "scenario_id": "tp-mini-T-9999",
                "scenario_json_sha256": "0" * 64,
                "steps": [{"step": 0, "content_hash": "0" * 64}],
                "v1_role": "target",
            }
        ],
    }
    raw = json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8")
    (directory / "scenarios" / "V1_MANIFEST.json").write_bytes(raw)
    return MiniRoot(directory, sha256(raw))


class TempDirs:
    """Temporary directories removed at cleanup."""

    def __init__(self) -> None:
        self._made: list[tempfile.TemporaryDirectory[str]] = []

    def new(self, prefix: str = "dail-p8a-") -> Path:
        made = tempfile.TemporaryDirectory(prefix=prefix)
        self._made.append(made)
        return Path(made.name)

    def close(self) -> None:
        for made in self._made:
            shutil.rmtree(made.name, ignore_errors=True)
            made.cleanup()
