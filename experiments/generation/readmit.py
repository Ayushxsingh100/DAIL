"""Re-admission of frozen candidates through the ``terraform validate`` gate (P10c Section 3.3;
C-227).

"A scoring step applies the validate gate to every frozen valid candidate of the three pilot
generations, through the real runner ... It records the result beside the frozen record. Frozen
files are never edited. Report valid patch rates before and after the gate, per model."

For every attempt the manifest lists as PATCH (valid under validator 1 or 2, before the gate), the
candidate is rebuilt from the frozen reply by the patch validator on the configuration-only S0 (as
``experiments.generation.export`` does), its tree hash is checked against the frozen one, the
caller's runner validates the build, and the build is deleted. Nothing is regenerated and no frozen
file is touched: the results are written once to
``<root>/candidates/<generation_id>/validate_gate/<name>/validate_gate.json``. A rebuild that does
not match the frozen tree hash is recorded and not validated.

Rates per model: ``before`` = PATCH attempts / attempts; ``after`` = attempts whose rebuilt
candidate passes ``terraform validate`` / attempts.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from experiments.artifacts import read_record, write_record
from experiments.generation.parent import s0_parent
from experiments.generation.run import (
    GenerationError,
    attempt_dir,
    frozen_response_text,
    generation_dir,
    read_manifest,
    sha256_file,
)
from experiments.generation.task import GenerationInput, change_scope
from experiments.trial import DAIL_CLOCK_BASE
from llm.validation.parser import parse_response
from llm.validation.patch import VALIDATOR_VERSION, PatchValidator, TerraformValidate


@dataclass(frozen=True)
class ReadmitSummary:
    path: Path
    results: list[dict[str, Any]]
    rates: dict[str, dict[str, Any]]


def _rate(k: int, n: int) -> dict[str, Any]:
    return {"numerator": k, "denominator": n, "value": None if n == 0 else k / n}


def _gate(
    given: GenerationInput,
    frozen: Mapping[str, Any],
    reply: str,
    request_id: str,
    terraform: TerraformValidate,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="dail-p10c-readmit-") as tmp:
        work = Path(tmp)
        parent = s0_parent(given, work / "parent", "generation")
        if parent.state.state_id != frozen["parent"]["state_id"]:
            return {"rebuild": "the rebuilt S0 is not the frozen parent"}
        parsed = parse_response(reply)
        if parsed.response is None or parsed.failure_class is not None:
            return {"rebuild": "the frozen reply does not parse"}
        outcome = PatchValidator(
            parent_dir=parent.directory,
            trusted=parent.state,
            scope=change_scope(parent.state.resources),
            work_root=work / "builds",
            variables=dict(given.variable_values),
            now=DAIL_CLOCK_BASE,
        ).validate(parsed.response, request_id=request_id, patch_id=frozen["patch_id"])
        if outcome.build is None:
            return {"rebuild": f"the validator refused the rebuild: {list(outcome.errors)}"}
        build = outcome.build
        try:
            result: dict[str, Any] = {
                "rebuild": "ok",
                "rebuilt_tree_hash": build.tree_hash,
                "tree_hash_matches": build.tree_hash == frozen["candidate_tree_hash"],
            }
            if result["tree_hash_matches"]:
                check = terraform(build.candidate_dir)
                result.update(
                    validate_ok=check.ok, validate_error=check.error, versions=dict(check.versions)
                )
            return result
        finally:
            shutil.rmtree(build.candidate_dir.parent, ignore_errors=True)


def readmit(
    *,
    root: Path,
    generation_id: str,
    inputs: Mapping[str, GenerationInput],
    terraform: TerraformValidate | None,
    name: str,
) -> ReadmitSummary:
    if terraform is None:
        raise GenerationError("re-admission needs a terraform validate runner (C-227)")
    manifest = read_manifest(root, generation_id)
    base = generation_dir(root, generation_id)
    out = base / "validate_gate" / name
    if out.exists():
        raise GenerationError(f"{out} exists; a re-admission is written once")
    results: list[dict[str, Any]] = []
    counts: dict[str, list[int]] = {}
    for row in manifest["attempts"]:
        cell = counts.setdefault(row["model_key"], [0, 0, 0])  # attempts, PATCH, validate-valid
        cell[0] += 1
        if row["status"] != "PATCH":
            continue
        cell[1] += 1
        given = inputs.get(row["scenario_id"])
        if given is None:
            raise GenerationError(f"{row['scenario_id']}: no generation input given")
        k = int(row["k"])
        folder = attempt_dir(base, row["model_key"], row["scenario_id"], k)
        frozen = read_record(folder / "attempt.json")
        reply, request_id = frozen_response_text(folder, frozen)
        gate = _gate(given, frozen, reply, request_id, terraform)
        record = {
            "model_key": row["model_key"],
            "scenario_id": row["scenario_id"],
            "family": row["family"],
            "k": k,
            "frozen_status": row["status"],
            "frozen_validator_version": frozen["observability"]["validator_version"],
            "frozen_tree_hash": frozen["candidate_tree_hash"],
            "attempt_sha256": sha256_file(folder / "attempt.json"),
            "tree_hash_matches": False,
            "validate_ok": None,
            "validate_error": None,
            **gate,
        }
        cell[2] += bool(record["validate_ok"])
        results.append(record)
    rates = {
        model: {"attempts": n, "before": _rate(p, n), "after": _rate(v, n)}
        for model, (n, p, v) in sorted(counts.items())
    }
    path = write_record(
        out / "validate_gate.json",
        {
            "record": "validate_gate",
            "generation_id": generation_id,
            "name": name,
            "gate": "C-227",
            "validator_version": VALIDATOR_VERSION,
            "candidates_manifest_sha256": sha256_file(base / "candidates_manifest.json"),
            "runner": getattr(terraform, "versions", None) and dict(terraform.versions),  # type: ignore[attr-defined]
            "rates": rates,
            "results": results,
        },
    )
    return ReadmitSummary(path, results, rates)
