"""Export valid LLM candidates for the oracle (P10a Section 3.3 "Export for the oracle"; P7b verdict
limit 6).

"For every valid candidate, a configuration-only directory (the built ``.tf`` files and nothing
else) plus an ``oracle_export.json`` with ids and hashes. TerraPreserve labels these in its own
package; DAIL never labels them."

Each valid frozen candidate is rebuilt from the frozen reply by the patch validator on the
configuration-only copy of S0 (the parent is built again with the same name-based ids, so it is the
parent the candidate was generated against: its state id is checked), the rebuilt tree hash is
checked against the frozen one, the ``.tf`` files of the build are copied, and the build is deleted.
A candidate whose rebuild differs, or whose build holds a file that is not ``.tf``, is listed under
``refused`` and not exported. ``content_hash`` of an exported directory is computed as
TerraPreserve's step hash (D4-09, ``experiments.loader.step_content_hash``).

Output, written once: ``<root>/candidates/<generation_id>/oracle_export/oracle_export.json`` and one
directory per candidate, ``<model>/<scenario_id>/<k>/``, beside it.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from experiments.artifacts import read_record, write_record
from experiments.generation.parent import s0_parent
from experiments.generation.run import (
    MANIFEST,
    attempt_dir,
    frozen_response_text,
    generation_dir,
    read_manifest,
    sha256_file,
)
from experiments.generation.task import GenerationError, GenerationInput, change_scope
from experiments.loader import step_content_hash
from experiments.trial import DAIL_CLOCK_BASE
from llm.validation.parser import parse_response
from llm.validation.patch import PatchValidator

EXPORT_INDEX = "oracle_export.json"


def _rebuild(
    given: GenerationInput, frozen: dict[str, Any], reply: str, request_id: str, work: Path
) -> tuple[Path | None, str | None, str | None]:
    """(the built directory, its tree hash, why it was refused)."""
    parent = s0_parent(given, work / "parent", "generation")
    if parent.state.state_id != frozen["parent"]["state_id"]:
        return None, None, "the rebuilt S0 is not the frozen parent"
    parsed = parse_response(reply)
    if parsed.response is None or parsed.failure_class is not None:
        return None, None, "the frozen reply does not parse"
    outcome = PatchValidator(
        parent_dir=parent.directory,
        trusted=parent.state,
        scope=change_scope(parent.state.resources),
        work_root=work / "builds",
        variables=dict(given.variable_values),
        now=DAIL_CLOCK_BASE,
    ).validate(parsed.response, request_id=request_id, patch_id=frozen["patch_id"])
    if outcome.build is None:
        return None, None, f"the validator refused the rebuild: {list(outcome.errors)}"
    return outcome.build.candidate_dir, outcome.build.tree_hash, None


def export_for_oracle(*, root: Path, generation_id: str, inputs: Sequence[GenerationInput]) -> Path:
    manifest = read_manifest(root, generation_id)
    base = generation_dir(root, generation_id)
    out = base / "oracle_export"
    if (out / EXPORT_INDEX).exists():
        raise GenerationError(f"{out / EXPORT_INDEX} exists; an export is written once")
    by_id = {g.scenario_id: g for g in inputs}
    exported: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for row in manifest["attempts"]:
        if row["status"] != "PATCH":
            continue
        given = by_id.get(row["scenario_id"])
        if given is None:
            raise GenerationError(f"{row['scenario_id']}: no generation input given")
        k = int(row["k"])
        folder = attempt_dir(base, row["model_key"], row["scenario_id"], k)
        frozen = read_record(folder / "attempt.json")
        reply, request_id = frozen_response_text(folder, frozen)
        ident = {"model_key": row["model_key"], "scenario_id": row["scenario_id"], "k": k}
        with tempfile.TemporaryDirectory(prefix="dail-p10a-export-") as tmp:
            built, digest, why = _rebuild(given, frozen, reply, request_id, Path(tmp))
            if built is not None and digest != frozen["candidate_tree_hash"]:
                why = "the rebuilt tree hash is not the frozen one"
            files = [] if built is None else sorted(p for p in built.rglob("*") if p.is_file())
            others = [p.name for p in files if not p.name.endswith(".tf")]
            if built is not None and others:
                why = f"the build holds files that are not .tf: {others}"
            if why is not None:
                refused.append({**ident, "reason": why})
                continue
            assert built is not None
            target = out / row["model_key"] / row["scenario_id"] / str(k)
            target.mkdir(parents=True)
            for path in files:
                if path.parent != built:
                    raise GenerationError(f"{path}: a built file outside the top level")
                shutil.copyfile(path, target / path.name)
            shutil.rmtree(built.parent, ignore_errors=True)
        exported.append(
            {
                "candidate_id": f"{generation_id}/{row['model_key']}/{row['scenario_id']}/{k}",
                "generation_id": generation_id,
                **ident,
                "family": row["family"],
                "model_tag": frozen["model_tag"],
                "model_digest": frozen["model_digest"],
                "s0_content_hash": frozen["parent"]["s0_content_hash"],
                "parent_state_id": frozen["parent"]["state_id"],
                "patch_sha256": frozen["patch_sha256"],
                "patch_id": frozen["patch_id"],
                "tree_hash": digest,
                "content_hash": step_content_hash(target),
                "directory": target.relative_to(out).as_posix(),
                "files": {p.name: sha256_file(p) for p in sorted(target.iterdir())},
            }
        )
    return write_record(
        out / EXPORT_INDEX,
        {
            "record": "oracle_export",
            "generation_id": generation_id,
            "candidates_manifest_sha256": sha256_file(base / MANIFEST),
            "candidates": exported,
            "refused": refused,
        },
    )
