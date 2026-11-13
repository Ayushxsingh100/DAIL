"""The TerraPreserve dev labels (P8b; D5-11; TerraPreserve read-only, ADR-010, ADR-013).

Read for scoring only. The files are the ones ``experiments.loader`` verified for execution: the
manifest's SHA-256 must be the pin and every scenario.json must have the manifest's SHA-256, or
``LoaderError`` is raised. The test split is refused.

Per scenario: ``truth[k]`` is ``labels[k].invariant_truth`` (the oracle's result per invariant at
step k), ``oracle_affected[k]`` is ``labels[k].oracle_affected``, ``mutations`` are the
``mutation_record`` rows, ``gt_class`` the scenario class of D5-11; the tier and the cluster come
from ``source.tier`` (``real_world``, else ``controlled``) and from ``template_id`` (controlled) or
``source.repo_lineage_id`` (real-world), as C-214 defines the clusters. ``declared[k]`` is the set
of resource addresses (``type.name``) that the ``.tf`` files of step k declare with a top-level
``resource`` block: the identity truth uses it to tell a created or deleted resource from one that
only gains or loses an attribute.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from experiments.loader import DEV_SPLIT, MANIFEST_SHA256, REFUSED_SPLIT, LoaderError, sha256_hex


@dataclass(frozen=True)
class MutationRow:
    step: int
    operator: str
    target_address: str
    attribute: str
    before: str | None
    after: str | None


@dataclass(frozen=True)
class ScenarioLabels:
    scenario_id: str
    family: str
    kind: str
    target: str | None
    tier: str
    cluster: str
    gt_class: str | None
    truth: tuple[Mapping[str, str], ...]
    oracle_affected: tuple[frozenset[str], ...]
    mutations: tuple[MutationRow, ...]
    declared: tuple[frozenset[str], ...] = ()


_RESOURCE = re.compile(r'^resource\s+"([^"]+)"\s+"([^"]+)"', re.MULTILINE)


def declared_resources(directory: Path) -> frozenset[str]:
    """The ``type.name`` of every top-level ``resource`` block in the step's ``.tf`` files."""
    found: set[str] = set()
    for file in sorted(directory.rglob("*.tf")):
        for kind, name in _RESOURCE.findall(file.read_text(encoding="utf-8")):
            found.add(f"{kind}.{name}")
    return frozenset(found)


def _scenario(sid: str, doc: Mapping[str, Any], base: Path | None = None) -> ScenarioLabels:
    rows = sorted(doc["labels"], key=lambda r: r["step"])
    if [r["step"] for r in rows] != list(range(len(doc["steps"]))):
        raise LoaderError(f"{sid}: labels do not cover steps 0..n")
    source = doc.get("source") or {}
    real = source.get("tier") == "real_world"
    cluster = source.get("repo_lineage_id") if real else doc.get("template_id")
    if not isinstance(cluster, str):
        cluster = doc.get("template_id") or source.get("repo_lineage_id") or sid
    target = doc["target"]
    return ScenarioLabels(
        scenario_id=sid,
        family=doc["family"],
        kind=target["kind"],
        target=target.get("invariant_id"),
        tier="real_world" if real else "controlled",
        cluster=str(cluster),
        gt_class=doc.get("gt_class"),
        truth=tuple(MappingProxyType(dict(r["invariant_truth"])) for r in rows),
        oracle_affected=tuple(frozenset(r.get("oracle_affected") or ()) for r in rows),
        mutations=tuple(
            MutationRow(
                int(m["step"]),
                m["operator"],
                m["target_address"],
                m["attribute"],
                m.get("before"),
                m.get("after"),
            )
            for m in doc.get("mutation_record") or ()
        ),
        declared=(
            ()
            if base is None
            else tuple(
                declared_resources(base / step["terraform_dir"])
                for step in sorted(doc["steps"], key=lambda st: st["step"])
            )
        ),
    )


def load_labels(
    root: Path,
    scenario_ids: Iterable[str] | None = None,
    *,
    split: str = DEV_SPLIT,
    manifest_sha256: str = MANIFEST_SHA256,
    roles: Iterable[str] = ("target",),
) -> dict[str, ScenarioLabels]:
    """The labels of the wanted dev scenarios (all targets by default), hash-checked."""
    if split == REFUSED_SPLIT or split != DEV_SPLIT:
        raise LoaderError(f"split {split!r} is refused: scoring reads the dev split only")
    path = Path(root) / "scenarios" / "V1_MANIFEST.json"
    if not path.is_file():
        raise LoaderError(f"no TerraPreserve manifest at {path}")
    raw = path.read_bytes()
    if sha256_hex(raw) != manifest_sha256:
        raise LoaderError("the manifest sha256 is not the pin")
    wanted = None if scenario_ids is None else set(scenario_ids)
    found: dict[str, ScenarioLabels] = {}
    for entry in json.loads(raw)[DEV_SPLIT]:
        sid = entry["scenario_id"]
        if entry["v1_role"] not in set(roles) or (wanted is not None and sid not in wanted):
            continue
        file = Path(root) / "scenarios" / DEV_SPLIT / sid / "scenario.json"
        data = file.read_bytes()
        if sha256_hex(data) != entry["scenario_json_sha256"]:
            raise LoaderError(f"{sid}: scenario.json sha256 is not the manifest's")
        found[sid] = _scenario(sid, json.loads(data), file.parent)
    if wanted is not None and set(found) != wanted:
        raise LoaderError(f"no labels for {sorted(wanted - set(found))}")
    return dict(sorted(found.items()))
