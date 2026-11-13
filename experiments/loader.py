"""The TerraPreserve loader (P8a; work package §3, §4.2; C-201, C-204; ADR-010, ADR-013).

Read only. It never imports, copies or runs TerraPreserve code; it reads the frozen files of a
TerraPreserve checkout: ``scenarios/V1_MANIFEST.json`` and ``scenarios/dev/<scenario_id>/
{scenario.json, step_0/, step_1/, ...}`` (D4-09).

**Checks, all before anything is returned** (one failure raises ``LoaderError`` and nothing partial
comes back, so a mismatch stops the run before any trial starts):

1. the split is ``dev``; ``test`` is refused (the test split is touched once, in P10, after the
   protocol is frozen), and so is anything else;
2. the SHA-256 of the manifest's bytes is the pin (``MANIFEST_SHA256`` for TerraPreserve v1.0);
3. for every manifest entry of the split with a wanted ``v1_role`` (``target`` by default): the
   SHA-256 of ``scenario.json`` is the manifest's ``scenario_json_sha256``; the scenario names
   itself and the ``dev`` split; its steps are 0..n in order, the same as the manifest's; every
   step's ``content_hash``, recomputed here from the definition of D4-09, equals both the manifest's
   and the scenario's.

**What execution gets** (``ScenarioInput``): the scenario id, family, split, template id or source
lineage id (a real-world scenario has no template), the step directories and hashes, the target's
kind and invariant id, the protected invariants, the two endpoints and the primary variable values.
The loader reads exactly those keys and nothing else of a scenario; the manifest's list of the
other split is never indexed.

``content_hash`` (D4-09): the SHA-256 of the newline-joined, path-sorted lines
``"<relative POSIX path>:<sha256 of the file's bytes>"`` of the step directory (no
trailing newline).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

MANIFEST_SHA256: Final = "665b326a024d295f727cd5648ffc7e0d375b9300584871f238c6bfa48edd2e2d"
TERRAPRESERVE_TAG: Final = "terrapreserve-v1.0"
DEV_SPLIT: Final = "dev"
REFUSED_SPLIT: Final = "test"
# C-201: the admission evidence of a step of the pinned v1.0 manifest (TerraPreserve D6 gate 2).
D6_VALIDATE_EVIDENCE: Final = (
    "terraform validate PASS at TerraPreserve D6 gate 2 (docs/D6_GATES.md: Terraform 1.15.8, "
    "hashicorp/aws 6.53.0, every step of every target); not run by DAIL (C-201)"
)
NO_VALIDATE_EVIDENCE: Final = (
    "no terraform validate evidence: the manifest is not the pinned TerraPreserve v1.0 manifest"
)


class LoaderError(Exception):
    """The TerraPreserve input cannot be used: nothing was loaded (an input failure)."""


@dataclass(frozen=True)
class StepInput:
    """One step of a scenario: its directory and its verified content hash."""

    index: int
    directory: Path
    content_hash: str


@dataclass(frozen=True)
class ScenarioInput:
    """Everything trial execution may know about a scenario (work package §4.2)."""

    scenario_id: str
    family: str
    split: str
    template_id: str | None
    source_lineage_id: str | None
    target_kind: str
    target_invariant_id: str | None
    protected_invariants: tuple[tuple[str, str], ...]
    source_endpoint: str
    destination_endpoint: str
    variable_values: Mapping[str, Any]
    steps: tuple[StepInput, ...]

    @property
    def transitions(self) -> int:
        """The number of steps after S0."""
        return len(self.steps) - 1


@dataclass(frozen=True)
class FixtureRecord:
    """The hashes of one scenario, for the experiment's fixture record (Doc 13 §40)."""

    scenario_id: str
    scenario_json_sha256: str
    step_hashes: tuple[str, ...]
    v1_role: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_json_sha256": self.scenario_json_sha256,
            "step_hashes": list(self.step_hashes),
            "v1_role": self.v1_role,
        }


@dataclass(frozen=True)
class LoadedSet:
    """A verified load: the scenarios for execution and the fixture hashes for the record."""

    root: Path
    split: str
    manifest_sha256: str
    scenarios: tuple[ScenarioInput, ...]
    fixtures: tuple[FixtureRecord, ...]
    admission_evidence: str


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def step_content_hash(directory: Path) -> str:
    """D4-09 (see the module docstring). Refuses a symbolic link."""
    entries: list[tuple[str, Path]] = []
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise LoaderError(f"{directory}: symbolic link {path.name} is refused")
        if path.is_file():
            entries.append((path.relative_to(directory).as_posix(), path))
    entries.sort(key=lambda entry: entry[0])
    lines = [f"{relative}:{sha256_hex(path.read_bytes())}" for relative, path in entries]
    return sha256_hex("\n".join(lines).encode("utf-8"))


def _take(data: object, key: str, kind: type | tuple[type, ...], where: str) -> Any:
    if not isinstance(data, Mapping) or key not in data:
        raise LoaderError(f"{where}: no {key!r}")
    value = data[key]
    if not isinstance(value, kind):
        raise LoaderError(f"{where}: {key!r} has the wrong type")
    return value


def _steps(sid: str, base: Path, listed: object, manifest_steps: object) -> tuple[StepInput, ...]:
    if not isinstance(listed, list) or not isinstance(manifest_steps, list) or not listed:
        raise LoaderError(f"{sid}: steps must be a non-empty list in the scenario and the manifest")
    if len(listed) != len(manifest_steps):
        raise LoaderError(f"{sid}: the scenario and the manifest list different steps")
    found = []
    for k, (step, pinned) in enumerate(zip(listed, manifest_steps, strict=True)):
        where = f"{sid} step {k}"
        if _take(step, "step", int, where) != k or _take(pinned, "step", int, where) != k:
            raise LoaderError(f"{where}: steps must be 0..n in order")
        name = _take(step, "terraform_dir", str, where)
        directory = base / name
        if Path(name).name != name or not directory.is_dir():
            raise LoaderError(f"{where}: step directory {name!r} is missing or not inside it")
        recomputed = step_content_hash(directory)
        claimed = _take(step, "content_hash", str, where)
        manifest_hash = _take(pinned, "content_hash", str, where)
        if not recomputed == claimed == manifest_hash:
            raise LoaderError(
                f"{where}: content_hash mismatch (recomputed {recomputed}, scenario {claimed}, "
                f"manifest {manifest_hash})"
            )
        found.append(StepInput(k, directory, recomputed))
    return tuple(found)


def _scenario(root: Path, split: str, entry: object) -> tuple[ScenarioInput, FixtureRecord]:
    sid = _take(entry, "scenario_id", str, "manifest entry")
    role = _take(entry, "v1_role", str, sid)
    base = root / "scenarios" / split / sid
    path = base / "scenario.json"
    if Path(sid).name != sid or not path.is_file():
        raise LoaderError(f"{sid}: scenario.json is missing")
    raw = path.read_bytes()
    pinned = _take(entry, "scenario_json_sha256", str, sid)
    if sha256_hex(raw) != pinned:
        raise LoaderError(f"{sid}: scenario.json sha256 is not the manifest's")
    try:
        doc = json.loads(raw)
    except ValueError as error:
        raise LoaderError(f"{sid}: scenario.json is not JSON: {error}") from None
    if _take(doc, "scenario_id", str, sid) != sid:
        raise LoaderError(f"{sid}: scenario.json names another scenario")
    if _take(doc, "split", str, sid) != split:
        raise LoaderError(f"{sid}: scenario.json is not in the {split} split")
    target = _take(doc, "target", dict, sid)
    endpoints = _take(doc, "endpoints", dict, sid)
    protected = []
    for item in _take(doc, "protected_invariants", list, sid):
        protected.append((_take(item, "invariant_id", str, sid), _take(item, "version", str, sid)))
    target_invariant = _take(target, "invariant_id", (str, type(None)), f"{sid} target")
    steps = _steps(sid, base, _take(doc, "steps", list, sid), _take(entry, "steps", list, sid))
    values = _take(doc, "variable_values", dict, sid)
    # a generated scenario names its template, a real-world one its source repository's lineage
    template = doc.get("template_id")
    source = doc.get("source")
    lineage = source.get("repo_lineage_id") if isinstance(source, Mapping) else None
    if not isinstance(template, str | None) or not isinstance(lineage, str | None):
        raise LoaderError(f"{sid}: template_id and source.repo_lineage_id must be text")
    if template is None and lineage is None:
        raise LoaderError(f"{sid}: neither a template_id nor a source.repo_lineage_id")
    scenario = ScenarioInput(
        scenario_id=sid,
        family=_take(doc, "family", str, sid),
        split=split,
        template_id=template,
        source_lineage_id=lineage,
        target_kind=_take(target, "kind", str, f"{sid} target"),
        target_invariant_id=target_invariant,
        protected_invariants=tuple(sorted(protected)),
        source_endpoint=_take(endpoints, "S", str, f"{sid} endpoints"),
        destination_endpoint=_take(endpoints, "D", str, f"{sid} endpoints"),
        variable_values=MappingProxyType(dict(values)),
        steps=steps,
    )
    fixture = FixtureRecord(sid, pinned, tuple(s.content_hash for s in steps), role)
    return scenario, fixture


def load(
    root: Path,
    *,
    split: str = DEV_SPLIT,
    manifest_sha256: str = MANIFEST_SHA256,
    roles: Iterable[str] = ("target",),
) -> LoadedSet:
    """Load and verify the ``split`` scenarios of the TerraPreserve checkout at ``root`` (see the
    module docstring). Raises ``LoaderError`` on any refusal or mismatch."""
    if split == REFUSED_SPLIT:
        raise LoaderError(
            "the test split is refused: it is read once, in P10, after the protocol is frozen"
        )
    if split != DEV_SPLIT:
        raise LoaderError(f"split {split!r} is refused: only {DEV_SPLIT!r} is read in P8")
    wanted = frozenset(roles)
    manifest = Path(root) / "scenarios" / "V1_MANIFEST.json"
    if not manifest.is_file():
        raise LoaderError(f"no TerraPreserve manifest at {manifest}")
    raw = manifest.read_bytes()
    digest = sha256_hex(raw)
    if digest != manifest_sha256:
        raise LoaderError(f"the manifest sha256 {digest} is not the pinned {manifest_sha256}")
    try:
        data = json.loads(raw)
    except ValueError as error:
        raise LoaderError(f"the manifest is not JSON: {error}") from None
    entries = _take(data, split, list, "manifest")
    scenarios, fixtures = [], []
    for entry in entries:
        if _take(entry, "v1_role", str, "manifest entry") not in wanted:
            continue
        scenario, fixture = _scenario(Path(root), split, entry)
        scenarios.append(scenario)
        fixtures.append(fixture)
    ids = [s.scenario_id for s in scenarios]
    if len(set(ids)) != len(ids):
        raise LoaderError("the manifest lists a scenario twice")
    order = sorted(range(len(ids)), key=lambda n: ids[n])
    return LoadedSet(
        root=Path(root),
        split=split,
        manifest_sha256=digest,
        scenarios=tuple(scenarios[n] for n in order),
        fixtures=tuple(fixtures[n] for n in order),
        admission_evidence=(
            D6_VALIDATE_EVIDENCE if digest == MANIFEST_SHA256 else NO_VALIDATE_EVIDENCE
        ),
    )
