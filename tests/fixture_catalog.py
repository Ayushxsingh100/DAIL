"""Loader and checker for the canonical fixtures (D2 step 6, Package 2).

Doc 12 §5-§7; Doc 15 §21 "basic fixture loading".

Standard library plus ``core.domain.enums``. Not a test module.

Every ``fixtures/**/expected.json`` is hand-written data (schema ``dail-fixture-expected/1``, C-89).
This module only parses it, checks its structure strictly and checks that the values agree with
each other. It never computes an expected value, and nothing here writes a fixture file.

All functions take ``repo_root`` so that the tests can run them on a corrupted copy of the fixtures.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.domain.enums import ChangeType, DecisionType, IdentityStatus, VerificationResult

REPO_ROOT = Path(__file__).resolve().parents[1]

SCHEMA = "dail-fixture-expected/1"
REGISTRY = {
    "tag": "registry-v1.0",
    "commit": "80d161ded595f26b7a339d3351ba335434d7ee32",
    "invariant_registry_version": 1,
}
DERIVATION = (
    "Hand-derived from registry-v1.0 and Docs 07-09 by the external reviewer, 24 Oct 2026; "
    "not computed."
)

SEC1, SEC2, SEC3, FUNC = "INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"
INVARIANTS = (FUNC, SEC1, SEC2, SEC3)  # sorted
BINDINGS = {FUNC: {"S": "aws_instance.app", "D": "aws_db_instance.database"}}

TOP_KEYS = (
    "schema",
    "fixture_id",
    "doc12_fixture",
    "kind",
    "registry",
    "config",
    "parent",
    "parent_remediation_targets",
    "bindings",
    "results",
    "changes",
    "impact",
    "decision",
    "baseline",
    "process",
    "derivation",
)
KINDS = ("baseline", "transition", "process")
ID_PATTERN = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)+_v[0-9]+$")
PROVIDER_BLOCK = re.compile(r'^\s*provider\s+"', re.MULTILINE)

DOC12_NAMES = (
    "baseline_safe",
    "safe_repair",
    "security_repair_breaks_function",
    "public_ssh_repair",
    "public_ssh_violation",
    "functional_reachable",
    "functional_broken",
    "created_resource",
    "deleted_dependency",
    "replacement_resource",
    "ambiguous_identity",
    "unknown_dependency",
    "unsupported_relationship",
    "stale_parent",
    "verifier_error",
)
EXPECTED_FIXTURE_COUNT = 20

RESULT_VALUES = {m.value for m in VerificationResult}
CHANGE_VALUES = {m.value for m in ChangeType}
DECISION_VALUES = {m.value for m in DecisionType}
IDENTITY_VALUES = {
    IdentityStatus.SAME.value,
    IdentityStatus.UNCERTAIN.value,
}  # null is allowed for CREATED/DELETED
NOT_A_PASS = {"UNKNOWN", "UNSUPPORTED", "VERIFIER_ERROR"}
CLAUSE_VALUES = {"PASS", "FAIL", "UNKNOWN", "UNSUPPORTED"}
PROCESS_KINDS = ("stale_parent", "verifier_fault")


@dataclass(frozen=True)
class Fixture:
    folder: str  # path of the fixture folder relative to the repository root, with forward slashes
    data: dict[str, Any]

    @property
    def fixture_id(self) -> str:
        return str(self.data["fixture_id"])


def fixtures_dir(repo_root: Path) -> Path:
    return repo_root / "fixtures"


def load_all(repo_root: Path = REPO_ROOT) -> dict[str, Fixture]:
    """Parse every ``fixtures/**/expected.json``; the key is the fixture folder (repo-relative)."""
    found: dict[str, Fixture] = {}
    for path in sorted(fixtures_dir(repo_root).rglob("expected.json")):
        folder = path.parent.relative_to(repo_root).as_posix()
        found[folder] = Fixture(folder, json.loads(path.read_text(encoding="utf-8")))
    return found


# ---------------------------------------------------------------- structure (one fixture)
def _is_sorted_invariants(value: Any) -> bool:
    return (
        isinstance(value, list)
        and value == sorted(value)
        and set(value) <= set(INVARIANTS)
        and len(set(value)) == len(value)
    )


def structure_problems(folder: str, data: Any) -> list[str]:
    """Strict check of one expected.json; unknown or missing keys fail."""
    where = f"{folder}/expected.json"
    if not isinstance(data, dict):
        return [f"{where}: not a JSON object"]
    problems: list[str] = []
    if tuple(data) != TOP_KEYS:
        missing = [k for k in TOP_KEYS if k not in data]
        extra = [k for k in data if k not in TOP_KEYS]
        problems.append(
            f"{where}: keys differ from the schema "
            f"(missing {missing}, unknown {extra}, or wrong order)"
        )
        return problems
    if data["schema"] != SCHEMA:
        problems.append(f"{where}: schema {data['schema']!r}")
    fid = data["fixture_id"]
    if not (isinstance(fid, str) and ID_PATTERN.match(fid)):
        problems.append(f"{where}: fixture_id {fid!r} does not match the Doc 12 §6 pattern")
    if data["doc12_fixture"] is not None and data["doc12_fixture"] not in DOC12_NAMES:
        problems.append(f"{where}: doc12_fixture {data['doc12_fixture']!r} is not a Doc 12 §7 name")
    kind = data["kind"]
    if kind not in KINDS:
        problems.append(f"{where}: kind {kind!r}")
    if data["registry"] != REGISTRY:
        problems.append(f"{where}: registry must be {REGISTRY}")
    if not isinstance(data["config"], str):
        problems.append(f"{where}: config must be a path")
    if kind == "baseline" and data["parent"] is not None:
        problems.append(f"{where}: a baseline has no parent")
    if kind in ("transition", "process") and not isinstance(data["parent"], str):
        problems.append(f"{where}: a {kind} needs a parent path")
    if not _is_sorted_invariants(data["parent_remediation_targets"]):
        problems.append(
            f"{where}: parent_remediation_targets must be a sorted list of invariant ids"
        )
    if data["bindings"] != BINDINGS:
        problems.append(f"{where}: bindings must be {BINDINGS}")
    problems += _results_problems(where, data["results"])
    problems += _changes_problems(where, kind, data["changes"])
    problems += _impact_problems(where, kind, data["impact"])
    problems += _decision_problems(where, kind, data["decision"])
    problems += _baseline_process_problems(where, kind, data["baseline"], data["process"])
    if data["derivation"] != DERIVATION:
        problems.append(f"{where}: derivation text differs from the schema")
    return problems


def _results_problems(where: str, results: Any) -> list[str]:
    if not isinstance(results, dict) or set(results) != set(INVARIANTS):
        return [f"{where}: results must have exactly the four invariants"]
    problems: list[str] = []
    for inv in INVARIANTS:
        entry = results[inv]
        has_clauses = inv in (SEC1, SEC2)
        expected_keys = ["invariant_version", "result", "basis"] + (
            ["clauses"] if has_clauses else []
        )
        if not isinstance(entry, dict) or list(entry) != expected_keys:
            problems.append(f"{where}: results[{inv}] keys must be {expected_keys}")
            continue
        if entry["invariant_version"] != 1:
            problems.append(f"{where}: results[{inv}].invariant_version must be 1")
        if entry["result"] not in RESULT_VALUES:
            problems.append(
                f"{where}: results[{inv}].result {entry['result']!r} is not a VerificationResult"
            )
        if not (isinstance(entry["basis"], str) and "§" in entry["basis"]):
            problems.append(f"{where}: results[{inv}].basis must cite a registry section")
        if has_clauses:
            clauses = entry["clauses"]
            if not (
                isinstance(clauses, dict)
                and list(clauses) == ["ipv4", "ipv6"]
                and set(clauses.values()) <= CLAUSE_VALUES
            ):
                problems.append(f"{where}: results[{inv}].clauses must be ipv4 and ipv6 results")
            elif "FAIL" in clauses.values():
                if entry["result"] != "FAIL":
                    problems.append(
                        f"{where}: results[{inv}]: a FAIL clause makes the result FAIL "
                        "(registry §3.4)"
                    )
            elif set(clauses.values()) == {"PASS"} and entry["result"] != "PASS":
                problems.append(
                    f"{where}: results[{inv}]: two PASS clauses make the result PASS "
                    "(registry §3.4)"
                )
    return problems


def _changes_problems(where: str, kind: str, changes: Any) -> list[str]:
    if kind == "baseline":
        return [] if changes is None else [f"{where}: a baseline has changes: null"]
    if (
        not isinstance(changes, dict)
        or list(changes) != ["default", "resources"]
        or changes["default"] != "UNCHANGED"
    ):
        return [f"{where}: changes must be {{default: UNCHANGED, resources: ...}}"]
    resources = changes["resources"]
    if not isinstance(resources, dict) or not resources or list(resources) != sorted(resources):
        return [f"{where}: changes.resources must be a non-empty object with sorted addresses"]
    problems: list[str] = []
    for address, entry in resources.items():
        if not (isinstance(entry, dict) and list(entry) == ["identity", "change"]):
            problems.append(f"{where}: changes[{address}] must have identity and change")
            continue
        identity, change = entry["identity"], entry["change"]
        if change not in CHANGE_VALUES or change == "UNCHANGED":
            problems.append(
                f"{where}: changes[{address}].change {change!r} "
                "(UNCHANGED resources are not listed)"
            )
        if identity is not None and identity not in IDENTITY_VALUES:
            problems.append(f"{where}: changes[{address}].identity {identity!r}")
        if (identity is None) != (change in ("CREATED", "DELETED")):
            problems.append(
                f"{where}: changes[{address}]: identity is null exactly for CREATED and DELETED"
            )
    return problems


def _impact_problems(where: str, kind: str, impact: Any) -> list[str]:
    if kind == "baseline":
        return [] if impact is None else [f"{where}: a baseline has impact: null"]
    keys = ["truth_changed", "oracle_affected", "required_affected"]
    if not (isinstance(impact, dict) and list(impact) == keys):
        return [f"{where}: impact must have {keys}"]
    return [
        f"{where}: impact.{k} must be a sorted list of invariant ids"
        for k in keys
        if not _is_sorted_invariants(impact[k])
    ]


def _decision_problems(where: str, kind: str, decision: Any) -> list[str]:
    if kind == "baseline":
        return [] if decision is None else [f"{where}: a baseline has decision: null"]
    if not (isinstance(decision, dict) and list(decision) == ["allowed", "reason"]):
        return [f"{where}: decision must have allowed and reason"]
    problems: list[str] = []
    allowed = decision["allowed"]
    if not (
        isinstance(allowed, list)
        and allowed
        and len(set(allowed)) == len(allowed)
        and set(allowed) <= DECISION_VALUES
    ):
        problems.append(
            f"{where}: decision.allowed must be a non-empty list of DecisionType values"
        )
    if not (isinstance(decision["reason"], str) and "Doc 09 §" in decision["reason"]):
        problems.append(f"{where}: decision.reason must cite a Doc 09 section")
    return problems


def _baseline_process_problems(where: str, kind: str, baseline: Any, process: Any) -> list[str]:
    problems: list[str] = []
    if kind == "baseline":
        ok = (
            isinstance(baseline, dict)
            and list(baseline) == ["eligible", "remediation_targets"]
            and baseline["eligible"] is True
            and _is_sorted_invariants(baseline["remediation_targets"])
        )
        if not ok:
            problems.append(
                f"{where}: a baseline needs "
                "baseline: {eligible: true, remediation_targets: [...]}"
            )
    elif baseline is not None:
        problems.append(f"{where}: only a baseline has a baseline object")
    if kind == "process":
        if not (
            isinstance(process, dict)
            and process.get("kind") in PROCESS_KINDS
            and isinstance(process.get("note"), str)
        ):
            problems.append(f"{where}: a process fixture needs a process descriptor")
        elif process["kind"] == "stale_parent" and not isinstance(
            process.get("trusted_current_from"), str
        ):
            problems.append(f"{where}: a stale_parent descriptor needs trusted_current_from")
        elif process["kind"] == "verifier_fault":
            override = process.get("results_override")
            if not (
                isinstance(override, dict)
                and override
                and set(override) <= set(INVARIANTS)
                and set(override.values()) <= RESULT_VALUES
                and process.get("invariant") in INVARIANTS
            ):
                problems.append(
                    f"{where}: a verifier_fault descriptor needs invariant and results_override"
                )
    elif process is not None:
        problems.append(f"{where}: only a process fixture has a process descriptor")
    return problems


# ---------------------------------------------------------------- terraform files
def terraform_roots(repo_root: Path) -> list[str]:
    """Fixture folders (repo-relative) that contain ``*.tf`` files."""
    return sorted(
        {p.parent.relative_to(repo_root).as_posix() for p in fixtures_dir(repo_root).rglob("*.tf")}
    )


def terraform_problems(repo_root: Path, fixtures: dict[str, Fixture]) -> list[str]:
    problems: list[str] = []
    configs = {f.data["config"] for f in fixtures.values() if isinstance(f.data.get("config"), str)}
    for folder, fx in fixtures.items():
        config = fx.data.get("config")
        if not isinstance(config, str):
            continue
        root = repo_root / config
        for name in ("main.tf", "versions.tf", ".terraform.lock.hcl"):
            if not (root / name).is_file():
                problems.append(f"{folder}: config {config} has no {name}")
        has_own_tf = any((repo_root / folder).glob("*.tf"))
        if has_own_tf and config != folder:
            problems.append(f"{folder}: has its own .tf files, so config must be its own folder")
        if not has_own_tf and config == folder:
            problems.append(f"{folder}: config points to itself but the folder has no .tf files")
    for root in terraform_roots(repo_root):
        if root not in configs:
            problems.append(f"{root}: a Terraform root that no fixture references")
    for path in sorted(fixtures_dir(repo_root).rglob("*.tf")):
        if PROVIDER_BLOCK.search(path.read_text(encoding="utf-8")):
            problems.append(
                f"{path.relative_to(repo_root).as_posix()}: provider block (C-86 forbids it)"
            )
    return problems


# ---------------------------------------------------------------- consistency (across fixtures)
def result_of(fx: Fixture, inv: str) -> str:
    """The nominal result of ``inv`` (process overrides are not applied)."""
    return str(fx.data["results"][inv]["result"])


def effective_results(fx: Fixture) -> dict[str, str]:
    """Nominal results with any process override applied."""
    out = {inv: result_of(fx, inv) for inv in INVARIANTS}
    process = fx.data.get("process")
    if isinstance(process, dict):
        out.update(process.get("results_override", {}))
    return out


def consistency_problems(fixtures: dict[str, Fixture]) -> list[str]:
    problems: list[str] = []
    for folder, fx in fixtures.items():
        data = fx.data
        kind = data["kind"]
        results = {inv: result_of(fx, inv) for inv in INVARIANTS}
        parent_fx: Fixture | None = None
        if kind != "baseline":
            parent_fx = fixtures.get(data["parent"])
            if parent_fx is None:
                problems.append(f"{folder}: parent {data['parent']!r} is not a fixture folder")
                continue
            parent_results = {inv: result_of(parent_fx, inv) for inv in INVARIANTS}
            truth = sorted(inv for inv in INVARIANTS if results[inv] != parent_results[inv])
            if data["impact"]["truth_changed"] != truth:
                problems.append(
                    f"{folder}: truth_changed {data['impact']['truth_changed']} "
                    f"but results differ for {truth}"
                )
            impact = data["impact"]
            if not set(impact["truth_changed"]) <= set(impact["required_affected"]):
                problems.append(f"{folder}: truth_changed is not inside required_affected")
            if not set(impact["oracle_affected"]) <= set(impact["required_affected"]):
                problems.append(f"{folder}: oracle_affected is not inside required_affected")
            if not data["changes"]["resources"]:
                problems.append(f"{folder}: a transition needs changed resources")
            # parent eligibility (C-87)
            problems += eligibility_problems(
                f"{folder} (parent {data['parent']})",
                parent_results,
                data["parent_remediation_targets"],
            )
        else:
            problems += eligibility_problems(
                folder, results, data["baseline"]["remediation_targets"]
            )
        problems += decision_problems(folder, fx)
    return problems


def eligibility_problems(label: str, results: dict[str, str], targets: list[str]) -> list[str]:
    """C-87: PASS or FAIL only, INV-FUNC-001 PASS, every FAIL a declared remediation target."""
    problems = []
    for inv, res in results.items():
        if res not in ("PASS", "FAIL"):
            problems.append(
                f"{label}: {inv} is {res}, not PASS or FAIL (not an eligible baseline or parent)"
            )
        if res == "FAIL" and inv not in targets:
            problems.append(f"{label}: {inv} FAILs but is not a declared remediation target")
    if results.get(FUNC) != "PASS":
        problems.append(f"{label}: INV-FUNC-001 must be PASS in a baseline or parent")
    return problems


def decision_problems(folder: str, fx: Fixture) -> list[str]:
    data = fx.data
    if data["kind"] == "baseline":
        return []
    allowed = data["decision"]["allowed"]
    results = effective_results(fx)
    process = data.get("process")
    stale = isinstance(process, dict) and process.get("kind") == "stale_parent"
    values = set(results.values())
    if "FAIL" in values:
        expected_ok = allowed == ["REJECT"]
        rule = "any FAIL -> [REJECT]"
    elif values & NOT_A_PASS:
        expected_ok = "PROMOTE" not in allowed
        rule = "UNKNOWN, UNSUPPORTED or VERIFIER_ERROR -> PROMOTE is not allowed"
    elif stale:
        expected_ok = allowed == ["REJECT"]
        rule = "stale parent -> [REJECT] (Doc 09 §25)"
    else:
        expected_ok = allowed == ["PROMOTE"]
        rule = "all PASS and not stale -> [PROMOTE]"
    return (
        [] if expected_ok else [f"{folder}: decision.allowed {allowed} violates the rule '{rule}'"]
    )


# ---------------------------------------------------------------- collection-level checks
def collection_problems(fixtures: dict[str, Fixture]) -> list[str]:
    problems: list[str] = []
    if len(fixtures) != EXPECTED_FIXTURE_COUNT:
        problems.append(f"expected {EXPECTED_FIXTURE_COUNT} fixtures, found {len(fixtures)}")
    ids = [f.data.get("fixture_id") for f in fixtures.values()]
    duplicated = sorted({i for i in ids if ids.count(i) > 1}, key=str)
    if duplicated:
        problems.append(f"duplicate fixture ids: {duplicated}")
    names = [
        f.data.get("doc12_fixture")
        for f in fixtures.values()
        if f.data.get("doc12_fixture") is not None
    ]
    for name in DOC12_NAMES:
        if names.count(name) != 1:
            problems.append(
                f"Doc 12 §7 name {name!r} appears {names.count(name)} times (must be exactly once)"
            )
    return problems


def all_problems(repo_root: Path = REPO_ROOT) -> list[str]:
    """Every problem in the fixtures under ``repo_root``; an empty list means consistent data."""
    try:
        fixtures = load_all(repo_root)
    except (json.JSONDecodeError, OSError) as exc:
        return [f"cannot parse a fixture: {exc}"]
    problems = collection_problems(fixtures)
    for folder, fx in fixtures.items():
        problems += structure_problems(folder, fx.data)
    if problems:
        return problems  # consistency checks assume a well-formed structure
    return problems + terraform_problems(repo_root, fixtures) + consistency_problems(fixtures)
