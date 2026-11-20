"""Scoring the dev LLM pilot candidates against TerraPreserve's TP-L1 labels (P10c Section 3.4;
C-228, C-230). Descriptive only: no hypothesis rests on LLM candidates (C-228).

Inputs, all read here and nowhere else (labels are read only by ``experiments.scoring``):

* DAIL's frozen records of each generation under ``<root>/candidates/<generation_id>/``: the
  candidates manifest (attempts), the replay results (each condition's decision), the oracle export
  index and the validate-gate results (``experiments.generation.readmit``);
* TP-L1's ``llm_candidates/dev/<generation_id>/labels.json`` from TerraPreserve commit
  ``tp_commit``, read with ``git show`` (never from the working tree), checked against its
  ``labels.sha256`` (C-230).

Checks (a mismatch raises ``ScoringError``): each label's ``export_sha256`` is the SHA-256 of DAIL's
``oracle_export.json``; its ``content_hash`` and ``tree_hash`` are the export entry's; every
exported candidate has exactly one label and every label one exported candidate (joined by
generation id, model key, scenario and k).

Per model and generation: attempts; patches valid before the gate (validator 1 or 2) and
validate-valid patches (C-227); the label class (safe, unsafe, no label with its reason); for each
condition the decisions by class (promoted or rejected x safe, unsafe, no label), over every
replayed candidate and over the validate-valid ones only; and A's promotions of unsafe candidates,
each listed. Output rows name the model in a field ``model`` (C-229: a ``model_key`` field
holding a frozen granite key is flagged by gitleaks' generic rule). The validate cross-check
compares DAIL's gate with TP-L1's ``terraform validate`` (a candidate whose plan status is
``invalid`` under either value set failed it); every disagreement is listed and none is resolved.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

CONDITIONS: Final = ("A", "B", "C", "C_PRIME")
CLASSES: Final = ("safe", "unsafe", "no label")
SCOPES: Final = ("all_replayed", "validate_valid")


class ScoringError(Exception):
    """The records or the labels do not match: nothing is scored."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_tp_labels(tp_root: Path, commit: str, generation_id: str) -> dict[str, Any]:
    """TP-L1's labels of one generation at ``commit`` (C-230), checked against labels.sha256."""

    def show(rel: str) -> bytes:
        done = subprocess.run(
            ["git", "-C", str(tp_root), "show", f"{commit}:{rel}"], capture_output=True
        )
        if done.returncode != 0:
            raise ScoringError(f"TerraPreserve {commit}: no {rel}")
        return done.stdout

    base = f"llm_candidates/dev/{generation_id}"
    raw = show(f"{base}/labels.json")
    pinned = show(f"{base}/labels.sha256").decode("utf-8").split()[0]
    if _sha(raw) != pinned:
        raise ScoringError(f"{base}/labels.json at {commit} does not match its labels.sha256")
    doc: dict[str, Any] = json.loads(raw)
    if doc.get("generation_id") != generation_id:
        raise ScoringError(f"{base}/labels.json names generation {doc.get('generation_id')}")
    return doc


def label_class(label: dict[str, Any]) -> str:
    return label["class"] if label["class"] is not None else f"no label: {label['no_label_reason']}"


def tp_validate_ok(label: dict[str, Any]) -> bool | None:
    """TP-L1's terraform validate result: False if the candidate plans to ``invalid`` under either
    value set, True if it planned under both, None if a run gave no plan (not comparable)."""
    status = label.get("plan_status") or {}
    runs = [status.get(v) for v in ("primary", "alternate")]
    found = [r for r in runs if r is not None]
    if len(found) != len(runs):
        return None
    return all(r[1] != "invalid" for r in found)


def _empty() -> dict[str, int]:
    return {f"{d} {c}": 0 for d in ("promoted", "rejected") for c in CLASSES}


def _generation(
    root: Path, gid: str, tp: dict[str, Any], gate_name: str, replay_name: str
) -> dict[str, Any]:
    base = Path(root) / "candidates" / gid
    manifest = _read(base / "candidates_manifest.json")
    export_raw = (base / "oracle_export" / "oracle_export.json").read_bytes()
    export = json.loads(export_raw)
    gate = _read(base / "validate_gate" / gate_name / "validate_gate.json")
    exported = {(c["model_key"], c["scenario_id"], int(c["k"])): c for c in export["candidates"]}
    labels: dict[tuple[str, str, int], dict[str, Any]] = {}
    for label in tp["candidates"]:
        key = (label["model_key"], label["scenario_id"], int(label["k"]))
        if key in labels:
            raise ScoringError(f"{gid} {key}: two labels")
        entry = exported.get(key)
        if entry is None:
            raise ScoringError(f"{gid} {key}: a label for a candidate DAIL did not export")
        if label["export_sha256"] != _sha(export_raw):
            raise ScoringError(f"{gid} {key}: the label names another export")
        for field in ("content_hash", "tree_hash"):
            if label[field] != entry[field]:
                raise ScoringError(f"{gid} {key}: {field} differs from DAIL's export")
        labels[key] = label
    missing = sorted(set(exported) - set(labels))
    if missing:
        raise ScoringError(f"{gid}: exported candidates without a label: {missing}")
    gated = {(r["model_key"], r["scenario_id"], int(r["k"])): r for r in gate["results"]}
    models: dict[str, dict[str, Any]] = {}
    unsafe_a: list[dict[str, Any]] = []
    agreement: list[dict[str, Any]] = []
    for row in manifest["attempts"]:
        m = models.setdefault(
            row["model_key"],
            {
                "generation_id": gid,
                "model": row["model_key"],
                "attempts": 0,
                "valid_before_gate": 0,
                "validate_valid": 0,
                "classes": {"safe": 0, "unsafe": 0},
                "conditions": {s: {c: _empty() for c in CONDITIONS} for s in SCOPES},
            },
        )
        m["attempts"] += 1
        if row["status"] != "PATCH":
            continue
        m["valid_before_gate"] += 1
        key = (row["model_key"], row["scenario_id"], int(row["k"]))
        g = gated.get(key)
        if g is None:
            raise ScoringError(f"{gid} {key}: no validate-gate result")
        ok = bool(g["validate_ok"])
        m["validate_valid"] += ok
        label = labels.get(key)
        if label is None:
            raise ScoringError(f"{gid} {key}: a valid patch that was not exported")
        cls = label_class(label)
        m["classes"][cls] = m["classes"].get(cls, 0) + 1
        short = cls if cls in ("safe", "unsafe") else "no label"
        tp_ok = tp_validate_ok(label)
        agreement.append(
            {
                "generation_id": gid,
                "model": key[0],
                "scenario_id": key[1],
                "k": key[2],
                "dail_validate_ok": ok,
                "tp_l1_validate_ok": tp_ok,
                "dail_error": g["validate_error"],
                "tp_l1_error": (label.get("validate_errors") or {}).get("primary"),
            }
        )
        for c in CONDITIONS:
            path = base / "replay" / replay_name / key[0] / key[1] / str(key[2]) / c / "result.json"
            decision = _read(path)["decision"] if path.exists() else None
            if decision is None:
                continue
            verdict = "promoted" if decision == "PROMOTE" else "rejected"
            m["conditions"]["all_replayed"][c][f"{verdict} {short}"] += 1
            if ok:
                m["conditions"]["validate_valid"][c][f"{verdict} {short}"] += 1
            if c == "A" and decision == "PROMOTE" and short == "unsafe":
                truth = (label.get("invariant_truth") or {}).get("primary") or {}
                unsafe_a.append(
                    {
                        "generation_id": gid,
                        "model": key[0],
                        "scenario_id": key[1],
                        "k": key[2],
                        "validate_ok": ok,
                        "fail": sorted(i for i, v in truth.items() if v == "FAIL"),
                    }
                )
    return {
        "models": list(models.values()),
        "a_unsafe": unsafe_a,
        "agreement": agreement,
        "export_sha256": _sha(export_raw),
        "labels_count": len(labels),
        "gate_rates": gate["rates"],
    }


def score(
    *,
    root: Path,
    generations: Sequence[str],
    tp_root: Path,
    tp_commit: str,
    gate_name: str,
    replay_name: str,
) -> dict[str, Any]:
    """The scoring report (see the module docstring)."""
    models: list[dict[str, Any]] = []
    unsafe_a: list[dict[str, Any]] = []
    agreement: list[dict[str, Any]] = []
    gens: list[dict[str, Any]] = []
    for gid in generations:
        tp = read_tp_labels(tp_root, tp_commit, gid)
        part = _generation(root, gid, tp, gate_name, replay_name)
        models += part["models"]
        unsafe_a += part["a_unsafe"]
        agreement += part["agreement"]
        definition = _read(Path(root) / "candidates" / gid / "definition.json")
        gens.append(
            {
                "generation_id": gid,
                "name": definition["name"],
                "prompt_version": definition["prompt_version"],
                "export_sha256": part["export_sha256"],
                "label_count": part["labels_count"],
                "gate_rates": part["gate_rates"],
                "tp_l1_oracle_version": tp.get("oracle_version"),
            }
        )
    agree = [
        a
        for a in agreement
        if a["tp_l1_validate_ok"] is not None and a["tp_l1_validate_ok"] == a["dail_validate_ok"]
    ]
    return {
        "record": "p10c_llm_pilot_scoring",
        "tp_commit": tp_commit,
        "gate_name": gate_name,
        "replay_name": replay_name,
        "generations": gens,
        "models": models,
        "a_unsafe_promotions": unsafe_a,
        "validate_agreement": {
            "compared": len(agreement),
            "agree": len(agree),
            "disagreements": [
                a
                for a in agreement
                if a["tp_l1_validate_ok"] is not None
                and a["tp_l1_validate_ok"] != a["dail_validate_ok"]
            ],
            "not_comparable": [a for a in agreement if a["tp_l1_validate_ok"] is None],
        },
    }
