"""The stored trial records as transitions (P8b; Doc 13 §31-§32).

A ``Transition`` is one (scenario, condition, step >= 1) of a trial result (``result.json``, the
P8a record format): its status (EVALUATED or TRUNCATED), DAIL's decision type, the open targets, the
required checks with their proof source, every work item run (target, type, result, ``applicable``,
origin and the item's reason), the invariants impact listed, DAIL's identity pairs and the step's
duration. ``trial_outcome`` gives Doc 13 §31's TrialOutcome of one transition.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class WorkRow:
    target_id: str
    target_type: str
    result: str
    applicable: bool
    origin: str
    selected_reason: str | None
    verifier_id: str | None = None
    reason: str | None = None  # the result's reason (for example invariant.unknown)


@dataclass(frozen=True)
class Transition:
    trial_id: str
    scenario_id: str
    condition: str
    step: int
    status: str
    decision: str | None
    open_targets: tuple[str, ...]
    required: tuple[tuple[str, str | None], ...]
    work: tuple[WorkRow, ...]
    impact_affected: frozenset[str]
    identity_pairs: tuple[tuple[str | None, str | None, str, bool], ...]
    latency: float | None

    @property
    def evaluated(self) -> bool:
        return self.status == "EVALUATED"


def invariant_of(target_id: str) -> str | None:
    """``INVARIANT:<id>:<version>`` to ``<id>``; None for a gate or a resource item."""
    if not target_id.startswith("INVARIANT:"):
        return None
    return target_id.split(":")[1]


def transitions_from_result(
    result: Mapping[str, Any], durations: Mapping[str, float] | None = None
) -> list[Transition]:
    found = []
    for t in result["transitions"]:
        decision = t.get("decision")
        found.append(
            Transition(
                trial_id=result["trial_id"],
                scenario_id=result["scenario_id"],
                condition=result["condition"],
                step=int(t["step_index"]),
                status=t["status"],
                decision=None if decision is None else decision["type"],
                open_targets=tuple(t.get("open_targets") or ()),
                required=tuple((r["target_id"], r["source"]) for r in t.get("required") or ()),
                work=tuple(
                    WorkRow(
                        w["target_id"],
                        w["target_type"],
                        w["result"],
                        bool(w["applicable"]),
                        w["origin"],
                        w.get("selected_reason"),
                        w.get("verifier_id"),
                        w.get("reason"),
                    )
                    for w in t.get("work") or ()
                ),
                impact_affected=frozenset(
                    a["invariant_id"] for a in ((t.get("impact") or {}).get("affected") or ())
                ),
                identity_pairs=tuple(
                    (p["trusted_ref"], p["candidate_ref"], p["change_type"], bool(p["moved"]))
                    for p in ((t.get("identity") or {}).get("pairs") or ())
                ),
                latency=None if durations is None else durations.get(f"step-{t['step_index']}"),
            )
        )
    return found


def trial_outcome(transition: Transition) -> dict[str, Any]:
    """Doc 13 §31 TrialOutcome for one transition of a fixed-patch trial."""
    if not transition.evaluated:
        return {
            "generation_status": "NOT_RUN",
            "patch_status": "NOT_RUN",
            "identity_status": "NOT_RUN",
            "impact_status": "NOT_RUN",
            "verification_status": "NOT_RUN",
            "promotion_decision": None,
            "invariant_results": [],
            "latency": None,
            "token_usage": None,
            "failure_class": None,
        }
    results = [
        {"invariant_id": invariant_of(w.target_id), "result": w.result}
        for w in transition.work
        if w.target_type == "INVARIANT"
    ]
    worst = {w.result for w in transition.work} - {"PASS"}
    return {
        "generation_status": "FIXED_PATCH",  # no generation in P8 (fixed patches, C-200)
        "patch_status": "ADMITTED",  # content hash checked (C-201)
        "identity_status": "OK" if transition.identity_pairs else "NO_PAIRS",
        "impact_status": "OK",
        "verification_status": "ALL_PASS" if not worst else "+".join(sorted(worst)),
        "promotion_decision": transition.decision,
        "invariant_results": results,
        "latency": transition.latency,
        "token_usage": None,
        "failure_class": None,
    }
