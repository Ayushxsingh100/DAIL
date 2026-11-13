"""What a trial stores per transition (P8a; work package §4.3; Doc 13 §40, §43-§44).

A transition record holds: the step index; the parent state id and hash; the candidate hash; the
open targets; the decision type and reason; the required set, and how each required item was proven
(VERIFIED, CARRIED_FORWARD) or which blocking conditions name it; every work item run, with its
class, target, result, ``applicable`` flag and origin (``impact``: impact listed it; ``condition``:
the condition's scope policy added it; ``gate``: the engine's mandatory gates); the work counts
split into gate items, invariant items, applicable baseline items and not-applicable baseline items;
the identity report's pairs with change types and the ``moved`` flag; the impact report's affected
invariants with impact types; the new state. Durations are kept apart, with the wall clock
(``timing.json``), so that a record holds no time that differs between two runs.

Outcome classes (Doc 13 §43-§44): ``DAIL_OUTCOME`` (a decision; a construction failure counts as a
REJECT, and DAIL stores no decision for it, C-170 (3)), ``HARNESS_FAILURE`` (an exception in the
harness: the trial is FAILED and no decision is made up), ``INPUT_FAILURE`` (a hash mismatch).

Every record carrying an invariant version carries ``registry`` (stored version 2 =
registry-v1.1, C-180, C-203).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from core.application.orchestrator import EvaluationResult, ResultKind
from core.domain.impact import ImpactReport, ReasonCode, VerificationWorkItem
from core.domain.state import TrustedState
from core.domain.verification import VerificationReport
from experiments.conditions import REGISTRY_RECORD

DAIL_OUTCOME: Final = "DAIL_OUTCOME"
HARNESS_FAILURE: Final = "HARNESS_FAILURE"
INPUT_FAILURE: Final = "INPUT_FAILURE"
NOT_EVALUATED: Final = "NOT_EVALUATED"
EVALUATED: Final = "EVALUATED"
TRUNCATED: Final = "TRUNCATED"
GATE_TYPE: Final = "STRUCTURAL"
NOT_PROTECTED_IN_PARENT: Final = ReasonCode.NOT_PROTECTED_IN_PARENT.value
# A random id is drawn for these reports (they are not derived from the request); the stored
# copy leaves it out and keeps the content hash, so two runs store the same bytes (C-207).
_RANDOM_IDS: Final = ("report_id", "graph_id")


def stable(data: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k not in _RANDOM_IDS}


def state_summary(state: TrustedState) -> dict[str, Any]:
    return {
        "state_id": state.state_id,
        "state_hash": state.state_hash,  # covers the lineage (C-33): differs between trials
        "resource_set_hash": state.resource_set_hash(),
        "version": state.version,
        "invariant_registry_version": state.invariant_registry_version,
        "invariants": {
            ref.invariant_id: {"version": ref.invariant_version, "status": ref.status.value}
            for ref in sorted(state.invariant_refs, key=lambda r: r.invariant_id)
        },
    }


def _counts() -> dict[str, int]:
    return {
        "gate": 0,
        "invariant": 0,
        "baseline_applicable": 0,
        "baseline_not_applicable": 0,
        "not_protected_in_parent": 0,  # U_t items (C-210), also counted under "invariant"
    }


def _work(
    report: VerificationReport,
    impact: ImpactReport,
    selected: Sequence[VerificationWorkItem] | None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    listed = {item.target_id for item in impact.verification_work}
    reasons = {item.target_id: item.reason.value for item in selected or ()}
    rows = []
    counts = _counts()
    for r in sorted(report.results, key=lambda x: x.target_id):
        kind = r.target_type.value
        if kind == GATE_TYPE:
            origin = "gate"
            counts["gate"] += 1
        else:
            origin = "impact" if r.target_id in listed else "condition"
            if kind == "INVARIANT":
                counts["invariant"] += 1
                if reasons.get(r.target_id) == NOT_PROTECTED_IN_PARENT:
                    counts["not_protected_in_parent"] += 1
            elif r.applicable:
                counts["baseline_applicable"] += 1
            else:
                counts["baseline_not_applicable"] += 1
        rows.append(
            {
                "target_id": r.target_id,
                "target_type": kind,
                "class": r.verification_class.value,
                "result": r.result.value,
                "reason": None if r.reason is None else r.reason.value,
                "applicable": r.applicable,
                "verifier_id": r.verifier_id,
                "verifier_version": r.verifier_version,
                "evidence_level": r.evidence_level,
                "origin": origin,
                "selected_reason": reasons.get(r.target_id),  # the work item's reason (C-211)
            }
        )
    return rows, counts


def _required(result: EvaluationResult) -> list[dict[str, Any]]:
    decision = result.decision
    if decision is None:
        return []
    blocking: dict[str, list[str]] = {}
    for condition in decision.blocking_conditions:
        blocking.setdefault(condition.target, []).append(condition.code.value)
    return [
        {
            "target_id": check.target_id,
            "kind": check.kind,
            "source": None if check.source is None else check.source.value,
            "verification_id": check.verification_id,
            "blocking": sorted(blocking.get(check.target_id, [])),
        }
        for check in decision.required_checks
    ]


def decision_summary(result: EvaluationResult) -> dict[str, Any]:
    if result.kind is ResultKind.CONSTRUCTION_FAILED or result.decision is None:
        return {
            "type": "REJECT",
            "reason": "CONSTRUCTION_FAILED",
            "decision_id": None,
            "blocking": [],
            "note": "construction failure: DAIL stores no decision (C-170 (3)); counted as REJECT",
        }
    decision = result.decision
    return {
        "type": decision.decision.value,
        "reason": decision.reason.value,
        "decision_id": decision.decision_id,
        "blocking": [c.to_dict() for c in decision.blocking_conditions],
        "note": None,
    }


def transition_record(
    *,
    base: Mapping[str, Any],
    step: int,
    admission: Mapping[str, Any],
    parent: TrustedState,
    open_targets: Sequence[str],
    result: EvaluationResult,
) -> dict[str, Any]:
    """The record of one evaluated transition (see the module docstring)."""
    impact, report, identity = result.impact, result.verification, result.identity
    work: list[dict[str, Any]] = []
    counts = _counts()
    if report is not None and impact is not None:
        work, counts = _work(report, impact, result.work)
    return {
        **base,
        "record": "transition",
        "step_index": step,
        "status": EVALUATED,
        "admission": dict(admission),
        "parent_state_id": parent.state_id,
        "parent_state_hash": parent.state_hash,
        "candidate_id": result.candidate.candidate_id,
        "candidate_state_hash": result.candidate.state_hash,
        "open_targets": list(open_targets),
        "outcome_class": DAIL_OUTCOME,
        "result_kind": result.kind.value,
        "decision": decision_summary(result),
        "required": _required(result),
        "work": work,
        "work_counts": counts,
        "identity": (
            None
            if identity is None
            else {
                "algorithm_version": identity.algorithm_version,
                "content_hash": identity.content_hash,
                "pairs": [
                    {
                        "trusted_ref": m.trusted_resource_ref,
                        "candidate_ref": m.candidate_resource_ref,
                        "change_type": m.change_type.value,
                        "moved": m.moved,
                    }
                    for m in identity.resource_matches
                ],
            }
        ),
        "impact": (
            None
            if impact is None
            else {
                "algorithm_version": impact.algorithm_version,
                "content_hash": impact.content_hash,
                "affected": [
                    {
                        "invariant_id": a.invariant_id,
                        "invariant_version": a.invariant_version,
                        "status": a.status.value,
                        "impact_types": [t.value for t in a.impact_types],
                    }
                    for a in impact.affected_invariants
                ],
            }
        ),
        "new_state": None if result.state is None else state_summary(result.state),
        "registry": dict(REGISTRY_RECORD),
    }


def truncated_record(*, base: Mapping[str, Any], step: int) -> dict[str, Any]:
    """A step that was not evaluated because an earlier one was not a PROMOTE (C-200)."""
    return {
        **base,
        "record": "transition",
        "step_index": step,
        "status": TRUNCATED,
        "admission": None,
        "parent_state_id": None,
        "parent_state_hash": None,
        "candidate_id": None,
        "candidate_state_hash": None,
        "open_targets": [],
        "outcome_class": NOT_EVALUATED,
        "result_kind": TRUNCATED,
        "decision": None,
        "required": [],
        "work": [],
        "work_counts": _counts(),
        "identity": None,
        "impact": None,
        "new_state": None,
        "registry": dict(REGISTRY_RECORD),
    }


def work_items(
    items: Sequence[VerificationWorkItem] | None, impact: ImpactReport | None
) -> list[Any]:
    """The work the scope policy selected, with its origin, for the verification artifact."""
    if items is None:
        return []
    listed = set() if impact is None else {w.target_id for w in impact.verification_work}
    return [
        {**item.to_dict(), "origin": "impact" if item.target_id in listed else "condition"}
        for item in items
    ]
