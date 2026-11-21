"""The metrics that ``metrics-final-1`` adds to P8b's definitions (P10d work package Step 2;
C-231 to C-240). ``experiments.metrics.extractor`` calls these; P8b's records are unchanged.

* **Scenario outcomes** (scope ``scenario``), one row per (condition, scenario):
  - the missed regression of decision 2 (C-232): for an unsafe scenario with a regression-inducing
    step, ``caught`` if the condition evaluated that first step and did not PROMOTE it, else
    ``missed`` (promoted, or the trajectory stopped earlier); ``no_regression_step`` for an unsafe
    scenario without one (C-239: counted apart, not in MR); None for a safe scenario;
  - ``blocked`` (H4): an unsafe scenario none of whose unsafe transitions the condition promoted;
  - repair success (P8b: every step evaluated and promoted, and every invariant PASS at the last
    step; an early termination is a failure);
  - W_{X,s}: the work of the executed steps by kind and in total (P8b's W).
  Records: ``missed_regression_rate`` (missed / (caught + missed)) and ``blocked_unsafe_rate``
  (blocked / unsafe) on the strata ``all``, ``kind=<repair|change_request>`` (MR only),
  ``family=<F>`` and ``tier=<T>``; ``mr_no_regression_step`` (a count).
* **κ** (P10d-3, C-237): Cohen's κ per invariant of DAIL's result under B against the scenario
  truth, over the PASS/FAIL cells of P8b's agreement table (S0 and every evaluated step); every
  other cell is tabulated apart. κ = (p_o - p_e) / (1 - p_e); undefined (None) when p_e = 1 or
  there is no cell.
* **Macro impact precision and recall** (C-240 (3)): per invariant, precision = transitions where
  impact lists it and the truth does / transitions where impact lists it, recall over transitions
  where the truth lists it; macro = their unweighted mean over the invariants whose denominator is
  not 0. Micro is P8b's pooled value.
* **Truth recall** of I_t (the invariants impact lists) and of V = I_t ∪ U_t (U_t: the invariants
  checked because they are not PROTECTED in the parent, C-210) on truth_changed, pooled over
  transitions; every miss is listed.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from experiments.metrics.model import Transition, invariant_of
from experiments.scoring.labels import ScenarioLabels
from experiments.scoring.truth import scenario_truth, transition_truth

PASS, FAIL = "PASS", "FAIL"
NOT_PROTECTED: Final = "NOT_PROTECTED_IN_PARENT"
KINDS: Final = ("repair", "change_request")


def kappa(cells: Mapping[tuple[str, str], int]) -> float | None:
    """Cohen's κ of the (DAIL result, truth) cells; only the PASS/FAIL cells count."""
    pp = cells.get((PASS, PASS), 0)
    pf = cells.get((PASS, FAIL), 0)
    fp = cells.get((FAIL, PASS), 0)
    ff = cells.get((FAIL, FAIL), 0)
    n = pp + pf + fp + ff
    if n == 0:
        return None
    observed = (pp + ff) / n
    dail_pass, truth_pass = (pp + pf) / n, (pp + fp) / n
    chance = dail_pass * truth_pass + (1 - dail_pass) * (1 - truth_pass)
    if math.isclose(chance, 1.0):
        return None
    return (observed - chance) / (1 - chance)


def kappa_rows(confusion: Mapping[str, Mapping[tuple[str, str], int]]) -> list[dict[str, Any]]:
    rows = []
    for invariant, cells in sorted(confusion.items()):
        binary = {k: v for k, v in cells.items() if k[0] in (PASS, FAIL) and k[1] in (PASS, FAIL)}
        other = {k: v for k, v in cells.items() if k not in binary}
        rows.append(
            {
                "invariant_id": invariant,
                "cells": {f"{d}/{t}": n for (d, t), n in sorted(binary.items()) if n},
                "other": {f"{d}/{t}": n for (d, t), n in sorted(other.items()) if n},
                "n": sum(binary.values()),
                "kappa": kappa(binary),
            }
        )
    return rows


def scenario_outcomes(
    by_condition: Mapping[str, Sequence[Transition]],
    scored: Mapping[str, ScenarioLabels],
    work_kinds: Callable[[Transition], Mapping[str, int]],
    work_w: Callable[[Transition], int],
    order: Sequence[str],
) -> list[dict[str, Any]]:
    rows = []
    for condition in [c for c in order if c in by_condition]:
        steps_of: dict[str, list[Transition]] = defaultdict(list)
        for t in by_condition[condition]:
            steps_of[t.scenario_id].append(t)
        for sid in sorted(steps_of):
            scenario = scored[sid]
            steps = sorted(steps_of[sid], key=lambda t: t.step)
            truth = scenario_truth(scenario)
            evaluated = [t for t in steps if t.evaluated]
            mr: str | None = None
            blocked: bool | None = None
            if truth.unsafe:
                first = truth.first_regression_step
                if first is None:
                    mr = "no_regression_step"
                else:
                    at = [t for t in evaluated if t.step == first]
                    mr = "caught" if at and at[0].decision != "PROMOTE" else "missed"
                blocked = not any(
                    t.decision == "PROMOTE"
                    and transition_truth(scenario, t.step, t.open_targets).unsafe
                    for t in evaluated
                )
            kinds: Counter[str] = Counter()
            for t in evaluated:
                kinds.update(work_kinds(t))
            rows.append(
                {
                    "condition": condition,
                    "scenario_id": sid,
                    "family": scenario.family,
                    "kind": scenario.kind,
                    "tier": scenario.tier,
                    "cluster": scenario.cluster,
                    "unsafe": truth.unsafe,
                    "first_regression_step": truth.first_regression_step,
                    "mr": mr,
                    "blocked": blocked,
                    "repair_success": bool(steps)
                    and all(t.evaluated and t.decision == "PROMOTE" for t in steps)
                    and all(v == PASS for v in scenario.truth[-1].values()),
                    "evaluated": len(evaluated),
                    "truncated": len(steps) - len(evaluated),
                    "work": dict(sorted(kinds.items())),
                    "work_w": sum(work_w(t) for t in evaluated),
                }
            )
    return rows


def scenario_records(out: Any, rows: Sequence[Mapping[str, Any]], order: Sequence[str]) -> None:
    for condition in order:
        mine = [r for r in rows if r["condition"] == condition]
        if not mine:
            continue
        groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for r in mine:
            for stratum in (
                "all",
                f"kind={r['kind']}",
                f"family={r['family']}",
                f"tier={r['tier']}",
            ):
                groups[stratum].append(r)
        for kind in KINDS:
            groups.setdefault(f"kind={kind}", [])
        for stratum, group in sorted(groups.items()):
            judged = [r for r in group if r["mr"] in ("caught", "missed")]
            out.ratio(
                "missed_regression_rate",
                condition,
                sum(r["mr"] == "missed" for r in judged),
                len(judged),
                scope="scenario",
                stratum=stratum,
            )
            if not stratum.startswith("kind="):
                unsafe = [r for r in group if r["unsafe"]]
                out.ratio(
                    "blocked_unsafe_rate",
                    condition,
                    sum(bool(r["blocked"]) for r in unsafe),
                    len(unsafe),
                    scope="scenario",
                    stratum=stratum,
                )
        out.amount(
            "mr_no_regression_step",
            condition,
            sum(r["mr"] == "no_regression_step" for r in mine),
            scope="scenario",
            stratum="all",
            unit="count",
        )


def impact_macro(out: Any, condition: str, items: Sequence[Any]) -> None:
    """``items``: the extractor's scored transitions (``t.impact_affected``, ``truth.affected``)."""
    found: Counter[str] = Counter()
    true: Counter[str] = Counter()
    hit: Counter[str] = Counter()
    for s in items:
        listed, affected = s.t.impact_affected, s.truth.affected
        found.update(listed)
        true.update(affected)
        hit.update(listed & affected)
    precisions, recalls = [], []
    for invariant in sorted(set(found) | set(true)):
        stratum = f"invariant={invariant}"
        out.ratio("impact_precision_per_invariant", condition, hit[invariant], found[invariant],
                  scope="all", stratum=stratum)  # fmt: skip
        out.ratio("impact_recall_per_invariant", condition, hit[invariant], true[invariant],
                  scope="all", stratum=stratum)  # fmt: skip
        if found[invariant]:
            precisions.append(hit[invariant] / found[invariant])
        if true[invariant]:
            recalls.append(hit[invariant] / true[invariant])
    for name, values in (("impact_precision_macro", precisions), ("impact_recall_macro", recalls)):
        out.add(
            name,
            condition,
            scope="all",
            stratum="all",
            numerator=None,
            denominator=len(values),
            value=sum(values) / len(values) if values else None,
            unit="macro_mean",
        )


def truth_recall(out: Any, x: Any, condition: str, items: Sequence[Any]) -> None:
    misses = x.lists.setdefault("truth_recall_misses", [])
    changed_total = covered_i = covered_v = 0
    for s in items:
        changed = s.truth.changed
        listed = s.t.impact_affected
        u_t = {
            name
            for w in s.t.work
            if w.target_type == "INVARIANT"
            and w.selected_reason == NOT_PROTECTED
            and (name := invariant_of(w.target_id)) is not None
        }
        changed_total += len(changed)
        covered_i += len(changed & listed)
        covered_v += len(changed & (listed | u_t))
        for name, have in (("impact", listed), ("v", listed | u_t)):
            for invariant in sorted(changed - have):
                misses.append(
                    {
                        "condition": condition,
                        "set": name,
                        "scenario_id": s.t.scenario_id,
                        "step": s.t.step,
                        "invariant_id": invariant,
                    }
                )
    out.ratio(
        "truth_recall_impact", condition, covered_i, changed_total, scope="all", stratum="all"
    )
    out.ratio("truth_recall_v", condition, covered_v, changed_total, scope="all", stratum="all")
