"""The metric extractor, version ``metrics-draft-1`` (P8b work package Section 4; Doc 13 §25-§35,
Appendix B; C-212 to C-214).

Input: the transitions of the stored trial records (``experiments.metrics.model``), the scenarios'
truth from ``experiments.scoring``, DAIL's S0 results under B, and the identity truth table. Output:
``MetricRecord``s (Appendix B, plus ``scope``, ``stratum`` and a Wilson 95% interval for
proportions) and the lists Section 4 asks for. Every proportion carries its numerator and
denominator; a denominator of 0 gives ``value = None``. Descriptive only (C-214): no test, no
p-value.

Populations. ``scope = all``: every evaluated transition of the condition (TRUNCATED ones are
counted apart). ``common_prefix_all``: the (scenario, step) pairs evaluated under every condition
present. ``common_prefix_B_C``: those evaluated under both B and C (for ``work_saving_c_vs_b``).
Strata: ``all``, ``family=<F>``, ``tier=<controlled|real_world>``, and for ``repair_success``
``kind=<repair|change_request>``. ``repair_success`` is per scenario and is reported on ``all``
only.

Definitions (Section 4): unsafe promotions per promotion and per evaluated transition; regressions
per evaluated transition and missed regressions per regression; false rejections per safe
transition; repair success per scenario; work by kind (gate; invariant items from impact, from the
condition's scope policy, and U_t items; applicable and not-applicable baseline items) with
W = gate + invariant + applicable baseline, its total, per-transition mean and median, and
Save(C vs B) = 1 - sum W_C / sum W_B on the common prefix of B and C; decision rates per evaluated
transition; UNKNOWN and UNSUPPORTED per required check (a carried-forward check has no result and is
neither); TRUNCATED transitions per transition; the oracle agreement of B (confusion per invariant
at S0 and every evaluated step, every disagreement listed); impact precision, recall and
truth-change coverage for C and C' (pooled and per family; a truth change outside the verified set
listed); identity error rate, UNCERTAIN share and evidence-transfer errors for C and C' over the
pairs the identity table gives (excluded pairs counted), and the work difference C' - C on F5 by
moved resource type; every promoted unsafe transition under C listed with its trace.

An evidence-transfer error (a reading for the authors, C-215): a true replacement that DAIL treats
as the same object (not REPLACED, not UNCERTAIN) in a transition where some required invariant was
CARRIED_FORWARD.
"""

from __future__ import annotations

import json
import math
import statistics
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from experiments.metrics.model import Transition, invariant_of
from experiments.scoring.identity import IdentityTable, judge, true_pairs
from experiments.scoring.labels import ScenarioLabels
from experiments.scoring.truth import TransitionTruth, transition_truth

EXTRACTOR_VERSION: Final = "metrics-draft-1"
NAMESPACE: Final = uuid.uuid5(uuid.NAMESPACE_URL, "dail/experiments/metrics")
Z95: Final = 1.959963984540054
ORDER: Final = ("A", "B", "C", "C_PRIME")
NOT_PROTECTED: Final = "NOT_PROTECTED_IN_PARENT"


def wilson(k: int, n: int) -> tuple[float | None, float | None]:
    """The Wilson score 95% interval of k successes in n."""
    if n == 0:
        return None, None
    p = k / n
    z2 = Z95 * Z95
    centre = (p + z2 / (2 * n)) / (1 + z2 / n)
    half = Z95 * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / (1 + z2 / n)
    return centre - half, centre + half


@dataclass
class Extraction:
    experiment_id: str
    metrics: list[dict[str, Any]] = field(default_factory=list)
    lists: dict[str, Any] = field(default_factory=dict)
    confusion: dict[str, dict[tuple[str, str], int]] = field(default_factory=dict)
    outcomes: list[dict[str, Any]] = field(default_factory=list)


def find(
    extraction: Extraction, name: str, condition: str, *, scope: str = "all", stratum: str = "all"
) -> dict[str, Any]:
    for record in extraction.metrics:
        if (
            record["metric_name"] == name
            and record["condition_id"] == condition
            and record["scope"] == scope
            and record["stratum"] == stratum
        ):
            return record
    raise KeyError((name, condition, scope, stratum))


class _Out:
    def __init__(self, experiment_id: str) -> None:
        self.experiment_id = experiment_id
        self.records: list[dict[str, Any]] = []

    def add(
        self,
        name: str,
        condition: str,
        *,
        scope: str,
        stratum: str,
        numerator: float | None,
        denominator: float | None,
        value: float | None,
        unit: str,
    ) -> None:
        interval = None
        if unit == "proportion" and denominator is not None:
            interval = list(wilson(int(numerator or 0), int(denominator)))
        self.records.append(
            {
                "metric_id": str(
                    uuid.uuid5(
                        NAMESPACE, f"{self.experiment_id}/{name}/{condition}/{scope}/{stratum}"
                    )
                ),
                "experiment_id": self.experiment_id,
                "trial_id": None,
                "condition_id": condition,
                "metric_name": name,
                "scope": scope,
                "stratum": stratum,
                "numerator": numerator,
                "denominator": denominator,
                "value": value,
                "unit": unit,
                "wilson95": interval,
                "extractor_version": EXTRACTOR_VERSION,
            }
        )

    def ratio(
        self, name: str, condition: str, num: int, den: int, *, scope: str, stratum: str
    ) -> None:
        self.add(
            name,
            condition,
            scope=scope,
            stratum=stratum,
            numerator=num,
            denominator=den,
            value=None if den == 0 else num / den,
            unit="proportion",
        )

    def amount(
        self, name: str, condition: str, value: float, *, scope: str, stratum: str, unit: str
    ) -> None:
        self.add(
            name,
            condition,
            scope=scope,
            stratum=stratum,
            numerator=None,
            denominator=None,
            value=value,
            unit=unit,
        )


@dataclass(frozen=True)
class _Scored:
    t: Transition
    truth: TransitionTruth
    scenario: ScenarioLabels


def _work(t: Transition) -> dict[str, int]:
    counts = Counter(
        {
            "gate": 0,
            "invariant_impact": 0,
            "invariant_condition": 0,
            "invariant_not_protected": 0,
            "baseline_applicable": 0,
            "baseline_not_applicable": 0,
        }
    )
    for w in t.work:
        if w.origin == "gate":
            counts["gate"] += 1
        elif w.target_type == "INVARIANT":
            if w.selected_reason == NOT_PROTECTED:
                counts["invariant_not_protected"] += 1
            elif w.origin == "impact":
                counts["invariant_impact"] += 1
            else:
                counts["invariant_condition"] += 1
        elif w.applicable:
            counts["baseline_applicable"] += 1
        else:
            counts["baseline_not_applicable"] += 1
    return dict(counts)


def work_w(t: Transition) -> int:
    c = _work(t)
    return (
        c["gate"]
        + c["invariant_impact"]
        + c["invariant_condition"]
        + c["invariant_not_protected"]
        + c["baseline_applicable"]
    )


def _strata(s: _Scored) -> list[str]:
    return ["all", f"family={s.scenario.family}", f"tier={s.scenario.tier}"]


def _core(out: _Out, condition: str, items: Sequence[_Scored], scope: str) -> None:
    """Section 4 items 1-3, 5 and 6 for one condition and population."""
    groups: dict[str, list[_Scored]] = defaultdict(list)
    for s in items:
        for stratum in _strata(s):
            groups[stratum].append(s)
    groups.setdefault("all", [])
    for stratum, group in sorted(groups.items()):
        promoted = [s for s in group if s.t.decision == "PROMOTE"]
        unsafe_promoted = [s for s in promoted if s.truth.unsafe]
        out.ratio(
            "unsafe_promotions_per_promotion",
            condition,
            len(unsafe_promoted),
            len(promoted),
            scope=scope,
            stratum=stratum,
        )
        out.ratio(
            "unsafe_promotions_per_evaluated",
            condition,
            len(unsafe_promoted),
            len(group),
            scope=scope,
            stratum=stratum,
        )
        regressions = [s for s in group if s.truth.regression]
        missed = [s for s in regressions if s.t.decision == "PROMOTE"]
        out.ratio(
            "regressions", condition, len(regressions), len(group), scope=scope, stratum=stratum
        )
        out.ratio(
            "missed_regressions_per_regression",
            condition,
            len(missed),
            len(regressions),
            scope=scope,
            stratum=stratum,
        )
        safe = [s for s in group if not s.truth.unsafe]
        rejected = [s for s in safe if s.t.decision != "PROMOTE"]
        out.ratio(
            "false_rejection_rate",
            condition,
            len(rejected),
            len(safe),
            scope=scope,
            stratum=stratum,
        )
        for decision in ("PROMOTE", "REJECT", "RETRY", "ESCALATE"):
            count = sum(1 for s in group if s.t.decision == decision)
            out.ratio(
                f"{decision.lower()}_rate",
                condition,
                count,
                len(group),
                scope=scope,
                stratum=stratum,
            )
        checks, unknown, unsupported = 0, 0, 0
        for s in group:
            results = {w.target_id: w.result for w in s.t.work}
            for target_id, source in s.t.required:
                checks += 1
                result = results.get(target_id) if source == "VERIFIED" else None
                unknown += result == "UNKNOWN"
                unsupported += result == "UNSUPPORTED"
        out.ratio("unknown_rate", condition, unknown, checks, scope=scope, stratum=stratum)
        out.ratio("unsupported_rate", condition, unsupported, checks, scope=scope, stratum=stratum)
        kinds: Counter[str] = Counter()
        totals = []
        for s in group:
            kinds.update(_work(s.t))
            totals.append(work_w(s.t))
        for kind in (
            "gate",
            "invariant_impact",
            "invariant_condition",
            "invariant_not_protected",
            "baseline_applicable",
            "baseline_not_applicable",
        ):
            out.amount(
                f"work_{kind}", condition, kinds[kind], scope=scope, stratum=stratum, unit="items"
            )
        out.amount("work_total", condition, sum(totals), scope=scope, stratum=stratum, unit="items")
        out.amount(
            "work_mean_per_transition",
            condition,
            sum(totals) / len(totals) if totals else 0,
            scope=scope,
            stratum=stratum,
            unit="items_per_transition",
        )
        out.amount(
            "work_median_per_transition",
            condition,
            statistics.median(totals) if totals else 0,
            scope=scope,
            stratum=stratum,
            unit="items_per_transition",
        )


def _repair_success(
    out: _Out, condition: str, all_items: Sequence[Transition], scored: Mapping[str, ScenarioLabels]
) -> None:
    by_scenario: dict[str, list[Transition]] = defaultdict(list)
    for t in all_items:
        by_scenario[t.scenario_id].append(t)
    for kind in ("repair", "change_request"):
        ids = sorted(sid for sid in by_scenario if scored[sid].kind == kind)
        ok = 0
        for sid in ids:
            steps = by_scenario[sid]
            last = scored[sid].truth[-1]
            if all(t.evaluated and t.decision == "PROMOTE" for t in steps) and all(
                v == "PASS" for v in last.values()
            ):
                ok += 1
        out.ratio("repair_success", condition, ok, len(ids), scope="all", stratum=f"kind={kind}")


def extract(
    *,
    experiment_id: str,
    transitions: Iterable[Transition],
    scored: Mapping[str, ScenarioLabels],
    baselines: Mapping[tuple[str, str], Mapping[str, str]],
    identity: IdentityTable,
) -> Extraction:
    """Every metric record and list of Section 4 (see the module docstring)."""
    out = _Out(experiment_id)
    x = Extraction(experiment_id)
    everything = sorted(transitions, key=lambda t: (t.condition, t.scenario_id, t.step))
    conditions = [c for c in ORDER if any(t.condition == c for t in everything)]
    by_condition = {c: [t for t in everything if t.condition == c] for c in conditions}
    scored_items = {
        c: [
            _Scored(
                t,
                transition_truth(scored[t.scenario_id], t.step, t.open_targets),
                scored[t.scenario_id],
            )
            for t in ts
            if t.evaluated
        ]
        for c, ts in by_condition.items()
    }
    keys = {c: {(s.t.scenario_id, s.t.step) for s in items} for c, items in scored_items.items()}
    prefix_all = set.intersection(*keys.values()) if keys else set()
    for c in conditions:
        items = scored_items[c]
        _core(out, c, items, "all")
        _core(
            out,
            c,
            [s for s in items if (s.t.scenario_id, s.t.step) in prefix_all],
            "common_prefix_all",
        )
        _repair_success(out, c, by_condition[c], scored)
        truncated = sum(1 for t in by_condition[c] if not t.evaluated)
        out.ratio(
            "truncated_transitions", c, truncated, len(by_condition[c]), scope="all", stratum="all"
        )
    if "B" in keys and "C" in keys:
        prefix = keys["B"] & keys["C"]
        sums = {
            c: sum(work_w(s.t) for s in scored_items[c] if (s.t.scenario_id, s.t.step) in prefix)
            for c in ("B", "C")
        }
        out.add(
            "work_saving_c_vs_b",
            "C",
            scope="common_prefix_B_C",
            stratum="all",
            numerator=sums["C"],
            denominator=sums["B"],
            value=None if sums["B"] == 0 else 1 - sums["C"] / sums["B"],
            unit="saving",
        )
    _agreement(x, scored_items.get("B", []), baselines, scored)
    for c in ("C", "C_PRIME"):
        if c in scored_items:
            _impact(out, x, c, scored_items[c])
            _identity(out, x, c, scored_items[c], identity)
    _work_difference_f5(x, scored_items, identity)
    x.lists["unsafe_promotions_c"] = [
        {
            "scenario_id": s.t.scenario_id,
            "step": s.t.step,
            "failing": sorted(s.truth.failing),
            "impact": sorted(s.t.impact_affected),
            "work": [
                {
                    "target_id": w.target_id,
                    "result": w.result,
                    "origin": w.origin,
                    "selected_reason": w.selected_reason,
                }
                for w in s.t.work
            ],
            "required": [{"target_id": r, "source": src} for r, src in s.t.required],
        }
        for s in scored_items.get("C", [])
        if s.t.decision == "PROMOTE" and s.truth.unsafe
    ]
    x.lists["clusters"] = _clusters(scored_items)
    x.lists["prefix_sizes"] = {
        "common_prefix_all": len(prefix_all),
        "common_prefix_B_C": len(keys.get("B", set()) & keys.get("C", set())),
    }
    x.metrics = sorted(
        out.records,
        key=lambda r: (r["metric_name"], ORDER.index(r["condition_id"]), r["scope"], r["stratum"]),
    )
    return x


def _agreement(
    x: Extraction,
    items: Sequence[_Scored],
    baselines: Mapping[tuple[str, str], Mapping[str, str]],
    scored: Mapping[str, ScenarioLabels],
) -> None:
    table: dict[str, Counter[tuple[str, str]]] = defaultdict(Counter)
    disagreements = []

    def note(sid: str, step: int, invariant: str, dail: str) -> None:
        truth = scored[sid].truth[step].get(invariant)
        if truth is None:
            return
        table[invariant][(dail, truth)] += 1
        if dail != truth:
            disagreements.append(
                {
                    "scenario_id": sid,
                    "step": step,
                    "invariant_id": invariant,
                    "dail": dail,
                    "oracle_truth": truth,
                }
            )

    for (sid, condition), results in sorted(baselines.items()):
        if condition == "B" and sid in scored:
            for invariant, dail in sorted(results.items()):
                note(sid, 0, invariant, dail)
    for s in items:
        for w in s.t.work:
            named = invariant_of(w.target_id)
            if named is not None:
                note(s.t.scenario_id, s.t.step, named, w.result)
    x.confusion = {k: dict(v) for k, v in sorted(table.items())}
    x.lists["disagreements"] = sorted(
        disagreements, key=lambda d: (d["scenario_id"], d["step"], d["invariant_id"])
    )


def _impact(out: _Out, x: Extraction, condition: str, items: Sequence[_Scored]) -> None:
    pooled: dict[str, Counter[str]] = defaultdict(Counter)
    outside = x.lists.setdefault("truth_changes_outside_v", [])
    for s in items:
        found, truth = s.t.impact_affected, s.truth.affected
        verified = {
            name
            for w in s.t.work
            if w.target_type == "INVARIANT" and (name := invariant_of(w.target_id)) is not None
        }
        for stratum in ("all", f"family={s.scenario.family}"):
            c = pooled[stratum]
            c["hit"] += len(found & truth)
            c["found"] += len(found)
            c["true"] += len(truth)
            c["changed"] += len(s.truth.changed)
            c["covered"] += len(s.truth.changed & verified)
        for invariant in sorted(s.truth.changed - verified):
            outside.append(
                {
                    "condition": condition,
                    "scenario_id": s.t.scenario_id,
                    "step": s.t.step,
                    "invariant_id": invariant,
                }
            )
    for stratum, c in sorted(pooled.items()):
        out.ratio("impact_precision", condition, c["hit"], c["found"], scope="all", stratum=stratum)
        out.ratio("impact_recall", condition, c["hit"], c["true"], scope="all", stratum=stratum)
        out.ratio(
            "truth_change_coverage",
            condition,
            c["covered"],
            c["changed"],
            scope="all",
            stratum=stratum,
        )
    if "all" not in pooled:
        for name in ("impact_precision", "impact_recall", "truth_change_coverage"):
            out.ratio(name, condition, 0, 0, scope="all", stratum="all")


def _identity(
    out: _Out, x: Extraction, condition: str, items: Sequence[_Scored], table: IdentityTable
) -> None:
    pairs = wrong = uncertain = transfer = excluded = 0
    errors = x.lists.setdefault("identity_errors", [])
    excluded_list = x.lists.setdefault("identity_excluded", [])
    for s in items:
        found, skipped = true_pairs(table, s.scenario, s.t.step)
        excluded += len(skipped)
        excluded_list += [
            {"condition": condition, "scenario_id": s.t.scenario_id, "step": s.t.step, **e}
            for e in skipped
        ]
        carried = any(src == "CARRIED_FORWARD" for _, src in s.t.required)
        for pair in found:
            verdict = judge(pair, s.t.identity_pairs)
            pairs += 1
            if verdict == "uncertain":
                uncertain += 1
            if verdict == "wrong":
                wrong += 1
                errors.append(
                    {
                        "condition": condition,
                        "scenario_id": s.t.scenario_id,
                        "step": s.t.step,
                        "operator": pair.operator,
                        "effect": pair.effect,
                        "old": pair.old,
                        "new": pair.new,
                        "dail_pairs": [
                            list(p)
                            for p in s.t.identity_pairs
                            if pair.old in p[:2] or pair.new in p[:2]
                        ],
                    }
                )
                if pair.effect == "REPLACE" and carried:
                    transfer += 1
    out.ratio("identity_error_rate", condition, wrong, pairs, scope="all", stratum="all")
    out.ratio("identity_uncertain_share", condition, uncertain, pairs, scope="all", stratum="all")
    out.amount(
        "evidence_transfer_errors", condition, transfer, scope="all", stratum="all", unit="count"
    )
    out.amount(
        "identity_excluded_pairs", condition, excluded, scope="all", stratum="all", unit="count"
    )


def _work_difference_f5(
    x: Extraction, scored_items: Mapping[str, Sequence[_Scored]], table: IdentityTable
) -> None:
    result: dict[str, dict[str, int]] = {}
    if "C" in scored_items and "C_PRIME" in scored_items:
        prime = {(s.t.scenario_id, s.t.step): s for s in scored_items["C_PRIME"]}
        for s in scored_items["C"]:
            other = prime.get((s.t.scenario_id, s.t.step))
            if other is None or s.scenario.family != "F5":
                continue
            moved = sorted(
                {
                    p.resource_type
                    for p in true_pairs(table, s.scenario, s.t.step)[0]
                    if p.effect == "MOVE"
                }
            )
            for kind in moved:
                row = result.setdefault(
                    kind, {"transitions": 0, "work_c": 0, "work_c_prime": 0, "difference": 0}
                )
                row["transitions"] += 1
                row["work_c"] += work_w(s.t)
                row["work_c_prime"] += work_w(other.t)
                row["difference"] = row["work_c_prime"] - row["work_c"]
    x.lists["work_difference_f5"] = dict(sorted(result.items()))


def _clusters(scored_items: Mapping[str, Sequence[_Scored]]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str, str], Counter[str]] = defaultdict(Counter)
    for condition, items in scored_items.items():
        for s in items:
            c = rows[(condition, s.scenario.tier, s.scenario.cluster)]
            c["evaluated"] += 1
            c["promoted"] += s.t.decision == "PROMOTE"
            c["unsafe_promoted"] += s.t.decision == "PROMOTE" and s.truth.unsafe
            c["safe"] += not s.truth.unsafe
            c["safe_not_promoted"] += (not s.truth.unsafe) and s.t.decision != "PROMOTE"
    return [
        {"condition": c, "tier": tier, "cluster": cluster, **dict(sorted(v.items()))}
        for (c, tier, cluster), v in sorted(
            rows.items(), key=lambda kv: (ORDER.index(kv[0][0]), kv[0][1], kv[0][2])
        )
    ]


def to_json(x: Extraction) -> dict[str, Any]:
    return {
        "extractor_version": EXTRACTOR_VERSION,
        "experiment_id": x.experiment_id,
        "metrics": x.metrics,
        "lists": x.lists,
        "confusion": {
            inv: [{"dail": d, "oracle_truth": o, "count": n} for (d, o), n in sorted(cells.items())]
            for inv, cells in x.confusion.items()
        },
        "trial_outcomes": x.outcomes,
    }


def dumps_metrics(x: Extraction) -> bytes:
    return (json.dumps(to_json(x), sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


Selector = Callable[[Transition], bool]
