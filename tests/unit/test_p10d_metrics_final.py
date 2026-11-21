"""The final metric definitions ``metrics-final-1`` (P10d work package Step 2; C-231 to C-239).

"Final metric definitions ``metrics-final-1``: P8b's definitions; the scenario-level MR of decision
2; κ (P10d-3); macro impact precision and recall; truth recall on I_t and on V; the LLM descriptive
metrics. Extractor version bumped. Tests first."

Every expected value below is computed by hand from those definitions (and from the paper's
§IV-H text the work package quotes), on the record set of ``tests/metrics_builders.py`` plus the
extra scenarios of ``extras()`` below; never from the extractor's output.

Truth of the base set (tests/metrics_builders.py): X F8 safe; Y F5 unsafe, regression F at step 1;
Z F1 safe; W F8 unsafe, regression F at step 1.

Extras (this file), two invariants S and F as in the builders:

* V  F8 repair, unsafe, controlled tpl-3: T0 {S FAIL, F PASS}, T1 {S FAIL, F PASS},
  T2 {S PASS, F FAIL}. The first regression-inducing step is 2. C REJECTs step 1 (so step 2 is
  TRUNCATED: missed, decision 2); B PROMOTEs step 1 and REJECTs step 2 (caught).
* U  F2 repair, unsafe, real-world lin-2: T0 {S FAIL, F PASS}, T1 {S FAIL, F PASS}: the repair does
  not fix the target and nothing regresses, so U has no regression-inducing step (C-239: excluded
  from MR, counted apart). C and B REJECT step 1.
* T  F4 repair, unsafe, controlled tpl-4: T0 {S FAIL, F PASS}, T1 {S PASS, F FAIL} (fixes the
  target, breaks F). C REJECTs (blocked; impact lists only F, and S is checked as a U_t item); A
  PROMOTEs (missed, not blocked).
* Q  F8 repair, unsafe, controlled tpl-5: T0 {S FAIL, F PASS}, T1 {S FAIL, F FAIL}, T2 {S PASS,
  F PASS}. A PROMOTEs the unsafe step 1 (missed) and REJECTs step 2: not blocked, although the
  trajectory ends in a rejection.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from types import MappingProxyType
from typing import Any

from experiments.metrics.extractor import EXTRACTOR_VERSION, METRICS_VERSION, extract, find
from experiments.metrics.final import kappa
from experiments.scoring.identity import (
    TABLE_PATH_1,
    TruePair,
    judge,
    judge_transition,
    load_identity_table,
    true_pairs,
)
from experiments.scoring.labels import ScenarioLabels
from experiments.scoring.truth import scenario_truth
from tests.metrics_builders import (
    NP,
    X_,
    F,
    P,
    S,
    baselines,
    inv,
    scenarios,
    tr,
    transitions,
)

EXPERIMENT = "00000000-0000-4000-8000-0000000000f1"


def _t(s: str, f: str) -> Any:
    return MappingProxyType({S: s, F: f})


def _labels(sid: str, family: str, tier: str, cluster: str, truth: tuple[Any, ...]) -> Any:
    return ScenarioLabels(
        sid,
        family,
        "repair",
        S,
        tier,
        cluster,
        "unsafe",
        truth,
        tuple(frozenset() for _ in truth),
        (),
        tuple(frozenset() for _ in truth),
    )


def extras() -> tuple[dict[str, ScenarioLabels], list[Any]]:
    labels = {
        "V": _labels("V", "F8", "controlled", "tpl-3", (_t(X_, P), _t(X_, P), _t(P, X_))),
        "U": _labels("U", "F2", "real_world", "lin-2", (_t(X_, P), _t(X_, P))),
        "T": _labels("T", "F4", "controlled", "tpl-4", (_t(X_, P), _t(P, X_))),
        "Q": _labels("Q", "F8", "controlled", "tpl-5", (_t(X_, P), _t(X_, X_), _t(P, P))),
    }
    found = [
        tr("C", "V", 1, "REJECT", [inv(S, "condition", X_, NP), inv(F, "impact", X_)],
           open_targets=[S], affected=[F]),
        tr("C", "V", 2, None),
        tr("B", "V", 1, "PROMOTE", [inv(S, "condition", X_), inv(F, "impact", P)],
           open_targets=[S]),
        tr("B", "V", 2, "REJECT", [inv(S, "impact", P), inv(F, "condition", X_)]),
        tr("C", "U", 1, "REJECT", [inv(S, "condition", X_, NP), inv(F, "impact", P)],
           affected=[F]),
        tr("B", "U", 1, "REJECT", [inv(S, "condition", X_), inv(F, "impact", P)]),
        tr("C", "T", 1, "REJECT", [inv(S, "condition", P, NP), inv(F, "impact", X_)],
           affected=[F]),
        tr("A", "T", 1, "PROMOTE", [inv(S, "impact", P)]),
        tr("A", "Q", 1, "PROMOTE", [inv(S, "condition", X_)], open_targets=[S]),
        tr("A", "Q", 2, "REJECT", [inv(S, "impact", P)]),
    ]  # fmt: skip
    return labels, found


def run(*, with_extras: bool = False, table: Any = None) -> Any:
    scored = scenarios()
    found = transitions()
    if with_extras:
        more, rows = extras()
        scored.update(more)
        found += rows
    return extract(
        experiment_id=EXPERIMENT,
        transitions=found,
        scored=scored,
        baselines=baselines(),
        identity=table if table is not None else load_identity_table(),
    )


class Case(unittest.TestCase):
    x: Any
    y: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.x = run()
        cls.y = run(with_extras=True)

    def ratio(self, x: Any, name: str, condition: str, num: int, den: int, **where: str) -> None:
        record = find(x, name, condition, **where)
        self.assertEqual((record["numerator"], record["denominator"]), (num, den), name)
        if den:
            self.assertAlmostEqual(record["value"], num / den)
        else:
            self.assertIsNone(record["value"])

    def outcome(self, x: Any, condition: str, scenario: str) -> dict[str, Any]:
        rows = [
            r
            for r in x.lists["scenario_outcomes"]
            if r["condition"] == condition and r["scenario_id"] == scenario
        ]
        self.assertEqual(len(rows), 1, (condition, scenario))
        return rows[0]


class TestVersions(unittest.TestCase):
    def test_the_definitions_are_metrics_final_1_and_the_extractor_is_5(self) -> None:
        self.assertEqual(METRICS_VERSION, "metrics-final-1")
        self.assertEqual(EXTRACTOR_VERSION, "extractor-5")
        for record in run().metrics:
            self.assertEqual(record["metrics_version"], "metrics-final-1")
            self.assertEqual(record["extractor_version"], "extractor-5")


class TestScenarioTruth(unittest.TestCase):
    def test_unsafe_class_and_first_regression_inducing_step(self) -> None:
        base = scenarios()
        more, _ = extras()
        expected = {
            "X": (False, None),
            "Y": (True, 1),
            "Z": (False, None),
            "W": (True, 1),
            "V": (True, 2),
            "U": (True, None),  # no invariant goes from PASS to FAIL (C-239)
            "T": (True, 1),
            "Q": (True, 1),
        }
        for sid, labels in {**base, **more}.items():
            with self.subTest(sid=sid):
                t = scenario_truth(labels)
                self.assertEqual((t.unsafe, t.first_regression_step), expected[sid])


class TestMissedRegressionsAtScenarioLevel(Case):
    """Decision 2 (C-232): caught only if X did not PROMOTE the first regression-inducing step."""

    def test_base_set(self) -> None:
        # Y1 and W1 are the first regression-inducing steps
        self.ratio(self.x, "missed_regression_rate", "A", 2, 2, scope="scenario")  # both promoted
        self.ratio(self.x, "missed_regression_rate", "B", 0, 2, scope="scenario")  # both rejected
        self.ratio(self.x, "missed_regression_rate", "C", 1, 2, scope="scenario")  # Y1 promoted
        self.ratio(self.x, "missed_regression_rate", "C_PRIME", 1, 2, scope="scenario")

    def test_a_trajectory_that_stopped_earlier_is_missed(self) -> None:
        self.assertEqual(self.outcome(self.y, "C", "V")["mr"], "missed")  # stopped at step 1
        self.assertEqual(self.outcome(self.y, "B", "V")["mr"], "caught")  # rejected step 2
        self.assertEqual(self.outcome(self.y, "C", "Y")["mr"], "missed")  # promoted it
        self.assertEqual(self.outcome(self.y, "C", "W")["mr"], "caught")

    def test_no_regression_inducing_step_is_excluded_and_counted(self) -> None:
        # C-239: U is counted apart, not in MR's denominator
        self.assertEqual(self.outcome(self.y, "C", "U")["mr"], "no_regression_step")
        self.assertIsNone(self.outcome(self.y, "C", "X")["mr"])  # safe
        rec = find(self.y, "mr_no_regression_step", "C", scope="scenario")
        self.assertEqual(rec["value"], 1)
        self.assertEqual(find(self.y, "mr_no_regression_step", "A", scope="scenario")["value"], 0)

    def test_with_the_extras(self) -> None:
        # C: Y missed, W caught, V missed, T caught; B: Y, W, V caught; A: Y, W, T, Q missed
        self.ratio(self.y, "missed_regression_rate", "C", 2, 4, scope="scenario")
        self.ratio(self.y, "missed_regression_rate", "B", 0, 3, scope="scenario")
        self.ratio(self.y, "missed_regression_rate", "A", 4, 4, scope="scenario")

    def test_strata(self) -> None:
        sc = {"scope": "scenario"}
        self.ratio(self.y, "missed_regression_rate", "C", 2, 4, stratum="kind=repair", **sc)
        self.ratio(self.y, "missed_regression_rate", "C", 0, 0, stratum="kind=change_request", **sc)
        self.ratio(self.y, "missed_regression_rate", "C", 1, 2, stratum="family=F8", **sc)
        self.ratio(self.y, "missed_regression_rate", "C", 0, 1, stratum="family=F4", **sc)
        self.ratio(self.y, "missed_regression_rate", "C", 2, 4, stratum="tier=controlled", **sc)


class TestH4Blocked(Case):
    def test_blocked_unsafe_f4(self) -> None:
        sc = {"scope": "scenario", "stratum": "family=F4"}
        self.ratio(self.y, "blocked_unsafe_rate", "C", 1, 1, **sc)  # T1 rejected
        self.ratio(self.y, "blocked_unsafe_rate", "A", 0, 1, **sc)  # T1 promoted
        self.assertTrue(self.outcome(self.y, "C", "T")["blocked"])
        self.assertFalse(self.outcome(self.y, "A", "T")["blocked"])
        self.assertIsNone(self.outcome(self.y, "C", "X")["blocked"])  # safe

    def test_an_unsafe_step_promoted_before_a_rejection_is_not_blocked(self) -> None:
        self.assertFalse(self.outcome(self.y, "A", "Q")["blocked"])
        self.assertEqual(self.outcome(self.y, "A", "Q")["mr"], "missed")


class TestWorkPerScenario(Case):
    """W_{X,s} over the executed steps of s under X (gate + invariant + applicable baseline)."""

    def test_totals(self) -> None:
        expected = {
            ("C", "X"): 7,  # X1 2 gates + S(U_t) + F; X2 2 gates + S
            ("B", "X"): 8,
            ("C", "Y"): 3,
            ("C_PRIME", "Y"): 4,
            ("B", "Y"): 4,
            ("A", "Z"): 2,
            ("C", "W"): 4,  # W2 TRUNCATED
            ("A", "W"): 6,
        }
        for (condition, sid), w in expected.items():
            with self.subTest(condition=condition, sid=sid):
                self.assertEqual(self.outcome(self.x, condition, sid)["work_w"], w)

    def test_by_kind(self) -> None:
        row = self.outcome(self.x, "C", "X")
        self.assertEqual(row["work"]["gate"], 4)
        self.assertEqual(row["work"]["invariant_impact"], 2)
        self.assertEqual(row["work"]["invariant_not_protected"], 1)
        self.assertEqual(row["work"]["invariant_condition"], 0)
        self.assertEqual((row["evaluated"], row["truncated"]), (2, 0))
        self.assertEqual(self.outcome(self.x, "C", "W")["truncated"], 1)

    def test_work_by_step_for_the_common_prefix(self) -> None:
        # step keys are strings (the rows are JSON); a TRUNCATED step has no entry
        self.assertEqual(self.outcome(self.x, "C", "X")["work_by_step"], {"1": 4, "2": 3})
        self.assertEqual(self.outcome(self.x, "C", "W")["work_by_step"], {"1": 4})

    def test_the_rows_carry_the_cluster_and_the_stratum(self) -> None:
        row = self.outcome(self.x, "B", "Z")
        self.assertEqual(
            (row["kind"], row["tier"], row["cluster"], row["family"]),
            ("change_request", "real_world", "lin-1", "F1"),
        )
        self.assertFalse(row["unsafe"])


class TestImpactMacro(Case):
    """Macro: the unweighted mean over invariants of the per-invariant precision (recall), over the
    invariants whose denominator is not 0 (C-240 (3))."""

    def test_per_invariant_and_macro_under_c(self) -> None:
        # S: found X2, Y1; true X2, Y1; hits 2.  F: found X1, Z1, W1; true X1, Y1, W1; hits X1, W1
        self.ratio(self.x, "impact_precision_per_invariant", "C", 2, 2, stratum=f"invariant={S}")
        self.ratio(self.x, "impact_recall_per_invariant", "C", 2, 2, stratum=f"invariant={S}")
        self.ratio(self.x, "impact_precision_per_invariant", "C", 2, 3, stratum=f"invariant={F}")
        self.ratio(self.x, "impact_recall_per_invariant", "C", 2, 3, stratum=f"invariant={F}")
        for name in ("impact_precision_macro", "impact_recall_macro"):
            self.assertAlmostEqual(find(self.x, name, "C")["value"], (1 + 2 / 3) / 2)
        # micro is P8b's pooled value, unchanged
        self.ratio(self.x, "impact_precision", "C", 4, 5)
        self.ratio(self.x, "impact_recall", "C", 4, 5)


class TestTruthRecall(Case):
    """Truth recall of I_t (and of V = I_t ∪ U_t) on truth_changed, pooled over transitions."""

    def test_base_set(self) -> None:
        # changed: X2 {S}, Y1 {S, F}, W1 {F}; I_t covers X2 S, Y1 S, W1 F; Y1 F is missed by both
        self.ratio(self.x, "truth_recall_impact", "C", 3, 4)
        self.ratio(self.x, "truth_recall_v", "C", 3, 4)

    def test_u_t_adds_to_v(self) -> None:
        # T1 changed {S, F}: I_t {F}; S is a U_t item (VIOLATED in the parent)
        self.ratio(self.y, "truth_recall_impact", "C", 4, 6)
        self.ratio(self.y, "truth_recall_v", "C", 5, 6)
        misses = {
            (m["set"], m["scenario_id"], m["step"], m["invariant_id"])
            for m in self.y.lists["truth_recall_misses"]
            if m["condition"] == "C"
        }
        self.assertEqual(misses, {("impact", "Y", 1, F), ("v", "Y", 1, F), ("impact", "T", 1, S)})


class TestKappa(Case):
    def test_cohen_kappa_worked_example(self) -> None:
        # Cohen's kappa worked example (Wikipedia, "Cohen's kappa", Simple example): 50 items,
        # both yes 20, rater A yes / B no 5, A no / B yes 10, both no 15: p_o = 0.7, p_e = 0.5,
        # kappa = 0.4
        cells = {(P, P): 20, (P, X_): 5, (X_, P): 10, (X_, X_): 15}
        self.assertAlmostEqual(kappa(cells), 0.4)

    def test_kappa_is_undefined_when_chance_agreement_is_1(self) -> None:
        self.assertIsNone(kappa({(P, P): 9}))
        self.assertIsNone(kappa({}))

    def test_kappa_per_invariant_under_b_and_the_other_results_apart(self) -> None:
        # S: 5 FAIL/FAIL, 4 PASS/PASS -> 1.  F: 6 PASS/PASS, 2 FAIL/FAIL, and Z's S0 UNKNOWN apart
        for invariant in (S, F):
            rec = find(self.x, "kappa", "B", stratum=f"invariant={invariant}")
            self.assertAlmostEqual(rec["value"], 1.0)
        table = {row["invariant_id"]: row for row in self.x.lists["kappa"]}
        self.assertEqual(table[S]["cells"], {"FAIL/FAIL": 5, "PASS/PASS": 4})
        self.assertEqual(table[F]["cells"], {"FAIL/FAIL": 2, "PASS/PASS": 6})
        self.assertEqual(table[F]["other"], {"UNKNOWN/PASS": 1})
        self.assertEqual(table[S]["other"], {})


class TestIdentityTruth2(unittest.TestCase):
    """Decision 4 (C-234): the count row; identity-truth-1 is kept for the records it scored."""

    def test_versions(self) -> None:
        self.assertEqual(load_identity_table().version, "identity-truth-2")
        self.assertEqual(load_identity_table(TABLE_PATH_1).version, "identity-truth-1")

    def test_the_count_row_is_an_implicit_move_from_c_76(self) -> None:
        table = load_identity_table()
        self.assertNotIn("op_f5_count_each_safe", table.excluded)
        row = table.rows["op_f5_count_each_safe"]
        self.assertEqual(row["source"], "C-76")
        self.assertEqual(row["sentence"], "adds or removes `count = 1` on `aws_instance`.")
        self.assertEqual(
            row["effects"],
            [{"effect": "COUNT_MOVE", "resource_type": "aws_instance", "attribute": "count"}],
        )
        # the other rows and exclusions are identity-truth-1's
        old = load_identity_table(TABLE_PATH_1)
        self.assertEqual({k: v for k, v in table.rows.items() if k != "op_f5_count_each_safe"},
                         dict(old.rows))  # fmt: skip
        self.assertEqual(
            dict(table.excluded),
            {k: v for k, v in old.excluded.items() if k != "op_f5_count_each_safe"},
        )

    @unittest.skipUnless(
        os.environ.get("TERRAPRESERVE_ROOT"), "set TERRAPRESERVE_ROOT to check the catalogue"
    )
    def test_the_count_sentence_is_the_catalogues(self) -> None:
        text = (Path(os.environ["TERRAPRESERVE_ROOT"]) / "docs" / "D4_OPERATORS.md").read_text(
            encoding="utf-8"
        )
        row = load_identity_table().rows["op_f5_count_each_safe"]
        self.assertIn(f"- `op_f5_count_each_safe`: {row['sentence']}", text)

    def test_count_added_or_removed_is_one_pair(self) -> None:
        table = load_identity_table()
        pairs, excluded = true_pairs(table, scenarios()["W"], 1)
        self.assertEqual(excluded, [])
        self.assertEqual(
            [(p.effect, p.resource_type, p.old, p.new) for p in pairs],
            [("MOVE", "aws_instance", "aws_instance.app", "aws_instance.app")],
        )

    def test_judging_a_count_move(self) -> None:
        pair = TruePair("op_f5_count_each_safe", "MOVE", "aws_instance", "aws_instance.app",
                        "aws_instance.app")  # fmt: skip
        dail = [("aws_instance.app", "aws_instance.app[0]", "MODIFIED", True)]
        self.assertEqual(judge(pair, dail), "correct")
        self.assertEqual(judge_transition(pair, dail), "correct")
        address_only = [
            ("aws_instance.app", None, "DELETED", False),
            (None, "aws_instance.app[0]", "CREATED", False),
        ]
        self.assertEqual(judge(pair, address_only), "wrong")
        self.assertEqual(judge_transition(pair, address_only), "wrong")


class TestTransitionErrors(unittest.TestCase):
    """C-240 (1): an identity error is a wrong correspondence; a transition error is a change type
    (with the move flag) other than the expected one: MOVE -> MODIFIED with moved, REPLACE ->
    REPLACED, CREATE -> CREATED, DELETE -> DELETED."""

    MOVE = TruePair("op", "MOVE", "aws_security_group_rule", "r.a", "r.b")

    def test_a_move_paired_without_the_move_flag_is_a_transition_error_only(self) -> None:
        dail = [("r.a", "r.b", "MODIFIED", False)]
        self.assertEqual(judge(self.MOVE, dail), "correct")
        self.assertEqual(judge_transition(self.MOVE, dail), "wrong")

    def test_a_move_called_replaced_is_a_transition_error_only(self) -> None:
        dail = [("r.a", "r.b", "REPLACED", True)]
        self.assertEqual(judge(self.MOVE, dail), "correct")
        self.assertEqual(judge_transition(self.MOVE, dail), "wrong")

    def test_uncertain_and_correct(self) -> None:
        self.assertEqual(judge_transition(self.MOVE, [("r.a", "r.b", "MODIFIED", True)]), "correct")
        self.assertEqual(judge_transition(self.MOVE, [("r.a", None, "UNCERTAIN", False)]),
                         "uncertain")  # fmt: skip
        replace = TruePair("op", "REPLACE", "aws_security_group", "g.db", "g.db")
        self.assertEqual(judge_transition(replace, [("g.db", "g.db", "MODIFIED", False)]), "wrong")
        self.assertEqual(judge_transition(replace, [("g.db", "g.db", "REPLACED", False)]),
                         "correct")  # fmt: skip


class TestIdentityRates(Case):
    """identity-truth-2 on the base set. C: Y1 rule move correct, db REPLACE wrong (MODIFIED), Z1
    mon CREATE correct, W1 count move wrong (no pair): 4 pairs, 2 wrong. C': rule wrong, db correct,
    mon UNCERTAIN, W1 wrong."""

    def test_rates_with_uncertain_excluded(self) -> None:
        self.ratio(self.x, "identity_error_rate_certain", "C", 2, 4)
        self.ratio(self.x, "transition_error_rate_certain", "C", 2, 4)
        self.ratio(self.x, "identity_error_rate_certain", "C_PRIME", 2, 3)
        self.ratio(self.x, "transition_error_rate_certain", "C_PRIME", 2, 3)
        self.ratio(self.x, "identity_uncertain_share", "C_PRIME", 1, 4)  # of all pairs

    def test_by_family_for_h3_on_f5(self) -> None:
        # F5 is Y1 only: C rule correct, db wrong; C' rule wrong, db correct; no UNCERTAIN on F5
        f5 = {"stratum": "family=F5"}
        self.ratio(self.x, "identity_error_rate_certain", "C", 1, 2, **f5)
        self.ratio(self.x, "transition_error_rate_certain", "C", 1, 2, **f5)
        self.ratio(self.x, "identity_error_rate_certain", "C_PRIME", 1, 2, **f5)
        self.ratio(self.x, "identity_uncertain_share_final", "C_PRIME", 0, 2, **f5)
        self.ratio(self.x, "identity_uncertain_share_final", "C_PRIME", 1, 4)
        self.ratio(self.x, "evidence_transfer_error_rate", "C", 1, 1, **f5)
        # F1 (Z1, mon) under C': the one UNCERTAIN pair, excluded from the certain rates
        self.ratio(self.x, "identity_error_rate_certain", "C_PRIME", 0, 0, stratum="family=F1")

    def test_evidence_transfer_error_rate(self) -> None:
        # true replacements: db at Y1. C keeps db (MODIFIED) while F is carried forward: 1 of 1
        self.ratio(self.x, "evidence_transfer_error_rate", "C", 1, 1)
        self.ratio(self.x, "evidence_transfer_error_rate", "C_PRIME", 0, 1)

    def test_no_pair_is_excluded_any_more(self) -> None:
        self.assertEqual(find(self.x, "identity_excluded_pairs", "C")["value"], 0)
        # under identity-truth-1 the count pair was excluded (P8b)
        old = run(table=load_identity_table(TABLE_PATH_1))
        self.assertEqual(find(old, "identity_excluded_pairs", "C")["value"], 1)


if __name__ == "__main__":
    unittest.main()
