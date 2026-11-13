"""The P8b metrics on a hand-built record set (P8b work package Section 4, metrics-draft-1; C-212 to
C-214). The record set is described in tests/metrics_builders.py; every expected value below was
computed by hand from the Section 4 definitions, never from the extractor's output.

Truth per transition (Section 4 "Truth per transition"; open target S on X1 and W1):
  X1 safe, no regression | X2 safe | Y1 unsafe (F FAIL), regression F | Z1 safe |
  W1 unsafe (F FAIL; S is the open target), regression F | W2 unsafe (F FAIL), no regression.
"""

from __future__ import annotations

import math
import unittest
from typing import Any

from experiments.metrics.extractor import EXTRACTOR_VERSION, extract, find, wilson
from experiments.scoring.identity import load_identity_table
from experiments.scoring.truth import transition_truth
from tests.metrics_builders import F, S, baselines, scenarios, transitions


def run() -> Any:
    return extract(
        experiment_id="00000000-0000-4000-8000-0000000000e8",
        transitions=transitions(),
        scored=scenarios(),
        baselines=baselines(),
        identity=load_identity_table(),
    )


class Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.x = run()

    def ratio(self, name: str, condition: str, num: int, den: int, **where: str) -> None:
        record = find(self.x, name, condition, **where)
        self.assertEqual((record["numerator"], record["denominator"]), (num, den), name)
        self.assertAlmostEqual(record["value"], num / den if den else 0.0)


class TestTruth(unittest.TestCase):
    def test_per_transition_truth(self) -> None:
        labels = scenarios()
        x1 = transition_truth(labels["X"], 1, (S,))
        self.assertFalse(x1.unsafe)
        self.assertEqual(x1.regression, frozenset())
        y1 = transition_truth(labels["Y"], 1, ())
        self.assertTrue(y1.unsafe)
        self.assertEqual(y1.regression, frozenset({F}))
        self.assertEqual(y1.changed, frozenset({S, F}))
        w1 = transition_truth(labels["W"], 1, (S,))
        self.assertTrue(w1.unsafe)
        self.assertEqual(w1.failing, frozenset({F}))  # S is the open target
        w2 = transition_truth(labels["W"], 2, ())
        self.assertTrue(w2.unsafe)
        self.assertEqual(w2.regression, frozenset())

    def test_on_the_last_step_there_is_no_open_target(self) -> None:
        # a FAIL of the target on the last step is unsafe even if the caller names it open
        labels = scenarios()
        self.assertFalse(transition_truth(labels["X"], 1, (S,)).unsafe)
        self.assertTrue(transition_truth(labels["W"], 1, ()).unsafe)


class TestSafety(Case):
    def test_unsafe_promotions(self) -> None:
        self.ratio("unsafe_promotions_per_promotion", "C", 1, 3)
        self.ratio("unsafe_promotions_per_evaluated", "C", 1, 5)
        self.ratio("unsafe_promotions_per_promotion", "B", 0, 3)
        self.ratio("unsafe_promotions_per_promotion", "A", 3, 6)
        self.ratio("unsafe_promotions_per_evaluated", "A", 3, 6)

    def test_missed_regressions(self) -> None:
        self.ratio("regressions", "C", 2, 5)
        self.ratio("missed_regressions_per_regression", "C", 1, 2)
        self.ratio("missed_regressions_per_regression", "B", 0, 2)
        self.ratio("missed_regressions_per_regression", "A", 2, 2)

    def test_false_rejection_rate(self) -> None:
        self.ratio("false_rejection_rate", "C", 1, 3)
        self.ratio("false_rejection_rate", "B", 0, 3)
        self.ratio("false_rejection_rate", "A", 0, 3)

    def test_repair_success_by_stratum(self) -> None:
        self.ratio("repair_success", "C", 1, 3, stratum="kind=repair")
        self.ratio("repair_success", "C", 0, 1, stratum="kind=change_request")
        self.ratio("repair_success", "B", 1, 3, stratum="kind=repair")
        self.ratio("repair_success", "B", 1, 1, stratum="kind=change_request")
        self.ratio("repair_success", "A", 1, 3, stratum="kind=repair")

    def test_unsafe_promotions_under_c_are_listed_with_their_trace(self) -> None:
        listed = self.x.lists["unsafe_promotions_c"]
        self.assertEqual([(u["scenario_id"], u["step"]) for u in listed], [("Y", 1)])
        self.assertEqual(listed[0]["failing"], [F])
        self.assertEqual(listed[0]["impact"], [S])
        self.assertIn("INVARIANT:INV-SEC-001:2", [w["target_id"] for w in listed[0]["work"]])


class TestWork(Case):
    def total(self, name: str, condition: str, **where: str) -> float:
        return find(self.x, name, condition, **where)["value"]

    def test_work_by_kind_under_c(self) -> None:
        self.assertEqual(self.total("work_gate", "C"), 10)
        self.assertEqual(self.total("work_invariant_impact", "C"), 5)
        self.assertEqual(self.total("work_invariant_condition", "C"), 0)
        self.assertEqual(self.total("work_invariant_not_protected", "C"), 2)
        self.assertEqual(self.total("work_baseline_applicable", "C"), 0)
        self.assertEqual(self.total("work_total", "C"), 17)
        self.assertAlmostEqual(self.total("work_mean_per_transition", "C"), 3.4)
        self.assertEqual(self.total("work_median_per_transition", "C"), 3)

    def test_work_under_b(self) -> None:
        self.assertEqual(self.total("work_total", "B"), 20)
        self.assertEqual(self.total("work_invariant_condition", "B"), 5)
        self.assertEqual(self.total("work_median_per_transition", "B"), 4)

    def test_saving_of_c_against_b_on_the_common_prefix(self) -> None:
        record = find(self.x, "work_saving_c_vs_b", "C", scope="common_prefix_B_C")
        self.assertEqual((record["numerator"], record["denominator"]), (17, 20))
        self.assertAlmostEqual(record["value"], 1 - 17 / 20)


class TestOutcomes(Case):
    def test_decision_rates(self) -> None:
        self.ratio("promote_rate", "C", 3, 5)
        self.ratio("reject_rate", "C", 1, 5)
        self.ratio("retry_rate", "C", 1, 5)
        self.ratio("escalate_rate", "C", 0, 5)
        self.ratio("reject_rate", "B", 2, 5)

    def test_unknown_and_unsupported_per_required_check(self) -> None:
        self.ratio("unknown_rate", "C", 1, 20)
        self.ratio("unsupported_rate", "C", 0, 20)
        self.ratio("unknown_rate", "A", 0, 17)


class TestEarlyTermination(Case):
    def test_truncated_counts(self) -> None:
        for condition, count in (("A", 0), ("B", 1), ("C", 1), ("C_PRIME", 1)):
            with self.subTest(condition=condition):
                record = find(self.x, "truncated_transitions", condition)
                self.assertEqual(record["numerator"], count)
                self.assertEqual(record["denominator"], 6)

    def test_metrics_on_the_common_prefix_of_all_four(self) -> None:
        self.ratio("unsafe_promotions_per_promotion", "A", 2, 5, scope="common_prefix_all")
        self.assertEqual(find(self.x, "work_total", "A", scope="common_prefix_all")["value"], 14)
        self.ratio("unsafe_promotions_per_promotion", "C", 1, 3, scope="common_prefix_all")


class TestAgreement(Case):
    def test_confusion_tables_of_b(self) -> None:
        table = self.x.confusion
        self.assertEqual(table[S], {("FAIL", "FAIL"): 5, ("PASS", "PASS"): 4})
        self.assertEqual(
            table[F], {("PASS", "PASS"): 6, ("FAIL", "FAIL"): 2, ("UNKNOWN", "PASS"): 1}
        )

    def test_every_disagreement_is_listed(self) -> None:
        self.assertEqual(
            self.x.lists["disagreements"],
            [
                {
                    "scenario_id": "Z",
                    "step": 0,
                    "invariant_id": F,
                    "dail": "UNKNOWN",
                    "oracle_truth": "PASS",
                }
            ],
        )


class TestImpact(Case):
    def test_precision_recall_and_coverage(self) -> None:
        for condition in ("C", "C_PRIME"):
            with self.subTest(condition=condition):
                self.ratio("impact_precision", condition, 4, 5)
                self.ratio("impact_recall", condition, 4, 5)
        self.ratio("truth_change_coverage", "C", 3, 4)
        self.ratio("truth_change_coverage", "C_PRIME", 4, 4)
        self.ratio("impact_precision", "C", 3, 3, stratum="family=F8")

    def test_truth_changes_outside_v_are_listed(self) -> None:
        self.assertEqual(
            self.x.lists["truth_changes_outside_v"],
            [{"condition": "C", "scenario_id": "Y", "step": 1, "invariant_id": F}],
        )


class TestIdentity(Case):
    def test_error_rate_uncertain_share_and_evidence_transfer(self) -> None:
        self.ratio("identity_error_rate", "C", 1, 3)
        self.ratio("identity_uncertain_share", "C", 0, 3)
        self.ratio("identity_error_rate", "C_PRIME", 1, 3)
        self.ratio("identity_uncertain_share", "C_PRIME", 1, 3)
        self.assertEqual(find(self.x, "evidence_transfer_errors", "C")["value"], 1)
        self.assertEqual(find(self.x, "evidence_transfer_errors", "C_PRIME")["value"], 0)
        self.assertEqual(find(self.x, "identity_excluded_pairs", "C")["value"], 1)

    def test_identity_errors_are_listed(self) -> None:
        listed = {(e["condition"], e["effect"]) for e in self.x.lists["identity_errors"]}
        self.assertEqual(listed, {("C", "REPLACE"), ("C_PRIME", "MOVE")})

    def test_work_difference_on_f5_by_moved_type(self) -> None:
        self.assertEqual(
            self.x.lists["work_difference_f5"],
            {
                "aws_security_group_rule": {
                    "transitions": 1,
                    "work_c": 3,
                    "work_c_prime": 4,
                    "difference": 1,
                }
            },
        )


class TestRecords(Case):
    def test_metric_records_have_the_fields_of_appendix_b(self) -> None:
        for record in self.x.metrics:
            for key in (
                "metric_id",
                "experiment_id",
                "trial_id",
                "condition_id",
                "metric_name",
                "numerator",
                "denominator",
                "value",
                "unit",
                "extractor_version",
            ):
                self.assertIn(key, record)
            self.assertEqual(record["extractor_version"], "metrics-draft-1")
        self.assertEqual(EXTRACTOR_VERSION, "metrics-draft-1")

    def test_the_extractor_is_deterministic(self) -> None:
        from experiments.metrics.extractor import dumps_metrics

        self.assertEqual(dumps_metrics(run()), dumps_metrics(run()))

    def test_wilson_interval(self) -> None:
        z = 1.959963984540054
        n, k = 3, 1
        p = k / n
        centre = (p + z * z / (2 * n)) / (1 + z * z / n)
        half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
        low, high = wilson(k, n)
        self.assertAlmostEqual(low, centre - half)
        self.assertAlmostEqual(high, centre + half)
        self.assertEqual(wilson(0, 0), (None, None))
        record = find(self.x, "unsafe_promotions_per_promotion", "C")
        self.assertAlmostEqual(record["wilson95"][0], centre - half)


class TestEdgeRules(unittest.TestCase):
    """Cases the main record set does not contain (added after mutations M2, M6 and M7 survived)."""

    def test_a_target_still_failing_on_the_last_step_is_unsafe_even_if_named_open(self) -> None:
        from types import MappingProxyType

        from experiments.scoring.labels import ScenarioLabels

        one = ScenarioLabels(
            "V", "F8", "repair", S, "controlled", "tpl-1", "unsafe",
            (MappingProxyType({S: "FAIL"}), MappingProxyType({S: "FAIL"})),
            (frozenset(), frozenset()), (), (frozenset(), frozenset()),
        )  # fmt: skip
        self.assertTrue(transition_truth(one, 1, (S,)).unsafe)

    def test_save_is_computed_on_the_common_prefix_only(self) -> None:
        # without C's X2: C evaluates X1 Y1 Z1 W1 (W 4+3+3+4 = 14); B on those four: 4 x 4 = 16
        kept = [
            t
            for t in transitions()
            if not (t.condition == "C" and t.scenario_id == "X" and t.step == 2)
        ]
        x = extract(
            experiment_id="00000000-0000-4000-8000-0000000000e8",
            transitions=kept,
            scored=scenarios(),
            baselines=baselines(),
            identity=load_identity_table(),
        )
        record = find(x, "work_saving_c_vs_b", "C", scope="common_prefix_B_C")
        self.assertEqual((record["numerator"], record["denominator"]), (14, 16))

    def test_a_carried_check_has_no_result(self) -> None:
        # F carried forward, and a stale UNKNOWN row for F in the work list: not an UNKNOWN check
        from tests.metrics_builders import inv, tr

        odd = tr(
            "C",
            "X",
            1,
            "PROMOTE",
            [inv(F, "impact", "UNKNOWN")],
            carried=[F],
            required=[],
            open_targets=[S],
        )
        x = extract(
            experiment_id="00000000-0000-4000-8000-0000000000e8",
            transitions=[odd],
            scored=scenarios(),
            baselines={},
            identity=load_identity_table(),
        )
        record = find(x, "unknown_rate", "C")
        self.assertEqual((record["numerator"], record["denominator"]), (0, 3))


if __name__ == "__main__":
    unittest.main()
