"""The analysis of the frozen protocol on scenario outcome rows (P10d Section 3; C-231, C-235 to
C-241). Every expected value is computed by hand below.

Hand rows (the extractor's ``scenario_outcomes``), target-bearing stratum (``repair``), unsafe
scenarios with a regression-inducing step, three clusters:

  cluster tpl-1 (controlled): s1, s2      cluster lin-1 (real-world): s3      lin-2: s4
  A missed s1, s2, s3 (caught s4); C missed s2 (caught the rest); B caught every one.
  W (C / B): s1 3 / 5, s2 4 / 4, s3 6 / 5, s4 2 / 4; s5 (lin-3, safe, change_request) 1 / 1.

H1 (A vs C), repair: cluster MR differences tpl-1 1 - 1/2 = 1/2, lin-1 1 - 0 = 1, lin-2 0: n+ 2,
n- 0, n0 1; two-sided p = 2 · (1/2)² = 0.5. change_request: no MR scenario, p = 1. Holm: 0.5 x 2
= 1.0, then 1.0. Paired cells (A, C): both missed s2 = 1, A only s1, s3 = 2, C only 0, neither s4
= 1; MR_A - MR_C = 3/4 - 1/4 = 1/2. Tiers: 1 controlled and 2 real-world clusters, both under 10:
descriptive.
H2 workload, all scenarios with B and C: cluster means of W_C - W_B: tpl-1 (-2 + 0)/2 = -1,
lin-1 +1, lin-2 -2, lin-3 0: n- 2 (favour C), n+ 1, n0 1, median of the cluster means -0.5;
one-sided p = P(X >= 2 | 3) = 4/8; estimate P(favours C | non-zero) = 2/3.
H2 NI (C vs B): cells both 0, C only 1 (s2), B only 0, neither 3.
H4 (C): F4 unsafe rows f4a blocked, f4b not: 1/2.
"""

from __future__ import annotations

import unittest
from typing import Any

from experiments.stats.analysis import (
    coverage_decision,
    h1,
    h2_noninferiority,
    h2_workload,
    h4,
    icc_estimates,
    mr_cluster_sizes,
)
from experiments.stats.procedures import deff, one_sided_upper_95


def r(cond: str, sid: str, cluster: str, tier: str, mr: Any, w: int, **extra: Any) -> Any:
    row = {
        "condition": cond,
        "scenario_id": sid,
        "family": extra.get("family", "F4"),
        "kind": extra.get("kind", "repair"),
        "tier": tier,
        "cluster": cluster,
        "unsafe": extra.get("unsafe", True),
        "mr": mr,
        "blocked": extra.get("blocked"),
        "work_w": w,
        "work_by_step": extra.get("steps", {"1": w}),
    }
    return row


C_, R_ = "controlled", "real_world"
ROWS = [
    r("A", "s1", "tpl-1", C_, "missed", 1),
    r("A", "s2", "tpl-1", C_, "missed", 1),
    r("A", "s3", "lin-1", R_, "missed", 1),
    r("A", "s4", "lin-2", R_, "caught", 1),
    r("C", "s1", "tpl-1", C_, "caught", 3),
    r("C", "s2", "tpl-1", C_, "missed", 4),
    r("C", "s3", "lin-1", R_, "caught", 6),
    r("C", "s4", "lin-2", R_, "caught", 2),
    r("B", "s1", "tpl-1", C_, "caught", 5),
    r("B", "s2", "tpl-1", C_, "caught", 4),
    r("B", "s3", "lin-1", R_, "caught", 5),
    r("B", "s4", "lin-2", R_, "caught", 4),
    r("A", "s6", "lin-4", R_, "no_regression_step", 1, family="F2"),
    r("C", "s6", "lin-4", R_, "no_regression_step", 1, family="F2"),
    r("C", "s5", "lin-3", R_, None, 1, kind="change_request", family="F1", unsafe=False),
    r("B", "s5", "lin-3", R_, None, 1, kind="change_request", family="F1", unsafe=False),
]


class TestH1(unittest.TestCase):
    def setUp(self) -> None:
        self.result = h1(ROWS, rho=0.0, alpha=0.05)

    def test_cluster_sign_test_per_stratum(self) -> None:
        repair = self.result["strata"]["repair"]
        self.assertEqual((repair["n_plus"], repair["n_minus"], repair["n_zero"]), (2, 0, 1))
        self.assertAlmostEqual(repair["p_two_sided"], 0.5)
        cr = self.result["strata"]["change_request"]
        self.assertEqual((cr["n_plus"], cr["n_minus"], cr["n_zero"]), (0, 0, 0))
        self.assertEqual(cr["p_two_sided"], 1.0)

    def test_holm_across_the_two_strata(self) -> None:
        self.assertEqual(self.result["holm_adjusted"], {"repair": 1.0, "change_request": 1.0})
        self.assertEqual(self.result["holm_rejected"], {"repair": False, "change_request": False})

    def test_scenario_weighted_difference_and_tiers(self) -> None:
        repair = self.result["strata"]["repair"]
        self.assertEqual(repair["cells"], {"both": 1, "first_only": 2, "second_only": 0,
                                           "neither": 1})  # fmt: skip
        self.assertAlmostEqual(repair["difference"], 0.5)
        self.assertEqual(repair["clusters_by_tier"], {"controlled": 1, "real_world": 2})
        self.assertEqual(repair["descriptive_tiers"], ["controlled", "real_world"])
        self.assertEqual(len(repair["interval95"]), 2)

    def test_a_scenario_without_a_regression_inducing_step_is_not_in_h1(self) -> None:
        # s6 (F2, C-239) is in neither the cells nor the clusters
        repair = self.result["strata"]["repair"]
        self.assertEqual((repair["scenarios"], repair["clusters"]), (4, 3))

    def test_the_sign_test_counts_clusters_not_scenarios(self) -> None:
        rows = [
            r("A", "t1", "tpl-7", C_, "missed", 1),
            r("A", "t2", "tpl-7", C_, "missed", 1),
            r("A", "t3", "lin-8", R_, "caught", 1),
            r("C", "t1", "tpl-7", C_, "caught", 1),
            r("C", "t2", "tpl-7", C_, "caught", 1),
            r("C", "t3", "lin-8", R_, "missed", 1),
        ]
        repair = h1(rows, rho=0.0)["strata"]["repair"]
        # scenarios: A only 2, C only 1; clusters: tpl-7 +1, lin-8 -1
        self.assertEqual((repair["cells"]["first_only"], repair["cells"]["second_only"]), (2, 1))
        self.assertEqual((repair["n_plus"], repair["n_minus"]), (1, 1))

    def test_mr_cluster_sizes(self) -> None:
        self.assertEqual(mr_cluster_sizes(ROWS, "C", "repair"), [2, 1, 1])
        self.assertEqual(mr_cluster_sizes(ROWS, "C", "change_request"), [])


class TestH2(unittest.TestCase):
    def test_workload_sign_test(self) -> None:
        w = h2_workload(ROWS)
        self.assertEqual((w["n_favour_c"], w["n_favour_b"], w["n_zero"]), (2, 1, 1))
        self.assertAlmostEqual(w["p_one_sided"], 4 / 8)
        self.assertAlmostEqual(w["median_cluster_difference"], -0.5)
        self.assertAlmostEqual(w["estimate_p_favours_c"], 2 / 3)

    def test_workload_on_the_common_prefix(self) -> None:
        rows = [
            r("C", "p", "lin-9", R_, None, 5, unsafe=False, steps={"1": 2, "2": 3}),
            r("B", "p", "lin-9", R_, None, 4, unsafe=False, steps={"1": 4}),
        ]
        # common prefix: step 1 only: 2 - 4 = -2 (all steps: 5 - 4 = +1)
        self.assertEqual(h2_workload(rows)["n_favour_b"], 1)
        prefix = h2_workload(rows, common_prefix=True)
        self.assertEqual(prefix["n_favour_c"], 1)
        self.assertAlmostEqual(prefix["median_cluster_difference"], -2)

    def test_noninferiority_is_exploratory(self) -> None:
        ni = h2_noninferiority(ROWS, rho=0.0)
        self.assertEqual(ni["cells"], {"both": 0, "first_only": 1, "second_only": 0, "neither": 3})
        self.assertAlmostEqual(ni["upper95_one_sided"], one_sided_upper_95(0, 1, 0, 3,
                               deff_value=deff([2, 1, 1], 0.0)))  # fmt: skip
        self.assertEqual(ni["margin"], 0.05)
        self.assertEqual(ni["status"], "exploratory (C-231)")
        self.assertFalse(ni["upper_below_margin"])


class TestH4(unittest.TestCase):
    def test_blocked_unsafe_f4(self) -> None:
        rows = [
            r("C", "f4a", "lin-5", R_, "caught", 1, blocked=True),
            r("C", "f4b", "lin-6", R_, "missed", 1, blocked=False),
            r("C", "f2", "lin-7", R_, "no_regression_step", 1, family="F2", blocked=True),
        ]
        result = h4(rows)
        self.assertEqual((result["numerator"], result["denominator"]), (1, 2))
        self.assertEqual(len(result["wilson95"]), 2)


class TestIcc(unittest.TestCase):
    def test_icc_of_the_paired_outcomes(self) -> None:
        found = icc_estimates(ROWS)
        # B misses nothing: no variance; C - B equals C's indicator: clusters (0, 1), (0), (0)
        self.assertIsNone(found["all"]["B"])
        self.assertEqual(found["all"]["C_minus_B"], found["all"]["C"])
        self.assertIsNotNone(found["all"]["A_minus_C"])


class TestCoverageDecision(unittest.TestCase):
    def test_below_093_anywhere_makes_the_stratum_descriptive(self) -> None:
        table = [
            {"config": "repair/test-even", "rho": 0.0, "coverage": 0.95},
            {"config": "repair/test-uneven", "rho": 0.3, "coverage": 0.929},
            {"config": "change_request/dev", "rho": 0.3, "coverage": 0.93},
        ]
        decision = coverage_decision(table, threshold=0.93)
        self.assertEqual(decision["repair"]["outcome"], "descriptive")
        self.assertAlmostEqual(decision["repair"]["minimum"], 0.929)
        self.assertEqual(decision["change_request"]["outcome"], "inferential")


if __name__ == "__main__":
    unittest.main()
