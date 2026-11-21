"""The inputs of the coverage and power simulations (P10d-1, C-235, C-238, C-239, C-241).

The test cluster sizes are public bounds (C-238), from TerraPreserve's DATASHEET (48 controlled and
48 real-world test targets, 3 + 3 per family x class), scenarios/README.md (10 test templates, each
at most once per cell) and scenarios/ASSEMBLY.md (64 real-world test scenarios in 57 lineages, so at
most 7 scenarios share a lineage with another). MR scenarios per stratum (C-239): target-bearing
F4 and F8 unsafe, 6 each (3 controlled + 3 real-world); change-request F1, F3, F5, F6, F7 unsafe, 6
each. Expected by hand:

  repair (12): controlled 6 in 2 cells over 10 templates: even 6 x 1, uneven 3 x 2;
               real-world 6: singletons, or 3 pairs.
  change_request (30): controlled 15 in 5 cells: even 5 x 2 + 5 x 1, uneven 3 x 5;
               real-world 15: singletons, or 7 pairs and 1 single.
  all (42): controlled 21 in 7 cells: even 1 x 3 + 9 x 2, uneven 3 x 7;
               real-world 21: singletons, or 7 pairs and 7 singles.
"""

from __future__ import annotations

import unittest

from experiments.stats.dry_run import analysis_rho, pi_grid, test_size_bounds


class TestSizeBounds(unittest.TestCase):
    def test_configurations(self) -> None:
        b = test_size_bounds()
        self.assertEqual(sorted(b["repair/test-even"]), [1] * 12)
        self.assertEqual(sorted(b["repair/test-uneven"]), [2] * 6)
        self.assertEqual(sorted(b["change_request/test-even"]), [1] * 20 + [2] * 5)
        self.assertEqual(sorted(b["change_request/test-uneven"]), [1] + [2] * 7 + [5] * 3)
        self.assertEqual(sorted(b["all/test-even"]), [1] * 21 + [2] * 9 + [3])
        self.assertEqual(sorted(b["all/test-uneven"]), [1] * 7 + [2] * 7 + [7] * 3)

    def test_totals_are_the_mr_strata(self) -> None:
        b = test_size_bounds()
        for name, total in (("repair", 12), ("change_request", 30), ("all", 42)):
            for variant in ("test-even", "test-uneven"):
                self.assertEqual(sum(b[f"{name}/{variant}"]), total, (name, variant))


class TestGrid(unittest.TestCase):
    def test_pi_grid(self) -> None:
        grid = pi_grid()
        for pi in grid:
            self.assertAlmostEqual(sum(pi), 1.0)
            self.assertTrue(all(p >= 0 for p in pi))
        self.assertEqual(len(grid), len(set(grid)))
        # independent: second 0.10, difference 0.10 -> first 0.20, both 0.02
        self.assertIn((0.02, 0.18, 0.08, 0.72), [tuple(round(p, 10) for p in pi) for pi in grid])
        # nested: second 0.10, difference 0.30
        self.assertIn((0.10, 0.30, 0.0, 0.60), [tuple(round(p, 10) for p in pi) for pi in grid])
        # second 0, difference 0: one point, not two
        self.assertEqual(sum(1 for pi in grid if pi[1] == 0 and pi[2] == 0 and pi[0] == 0), 1)


class TestAnalysisRho(unittest.TestCase):
    def test_the_dev_estimate_if_defined_and_not_negative_else_the_top_of_the_range(self) -> None:
        # C-241 (5): undefined or negative -> 0.30; an estimate above the range is kept (larger
        # DEFF, conservative)
        self.assertEqual(analysis_rho(None), 0.30)
        self.assertEqual(analysis_rho(0.12), 0.12)
        self.assertEqual(analysis_rho(-0.2), 0.30)
        self.assertEqual(analysis_rho(0.45), 0.45)


if __name__ == "__main__":
    unittest.main()
