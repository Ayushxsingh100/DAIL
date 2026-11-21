"""The statistical procedures of the frozen protocol (P10d work package Section 3; C-231, C-235 to
C-241).

"Every procedure against hand-computed or published worked examples (cite the source for
Newcombe's method 10 ... and check the numbers); Wilson against a known value; the exact sign test
against the binomial; Holm on a hand example; DEFF on a hand example; the coverage simulation is
reproducible with its seed."

Sources of the expected values:

* Newcombe's method 10 (Newcombe 1998, Stat Med 17:2635-2650): the Armitage and Berry (1994, p.
  138) paired example as worked on the StatsDirect help page "Paired proportions"
  (statsdirect.co.uk/help/proportions/paired.htm, read 21 Nov 2026): both media positive 20, first
  only 12, second only 2, both negative 16 (n = 50); difference 0.2; "Score based (Newcombe) 95%
  confidence interval for the proportion difference: 0.056156 to 0.329207"; "Exact two sided P =
  0.0129", "Exact one sided P = 0.0065". Newcombe's own Table II was not checked (the PDF read had
  no text layer).
* The best case of the paper (DAIL.tex §IV-H, C-231): no miss under either condition in 48
  scenarios, DEFF = 1: the one-sided 95% upper limit is z_{0.95}^2 / (n + z_{0.95}^2) ≈ 0.053.
* Wilson: 81 of 263 (the example of Newcombe 1998a, Stat Med 17:857-872, Table I), computed by hand
  from Wilson's formula: centre (81 + z²/2) / (263 + z²), half-width z √(81 · 182 / 263 + z²/4) /
  (263 + z²), z = 1.959964: 0.2553 to 0.3662.
* Sign test: the binomial by hand. 8 positive, 2 negative: P(X >= 8 | 10, 1/2) = (45 + 10 + 1) /
  1024 = 0.0546875; two-sided 0.109375.
* Holm (1979) by hand: p = (0.01, 0.04, 0.03), alpha 0.05: sorted 0.01 x 3 = 0.03 (reject),
  0.03 x 2 = 0.06 (stop); adjusted (0.03, 0.06, 0.06).
* DEFF = 1 + [(1 + CV²) m̄ - 1] ρ by hand (CV with the population standard deviation, C-241 (2)):
  sizes (1, 2, 3): m̄ = 2, CV² = (2/3) / 4 = 1/6, (1 + 1/6) · 2 = 7/3; ρ = 0.1: 1 + (4/3) · 0.1.
* The one-way ANOVA ICC by hand (C-241 (3)).
"""

from __future__ import annotations

import math
import random
import unittest

from experiments.stats.procedures import (
    Z90_ONE_SIDED,
    deff,
    holm,
    icc_anova,
    mcnemar_exact,
    newcombe10,
    one_sided_upper_95,
    sign_test,
    wilson,
)
from experiments.stats.simulate import coverage, coverage_table, paired_data


class TestWilson(unittest.TestCase):
    def test_known_value(self) -> None:
        low, high = wilson(81, 263)
        self.assertAlmostEqual(low, 0.2553, places=4)
        self.assertAlmostEqual(high, 0.3662, places=4)

    def test_zero_of_n_upper_limit_at_one_sided_95(self) -> None:
        z = Z90_ONE_SIDED
        _, high = wilson(0, 48, z=z)
        self.assertAlmostEqual(high, z * z / (48 + z * z))
        self.assertAlmostEqual(high, 0.053, places=3)

    def test_empty(self) -> None:
        self.assertEqual(wilson(0, 0), (None, None))


class TestSignTest(unittest.TestCase):
    def test_against_the_binomial(self) -> None:
        self.assertAlmostEqual(sign_test(8, 2, alternative="greater"), 56 / 1024)
        self.assertAlmostEqual(sign_test(8, 2, alternative="two-sided"), 112 / 1024)
        self.assertAlmostEqual(sign_test(2, 8, alternative="greater"), 1013 / 1024)
        self.assertAlmostEqual(sign_test(6, 0, alternative="two-sided"), 2 / 64)
        self.assertAlmostEqual(sign_test(5, 5, alternative="two-sided"), 1.0)
        self.assertEqual(sign_test(0, 0, alternative="two-sided"), 1.0)

    def test_exact_mcnemar_is_the_sign_test_on_the_discordant_pairs(self) -> None:
        # StatsDirect / Armitage and Berry: discordant 12 and 2
        self.assertAlmostEqual(mcnemar_exact(12, 2), 0.0129, places=4)
        self.assertAlmostEqual(mcnemar_exact(12, 2, alternative="greater"), 0.0065, places=4)
        self.assertAlmostEqual(mcnemar_exact(12, 2), sign_test(12, 2, alternative="two-sided"))


class TestHolm(unittest.TestCase):
    def test_hand_example(self) -> None:
        adjusted, rejected = holm({"a": 0.01, "b": 0.04, "c": 0.03}, alpha=0.05)
        self.assertEqual(set(adjusted), {"a", "b", "c"})
        self.assertAlmostEqual(adjusted["a"], 0.03)
        self.assertAlmostEqual(adjusted["c"], 0.06)
        self.assertAlmostEqual(adjusted["b"], 0.06)
        self.assertEqual(rejected, {"a": True, "b": False, "c": False})

    def test_two_strata(self) -> None:
        adjusted, rejected = holm({"repair": 0.02, "change_request": 0.04}, alpha=0.05)
        self.assertEqual(adjusted, {"repair": 0.04, "change_request": 0.04})
        self.assertEqual(rejected, {"repair": True, "change_request": True})
        _, rejected = holm({"repair": 0.03, "change_request": 0.20}, alpha=0.05)
        self.assertEqual(rejected, {"repair": False, "change_request": False})  # 0.03 x 2 > 0.05


class TestDeff(unittest.TestCase):
    def test_hand_example(self) -> None:
        self.assertAlmostEqual(deff([1, 2, 3], 0.1), 1 + (7 / 3 - 1) * 0.1)
        self.assertAlmostEqual(deff([4, 4, 4], 0.2), 1 + (4 - 1) * 0.2)  # CV = 0
        self.assertEqual(deff([1, 1, 1], 0.3), 1.0)  # singletons
        self.assertEqual(deff([5, 2], 0.0), 1.0)


class TestNewcombe10(unittest.TestCase):
    def test_statsdirect_armitage_and_berry_example(self) -> None:
        low, high = newcombe10(20, 12, 2, 16)
        self.assertAlmostEqual(low, 0.056156, places=6)
        self.assertAlmostEqual(high, 0.329207, places=6)

    def test_the_best_case_of_the_paper(self) -> None:
        # 48 scenarios, no miss under either condition, DEFF = 1 (C-231)
        upper = one_sided_upper_95(0, 0, 0, 48, deff_value=1.0)
        self.assertAlmostEqual(upper, Z90_ONE_SIDED**2 / (48 + Z90_ONE_SIDED**2))
        self.assertGreater(upper, 0.05)

    def test_cells_are_divided_by_deff(self) -> None:
        self.assertEqual(
            one_sided_upper_95(20, 12, 2, 16, deff_value=2.0),
            newcombe10(10, 6, 1, 8, z=Z90_ONE_SIDED)[1],
        )
        self.assertGreater(
            one_sided_upper_95(20, 12, 2, 16, deff_value=2.0),
            one_sided_upper_95(20, 12, 2, 16, deff_value=1.0),
        )

    def test_one_sided_upper_is_the_upper_end_of_the_nominal_90_interval(self) -> None:
        self.assertAlmostEqual(Z90_ONE_SIDED, 1.6448536269514722)
        self.assertEqual(
            one_sided_upper_95(20, 12, 2, 16, deff_value=1.0),
            newcombe10(20, 12, 2, 16, z=Z90_ONE_SIDED)[1],
        )

    def test_empty_table(self) -> None:
        self.assertEqual(newcombe10(0, 0, 0, 0), (None, None))


class TestIcc(unittest.TestCase):
    def test_hand_examples(self) -> None:
        self.assertAlmostEqual(icc_anova([[1, 1], [0, 0]]), 1.0)  # MSB 1, MSW 0
        self.assertAlmostEqual(icc_anova([[1, 0], [1, 0]]), -1.0)  # MSB 0, MSW 0.5, m0 2
        # MSB 1/3, MSW 1/3, m0 = (4 - 10/4) / 1 = 1.5: 0
        self.assertAlmostEqual(icc_anova([[1, 0, 1], [0]]), 0.0)

    def test_undefined(self) -> None:
        self.assertIsNone(icc_anova([[0, 0], [0, 0, 0]]))  # no variance
        self.assertIsNone(icc_anova([[1, 0]]))  # one cluster
        self.assertIsNone(icc_anova([[1], [0]]))  # no within-cluster degrees of freedom


class TestSimulation(unittest.TestCase):
    PI = (0.05, 0.10, 0.0, 0.85)  # both missed, X only, Y only, neither: true difference 0.10

    def test_rho_zero_gives_the_marginal_probabilities(self) -> None:
        rng = random.Random(1)
        counts = [0, 0, 0, 0]
        for _ in range(400):
            for cell in paired_data([5, 5], 0.0, self.PI, rng):
                counts[cell] += 1
        total = sum(counts)
        self.assertAlmostEqual(counts[1] / total, 0.10, delta=0.02)
        self.assertEqual(counts[2], 0)  # a zero cell is never drawn

    def test_clustering_raises_the_between_cluster_variance(self) -> None:
        def spread(rho: float) -> float:
            rng = random.Random(7)
            shares = []
            for _ in range(300):
                cells = paired_data([10], rho, self.PI, rng)
                shares.append(sum(c == 1 for c in cells) / 10)
            return sum((s - 0.10) ** 2 for s in shares) / len(shares)

        self.assertGreater(spread(0.3), 2 * spread(0.0))

    def test_reproducible_with_its_seed(self) -> None:
        sizes = [2, 2, 1, 1, 1]
        one = coverage(sizes, 0.1, 0.3, self.PI, reps=200, seed=20261121)
        two = coverage(sizes, 0.1, 0.3, self.PI, reps=200, seed=20261121)
        self.assertEqual(one, two)
        table_one = coverage_table({"s": sizes}, [0.0, 0.2], 0.3, [self.PI], reps=50, seed=5)
        table_two = coverage_table({"s": sizes}, [0.0, 0.2], 0.3, [self.PI], reps=50, seed=5)
        self.assertEqual(table_one, table_two)
        # the seed is what changes the draws (coverage itself can be 1.0 for every seed here)
        self.assertNotEqual(
            paired_data([5] * 20, 0.1, self.PI, random.Random(1)),
            paired_data([5] * 20, 0.1, self.PI, random.Random(2)),
        )
        self.assertEqual(
            paired_data([5] * 20, 0.1, self.PI, random.Random(1)),
            paired_data([5] * 20, 0.1, self.PI, random.Random(1)),
        )

    def test_coverage_is_a_proportion_of_covering_upper_limits(self) -> None:
        # no difference and no miss: every upper limit is above 0, so coverage is 1
        self.assertEqual(coverage([1] * 20, 0.0, 0.0, (0.0, 0.0, 0.0, 1.0), reps=20, seed=3), 1.0)
        value = coverage([1] * 30, 0.0, 0.0, self.PI, reps=400, seed=3)
        self.assertTrue(0.85 < value <= 1.0, value)
        self.assertFalse(math.isnan(value))


if __name__ == "__main__":
    unittest.main()
