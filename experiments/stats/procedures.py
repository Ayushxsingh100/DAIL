"""The statistical procedures of the frozen protocol (P10d Section 3, from the paper's §IV-H; C-231,
C-235 to C-241). Standard library only (``math``, ``statistics.NormalDist``).

* ``wilson``: the Wilson score interval (Wilson 1927) of k in n; k and n may be real numbers (the
  cells of a table divided by a design effect).
* ``sign_test``: the exact sign test (binomial, p = 1/2) on n_plus positive and n_minus negative
  differences (zeros dropped); ``greater``: P(X >= n_plus); ``two-sided``: twice the smaller tail,
  at most 1. ``mcnemar_exact`` is the same test on the discordant pairs b and c (for single-scenario
  clusters the cluster sign test is exact McNemar).
* ``holm``: Holm's (1979) step-down adjusted p-values and rejections at alpha.
* ``deff``: DEFF = 1 + [(1 + CV²) m̄ - 1] ρ (Rao and Scott 1992; Eldridge et al. 2006), m̄ the mean
  cluster size, CV the coefficient of variation of cluster size with the population standard
  deviation, so (1 + CV²) m̄ = Σ m² / Σ m (C-241 (2)).
* ``newcombe10``: Newcombe's (1998) method 10 for the difference of paired proportions p1 - p2,
  with a = both, b = first only, c = second only, d = neither: the Wilson limits (l1, u1) of p1 =
  (a + b) / n and (l2, u2) of p2 = (a + c) / n, φ = (ad - bc) / √((a+b)(c+d)(a+c)(b+d)) with
  ad - bc replaced by max(ad - bc - n/2, 0) when ad > bc (0 when a margin is 0),
  L = p1 - p2 - √((p1-l1)² - 2φ(p1-l1)(u2-p2) + (u2-p2)²),
  U = p1 - p2 + √((u1-p1)² - 2φ(u1-p1)(p2-l2) + (p2-l2)²).
* ``one_sided_upper_95``: the paper's one-sided 95% upper limit, the upper end of the nominal 90%
  method-10 interval after each cell is divided by DEFF.
* ``icc_anova``: the one-way ANOVA estimator of the intraclass correlation for unequal cluster
  sizes, ρ = (MSB - MSW) / (MSB + (m0 - 1) MSW), m0 = (N - Σ n_i² / N) / (k - 1); None when it is
  undefined (fewer than 2 clusters, no within-cluster degree of freedom, or no variance; C-241 (3)).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from statistics import NormalDist, fmean, pvariance
from typing import Final

Z95: Final = NormalDist().inv_cdf(0.975)
Z90_ONE_SIDED: Final = NormalDist().inv_cdf(0.95)  # one-sided 95% = upper end of nominal 90%


def wilson(k: float, n: float, *, z: float = Z95) -> tuple[float | None, float | None]:
    if n <= 0:
        return None, None
    p = k / n
    z2 = z * z
    centre = (p + z2 / (2 * n)) / (1 + z2 / n)
    half = z * math.sqrt(max(0.0, p * (1 - p) / n + z2 / (4 * n * n))) / (1 + z2 / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def _tail_ge(k: int, n: int) -> float:
    total: int = sum(math.comb(n, i) for i in range(k, n + 1))
    return total / (1 << n)


def sign_test(n_plus: int, n_minus: int, *, alternative: str) -> float:
    n = n_plus + n_minus
    if n == 0:
        return 1.0
    if alternative == "greater":
        return _tail_ge(n_plus, n)
    if alternative == "two-sided":
        return min(1.0, 2 * min(_tail_ge(n_plus, n), _tail_ge(n_minus, n)))
    raise ValueError(f"alternative {alternative!r}")


def min_p_two_sided(discordant: int) -> float:
    """The smallest two-sided p-value the exact sign test can reach with ``discordant`` non-zero
    clusters (all on one side): 2 · 0.5^k, capped at 1 (C-243)."""
    if discordant < 0:
        raise ValueError(f"discordant {discordant}")
    return min(1.0, 2 / (1 << discordant))


def mcnemar_exact(b: int, c: int, *, alternative: str = "two-sided") -> float:
    return sign_test(b, c, alternative=alternative)


def holm(pvalues: Mapping[str, float], *, alpha: float) -> tuple[dict[str, float], dict[str, bool]]:
    ordered = sorted(pvalues.items(), key=lambda kv: (kv[1], kv[0]))
    m = len(ordered)
    adjusted: dict[str, float] = {}
    running = 0.0
    for i, (name, p) in enumerate(ordered):
        running = max(running, min(1.0, (m - i) * p))
        adjusted[name] = running
    return adjusted, {name: adjusted[name] <= alpha for name in pvalues}


def deff(sizes: Sequence[int], rho: float) -> float:
    if not sizes or rho == 0:
        return 1.0
    mean = fmean(sizes)
    cv2 = pvariance(sizes) / (mean * mean)
    return 1 + ((1 + cv2) * mean - 1) * rho


def newcombe10(
    a: float, b: float, c: float, d: float, *, z: float = Z95
) -> tuple[float | None, float | None]:
    n = a + b + c + d
    if n <= 0:
        return None, None
    p1, p2 = (a + b) / n, (a + c) / n
    l1, u1 = wilson(a + b, n, z=z)
    l2, u2 = wilson(a + c, n, z=z)
    assert l1 is not None and u1 is not None and l2 is not None and u2 is not None
    margins = (a + b) * (c + d) * (a + c) * (b + d)
    if margins <= 0:
        phi = 0.0
    else:
        num = a * d - b * c
        if num > 0:
            num = max(num - n / 2, 0.0)
        phi = num / math.sqrt(margins)
    diff = p1 - p2
    delta = math.sqrt(max(0.0, (p1 - l1) ** 2 - 2 * phi * (p1 - l1) * (u2 - p2) + (u2 - p2) ** 2))
    epsilon = math.sqrt(max(0.0, (u1 - p1) ** 2 - 2 * phi * (u1 - p1) * (p2 - l2) + (p2 - l2) ** 2))
    return max(-1.0, diff - delta), min(1.0, diff + epsilon)


def one_sided_upper_95(
    a: float, b: float, c: float, d: float, *, deff_value: float
) -> float | None:
    return newcombe10(
        a / deff_value, b / deff_value, c / deff_value, d / deff_value, z=Z90_ONE_SIDED
    )[1]


def icc_anova(groups: Sequence[Sequence[float]]) -> float | None:
    groups = [list(g) for g in groups if len(g)]
    k = len(groups)
    n_total = sum(len(g) for g in groups)
    if k < 2 or n_total - k < 1:
        return None
    grand = sum(sum(g) for g in groups) / n_total
    msb = sum(len(g) * (fmean(g) - grand) ** 2 for g in groups) / (k - 1)
    msw = sum(sum((y - fmean(g)) ** 2 for y in g) for g in groups) / (n_total - k)
    m0 = (n_total - sum(len(g) ** 2 for g in groups) / n_total) / (k - 1)
    denominator = msb + (m0 - 1) * msw
    if math.isclose(denominator, 0.0, abs_tol=1e-15):
        return None
    return (msb - msw) / denominator
