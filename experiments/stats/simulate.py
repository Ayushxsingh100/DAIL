"""Simulations of the frozen protocol (P10d-1, C-235; the power simulations of Section 3). Standard
library only; every run takes a seed and is reproducible with it.

**Paired clustered data** (C-241 (4)): each scenario has one of four outcomes, the cells of the
paired table: 0 both missed, 1 the first condition only, 2 the second only, 3 neither, with
probabilities ``pi``. With ρ > 0 each cluster draws its own probabilities from a Dirichlet
distribution with parameters pi_j (1 - ρ) / ρ (a Dirichlet-multinomial model), so the indicator of
every cell has intraclass correlation ρ; ρ = 0 gives independent scenarios. A cell with
probability 0 is never drawn.

**Coverage** of the one-sided 95% upper limit of p1 - p2 (= pi_1 - pi_2): the share of
replications whose limit (method 10 with the cells divided by DEFF, ``one_sided_upper_95``) is at
least the true difference. The analysis's DEFF uses ``rho_analysis`` (C-241 (5)).

**Power** of H1 (the two-sided exact cluster sign test per stratum on the cluster MR differences,
Holm across the strata at alpha) and of H2's workload test (the one-sided exact sign test on the
cluster mean W_C - W_B, clusters drawn with replacement from the dev clusters of each tier).
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from typing import Any

from experiments.stats.procedures import deff, holm, one_sided_upper_95, sign_test

Pi = tuple[float, float, float, float]


def _cluster_probs(pi: Pi, rho: float, rng: random.Random) -> list[float]:
    if rho <= 0:
        return list(pi)
    scale = (1 - rho) / rho
    draws = [rng.gammavariate(p * scale, 1.0) if p > 0 else 0.0 for p in pi]
    total = sum(draws)
    if total <= 0:
        return list(pi)
    return [x / total for x in draws]


def paired_clusters(
    sizes: Sequence[int], rho: float, pi: Pi, rng: random.Random
) -> list[list[int]]:
    found = []
    for size in sizes:
        probs = _cluster_probs(pi, rho, rng)
        cells = []
        for _ in range(size):
            u, acc, cell = rng.random(), 0.0, 3
            for j, p in enumerate(probs):
                acc += p
                if u < acc and p > 0:
                    cell = j
                    break
            else:
                cell = max(j for j, p in enumerate(probs) if p > 0)
            cells.append(cell)
        found.append(cells)
    return found


def paired_data(sizes: Sequence[int], rho: float, pi: Pi, rng: random.Random) -> list[int]:
    return [c for cluster in paired_clusters(sizes, rho, pi, rng) for c in cluster]


def coverage(
    sizes: Sequence[int], rho: float, rho_analysis: float, pi: Pi, *, reps: int, seed: int
) -> float:
    rng = random.Random(seed)
    truth = pi[1] - pi[2]
    design = deff(sizes, rho_analysis)
    covered = 0
    for _ in range(reps):
        cells = paired_data(sizes, rho, pi, rng)
        counts = [cells.count(j) for j in range(4)]
        upper = one_sided_upper_95(*counts, deff_value=design)
        covered += upper is not None and upper >= truth - 1e-12
    return covered / reps


def coverage_table(
    configs: Mapping[str, Sequence[int]],
    rhos: Sequence[float],
    rho_analysis: float,
    pis: Sequence[Pi],
    *,
    reps: int,
    seed: int,
) -> list[dict[str, Any]]:
    rows = []
    index = 0
    for name, sizes in configs.items():
        for rho in rhos:
            for pi in pis:
                index += 1
                rows.append(
                    {
                        "config": name,
                        "rho": rho,
                        "pi": list(pi),
                        "true_difference": pi[1] - pi[2],
                        "coverage": coverage(
                            sizes, rho, rho_analysis, pi, reps=reps, seed=seed * 100_003 + index
                        ),
                    }
                )
    return rows


def h1_power(
    strata: Mapping[str, Sequence[int]],
    mr_c: float,
    effect: float,
    rho: float,
    *,
    alpha: float,
    reps: int,
    seed: int,
) -> dict[str, float]:
    """A misses whatever C misses plus ``effect``: pi = (mr_c, effect, 0, 1 - mr_c - effect)."""
    rng = random.Random(seed)
    pi: Pi = (mr_c, effect, 0.0, max(0.0, 1 - mr_c - effect))
    hits = dict.fromkeys(strata, 0)
    for _ in range(reps):
        pvalues = {}
        for name, sizes in strata.items():
            plus = minus = 0
            for cluster in paired_clusters(sizes, rho, pi, rng):
                d = sum(c == 1 for c in cluster) - sum(c == 2 for c in cluster)
                plus += d > 0
                minus += d < 0
            pvalues[name] = sign_test(plus, minus, alternative="two-sided")
        _, rejected = holm(pvalues, alpha=alpha)
        for name in strata:
            hits[name] += rejected[name]
    return {name: hits[name] / reps for name in strata}


def h2_power(
    tiers: Mapping[str, tuple[Sequence[float], int]], *, alpha: float, reps: int, seed: int
) -> float:
    """``tiers``: per tier, the dev cluster means of W_C - W_B and the number of test clusters."""
    rng = random.Random(seed)
    hits = 0
    for _ in range(reps):
        favour_c = against = 0
        for means, count in tiers.values():
            for _ in range(count):
                d = rng.choice(list(means))
                favour_c += d < 0
                against += d > 0
        hits += sign_test(favour_c, against, alternative="greater") < alpha
    return hits / reps
