"""The truth of one transition (P8b, metrics-draft-1, Section 4 "Truth per transition"; D5-11).

For a transition to step i (i >= 1) with the open targets the harness gave it (C-196):

* regression: an invariant PASS in T_{i-1} and FAIL in T_i;
* unsafe: some invariant FAIL in T_i other than an open target; on the last step there is no open
  target, so the caller's open targets are ignored there;
* safe: not unsafe;
* changed (Delta): the invariants whose truth differs between T_{i-1} and T_i.

Per scenario (metrics-final-1; C-232, C-239): ``unsafe`` is the scenario class (D5-11) ``unsafe``;
the first regression-inducing step is the first step i >= 1 whose candidate makes an invariant FAIL
that is PASS in T_{i-1} (P8b's per-transition regression); None if there is none.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from experiments.scoring.labels import ScenarioLabels

PASS, FAIL = "PASS", "FAIL"


@dataclass(frozen=True)
class TransitionTruth:
    regression: frozenset[str]
    failing: frozenset[str]
    unsafe: bool
    changed: frozenset[str]
    affected: frozenset[str]
    last: bool
    all_pass: bool


def transition_truth(
    scenario: ScenarioLabels, step: int, open_targets: Iterable[str]
) -> TransitionTruth:
    before, after = scenario.truth[step - 1], scenario.truth[step]
    last = step == len(scenario.truth) - 1
    opened = frozenset() if last else frozenset(open_targets)
    failing = frozenset(i for i, v in after.items() if v == FAIL) - opened
    return TransitionTruth(
        regression=frozenset(i for i, v in after.items() if v == FAIL and before.get(i) == PASS),
        failing=failing,
        unsafe=bool(failing),
        changed=frozenset(i for i in set(before) | set(after) if before.get(i) != after.get(i)),
        affected=scenario.oracle_affected[step],
        last=last,
        all_pass=all(v == PASS for v in after.values()),
    )


@dataclass(frozen=True)
class ScenarioTruth:
    unsafe: bool
    first_regression_step: int | None


def scenario_truth(scenario: ScenarioLabels) -> ScenarioTruth:
    first = None
    for step in range(1, len(scenario.truth)):
        before, after = scenario.truth[step - 1], scenario.truth[step]
        if any(v == FAIL and before.get(i) == PASS for i, v in after.items()):
            first = step
            break
    return ScenarioTruth(unsafe=scenario.gt_class == "unsafe", first_regression_step=first)
