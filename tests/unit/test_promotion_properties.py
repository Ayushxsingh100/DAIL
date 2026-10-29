"""Properties of ``decide`` over generated worlds (P6a step 6; Doc 12 §17; C-45, C-158 to C-161).

Seeded ``random`` (standard library), five seeds, 60 worlds each. Every property is stated from the
spec, not from the code:

* a required FAIL never gives PROMOTE (and gives REJECT); a required UNKNOWN, UNSUPPORTED or
  VERIFIER_ERROR never gives PROMOTE;
* PROMOTE implies every required invariant has a proof-plan entry and every supporting result id is
  in the verification report;
* a stale parent never gives PROMOTE;
* an affected, uncertain, non-PROTECTED, or policy-disabled invariant never appears with the source
  CARRIED_FORWARD (the executable form of C-45);
* the decision does not depend on which item carries which non-success (order independence);
* ``decide`` does not mutate any argument and is deterministic;
* the emergency switch, the retry budget and the oracle conflict each stop a PROMOTE.

Each property is run by a checker function, and the last class shows that every checker FAILS on a
decision that breaks its rule (a test that cannot fail proves nothing).
"""

from __future__ import annotations

import dataclasses
import itertools
import random
import unittest
from collections.abc import Callable
from typing import Any

from core.domain.enums import DecisionType, InvariantStatus, VerificationResult
from core.domain.promotion import (
    DecisionOutcome,
    DecisionReason,
    OracleVerdict,
    ProofSource,
)
from tests.domain_builders import uid
from tests.promotion_builders import (
    ALL,
    BASELINE_ITEM,
    ERROR,
    FAIL,
    GATES,
    PASS,
    SEC1,
    UNKNOWN,
    UNSUPPORTED,
    World,
    make_world,
    run,
    target,
    trusted_state,
)

D, R = DecisionType, DecisionReason
SEEDS = (20261029, 1, 7, 424242, 99991)
WORLDS = 60
NON_SUCCESS = (UNKNOWN, UNSUPPORTED, ERROR)
RESULT_CHOICES: list[VerificationResult | None] = [PASS] * 8 + [
    FAIL,
    UNKNOWN,
    UNSUPPORTED,
    ERROR,
    None,
]
STATUS_CHOICES = (
    InvariantStatus.PROTECTED,
    InvariantStatus.PROTECTED,
    InvariantStatus.VIOLATED,
    InvariantStatus.UNCERTAIN,
)
REQUIRED_TARGETS = (*GATES, *(target(i) for i in ALL), BASELINE_ITEM)


@dataclasses.dataclass
class Case:
    world: World
    results: dict[str, VerificationResult | None]
    roles: dict[str, str]
    statuses: dict[str, InvariantStatus]
    attempt: int
    oracle: list[OracleVerdict]
    stale: bool


def random_case(rng: random.Random) -> Case:
    friendly = rng.random() < 0.5  # half the worlds start from a promotable one and are spoiled
    statuses = {i: rng.choice(STATUS_CHOICES) for i in ALL}
    roles = {
        i: rng.choice(["affected", "affected", "uncertain", "carry", "carry", "ineligible", "none"])
        for i in ALL
    }
    if friendly:
        roles = {i: rng.choice(["affected", "carry"]) for i in ALL}
        statuses = {
            i: InvariantStatus.PROTECTED if roles[i] == "carry" else rng.choice(STATUS_CHOICES)
            for i in ALL
        }

    def pick(role: str) -> list[str]:
        return [i for i in ALL if roles[i] == role]

    owed = [*GATES, BASELINE_ITEM, *(target(i) for i in pick("affected") + pick("uncertain"))]
    results: dict[str, VerificationResult | None] = {}
    for tid in (*owed, *(target(i) for i in ALL if rng.random() < 0.25)):
        results[tid] = PASS if friendly and rng.random() < 0.93 else rng.choice(RESULT_CHOICES)
    if friendly and rng.random() < 0.4:  # exactly one thing is wrong
        for tid in owed:
            results[tid] = PASS
        results[rng.choice(owed)] = rng.choice([FAIL, UNKNOWN, UNSUPPORTED, ERROR, None])
    world = make_world(
        results=results,  # type: ignore[arg-type]
        affected=pick("affected"),
        uncertain=pick("uncertain"),
        carry=pick("carry"),
        ineligible=pick("ineligible"),
        statuses=statuses,
        automatic_enabled=rng.random() < 0.9,
    ).with_policy(
        carry_forward_enabled=rng.random() < 0.9,
        max_attempts=rng.randint(2, 6),
        conflict_decision=rng.choice([D.REJECT, D.ESCALATE]),
    )
    stale = rng.random() < 0.08
    if stale:
        world = dataclasses.replace(world, trusted=trusted_state(statuses, state_id=uid(2)))
    verdicts = [
        OracleVerdict(i, 1, rng.choice([PASS, FAIL]), "oracle-1") for i in ALL if rng.random() < 0.1
    ]
    return Case(world, results, roles, statuses, rng.randint(1, 5), verdicts, stale)


def cases() -> list[tuple[int, Case]]:
    return [
        (seed, random_case(random.Random(seed * 1000 + n))) for seed in SEEDS for n in range(WORLDS)
    ]


def decide_case(case: Case) -> DecisionOutcome:
    return run(case.world, attempt_number=case.attempt, oracle=case.oracle)


# --- the checkers: each returns the list of ways a decision breaks one rule -----------------------


def check_fail_rejects(case: Case, out: DecisionOutcome) -> list[str]:
    fails = [t for t in REQUIRED_TARGETS if case.results.get(t) is FAIL]
    if fails and out.decision.decision is not D.REJECT:
        return [f"a required FAIL on {fails[0]} gave {out.decision.decision.value}"]
    return []


def check_non_success_never_promotes(case: Case, out: DecisionOutcome) -> list[str]:
    bad = [t for t in REQUIRED_TARGETS if case.results.get(t) in NON_SUCCESS]
    if bad and out.decision.decision is D.PROMOTE:
        return [f"a required non-success on {bad[0]} gave PROMOTE"]
    return []


def check_promote_has_full_proof(case: Case, out: DecisionOutcome) -> list[str]:
    if out.decision.decision is not D.PROMOTE:
        return []
    problems = []
    planned = {e.invariant_id for e in out.proof_plan}
    required = {r.invariant_id for r in case.world.trusted.invariant_refs}
    if planned != required:
        problems.append(f"plan {sorted(planned)} is not the required set {sorted(required)}")
    report_ids = {r.verification_id for r in case.world.verification.results}
    if (
        not set(out.decision.supporting_results) <= report_ids
        or not out.decision.supporting_results
    ):
        problems.append("a supporting result is not in the report, or there is none")
    if out.decision.blocking_conditions:
        problems.append("a PROMOTE with blocking conditions")
    if any(c.source is None for c in out.decision.required_checks):
        problems.append("a PROMOTE with an unproven required check")
    return problems


def check_stale_never_promotes(case: Case, out: DecisionOutcome) -> list[str]:
    if case.stale and (out.decision.decision, out.decision.reason) != (D.REJECT, R.STALE_PARENT):
        return [f"a stale parent gave {out.decision.decision.value} {out.decision.reason.value}"]
    return []


def check_c45(case: Case, out: DecisionOutcome) -> list[str]:
    problems = []
    for entry in out.proof_plan:
        if entry.source is not ProofSource.CARRIED_FORWARD:
            continue
        role = case.roles[entry.invariant_id]
        if role in ("affected", "uncertain"):
            problems.append(f"{entry.invariant_id} was {role} but carried forward")
        if case.statuses[entry.invariant_id] is not InvariantStatus.PROTECTED:
            problems.append(f"{entry.invariant_id} was not PROTECTED but carried forward")
        if role in ("ineligible", "none"):
            problems.append(f"{entry.invariant_id} had no eligible evidence but was carried")
        if not case.world.policy.carry_forward_enabled:
            problems.append("the policy disables carry-forward but a proof was carried")
    return problems


def check_switch_budget_conflict(case: Case, out: DecisionOutcome) -> list[str]:
    problems = []
    if out.decision.decision is D.PROMOTE:
        if not case.world.policy.automatic_enabled:
            problems.append("PROMOTE with the emergency switch off")
        proven = {(e.invariant_id, 1) for e in out.proof_plan}
        for verdict in case.oracle:
            if (
                verdict.result is FAIL
                and (verdict.invariant_id, verdict.invariant_version) in proven
            ):
                problems.append(f"PROMOTE although the oracle failed {verdict.invariant_id}")
    if out.decision.decision is D.RETRY and case.attempt >= case.world.policy.max_attempts:
        problems.append("a RETRY at or beyond the retry budget")
    return problems


CHECKERS: dict[str, Callable[[Case, DecisionOutcome], list[str]]] = {
    "a required FAIL rejects": check_fail_rejects,
    "a non-success never promotes": check_non_success_never_promotes,
    "a PROMOTE has full proof": check_promote_has_full_proof,
    "a stale parent is rejected": check_stale_never_promotes,
    "C-45: nothing affected is carried": check_c45,
    "switch, budget and oracle conflict stop a PROMOTE": check_switch_budget_conflict,
}


class TestProperties(unittest.TestCase):
    def test_each_property_holds_over_the_generated_worlds(self) -> None:
        sample = cases()
        seen: set[tuple[DecisionType, DecisionReason]] = set()
        for name, checker in CHECKERS.items():
            with self.subTest(property=name):
                for seed, case in sample:
                    out = decide_case(case)
                    seen.add((out.decision.decision, out.decision.reason))
                    self.assertEqual(checker(case, out), [], f"seed {seed}")
        # the generator reaches every kind of decision, or the properties would be vacuous
        decisions = {d for d, _ in seen}
        self.assertEqual(decisions, set(DecisionType))
        self.assertGreaterEqual(len(seen), 8)

    def test_a_good_share_of_the_worlds_are_promoted_and_carry_something(self) -> None:
        promoted = carried = 0
        for _, case in cases():
            out = decide_case(case)
            if out.decision.decision is D.PROMOTE:
                promoted += 1
                carried += any(e.source is ProofSource.CARRIED_FORWARD for e in out.proof_plan)
        self.assertGreater(promoted, 10)
        self.assertGreater(carried, 3)

    def test_the_decision_does_not_change_any_argument_and_is_deterministic(self) -> None:
        for seed, case in cases()[::7]:
            w = case.world
            before = (
                w.candidate.to_dict(),
                w.trusted.to_dict(),
                w.impact.to_dict(),
                w.verification.to_dict(),
                w.policy,
                list(case.oracle),
            )
            first = decide_case(case)
            second = decide_case(case)
            after = (
                w.candidate.to_dict(),
                w.trusted.to_dict(),
                w.impact.to_dict(),
                w.verification.to_dict(),
                w.policy,
                list(case.oracle),
            )
            self.assertEqual(before, after, f"seed {seed}")
            self.assertEqual(first, second, f"seed {seed}")

    def test_the_decision_does_not_depend_on_the_order_of_the_oracle_verdicts(self) -> None:
        rng = random.Random(SEEDS[0])
        for _, case in cases()[::5]:
            if len(case.oracle) < 2:
                continue
            want = decide_case(case)
            shuffled = case.oracle[:]
            rng.shuffle(shuffled)
            got = run(case.world, attempt_number=case.attempt, oracle=shuffled)
            self.assertEqual(got, want)


class TestOrderIndependence(unittest.TestCase):
    """The decision depends on the classes of the conditions, not on which item carries which."""

    def decision(self, assignment: dict[str, VerificationResult]) -> tuple[Any, Any]:
        out = run(make_world(results=assignment))  # type: ignore[arg-type]
        return out.decision.decision, out.decision.reason

    def test_swapping_two_results_between_two_items_changes_nothing(self) -> None:
        items = ("STRUCTURAL", "CONSISTENCY", target("INV-FUNC-001"), target(SEC1), BASELINE_ITEM)
        results = (FAIL, UNKNOWN, UNSUPPORTED, ERROR)
        for first, second in itertools.combinations(items, 2):
            for a, b in itertools.permutations(results, 2):
                with self.subTest(first=first, second=second, a=a.value, b=b.value):
                    one = self.decision({first: a, second: b})
                    other = self.decision({first: b, second: a})
                    self.assertEqual(one[0], other[0])
                    # the reason may differ only where an item is a gate (each gate FAIL has its
                    # own code); for two items that are not gates it is equal
                    if first not in GATES and second not in GATES:
                        self.assertEqual(one, other)

    def test_a_fail_is_never_hidden_by_any_other_non_success_at_any_position(self) -> None:
        items = ("STRUCTURAL", "CONSISTENCY", target("INV-FUNC-001"), target(SEC1), BASELINE_ITEM)
        for failing, other in itertools.permutations(items, 2):
            for non_success in NON_SUCCESS:
                with self.subTest(failing=failing, other=other, non_success=non_success.value):
                    got = self.decision({failing: FAIL, other: non_success})
                    self.assertEqual(got[0], D.REJECT)


class TestTheCheckersCanFail(unittest.TestCase):
    """A property that cannot fail proves nothing: hand each checker a decision that breaks it."""

    def case_and_out(self, **kw: Any) -> tuple[Case, DecisionOutcome]:
        world = make_world(**kw)
        case = Case(
            world,
            {t: PASS for t in REQUIRED_TARGETS},
            {i: "affected" if i in (SEC1, "INV-FUNC-001") else "carry" for i in ALL},
            {i: InvariantStatus.PROTECTED for i in ALL},
            1,
            [],
            False,
        )
        return case, run(world)

    def test_a_promote_that_ignores_a_fail_is_caught(self) -> None:
        case, out = self.case_and_out()
        self.assertEqual(out.decision.decision, D.PROMOTE)
        case.results[target(SEC1)] = (
            FAIL  # pretend the report said FAIL while the decision promoted
        )
        self.assertTrue(check_fail_rejects(case, out))

    def test_a_promote_that_ignores_a_non_success_is_caught(self) -> None:
        case, out = self.case_and_out()
        case.results[BASELINE_ITEM] = UNKNOWN
        self.assertTrue(check_non_success_never_promotes(case, out))

    def test_a_promote_without_a_full_plan_is_caught(self) -> None:
        case, out = self.case_and_out()
        thin = dataclasses.replace(out, proof_plan=out.proof_plan[:-1])
        self.assertTrue(check_promote_has_full_proof(case, thin))

    def test_a_promote_for_a_stale_parent_is_caught(self) -> None:
        case, out = self.case_and_out()
        case.stale = True
        self.assertTrue(check_stale_never_promotes(case, out))

    def test_a_carried_affected_invariant_is_caught(self) -> None:
        case, out = self.case_and_out()
        carried = next(e for e in out.proof_plan if e.source is ProofSource.CARRIED_FORWARD)
        case.roles[carried.invariant_id] = "affected"
        self.assertTrue(check_c45(case, out))
        case.roles[carried.invariant_id] = "carry"
        case.statuses[carried.invariant_id] = InvariantStatus.VIOLATED
        self.assertTrue(check_c45(case, out))
        case.statuses[carried.invariant_id] = InvariantStatus.PROTECTED
        case.world = case.world.with_policy(carry_forward_enabled=False)
        self.assertTrue(check_c45(case, out))

    def test_a_promote_with_the_switch_off_is_caught(self) -> None:
        case, out = self.case_and_out()
        case.world = case.world.with_policy(automatic_enabled=False)
        self.assertTrue(check_switch_budget_conflict(case, out))

    def test_a_promote_against_an_oracle_fail_is_caught(self) -> None:
        case, out = self.case_and_out()
        case.oracle = [OracleVerdict("INV-FUNC-001", 1, FAIL, "oracle-1")]
        self.assertTrue(check_switch_budget_conflict(case, out))

    def test_a_retry_beyond_the_budget_is_caught(self) -> None:
        case, _ = self.case_and_out()
        case.world = case.world.with_policy(max_attempts=2)
        retry = run(
            make_world(results={target("INV-FUNC-001"): UNKNOWN}).with_policy(max_attempts=9)
        )
        self.assertEqual(retry.decision.decision, D.RETRY)
        case.attempt = 2
        self.assertTrue(check_switch_budget_conflict(case, retry))


if __name__ == "__main__":
    unittest.main()
