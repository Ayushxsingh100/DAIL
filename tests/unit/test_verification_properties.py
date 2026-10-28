"""Properties of the security predicates on generated group and rule sets (P5a step 7; C-146).

Seeded ``random`` (standard library), five seeds. The generator writes configurations in which each
group uses one style only (inline blocks, or rule resources), so no group is MIXED and a baseline
has no RETAINED-INLINE group; every rule is determinate. For those the expected result is computed
by an independent oracle in this file (a group's TCP/p rules cover the whole range when their
sources hold both halves of the address space), never by the code under test.

Properties checked:

* the result equals the oracle's, and is the worst-clause combination of the clauses (§3.4);
* ``PIP`` is monotone: adding an allow rule never turns a FAIL into a non-FAIL, and removing a rule
  never turns a non-FAIL into a FAIL;
* the order of groups, rules, CIDRs and resources never changes the result;
* every indeterminate or unsupported input gives UNKNOWN, UNSUPPORTED or FAIL, never PASS (the
  executable form of "unknown and unsupported cases do not become PASS");
* the checkers themselves fail when a rule is dropped.
"""

from __future__ import annotations

import random
import unittest
from collections.abc import Callable
from dataclasses import dataclass, replace

from core.domain.enums import VerificationResult
from core.verification.outcome import PredicateOutcome
from core.verification.public_ingress import evaluate_public_ingress
from core.verification.rds_public_flag import evaluate_rds_public_flag
from tests.security_builders import VARS, inline, resources_of, rule, sg

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
SEEDS = (20261028, 1, 7, 424242, 99991)
CASES_PER_SEED = 25
PORT = 22

PROTOCOLS = ("tcp", "tcp", "tcp", "udp", "-1")
RANGES = ((22, 22), (0, 65535), (20, 30), (80, 80), (5432, 5432), (23, 100))
V4 = (
    (),
    ("0.0.0.0/0",),
    ("0.0.0.0/1",),
    ("128.0.0.0/1",),
    ("10.0.0.0/8",),
    ("0.0.0.0/1", "128.0.0.0/1"),
)
V6 = ((), ("::/0",), ("::/1",), ("8000::/1",), ("fd00::/8",))


@dataclass(frozen=True)
class Rule:
    protocol: str
    low: int
    high: int
    v4: tuple[str, ...]
    v6: tuple[str, ...]


@dataclass(frozen=True)
class Group:
    name: str
    style: str  # "inline" or "resource"
    rules: tuple[Rule, ...]


Spec = tuple[Group, ...]


def random_rule(rng: random.Random) -> Rule:
    low, high = rng.choice(RANGES)
    protocol = rng.choice(PROTOCOLS)
    if protocol == "-1":
        low = high = 0
    return Rule(protocol, low, high, rng.choice(V4), rng.choice(V6))


def random_spec(rng: random.Random) -> Spec:
    return tuple(
        Group(
            f"g{index}",
            rng.choice(("inline", "resource")),
            tuple(random_rule(rng) for _ in range(rng.randint(0, 4))),
        )
        for index in range(rng.randint(1, 4))
    )


def render(spec: Spec) -> str:
    text = ""
    for group in spec:
        if group.style == "inline":
            body = "".join(
                inline("ingress", r.protocol, r.low, r.high, list(r.v4) or None, list(r.v6) or None)
                for r in group.rules
            )
            text += sg(group.name, body)
        else:
            text += sg(group.name)
            for index, r in enumerate(group.rules):
                text += rule(
                    f"{group.name}_{index}",
                    "ingress",
                    r.protocol,
                    r.low,
                    r.high,
                    list(r.v4) or None,
                    list(r.v6) or None,
                    target=f"aws_security_group.{group.name}.id",
                )
    return text


def evaluate(spec: Spec, port: int = PORT) -> PredicateOutcome:
    return evaluate_public_ingress(port, resources_of(render(spec)))


# --- the oracle: independent of core.verification --------------------------------------------


def halves(cidrs: tuple[str, ...]) -> set[int]:
    """Which halves of the address space a CIDR list covers: only /0 and /1 are big enough."""
    found: set[int] = set()
    for cidr in cidrs:
        if cidr in ("0.0.0.0/0", "::/0"):
            found |= {0, 1}
        elif cidr in ("0.0.0.0/1", "::/1"):
            found.add(0)
        elif cidr in ("128.0.0.0/1", "8000::/1"):
            found.add(1)
    return found


def permits(r: Rule, port: int) -> bool:
    return r.protocol == "-1" or (r.protocol == "tcp" and r.low <= port <= r.high)


def oracle(spec: Spec, port: int = PORT) -> dict[str, VerificationResult]:
    clauses = {}
    for name, field in (("IPV4", "v4"), ("IPV6", "v6")):
        failing = False
        for group in spec:
            union: set[int] = set()
            for r in group.rules:
                if permits(r, port):
                    union |= halves(getattr(r, field))
            failing = failing or union == {0, 1}
        clauses[name] = F if failing else P
    return clauses


def oracle_result(clauses: dict[str, VerificationResult]) -> VerificationResult:
    return F if F in clauses.values() else P


def got_clauses(outcome: PredicateOutcome) -> dict[str, VerificationResult]:
    return dict(outcome.clauses or {})


# --- the property checkers: each returns the cases that violate it ----------------------------

Evaluator = Callable[[Spec], PredicateOutcome]


def oracle_violations(evaluator: Evaluator, specs: list[Spec]) -> list[Spec]:
    bad = []
    for spec in specs:
        outcome = evaluator(spec)
        want = oracle(spec)
        if got_clauses(outcome) != want or outcome.result is not oracle_result(want):
            bad.append(spec)
    return bad


def add_rule(spec: Spec, rng: random.Random) -> Spec:
    index = rng.randrange(len(spec))
    group = spec[index]
    grown = replace(group, rules=(*group.rules, random_rule(rng)))
    return (*spec[:index], grown, *spec[index + 1 :])


def drop_rule(spec: Spec, rng: random.Random) -> Spec | None:
    candidates = [i for i, g in enumerate(spec) if g.rules]
    if not candidates:
        return None
    index = rng.choice(candidates)
    group = spec[index]
    victim = rng.randrange(len(group.rules))
    smaller = replace(group, rules=(*group.rules[:victim], *group.rules[victim + 1 :]))
    return (*spec[:index], smaller, *spec[index + 1 :])


def monotone_violations(evaluator: Evaluator, specs: list[Spec], seed: int) -> list[Spec]:
    """Adding an allow rule must keep every FAILed clause failed; a clause that FAILs after a rule
    was removed must already have FAILed before (the smaller configuration is a subset)."""
    rng = random.Random(seed)
    bad = []
    for spec in specs:
        before = got_clauses(evaluator(spec))
        after = got_clauses(evaluator(add_rule(spec, rng)))
        if any(clause is F and after[name] is not F for name, clause in before.items()):
            bad.append(spec)
        smaller = drop_rule(spec, rng)
        if smaller is not None:
            fewer = got_clauses(evaluator(smaller))
            if any(clause is F and before[name] is not F for name, clause in fewer.items()):
                bad.append(spec)
    return bad


def generated(seed: int) -> list[Spec]:
    rng = random.Random(seed)
    return [random_spec(rng) for _ in range(CASES_PER_SEED)]


class TestAgainstTheOracle(unittest.TestCase):
    def test_the_result_and_both_clauses_equal_the_oracle(self) -> None:
        total = fails = 0
        for seed in SEEDS:
            specs = generated(seed)
            self.assertEqual(oracle_violations(evaluate, specs), [], f"seed {seed}")
            total += len(specs)
            fails += sum(1 for spec in specs if oracle_result(oracle(spec)) is F)
        self.assertEqual(total, len(SEEDS) * CASES_PER_SEED)
        self.assertGreater(fails, 10)  # the property is not vacuous in either direction
        self.assertGreater(total - fails, 10)

    def test_the_other_port_equals_the_oracle_too(self) -> None:
        for seed in SEEDS[:2]:
            for spec in generated(seed):
                outcome = evaluate(spec, 5432)
                want = oracle(spec, 5432)
                self.assertEqual(got_clauses(outcome), want)
                self.assertIs(outcome.result, oracle_result(want))

    def test_the_result_is_the_worst_clause_combination(self) -> None:
        rank = {P: 0, U: 1, S: 2}
        for seed in SEEDS:
            for spec in generated(seed):
                outcome = evaluate(spec)
                clauses = got_clauses(outcome)
                expected = (
                    F if F in clauses.values() else max(clauses.values(), key=rank.__getitem__)
                )
                self.assertIs(outcome.result, expected)


class TestMonotone(unittest.TestCase):
    def test_adding_a_rule_never_removes_a_fail_and_removing_one_never_adds_it(self) -> None:
        for seed in SEEDS:
            self.assertEqual(
                monotone_violations(evaluate, generated(seed), seed), [], f"seed {seed}"
            )


class TestOrder(unittest.TestCase):
    def test_the_order_of_groups_rules_and_cidrs_never_changes_the_result(self) -> None:
        for seed in SEEDS:
            rng = random.Random(seed)
            for spec in generated(seed):
                base = evaluate(spec)
                groups = [
                    replace(
                        g,
                        rules=tuple(
                            replace(
                                r,
                                v4=tuple(rng.sample(r.v4, len(r.v4))),
                                v6=tuple(rng.sample(r.v6, len(r.v6))),
                            )
                            for r in rng.sample(g.rules, len(g.rules))
                        ),
                    )
                    for g in rng.sample(spec, len(spec))
                ]
                shuffled = evaluate(tuple(groups))
                self.assertEqual(
                    (shuffled.result, got_clauses(shuffled)), (base.result, got_clauses(base))
                )

    def test_the_order_of_resources_never_changes_the_outcome(self) -> None:
        rng = random.Random(SEEDS[0])
        for spec in generated(SEEDS[0]):
            resources = list(resources_of(render(spec)))
            base = evaluate_public_ingress(PORT, resources)
            rng.shuffle(resources)
            self.assertEqual(evaluate_public_ingress(PORT, resources), base)


class TestNeverPass(unittest.TestCase):
    """Every indeterminate or unsupported input is UNKNOWN, UNSUPPORTED or FAIL, never PASS."""

    POISONS = {
        "unresolved source": VARS + sg("p", inline("ingress", "tcp", 22, 22, "[var.ssh_cidr]")),
        "prefix list": sg("p")
        + rule(
            "p",
            "ingress",
            "tcp",
            22,
            22,
            extra='  prefix_list_ids = ["pl-1"]\n',
            target="aws_security_group.p.id",
        ),
        "invalid cidr": sg("p", inline("ingress", "udp", 80, 80, ["10.0.0.1/8"])),
        "mixed group": sg("p", inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"]))
        + rule("m", "ingress", "tcp", 81, 81, ["10.0.0.0/8"], target="aws_security_group.p.id"),
        "unexpandable dynamic block": VARS
        + sg(
            "p",
            '  dynamic "ingress" {\n    for_each = var.u\n    content {\n      protocol = "tcp"\n'
            "      from_port = 22\n      to_port = 22\n      cidr_blocks = []\n    }\n  }\n",
        ),
        "relevant-unsupported type": sg("p")
        + 'resource "aws_default_security_group" "d" {\n  vpc_id = "vpc-1"\n}\n',
        "unresolved ingress form": VARS + sg("p", "  ingress = var.u\n"),
        "rule with an unresolved type": VARS
        + sg("p")
        + rule("t", "var.u", "tcp", 22, 22, ["0.0.0.0/0"], target="aws_security_group.p.id"),
        "group with an unknown count": VARS
        + 'resource "aws_security_group" "c" {\n  count = var.u\n}\n',
        "unknown rule resource": VARS
        + sg("p")
        + 'resource "aws_security_group_rule" "u" {\n  count = var.u\n  type = "ingress"\n'
        '  security_group_id = aws_security_group.p.id\n  protocol = "tcp"\n'
        "  from_port = 22\n  to_port = 22\n}\n",
    }

    def test_each_poison_alone_is_not_a_pass(self) -> None:
        for name, poison in self.POISONS.items():
            with self.subTest(poison=name):
                outcome = evaluate_public_ingress(PORT, resources_of(poison))
                self.assertIn(outcome.result, (U, S))  # alone there is nothing to FAIL

    def test_each_poison_on_top_of_a_random_base_is_unknown_unsupported_or_fail(self) -> None:
        for name, poison in self.POISONS.items():
            for spec in generated(SEEDS[1])[:6]:
                text = VARS + render(spec) + poison.replace(VARS, "")
                with self.subTest(poison=name):
                    outcome = evaluate_public_ingress(PORT, resources_of(text))
                    self.assertIn(outcome.result, (U, S, F))

    def test_the_database_flag_never_passes_on_unresolved_input(self) -> None:
        unresolved = (
            'variable "u" {}\nresource "aws_db_instance" "d" {\n  identifier = "d"\n'
            "  publicly_accessible = var.u\n}\n",
            'variable "n" {}\nresource "aws_db_instance" "d" {\n  count = var.n\n'
            '  identifier = "d"\n}\n',
            'resource "aws_db_instance" "d" {\n  identifier = "d"\n'
            '  publicly_accessible = "maybe"\n}\n',
        )
        for text in unresolved:
            self.assertIsNot(evaluate_rds_public_flag(resources_of(text)).result, P)


class TestTheCheckersCanFail(unittest.TestCase):
    """A property checker that cannot fail proves nothing: break the predicate and see it fail."""

    def test_dropping_the_last_rule_of_every_group_is_caught(self) -> None:
        def dropping(spec: Spec) -> PredicateOutcome:
            return evaluate(tuple(replace(g, rules=g.rules[:-1]) for g in spec))

        caught = sum(len(oracle_violations(dropping, generated(seed))) for seed in SEEDS)
        self.assertGreater(caught, 5)

    def test_ignoring_ipv6_is_caught(self) -> None:
        def no_ipv6(spec: Spec) -> PredicateOutcome:
            return evaluate(
                tuple(replace(g, rules=tuple(replace(r, v6=()) for r in g.rules)) for g in spec)
            )

        caught = sum(len(oracle_violations(no_ipv6, generated(seed))) for seed in SEEDS)
        self.assertGreater(caught, 5)

    def test_a_non_monotone_predicate_is_caught(self) -> None:
        def forgetful(spec: Spec) -> PredicateOutcome:
            # forgets every rule when the number of rules is odd: adding one can remove a FAIL
            odd = sum(len(g.rules) for g in spec) % 2 == 1
            return evaluate(tuple(replace(g, rules=()) for g in spec)) if odd else evaluate(spec)

        caught = sum(len(monotone_violations(forgetful, generated(seed), seed)) for seed in SEEDS)
        self.assertGreater(caught, 5)


if __name__ == "__main__":
    unittest.main()
