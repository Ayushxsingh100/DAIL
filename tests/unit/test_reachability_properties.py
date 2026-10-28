"""INV-FUNC-001 on generated topologies (P5b step 6; registry §6.3, §6.4; C-151 to C-154).

Part one is **exhaustive** over a family of fully determinate topologies, against an oracle written
in this file with plain ``ipaddress`` arithmetic and the table of §6.4 (no code of
``core.verification``): 6 egress variants x 5 ingress variants x 3 private-IP variants x 3
placements of the instance, 270 configurations. The oracle is hand-derived in its docstring.

Part two is seeded ``random`` (stdlib), five seeds: the result does not depend on the order of the
resources; adding a matching allow rule never turns PASS into non-PASS and never turns UNKNOWN into
FAIL; resources of irrelevant types change nothing; an intra-VPC non-local route, a type of the
relevant-unsupported list, ``propagating_vgws`` or an interface block always gives UNSUPPORTED; and
every indeterminate, partial or unsupported input is UNKNOWN, UNSUPPORTED or FAIL, never PASS (the
executable form of "unknown and unsupported cases do not become PASS").

Part three shows that the checkers themselves fail when a rule is broken.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import random
import unittest
from collections.abc import Callable

from core.domain.enums import VerificationResult
from core.domain.registry_v1 import FUNC_RELEVANT_UNSUPPORTED
from core.verification.outcome import PredicateOutcome
from core.verification.reachability import evaluate_reachability
from tests.func_builders import (
    APP_EGRESS,
    APP_TO_DB,
    DB_SGS_LINE,
    IGW_ROUTE,
    PUBLIC_IP_LINE,
    SOURCE_LINE,
    SUBNET_LINE,
    canonical,
    edit,
    egress_5432,
    ingress_5432,
    rule,
)
from tests.reach_builders import definition, inputs

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
SEEDS = (20261029, 1, 7, 424242, 99991)
VAR = 'variable "u" {}\n'
FAR = (
    '\nresource "aws_vpc" "other" {\n  cidr_block = "10.1.0.0/16"\n}\n'
    '\nresource "aws_subnet" "far" {\n  vpc_id = aws_vpc.other.id\n'
    '  cidr_block = "10.1.1.0/24"\n  availability_zone = "us-east-1a"\n}\n'
)

EGRESS = {
    "all": APP_EGRESS,
    "vpc": egress_5432("e", '  cidr_blocks = ["10.0.0.0/16"]\n'),
    "dbsubnet": egress_5432("e", '  cidr_blocks = ["10.0.2.0/24"]\n'),
    "other_port": rule("e", "egress", "tcp", 5433, 5433, "app", '  cidr_blocks = ["0.0.0.0/0"]\n'),
    "none": "",
    "to_db": egress_5432("e", "  source_security_group_id = aws_security_group.db.id\n"),
}
INGRESS = {
    "group": APP_TO_DB,
    "app_subnet": ingress_5432("i", '  cidr_blocks = ["10.0.1.0/24"]\n'),
    "half": ingress_5432("i", '  cidr_blocks = ["10.0.1.0/25"]\n'),
    "other": ingress_5432("i", '  cidr_blocks = ["10.0.9.0/24"]\n'),
    "none": "",
}
PRIVATE_IP = (None, "10.0.1.10", "10.0.1.200")
PLACEMENT = ("app", "db_b", "far")
SUBNET_CIDR = {"app": "10.0.1.0/24", "db_b": "10.0.3.0/24"}
INGRESS_CIDR = {"app_subnet": "10.0.1.0/24", "half": "10.0.1.0/25", "other": "10.0.9.0/24"}


def build(egress: str, ingress: str, ip: str | None, placement: str) -> str:
    text = edit(canonical(), APP_EGRESS, EGRESS[egress])
    text = edit(text, APP_TO_DB, INGRESS[ingress])
    if placement == "db_b":
        text = edit(text, SUBNET_LINE, "  subnet_id                   = aws_subnet.db_b.id\n")
    elif placement == "far":
        text = edit(text, SUBNET_LINE, "  subnet_id                   = aws_subnet.far.id\n") + FAR
    if ip is not None:
        text = edit(
            text,
            PUBLIC_IP_LINE,
            f'  associate_public_ip_address = true\n  private_ip = "{ip}"\n}}',
        )
    return text


def oracle(
    egress: str, ingress: str, ip: str | None, placement: str
) -> tuple[VerificationResult, int]:
    """Registry §6.4 for this family, by hand. Every rule is determinate and there is no
    unsupported construct, so rows 1 to 4 never apply and row 5 is the instance in another VPC.

    E5 holds for a ``-1`` rule to the internet, a TCP/5432 rule whose CIDR is the whole VPC
    10.0.0.0/16, or one whose destination group is the database group; it fails with a partial
    cover for 10.0.2.0/24 (inside the VPC but not all of it) and with no cover for another port or
    no rule. ADDR(S) is private_ip/32 if set, else the subnet CIDR. E6 holds for the app group as
    source, or a CIDR that contains ADDR(S); it is partial when the CIDR overlaps ADDR(S) without
    containing it, which a single address cannot do. Row 8 if a failing condition is partial,
    else row 9; row 6 if both hold."""
    if placement == "far":
        return F, 5
    e5 = egress in ("all", "vpc", "to_db")
    e5_partial = egress == "dbsubnet"
    address = ipaddress.ip_network(f"{ip}/32" if ip else SUBNET_CIDR[placement])
    if ingress == "group":
        e6, e6_partial = True, False
    elif ingress == "none":
        e6, e6_partial = False, False
    else:
        net = ipaddress.ip_network(INGRESS_CIDR[ingress])
        e6 = address.subnet_of(net)
        e6_partial = (not e6) and net.overlaps(address)
    if e5 and e6:
        return P, 6
    if (not e5 and e5_partial) or (not e6 and e6_partial):
        return U, 8
    return F, 9


def evaluate(text: str, shuffle: int | None = None) -> PredicateOutcome:
    given = inputs(text)
    if shuffle is not None:
        resources = list(given.candidate_resources)
        random.Random(shuffle).shuffle(resources)
        given = dataclasses.replace(given, candidate_resources=tuple(resources))
    return evaluate_reachability(definition(given), given)


Evaluator = Callable[[str, int | None], PredicateOutcome]


class TestAgainstTheOracle(unittest.TestCase):
    def test_every_configuration_of_the_family(self) -> None:
        seen: dict[tuple[VerificationResult, int], int] = {}
        total = 0
        for egress in EGRESS:
            for ingress in INGRESS:
                for ip in PRIVATE_IP:
                    for placement in PLACEMENT:
                        want = oracle(egress, ingress, ip, placement)
                        outcome = evaluate(build(egress, ingress, ip, placement))
                        got = (outcome.result, outcome.observations["row"])
                        with self.subTest(egress=egress, ingress=ingress, ip=ip, at=placement):
                            self.assertEqual(got, want)
                        seen[want] = seen.get(want, 0) + 1
                        total += 1
        self.assertEqual(total, 6 * 5 * 3 * 3)
        # the family reaches every row it can: the check is not vacuous in any direction
        self.assertEqual({row for _, row in seen}, {5, 6, 8, 9})
        self.assertTrue(all(count >= 5 for count in seen.values()), seen)


# --- part two: properties -------------------------------------------------------------------------


def random_text(rng: random.Random) -> str:
    return build(
        rng.choice(list(EGRESS)),
        rng.choice(list(INGRESS)),
        rng.choice(PRIVATE_IP),
        rng.choice(("app", "app", "db_b")),
    )


def key(outcome: PredicateOutcome) -> tuple[VerificationResult, object, object, object]:
    obs = outcome.observations
    return (outcome.result, obs["row"], outcome.reason, tuple(obs["failing_conditions"]))


def order_violations(evaluator: Evaluator, seed: int, cases: int = 12) -> list[str]:
    rng = random.Random(seed)
    bad = []
    for _ in range(cases):
        text = random_text(rng)
        base = key(evaluator(text, None))
        for shuffle in (1, 2, 3):
            if key(evaluator(text, shuffle)) != base:
                bad.append(text)
                break
    return bad


NOISE = (
    '\nresource "aws_internet_gateway" "spare" {\n  vpc_id = aws_vpc.main.id\n}\n',
    '\nresource "aws_subnet" "spare" {\n  vpc_id = aws_vpc.main.id\n  cidr_block = "10.0.7.0/24"\n'
    '  availability_zone = "us-east-1c"\n}\n',
    '\nresource "aws_security_group" "spare" {\n  vpc_id = aws_vpc.main.id\n}\n'
    + rule("spare_rule", "ingress", "tcp", 22, 22, "spare", '  cidr_blocks = ["10.0.0.0/8"]\n'),
    '\nresource "aws_vpc" "spare" {\n  cidr_block = "10.9.0.0/16"\n}\n'
    '\nresource "aws_route_table" "spare" {\n  vpc_id = aws_vpc.spare.id\n'
    '  propagating_vgws = ["vgw-1"]\n  route {\n    cidr_block = "10.9.1.0/24"\n'
    '    nat_gateway_id = "nat-1"\n  }\n}\n',
    '\nresource "aws_route_table_association" "spare" {\n  subnet_id = aws_subnet.db_a.id\n'
    "  route_table_id = aws_route_table.public.id\n}\n",
)


def noise_violations(evaluator: Evaluator, seed: int, cases: int = 10) -> list[str]:
    rng = random.Random(seed)
    bad = []
    for _ in range(cases):
        text = random_text(rng)
        added = text + "".join(rng.sample(NOISE, rng.randint(1, 3)))
        if key(evaluator(text, None)) != key(evaluator(added, None)):
            bad.append(text)
    return bad


ALLOW_EGRESS = (
    egress_5432("extra", '  cidr_blocks = ["10.0.0.0/16"]\n'),
    egress_5432("extra", "  source_security_group_id = aws_security_group.db.id\n"),
    rule("extra", "egress", "-1", 0, 0, "app", '  cidr_blocks = ["0.0.0.0/0"]\n'),
    rule("extra", "egress", "tcp", 80, 80, "app", '  cidr_blocks = ["10.0.0.0/16"]\n'),
)
ALLOW_INGRESS = (
    ingress_5432("extra", "  source_security_group_id = aws_security_group.app.id\n"),
    ingress_5432("extra", '  cidr_blocks = ["10.0.1.0/24"]\n'),
    rule("extra", "ingress", "tcp", 22, 22, "db", '  cidr_blocks = ["10.0.0.0/8"]\n'),
)
INDETERMINATE = (
    ingress_5432("extra", "  source_security_group_id = var.u\n"),
    egress_5432("extra", "  source_security_group_id = var.u\n"),
)


def monotone_violations(evaluator: Evaluator, seed: int, cases: int = 16) -> list[str]:
    """Adding a determinate allow rule on S's egress or D's ingress never turns PASS into
    non-PASS and never turns UNKNOWN into FAIL; adding an indeterminate rule keeps PASS."""
    rng = random.Random(seed)
    bad = []
    for _ in range(cases):
        text = random_text(rng)
        before = evaluator(text, None).result
        for extra in (rng.choice(ALLOW_EGRESS), rng.choice(ALLOW_INGRESS)):
            after = evaluator(VAR + text + extra, None).result
            if before is P and after is not P:
                bad.append(text)
            if before is U and after is F:
                bad.append(text)
        if before is P and evaluator(VAR + text + rng.choice(INDETERMINATE), None).result is not P:
            bad.append(text)
    return bad


TABLE_HEAD = 'resource "aws_route_table" "public" {\n  vpc_id = aws_vpc.main.id\n'
PUBLIC_IP = "  associate_public_ip_address = true\n"
NACL = '\nresource "aws_network_acl" "n" {\n  vpc_id = aws_vpc.main.id\n}\n'
INTRA_ROUTE = '  route {\n    cidr_block = "10.0.2.0/24"\n    nat_gateway_id = "nat-1"\n  }\n'
INTERFACE = (
    "  network_interface {\n    device_index = 0\n" '    network_interface_id = "eni-1"\n  }\n'
)

Transform = Callable[[str], str]


def unsupported_triggers(kind: str) -> dict[str, Transform]:
    """Edits that put a configuration outside the model, whatever else it says (row 2)."""
    return {
        "an intra-VPC non-local route": lambda t: edit(t, IGW_ROUTE, IGW_ROUTE + INTRA_ROUTE),
        "propagating_vgws": lambda t: edit(t, TABLE_HEAD, TABLE_HEAD + "  propagating_vgws = []\n"),
        f"a {kind}": lambda t: t + f'\nresource "{kind}" "x" {{\n}}\n',
        "an interface block": lambda t: edit(t, PUBLIC_IP, PUBLIC_IP + INTERFACE),
    }


def unsupported_violations(evaluator: Evaluator, seed: int, cases: int = 12) -> list[str]:
    rng = random.Random(seed)
    bad = []
    for _ in range(cases):
        text = random_text(rng)
        kind = rng.choice(sorted(FUNC_RELEVANT_UNSUPPORTED))
        for label, transform in unsupported_triggers(kind).items():
            outcome = evaluator(transform(text), None)
            if outcome.result is not S or outcome.observations["row"] != 2:
                bad.append(f"{label}: {text[:40]!r}")
    return bad


# Edits of the canonical text after which no PASS may be reported: an unresolved or partial or
# unsupported fact on the path (each one removes the determinate support for a PASS or sits ahead
# of it in the table).
POISONS: dict[str, Transform] = {
    "D groups unknown": lambda t: edit(t, DB_SGS_LINE, "  vpc_security_group_ids      = var.u\n"),
    "S subnet unknown": lambda t: edit(t, SUBNET_LINE, "  subnet_id                   = var.u\n"),
    "port unknown": lambda t: edit(
        t,
        "  publicly_accessible         = false\n",
        "  publicly_accessible         = false\n  port = var.u\n",
    ),
    "engine unknown": lambda t: edit(
        t, '  engine                      = "postgres"\n', "  engine                      = var.u\n"
    ),
    "source group unknown": lambda t: edit(t, SOURCE_LINE, "  source_security_group_id = var.u\n"),
    "ingress prefix list": lambda t: edit(t, SOURCE_LINE, '  prefix_list_ids = ["pl-1"]\n'),
    "destination partly covered": lambda t: edit(
        t, APP_EGRESS, egress_5432("e", '  cidr_blocks = ["10.0.2.0/24"]\n')
    ),
    "a network acl": lambda t: t + NACL,
    "name-based groups": lambda t: edit(
        t, PUBLIC_IP, PUBLIC_IP + '  security_groups = ["default"]\n'
    ),
    "no subnet": lambda t: edit(t, SUBNET_LINE, ""),
    "an interface block": lambda t: edit(t, PUBLIC_IP, PUBLIC_IP + INTERFACE),
    "an intra-VPC route": lambda t: edit(t, IGW_ROUTE, IGW_ROUTE + INTRA_ROUTE),
}


def never_pass_violations(evaluator: Evaluator, seed: int, cases: int = 4) -> list[str]:
    rng = random.Random(seed)
    bad = []
    for label, transform in POISONS.items():
        for _ in range(cases):
            noise = "".join(rng.sample(NOISE, rng.randint(0, 2)))
            outcome = evaluator(VAR + transform(canonical()) + noise, None)
            if outcome.result is P:
                bad.append(label)
    return bad


class TestProperties(unittest.TestCase):
    def test_the_order_of_the_resources_never_changes_the_outcome(self) -> None:
        for seed in SEEDS:
            self.assertEqual(order_violations(evaluate, seed), [], f"seed {seed}")

    def test_the_order_of_a_cidr_list_never_changes_the_outcome(self) -> None:
        # within one rule a CIDR list is a union (registry 2.5): two halves cover the VPC CIDR
        # (E5 holds, row 6) whichever comes first; a list that leaves a half out is partial (row 8)
        cases = (
            (["10.0.0.0/17", "10.0.128.0/17"], P, 6),
            (["10.0.128.0/17", "10.0.0.0/17"], P, 6),
            (["10.0.0.0/17", "10.0.0.0/18"], U, 8),
            (["10.0.0.0/18", "10.0.0.0/17"], U, 8),
        )
        for order, result, row in cases:
            body = f"  cidr_blocks = {order!r}\n".replace("'", '"')
            text = edit(canonical(), APP_EGRESS, egress_5432("halves", body))
            outcome = evaluate(text)
            with self.subTest(order=order):
                self.assertEqual((outcome.result, outcome.observations["row"]), (result, row))

    def test_irrelevant_resources_change_nothing(self) -> None:
        for seed in SEEDS:
            self.assertEqual(noise_violations(evaluate, seed), [], f"seed {seed}")

    def test_adding_permission_is_monotone(self) -> None:
        for seed in SEEDS:
            self.assertEqual(monotone_violations(evaluate, seed), [], f"seed {seed}")

    def test_anything_outside_the_model_is_unsupported(self) -> None:
        for seed in SEEDS:
            self.assertEqual(unsupported_violations(evaluate, seed), [], f"seed {seed}")

    def test_indeterminate_partial_or_unsupported_input_is_never_a_pass(self) -> None:
        for seed in SEEDS:
            self.assertEqual(never_pass_violations(evaluate, seed), [], f"seed {seed}")

    def test_every_poison_is_a_real_change(self) -> None:
        for label, transform in POISONS.items():
            with self.subTest(poison=label):
                self.assertNotEqual(transform(canonical()), canonical())


# --- part three: the checkers can fail ----------------------------------------------------------


def replaced(outcome: PredicateOutcome, **fields: object) -> PredicateOutcome:
    return dataclasses.replace(outcome, **fields)  # type: ignore[arg-type]


class TestTheCheckersCanFail(unittest.TestCase):
    """A property checker that cannot fail proves nothing: break the verifier and watch it fail."""

    def test_the_oracle_check_catches_a_changed_row(self) -> None:
        def row_eight_as_fail(text: str, shuffle: int | None) -> PredicateOutcome:
            outcome = evaluate(text, shuffle)
            return replaced(outcome, result=F) if outcome.observations["row"] == 8 else outcome

        caught = 0
        for egress in EGRESS:
            for ingress in INGRESS:
                outcome = row_eight_as_fail(build(egress, ingress, None, "app"), None)
                got = (outcome.result, outcome.observations["row"])
                caught += got != oracle(egress, ingress, None, "app")
        self.assertGreater(caught, 0)

    def test_the_order_check_catches_an_order_dependent_verifier(self) -> None:
        def drops_the_last_resource(text: str, shuffle: int | None) -> PredicateOutcome:
            given = inputs(text)
            resources = list(given.candidate_resources)
            if shuffle is not None:
                random.Random(shuffle).shuffle(resources)
                resources = resources[:-1]
            given = dataclasses.replace(given, candidate_resources=tuple(resources))
            return evaluate_reachability(definition(given), given)

        self.assertGreater(sum(len(order_violations(drops_the_last_resource, s)) for s in SEEDS), 0)

    def test_the_noise_check_catches_a_verifier_that_reads_irrelevant_resources(self) -> None:
        def nervous(text: str, shuffle: int | None) -> PredicateOutcome:
            outcome = evaluate(text, shuffle)
            return replaced(outcome, result=S) if "spare" in text else outcome

        self.assertGreater(sum(len(noise_violations(nervous, s)) for s in SEEDS), 0)

    def test_the_monotone_check_catches_a_non_monotone_verifier(self) -> None:
        def forgetful(text: str, shuffle: int | None) -> PredicateOutcome:
            outcome = evaluate(text, shuffle)
            crowded = text.count('resource "aws_security_group_rule"') > 2
            return replaced(outcome, result=F) if crowded and outcome.result is P else outcome

        self.assertGreater(sum(len(monotone_violations(forgetful, s)) for s in SEEDS), 0)

    def test_the_unsupported_check_catches_a_verifier_that_ignores_a_trigger(self) -> None:
        def ignores_types(text: str, shuffle: int | None) -> PredicateOutcome:
            outcome = evaluate(text, shuffle)
            if outcome.reason is not None and outcome.reason.value == "type.relevant_unsupported":
                return replaced(outcome, result=P)
            return outcome

        self.assertGreater(sum(len(unsupported_violations(ignores_types, s)) for s in SEEDS), 0)

    def test_the_never_pass_check_catches_unknown_read_as_pass(self) -> None:
        def optimistic(text: str, shuffle: int | None) -> PredicateOutcome:
            outcome = evaluate(text, shuffle)
            return replaced(outcome, result=P) if outcome.result is U else outcome

        self.assertGreater(sum(len(never_pass_violations(optimistic, s)) for s in SEEDS), 0)


if __name__ == "__main__":
    unittest.main()
