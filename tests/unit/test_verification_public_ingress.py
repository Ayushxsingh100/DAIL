"""INV-SEC-001 and INV-SEC-002: ``PIP(p)`` (P5a step 4; registry §2.6, §3, §4, §8; C-146).

Every expected value below is derived by hand from the registry text, in this order of reasoning:
§2.6 builds ``In(g)`` and decides MIXED and RETAINED-INLINE; §3.3 defines ``D(g)``, ``violates``
and ``possible`` per address family; §3.4 gives the clause order FAIL, UNSUPPORTED, UNKNOWN,
PASS and the invariant rule (FAIL if either clause FAILs, otherwise the worse clause). The
registry's own table (§8, vectors S1-S20) is then compared; none is computed with the code under
test.

Vector, derivation, registry's answer:

    S1   inline tcp 22 from 0.0.0.0/0 -> violates4 -> IPv4 FAIL, IPv6 PASS -> FAIL      (FAIL)
    S2   rule "-1" from 0.0.0.0/0     -> ALL permits 22 -> same                         (FAIL)
    S3   tcp 0-65535 from ::/0        -> violates6 -> IPv4 PASS, IPv6 FAIL -> FAIL      (FAIL)
    S4   0.0.0.0/1 + 128.0.0.0/1      -> union covers 0.0.0.0/0 -> FAIL                 (FAIL)
    S5   two rules, one group         -> D(g) holds both (20-30 permits 22) -> FAIL     (FAIL)
    S6   two groups, one half each    -> neither covers alone -> PASS                   (PASS)
    S7   10.0.0.0/16                  -> not public -> PASS                             (PASS)
    S8   udp 22 from 0.0.0.0/0        -> not TCP -> PASS                                (PASS)
    S9   cidr from an unset variable  -> possible4 -> IPv4 UNKNOWN, IPv6 PASS           (UNKNOWN)
    S10  prefix list only             -> possible4 and possible6 -> UNKNOWN             (UNKNOWN)
    S11  inline block + a rule        -> MIXED -> UNSUPPORTED                       (UNSUPPORTED)
    S12  unused group, tcp 22 public  -> every group counts -> FAIL                     (FAIL)
    S13  ingress_rule resource        -> relevant-unsupported -> UNSUPPORTED        (UNSUPPORTED)
    S14  tcp 5432 public (p = 5432)   -> FAIL                                           (FAIL)
    S15  rules_exclusive resource     -> relevant-unsupported -> UNSUPPORTED        (UNSUPPORTED)
    S16  parent blocks, candidate absent -> RETAINED-INLINE -> UNSUPPORTED          (UNSUPPORTED)
    S17  as S16 but ``ingress = []``  -> no inline rules -> PASS                        (PASS)
    S18  baseline, no ingress argument -> deployed fresh -> PASS                        (PASS)
    S19  ``ingress = []`` + ingress rule -> MIXED -> UNSUPPORTED                    (UNSUPPORTED)
    S20  S16 plus a public group      -> FAIL first (the retained group is skipped)     (FAIL)
"""

from __future__ import annotations

import json
import random
import unittest

from core.domain.enums import VerificationResult
from core.domain.verification import VerificationReason
from core.verification.public_ingress import (
    RELEVANT_UNSUPPORTED,
    PredicateOutcome,
    evaluate_public_ingress,
)
from core.verification.views import ViewError
from tests.security_builders import (
    APP,
    VARS,
    inline,
    pair,
    resources_of,
    rule,
    sg,
    with_security,
)

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
R = VerificationReason
ANY4, ANY6 = ["0.0.0.0/0"], ["::/0"]


def run(text: str, port: int = 22, parent: str | None = None) -> PredicateOutcome:
    """The predicate for a candidate text, with the identity of its parent text if it has one."""
    if parent is None:
        return evaluate_public_ingress(port, resources_of(text))
    both = pair(parent, text)
    return evaluate_public_ingress(
        port, both.candidate, parent_resources=both.parent, identity=both.identity
    )


class Expect(unittest.TestCase):
    def check(
        self,
        outcome: PredicateOutcome,
        result: VerificationResult,
        ipv4: VerificationResult,
        ipv6: VerificationResult,
        reason: VerificationReason | None,
    ) -> None:
        self.assertEqual(
            (outcome.result, dict(outcome.clauses or {}), outcome.reason),
            (result, {"IPV4": ipv4, "IPV6": ipv6}, reason),
        )


class TestRegistryVectors(Expect):
    def test_s1_inline_ssh_open_to_the_internet(self) -> None:
        text = sg(body=inline("ingress", "tcp", 22, 22, ANY4))
        self.check(run(text), F, F, P, R.PREDICATE_VIOLATED)

    def test_s2_rule_with_protocol_minus_one(self) -> None:
        text = sg() + rule("r", "ingress", "-1", 0, 0, ANY4)
        self.check(run(text), F, F, P, R.PREDICATE_VIOLATED)

    def test_s3_ipv6_only(self) -> None:
        text = sg() + rule("r", "ingress", "tcp", 0, 65535, None, ANY6)
        self.check(run(text), F, P, F, R.PREDICATE_VIOLATED)

    def test_s4_one_rule_two_halves(self) -> None:
        text = sg() + rule("r", "ingress", "tcp", 22, 22, ["0.0.0.0/1", "128.0.0.0/1"])
        self.check(run(text), F, F, P, R.PREDICATE_VIOLATED)

    def test_s5_two_rules_in_one_group(self) -> None:
        text = (
            sg()
            + rule("a", "ingress", "tcp", 22, 22, ["0.0.0.0/1"])
            + rule("b", "ingress", "tcp", 20, 30, ["128.0.0.0/1"])
        )
        outcome = run(text)
        self.check(outcome, F, F, P, R.PREDICATE_VIOLATED)
        (violation,) = outcome.observations["violations"]
        self.assertEqual(violation["group"], APP)
        self.assertEqual(
            violation["rules"], ["aws_security_group_rule.a", "aws_security_group_rule.b"]
        )

    def test_s6_coverage_split_across_groups_is_not_detected(self) -> None:
        text = (
            sg("a")
            + sg("b")
            + rule("ra", "ingress", "tcp", 22, 22, ["0.0.0.0/1"], target="aws_security_group.a.id")
            + rule(
                "rb", "ingress", "tcp", 22, 22, ["128.0.0.0/1"], target="aws_security_group.b.id"
            )
        )
        self.check(run(text), P, P, P, None)

    def test_s7_private_range(self) -> None:
        text = sg(body=inline("ingress", "tcp", 22, 22, ["10.0.0.0/16"]))
        self.check(run(text), P, P, P, None)

    def test_s8_udp(self) -> None:
        text = sg(body=inline("ingress", "udp", 22, 22, ANY4))
        self.check(run(text), P, P, P, None)

    def test_s9_cidr_from_a_variable_without_a_value(self) -> None:
        text = VARS + sg() + rule("r", "ingress", "tcp", 22, 22, "[var.ssh_cidr]")
        self.check(run(text), U, U, P, R.RULE_INDETERMINATE)

    def test_s10_prefix_list_only(self) -> None:
        extra = '  prefix_list_ids = ["pl-0123"]\n'
        text = sg() + rule("r", "ingress", "tcp", 22, 22, None, None, extra=extra)
        self.check(run(text), U, U, U, R.RULE_INDETERMINATE)

    def test_s11_inline_block_and_a_rule_resource_is_mixed(self) -> None:
        text = sg(body=inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"])) + rule(
            "r", "ingress", "tcp", 443, 443, ["10.0.0.0/8"]
        )
        outcome = run(text)
        self.check(outcome, S, S, S, R.GROUP_MIXED)
        self.assertEqual(outcome.observations["mixed_groups"], [APP])

    def test_s12_a_group_used_by_nothing_still_counts(self) -> None:
        text = sg("unused", inline("ingress", "tcp", 22, 22, ANY4))
        self.check(run(text), F, F, P, R.PREDICATE_VIOLATED)

    def test_s13_ingress_rule_resource_type_is_relevant_unsupported(self) -> None:
        text = sg() + (
            'resource "aws_vpc_security_group_ingress_rule" "x" {\n'
            '  security_group_id = aws_security_group.app.id\n  ip_protocol = "tcp"\n'
            '  from_port = 22\n  to_port = 22\n  cidr_ipv4 = "10.0.0.0/8"\n}\n'
        )
        outcome = run(text)
        self.check(outcome, S, S, S, R.TYPE_RELEVANT_UNSUPPORTED)
        self.assertEqual(
            outcome.observations["relevant_unsupported"],
            ["aws_vpc_security_group_ingress_rule.x"],
        )

    def test_s14_postgres_open_to_the_internet(self) -> None:
        text = sg(body=inline("ingress", "tcp", 5432, 5432, ANY4))
        self.check(run(text, 5432), F, F, P, R.PREDICATE_VIOLATED)
        self.check(run(text, 22), P, P, P, None)  # the same group is no SSH problem

    def test_s15_rules_exclusive_type_is_relevant_unsupported(self) -> None:
        text = sg() + (
            'resource "aws_vpc_security_group_rules_exclusive" "x" {\n'
            "  security_group_id = aws_security_group.app.id\n  ingress_rule_ids = []\n}\n"
        )
        self.check(run(text), S, S, S, R.TYPE_RELEVANT_UNSUPPORTED)

    def test_s16_ingress_argument_removed_keeps_the_parents_rules(self) -> None:
        parent = sg(body=inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"]))
        outcome = run(sg(), parent=parent)
        self.check(outcome, S, S, S, R.GROUP_RETAINED_INLINE)
        self.assertEqual(
            outcome.observations["retained_inline"], [{"group": APP, "direction": "ingress"}]
        )

    def test_s17_explicit_empty_list_removes_them(self) -> None:
        parent = sg(body=inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"]))
        self.check(run(sg(body="  ingress = []\n"), parent=parent), P, P, P, None)

    def test_s18_baseline_group_without_an_ingress_argument(self) -> None:
        self.check(run(sg()), P, P, P, None)

    def test_s19_explicit_empty_and_an_ingress_rule_is_mixed(self) -> None:
        text = sg(body="  ingress = []\n") + rule("r", "ingress", "tcp", 22, 22, ["10.0.0.0/8"])
        self.check(run(text), S, S, S, R.GROUP_MIXED)

    def test_s20_a_violation_elsewhere_still_fails(self) -> None:
        parent = sg(body=inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"])) + sg("other")
        text = sg() + sg("other", inline("ingress", "tcp", 22, 22, ANY4))
        # the IPv6 clause cannot be decided because of the retained group, so it is UNSUPPORTED
        self.check(run(text, parent=parent), F, F, S, R.PREDICATE_VIOLATED)


class TestClauseOrder(Expect):
    def test_unsupported_beats_unknown(self) -> None:
        text = (
            VARS
            + sg(body=inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"]))
            + rule("mixing", "ingress", "tcp", 443, 443, ["10.0.0.0/8"])
            + sg("b")
            + rule(
                "unsure",
                "ingress",
                "tcp",
                22,
                22,
                "[var.ssh_cidr]",
                target="aws_security_group.b.id",
            )
        )
        self.check(run(text), S, S, S, R.GROUP_MIXED)

    def test_unknown_beats_pass(self) -> None:
        text = VARS + sg() + rule("r", "ingress", "tcp", 22, 22, "[var.ssh_cidr]")
        self.assertIs(run(text).result, U)

    def test_a_mixed_group_does_not_hide_a_violation_in_another_group(self) -> None:
        text = (
            sg(body=inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"]))
            + rule("mixing", "ingress", "tcp", 443, 443, ["10.0.0.0/8"])
            + sg("bad", inline("ingress", "tcp", 22, 22, ANY4))
        )
        self.check(run(text), F, F, S, R.PREDICATE_VIOLATED)

    def test_a_mixed_group_is_not_evaluated_by_violates(self) -> None:
        # the registry skips MIXED groups for FAIL: the applied rule set is not determined
        text = sg(body=inline("ingress", "tcp", 22, 22, ANY4)) + rule(
            "r", "ingress", "tcp", 80, 80, ["10.0.0.0/8"]
        )
        self.check(run(text), S, S, S, R.GROUP_MIXED)

    def test_the_two_ports_are_independent(self) -> None:
        text = sg(body=inline("ingress", "tcp", 22, 22, ANY4)) + sg(
            "db", inline("ingress", "tcp", 5432, 5432, ANY4)
        )
        self.assertEqual(run(text, 22).observations["violations"][0]["group"], APP)
        self.assertEqual(
            run(text, 5432).observations["violations"][0]["group"], "aws_security_group.db"
        )


class TestMixed(Expect):
    def test_inline_egress_blocks_and_an_ingress_rule(self) -> None:
        text = sg(body=inline("egress", "-1", 0, 0, ANY4)) + rule(
            "r", "ingress", "tcp", 22, 22, ["10.0.0.0/8"]
        )
        self.check(run(text), S, S, S, R.GROUP_MIXED)

    def test_explicit_empty_egress_and_an_egress_rule(self) -> None:
        text = sg(body="  egress = []\n") + rule("r", "egress", "-1", 0, 0, ANY4)
        self.check(run(text), S, S, S, R.GROUP_MIXED)

    def test_explicit_empty_egress_and_an_ingress_rule_is_not_mixed(self) -> None:
        text = sg(body="  egress = []\n") + rule("r", "ingress", "tcp", 22, 22, ["10.0.0.0/8"])
        self.check(run(text), P, P, P, None)

    def test_explicit_empty_ingress_and_an_egress_rule_is_not_mixed(self) -> None:
        text = sg(body="  ingress = []\n") + rule("r", "egress", "-1", 0, 0, ANY4)
        self.check(run(text), P, P, P, None)

    def test_a_rule_whose_type_is_unresolved_counts_for_every_direction(self) -> None:
        text = (
            VARS + sg(body="  ingress = []\n") + rule("r", "var.u", "tcp", 80, 80, ["10.0.0.0/8"])
        )
        self.check(run(text), S, S, S, R.GROUP_MIXED)

    def test_pseudo_groups_are_never_mixed(self) -> None:
        text = rule("r", "ingress", "tcp", 22, 22, ANY4, target='"sg-0123abcd"')
        outcome = run(text)
        self.check(outcome, F, F, P, R.PREDICATE_VIOLATED)
        self.assertEqual(outcome.observations["violations"][0]["group"], "EXTERNAL:sg-0123abcd")


class TestFormsAndRules(Expect):
    def test_an_ingress_direction_that_cannot_be_fixed_is_unsupported_not_empty(self) -> None:
        # C-120(c), the P5 gate item
        outcome = run(VARS + sg(body="  ingress = var.u\n"))
        self.check(outcome, S, S, S, R.FORMS_UNRESOLVED)
        self.assertEqual(outcome.observations["unresolved_forms"], [APP])

    def test_an_unresolved_egress_direction_matters_only_with_a_rule_resource(self) -> None:
        alone = run(VARS + sg(body="  egress = var.u\n"))
        self.check(alone, P, P, P, None)
        targeted = run(
            VARS
            + sg(body="  egress = var.u\n")
            + rule("r", "ingress", "tcp", 22, 22, ["10.0.0.0/8"])
        )
        self.check(targeted, S, S, S, R.GROUP_MIXED)

    def test_an_unexpandable_dynamic_block_is_an_indeterminate_rule(self) -> None:
        text = VARS + sg(
            body='  dynamic "ingress" {\n    for_each = var.u\n    content {\n'
            '      protocol = "tcp"\n      from_port = 22\n      to_port = 22\n'
            '      cidr_blocks = ["10.0.0.0/8"]\n    }\n  }\n'
        )
        self.check(run(text), U, U, U, R.RULE_INDETERMINATE)

    def test_an_expandable_dynamic_block_gives_rules(self) -> None:
        text = 'variable "ports" {\n  default = [22]\n}\n' + sg(
            body='  dynamic "ingress" {\n    for_each = var.ports\n    content {\n'
            '      protocol = "tcp"\n      from_port = ingress.value\n'
            '      to_port = ingress.value\n      cidr_blocks = ["0.0.0.0/0"]\n    }\n  }\n'
        )
        self.check(run(text), F, F, P, R.PREDICATE_VIOLATED)

    def test_an_unsupported_ingress_rule_is_unsupported_whatever_its_port(self) -> None:
        # registry 3.4: "some ingress rule is UNSUPPORTED"; an invalid CIDR on a UDP rule counts
        text = sg(body=inline("ingress", "udp", 80, 80, ["10.0.0.1/8"]))
        self.check(run(text), S, S, S, R.RULE_UNSUPPORTED)

    def test_egress_rules_are_not_read(self) -> None:
        text = sg(body=inline("egress", "tcp", 22, 22, ANY4))
        self.check(run(text), P, P, P, None)

    def test_a_rule_with_an_unresolved_type_is_a_possible_ingress_rule(self) -> None:
        # prompt C-146: never silently skipped. IPv4 is possible (a public range, type unknown),
        # IPv6 has no sources at all.
        text = VARS + sg() + rule("r", "var.u", "tcp", 22, 22, ANY4)
        outcome = run(text)
        self.check(outcome, U, U, P, R.RULE_INDETERMINATE)
        self.assertEqual(
            outcome.observations["unresolved_type_rules"], ["aws_security_group_rule.r"]
        )

    def test_a_rule_with_an_invalid_type_is_unsupported(self) -> None:
        text = sg() + rule("r", "sideways", "tcp", 22, 22, ANY4)
        self.check(run(text), S, S, S, R.RULE_UNSUPPORTED)

    def test_rules_from_security_group_sources_are_not_public(self) -> None:
        extra = "  source_security_group_id = aws_security_group.other.id\n"
        text = sg() + sg("other") + rule("r", "ingress", "tcp", 22, 22, None, None, extra=extra)
        self.check(run(text), P, P, P, None)

    def test_an_unresolved_source_group_flags_neither_family(self) -> None:
        # func_unknown_dependency_unknown_v1: indeterminate, but IPv4 and IPv6 sources are resolved
        extra = "  source_security_group_id = var.u\n"
        text = VARS + sg() + rule("r", "ingress", "tcp", 5432, 5432, None, None, extra=extra)
        outcome = run(text, 5432)
        self.check(outcome, P, P, P, None)
        self.assertEqual(
            [item["rule"] for item in outcome.observations["indeterminate_rules"]],
            ["aws_security_group_rule.r"],
        )

    def test_a_rule_that_cannot_reach_the_port_is_not_a_possibility(self) -> None:
        text = VARS + sg() + rule("r", "ingress", "tcp", 80, 80, "[var.ssh_cidr]")
        self.check(run(text), P, P, P, None)

    def test_an_inline_rule_with_an_unresolved_source_is_a_possibility(self) -> None:
        text = VARS + sg(body=inline("ingress", "tcp", 22, 22, "[var.ssh_cidr]"))
        self.check(run(text), U, U, P, R.RULE_INDETERMINATE)

    def test_an_unresolved_ipv6_list_is_unknown_for_ipv6_only(self) -> None:
        text = (
            VARS
            + sg()
            + (
                'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n'
                '  security_group_id = aws_security_group.app.id\n  protocol = "tcp"\n'
                "  from_port = 22\n  to_port = 22\n  ipv6_cidr_blocks = var.u\n}\n"
            )
        )
        self.check(run(text), U, P, U, R.RULE_INDETERMINATE)


class TestRegistryGap(Expect):
    """Registry §3.3 makes ``possible4`` depend on the IPv4 sources being unresolved or including a
    prefix list. A rule whose *port* is unresolved but whose IPv4 source is the whole internet is
    therefore not a possibility, and the registry text gives PASS. That is implemented verbatim
    (prompt, C-146) and recorded as an Open row (C-150) for the authors: the next test pins the
    behaviour so that it cannot change unnoticed."""

    def test_unresolved_port_with_a_public_source_is_pass_by_the_registry_text(self) -> None:
        text = (
            VARS
            + sg()
            + (
                'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n'
                '  security_group_id = aws_security_group.app.id\n  protocol = "tcp"\n'
                '  from_port = var.u\n  to_port = 22\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
            )
        )
        outcome = run(text)
        self.check(outcome, P, P, P, None)
        # not hidden: the rule is reported as indeterminate in the observations
        self.assertEqual(len(outcome.observations["indeterminate_rules"]), 1)


class TestIdentityAndRetention(Expect):
    OLD = sg(body=inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"]))

    def test_a_created_group_is_deployed_fresh(self) -> None:
        # 'app' keeps its blocks; 'new' is CREATED, has no counterpart and no ingress argument
        self.check(run(self.OLD + sg("new"), parent=self.OLD), P, P, P, None)

    def test_retention_follows_a_moved_block(self) -> None:
        text = (
            sg("renamed")
            + "moved {\n  from = aws_security_group.app\n  to   = aws_security_group.renamed\n}\n"
        )
        outcome = run(text, parent=self.OLD)
        self.check(outcome, S, S, S, R.GROUP_RETAINED_INLINE)
        self.assertEqual(
            outcome.observations["retained_inline"][0]["group"], "aws_security_group.renamed"
        )

    def test_a_retained_group_is_not_evaluated_by_violates(self) -> None:
        # registry 3.4: "A RETAINED-INLINE group is not evaluated by violates(g), because its
        # rules are not known". Its own public rule resource therefore does not give FAIL; the
        # group is UNSUPPORTED (nothing else violates), and a public rule elsewhere still would.
        text = sg() + rule("r", "ingress", "tcp", 22, 22, ANY4)
        self.check(run(text, parent=self.OLD), S, S, S, R.GROUP_RETAINED_INLINE)

    def test_a_parent_that_is_a_placeholder_cannot_rule_blocks_out(self) -> None:
        # the counterpart's inline rules are unknown, so the group may retain them (R5: UNSUPPORTED)
        parent = VARS + 'resource "aws_security_group" "app" {\n  count = var.u\n}\n'
        self.check(run(sg(), parent=parent), S, S, S, R.GROUP_RETAINED_INLINE)

    def test_a_parent_that_was_explicit_empty_or_absent_retains_nothing(self) -> None:
        for parent in (sg(body="  ingress = []\n"), sg()):
            with self.subTest(parent=parent):
                self.check(run(sg(), parent=parent), P, P, P, None)

    def test_a_replaced_group_counts_as_having_a_counterpart(self) -> None:
        # conservative: the identity report pairs the two groups (REPLACED), so the registry's
        # "parent counterpart" exists; UNSUPPORTED never passes
        parent = sg(body='  name = "one"\n' + inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"]))
        both = pair(parent, sg(body='  name = "two"\n'))
        (match,) = both.identity.resource_matches
        self.assertIn(match.change_type.value, ("MODIFIED", "REPLACED"))  # a pair, not CREATED
        outcome = evaluate_public_ingress(
            22, both.candidate, parent_resources=both.parent, identity=both.identity
        )
        self.check(outcome, S, S, S, R.GROUP_RETAINED_INLINE)

    def test_a_parent_without_an_identity_report_is_unsupported_not_fresh(self) -> None:
        both = pair(self.OLD, sg())
        outcome = evaluate_public_ingress(22, both.candidate, parent_resources=both.parent)
        self.check(outcome, S, S, S, R.IDENTITY_MISSING)

    def test_identity_missing_does_not_touch_groups_that_wrote_the_argument(self) -> None:
        both = pair(self.OLD, sg(body="  ingress = []\n"))
        outcome = evaluate_public_ingress(22, both.candidate, parent_resources=both.parent)
        self.check(outcome, P, P, P, None)

    def test_a_report_that_does_not_cover_the_group_is_identity_missing(self) -> None:
        other = pair(self.OLD, sg("other"))
        both = pair(self.OLD, sg())
        outcome = evaluate_public_ingress(
            22, both.candidate, parent_resources=both.parent, identity=other.identity
        )
        self.check(outcome, S, S, S, R.IDENTITY_MISSING)

    def test_an_uncertain_counterpart_that_used_blocks_retains(self) -> None:
        parent = (
            'resource "aws_security_group" "g" {\n  for_each = toset(["a", "b"])\n'
            + inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"])
            + "}\n"
        )
        candidate = 'resource "aws_security_group" "g" {\n  for_each = toset(["c", "d"])\n}\n'
        both = pair(parent, candidate)
        kinds = {m.change_type.value for m in both.identity.resource_matches}
        self.assertIn("UNCERTAIN", kinds, "the scenario must produce an UNCERTAIN match")
        outcome = evaluate_public_ingress(
            22, both.candidate, parent_resources=both.parent, identity=both.identity
        )
        self.check(outcome, S, S, S, R.GROUP_RETAINED_INLINE)

    def test_an_uncertain_counterpart_that_used_no_blocks_retains_nothing(self) -> None:
        parent = 'resource "aws_security_group" "g" {\n  for_each = toset(["a", "b"])\n}\n'
        candidate = 'resource "aws_security_group" "g" {\n  for_each = toset(["c", "d"])\n}\n'
        both = pair(parent, candidate)
        outcome = evaluate_public_ingress(
            22, both.candidate, parent_resources=both.parent, identity=both.identity
        )
        self.check(outcome, P, P, P, None)


class TestPlaceholders(Expect):
    def test_a_group_with_an_unknown_count_is_unknown_not_empty(self) -> None:
        text = VARS + 'resource "aws_security_group" "p" {\n  count = var.u\n}\n' + sg()
        outcome = run(text)
        self.check(outcome, U, U, U, R.RULE_INDETERMINATE)
        self.assertEqual(outcome.observations["placeholders"], ["aws_security_group.p"])

    def test_a_rule_with_an_unknown_count_is_unknown(self) -> None:
        text = (
            VARS
            + sg()
            + 'resource "aws_security_group_rule" "pr" {\n  count = var.u\n  type = "ingress"\n'
            '  security_group_id = aws_security_group.app.id\n  protocol = "tcp"\n'
            "  from_port = 80\n  to_port = 80\n}\n"
        )
        self.check(run(text), U, U, U, R.RULE_INDETERMINATE)

    def test_a_relevant_unsupported_type_with_an_unknown_count_is_unsupported(self) -> None:
        # registry silent (R5): UNSUPPORTED, reported as a spec gap
        text = (
            VARS
            + sg()
            + (
                'resource "aws_default_security_group" "d" {\n  count = var.u\n'
                '  vpc_id = "vpc-1"\n}\n'
            )
        )
        self.check(run(text), S, S, S, R.TYPE_RELEVANT_UNSUPPORTED)

    def test_a_malformed_stored_view_is_an_error_not_a_result(self) -> None:
        base = next(r for r in resources_of(sg()) if r.resource_type == "aws_security_group")
        broken = with_security(base, {})  # supported, but the view is not the shape P3a writes
        with self.assertRaises(ViewError):
            evaluate_public_ingress(22, [broken])  # the engine turns this into VERIFIER_ERROR


class TestEvidenceFields(unittest.TestCase):
    def test_the_assumptions_are_a_sorted_closed_list(self) -> None:
        outcome = run(sg())
        self.assertEqual(
            outcome.assumptions,
            (
                "egress contents are not read",
                "scope: every group, attached or not (C-64)",
                "v1: coverage split across groups is not detected (S6)",
            ),
        )

    def test_the_tolerated_type_is_recorded_when_present(self) -> None:
        text = sg() + 'resource "aws_db_subnet_group" "g" {\n  subnet_ids = []\n}\n'
        self.assertIn("tolerated type: aws_db_subnet_group (C-15)", run(text).assumptions)
        self.assertNotIn("tolerated type: aws_db_subnet_group (C-15)", run(sg()).assumptions)

    def test_observations_for_a_clean_configuration(self) -> None:
        outcome = run(sg() + sg("b"))
        self.assertEqual(
            dict(outcome.observations),
            {
                "port": 22,
                "groups_evaluated": 2,
                "violations": [],
                "mixed_groups": [],
                "retained_inline": [],
                "unresolved_forms": [],
                "identity_missing": [],
                "indeterminate_rules": [],
                "unsupported_rules": [],
                "unresolved_type_rules": [],
                "relevant_unsupported": [],
                "placeholders": [],
            },
        )

    def test_the_relevant_unsupported_types_are_the_registry_list(self) -> None:
        self.assertEqual(
            RELEVANT_UNSUPPORTED,
            frozenset(
                {
                    "aws_vpc_security_group_ingress_rule",
                    "aws_default_security_group",
                    "aws_vpc_security_group_rules_exclusive",
                }
            ),
        )

    def test_the_outcome_does_not_depend_on_resource_order(self) -> None:
        text = (
            VARS
            + sg(body=inline("ingress", "tcp", 22, 22, ANY4))
            + sg("b")
            + rule(
                "r", "ingress", "tcp", 22, 22, "[var.ssh_cidr]", target="aws_security_group.b.id"
            )
        )
        resources = list(resources_of(text))
        baseline = evaluate_public_ingress(22, resources)
        rng = random.Random(20261028)
        for _ in range(10):
            rng.shuffle(resources)
            again = evaluate_public_ingress(22, resources)
            self.assertEqual(again, baseline)

    def test_the_observations_are_plain_json(self) -> None:
        outcome = run(sg(body=inline("ingress", "tcp", 22, 22, ANY4)))
        json.dumps(dict(outcome.observations))  # raises on anything that is not plain JSON


if __name__ == "__main__":
    unittest.main()
