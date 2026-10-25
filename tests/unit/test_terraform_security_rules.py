"""Canonical security rules (P3a-3 step 4; Doc 04 §8, §16.1, §18, §24; registry §2.5, §2.6; C-116).

Expected values are written by hand from the spec text: the Doc 04 §16.1 example, the registry
§2.5 protocol table and the §2.6 rules for indeterminate rules and pseudo-groups.
"""

from __future__ import annotations

import ast
import unittest
from collections.abc import Mapping
from pathlib import Path

from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.terraform_model import security_rules
from core.terraform_model.normalize import normalize_instance
from core.terraform_model.security_rules import (
    EGRESS,
    INGRESS,
    ORIGIN_INLINE,
    ORIGIN_RULE_RESOURCE,
    PROBLEM_CODES,
    CanonicalSecurityRule,
    canonical_protocol,
    index_rules,
    inline_rules,
    resource_rule,
    rules_of,
)
from tests.tf_builders import NOW, evaluate_ok

ROOT = Path(__file__).resolve().parents[2]
SG = 'resource "aws_security_group" "app" {}\n'
EMPTY_FIELDS = {
    "ipv6_sources": [],
    "source_security_groups": [],
    "prefix_list_ids": [],
    "self": False,
    "determinate": True,
    "unsupported": False,
    "problems": [],
}


def rule_of(body: str, variables: Mapping[str, object] | None = None) -> CanonicalSecurityRule:
    """The rule of an ``aws_security_group_rule`` with the given arguments."""
    text = (
        'variable "v" {}\n'
        + SG
        + 'resource "aws_security_group_rule" "r" {\n'
        + "  security_group_id = aws_security_group.app.id\n"
        + body
        + "\n}\n"
    )
    _, outcome = evaluate_ok(text, variables)
    return resource_rule(outcome.instances["aws_security_group_rule.r"])


def tcp(extra: str = "", port: int = 22) -> CanonicalSecurityRule:
    return rule_of(
        f'  type = "ingress"\n  protocol = "tcp"\n  from_port = {port}\n  to_port = {port}\n{extra}'
    )


def inline_of(block: str, variables: Mapping[str, object] | None = None) -> CanonicalSecurityRule:
    text = f'variable "v" {{}}\nresource "aws_security_group" "app" {{\n{block}\n}}\n'
    _, outcome = evaluate_ok(text, variables)
    result = inline_rules(outcome.instances["aws_security_group.app"])
    assert len(result.rules) == 1, result
    return result.rules[0]


def resources_of(text: str, variables: Mapping[str, object] | None = None) -> dict[str, Resource]:
    _, outcome = evaluate_ok(text, variables)
    return {
        address: normalize_instance(instance, now=NOW)
        for address, instance in outcome.instances.items()
        if instance.kind == "resource"
    }


class TestTheSpecExample(unittest.TestCase):
    """Doc 04 §16.1: ingress tcp 22 from ["0.0.0.0/0"]."""

    def test_the_rule_resource_has_the_fields_of_the_example_and_of_c116(self) -> None:
        rule = tcp('  cidr_blocks = ["0.0.0.0/0"]\n')
        self.assertEqual(
            rule.core_json(),
            {
                "direction": "INGRESS",
                "protocol": "TCP",
                "from_port": 22,
                "to_port": 22,
                "ipv4_sources": ["0.0.0.0/0"],
                "target_security_group": "aws_security_group.app",
                **EMPTY_FIELDS,
            },
        )
        self.assertEqual(rule.origin, ORIGIN_RULE_RESOURCE)

    def test_the_source_address_and_origin(self) -> None:
        rule = tcp('  cidr_blocks = ["0.0.0.0/0"]\n')
        self.assertEqual(rule.source_address, "aws_security_group_rule.r")
        self.assertIsNone(rule.description)
        full = rule.to_json()
        self.assertEqual(full["origin"], "RULE_RESOURCE")
        self.assertEqual(full["source_address"], "aws_security_group_rule.r")

    def test_the_protocol_is_the_canonical_name_not_the_spelling_in_doc_04(self) -> None:
        # Doc 04 §16.1 writes "tcp"; registry §2.5 (later, v1.0) names the canonical form TCP
        self.assertEqual(tcp().protocol, "TCP")


class TestEquivalence(unittest.TestCase):
    def test_an_inline_block_and_a_separate_rule_have_the_same_key(self) -> None:
        inline = inline_of(
            '  ingress {\n    protocol = "tcp"\n    from_port = 22\n    to_port = 22\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n  }'
        )
        separate = tcp('  cidr_blocks = ["0.0.0.0/0"]\n')
        self.assertEqual(inline.origin, ORIGIN_INLINE)
        self.assertEqual(separate.origin, ORIGIN_RULE_RESOURCE)
        self.assertEqual(inline.rule_key(), separate.rule_key())
        self.assertNotEqual(inline.to_json(), separate.to_json())

    def test_every_field_takes_part_in_the_key(self) -> None:
        base = tcp('  cidr_blocks = ["0.0.0.0/0"]\n')
        variants = [
            tcp('  cidr_blocks = ["10.0.0.0/8"]\n'),
            tcp('  cidr_blocks = ["0.0.0.0/0"]\n', port=80),
            tcp('  cidr_blocks = ["0.0.0.0/0"]\n  self = true\n'),
            tcp('  cidr_blocks = ["0.0.0.0/0"]\n  ipv6_cidr_blocks = ["::/0"]\n'),
            tcp('  cidr_blocks = ["0.0.0.0/0"]\n  source_security_group_id = "sg-1"\n'),
            rule_of(
                '  type = "egress"\n  protocol = "tcp"\n  from_port = 22\n  to_port = 22\n'
                '  cidr_blocks = ["0.0.0.0/0"]\n'
            ),
            rule_of(
                '  type = "ingress"\n  protocol = "udp"\n  from_port = 22\n  to_port = 22\n'
                '  cidr_blocks = ["0.0.0.0/0"]\n'
            ),
        ]
        keys = {base.rule_key(), *(v.rule_key() for v in variants)}
        self.assertEqual(len(keys), len(variants) + 1)

    def test_the_description_is_kept_but_not_part_of_the_key(self) -> None:
        a = tcp('  cidr_blocks = ["0.0.0.0/0"]\n  description = "one"\n')
        b = tcp('  cidr_blocks = ["0.0.0.0/0"]\n  description = "two"\n')
        self.assertEqual((a.description, b.description), ("one", "two"))
        self.assertEqual(a.rule_key(), b.rule_key())
        self.assertNotEqual(a.to_json(), b.to_json())

    def test_a_different_target_is_a_different_rule(self) -> None:
        text = (
            'resource "aws_security_group" "a" {}\nresource "aws_security_group" "b" {}\n'
            'resource "aws_security_group_rule" "r1" {\n  type = "ingress"\n  protocol = "-1"\n'
            "  security_group_id = aws_security_group.a.id\n}\n"
            'resource "aws_security_group_rule" "r2" {\n  type = "ingress"\n  protocol = "-1"\n'
            "  security_group_id = aws_security_group.b.id\n}\n"
        )
        _, outcome = evaluate_ok(text)
        one = resource_rule(outcome.instances["aws_security_group_rule.r1"])
        two = resource_rule(outcome.instances["aws_security_group_rule.r2"])
        self.assertNotEqual(one.rule_key(), two.rule_key())


class TestInvariance(unittest.TestCase):
    def test_cidr_order_and_duplicates_never_matter(self) -> None:
        a = tcp('  cidr_blocks = ["10.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"]\n')
        b = tcp('  cidr_blocks = ["192.168.0.0/16", "10.0.0.0/8"]\n')
        self.assertEqual(a.ipv4_sources, ("10.0.0.0/8", "192.168.0.0/16"))
        self.assertEqual(a.rule_key(), b.rule_key())

    def test_cidrs_are_sorted_by_address_then_prefix_length(self) -> None:
        rule = tcp('  cidr_blocks = ["192.168.0.0/16", "10.0.0.0/16", "10.0.0.0/8", "0.0.0.0/0"]\n')
        self.assertEqual(
            rule.ipv4_sources, ("0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/16", "192.168.0.0/16")
        )

    def test_ipv6_cidrs_have_one_text_form(self) -> None:
        rule = tcp('  ipv6_cidr_blocks = ["2001:DB8::/32", "::/0", "2001:0db8::/32"]\n')
        self.assertEqual(rule.ipv6_sources, ("::/0", "2001:db8::/32"))
        self.assertTrue(rule.determinate)

    def test_protocol_spelling(self) -> None:
        table = {
            "tcp": "TCP", "TCP": "TCP", "Tcp": "TCP", "6": "TCP",
            "udp": "UDP", "UDP": "UDP", "17": "UDP",
            "icmp": "ICMP", "ICMP": "ICMP", "1": "ICMP",
            "icmpv6": "ICMPV6", "ICMPv6": "ICMPV6", "58": "ICMPV6",
            "-1": "ALL", "all": "ALL", "ALL": "ALL",
            "47": "47", "047": "47", "0": "0", "132": "132",
        }  # fmt: skip
        for text, expected in table.items():
            with self.subTest(text=text):
                self.assertEqual(canonical_protocol(text), expected)
        for text in ("gre", "esp", "", " tcp", "tcp ", "t cp", "1.5", "-2", "٦"):
            with self.subTest(text=text):
                self.assertIsNone(canonical_protocol(text))

    def test_six_is_tcp_and_minus_one_is_all_in_a_rule(self) -> None:
        numeric = rule_of(
            '  type = "ingress"\n  protocol = "6"\n  from_port = 22\n  to_port = 22\n'
        )
        named = tcp()
        self.assertEqual(numeric.rule_key(), named.rule_key())
        number = rule_of('  type = "ingress"\n  protocol = 6\n  from_port = 22\n  to_port = 22\n')
        self.assertEqual(number.rule_key(), named.rule_key())
        everything = rule_of(
            '  type = "ingress"\n  protocol = "-1"\n  from_port = 0\n  to_port = 0\n'
        )
        also = rule_of(
            '  type = "ingress"\n  protocol = "all"\n  from_port = 0\n  to_port = 65535\n'
        )
        self.assertEqual(everything.rule_key(), also.rule_key())

    def test_ports_of_all_are_null_and_the_raw_ones_stay_in_attributes(self) -> None:
        rule = rule_of('  type = "ingress"\n  protocol = "-1"\n  from_port = 0\n  to_port = 0\n')
        self.assertEqual((rule.protocol, rule.from_port, rule.to_port), ("ALL", None, None))
        self.assertTrue(rule.determinate)
        text = (
            SG + 'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  protocol = "-1"\n'
            "  from_port = 0\n  to_port = 0\n  security_group_id = aws_security_group.app.id\n}\n"
        )
        resource = resources_of(text)["aws_security_group_rule.r"]
        self.assertEqual(
            thaw_json(resource.attributes)["from_port"], {"form": "ATTRIBUTE", "value": 0}
        )
        self.assertIsNone(thaw_json(resource.security_attributes)["rule"]["from_port"])

    def test_other_protocols_keep_their_numbers(self) -> None:
        rule = rule_of('  type = "ingress"\n  protocol = "icmp"\n  from_port = 8\n  to_port = -1\n')
        self.assertEqual((rule.protocol, rule.from_port, rule.to_port), ("ICMP", 8, -1))
        self.assertTrue(rule.determinate)
        gre = rule_of('  type = "ingress"\n  protocol = "47"\n  from_port = 0\n  to_port = 0\n')
        self.assertEqual(gre.protocol, "47")

    def test_source_security_groups_are_a_sorted_set(self) -> None:
        text = (
            'resource "aws_security_group" "a" {}\nresource "aws_security_group" "b" {}\n'
            'resource "aws_security_group" "t" {\n'
            "  ingress {\n"
            '    protocol = "tcp"\n'
            "    from_port = 1\n"
            "    to_port = 1\n"
            "    security_groups = [aws_security_group.b.id, aws_security_group.a.id,"
            ' aws_security_group.a.id, "sg-0123"]\n  }\n}\n'
        )
        _, outcome = evaluate_ok(text)
        (rule,) = inline_rules(outcome.instances["aws_security_group.t"]).rules
        self.assertEqual(
            rule.source_security_groups,
            ("EXTERNAL:sg-0123", "aws_security_group.a", "aws_security_group.b"),
        )
        self.assertTrue(rule.determinate)


class TestProblemPaths(unittest.TestCase):
    """Every problem path of registry §2.5 and §2.6."""

    def check(
        self,
        rule: CanonicalSecurityRule,
        *,
        determinate: bool,
        unsupported: bool,
        problems: tuple[str, ...],
    ) -> None:
        self.assertEqual(
            (rule.determinate, rule.unsupported, rule.problems),
            (determinate, unsupported, problems),
        )

    def test_a_malformed_cidr_is_unsupported(self) -> None:
        for bad in ("10.0.0.0/33", "10.0.0/8", "not-a-cidr", "10.0.0.0", "10.0.0.0/8/9", ""):
            with self.subTest(bad=bad):
                rule = tcp(f'  cidr_blocks = ["{bad}"]\n')
                self.check(
                    rule, determinate=False, unsupported=True, problems=(f"cidr.invalid:{bad}",)
                )
                self.assertEqual(rule.ipv4_sources, ())

    def test_a_cidr_with_host_bits_is_unsupported(self) -> None:
        rule = tcp('  cidr_blocks = ["10.0.0.1/8"]\n')
        self.check(rule, determinate=False, unsupported=True, problems=("cidr.invalid:10.0.0.1/8",))
        v6 = tcp('  ipv6_cidr_blocks = ["2001:db8::1/32"]\n')
        self.check(
            v6, determinate=False, unsupported=True, problems=("cidr.invalid:2001:db8::1/32",)
        )

    def test_a_cidr_of_the_wrong_family_is_unsupported(self) -> None:
        rule = tcp('  cidr_blocks = ["::/0"]\n  ipv6_cidr_blocks = ["0.0.0.0/0"]\n')
        self.check(
            rule,
            determinate=False,
            unsupported=True,
            problems=("cidr.invalid:0.0.0.0/0", "cidr.invalid:::/0"),
        )

    def test_the_good_cidrs_of_a_bad_rule_are_still_listed(self) -> None:
        rule = tcp('  cidr_blocks = ["10.0.0.0/8", "10.0.0.1/8"]\n')
        self.assertEqual(rule.ipv4_sources, ("10.0.0.0/8",))
        self.assertTrue(rule.unsupported)

    def test_inverted_tcp_ports_are_unsupported(self) -> None:
        rule = rule_of('  type = "ingress"\n  protocol = "tcp"\n  from_port = 80\n  to_port = 22\n')
        self.check(rule, determinate=False, unsupported=True, problems=("ports.inverted",))
        udp = rule_of('  type = "ingress"\n  protocol = "udp"\n  from_port = 80\n  to_port = 22\n')
        self.assertTrue(udp.determinate)  # only TCP is checked (registry §2.5)

    def test_missing_and_invalid_ports(self) -> None:
        missing = rule_of('  type = "ingress"\n  protocol = "tcp"\n  from_port = 22\n')
        self.check(missing, determinate=False, unsupported=True, problems=("ports.missing",))
        high = rule_of(
            '  type = "ingress"\n  protocol = "tcp"\n  from_port = 22\n  to_port = 70000\n'
        )
        self.check(high, determinate=False, unsupported=True, problems=("ports.invalid",))
        fraction = rule_of(
            '  type = "ingress"\n  protocol = "tcp"\n  from_port = 1.5\n  to_port = 22\n'
        )
        self.assertIn("ports.invalid", fraction.problems)

    def test_missing_and_unsupported_protocols(self) -> None:
        missing = rule_of('  type = "ingress"\n  from_port = 22\n  to_port = 22\n')
        self.check(missing, determinate=False, unsupported=True, problems=("protocol.missing",))
        self.assertIsNone(missing.protocol)
        odd = rule_of('  type = "ingress"\n  protocol = "GRE"\n  from_port = 0\n  to_port = 0\n')
        self.check(odd, determinate=False, unsupported=True, problems=("protocol.unsupported:gre",))

    def test_an_unknown_value_makes_the_rule_indeterminate_not_unsupported(self) -> None:
        unknown = ("variable.no_value",)
        cases = {
            "cidr_blocks": '  type = "ingress"\n'
            '  protocol = "tcp"\n'
            "  from_port = 22\n"
            "  to_port = 22\n"
            "  cidr_blocks = var.v\n",
            "ipv6": '  type = "ingress"\n'
            '  protocol = "tcp"\n'
            "  from_port = 22\n"
            "  to_port = 22\n"
            "  ipv6_cidr_blocks = [var.v]\n",
            "protocol": '  type = "ingress"\n'
            "  protocol = var.v\n"
            "  from_port = 22\n"
            "  to_port = 22\n",
            "from_port": '  type = "ingress"\n'
            '  protocol = "tcp"\n'
            "  from_port = var.v\n"
            "  to_port = 22\n",
            "to_port": '  type = "ingress"\n'
            '  protocol = "tcp"\n'
            "  from_port = 22\n"
            "  to_port = var.v\n",
            "source": '  type = "ingress"\n'
            '  protocol = "tcp"\n'
            "  from_port = 22\n"
            "  to_port = 22\n"
            "  source_security_group_id = var.v\n",
            "self": '  type = "ingress"\n'
            '  protocol = "tcp"\n'
            "  from_port = 22\n"
            "  to_port = 22\n"
            "  self = var.v\n",
            "prefix": '  type = "ingress"\n'
            '  protocol = "tcp"\n'
            "  from_port = 22\n"
            "  to_port = 22\n"
            "  prefix_list_ids = var.v\n",
        }
        for label, body in cases.items():
            with self.subTest(label):
                self.check(rule_of(body), determinate=False, unsupported=False, problems=unknown)

    def test_an_unsupported_value_makes_the_rule_unsupported(self) -> None:
        rule = tcp("  cidr_blocks = [abs(1)]\n")
        self.check(
            rule,
            determinate=False,
            unsupported=True,
            problems=("function.not_implemented:abs",),
        )

    def test_a_value_of_the_wrong_type_is_unsupported(self) -> None:
        rule = tcp("  cidr_blocks = 5\n")
        self.assertEqual((rule.determinate, rule.unsupported), (False, True))
        self.assertEqual(rule.problems, ("field.type:cidr_blocks",))
        self.assertEqual(tcp('  self = "yes"\n').problems, ("field.type:self",))

    def test_a_non_empty_prefix_list_is_indeterminate(self) -> None:
        rule = tcp('  prefix_list_ids = ["pl-123", "pl-123", "pl-000"]\n')
        self.assertEqual(rule.prefix_list_ids, ("pl-000", "pl-123"))
        self.check(
            rule, determinate=False, unsupported=False, problems=("prefix_list_ids.present",)
        )
        empty = tcp("  prefix_list_ids = []\n")
        self.assertTrue(empty.determinate)

    def test_a_reference_in_a_list_that_needs_a_value_is_indeterminate(self) -> None:
        text = (
            SG
            + 'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  protocol = "tcp"\n'
            "  from_port = 1\n  to_port = 1\n  cidr_blocks = [aws_security_group.app.id]\n"
            "  security_group_id = aws_security_group.app.id\n}\n"
        )
        _, outcome = evaluate_ok(text)
        rule = resource_rule(outcome.instances["aws_security_group_rule.r"])
        self.check(
            rule, determinate=False, unsupported=False,
            problems=("ref.derived:aws_security_group.app.id",),
        )  # fmt: skip

    def test_a_field_written_as_a_block_is_unsupported(self) -> None:
        rule = inline_of(
            '  ingress {\n    protocol = "tcp"\n    from_port = 1\n    to_port = 1\n'
            "    cidr_blocks {\n      x = 1\n    }\n  }"
        )
        self.assertEqual(rule.problems, ("field.form",))
        self.assertTrue(rule.unsupported)

    def test_the_problem_codes_are_registered(self) -> None:
        source = (ROOT / "core" / "terraform_model" / "security_rules.py").read_text(
            encoding="utf-8"
        )
        used: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "structural"
                and isinstance(node.args[0], ast.Constant)
            ):
                used.add(str(node.args[0].value))
        self.assertEqual(sorted(used - set(PROBLEM_CODES)), [])
        self.assertEqual(sorted(set(PROBLEM_CODES) - used - {"ref.derived", "field.form"}), [])


class TestTargetsAndDirections(unittest.TestCase):
    def target_of(self, group: str, variables: Mapping[str, object] | None = None) -> str:
        text = (
            'variable "v" {}\nresource "aws_vpc" "main" {}\n' + SG
            + 'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  protocol = "-1"\n'
            f"  security_group_id = {group}\n}}\n"
        )  # fmt: skip
        _, outcome = evaluate_ok(text, variables)
        return resource_rule(outcome.instances["aws_security_group_rule.r"]).target_security_group

    def test_a_reference_to_a_configured_group_is_its_address(self) -> None:
        self.assertEqual(self.target_of("aws_security_group.app.id"), "aws_security_group.app")

    def test_a_literal_id_is_an_external_pseudo_group(self) -> None:
        self.assertEqual(self.target_of('"sg-0123abcd"'), "EXTERNAL:sg-0123abcd")
        self.assertEqual(self.target_of("var.v", {"v": "sg-9"}), "EXTERNAL:sg-9")

    def test_an_unresolved_id_is_keyed_by_the_rule_address(self) -> None:
        self.assertEqual(self.target_of("var.v"), "UNRESOLVED:aws_security_group_rule.r")
        self.assertEqual(self.target_of("aws_vpc.main.id"), "UNRESOLVED:aws_security_group_rule.r")

    def test_a_group_with_for_each_has_instance_addresses(self) -> None:
        text = (
            'resource "aws_security_group" "g" {\n  for_each = toset(["a", "b"])\n}\n'
            'resource "aws_security_group_rule" "r" {\n  for_each = toset(["a", "b"])\n'
            '  type = "ingress"\n'
            '  protocol = "-1"\n'
            "  security_group_id = aws_security_group.g[each.key].id\n"
            "}\n"
        )
        _, outcome = evaluate_ok(text)
        targets = sorted(
            resource_rule(i).target_security_group
            for a, i in outcome.instances.items()
            if i.type == "aws_security_group_rule"
        )
        self.assertEqual(targets, ['aws_security_group.g["a"]', 'aws_security_group.g["b"]'])

    def test_the_type_decides_the_direction(self) -> None:
        egress = rule_of('  type = "egress"\n  protocol = "-1"\n')
        self.assertEqual(egress.direction, EGRESS)
        self.assertEqual(rule_of('  type = "ingress"\n  protocol = "-1"\n').direction, INGRESS)

    def test_a_type_that_is_neither_is_unsupported(self) -> None:
        for body in (
            '  type = "Ingress"\n  protocol = "-1"\n',
            '  protocol = "-1"\n',
            '  type = 5\n  protocol = "-1"\n',
        ):
            with self.subTest(body=body):
                rule = rule_of(body)
                self.assertIsNone(rule.direction)
                self.assertTrue(rule.unsupported)

    def test_an_unknown_type_is_indeterminate(self) -> None:
        rule = rule_of('  type = var.v\n  protocol = "-1"\n')
        self.assertIsNone(rule.direction)
        self.assertEqual((rule.determinate, rule.unsupported), (False, False))
        self.assertEqual(rule.problems, ("variable.no_value",))


class TestInlineRules(unittest.TestCase):
    def group(self, body: str, variables: Mapping[str, object] | None = None):  # type: ignore[no-untyped-def]
        text = f'variable "v" {{}}\nresource "aws_security_group" "g" {{\n{body}\n}}\n'
        _, outcome = evaluate_ok(text, variables)
        return inline_rules(outcome.instances["aws_security_group.g"])

    def test_each_block_is_one_rule_with_the_group_as_target(self) -> None:
        result = self.group(
            '  ingress {\n    protocol = "tcp"\n    from_port = 22\n    to_port = 22\n  }\n'
            '  egress {\n    protocol = "-1"\n    from_port = 0\n    to_port = 0\n  }'
        )
        self.assertEqual(len(result.rules), 2)
        self.assertEqual({r.target_security_group for r in result.rules}, {"aws_security_group.g"})
        self.assertEqual({r.direction for r in result.rules}, {INGRESS, EGRESS})
        self.assertEqual({r.origin for r in result.rules}, {ORIGIN_INLINE})
        self.assertEqual(dict(result.forms), {"ingress": "blocks", "egress": "blocks"})

    def test_a_dynamic_group_expands_into_rules(self) -> None:
        result = self.group(
            '  dynamic "ingress" {\n'
            "    for_each = [22, 80]\n"
            "    content {\n"
            '      protocol = "tcp"\n'
            "      from_port = ingress.value\n      to_port = ingress.value\n    }\n  }"
        )
        self.assertEqual([r.from_port for r in result.rules], [22, 80])
        self.assertEqual(dict(result.forms)["ingress"], "dynamic")
        self.assertEqual(result.indeterminate, ())

    def test_an_indeterminate_dynamic_group_is_a_recorded_reason(self) -> None:
        result = self.group('  dynamic "ingress" {\n    for_each = var.v\n    content {}\n  }')
        self.assertEqual(result.rules, ())
        self.assertEqual(
            result.indeterminate, ({"$dail": "unknown", "reason": "variable.no_value"},)
        )

    def test_an_attribute_form_list_gives_rules(self) -> None:
        result = self.group(
            '  ingress = [{ protocol = "tcp", from_port = 22, to_port = 22,'
            ' cidr_blocks = ["10.0.0.0/8"] }]'
        )
        (rule,) = result.rules
        self.assertEqual((rule.protocol, rule.ipv4_sources), ("TCP", ("10.0.0.0/8",)))
        self.assertEqual(dict(result.forms)["ingress"], "blocks")

    def test_an_unresolved_element_is_a_recorded_reason(self) -> None:
        result = self.group('  ingress = [var.v, { protocol = "-1" }]')
        self.assertEqual(len(result.rules), 1)
        self.assertEqual(
            result.indeterminate, ({"$dail": "unknown", "reason": "variable.no_value"},)
        )

    def test_explicit_empty_and_absent_have_no_rules(self) -> None:
        result = self.group("  egress = []")
        self.assertEqual(result.rules, ())
        self.assertEqual(dict(result.forms), {"ingress": "absent", "egress": "explicit_empty"})

    def test_the_rules_are_sorted(self) -> None:
        one = self.group(
            '  ingress {\n    protocol = "tcp"\n    from_port = 80\n    to_port = 80\n  }\n'
            '  ingress {\n    protocol = "tcp"\n    from_port = 22\n    to_port = 22\n  }'
        )
        two = self.group(
            '  ingress {\n    protocol = "tcp"\n    from_port = 22\n    to_port = 22\n  }\n'
            '  ingress {\n    protocol = "tcp"\n    from_port = 80\n    to_port = 80\n  }'
        )
        self.assertEqual([r.rule_key() for r in one.rules], [r.rule_key() for r in two.rules])


class TestInsideTheResource(unittest.TestCase):
    TEXT = (
        'resource "aws_security_group" "app" {\n'
        "  ingress {\n"
        '    protocol = "tcp"\n'
        "    from_port = 22\n"
        '    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        'resource "aws_security_group_rule" "r" {\n  type = "egress"\n  protocol = "-1"\n'
        "  security_group_id = aws_security_group.app.id\n}\n"
    )

    def test_an_inline_rule_is_stored_without_the_address_of_its_group(self) -> None:
        group = resources_of(self.TEXT)["aws_security_group.app"]
        security = thaw_json(group.security_attributes)
        (view,) = security["inline_rules"]
        self.assertEqual(view["target_security_group"], "SELF")
        self.assertNotIn("source_address", view)
        self.assertNotIn(
            "aws_security_group.app", group.canonical_json.replace("aws_security_group.app_", "")
        )

    def test_renaming_a_group_does_not_change_its_fingerprint(self) -> None:
        renamed = self.TEXT.replace('"app"', '"web"').replace(
            "security_group.app", "security_group.web"
        )
        before = resources_of(self.TEXT)["aws_security_group.app"]
        after = resources_of(renamed)["aws_security_group.web"]
        self.assertEqual(before.fingerprint, after.fingerprint)

    def test_the_rule_resource_stores_the_rule_and_the_target(self) -> None:
        rule_resource = resources_of(self.TEXT)["aws_security_group_rule.r"]
        security = thaw_json(rule_resource.security_attributes)
        self.assertEqual(security["target"], "aws_security_group.app")
        self.assertEqual(security["rule"]["target_security_group"], "aws_security_group.app")
        self.assertEqual(security["rule"]["origin"], "RULE_RESOURCE")

    def test_rules_round_trip_through_the_resource(self) -> None:
        resources = resources_of(self.TEXT)
        (rebuilt,) = rules_of(resources["aws_security_group.app"])
        _, outcome = evaluate_ok(self.TEXT)
        (original,) = inline_rules(outcome.instances["aws_security_group.app"]).rules
        self.assertEqual(rebuilt, original)
        (separate,) = rules_of(resources["aws_security_group_rule.r"])
        self.assertEqual(separate, resource_rule(outcome.instances["aws_security_group_rule.r"]))

    def test_other_types_hold_no_rules(self) -> None:
        resources = resources_of('resource "aws_vpc" "v" {}\n')
        self.assertEqual(rules_of(resources["aws_vpc.v"]), ())


class TestTheIndex(unittest.TestCase):
    TEXT = (
        'resource "aws_security_group" "b" {\n  egress = []\n}\n'
        'resource "aws_security_group" "a" {\n'
        "  ingress {\n"
        '    protocol = "tcp"\n'
        "    from_port = 22\n"
        '    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        'resource "aws_security_group_rule" "same" {\n  type = "ingress"\n  protocol = "tcp"\n'
        '  from_port = 22\n  to_port = 22\n  cidr_blocks = ["0.0.0.0/0"]\n'
        "  security_group_id = aws_security_group.a.id\n}\n"
        'resource "aws_security_group_rule" "ext" {\n  type = "egress"\n  protocol = "-1"\n'
        '  security_group_id = "sg-0123"\n}\n'
        'resource "aws_security_group_rule" "loose" {\n  type = "ingress"\n  protocol = "-1"\n'
        "  security_group_id = aws_vpc.nothing.id\n}\n"
    ).replace("aws_vpc.nothing.id", '"sg-x"')

    def test_the_groups_are_sorted_and_pseudo_groups_appear(self) -> None:
        index = index_rules(resources_of(self.TEXT).values())
        self.assertEqual(
            list(index),
            ["EXTERNAL:sg-0123", "EXTERNAL:sg-x", "aws_security_group.a", "aws_security_group.b"],
        )

    def test_equal_rules_are_both_kept(self) -> None:
        group = index_rules(resources_of(self.TEXT).values())["aws_security_group.a"]
        self.assertEqual(len(group.ingress), 2)
        self.assertEqual(group.ingress[0].rule_key(), group.ingress[1].rule_key())
        self.assertEqual({r.origin for r in group.ingress}, {ORIGIN_INLINE, ORIGIN_RULE_RESOURCE})
        self.assertEqual(group.egress, ())

    def test_a_group_without_rules_still_has_its_forms(self) -> None:
        group = index_rules(resources_of(self.TEXT).values())["aws_security_group.b"]
        self.assertEqual((group.ingress, group.egress), ((), ()))
        self.assertEqual(
            dict(group.inline_forms or {}), {"ingress": "absent", "egress": "explicit_empty"}
        )

    def test_a_pseudo_group_has_no_forms(self) -> None:
        group = index_rules(resources_of(self.TEXT).values())["EXTERNAL:sg-0123"]
        self.assertIsNone(group.inline_forms)
        self.assertEqual(len(group.egress), 1)

    def test_the_index_does_not_depend_on_the_order_of_the_resources(self) -> None:
        resources = list(resources_of(self.TEXT).values())
        forward = index_rules(resources)
        backward = index_rules(reversed(resources))
        self.assertEqual(list(forward), list(backward))
        for key in forward:
            self.assertEqual(forward[key], backward[key])

    def test_rules_of_an_unresolved_direction_are_kept_apart(self) -> None:
        text = (
            'variable "v" {}\n' + SG
            + 'resource "aws_security_group_rule" "r" {\n  type = var.v\n  protocol = "-1"\n'
            "  security_group_id = aws_security_group.app.id\n}\n"
        )  # fmt: skip
        group = index_rules(resources_of(text).values())["aws_security_group.app"]
        self.assertEqual((group.ingress, group.egress), ((), ()))
        self.assertEqual(len(group.unresolved_direction), 1)

    def test_the_index_is_only_an_index(self) -> None:
        # no predicate: the module has no function that decides public access or reachability
        names = {n for n in dir(security_rules) if not n.startswith("_")}
        self.assertFalse({n for n in names if "public" in n.lower() or "reach" in n.lower()})


if __name__ == "__main__":
    unittest.main()
