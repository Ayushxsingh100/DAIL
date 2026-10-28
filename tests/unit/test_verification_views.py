"""The verifier's reader of the stored security view (P5a step 3; C-144, C-149).

Part one: hand-derived expectations on small configurations, written from the registry text (§2.6
rule sets, §3.3 indeterminate rules) and from the shape P3a stores (``security_rules`` module
docstring). Part two: the equivalence test of C-144, the one place that imports both readers. On
every fixture configuration and on seeded generated configurations the verifier's rules, groups and
forms equal ``core.terraform_model.security_rules.index_rules``, field by field.
"""

from __future__ import annotations

import random
import unittest
from collections.abc import Mapping
from typing import Any

from core.domain.enums import ResourceSupport
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.terraform_model import security_rules as p3a
from core.terraform_model.normalization import normalize_directory
from core.verification import views
from core.verification.views import EGRESS, INGRESS, ViewError
from tests import fixture_catalog as fc
from tests.identity_builders import NOW, normalize

VARS = 'variable "u" {}\n'
APP = "aws_security_group.app"


def resources_of(text: str, variables: Mapping[str, object] | None = None) -> tuple[Resource, ...]:
    return normalize(text, variables).resources


def group(body: str = "", name: str = "app") -> str:
    return f'resource "aws_security_group" "{name}" {{\n{body}\n}}\n'


def rule_resource(body: str, name: str = "r", target: str = "aws_security_group.app.id") -> str:
    return (
        f'resource "aws_security_group_rule" "{name}" {{\n  security_group_id = {target}\n'
        f"{body}\n}}\n"
    )


def view_of(text: str, address: str = APP) -> views.GroupView:
    return views.index_rules(resources_of(text))[address]


class TestInlineRules(unittest.TestCase):
    def test_a_determinate_inline_rule(self) -> None:
        text = group(
            '  ingress {\n protocol = "tcp"\n from_port = 22\n to_port = 22\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n }'
        )
        view = view_of(text)
        self.assertEqual(len(view.ingress), 1)
        self.assertEqual(view.egress, ())
        self.assertEqual(view.unresolved_direction, ())
        rule = view.ingress[0]
        self.assertEqual(
            (rule.direction, rule.protocol, rule.from_port, rule.to_port),
            (INGRESS, "TCP", 22, 22),
        )
        self.assertEqual(rule.ipv4_sources, ("0.0.0.0/0",))
        self.assertEqual(rule.ipv6_sources, ())
        self.assertEqual(rule.target, APP)  # the SELF token is resolved to the owner
        self.assertEqual(rule.source_address, APP)
        self.assertEqual(rule.origin, "INLINE")
        self.assertTrue(rule.determinate)
        self.assertFalse(rule.unsupported)
        self.assertEqual(rule.problems, ())
        self.assertFalse(rule.ipv4_unresolved or rule.ipv6_unresolved)
        self.assertEqual(dict(view.forms or {}), {"ingress": "blocks", "egress": "absent"})

    def test_the_forms(self) -> None:
        cases = {
            "": {"ingress": "absent", "egress": "absent"},
            "  ingress = []\n": {"ingress": "explicit_empty", "egress": "absent"},
            "  egress = []\n  ingress = []\n": {
                "ingress": "explicit_empty",
                "egress": "explicit_empty",
            },
            '  egress {\n protocol = "-1"\n from_port = 0\n to_port = 0\n }': {
                "ingress": "absent",
                "egress": "blocks",
            },
        }
        for body, expected in cases.items():
            with self.subTest(body=body):
                self.assertEqual(dict(view_of(group(body)).forms or {}), expected)

    def test_a_direction_that_cannot_be_fixed_is_unresolved_not_empty(self) -> None:
        # C-120(c): the form is `unresolved`, which the predicates turn into UNSUPPORTED
        view = view_of(VARS + group("  ingress = var.u\n"))
        self.assertEqual((view.forms or {})["ingress"], "unresolved")
        self.assertEqual(view.ingress, ())

    def test_an_unexpandable_dynamic_block_is_a_placeholder_not_nothing(self) -> None:
        text = VARS + group(
            '  dynamic "ingress" {\n    for_each = var.u\n    content {\n'
            '      protocol = "tcp"\n      from_port = 22\n      to_port = 22\n'
            '      cidr_blocks = ["0.0.0.0/0"]\n    }\n  }\n'
        )
        view = view_of(text)
        self.assertEqual((view.forms or {})["ingress"], "dynamic")
        self.assertEqual(view.ingress, ())
        self.assertEqual(len(view.indeterminate_blocks["ingress"]), 1)
        self.assertEqual(view.indeterminate_blocks["egress"], ())

    def test_an_expandable_dynamic_block_gives_rules(self) -> None:
        text = 'variable "ports" {\n  default = [22, 80]\n}\n' + group(
            '  dynamic "ingress" {\n    for_each = var.ports\n    content {\n'
            '      protocol = "tcp"\n      from_port = ingress.value\n'
            '      to_port = ingress.value\n      cidr_blocks = ["10.0.0.0/8"]\n    }\n  }\n'
        )
        view = view_of(text)
        self.assertEqual(sorted(r.from_port for r in view.ingress), [22, 80])
        self.assertEqual(view.indeterminate_blocks["ingress"], ())

    def test_the_unresolved_family_flags_are_the_union_over_the_direction(self) -> None:
        # C-149: two indeterminate blocks, one unresolved in IPv4 and the other in IPv6; the view
        # cannot pair a block with its rule, so both rules carry both flags (conservative)
        text = VARS + group(
            '  ingress {\n protocol = "tcp"\n from_port = 22\n to_port = 22\n'
            "    cidr_blocks = var.u\n }\n"
            '  ingress {\n protocol = "tcp"\n from_port = 22\n to_port = 22\n'
            "    ipv6_cidr_blocks = var.u\n }\n"
            '  ingress {\n protocol = "tcp"\n from_port = 80\n to_port = 80\n'
            '    cidr_blocks = ["10.0.0.0/8"]\n }\n'
        )
        view = view_of(text)
        indeterminate = [r for r in view.ingress if not r.determinate]
        determinate = [r for r in view.ingress if r.determinate]
        self.assertEqual(len(indeterminate), 2)
        self.assertEqual(len(determinate), 1)
        for rule in indeterminate:
            self.assertTrue(rule.ipv4_unresolved)
            self.assertTrue(rule.ipv6_unresolved)
        # a determinate rule is never flagged
        self.assertFalse(determinate[0].ipv4_unresolved or determinate[0].ipv6_unresolved)

    def test_one_indeterminate_block_flags_only_its_own_family(self) -> None:
        text = VARS + group(
            '  ingress {\n protocol = "tcp"\n from_port = 22\n to_port = 22\n'
            "    cidr_blocks = var.u\n }\n"
        )
        rule = view_of(text).ingress[0]
        self.assertTrue(rule.ipv4_unresolved)
        self.assertFalse(rule.ipv6_unresolved)

    def test_flags_are_per_direction(self) -> None:
        text = VARS + group(
            '  egress {\n protocol = "tcp"\n from_port = 22\n to_port = 22\n'
            "    cidr_blocks = var.u\n }\n"
            '  ingress {\n protocol = "tcp"\n from_port = 22\n to_port = 22\n'
            "    ipv6_cidr_blocks = var.u\n }\n"
        )
        view = view_of(text)
        self.assertFalse(view.ingress[0].ipv4_unresolved)
        self.assertTrue(view.ingress[0].ipv6_unresolved)
        self.assertTrue(view.egress[0].ipv4_unresolved)
        self.assertFalse(view.egress[0].ipv6_unresolved)


class TestRuleResources(unittest.TestCase):
    def view(self, body: str) -> views.Rule:
        view = view_of(VARS + group() + rule_resource(body))
        (rule,) = view.ingress
        return rule

    BASE = '  type = "ingress"\n  protocol = "tcp"\n  from_port = 5432\n  to_port = 5432\n'

    def test_a_determinate_rule_resource(self) -> None:
        rule = self.view(self.BASE + '  cidr_blocks = ["10.0.0.0/16"]\n')
        self.assertEqual(rule.origin, "RULE_RESOURCE")
        self.assertEqual(rule.source_address, "aws_security_group_rule.r")
        self.assertEqual(rule.target, APP)
        self.assertTrue(rule.determinate)
        self.assertFalse(rule.ipv4_unresolved or rule.ipv6_unresolved)

    def test_an_unresolved_ipv4_list_is_flagged_exactly(self) -> None:
        rule = self.view(self.BASE + "  cidr_blocks = var.u\n")
        self.assertFalse(rule.determinate)
        self.assertTrue(rule.ipv4_unresolved)
        self.assertFalse(rule.ipv6_unresolved)

    def test_one_unresolved_element_is_flagged(self) -> None:
        rule = self.view(self.BASE + '  cidr_blocks = ["10.0.0.0/8", var.u]\n')
        self.assertTrue(rule.ipv4_unresolved)

    def test_an_unresolved_ipv6_list_is_flagged_exactly(self) -> None:
        rule = self.view(self.BASE + "  ipv6_cidr_blocks = var.u\n")
        self.assertTrue(rule.ipv6_unresolved)
        self.assertFalse(rule.ipv4_unresolved)

    def test_an_unresolved_source_group_flags_neither_family(self) -> None:
        # func_unknown_dependency_unknown_v1: the rule is indeterminate but its IPv4 and IPv6
        # sources are resolved (empty), so possible4 and possible6 are both false (registry §3.3)
        rule = self.view(self.BASE + "  source_security_group_id = var.u\n")
        self.assertFalse(rule.determinate)
        self.assertFalse(rule.ipv4_unresolved)
        self.assertFalse(rule.ipv6_unresolved)

    def test_an_unresolved_protocol_or_port_flags_neither_family(self) -> None:
        rule = self.view(
            '  type = "ingress"\n  protocol = var.u\n  from_port = 22\n  to_port = 22\n'
            '  cidr_blocks = ["0.0.0.0/0"]\n'
        )
        self.assertFalse(rule.determinate)
        self.assertIsNone(rule.protocol)
        self.assertFalse(rule.ipv4_unresolved)

    def test_a_prefix_list_is_its_own_field_not_an_unresolved_family(self) -> None:
        rule = self.view(self.BASE + '  prefix_list_ids = ["pl-1"]\n')
        self.assertEqual(rule.prefix_list_ids, ("pl-1",))
        self.assertFalse(rule.determinate)
        self.assertFalse(rule.ipv4_unresolved or rule.ipv6_unresolved)

    def test_an_unresolved_type_has_no_direction_and_is_not_dropped(self) -> None:
        text = (
            VARS
            + group()
            + rule_resource(
                '  type = var.u\n  protocol = "tcp"\n  from_port = 22\n  to_port = 22\n'
                '  cidr_blocks = ["0.0.0.0/0"]\n'
            )
        )
        view = view_of(text)
        self.assertEqual(view.ingress, ())
        self.assertEqual(view.egress, ())
        (rule,) = view.unresolved_direction
        self.assertIsNone(rule.direction)
        self.assertFalse(rule.determinate)

    def test_an_invalid_type_is_unsupported_and_has_no_direction(self) -> None:
        text = group() + rule_resource(
            '  type = "sideways"\n  protocol = "tcp"\n  from_port = 22\n  to_port = 22\n'
        )
        (rule,) = view_of(text).unresolved_direction
        self.assertTrue(rule.unsupported)

    def test_egress_goes_to_egress(self) -> None:
        text = group() + rule_resource(
            '  type = "egress"\n  protocol = "-1"\n  from_port = 0\n  to_port = 0\n'
            '  cidr_blocks = ["0.0.0.0/0"]\n'
        )
        view = view_of(text)
        self.assertEqual(view.ingress, ())
        self.assertEqual(len(view.egress), 1)

    def test_pseudo_groups(self) -> None:
        text = (
            group()
            + rule_resource(
                self.BASE + '  cidr_blocks = ["0.0.0.0/0"]\n', name="ext", target='"sg-0123abcd"'
            )
            + rule_resource(self.BASE, name="loose", target="var.nowhere")
        )
        index = views.index_rules(resources_of('variable "nowhere" {}\n' + text))
        self.assertIn("EXTERNAL:sg-0123abcd", index)
        self.assertIn("UNRESOLVED:aws_security_group_rule.loose", index)
        for key in ("EXTERNAL:sg-0123abcd", "UNRESOLVED:aws_security_group_rule.loose"):
            self.assertIsNone(index[key].forms)
            self.assertEqual(len(index[key].ingress), 1)

    def test_every_group_is_indexed_even_without_rules(self) -> None:
        index = views.index_rules(resources_of(group(name="a") + group(name="b")))
        self.assertEqual(sorted(index), ["aws_security_group.a", "aws_security_group.b"])
        self.assertEqual(index["aws_security_group.a"].ingress, ())


class TestOtherTypes(unittest.TestCase):
    def test_other_resources_have_no_rules(self) -> None:
        for resource in resources_of(
            'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        ):
            self.assertEqual(views.rules_of(resource), ())
        self.assertEqual(views.index_rules(()), {})


class TestPlaceholders(unittest.TestCase):
    """P3a's index reads a placeholder's empty view as a group with no rules; this must not."""

    def test_an_unknown_count_resource_is_listed_never_read_as_no_rules(self) -> None:
        text = (
            VARS
            + 'resource "aws_security_group" "p" {\n  count = var.u\n}\n'
            + group()
            + 'resource "aws_security_group_rule" "pr" {\n  count = var.u\n  type = "ingress"\n'
            '  security_group_id = aws_security_group.app.id\n  protocol = "tcp"\n'
            "  from_port = 22\n  to_port = 22\n}\n"
        )
        resources = resources_of(text)
        config = views.read_security(resources)
        self.assertEqual(
            config.unknown_resources, ("aws_security_group.p", "aws_security_group_rule.pr")
        )
        self.assertEqual(config.unsupported_resources, ())
        self.assertEqual(sorted(config.groups), [APP])  # the placeholder group is not a group
        # the contrast that motivates this: P3a's own index does list the placeholder as empty
        self.assertIn("aws_security_group.p", p3a.index_rules(resources))
        for resource in resources:
            if resource.address in config.unknown_resources:
                self.assertEqual(views.rules_of(resource), ())

    def test_an_unreadable_resource_is_listed_as_unsupported(self) -> None:
        base = next(r for r in resources_of(group()) if r.resource_type == "aws_security_group")
        broken = Resource.create(
            address=base.address,
            resource_type=base.resource_type,
            logical_identity={},
            attributes={"$content": {"$dail": "unsupported", "reason": "limit.json_depth"}},
            security_attributes={},
            semantic_attributes={},
            references=(),
            provenance=base.provenance,
            support_status=ResourceSupport.UNSUPPORTED,
        )
        config = views.read_security([broken])
        self.assertEqual(config.unsupported_resources, (base.address,))
        self.assertEqual(dict(config.groups), {})

    def test_a_supported_group_with_an_empty_view_is_malformed_not_empty(self) -> None:
        base = next(r for r in resources_of(group()) if r.resource_type == "aws_security_group")
        with self.assertRaises(ViewError):
            views.read_security([replace_security(base, {})])

    def test_other_types_are_not_placeholders_of_this_reader(self) -> None:
        text = VARS + 'resource "aws_vpc" "v" {\n  count = var.u\n}\n'
        config = views.read_security(resources_of(text))
        self.assertEqual((config.unknown_resources, config.unsupported_resources), ((), ()))


def replace_security(resource: Resource, security: Mapping[str, Any]) -> Resource:
    return Resource.create(
        address=resource.address,
        resource_type=resource.resource_type,
        logical_identity=thaw_json(resource.logical_identity),
        attributes=thaw_json(resource.attributes),
        security_attributes=security,
        semantic_attributes=thaw_json(resource.semantic_attributes),
        references=resource.references,
        provenance=resource.provenance,
        support_status=resource.support_status,
    )


class TestMalformedViews(unittest.TestCase):
    """A stored view that does not have the shape P3a writes is an error, never 'no rules'."""

    def group(self) -> Resource:
        text = group('  ingress {\n protocol = "tcp"\n from_port = 22\n to_port = 22\n }')
        return next(r for r in resources_of(text) if r.resource_type == "aws_security_group")

    def test_a_rule_view_missing_a_field_is_refused(self) -> None:
        security = thaw_json(self.group().security_attributes)
        del security["inline_rules"][0]["from_port"]
        with self.assertRaises(ViewError):
            views.rules_of(replace_security(self.group(), security))

    def test_a_rule_view_with_the_wrong_type_is_refused(self) -> None:
        for field, bad in (
            ("determinate", "yes"),
            ("ipv4_sources", "0.0.0.0/0"),
            ("from_port", "22"),
            ("origin", 5),
            ("direction", "SIDEWAYS"),
            ("problems", [1]),
        ):
            security = thaw_json(self.group().security_attributes)
            security["inline_rules"][0][field] = bad
            with self.subTest(field=field), self.assertRaises(ViewError):
                views.rules_of(replace_security(self.group(), security))

    def test_unknown_form_text_is_refused(self) -> None:
        security = thaw_json(self.group().security_attributes)
        security["forms"]["ingress"] = "sideways"
        with self.assertRaises(ViewError):
            views.index_rules([replace_security(self.group(), security)])

    def test_a_group_without_forms_is_refused_never_treated_as_absent(self) -> None:
        security = thaw_json(self.group().security_attributes)
        del security["forms"]
        with self.assertRaises(ViewError):
            views.index_rules([replace_security(self.group(), security)])


# ------------------------------------------------------------------------- equivalence (C-144)


def same_rule(
    testcase: unittest.TestCase, mine: views.Rule, theirs: p3a.CanonicalSecurityRule
) -> None:
    pairs = {
        "direction": (mine.direction, theirs.direction),
        "protocol": (mine.protocol, theirs.protocol),
        "from_port": (mine.from_port, theirs.from_port),
        "to_port": (mine.to_port, theirs.to_port),
        "ipv4_sources": (mine.ipv4_sources, theirs.ipv4_sources),
        "ipv6_sources": (mine.ipv6_sources, theirs.ipv6_sources),
        "source_security_groups": (mine.source_security_groups, theirs.source_security_groups),
        "prefix_list_ids": (mine.prefix_list_ids, theirs.prefix_list_ids),
        "self": (mine.self_reference, theirs.self_reference),
        "target": (mine.target, theirs.target_security_group),
        "origin": (mine.origin, theirs.origin),
        "description": (mine.description, theirs.description),
        "source_address": (mine.source_address, theirs.source_address),
        "determinate": (mine.determinate, theirs.determinate),
        "unsupported": (mine.unsupported, theirs.unsupported),
        "problems": (mine.problems, theirs.problems),
    }
    for name, (got, want) in pairs.items():
        testcase.assertEqual(got, want, f"{mine.source_address}: {name}")
    testcase.assertEqual(mine.rule_key(), theirs.rule_key())


def same_index(testcase: unittest.TestCase, resources: tuple[Resource, ...], label: str) -> None:
    mine = views.index_rules(resources)
    theirs = p3a.index_rules(resources)
    testcase.assertEqual(sorted(mine), sorted(theirs), label)
    for key in theirs:
        a, b = mine[key], theirs[key]
        for direction in ("ingress", "egress", "unresolved_direction"):
            ours, expected = getattr(a, direction), getattr(b, direction)
            testcase.assertEqual(len(ours), len(expected), f"{label} {key} {direction}")
            for left, right in zip(ours, expected, strict=True):
                same_rule(testcase, left, right)
        testcase.assertEqual(
            None if a.forms is None else dict(a.forms),
            None if b.inline_forms is None else dict(b.inline_forms),
            f"{label} {key} forms",
        )
        testcase.assertEqual(
            list(a.inline_indeterminate), list(b.inline_indeterminate), f"{label} {key} reasons"
        )


class TestEquivalenceOnFixtures(unittest.TestCase):
    def test_every_fixture_configuration(self) -> None:
        fixtures = fc.load_all()
        self.assertEqual(len(fixtures), fc.EXPECTED_FIXTURE_COUNT)
        folders = set()
        for fixture in fixtures.values():
            self.assertTrue(fixture.data["config"], fixture.folder)
            for key in ("config", "parent"):
                if fixture.data.get(key):
                    folders.add(fixture.data[key])  # fixtures share parents and configurations
        self.assertTrue({fx.data["config"] for fx in fixtures.values()} <= folders)
        for folder in sorted(folders):
            with self.subTest(folder=folder):
                outcome = normalize_directory(fc.REPO_ROOT / folder, None, now=NOW)
                same_index(self, outcome.resources, folder)


def generated_configuration(rng: random.Random) -> tuple[str, dict[str, tuple[bool, bool]]]:
    """A random configuration of security groups and rule resources, and for each rule resource the
    families it leaves unresolved, known from how it was written (not from the reader)."""
    protocols = ['"tcp"', '"TCP"', '"-1"', '"udp"', '"icmp"', '"6"', '"bogus"', "var.u"]
    ports = ["0", "22", "5432", "65535", "var.u", "300000"]
    v4 = [
        "[]",
        '["0.0.0.0/0"]',
        '["10.0.0.0/8"]',
        '["0.0.0.0/1", "128.0.0.0/1"]',
        "[var.u]",
        "var.u",
        '["bad"]',
        '["10.0.0.1/8"]',
    ]
    v6 = ["[]", '["::/0"]', "[var.u]", "var.u"]
    lines = ['variable "u" {}', 'variable "d" {\n  default = [22, 80]\n}']
    unresolved: dict[str, tuple[bool, bool]] = {}
    names = [f"g{i}" for i in range(rng.randint(1, 3))]
    for name in names:
        body = []
        for direction in ("ingress", "egress"):
            style = rng.choice(["absent", "empty", "blocks", "blocks", "dynamic", "unresolved"])
            if style == "empty":
                body.append(f"  {direction} = []")
            elif style == "unresolved":
                body.append(f"  {direction} = var.u")
            elif style == "dynamic":
                for_each = rng.choice(["var.u", "var.d"])
                value = f"{direction}.value"
                body.append(
                    f'  dynamic "{direction}" {{\n    for_each = {for_each}\n    content {{\n'
                    f'      protocol = "tcp"\n      from_port = {value}\n      to_port = {value}\n'
                    '      cidr_blocks = ["10.0.0.0/8"]\n    }\n  }'
                )
            elif style == "blocks":
                for _ in range(rng.randint(1, 3)):
                    block = [
                        f"  {direction} {{",
                        f"    protocol = {rng.choice(protocols)}",
                        f"    from_port = {rng.choice(ports)}",
                        f"    to_port = {rng.choice(ports)}",
                        f"    cidr_blocks = {rng.choice(v4)}",
                        f"    ipv6_cidr_blocks = {rng.choice(v6)}",
                    ]
                    if rng.random() < 0.15:
                        block.append('    prefix_list_ids = ["pl-1"]')
                    if rng.random() < 0.2:
                        block.append(f"    self = {rng.choice(['true', 'false', 'var.u'])}")
                    body.append("\n".join([*block, "  }"]))
        lines.append(f'resource "aws_security_group" "{name}" {{\n' + "\n".join(body) + "\n}")
    for index in range(rng.randint(0, 4)):
        target = rng.choice(
            [f"aws_security_group.{rng.choice(names)}.id"] * 3 + ['"sg-0123abcd"', "var.u"]
        )
        kind = rng.choice(['"ingress"', '"ingress"', '"egress"', "var.u", '"sideways"'])
        cidr4, cidr6 = rng.choice(v4), rng.choice(v6)
        extra = rng.choice(
            [
                "",
                "  source_security_group_id = var.u\n",
                '  prefix_list_ids = ["pl-1"]\n',
                "  self = true\n",
            ]
        )
        address = f"aws_security_group_rule.r{index}"
        lines.append(
            f'resource "aws_security_group_rule" "r{index}" {{\n  type = {kind}\n'
            f"  security_group_id = {target}\n  protocol = {rng.choice(protocols)}\n"
            f"  from_port = {rng.choice(ports)}\n  to_port = {rng.choice(ports)}\n"
            f"  cidr_blocks = {cidr4}\n  ipv6_cidr_blocks = {cidr6}\n{extra}}}"
        )
        unresolved[address] = ("var.u" in cidr4, "var.u" in cidr6)
    return "\n".join(lines) + "\n", unresolved


class TestEquivalenceOnGeneratedConfigurations(unittest.TestCase):
    SEEDS = (20261028, 1, 7, 424242, 99991)

    def test_generated_configurations_read_the_same(self) -> None:
        cases = 0
        for seed in self.SEEDS:
            rng = random.Random(seed)
            for number in range(60):
                text, _ = generated_configuration(rng)
                try:
                    resources = resources_of(text)
                except AssertionError:  # the generator wrote something Terraform-invalid
                    continue
                cases += 1
                same_index(self, resources, f"seed {seed} case {number}")
        self.assertGreater(cases, 150)

    def test_the_unresolved_flags_of_rule_resources_are_exact(self) -> None:
        checked = flagged = 0
        for seed in self.SEEDS:
            rng = random.Random(seed)
            for number in range(60):
                text, unresolved = generated_configuration(rng)
                try:
                    resources = resources_of(text)
                except AssertionError:
                    continue
                rules = {
                    rule.source_address: rule
                    for resource in resources
                    for rule in views.rules_of(resource)
                    if rule.origin == "RULE_RESOURCE"
                }
                for address, (want4, want6) in unresolved.items():
                    rule = rules[address]
                    with self.subTest(seed=seed, number=number, address=address):
                        self.assertEqual(
                            (rule.ipv4_unresolved, rule.ipv6_unresolved), (want4, want6)
                        )
                    checked += 1
                    flagged += want4 or want6
        self.assertGreater(checked, 100)
        self.assertGreater(flagged, 20)


class TestStoredShape(unittest.TestCase):
    """The reader follows the shape P3a stores, so the keys are pinned here."""

    def test_p3a_writes_the_keys_the_reader_reads(self) -> None:
        resource = next(
            r
            for r in resources_of(
                group('  ingress {\n protocol = "tcp"\n from_port = 1\n to_port = 1\n }')
            )
            if r.resource_type == "aws_security_group"
        )
        security = thaw_json(resource.security_attributes)
        self.assertEqual(sorted(security), ["forms", "inline_indeterminate", "inline_rules"])
        self.assertEqual(sorted(security["forms"]), ["egress", "ingress"])
        self.assertEqual(
            sorted(security["inline_rules"][0]),
            sorted(
                [
                    "direction",
                    "protocol",
                    "from_port",
                    "to_port",
                    "ipv4_sources",
                    "ipv6_sources",
                    "source_security_groups",
                    "prefix_list_ids",
                    "self",
                    "target_security_group",
                    "determinate",
                    "unsupported",
                    "problems",
                    "origin",
                    "description",
                ]
            ),
        )
        self.assertEqual(EGRESS, "EGRESS")


if __name__ == "__main__":
    unittest.main()
