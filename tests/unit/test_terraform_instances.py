"""Instance expansion and evaluated instances (P3a-2 step 4; Doc 04 §17; registry §2.3, §2.6;
C-84, C-100, C-105).

Expected addresses for string keys were printed by ``terraform plan`` of Terraform 1.15.8 (builtin
``terraform_data`` resources with ``for_each = toset([...])``, scratch directory outside the
repository, no credentials); they are marked ``plan``. The rules for ``count`` and ``for_each``
values were measured with ``terraform validate`` the same way and are marked ``validate``.
"""

from __future__ import annotations

import ast
import re
import tempfile
import unittest
from pathlib import Path

from core.terraform_model import instances as instances_module
from core.terraform_model.config import (
    DiagnosticSeverity,
    ParsedConfiguration,
    ParseStatus,
    load_configuration,
)
from core.terraform_model.evaluate import Scope
from core.terraform_model.instances import (
    MAX_DYNAMIC_BLOCKS,
    MAX_INSTANCES_PER_RESOURCE,
    ArgumentForm,
    EvaluatedInstance,
    Expansion,
    ResourceRuntime,
    format_key,
    instance_address,
    is_print,
    quote_key,
)
from core.terraform_model.print_table import PRINTABLE, SOURCE_SHA256, SOURCE_UNICODE_VERSION
from core.terraform_model.values import (
    NULL,
    Known,
    Ref,
    Unknown,
    Unsupported,
    Value,
    from_json,
    known_object,
    known_tuple,
)

ROOT = Path(__file__).resolve().parents[2]
BS = chr(92)  # a backslash, so that the expected text reads as the plan printed it
U = Unknown("variable.no_value")


def tup(*items: object) -> Value:
    return known_tuple(
        i if isinstance(i, Known | Unknown | Unsupported | Ref) else from_json(i) for i in items
    )


class Resolver:
    def __init__(self) -> None:
        self.runtimes: dict[tuple[str, str, str], ResourceRuntime] = {}

    def resource(self, kind: str, type_: str, name: str) -> ResourceRuntime | None:
        return self.runtimes.get((kind, type_, name))


class Built:
    def __init__(self, parsed: ParsedConfiguration, scope: Scope, resolver: Resolver) -> None:
        self.parsed = parsed
        self.scope = scope
        self.resolver = resolver

    def expand(self, type_: str, name: str, kind: str = "resource") -> Expansion:
        return self.resolver.runtimes[(kind, type_, name)].expand()

    def one(self, type_: str, name: str) -> EvaluatedInstance:
        expansion = self.expand(type_, name)
        assert len(expansion.instances) == 1, expansion
        return expansion.instances[0]


def build(text: str, variables: dict[str, Value] | None = None) -> Built:
    with tempfile.TemporaryDirectory() as directory:
        (Path(directory) / "main.tf").write_text(text, encoding="utf-8", newline="\n")
        outcome = load_configuration(Path(directory))
    assert outcome.status is ParseStatus.OK, outcome.diagnostics
    parsed = outcome.configuration
    assert parsed is not None
    resolver = Resolver()
    scope = Scope(
        variables=variables or {},
        locals={name: decl.attribute.expr for name, decl in parsed.locals.items()},
        resources=resolver,
    )
    for (type_, name), decl in parsed.resources.items():
        resolver.runtimes[("resource", type_, name)] = ResourceRuntime(decl, scope)
    for (type_, name), decl in parsed.data_sources.items():
        resolver.runtimes[("data", type_, name)] = ResourceRuntime(decl, scope)
    return Built(parsed, scope, resolver)


def addresses(expansion: Expansion) -> list[str]:
    return [i.address for i in expansion.instances]


class TestCanonicalKeys(unittest.TestCase):
    """The expected text is what ``terraform plan`` printed for the same key (plan)."""

    def test_keys_as_terraform_prints_them(self) -> None:
        cases = [
            ("plain", '"plain"'),
            ("", '""'),
            ("a b", '"a b"'),
            ('quo"te', '"quo' + BS + '"te"'),
            ("back" + BS + "slash", '"back' + BS + BS + 'slash"'),
            ("tab\there", '"tab' + BS + 'there"'),
            ("nl\nx", '"nl' + BS + 'nx"'),
            ("cr\rx", '"cr' + BS + 'rx"'),
            ("dollar$", '"dollar$"'),
            ("dollar${x", '"dollar$${x"'),
            ("pct%", '"pct%"'),
            ("pct%{x", '"pct%%{x"'),
            ("$", '"$"'),
            ("a$", '"a$"'),
            ("$$", '"$$"'),
            ("é", '"é"'),
            (chr(0x1F600), '"' + chr(0x1F600) + '"'),
            (chr(0xA0), '"' + BS + 'u00a0"'),
            (chr(0x200B), '"' + BS + 'u200b"'),
            (chr(0x85), '"' + BS + 'u0085"'),
            (chr(0x7F), '"' + BS + 'u007f"'),
            (chr(1), '"' + BS + 'u0001"'),
            (chr(0x1C89), '"' + BS + 'u1c89"'),  # assigned in Unicode 16: not printable for Go 15.0
            (chr(0x2EBF0), '"' + BS + 'U0002ebf0"'),  # assigned in Unicode 15.1
            (chr(0xFFFF), '"' + BS + 'uffff"'),
            (chr(0x378), '"' + BS + 'u0378"'),
            (chr(0xE000), '"' + BS + 'ue000"'),
            (chr(0x2028), '"' + BS + 'u2028"'),
            (chr(0x3000), '"' + BS + 'u3000"'),
            (chr(0xAD), '"' + BS + 'u00ad"'),
            (chr(0xE0001), '"' + BS + 'U000e0001"'),
        ]
        for key, expected in cases:
            with self.subTest(key=key.encode("unicode_escape")):
                self.assertEqual(quote_key(key), expected)

    def test_format_and_address(self) -> None:
        self.assertEqual(format_key(0), "[0]")
        self.assertEqual(format_key(12), "[12]")
        self.assertEqual(format_key("a"), '["a"]')
        self.assertEqual(instance_address("resource", "aws_vpc", "main"), "aws_vpc.main")
        self.assertEqual(instance_address("resource", "aws_vpc", "main", 2), "aws_vpc.main[2]")
        self.assertEqual(instance_address("resource", "aws_vpc", "main", "x"), 'aws_vpc.main["x"]')
        self.assertEqual(instance_address("data", "aws_ami", "x"), "data.aws_ami.x")
        self.assertEqual(instance_address("data", "aws_ami", "x", "k"), 'data.aws_ami.x["k"]')

    def test_the_address_of_an_instance_with_a_special_key(self) -> None:
        built = build(
            'resource "terraform_data" "x" {\n  for_each = toset(["a\\"b", "c${"$"}{d"])\n}\n'
        )
        found = addresses(built.expand("terraform_data", "x"))
        self.assertEqual(
            found,
            ["terraform_data.x[" + '"a' + BS + '"b"]', 'terraform_data.x["c$${d"]'],
        )

    def test_the_print_table_is_the_unicode_15_table(self) -> None:
        self.assertEqual(SOURCE_UNICODE_VERSION, "15.0.0")
        self.assertRegex(SOURCE_SHA256, r"^[0-9a-f]{64}$")
        generator = (ROOT / "scripts" / "generate_print_table.py").read_text(encoding="utf-8")
        self.assertIn(f'EXPECTED_SHA256 = "{SOURCE_SHA256}"', generator)
        previous = -1
        for low, high in PRINTABLE:
            self.assertLessEqual(low, high)
            self.assertGreater(low, previous + 1)  # sorted, disjoint and merged
            previous = high
        self.assertLessEqual(previous, 0x10FFFF)

    def test_characters_by_category(self) -> None:
        for char in (
            "a",
            "Z",
            "0",
            " ",
            "~",
            "é",
            chr(0x4E2D),
            chr(0x1F600),
            chr(0x300),
            chr(0x20AC),
        ):
            self.assertTrue(is_print(ord(char)), hex(ord(char)))
        for code in (
            0,
            9,
            10,
            0x1F,
            0x7F,
            0x80,
            0xA0,
            0xAD,
            0x200B,
            0x2028,
            0x2029,
            0x3000,
            0xD800,
            0xE000,
            0xFFFE,
            0x10FFFF,
        ):
            self.assertFalse(is_print(code), hex(code))

    def test_the_table_equals_the_interpreters_when_it_has_the_same_unicode_version(self) -> None:
        import sys
        import unicodedata

        if unicodedata.unidata_version != SOURCE_UNICODE_VERSION:
            self.skipTest(f"this interpreter has Unicode {unicodedata.unidata_version}")
        for code in range(sys.maxunicode + 1):
            if is_print(code) != chr(code).isprintable():
                self.fail(f"U+{code:04X} differs from str.isprintable")

    def test_the_generator_reads_first_last_ranges_and_categories(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "generate_print_table", ROOT / "scripts" / "generate_print_table.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        text = "\n".join(
            [
                "0041;LATIN CAPITAL LETTER A;Lu;0;L;;;;;N;;;;0061;",
                "0085;<control>;Cc;0;B;;;;;N;;;;;",
                "00A0;NO-BREAK SPACE;Zs;0;CS;<noBreak> 0020;;;;N;NON-BREAKING SPACE;;;;",
                "00AD;SOFT HYPHEN;Cf;0;BN;;;;;N;;;;;",
                "3400;<CJK Ideograph Extension A, First>;Lo;0;L;;;;;N;;;;;",
                "4DBF;<CJK Ideograph Extension A, Last>;Lo;0;L;;;;;N;;;;;",
                "D800;<Non Private Use High Surrogate, First>;Cs;0;L;;;;;N;;;;;",
                "DB7F;<Non Private Use High Surrogate, Last>;Cs;0;L;;;;;N;;;;;",
                "20AC;EURO SIGN;Sc;0;ET;;;;;N;;;;;",
            ]
        )
        points = module.printable_points(text)
        self.assertEqual(points, {0x20, 0x41, 0x20AC, *range(0x3400, 0x4DC0)})
        self.assertEqual(module.to_ranges({1, 2, 3, 7}), [(1, 3), (7, 7)])


class TestSingleInstance(unittest.TestCase):
    def test_no_count_and_no_for_each(self) -> None:
        built = build('resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n')
        expansion = built.expand("aws_vpc", "main")
        self.assertIsNone(expansion.indeterminate)
        (instance,) = expansion.instances
        self.assertEqual(
            (instance.address, instance.kind, instance.type, instance.name, instance.key),
            ("aws_vpc.main", "resource", "aws_vpc", "main", None),
        )
        self.assertTrue(instance.determinate)
        self.assertEqual(instance.arguments["cidr_block"].value, Known("10.0.0.0/16"))
        self.assertEqual(instance.arguments["cidr_block"].form, ArgumentForm.ATTRIBUTE)
        self.assertEqual(instance.source_range.start_line, 1)

    def test_a_data_source_has_the_data_prefix(self) -> None:
        built = build('data "aws_ami" "x" {\n  owners = ["self"]\n}\n')
        (instance,) = built.expand("aws_ami", "x", "data").instances
        self.assertEqual((instance.address, instance.kind), ("data.aws_ami.x", "data"))


class TestCount(unittest.TestCase):
    def counted(self, expression: str, variables: dict[str, Value] | None = None) -> Expansion:
        text = f'resource "aws_subnet" "s" {{\n  count = {expression}\n  tag = count.index\n}}\n'
        return build(text, variables).expand("aws_subnet", "s")

    def test_instances_and_their_index(self) -> None:
        expansion = self.counted("3")
        self.assertEqual(
            addresses(expansion), ["aws_subnet.s[0]", "aws_subnet.s[1]", "aws_subnet.s[2]"]
        )
        self.assertEqual([i.key for i in expansion.instances], [0, 1, 2])
        self.assertEqual(
            [i.arguments["tag"].value for i in expansion.instances], [Known(0), Known(1), Known(2)]
        )

    def test_zero_gives_no_instances_and_is_not_indeterminate(self) -> None:
        expansion = self.counted("0")
        self.assertEqual((expansion.instances, expansion.indeterminate), ((), None))

    def test_accepted_values(self) -> None:
        # validate: `count = "2"` is accepted (the string converts); an expression is fine
        self.assertEqual(len(self.counted('"2"').instances), 2)
        self.assertEqual(len(self.counted("1 + 1").instances), 2)
        self.assertEqual(len(self.counted("var.n", {"n": Known(4)}).instances), 4)
        self.assertEqual(len(self.counted("length(var.l)", {"l": tup(1, 2, 3)}).instances), 3)
        self.assertEqual(len(self.counted("2.0").instances), 2)

    def test_values_terraform_rejects_are_unsupported(self) -> None:
        # validate: negative, fractional, null, bool and non-numeric strings are errors
        cases = [
            ("-1", "count.invalid"),
            ("1.5", "count.invalid"),
            ("true", "count.invalid"),
            ('"abc"', "count.invalid"),
            ("[1]", "count.invalid"),
            ("null", "count.null"),
        ]
        for expression, reason in cases:
            with self.subTest(expression=expression):
                expansion = self.counted(expression)
                self.assertEqual(expansion.instances, ())
                assert expansion.indeterminate is not None
                self.assertEqual(expansion.indeterminate.reason, Unsupported(reason))
                self.assertFalse(expansion.indeterminate.determinate)

    def test_an_unknown_count_makes_the_resource_indeterminate(self) -> None:
        expansion = self.counted("var.n", {"n": U})
        self.assertEqual(expansion.instances, ())
        resource = expansion.indeterminate
        assert resource is not None
        self.assertEqual(resource.reason, Unknown("expansion.count_unknown:variable.no_value"))
        self.assertEqual(
            (resource.address, resource.kind, resource.type, resource.name),
            ("aws_subnet.s", "resource", "aws_subnet", "s"),
        )
        self.assertFalse(resource.determinate)

    def test_an_unsupported_count_is_unsupported(self) -> None:
        expansion = self.counted("abs(1)")
        assert expansion.indeterminate is not None
        self.assertEqual(
            expansion.indeterminate.reason, Unsupported("function.not_implemented:abs")
        )

    def test_the_limit_per_resource(self) -> None:
        at_limit = self.counted(str(MAX_INSTANCES_PER_RESOURCE))
        self.assertEqual(len(at_limit.instances), MAX_INSTANCES_PER_RESOURCE)
        over = self.counted(str(MAX_INSTANCES_PER_RESOURCE + 1))
        self.assertEqual(over.instances, ())
        assert over.indeterminate is not None
        self.assertEqual(over.indeterminate.reason, Unsupported("limit.instances_per_resource"))
        self.assertEqual(
            [(d.severity, d.code) for d in over.indeterminate.diagnostics],
            [(DiagnosticSeverity.UNSUPPORTED, "limit.instances_per_resource")],
        )

    def test_count_and_for_each_together_are_invalid(self) -> None:
        # validate: "Invalid combination of "count" and "for_each""
        built = build('resource "aws_vpc" "v" {\n  count = 1\n  for_each = toset(["a"])\n}\n')
        expansion = built.expand("aws_vpc", "v")
        self.assertEqual(expansion.instances, ())
        assert expansion.indeterminate is not None
        self.assertEqual(
            [(d.severity, d.code) for d in expansion.indeterminate.diagnostics],
            [(DiagnosticSeverity.INVALID, "eval.count_and_for_each")],
        )

    def test_each_inside_count_is_invalid(self) -> None:
        built = build('resource "aws_vpc" "v" {\n  count = 1\n  name = each.key\n}\n')
        (instance,) = built.expand("aws_vpc", "v").instances
        self.assertIsInstance(instance.arguments["name"].value, Unsupported)
        self.assertEqual([d.code for d in built.scope.diagnostics], ["eval.each_context"])


class TestForEach(unittest.TestCase):
    def each(self, expression: str, variables: dict[str, Value] | None = None) -> Expansion:
        text = (
            'resource "aws_sg" "g" {\n'
            f"  for_each = {expression}\n"
            '  name = "n-${each.key}"\n'
            "  value = each.value\n"
            "}\n"
        )
        return build(text, variables).expand("aws_sg", "g")

    def test_set_of_strings(self) -> None:
        expansion = self.each('toset(["b", "a"])')
        self.assertEqual(addresses(expansion), ['aws_sg.g["a"]', 'aws_sg.g["b"]'])
        self.assertEqual([i.key for i in expansion.instances], ["a", "b"])
        self.assertEqual(
            [i.arguments["name"].value for i in expansion.instances], [Known("n-a"), Known("n-b")]
        )
        self.assertEqual(
            [i.arguments["value"].value for i in expansion.instances], [Known("a"), Known("b")]
        )

    def test_map_and_object(self) -> None:
        expansion = self.each("{ x = 1, y = { z = 2 } }")
        self.assertEqual(addresses(expansion), ['aws_sg.g["x"]', 'aws_sg.g["y"]'])
        self.assertEqual(expansion.instances[0].arguments["value"].value, Known(1))
        self.assertEqual(
            expansion.instances[1].arguments["value"].value, known_object({"z": Known(2)})
        )

    def test_the_order_of_the_source_never_changes_addresses_or_values(self) -> None:
        one = self.each("{ b = 1, a = 2 }")
        two = self.each("{ a = 2, b = 1 }")
        self.assertEqual(addresses(one), addresses(two))
        self.assertEqual([i.arguments for i in one.instances], [i.arguments for i in two.instances])
        three = self.each('toset(["a", "b"])')
        four = self.each('toset(["b", "a", "b"])')
        self.assertEqual(addresses(three), addresses(four))

    def test_an_empty_collection_has_no_instances(self) -> None:
        for expression in ("{}", "toset([])"):
            expansion = self.each(expression)
            self.assertEqual((expansion.instances, expansion.indeterminate), ((), None))

    def test_map_values_may_be_null_or_unknown(self) -> None:
        # validate: `{ a = null }` and `{ a = { b = 1 } }` are accepted. Keys decide the instances,
        # so an unknown value is an instance whose each.value is unknown (Terraform expands it).
        expansion = self.each("{ a = null, b = var.u }", {"u": U})
        self.assertEqual(addresses(expansion), ['aws_sg.g["a"]', 'aws_sg.g["b"]'])
        self.assertEqual(expansion.instances[0].arguments["value"].value, NULL)
        self.assertEqual(expansion.instances[1].arguments["value"].value, U)

    def test_values_terraform_rejects_are_unsupported(self) -> None:
        # validate: a list, null, a bool, a string and a set of numbers are errors
        cases = [
            ('["a"]', "for_each.list"),
            ("null", "for_each.null"),
            ("true", "for_each.type"),
            ('"abc"', "for_each.type"),
            ("1", "for_each.type"),
            ("toset([1, 2])", "for_each.set_element"),
            ("toset([[1]])", "for_each.set_element"),
        ]
        for expression, reason in cases:
            with self.subTest(expression=expression):
                expansion = self.each(expression)
                assert expansion.indeterminate is not None
                self.assertEqual(expansion.indeterminate.reason, Unsupported(reason))
                self.assertEqual(expansion.instances, ())

    def test_mixed_set_elements_are_unified_to_strings(self) -> None:
        expansion = self.each('toset(["a", 1])')
        self.assertEqual(addresses(expansion), ['aws_sg.g["1"]', 'aws_sg.g["a"]'])

    def test_an_unknown_for_each_makes_the_resource_indeterminate(self) -> None:
        expansion = self.each("var.m", {"m": U})
        assert expansion.indeterminate is not None
        self.assertEqual(
            expansion.indeterminate.reason, Unknown("expansion.for_each_unknown:variable.no_value")
        )
        self.assertEqual(expansion.instances, ())

    def test_a_set_with_an_unknown_element_is_indeterminate(self) -> None:
        expansion = self.each("toset(var.l)", {"l": tup("a", U)})
        assert expansion.indeterminate is not None
        self.assertEqual(
            expansion.indeterminate.reason, Unknown("expansion.for_each_unknown:variable.no_value")
        )

    def test_a_set_of_references_is_indeterminate(self) -> None:
        text = (
            'resource "aws_vpc" "v" {}\n'
            'resource "aws_sg" "g" {\n  for_each = toset([aws_vpc.v.id])\n}\n'
        )
        expansion = build(text).expand("aws_sg", "g")
        assert expansion.indeterminate is not None
        self.assertEqual(
            expansion.indeterminate.reason,
            Unknown("expansion.for_each_unknown:ref.derived:aws_vpc.v.id"),
        )

    def test_a_key_with_a_lone_surrogate_is_unsupported(self) -> None:
        expansion = self.each("toset(var.l)", {"l": tup(chr(0xD800))})
        assert expansion.indeterminate is not None
        self.assertEqual(expansion.indeterminate.reason, Unsupported("expansion.key_surrogate"))

    def test_the_limit_per_resource(self) -> None:
        keys = {f"k{i:04d}": Known(i) for i in range(MAX_INSTANCES_PER_RESOURCE + 1)}
        at_limit = dict(list(keys.items())[:MAX_INSTANCES_PER_RESOURCE])
        self.assertEqual(
            len(self.each("var.m", {"m": known_object(at_limit)}).instances),
            MAX_INSTANCES_PER_RESOURCE,
        )
        over = self.each("var.m", {"m": known_object(keys)})
        assert over.indeterminate is not None
        self.assertEqual(over.indeterminate.reason, Unsupported("limit.instances_per_resource"))
        sets_over = self.each("toset(var.l)", {"l": tup(*keys)})
        assert sets_over.indeterminate is not None
        self.assertEqual(
            sets_over.indeterminate.reason, Unsupported("limit.instances_per_resource")
        )


class TestArgumentForms(unittest.TestCase):
    """Registry §2.6 (C-84): the form of every argument name is kept exactly."""

    def group(self, body: str) -> EvaluatedInstance:
        return build(f'resource "aws_security_group" "g" {{\n{body}\n}}\n').one(
            "aws_security_group", "g"
        )

    def test_attribute_blocks_and_absent(self) -> None:
        instance = self.group(
            '  name = "g"\n'
            "  egress = []\n"
            "  ingress {\n"
            "    from_port = 22\n"
            '    protocol = "tcp"\n'
            "  }\n"
            "  ingress {\n"
            "    from_port = 80\n"
            "  }\n"
        )
        self.assertEqual(instance.arguments["name"].form, ArgumentForm.ATTRIBUTE)
        egress = instance.arguments["egress"]
        self.assertEqual(
            (egress.form, egress.value, egress.blocks), (ArgumentForm.ATTRIBUTE, Known(()), ())
        )
        ingress = instance.arguments["ingress"]
        self.assertEqual(ingress.form, ArgumentForm.BLOCKS)
        self.assertIsNone(ingress.value)
        self.assertEqual(
            [b.arguments["from_port"].value for b in ingress.blocks], [Known(22), Known(80)]
        )
        self.assertEqual(ingress.blocks[0].arguments["protocol"].value, Known("tcp"))
        self.assertFalse(any(b.from_dynamic for b in ingress.blocks))
        self.assertNotIn("tags", instance.arguments)  # absent stays absent

    def test_explicit_empty_differs_from_absent_and_from_blocks(self) -> None:
        empty = self.group("  egress = []")
        absent = self.group('  name = "x"')
        self.assertEqual(empty.arguments["egress"].value, Known(()))
        self.assertNotIn("egress", absent.arguments)

    def test_dynamic_blocks_have_their_own_form(self) -> None:
        instance = self.group(
            '  dynamic "ingress" {\n'
            "    for_each = [22, 80]\n"
            "    content {\n"
            "      from_port = ingress.value\n"
            "    }\n"
            "  }\n"
        )
        ingress = instance.arguments["ingress"]
        self.assertEqual(ingress.form, ArgumentForm.DYNAMIC)
        self.assertEqual(
            [b.arguments["from_port"].value for b in ingress.blocks], [Known(22), Known(80)]
        )
        self.assertTrue(all(b.from_dynamic for b in ingress.blocks))
        self.assertTrue(instance.determinate)

    def test_static_and_dynamic_blocks_of_one_name_are_mixed(self) -> None:
        # C-100: terraform accepts an ingress block together with a dynamic "ingress" block
        instance = self.group(
            "  ingress {\n    from_port = 1\n  }\n"
            '  dynamic "ingress" {\n'
            "    for_each = [2, 3]\n"
            "    content {\n"
            "      from_port = ingress.value\n"
            "    }\n"
            "  }\n"
            "  ingress {\n    from_port = 4\n  }\n"
        )
        ingress = instance.arguments["ingress"]
        self.assertEqual(ingress.form, ArgumentForm.MIXED)
        self.assertEqual(
            [b.arguments["from_port"].value for b in ingress.blocks],
            [Known(i) for i in (1, 2, 3, 4)],
        )
        self.assertEqual([b.from_dynamic for b in ingress.blocks], [False, True, True, False])

    def test_an_attribute_and_a_block_of_one_name_are_invalid_and_never_resolved(self) -> None:
        # C-100: Terraform rejects `ingress = []` together with an ingress block or a dynamic one
        for block in (
            "  ingress {\n    from_port = 1\n  }",
            '  dynamic "ingress" {\n    for_each = []\n    content {}\n  }',
        ):
            with self.subTest(block=block[:20]):
                instance = self.group("  ingress = []\n" + block)
                self.assertNotIn("ingress", instance.arguments)
                self.assertEqual(
                    [(d.severity, d.code) for d in instance.diagnostics],
                    [(DiagnosticSeverity.INVALID, "eval.attribute_and_block")],
                )

    def test_nested_blocks_keep_their_forms(self) -> None:
        instance = self.group("  rule {\n    inner = []\n    thing {\n      a = 1\n    }\n  }")
        (rule,) = instance.arguments["rule"].blocks
        self.assertEqual(rule.arguments["inner"].form, ArgumentForm.ATTRIBUTE)
        self.assertEqual(rule.arguments["thing"].form, ArgumentForm.BLOCKS)

    def test_block_labels(self) -> None:
        instance = self.group('  provisioner_like "a" "b" {\n    x = 1\n  }')
        (block,) = instance.arguments["provisioner_like"].blocks
        self.assertEqual(block.labels, (Known("a"), Known("b")))

    def test_argument_evaluation_uses_the_instances_context(self) -> None:
        text = (
            'resource "aws_x" "x" {\n'
            "  count = 2\n"
            "  n = count.index\n"
            "  b {\n"
            "    i = count.index\n"
            "  }\n"
            "}\n"
        )
        first, second = build(text).expand("aws_x", "x").instances
        self.assertEqual(
            (first.arguments["n"].value, second.arguments["n"].value), (Known(0), Known(1))
        )
        self.assertEqual(second.arguments["b"].blocks[0].arguments["i"].value, Known(1))


class TestDynamicBlocks(unittest.TestCase):
    def blocks(self, dynamic: str, variables: dict[str, Value] | None = None) -> EvaluatedInstance:
        text = f'resource "aws_x" "x" {{\n{dynamic}\n}}\n'
        return build(text, variables).one("aws_x", "x")

    def test_a_list(self) -> None:
        instance = self.blocks(
            '  dynamic "rule" {\n'
            '    for_each = ["a", "b"]\n'
            "    content {\n"
            "      k = rule.key\n"
            "      v = rule.value\n"
            "    }\n"
            "  }"
        )
        rule = instance.arguments["rule"]
        self.assertEqual(
            [(b.arguments["k"].value, b.arguments["v"].value) for b in rule.blocks],
            [(Known(0), Known("a")), (Known(1), Known("b"))],
        )

    def test_a_map_and_a_set(self) -> None:
        instance = self.blocks(
            '  dynamic "m" {\n'
            "    for_each = { y = 1, x = 2 }\n"
            "    content {\n"
            "      k = m.key\n"
            "      v = m.value\n"
            "    }\n"
            "  }\n"
            '  dynamic "s" {\n'
            '    for_each = toset(["q", "p"])\n'
            "    content {\n"
            "      k = s.key\n"
            "      v = s.value\n"
            "    }\n"
            "  }"
        )
        self.assertEqual(
            [
                (b.arguments["k"].value, b.arguments["v"].value)
                for b in instance.arguments["m"].blocks
            ],
            [(Known("x"), Known(2)), (Known("y"), Known(1))],
        )
        self.assertEqual(
            [
                (b.arguments["k"].value, b.arguments["v"].value)
                for b in instance.arguments["s"].blocks
            ],
            [(Known("p"), Known("p")), (Known("q"), Known("q"))],
        )

    def test_the_iterator_argument(self) -> None:
        instance = self.blocks(
            '  dynamic "rule" {\n'
            "    for_each = [7]\n"
            "    iterator = it\n"
            "    content {\n"
            "      v = it.value\n"
            "    }\n"
            "  }"
        )
        self.assertEqual(instance.arguments["rule"].blocks[0].arguments["v"].value, Known(7))

    def test_labels(self) -> None:
        instance = self.blocks(
            '  dynamic "rule" {\n'
            '    for_each = ["a"]\n'
            '    labels = ["x", rule.value]\n'
            "    content {}\n"
            "  }"
        )
        (block,) = instance.arguments["rule"].blocks
        self.assertEqual(block.labels, (Known("x"), Known("a")))
        self.assertEqual(block.type, "rule")

    def test_nested_dynamic_blocks(self) -> None:
        instance = self.blocks(
            '  dynamic "outer" {\n    for_each = [1, 2]\n    content {\n'
            '      dynamic "inner" {\n'
            '        for_each = ["a", "b"]\n'
            "        content {\n"
            '          pair = "${outer.value}${inner.value}"\n'
            "        }\n"
            "      }\n"
            "    }\n  }"
        )
        outer = instance.arguments["outer"].blocks
        self.assertEqual(len(outer), 2)
        pairs = [[b.arguments["pair"].value for b in o.arguments["inner"].blocks] for o in outer]
        self.assertEqual(pairs, [[Known("1a"), Known("1b")], [Known("2a"), Known("2b")]])

    def test_dynamic_inside_a_counted_resource(self) -> None:
        text = (
            'resource "aws_x" "x" {\n'
            "  count = 2\n"
            '  dynamic "r" {\n'
            "    for_each = [10]\n"
            "    content {\n"
            "      v = r.value + count.index\n"
            "    }\n"
            "  }\n"
            "}\n"
        )
        first, second = build(text).expand("aws_x", "x").instances
        self.assertEqual(first.arguments["r"].blocks[0].arguments["v"].value, Known(10))
        self.assertEqual(second.arguments["r"].blocks[0].arguments["v"].value, Known(11))

    def test_an_unknown_for_each_is_indeterminate_and_recorded_under_the_name(self) -> None:
        instance = self.blocks(
            '  dynamic "rule" {\n'
            "    for_each = var.rules\n"
            "    content {\n"
            "      v = 1\n"
            "    }\n"
            "  }\n"
            '  name = "n"',
            {"rules": U},
        )
        rule = instance.arguments["rule"]
        self.assertEqual(
            (rule.form, rule.blocks, rule.indeterminate), (ArgumentForm.DYNAMIC, (), (U,))
        )
        self.assertFalse(instance.determinate)
        self.assertEqual(instance.arguments["name"].value, Known("n"))

    def test_an_indeterminate_group_among_static_blocks(self) -> None:
        instance = self.blocks(
            "  rule {\n"
            "    v = 1\n"
            "  }\n"
            '  dynamic "rule" {\n'
            "    for_each = var.rules\n"
            "    content {}\n"
            "  }",
            {"rules": U},
        )
        rule = instance.arguments["rule"]
        self.assertEqual(rule.form, ArgumentForm.MIXED)
        self.assertEqual(len(rule.blocks), 1)
        self.assertEqual(rule.indeterminate, (U,))

    def test_a_set_with_an_unknown_element_is_indeterminate(self) -> None:
        instance = self.blocks(
            '  dynamic "rule" {\n    for_each = toset(var.l)\n    content {}\n  }',
            {"l": tup("a", U)},
        )
        self.assertEqual(instance.arguments["rule"].indeterminate, (U,))

    def test_a_list_with_an_unknown_element_still_expands(self) -> None:
        instance = self.blocks(
            '  dynamic "rule" {\n'
            "    for_each = var.l\n"
            "    content {\n"
            "      v = rule.value\n"
            "    }\n"
            "  }",
            {"l": tup("a", U)},
        )
        values = [b.arguments["v"].value for b in instance.arguments["rule"].blocks]
        self.assertEqual(values, [Known("a"), U])
        self.assertTrue(instance.determinate)

    def test_for_each_values_that_are_not_collections_are_unsupported(self) -> None:
        for expression in ('"abc"', "1", "null", "true"):
            with self.subTest(expression=expression):
                instance = self.blocks(
                    f'  dynamic "r" {{\n    for_each = {expression}\n    content {{}}\n  }}'
                )
                self.assertEqual(
                    instance.arguments["r"].indeterminate, (Unsupported("dynamic.for_each"),)
                )

    def test_malformed_dynamic_blocks_are_unsupported_and_recorded(self) -> None:
        cases = [
            '  dynamic "r" {\n    content {}\n  }',  # no for_each
            '  dynamic "r" {\n    for_each = []\n  }',  # no content
            (
                '  dynamic "r" {\n' "    for_each = []\n" "    content {}\n" "    other = 1\n" "  }"
            ),  # unknown argument
            (
                '  dynamic "r" {\n'
                "    for_each = []\n"
                "    content {}\n"
                "    content {}\n"
                "  }"
            ),  # two contents
            (
                '  dynamic "r" {\n'
                "    for_each = []\n"
                '    iterator = "x"\n'
                "    content {}\n"
                "  }"
            ),  # iterator not a name
        ]
        for dynamic in cases:
            with self.subTest(dynamic=dynamic[:40]):
                instance = self.blocks(dynamic)
                self.assertEqual(
                    instance.arguments["r"].indeterminate, (Unsupported("dynamic.malformed"),)
                )
                self.assertEqual(
                    [(d.severity, d.code) for d in instance.diagnostics],
                    [(DiagnosticSeverity.UNSUPPORTED_CONSTRUCT, "eval.dynamic_malformed")],
                )
                self.assertFalse(instance.determinate)

    def test_the_limit_on_expanded_blocks(self) -> None:
        text = '  dynamic "r" {\n    for_each = var.l\n    content {}\n  }'
        at_limit = self.blocks(text, {"l": tup(*range(MAX_DYNAMIC_BLOCKS))})
        self.assertEqual(len(at_limit.arguments["r"].blocks), MAX_DYNAMIC_BLOCKS)
        over = self.blocks(text, {"l": tup(*range(MAX_DYNAMIC_BLOCKS + 1))})
        self.assertEqual(over.arguments["r"].indeterminate, (Unsupported("limit.dynamic_blocks"),))


class TestReferencesBetweenResources(unittest.TestCase):
    def test_id_and_configured_arguments(self) -> None:
        text = (
            'resource "aws_security_group" "app" {\n  name = "app"\n}\n'
            'resource "aws_security_group" "db" {\n'
            '  name = "db-${aws_security_group.app.name}"\n'
            "  peer = aws_security_group.app.id\n"
            "  arn_of = aws_security_group.app.arn\n"
            "}\n"
        )
        instance = build(text).one("aws_security_group", "db")
        self.assertEqual(instance.arguments["name"].value, Known("db-app"))
        self.assertEqual(instance.arguments["peer"].value, Ref("aws_security_group.app", "id"))
        self.assertEqual(instance.arguments["arn_of"].value, Unknown("resource.computed:arn"))

    def test_references_to_counted_and_keyed_instances(self) -> None:
        text = (
            'resource "aws_subnet" "s" {\n  count = 2\n  cidr = "10.0.${count.index}.0/24"\n}\n'
            'resource "aws_sg" "g" {\n  for_each = toset(["a"])\n}\n'
            'resource "aws_instance" "i" {\n'
            "  first = aws_subnet.s[0].id\n"
            "  cidrs = aws_subnet.s[*].cidr\n"
            "  all_ids = aws_subnet.s[*].id\n"
            '  keyed = aws_sg.g["a"].id\n  last = aws_subnet.s[length(aws_subnet.s) - 1].cidr\n}\n'
        )
        instance = build(text).one("aws_instance", "i")
        self.assertEqual(instance.arguments["first"].value, Ref("aws_subnet.s[0]", "id"))
        self.assertEqual(instance.arguments["cidrs"].value, tup("10.0.0.0/24", "10.0.1.0/24"))
        self.assertEqual(
            instance.arguments["all_ids"].value,
            tup(Ref("aws_subnet.s[0]", "id"), Ref("aws_subnet.s[1]", "id")),
        )
        self.assertEqual(instance.arguments["keyed"].value, Ref('aws_sg.g["a"]', "id"))
        self.assertEqual(instance.arguments["last"].value, Known("10.0.1.0/24"))

    def test_a_missing_instance_key_is_unsupported(self) -> None:
        text = (
            'resource "aws_subnet" "s" {\n  count = 1\n}\n'
            'resource "aws_instance" "i" {\n  x = aws_subnet.s[5].id\n}\n'
        )
        self.assertIsInstance(
            build(text).one("aws_instance", "i").arguments["x"].value, Unsupported
        )

    def test_a_reference_to_an_indeterminate_resource_is_unknown(self) -> None:
        text = (
            'resource "aws_subnet" "s" {\n  count = var.n\n}\n'
            'resource "aws_instance" "i" {\n'
            "  x = aws_subnet.s[0].id\n"
            "  y = aws_subnet.s[*].id\n"
            "  z = aws_subnet.s\n"
            "}\n"
        )
        instance = build(text, {"n": U}).one("aws_instance", "i")
        expected = Unknown("expansion.count_unknown:variable.no_value")
        for name in ("x", "y", "z"):
            self.assertEqual(instance.arguments[name].value, expected, name)

    def test_a_reference_to_a_block_argument_is_unsupported(self) -> None:
        text = (
            'resource "aws_security_group" "g" {\n  ingress {\n    from_port = 1\n  }\n}\n'
            'resource "aws_instance" "i" {\n  x = aws_security_group.g.ingress\n}\n'
        )
        value = build(text).one("aws_instance", "i").arguments["x"].value
        self.assertEqual(value, Unsupported("resource.block_argument"))

    def test_a_whole_resource_holds_id_and_the_configured_arguments(self) -> None:
        text = (
            'resource "aws_vpc" "v" {\n'
            '  cidr = "10.0.0.0/16"\n'
            "}\n"
            'resource "aws_x" "x" {\n'
            "  whole = aws_vpc.v\n"
            "}\n"
        )
        value = build(text).one("aws_x", "x").arguments["whole"].value
        self.assertEqual(
            value, known_object({"id": Ref("aws_vpc.v", "id"), "cidr": Known("10.0.0.0/16")})
        )

    def test_a_cycle_between_arguments_is_invalid_and_unsupported(self) -> None:
        # validate: Error: Cycle
        text = (
            'resource "aws_a" "a" {\n  x = aws_b.b.y\n}\n'
            'resource "aws_b" "b" {\n  y = aws_a.a.x\n}\n'
        )
        built = build(text)
        instance = built.one("aws_a", "a")
        self.assertIsInstance(instance.arguments["x"].value, Unsupported)
        self.assertIn("eval.resource_cycle", [d.code for d in built.scope.diagnostics])

    def test_a_resource_that_refers_to_itself_is_unsupported_not_invalid(self) -> None:
        # Terraform 1.15.8: `validate` accepts `x = aws_a.a.x` and `x = aws_a.a.id`; `plan` fails
        # with "Self-referential block". So it is not INVALID (C-92); the config cannot be planned.
        for body in (
            "x = aws_a.a.x",
            "x = aws_a.a.id",
            "x = aws_a.a",
            "x = [for r in aws_a.a : r]",
            "count = 2\n  x = aws_a.a[0].id",
            "count = 2\n  x = aws_a.a[*].x",
            "count = length(aws_a.a)",
            "for_each = toset([aws_a.a.id])",
        ):
            with self.subTest(body=body):
                built = build('resource "aws_a" "a" {\n  ' + body + "\n}\n")
                expansion = built.expand("aws_a", "a")
                found = [(d.severity, d.code) for d in built.scope.diagnostics]
                self.assertEqual(
                    set(found), {(DiagnosticSeverity.UNSUPPORTED, "eval.self_reference")}
                )
                values = [
                    argument.value
                    for instance in expansion.instances
                    for argument in instance.arguments.values()
                ]
                if expansion.instances:
                    self.assertEqual(values, [Unsupported("resource.self_reference")] * len(values))
                else:
                    assert expansion.indeterminate is not None
                    self.assertEqual(
                        expansion.indeterminate.reason, Unsupported("resource.self_reference")
                    )

    def test_a_data_source_that_refers_to_itself(self) -> None:
        built = build('data "aws_a" "a" {\n  x = data.aws_a.a.id\n}\n')
        built.expand("aws_a", "a", "data")
        self.assertEqual([d.code for d in built.scope.diagnostics], ["eval.self_reference"])

    def test_references_to_another_resource_with_the_same_name_are_not_self_references(
        self,
    ) -> None:
        text = 'resource "aws_a" "n" {}\nresource "aws_b" "n" {\n  x = aws_a.n.id\n}\n'
        built = build(text)
        self.assertEqual(built.one("aws_b", "n").arguments["x"].value, Ref("aws_a.n", "id"))
        self.assertEqual(built.scope.diagnostics, ())

    def test_a_cycle_through_count(self) -> None:
        text = (
            'resource "aws_a" "a" {\n  count = length(aws_b.b)\n}\n'
            'resource "aws_b" "b" {\n  count = length(aws_a.a)\n}\n'
        )
        built = build(text)
        expansion = built.expand("aws_a", "a")
        assert expansion.indeterminate is not None
        self.assertIn("eval.resource_cycle", [d.code for d in built.scope.diagnostics])

    def test_data_sources_are_unknown(self) -> None:
        text = (
            'data "aws_ami" "x" {}\nresource "aws_instance" "i" {\n  ami = data.aws_ami.x.id\n}\n'
        )
        self.assertEqual(
            build(text).one("aws_instance", "i").arguments["ami"].value, Unknown("data_source")
        )

    def test_locals_variables_and_defaults_reach_arguments(self) -> None:
        text = (
            "locals {\n"
            '  base = "${var.env}-app"\n'
            "}\n"
            'resource "aws_x" "x" {\n'
            "  name = local.base\n"
            "}\n"
        )
        instance = build(text, {"env": Known("prod")}).one("aws_x", "x")
        self.assertEqual(instance.arguments["name"].value, Known("prod-app"))


class TestMetaArguments(unittest.TestCase):
    def test_meta_arguments_are_recorded_and_not_arguments(self) -> None:
        text = (
            'resource "aws_x" "x" {\n'
            "  count = 1\n"
            "  provider = aws.west\n"
            "  depends_on = [aws_y.y, aws_z.z]\n"
            "  lifecycle {\n"
            "    create_before_destroy = true\n"
            "    prevent_destroy = false\n"
            "    ignore_changes = [tags]\n"
            "  }\n"
            '  name = "n"\n}\n'
        )
        (instance,) = build(text).expand("aws_x", "x").instances
        meta = instance.meta
        self.assertEqual(meta.provider, "aws.west")
        self.assertEqual(meta.depends_on, ("aws_y.y", "aws_z.z"))
        self.assertEqual(
            (meta.create_before_destroy, meta.prevent_destroy), (Known(True), Known(False))
        )
        self.assertEqual(len(meta.lifecycle), 1)
        self.assertIsNotNone(meta.count)
        self.assertEqual(sorted(instance.arguments), ["name"])

    def test_defaults(self) -> None:
        meta = build('resource "aws_x" "x" {}\n').one("aws_x", "x").meta
        self.assertEqual(
            (meta.provider, meta.depends_on, meta.create_before_destroy, meta.prevent_destroy),
            (None, None, None, None),
        )
        self.assertEqual(
            (meta.count, meta.for_each, meta.lifecycle, meta.provisioners, meta.connections),
            (None, None, (), (), ()),
        )

    def test_provisioners_and_connections_are_flagged_and_not_evaluated(self) -> None:
        text = (
            'resource "aws_x" "x" {\n  connection {\n    host = var.nope\n  }\n'
            '  provisioner "local-exec" {\n    command = "echo ${var.nope}"\n  }\n}\n'
        )
        built = build(text)
        instance = built.one("aws_x", "x")
        self.assertEqual(
            [(d.severity, d.code) for d in instance.diagnostics],
            [
                (DiagnosticSeverity.UNSUPPORTED_CONSTRUCT, "eval.connection"),
                (DiagnosticSeverity.UNSUPPORTED_CONSTRUCT, "eval.provisioner"),
            ],
        )
        self.assertEqual((len(instance.meta.provisioners), len(instance.meta.connections)), (1, 1))
        self.assertEqual(built.scope.diagnostics, ())  # var.nope inside them was not evaluated

    def test_depends_on_that_is_not_a_list_of_references_is_not_recorded(self) -> None:
        meta = build('resource "aws_x" "x" {\n  depends_on = var.deps\n}\n').one("aws_x", "x").meta
        self.assertIsNone(meta.depends_on)


class TestRecordsAreFrozen(unittest.TestCase):
    def test_instances_and_arguments_cannot_change(self) -> None:
        instance = build('resource "aws_x" "x" {\n  a = 1\n  b {\n    c = 1\n  }\n}\n').one(
            "aws_x", "x"
        )
        with self.assertRaises(AttributeError):
            instance.address = "other"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            instance.arguments["z"] = instance.arguments["a"]  # type: ignore[index]
        with self.assertRaises(TypeError):
            instance.arguments["b"].blocks[0].arguments["z"] = instance.arguments["a"]  # type: ignore[index]
        self.assertEqual(list(instance.arguments), sorted(instance.arguments))

    def test_expansion_is_repeatable_and_does_not_change_the_scope(self) -> None:
        text = 'resource "aws_x" "x" {\n  for_each = toset(["a", "b"])\n  n = each.key\n}\n'
        built = build(text)
        first = built.expand("aws_x", "x")
        second = built.expand("aws_x", "x")
        self.assertEqual(first, second)
        self.assertEqual(built.scope.diagnostics, ())


class TestRegistries(unittest.TestCase):
    def test_every_reason_and_diagnostic_in_instances_is_registered(self) -> None:
        source = (ROOT / "core" / "terraform_model" / "instances.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        skipped: set[int] = set()
        for node in ast.walk(tree):
            targets = (
                node.targets if isinstance(node, ast.Assign) else [getattr(node, "target", None)]
            )
            if any(
                isinstance(t, ast.Name) and t.id in ("REASONS", "UNKNOWN_REASONS", "DIAGNOSTICS")
                for t in targets
            ):
                skipped |= {id(inner) for inner in ast.walk(node)}
        reasons: set[str] = set()
        unknowns: set[str] = set()
        diagnostics: set[str] = set()
        strings: set[str] = set()
        for node in ast.walk(tree):
            if id(node) in skipped:
                continue
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                strings.add(node.value)
            if not isinstance(node, ast.Call):
                continue
            called = (
                node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            )
            args = node.args
            first = args[0] if args else None
            if called in ("Unsupported", "Fail") and isinstance(first, ast.Constant):
                reasons.add(str(first.value))
            if called == "Unknown":
                if isinstance(first, ast.Constant):
                    unknowns.add(str(first.value).rstrip(":"))
                elif isinstance(first, ast.JoinedStr) and isinstance(first.values[0], ast.Constant):
                    unknowns.add(str(first.values[0].value).rstrip(":"))
            if called in ("_diagnostic", "report"):
                code = (
                    args[1]
                    if called == "_diagnostic" and len(args) > 1
                    else (args[0] if args else None)
                )
                if isinstance(code, ast.Constant):
                    diagnostics.add(str(code.value))
        from core.terraform_model import convert, evaluate, functions

        known_reasons = {
            *instances_module.REASONS,
            *evaluate.REASONS,
            *convert.REASONS,
            *functions.FUNCTION_REASONS,
        }
        self.assertEqual(sorted(reasons - known_reasons), [])
        self.assertEqual(
            sorted(
                unknowns - set(instances_module.UNKNOWN_REASONS) - set(evaluate.UNKNOWN_REASONS)
            ),
            [],
        )
        self.assertEqual(sorted(diagnostics - set(instances_module.DIAGNOSTICS)), [])
        unused = set(instances_module.REASONS) - reasons - strings
        self.assertEqual(sorted(unused), [])
        unused_diagnostics = set(instances_module.DIAGNOSTICS) - diagnostics - strings
        self.assertEqual(sorted(unused_diagnostics), [])
        self.assertTrue(re.fullmatch(r"[a-z_.]+", "eval.attribute_and_block"))


if __name__ == "__main__":
    unittest.main()
