"""The function subset (Doc 04 §17; C-103) and the type constraints of variables.

Every function has the examples of its Terraform 1.15 documentation page
(``hashicorp/web-unified-docs`` commit ``fefc7502dba86c70716f0109c324c85829229b2f``,
``content/terraform/v1.15.x/docs/language/functions/<name>.mdx``) and the results of probes of
``terraform console`` of Terraform 1.15.8 (scratch directory outside the repository, no
credentials), marked ``probe``. Expected values never come from the implementation.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from core.terraform_model.convert import (
    Fail,
    convert_to,
    make_number,
    number_text,
    parse_number,
    parse_type,
    unify,
    unify_pair,
)
from core.terraform_model.evaluate import Scope, evaluate_expression
from core.terraform_model.functions import FUNCTIONS
from core.terraform_model.values import (
    FALSE,
    NULL,
    TRUE,
    Known,
    Ref,
    Unknown,
    Unsupported,
    from_json,
    known_object,
    known_set,
    known_tuple,
)
from tests.unit.test_terraform_evaluate import ev, k, obj, parse_expression, tup

U = Unknown("variable.no_value")


def unsupported(text: str, **scope: object) -> Unsupported:
    value = ev(text, **scope)
    assert isinstance(value, Unsupported), (text, value)
    return value


class TestDocumentationExamples(unittest.TestCase):
    """Each example is the one printed on the function's page."""

    def check(self, cases: list[tuple[str, object]]) -> None:
        for text, expected in cases:
            with self.subTest(text=text):
                want = (
                    expected if isinstance(expected, Known | Unknown | Unsupported) else k(expected)
                )
                self.assertEqual(ev(text), want)

    def test_cidrhost(self) -> None:
        self.check(
            [
                ('cidrhost("10.12.112.0/20", 16)', "10.12.112.16"),
                ('cidrhost("10.12.112.0/20", 268)', "10.12.113.12"),
                ('cidrhost("fd00:fd12:3456:7890:00a2::/72", 34)', "fd00:fd12:3456:7890::22"),
                ('cidrhost("10.1.2.240/28", 1)', "10.1.2.241"),
                ('cidrhost("10.1.2.240/28", 14)', "10.1.2.254"),
                ('cidrhost("10.0.0.0/8", -2)', "10.255.255.254"),
            ]
        )

    def test_cidrsubnet(self) -> None:
        self.check(
            [
                ('cidrsubnet("172.16.0.0/12", 4, 2)', "172.18.0.0/16"),
                ('cidrsubnet("10.1.2.0/24", 4, 15)', "10.1.2.240/28"),
                (
                    'cidrsubnet("fd00:fd12:3456:7890::/56", 16, 162)',
                    "fd00:fd12:3456:7800:a200::/72",
                ),
            ]
        )

    def test_coalesce(self) -> None:
        self.check(
            [
                ('coalesce("a", "b")', "a"),
                ('coalesce("", "b")', "b"),
                ("coalesce(1,2)", 1),
                ('coalesce(["", "b"]...)', "b"),
                ('coalesce(1, "hello")', "1"),
                ('coalesce(true, "hello")', "true"),
            ]
        )
        unsupported('coalesce({}, "hello")')  # the page: "all arguments must have the same type"

    def test_compact_concat_contains_distinct(self) -> None:
        self.check(
            [
                ('compact(["a", "", "b", null, "c"])', ["a", "b", "c"]),
                ('concat(["a", ""], ["b", "c"])', ["a", "", "b", "c"]),
                ('concat([], [1, "a"], [[3], "c"])', [1, "a", [3], "c"]),
                ('contains(["a", "b", "c"], "a")', True),
                ('contains(["a", "b", "c"], "d")', False),
                ('distinct(["a", "b", "a", "c", "d", "b"])', ["a", "b", "c", "d"]),
            ]
        )

    def test_element_flatten_join_keys_values(self) -> None:
        self.check(
            [
                ('element(["a", "b", "c"], 1)', "b"),
                ('element(["a", "b", "c"], 3)', "a"),
                ('element(["a", "b", "c"], -1)', "c"),
                ('flatten([["a", "b"], [], ["c"]])', ["a", "b", "c"]),
                ('flatten([[["a", "b"], []], ["c"]])', ["a", "b", "c"]),
                ('join("-", ["foo", "bar", "baz"])', "foo-bar-baz"),
                ('join(", ", ["foo", "bar", "baz"])', "foo, bar, baz"),
                ('join(", ", ["foo"])', "foo"),
                ("keys({a=1, c=2, d=3})", ["a", "c", "d"]),
                ("values({a=3, c=2, d=1})", [3, 2, 1]),
            ]
        )

    def test_format(self) -> None:
        self.check(
            [
                ('format("Hello, %s!", "Ander")', "Hello, Ander!"),
                ('format("There are %d lights", 4)', "There are 4 lights"),
            ]
        )
        # the page also shows %[1]s and %#v; DAIL implements only %s, %d, %v and %%
        for text in (
            'format("%[1]s%[2]s%[1]s%[3]s", "/", "path", "file.tf")',
            'format("%#v", "hello")',
        ):
            self.assertEqual(unsupported(text).reason, "function.format_verb")

    def test_length_lookup_merge_split(self) -> None:
        self.check(
            [
                ("length([])", 0),
                ('length(["a", "b"])', 2),
                ('length({"a" = "b"})', 1),
                ('length("hello")', 5),
                ('lookup({a="ay", b="bee"}, "a", "what?")', "ay"),
                ('lookup({a="ay", b="bee"}, "c", "what?")', "what?"),
                ('merge({a="b", c="d"}, {e="f", c="z"})', {"a": "b", "c": "z", "e": "f"}),
                ('merge({a="b"}, {a=[1,2], c="z"}, {d=3})', {"a": [1, 2], "c": "z", "d": 3}),
                ('merge([{a="b", c="d"}, {}, {e="f", c="z"}]...)', {"a": "b", "c": "z", "e": "f"}),
                ('split(",", "foo,bar,baz")', ["foo", "bar", "baz"]),
                ('split(",", "foo")', ["foo"]),
                ('split(",", "")', [""]),
            ]
        )

    def test_length_of_a_string_with_non_ascii_characters_is_not_computed(self) -> None:
        # the page: length("👾🕹️") is 2 (grapheme clusters); Python has no segmentation
        self.assertEqual(unsupported('length("👾🕹️")').reason, "function.unicode_length")

    def test_case_conversion(self) -> None:
        self.check([('lower("HELLO")', "hello"), ('upper("hello")', "HELLO")])
        # the pages also show lower("ΓΕΙΑ ΣΟΥ") and upper("алло!"); Go and Python differ on some
        # non-ASCII mappings (probe: lower("ΟΔΟΣ") is "οδοσ", upper("straße") is "STRAßE")
        for text in ('lower("ΓΕΙΑ ΣΟΥ")', 'upper("алло!")', 'upper("straße")'):
            self.assertEqual(unsupported(text).reason, "function.non_ascii")

    def test_conversions(self) -> None:
        self.check(
            [
                ("tobool(true)", True),
                ('tobool("true")', True),
                ("tobool(null)", None),
                ('tolist(["a", "b", "c"])', ["a", "b", "c"]),
                ('tolist(["a", "b", 3])', ["a", "b", "3"]),
                ('tomap({"a" = 1, "b" = 2})', {"a": 1, "b": 2}),
                ('tomap({"a" = "foo", "b" = true})', {"a": "foo", "b": "true"}),
                ("tonumber(1)", 1),
                ('tonumber("1")', 1),
                ("tonumber(null)", None),
                ('tostring("hello")', "hello"),
                ("tostring(1)", "1"),
                ("tostring(true)", "true"),
                ("tostring(null)", None),
            ]
        )
        for text in ('tobool("no")', "tobool(1)", 'tonumber("no")', "tostring([])"):
            unsupported(text)  # the pages: each is an error
        self.assertEqual(
            ev('toset(["a", "b", "c"])'), known_set([Known("a"), Known("b"), Known("c")])
        )
        self.assertEqual(
            ev('toset(["a", "b", 3])'), known_set([Known("3"), Known("a"), Known("b")])
        )
        self.assertEqual(ev('toset(["c", "b", "b"])'), known_set([Known("b"), Known("c")]))


class TestTerraformProbes(unittest.TestCase):
    def test_number_conversions(self) -> None:
        cases = [
            ('tonumber("1e3")', 1000),
            ('tonumber("+5")', 5),
            ('tonumber("5.")', 5),
            ('tonumber(".5")', Decimal("0.5")),
            ('tonumber("-1.50")', Decimal("-1.5")),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(ev(text), Known(expected))
        for text in (
            'tonumber(" 5")',
            'tonumber("0x10")',
            'tonumber("1_0")',
            'tonumber("5 ")',
            'tonumber("")',
            'tonumber("1e")',
            "tonumber(true)",
        ):
            with self.subTest(text=text):
                unsupported(text)

    def test_bool_conversions(self) -> None:
        self.assertEqual(ev('tobool("false")'), FALSE)
        unsupported('tobool("TRUE")')
        unsupported('tobool("")')

    def test_number_to_string(self) -> None:
        cases = [
            ("tostring(1e3)", "1000"),
            ("tostring(0.1)", "0.1"),
            ("tostring(1e-7)", "0.0000001"),
            ("tostring(1.5e30)", "1500000000000000000000000000000"),
            ("tostring(123456789012345678901234567890)", "123456789012345678901234567890"),
            ("tostring(10/4)", "2.5"),
            ("tostring(1.0)", "1"),
            ("tostring(0.000001)", "0.000001"),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(ev(text), Known(expected))

    def test_format_directives(self) -> None:
        cases = [
            ('format("%d", 3.0)', "3"),
            ('format("%d", "3")', "3"),
            ('format("%s", 1.5)', "1.5"),
            ('format("%v", 1.5)', "1.5"),
            ('format("%v", 10)', "10"),
            ('format("%s", true)', "true"),
            ('format("%v", null)', "null"),
            ('format("%%")', "%"),
            ('format("%d%%", 5)', "5%"),
            ('format("%s-%s", "a", 1)', "a-1"),
            ('format("%s", 1e20)', "100000000000000000000"),
            ('format("%d", 1e20)', "100000000000000000000"),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(ev(text), Known(expected))

    def test_format_errors_and_unimplemented_verbs(self) -> None:
        for text, reason in [
            ('format("%s")', "function.format_arguments"),
            ('format("%s", 1, 2)', "function.format_arguments"),
            ('format("%s %s", "a")', "function.format_arguments"),
            ('format("%v")', "function.format_arguments"),
            ('format("%d", 1.5)', "number.not_integer"),
            ('format("%s", [1])', "function.format_collection"),
            ('format("%v", [1,"a"])', "function.format_collection"),
            ('format("%v", {a=1})', "function.format_collection"),
            ('format("%s", null)', "value.null"),
            ('format("%x", 255)', "function.format_verb"),
            ('format("%5s", "a")', "function.format_verb"),
            ('format("%-5d|", 3)', "function.format_verb"),
            ('format("%05d", 3)', "function.format_verb"),
            ('format("%2$s", "a")', "function.format_verb"),
            ('format("100%")', "function.format_verb"),
        ]:
            with self.subTest(text=text):
                self.assertEqual(unsupported(text).reason, reason)

    def test_collection_functions(self) -> None:
        cases = [
            ("element([1,2,3], 4)", Known(2)),
            ('lookup({a=1}, "b", null)', NULL),
            ('lookup({a="x"}, "a", 1)', Known("x")),
            ('coalesce("", null, "x")', Known("x")),
            ('compact(["a","",null])', tup("a")),
            ("compact([1])", tup("1")),
            ("flatten([1,[2,[3]]])", tup(1, 2, 3)),
            ("flatten(toset([[1],[2]]))", tup(1, 2)),
            ('distinct([1,"1",1])', tup("1")),
            ('distinct(["b","a","b"])', tup("b", "a")),
            ("length(toset([1,1]))", Known(1)),
            ("keys({b=1,a=2})", tup("a", "b")),
            ("values({b=1,a=2})", tup(2, 1)),
            ("merge({a=1},{a=2},null)", obj(a=2)),
            ("merge()", obj()),
            ('merge({a=1}, {b="x"})', obj(a=1, b="x")),
            ("concat([1],[2])", tup(1, 2)),
            ("toset([3,1,3])", known_set([Known(1), Known(3)])),
            ('tolist(toset(["b","a"]))', tup("a", "b")),
            ('contains(["a"], "a")', TRUE),
            ('contains([1], "1")', FALSE),
            ('contains(toset(["a"]), "a")', TRUE),
            ('join(",", [])', Known("")),
            ('join(",", [1,true])', Known("1,true")),
            ('join(",", toset(["b","a"]))', Known("a,b")),
            ('join(",", ["a"], ["b"])', Known("a,b")),
            ('split("", "ab")', tup("a", "b")),
            ('split("", "")', tup()),
            ('split(",", "a,,b,")', tup("a", "", "b", "")),
            ("upper(1)", Known("1")),
            ('length("a\\r\\nb")', Known(3)),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(ev(text), expected)

    def test_collection_function_errors(self) -> None:
        for text in (
            "element([], 0)",
            'element(toset(["b"]), 0)',
            "element([1], 1.5)",
            'lookup({a=1}, "b")',
            "coalesce(null)",
            'coalesce("", null)',
            "length(null)",
            "length(1)",
            "keys(null)",
            "lower(null)",
            "concat()",
            "concat([1], toset([2]))",
            "merge([1])",
            "contains({a=1}, 1)",
            "flatten(1)",
        ):
            with self.subTest(text=text):
                unsupported(text)

    def test_wrong_number_of_arguments(self) -> None:
        for text in (
            "length()",
            "length(1, 2)",
            "lookup({})",
            'lookup({}, "a", 1, 2)',
            "element([])",
            "format()",
            "cidrhost()",
        ):
            with self.subTest(text=text):
                self.assertEqual(unsupported(text).reason, "function.arguments")

    def test_equality_inside_functions_uses_the_terraform_rules(self) -> None:
        self.assertEqual(ev('distinct(["a", "a", "b"])'), tup("a", "b"))
        self.assertEqual(unsupported("distinct([[1], [1]])").reason, "operator.collection_equality")
        self.assertEqual(unsupported("contains([[1]], [1])").reason, "operator.collection_equality")

    def test_a_set_of_true_and_one_keeps_both(self) -> None:
        # unify turns a bool and a number into strings first, as Terraform does
        self.assertEqual(ev("toset([true, 1])"), known_set([Known("1"), Known("true")]))

    def test_cidr_errors(self) -> None:
        for text in (
            'cidrsubnet("10.0.0.0/8", 25, 0)',  # probe: insufficient address space
            'cidrhost("10.0.0.0/24", 256)',  # probe: does not accommodate
            'cidrhost("10.0.0.0/8", 16777216)',
            'cidrhost("10.0.0.0/8", -16777217)',
            'cidrhost("10.0.0.0", 1)',  # probe: invalid CIDR
            'cidrhost("10.0.0.0/255.0.0.0", 1)',  # probe: invalid CIDR
            'cidrhost("10.0.0.0/8", 1.5)',  # probe: must be whole
            'cidrhost("::ffff:1.2.3.4/120", 1)',  # probe: odd output, so not modelled
            'cidrhost("10.0.0.0/08", 1)',  # probe: accepted by Terraform, not read by DAIL
            'cidrsubnet("10.0.0.0/8", 8, -1)',  # probe: accepted with a surprising result
            'cidrsubnet("10.0.0.0/8", -1, 0)',  # probe: accepted with a shorter prefix
            'cidrsubnet("10.0.0.0/8", 2, 4)',
            'cidrhost("10.0.0.0%eth0/8", 1)',
            'cidrhost("300.0.0.0/8", 1)',
        ):
            with self.subTest(text=text):
                unsupported(text)

    def test_cidr_values_from_probes(self) -> None:
        cases = [
            ('cidrsubnet("10.0.0.1/8", 8, 1)', "10.1.0.0/16"),
            ('cidrsubnet("10.0.0.0/8", 0, 0)', "10.0.0.0/8"),
            ('cidrhost("10.0.0.0/8", -16777216)', "10.0.0.0"),
            ('cidrhost("::/64", 1)', "::1"),
            ('cidrhost("FD00::/64", 1)', "fd00::1"),
            ('cidrsubnet("10.0.0.0/8", 2.0, 1)', "10.64.0.0/10"),
            ('cidrsubnet("10.0.0.0/8", "2", 1)', "10.64.0.0/10"),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(ev(text), Known(expected))

    def test_every_function_checks_its_argument_count_from_the_table(self) -> None:
        for name, (minimum, maximum, _) in FUNCTIONS.items():
            with self.subTest(name=name):
                if minimum > 0:
                    args = ", ".join(["1"] * (minimum - 1))
                    self.assertEqual(unsupported(f"{name}({args})").reason, "function.arguments")
                if maximum is not None:
                    args = ", ".join(["1"] * (maximum + 1))
                    self.assertEqual(unsupported(f"{name}({args})").reason, "function.arguments")


class TestFunctionsWithUnknowns(unittest.TestCase):
    def scope(self) -> dict[str, object]:
        return {"variables": {"u": U, "l": tup(1, U)}}

    UNKNOWN_CALLS = (
        "tostring(u)", "tonumber(u)", "tobool(u)", "toset(u)", "tolist(u)", "tomap(u)",
        "concat(u, [1])", "merge(u)", "length(u)", "element(u, 0)", "element([1], u)",
        'lookup(u, "a")', "contains(u, 1)", "contains([1], u)", "distinct(u)", "flatten(u)",
        "keys(u)", "values(u)", "compact(u)", "lower(u)", "upper(u)", 'join(",", u)',
        'join(u, ["a"])', 'split(u, "a")', 'split(",", u)', "format(u)", 'format("%s", u)',
        "cidrsubnet(u, 1, 1)", 'cidrsubnet("10.0.0.0/8", u, 1)', 'cidrhost("10.0.0.0/8", u)',
    )  # fmt: skip

    def test_an_unknown_argument_gives_an_unknown_result(self) -> None:
        for call in self.UNKNOWN_CALLS:
            text = call.replace("(u", "(var.u").replace(", u", ", var.u")
            with self.subTest(text=text):
                self.assertEqual(ev(text, **self.scope()), U)

    def test_an_unsupported_argument_gives_an_unsupported_result(self) -> None:
        for text in (
            "tostring(abs(1))",
            "length(abs(1))",
            'format("%s", abs(1))',
            "contains([1], abs(1))",
        ):
            with self.subTest(text=text):
                self.assertEqual(ev(text), Unsupported("function.not_implemented:abs"))

    def test_contains_with_an_unknown_element(self) -> None:
        self.assertEqual(ev("contains(var.l, 1)", **self.scope()), TRUE)  # found for certain
        self.assertEqual(
            ev("contains(var.l, 2)", **self.scope()), Unknown("function.contains_undecided")
        )

    def test_toset_keeps_an_unknown_element(self) -> None:
        value = ev("toset(var.l)", **self.scope())
        self.assertEqual(value, known_set([Known(1), U]))

    def test_references_pass_through_where_the_value_is_only_moved(self) -> None:
        ref = Ref("aws_x.y", "id")
        scope = {"variables": {"r": ref}}
        self.assertEqual(ev("tostring(var.r)", **scope), ref)
        self.assertEqual(ev("concat([var.r], [var.r])", **scope), tup(ref, ref))
        self.assertEqual(ev("merge({a = var.r})", **scope), obj(a=ref))
        self.assertEqual(ev("flatten([[var.r]])", **scope), tup(ref))
        self.assertEqual(ev('compact([var.r, ""])', **scope), tup(ref))
        self.assertEqual(ev('coalesce("", var.r)', **scope), ref)
        self.assertEqual(ev("element([var.r], 0)", **scope), ref)
        self.assertEqual(ev('lookup({a = var.r}, "a")', **scope), ref)
        self.assertEqual(ev("distinct([var.r, var.r])", **scope), tup(ref))
        self.assertEqual(ev("contains([var.r], var.r)", **scope), TRUE)
        self.assertEqual(ev('join(",", [var.r])', **scope), Unknown("ref.derived:aws_x.y.id"))
        self.assertEqual(ev("tonumber(var.r)", **scope), Unknown("ref.derived:aws_x.y.id"))


class TestNumbersAndUnification(unittest.TestCase):
    def test_number_text(self) -> None:
        self.assertEqual(number_text(1000), "1000")
        self.assertEqual(number_text(Decimal("1E-7")), "0.0000001")
        self.assertEqual(number_text(Decimal("1.5E+3")), "1500")
        self.assertEqual(number_text(-5), "-5")

    def test_parse_number(self) -> None:
        self.assertEqual(parse_number("007"), 7)
        self.assertEqual(parse_number("1E3"), 1000)
        self.assertEqual(parse_number("-0.5"), Decimal("-0.5"))
        with self.assertRaises(Fail):
            parse_number("-0")  # Terraform keeps -0
        with self.assertRaises(Fail):
            parse_number("1e99999")  # outside what DAIL keeps exactly
        with self.assertRaises(Fail):
            parse_number("5\n")

    def test_make_number_refuses_a_negative_zero(self) -> None:
        with self.assertRaises(Fail):
            make_number(Decimal("-0.0"))

    def test_unify(self) -> None:
        self.assertEqual(unify([Known(1), Known("a")]), [Known("1"), Known("a")])
        self.assertEqual(unify([Known(1), Known(2)]), [Known(1), Known(2)])
        self.assertEqual(unify([Known(True), Known(1)]), [Known("true"), Known("1")])
        self.assertEqual(unify([NULL, Known(1), U]), [NULL, Known(1), U])
        with self.assertRaises(Fail):
            unify([Known(1), tup(1)])
        with self.assertRaises(Fail):
            unify([tup(1), obj(a=1)])

    def test_unify_pair(self) -> None:
        self.assertEqual(unify_pair(Known(1), Known("a")), Known("1"))
        self.assertEqual(unify_pair(tup(1), tup("a")), tup("1"))
        self.assertEqual(unify_pair(tup(1, 2), tup(3)), tup(1, 2))
        self.assertEqual(unify_pair(obj(a=1), obj(b="x")), obj(a="1"))
        self.assertEqual(unify_pair(Known(1), NULL), Known(1))
        self.assertEqual(unify_pair(NULL, Known(1)), NULL)
        with self.assertRaises(Fail):
            unify_pair(tup(1), obj(a=1))
        with self.assertRaises(Fail):
            unify_pair(tup(1), Known(1))


def constraint(text: str):  # type: ignore[no-untyped-def]
    return parse_type(parse_expression(text))


class TestTypeConstraints(unittest.TestCase):
    """The type constraint syntax and conversion rules of ``expressions/type-constraints.mdx``."""

    def test_primitives_convert(self) -> None:
        self.assertEqual(convert_to(Known(1), constraint("string")), Known("1"))
        self.assertEqual(convert_to(Known(True), constraint("string")), Known("true"))
        self.assertEqual(convert_to(Known("5"), constraint("number")), Known(5))
        self.assertEqual(convert_to(Known("true"), constraint("bool")), TRUE)
        for value, spec in [
            (Known("x"), "number"),
            (Known("yes"), "bool"),
            (tup(1), "string"),
            (Known(1), "bool"),
        ]:
            with self.subTest(value=value, spec=spec), self.assertRaises(Fail):
                convert_to(value, constraint(spec))

    def test_null_converts_to_every_type(self) -> None:
        for spec in (
            "string",
            "number",
            "bool",
            "list(string)",
            "map(string)",
            "object({a=string})",
        ):
            self.assertEqual(convert_to(NULL, constraint(spec)), NULL)

    def test_any_keeps_the_value(self) -> None:
        value = tup(1, "a")
        self.assertIs(convert_to(value, constraint("any")), value)

    def test_list_set_map(self) -> None:
        self.assertEqual(convert_to(tup(1, 2), constraint("list(string)")), tup("1", "2"))
        self.assertEqual(
            convert_to(tup("b", "a", "b"), constraint("set(string)")),
            known_set([Known("a"), Known("b")]),
        )
        self.assertEqual(convert_to(obj(a=1), constraint("map(string)")), obj(a="1"))
        self.assertEqual(convert_to(tup(1, "a"), constraint("list(any)")), tup("1", "a"))
        with self.assertRaises(Fail):
            convert_to(obj(a=1), constraint("list(string)"))
        with self.assertRaises(Fail):
            convert_to(tup(1), constraint("map(string)"))
        with self.assertRaises(Fail):
            convert_to(tup("x"), constraint("list(number)"))

    def test_object(self) -> None:
        spec = constraint("object({name = string, age = number})")
        self.assertEqual(convert_to(obj(name="a", age="3"), spec), obj(name="a", age=3))
        self.assertEqual(
            convert_to(obj(name="a", age=3, extra=1), spec), obj(name="a", age=3)
        )  # extra attributes are dropped
        with self.assertRaises(Fail):
            convert_to(obj(name="a"), spec)

    def test_optional_attributes(self) -> None:
        spec = constraint('object({a = string, b = optional(number), c = optional(string, "d")})')
        self.assertEqual(convert_to(obj(a="x"), spec), obj(a="x", b=None, c="d"))
        self.assertEqual(convert_to(obj(a="x", b="2", c="e"), spec), obj(a="x", b=2, c="e"))

    def test_tuple(self) -> None:
        spec = constraint("tuple([string, number])")
        self.assertEqual(convert_to(tup(1, "2"), spec), tup("1", 2))
        with self.assertRaises(Fail):
            convert_to(tup(1), spec)

    def test_nested(self) -> None:
        spec = constraint("map(object({ports = list(number)}))")
        value = obj(web=obj(ports=tup("80", 443)))
        self.assertEqual(convert_to(value, spec), obj(web=obj(ports=tup(80, 443))))

    def test_unknown_and_reference_values(self) -> None:
        self.assertEqual(convert_to(U, constraint("number")), U)
        self.assertEqual(convert_to(tup(U), constraint("list(string)")), tup(U))
        ref = Ref("aws_x.y", "id")
        self.assertEqual(convert_to(ref, constraint("string")), ref)
        with self.assertRaises(Fail):
            convert_to(ref, constraint("number"))

    def test_bad_type_constraints_are_refused(self) -> None:
        for text in (
            "strng",
            "list",
            "list(string, string)",
            "object(string)",
            "object({a=nope})",
            "tuple(string)",
            "foo(string)",
            "1",
            '"string"',
            "object({a=string, a=number})",
            "optional(string)",
        ):
            with self.subTest(text=text), self.assertRaises(Fail):
                constraint(text)

    def test_a_scenario_value_is_read_from_json(self) -> None:
        value = from_json({"cidrs": ["10.0.0.0/8"], "port": 22, "tags": {"a": "b"}})
        spec = constraint("object({cidrs = list(string), port = number, tags = map(string)})")
        self.assertEqual(
            convert_to(value, spec),
            known_object(
                {
                    "cidrs": known_tuple([Known("10.0.0.0/8")]),
                    "port": Known(22),
                    "tags": known_object({"a": Known("b")}),
                }
            ),
        )


class TestEvaluateExpressionNeverRaises(unittest.TestCase):
    def test_a_scope_without_anything(self) -> None:
        for text in (
            "var.a",
            "local.a",
            "aws_x.y.id",
            "data.a.b.c",
            "each.key",
            "count.index",
            "[for x in var.a : x]",
        ):
            with self.subTest(text=text):
                value = evaluate_expression(parse_expression(text), Scope())
                self.assertIsInstance(value, Unsupported)


if __name__ == "__main__":
    unittest.main()
