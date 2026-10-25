"""The expression evaluator (Doc 04 §17; C-102, C-103, C-105).

Expected values come from the Terraform 1.15 documentation pages named in the module docstring of
``core.terraform_model.evaluate`` and from probes of ``terraform console`` and ``terraform
validate`` of Terraform 1.15.8 (scratch directory outside the repository, no credentials), never
from the implementation. A probe is marked ``probe`` in a comment.
"""

from __future__ import annotations

import ast
import unittest
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path

from core.terraform_model import convert, evaluate, functions
from core.terraform_model.config import DiagnosticSeverity
from core.terraform_model.evaluate import (
    MAX_DEPTH,
    MAX_FOR_ELEMENTS,
    MAX_STEPS,
    Scope,
    evaluate_expression,
)
from core.terraform_model.hcl.ast import Attribute, Expression
from core.terraform_model.hcl.parser import parse_file
from core.terraform_model.values import (
    FALSE,
    NULL,
    TRUE,
    Known,
    Ref,
    Unknown,
    Unsupported,
    Value,
    from_json,
    known_object,
    known_set,
    known_tuple,
)

ROOT = Path(__file__).resolve().parents[2]


def parse_expression(text: str) -> Expression:
    body = parse_file(f"x = {text}\n", "t.tf")
    item = body.items[0]
    assert isinstance(item, Attribute)
    return item.expr


def run(text: str, **scope: object) -> tuple[Value, Scope]:
    built = Scope(**scope)  # type: ignore[arg-type]
    return evaluate_expression(parse_expression(text), built), built


def ev(text: str, **scope: object) -> Value:
    return run(text, **scope)[0]


def k(value: object) -> Value:
    return from_json(value)


def tup(*items: object) -> Value:
    return known_tuple(
        i if isinstance(i, Known | Unknown | Unsupported | Ref) else k(i) for i in items
    )


def obj(**items: object) -> Value:
    return known_object(
        {
            n: v if isinstance(v, Known | Unknown | Unsupported | Ref) else k(v)
            for n, v in items.items()
        }
    )


# A fake resource table, standing in for the instances of step 4.


class FakeInstance:
    def __init__(self, address: str, key: Value | None, arguments: Mapping[str, Value]) -> None:
        self.address = address
        self.key = key
        self._arguments = arguments

    def attribute(self, name: str) -> Value:
        if name == "id":
            return Ref(self.address, "id")
        if name in self._arguments:
            return self._arguments[name]
        return Unknown(f"resource.computed:{name}")

    def attributes(self) -> Mapping[str, Value]:
        return {"id": Ref(self.address, "id"), **self._arguments}


class FakeResource:
    def __init__(self, mode: str, instances: object) -> None:
        self.mode = mode
        self._instances = instances

    def instances(self) -> object:
        return self._instances


class FakeResolver:
    def __init__(self, resources: Mapping[tuple[str, str, str], FakeResource]) -> None:
        self._resources = resources

    def resource(self, kind: str, type_: str, name: str) -> FakeResource | None:
        return self._resources.get((kind, type_, name))


def single(address: str, **arguments: Value) -> FakeResource:
    return FakeResource("single", (FakeInstance(address, None, arguments),))


class TestLiterals(unittest.TestCase):
    def test_scalars(self) -> None:
        self.assertEqual(ev("1"), Known(1))
        self.assertEqual(ev("1.5"), Known(Decimal("1.5")))
        self.assertEqual(ev('"abc"'), Known("abc"))
        self.assertEqual(ev("true"), TRUE)
        self.assertEqual(ev("false"), FALSE)
        self.assertEqual(ev("null"), NULL)

    def test_a_number_is_exact(self) -> None:
        self.assertEqual(
            ev("123456789012345678901234567890"), Known(123456789012345678901234567890)
        )
        self.assertEqual(
            ev("0.1234567890123456789012345678901234567890"),
            Known(Decimal("0.123456789012345678901234567890123456789")),
        )

    def test_collections(self) -> None:
        self.assertEqual(ev('[1, "a", null]'), tup(1, "a", None))
        self.assertEqual(ev("{b = 1, a = 2}"), obj(a=2, b=1))

    def test_object_keys(self) -> None:
        # probe: a number or bool key is converted to a string; a later duplicate key wins
        self.assertEqual(ev("{(1) = 2}"), obj(**{"1": 2}))
        self.assertEqual(ev("{(true) = 2}"), obj(**{"true": 2}))
        self.assertEqual(ev("{a = 1, a = 2}"), obj(a=2))
        self.assertEqual(ev('{"a" = 1, a = 2}'), obj(a=2))
        self.assertIsInstance(ev("{(null) = 2}"), Unsupported)  # probe: "Null value as key"


class TestTemplates(unittest.TestCase):
    def test_numbers_print_without_exponent(self) -> None:
        # probe: tostring(1e3) = "1000", ${0.10} = "0.1", tostring(1e-7) = "0.0000001"
        self.assertEqual(ev('"${1e3}-${0.10}"'), Known("1000-0.1"))
        self.assertEqual(ev('"x${1e-7}"'), Known("x0.0000001"))
        self.assertEqual(ev('"x${1.5e30}"'), Known("x1500000000000000000000000000000"))

    def test_bool_in_text(self) -> None:
        self.assertEqual(ev('"a${true}"'), Known("atrue"))  # probe

    def test_a_single_interpolation_keeps_the_type(self) -> None:
        # probe: "${true}" is the bool, "${null}" is null, "${[1]}" is the list
        self.assertEqual(ev('"${true}"'), TRUE)
        self.assertEqual(ev('"${null}"'), NULL)
        self.assertEqual(ev('"${[1]}"'), tup(1))
        self.assertEqual(ev('"${1}${2}"'), Known("12"))  # probe

    def test_null_and_collections_in_text_are_unsupported(self) -> None:
        self.assertIsInstance(ev('"a${null}"'), Unsupported)
        self.assertIsInstance(ev('"a${[1]}"'), Unsupported)
        self.assertIsInstance(ev('"a${{b=1}}"'), Unsupported)

    def test_directives_are_unsupported_in_v1(self) -> None:
        # the work package, Step 3: %{if} and %{for} are unsupported (reason template.directive)
        for text in (
            '"%{ if true }a%{ else }b%{ endif }"',
            '"%{ for x in [1,2] }<${x}>%{ endfor }"',
            '"a${1}%{ if var.c }a%{ endif }"',
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    ev(text, variables={"c": Unknown("variable.no_value")}),
                    Unsupported("template.directive"),
                )
        heredoc = "<<EOT" + chr(10) + "%{ if true }a%{ endif }" + chr(10) + "EOT" + chr(10)
        self.assertEqual(ev(heredoc), Unsupported("template.directive"))

    def test_heredoc(self) -> None:
        text = "<<EOT\nhello ${1 + 1}\nEOT\n"
        self.assertEqual(ev(text), Known("hello 2\n"))
        indented = "<<-EOT\n    a\n      b ${var.v}\n    EOT\n"
        self.assertEqual(ev(indented, variables={"v": Known("x")}), Known("a\n  b x\n"))

    def test_unknown_in_text_is_unknown_and_unsupported_beats_it(self) -> None:
        scope = {"variables": {"u": Unknown("variable.no_value")}}
        self.assertEqual(ev('"a${var.u}"', **scope), Unknown("variable.no_value"))
        self.assertEqual(
            ev('"a${var.u}${abs(1)}"', **scope), Unsupported("function.not_implemented:abs")
        )
        self.assertEqual(
            ev('"a${abs(1)}${var.u}"', **scope), Unsupported("function.not_implemented:abs")
        )


class TestOperators(unittest.TestCase):
    def test_arithmetic(self) -> None:
        cases = [
            ("1 + 2", 3),
            ("2 - 3 - 4", -5),  # probe: left associative
            ("2 * 3 + 4", 10),
            ("6 / 3", 2),
            ("2 / 4", Decimal("0.5")),  # probe
            ("10 / 4", Decimal("2.5")),  # probe
            ("-5 % 3", -2),  # probe: the sign of the dividend
            ("5 % -3", 2),  # probe
            ("7.5 % 2", Decimal("1.5")),  # probe
            ("10 % 4.5", 1),  # probe
            ("-3 % 3", 0),  # probe: +0
            ("0 - 0", 0),
            ("-1 + 1", 0),
            ('1 + "2"', 3),  # probe: strings convert
            ('2 * "3"', 6),  # probe
            ('-"5"', -5),  # probe
            ("-(2)", -2),
            ("0.1 + 0.2", Decimal("0.3")),
            ("10000000000000000000000000000000000000000 + 1", 10**40 + 1),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(ev(text), Known(expected))

    def test_what_terraform_prints_as_minus_zero_is_unsupported(self) -> None:
        # probe: tostring(0 * -1) = "-0", tostring(-0) = "-0", tostring(0 / -5) = "-0"
        for text in ("0 * -1", "-1 * 0", "0 / -5", "-0", "0.0 * -1.5"):
            with self.subTest(text=text):
                self.assertEqual(ev(text), Unsupported("number.negative_zero"))

    def test_results_that_are_not_exact_are_unsupported(self) -> None:
        self.assertEqual(ev("1 / 3"), Unsupported("number.inexact"))
        self.assertEqual(ev("1 / 0"), Unsupported("number.divide_by_zero"))
        self.assertEqual(ev("1 % 0"), Unsupported("number.divide_by_zero"))

    def test_type_errors_are_unsupported(self) -> None:
        for text in ('"a" + 1', "true + 1", "[1] + 1", "null + 1", '"a" < "b"', "!null", '!"yes"'):
            with self.subTest(text=text):
                self.assertIsInstance(ev(text), Unsupported)

    def test_comparison(self) -> None:
        self.assertEqual(ev("1 < 2"), TRUE)
        self.assertEqual(ev("2 <= 2"), TRUE)
        self.assertEqual(ev("2 > 2"), FALSE)
        self.assertEqual(ev("2 >= 3"), FALSE)
        self.assertEqual(ev('"1" < 2'), TRUE)  # probe

    def test_equality(self) -> None:
        cases = [
            ('1 == "1"', False),  # probe
            ("1 == 1.0", True),  # probe
            ('"a" == "a"', True),
            ('true == "true"', False),  # probe
            ("null == null", True),  # probe
            ("null == 0", False),
            ('"a" != "b"', True),
            ("1 != 1", False),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(ev(text), Known(expected))

    def test_equality_of_collections_is_not_modelled(self) -> None:
        # Terraform: [1] == [1] is true and [1] == toset([1]) is false (probe); DAIL keeps list and
        # tuple as one kind, so it refuses
        for text in ("[1] == [1]", "{a=1} == {a=1}", "[1] == toset([1])", "[1] != [2]"):
            with self.subTest(text=text):
                self.assertEqual(ev(text), Unsupported("operator.collection_equality"))

    def test_logic(self) -> None:
        self.assertEqual(ev("true && false"), FALSE)
        self.assertEqual(ev("true || false"), TRUE)
        self.assertEqual(ev('true && "true"'), TRUE)  # probe
        self.assertEqual(ev("!true"), FALSE)
        self.assertEqual(ev('!"true"'), FALSE)  # probe

    def test_precedence_follows_the_specification(self) -> None:
        self.assertEqual(ev("1 + 2 * 3"), Known(7))
        self.assertEqual(ev("(1 + 2) * 3"), Known(9))
        self.assertEqual(ev("1 < 2 == true"), TRUE)
        self.assertEqual(ev("true || false && false"), TRUE)

    def test_a_long_chain_does_not_recurse(self) -> None:
        # the parser limits operator nesting to 64 (C-93); the evaluator folds the chain in a loop
        self.assertEqual(ev(" + ".join(["1"] * 60)), Known(60))


class TestShortCircuit(unittest.TestCase):
    """probe, Terraform 1.15.8: `false && [1][5]` is false and `true || [1][5]` is true (the right
    operand is not evaluated when the left one decides), so an error there is not an error."""

    def test_an_error_in_the_right_operand_is_ignored_when_the_left_decides(self) -> None:
        self.assertEqual(ev("false && [1][5]"), FALSE)
        self.assertEqual(ev("true || [1][5]"), TRUE)
        self.assertEqual(ev('false && tobool("x")'), FALSE)
        self.assertEqual(ev('"false" && null.a'), FALSE)
        self.assertEqual(ev("var.x != null && var.x.a == 1", variables={"x": NULL}), FALSE)

    def test_an_error_in_the_right_operand_counts_when_the_left_does_not_decide(self) -> None:
        self.assertIsInstance(ev("true && [1][5]"), Unsupported)
        self.assertIsInstance(ev("false || [1][5]"), Unsupported)

    def test_an_unknown_operand_follows_the_terraform_measurement(self) -> None:
        # Measured on 1.15.8 (plan; unknown = terraform_data.a.id == "x"): false && unknown,
        # unknown && false, true || unknown and unknown || true are known; true && unknown and
        # false || unknown are unknown (C-108).
        scope = {"variables": {"u": Unknown("variable.no_value")}}
        cases = [
            ("false && var.u", FALSE),
            ("var.u && false", FALSE),
            ("true || var.u", TRUE),
            ("var.u || true", TRUE),
            ("true && var.u", Unknown("variable.no_value")),
            ("var.u && true", Unknown("variable.no_value")),
            ("false || var.u", Unknown("variable.no_value")),
            ("var.u || false", Unknown("variable.no_value")),
            ("var.u && var.u", Unknown("variable.no_value")),
            ('"false" && var.u', FALSE),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(ev(text, **scope), expected)

    def test_an_unsupported_operand_is_never_replaced_by_the_decision(self) -> None:
        self.assertEqual(ev("false && abs(1)"), Unsupported("function.not_implemented:abs"))
        self.assertEqual(ev("abs(1) && false"), Unsupported("function.not_implemented:abs"))
        self.assertEqual(ev("true || abs(1)"), Unsupported("function.not_implemented:abs"))

    def test_a_reference_is_not_a_decided_operand(self) -> None:
        resolver = FakeResolver({("resource", "aws_x", "y"): single("aws_x.y")})
        self.assertEqual(
            ev("false && aws_x.y.id", resources=resolver), Unknown("ref.derived:aws_x.y.id")
        )

    def test_the_left_operand_is_always_evaluated(self) -> None:
        self.assertIsInstance(ev("[1][5] && false"), Unsupported)


class TestConditional(unittest.TestCase):
    def test_taken_branch(self) -> None:
        self.assertEqual(ev("true ? 1 : 2"), Known(1))
        self.assertEqual(ev("false ? 1 : 2"), Known(2))
        self.assertEqual(ev('"true" ? 1 : 2'), Known(1))  # probe

    def test_branch_types_are_unified(self) -> None:
        self.assertEqual(ev('true ? 1 : "a"'), Known("1"))  # probe
        self.assertEqual(ev('false ? [1] : ["a"]'), tup("a"))
        self.assertEqual(ev("true ? null : 1"), NULL)  # probe
        self.assertEqual(ev("true ? {a=1} : {b=2}"), obj(a=1))  # probe

    def test_branches_with_no_common_type_are_unsupported(self) -> None:
        self.assertIsInstance(ev('true ? [1] : "a"'), Unsupported)

    def test_bad_conditions_are_unsupported(self) -> None:
        for text in ('"" ? 1 : 2', "null ? 1 : 2", "1 ? 1 : 2", "[] ? 1 : 2"):
            with self.subTest(text=text):
                self.assertIsInstance(ev(text), Unsupported)

    def test_an_error_in_the_branch_not_taken_is_ignored(self) -> None:
        # Terraform reports only the diagnostics of the branch it takes (HCL ConditionalExpr.Value)
        self.assertEqual(ev("true ? 1 : [1][5]"), Known(1))
        self.assertEqual(ev("false ? [1][5] : 2"), Known(2))
        self.assertEqual(ev("true ? 1 : abs(1)"), Known(1))

    def test_an_unknown_branch_not_taken_does_not_change_the_result(self) -> None:
        scope = {"variables": {"u": Unknown("variable.no_value")}}
        self.assertEqual(ev("true ? 1 : var.u", **scope), Known(1))
        self.assertEqual(ev("false ? var.u : 2", **scope), Known(2))

    def test_the_branch_taken_decides_unknown(self) -> None:
        scope = {"variables": {"u": Unknown("variable.no_value")}}
        self.assertEqual(ev("true ? var.u : 2", **scope), Unknown("variable.no_value"))

    def test_an_unknown_condition_is_unknown(self) -> None:
        scope = {"variables": {"u": Unknown("variable.no_value")}}
        self.assertEqual(ev("var.u ? 1 : 1", **scope), Unknown("variable.no_value"))

    def test_an_undeclared_reference_in_the_branch_not_taken_is_still_reported(self) -> None:
        value, scope = run("true ? 1 : var.nope")
        self.assertEqual(value, Known(1))
        self.assertEqual([d.code for d in scope.diagnostics], ["eval.undeclared_reference"])


class TestForExpressions(unittest.TestCase):
    def test_tuple_and_object_results(self) -> None:
        self.assertEqual(ev("[for x in [1,2,3] : x * 2 if x > 1]"), tup(4, 6))  # probe
        self.assertEqual(ev("{for k, v in {a=1,b=2} : k => v}"), obj(a=1, b=2))  # probe
        self.assertEqual(ev('{for i, x in ["a","b"] : x => i}'), obj(a=0, b=1))  # probe

    def test_iteration_order(self) -> None:
        self.assertEqual(ev("[for k, v in {b=1,a=2} : k]"), tup("a", "b"))  # probe
        self.assertEqual(ev('[for x in toset(["b","a"]) : x]'), tup("a", "b"))  # probe
        self.assertEqual(ev("[for x in {b=1,a=2} : x]"), tup(2, 1))  # probe

    def test_the_key_of_a_set_is_its_element(self) -> None:
        self.assertEqual(ev('[for i, x in toset(["a"]) : i]'), tup("a"))  # probe

    def test_duplicate_keys(self) -> None:
        self.assertIsInstance(ev('{for x in ["a","a"] : x => 1}'), Unsupported)  # probe: error
        self.assertEqual(ev('{for x in ["a","a"] : x => 1...}'), obj(a=tup(1, 1)))  # probe

    def test_not_iterable(self) -> None:
        for text in ('[for x in "abc" : x]', "[for x in null : x]", "[for x in 1 : x]"):  # probe
            with self.subTest(text=text):
                self.assertIsInstance(ev(text), Unsupported)

    def test_unknown_collection_or_condition(self) -> None:
        scope = {"variables": {"u": Unknown("variable.no_value"), "l": tup(1, 2)}}
        self.assertEqual(ev("[for x in var.u : x]", **scope), Unknown("variable.no_value"))
        self.assertEqual(ev("[for x in var.l : x if var.u]", **scope), Unknown("variable.no_value"))

    def test_unknown_element_stays_an_element(self) -> None:
        scope = {"variables": {"l": tup(1, Unknown("variable.no_value"))}}
        self.assertEqual(ev("[for x in var.l : x]", **scope), tup(1, Unknown("variable.no_value")))

    def test_unknown_key_makes_the_object_unknown(self) -> None:
        scope = {"variables": {"l": tup("a", Unknown("variable.no_value"))}}
        self.assertEqual(ev("{for x in var.l : x => 1}", **scope), Unknown("variable.no_value"))

    def test_the_variable_shadows_and_ends(self) -> None:
        scope = {"variables": {"x": Known("outer")}}
        self.assertEqual(ev("[for x in [1] : x]", **scope), tup(1))
        self.assertEqual(ev("[[for x in [1] : x], var.x]", **scope), tup(tup(1), "outer"))

    def test_nested(self) -> None:
        self.assertEqual(
            ev("[for x in [1,2] : [for y in [10,20] : x * y]]"), tup(tup(10, 20), tup(20, 40))
        )


class TestIndexAttributeSplat(unittest.TestCase):
    def test_index(self) -> None:
        self.assertEqual(ev("[1,2,3][1]"), Known(2))
        self.assertEqual(ev("[1,2][1.0]"), Known(2))  # probe
        self.assertEqual(ev('[1,2]["1"]'), Known(2))  # probe
        self.assertEqual(ev('{a=1}["a"]'), Known(1))

    def test_bad_index_is_unsupported(self) -> None:
        for text in (
            "[1,2][5]",
            "[1,2][-1]",
            '{a=1}["b"]',
            "{a=1}[0]",
            "toset([1,2])[0]",
            '"abc"[0]',
            "[1][1.5]",
            "null[0]",
        ):
            with self.subTest(text=text):
                self.assertIsInstance(ev(text), Unsupported)  # probe: each is an error

    def test_attribute(self) -> None:
        self.assertEqual(ev("{a=1}.a"), Known(1))
        self.assertEqual(ev("{a={b=2}}.a.b"), Known(2))
        self.assertIsInstance(ev("{a=1}.b"), Unsupported)  # probe
        self.assertIsInstance(ev("null.a"), Unsupported)
        self.assertIsInstance(ev("[1].a"), Unsupported)

    def test_legacy_index(self) -> None:
        self.assertEqual(ev("var.l.1", variables={"l": tup("a", "b")}), Known("b"))

    def test_full_splat(self) -> None:
        self.assertEqual(ev("[{a=1},{a=2}][*].a"), tup(1, 2))  # probe
        self.assertEqual(ev("{a=[1,2]}.a[*]"), tup(1, 2))  # probe
        self.assertEqual(ev("null[*]"), tup())  # probe
        self.assertEqual(ev("1[*]"), tup(1))  # probe
        self.assertEqual(ev("{a=1}[*]"), tup(obj(a=1)))  # probe

    def test_attribute_splat(self) -> None:
        self.assertEqual(ev("[{a=1},{a=2}].*.a"), tup(1, 2))  # probe

    def test_splat_over_a_set(self) -> None:
        self.assertEqual(ev('toset(["b","a"])[*]'), tup("a", "b"))

    def test_unknown_in_index_or_collection(self) -> None:
        scope = {"variables": {"u": Unknown("variable.no_value")}}
        self.assertEqual(ev("[1,2][var.u]", **scope), Unknown("variable.no_value"))
        self.assertEqual(ev("var.u[0]", **scope), Unknown("variable.no_value"))
        self.assertEqual(ev("var.u.a", **scope), Unknown("variable.no_value"))
        self.assertEqual(ev("var.u[*].a", **scope), Unknown("variable.no_value"))


class TestReferences(unittest.TestCase):
    def test_variables(self) -> None:
        scope = {"variables": {"s": Known("x"), "o": obj(a=1, b=tup(1, 2))}}
        self.assertEqual(ev("var.s", **scope), Known("x"))
        self.assertEqual(ev("var.o.b[1]", **scope), Known(2))

    def test_undeclared_variable_is_reported_and_unsupported(self) -> None:
        value, scope = run("var.nope")
        self.assertEqual(value, Unsupported("reference.undeclared"))
        self.assertEqual(
            [(d.severity, d.code) for d in scope.diagnostics],
            [(DiagnosticSeverity.INVALID, "eval.undeclared_reference")],
        )
        self.assertEqual((scope.diagnostics[0].file, scope.diagnostics[0].line), ("t.tf", 1))

    def test_locals(self) -> None:
        local_expressions = {
            n: parse_expression(t)
            for n, t in {"a": "1", "b": "local.a + 1", "c": '"${local.b}-${var.v}"'}.items()
        }
        scope = {"locals": local_expressions, "variables": {"v": Known("z")}}
        self.assertEqual(ev("local.c", **scope), Known("2-z"))

    def test_locals_are_evaluated_once(self) -> None:
        local_expressions = {"a": parse_expression("[1]")}
        built = Scope(locals=local_expressions)
        first = evaluate_expression(parse_expression("local.a"), built)
        second = evaluate_expression(parse_expression("local.a"), built)
        self.assertIs(first, second)

    def test_a_cycle_between_locals_is_invalid_and_unsupported(self) -> None:
        local_expressions = {
            "a": parse_expression("local.b"),
            "b": parse_expression("local.a"),
        }  # probe: "Cycle:"
        value, scope = run("local.a", locals=local_expressions)
        self.assertEqual(value, Unsupported("local.cycle"))
        self.assertIn("eval.cycle", [d.code for d in scope.diagnostics])
        value, scope = run("local.s", locals={"s": parse_expression("local.s")})
        self.assertIsInstance(value, Unsupported)

    def test_undeclared_local(self) -> None:
        value, scope = run("local.nope")
        self.assertIsInstance(value, Unsupported)
        self.assertEqual([d.code for d in scope.diagnostics], ["eval.undeclared_reference"])

    def test_each(self) -> None:
        base = Scope()
        inside = base.with_instance(each=(Known("k"), Known("v")))
        self.assertEqual(evaluate_expression(parse_expression("each.key"), inside), Known("k"))
        self.assertEqual(
            evaluate_expression(parse_expression('"${each.key}=${each.value}"'), inside),
            Known("k=v"),
        )

    def test_each_outside_for_each_is_invalid(self) -> None:
        value, scope = run("each.key")  # probe: validate rejects
        self.assertIsInstance(value, Unsupported)
        self.assertEqual([d.code for d in scope.diagnostics], ["eval.each_context"])

    def test_count_index(self) -> None:
        inside = Scope().with_instance(count_index=Known(2))
        self.assertEqual(evaluate_expression(parse_expression("count.index + 1"), inside), Known(3))

    def test_count_index_outside_count_is_invalid(self) -> None:
        value, scope = run("count.index")
        self.assertIsInstance(value, Unsupported)
        self.assertEqual([d.code for d in scope.diagnostics], ["eval.count_context"])

    def test_references_that_are_not_evaluated(self) -> None:
        for text, reason in (
            ("path.module", "reference.path"),
            ("terraform.workspace", "reference.terraform"),
            ("module.m.out", "reference.module"),
            ("self.id", "reference.self"),
        ):
            with self.subTest(text=text):
                self.assertEqual(ev(text), Unsupported(reason))

    def test_a_malformed_reference_is_unsupported(self) -> None:
        for text in ("var", "local", "each", "count.nope", "each.nope", "var[0]"):
            with self.subTest(text=text):
                self.assertIsInstance(
                    ev(text, each=(Known(1), Known(2)), count_index=Known(1)), Unsupported
                )

    def test_data_sources_are_unknown(self) -> None:
        resolver = FakeResolver({("data", "aws_ami", "x"): single("data.aws_ami.x")})
        self.assertEqual(ev("data.aws_ami.x.id", resources=resolver), Unknown("data_source"))
        self.assertEqual(ev("data.aws_ami.x", resources=resolver), Unknown("data_source"))
        value, scope = run("data.aws_ami.nope.id", resources=resolver)
        self.assertIsInstance(value, Unsupported)
        self.assertEqual([d.code for d in scope.diagnostics], ["eval.undeclared_reference"])


class TestResourceReferences(unittest.TestCase):
    def resolver(self) -> FakeResolver:
        counted = FakeResource(
            "count",
            tuple(
                FakeInstance(f"aws_subnet.s[{i}]", Known(i), {"cidr": Known(f"10.0.{i}.0/24")})
                for i in range(3)
            ),
        )
        keyed = FakeResource(
            "for_each",
            tuple(
                FakeInstance(f'aws_sg.g["{n}"]', Known(n), {"name": Known(f"sg-{n}")})
                for n in ("a", "b")
            ),
        )
        return FakeResolver(
            {
                ("resource", "aws_security_group", "app"): single(
                    "aws_security_group.app", name=Known("app")
                ),
                ("resource", "aws_subnet", "s"): counted,
                ("resource", "aws_sg", "g"): keyed,
                ("resource", "aws_x", "none"): FakeResource("count", ()),
                ("resource", "aws_x", "later"): FakeResource("count", Unknown("expansion.unknown")),
            }
        )

    def test_id_is_a_reference(self) -> None:
        self.assertEqual(
            ev("aws_security_group.app.id", resources=self.resolver()),
            Ref("aws_security_group.app", "id"),
        )

    def test_a_configured_argument_is_its_value(self) -> None:
        self.assertEqual(ev("aws_security_group.app.name", resources=self.resolver()), Known("app"))

    def test_any_other_attribute_is_unknown(self) -> None:
        self.assertEqual(
            ev("aws_security_group.app.arn", resources=self.resolver()),
            Unknown("resource.computed:arn"),
        )

    def test_a_reference_passes_through_collections_and_single_interpolation(self) -> None:
        ref = Ref("aws_security_group.app", "id")
        self.assertEqual(ev("[aws_security_group.app.id]", resources=self.resolver()), tup(ref))
        self.assertEqual(ev('"${aws_security_group.app.id}"', resources=self.resolver()), ref)
        self.assertEqual(
            ev("{sg = aws_security_group.app.id}", resources=self.resolver()), obj(sg=ref)
        )

    def test_anything_computed_from_a_reference_is_unknown(self) -> None:
        for text in (
            '"${aws_security_group.app.id}-x"',
            "aws_security_group.app.id + 1",
            "upper(aws_security_group.app.id)",
            "length(aws_security_group.app.id)",
            "aws_security_group.app.id ? 1 : 2",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    ev(text, resources=self.resolver()),
                    Unknown("ref.derived:aws_security_group.app.id"),
                )

    def test_references_compare_by_instance(self) -> None:
        resolver = self.resolver()
        self.assertEqual(
            ev("aws_security_group.app.id == aws_security_group.app.id", resources=resolver), TRUE
        )
        self.assertEqual(ev("aws_subnet.s[0].id == aws_subnet.s[1].id", resources=resolver), FALSE)
        self.assertIsInstance(
            ev('aws_security_group.app.id == "sg-1"', resources=resolver), Unknown
        )

    def test_count_instances(self) -> None:
        resolver = self.resolver()
        self.assertEqual(ev("aws_subnet.s[1].id", resources=resolver), Ref("aws_subnet.s[1]", "id"))
        self.assertEqual(ev("aws_subnet.s[2].cidr", resources=resolver), Known("10.0.2.0/24"))
        self.assertEqual(ev("aws_subnet.s[1 + 1].cidr", resources=resolver), Known("10.0.2.0/24"))
        self.assertIsInstance(ev("aws_subnet.s[3].id", resources=resolver), Unsupported)
        self.assertIsInstance(ev("aws_subnet.s[-1].id", resources=resolver), Unsupported)

    def test_for_each_instances(self) -> None:
        resolver = self.resolver()
        self.assertEqual(ev('aws_sg.g["b"].name', resources=resolver), Known("sg-b"))
        self.assertEqual(ev('aws_sg.g["a"].id', resources=resolver), Ref('aws_sg.g["a"]', "id"))
        self.assertIsInstance(ev('aws_sg.g["c"].id', resources=resolver), Unsupported)

    def test_splat_over_instances(self) -> None:
        resolver = self.resolver()
        self.assertEqual(
            ev("aws_subnet.s[*].id", resources=resolver),
            tup(*[Ref(f"aws_subnet.s[{i}]", "id") for i in range(3)]),
        )
        self.assertEqual(ev("aws_sg.g[*].name", resources=resolver), tup("sg-a", "sg-b"))
        self.assertEqual(ev("aws_x.none[*].id", resources=resolver), tup())
        self.assertEqual(
            ev("aws_security_group.app[*].id", resources=resolver),
            tup(Ref("aws_security_group.app", "id")),
        )

    def test_for_over_instances(self) -> None:
        resolver = self.resolver()
        self.assertEqual(
            ev("[for s in aws_subnet.s : s.cidr]", resources=resolver),
            tup("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"),
        )
        self.assertEqual(
            ev("{for k, g in aws_sg.g : k => g.name}", resources=resolver), obj(a="sg-a", b="sg-b")
        )
        self.assertEqual(ev("length([for s in aws_subnet.s : s.id])", resources=resolver), Known(3))

    def test_a_whole_resource_is_an_object_a_tuple_or_a_map_of_instances(self) -> None:
        # "References to Named Values": a resource is an object, or a list (count) or a map
        # (for_each) of objects; an instance object holds id and the configured arguments
        resolver = self.resolver()
        app = obj(id=Ref("aws_security_group.app", "id"), name="app")
        self.assertEqual(ev("aws_security_group.app", resources=resolver), app)
        self.assertEqual(ev("[aws_security_group.app]", resources=resolver), tup(app))
        subnets = ev("aws_subnet.s", resources=resolver)
        self.assertEqual(
            subnets,
            tup(
                *[obj(id=Ref(f"aws_subnet.s[{i}]", "id"), cidr=f"10.0.{i}.0/24") for i in range(3)]
            ),
        )
        self.assertEqual(ev("length(aws_subnet.s)", resources=resolver), Known(3))
        self.assertEqual(ev("length(aws_x.none)", resources=resolver), Known(0))
        groups = ev("aws_sg.g", resources=resolver)
        self.assertEqual(
            groups,
            obj(
                a=obj(id=Ref('aws_sg.g["a"]', "id"), name="sg-a"),
                b=obj(id=Ref('aws_sg.g["b"]', "id"), name="sg-b"),
            ),
        )
        self.assertEqual(ev("keys(aws_sg.g)", resources=resolver), tup("a", "b"))

    def test_an_attribute_not_configured_is_computed_through_the_object_too(self) -> None:
        # C-110 (authors' condition): the same Unknown("resource.computed:<attr>") as a direct
        # reference, whatever the way the instance object is reached
        resolver = self.resolver()
        direct = ev("aws_security_group.app.arn", resources=resolver)
        self.assertEqual(direct, Unknown("resource.computed:arn"))
        local = {
            "all": parse_expression("aws_subnet.s"),
            "one": parse_expression("aws_security_group.app"),
        }
        cases = [
            "local.all[0].arn",
            'local.all[0]["arn"]',
            "local.one.arn",
            'local.one["arn"]',
            "local.all[*].arn",
            "[for s in local.all : s.arn]",
            "aws_subnet.s[0].arn",
        ]
        for text in cases:
            with self.subTest(text=text):
                value = ev(text, locals=local, resources=resolver)
                expected = Unknown("resource.computed:arn")
                if "*" in text or "for" in text:
                    expected = tup(*[expected] * 3)
                self.assertEqual(value, expected)
        self.assertEqual(
            ev("local.all[0].cidr", locals=local, resources=resolver), Known("10.0.0.0/24")
        )
        self.assertEqual(
            ev("local.one.id", locals=local, resources=resolver),
            Ref("aws_security_group.app", "id"),
        )

    def test_the_marker_is_only_on_instance_objects(self) -> None:
        # a plain object, or a merge of an instance object, still has no such attribute
        resolver = self.resolver()
        local = {"one": parse_expression("aws_security_group.app")}
        self.assertIsInstance(ev("{a = 1}.arn", resources=resolver), Unsupported)
        self.assertIsInstance(
            ev("merge(local.one, {}).arn", locals=local, resources=resolver), Unsupported
        )
        self.assertEqual(
            ev("local.one", locals=local, resources=resolver),
            obj(id=Ref("aws_security_group.app", "id"), name="app"),
        )

    def test_an_attribute_without_an_index_is_unsupported(self) -> None:
        self.assertEqual(
            ev("aws_subnet.s.id", resources=self.resolver()), Unsupported("reference.missing_key")
        )

    def test_index_on_a_single_instance_is_unsupported(self) -> None:
        self.assertIsInstance(
            ev("aws_security_group.app[0].id", resources=self.resolver()), Unsupported
        )

    def test_unknown_expansion_is_unknown(self) -> None:
        self.assertEqual(
            ev("aws_x.later[0].id", resources=self.resolver()), Unknown("expansion.unknown")
        )

    def test_undeclared_resource_is_reported(self) -> None:
        value, scope = run("aws_nothing.x.id", resources=self.resolver())
        self.assertIsInstance(value, Unsupported)
        self.assertEqual([d.code for d in scope.diagnostics], ["eval.undeclared_reference"])
        value, scope = run("aws_nothing.x.id")
        self.assertEqual([d.code for d in scope.diagnostics], ["eval.undeclared_reference"])


class TestPropagation(unittest.TestCase):
    """C-102: unsupported beats unknown, and unknown beats known."""

    U = Unknown("variable.no_value")
    S = Unsupported("function.not_implemented:abs")

    def scope(self) -> dict[str, object]:
        return {"variables": {"u": self.U, "l": tup(1, self.U), "m": obj(a=self.U)}}

    def test_an_operation_on_an_unknown_operand_is_unknown(self) -> None:
        for text in (
            "var.u + 1",
            "1 + var.u",
            "-var.u",
            "!var.u",
            "var.u == 1",
            "1 < var.u",
            "var.u && true",
            "length(var.u)",
            "upper(var.u)",
            "var.u ? 1 : 2",
        ):
            with self.subTest(text=text):
                self.assertEqual(ev(text, **self.scope()), self.U)

    def test_unsupported_beats_unknown(self) -> None:
        for text in (
            "var.u + abs(1)",
            "abs(1) + var.u",
            '"${var.u}${abs(1)}"',
            "var.u == abs(1)",
            "abs(1) == var.u",
        ):
            with self.subTest(text=text):
                self.assertEqual(ev(text, **self.scope()), self.S)

    def test_an_unsupported_element_stays_an_element(self) -> None:
        self.assertEqual(ev("[1, abs(1)]"), tup(1, self.S))
        self.assertEqual(ev("length([1, abs(1)])"), Known(2))
        self.assertEqual(ev("[1, abs(1)][1]"), self.S)

    def test_unsupported_operand_is_unsupported(self) -> None:
        for text in (
            "abs(1) + 1",
            "!abs(1)",
            "abs(1) ? 1 : 2",
            "length(abs(1))",
            "abs(1)[0]",
            "abs(1).a",
        ):
            with self.subTest(text=text):
                self.assertEqual(ev(text), self.S)

    def test_a_collection_with_an_unknown_element_is_still_a_collection(self) -> None:
        self.assertEqual(ev("var.l", **self.scope()), tup(1, self.U))
        self.assertEqual(ev("length(var.l)", **self.scope()), Known(2))
        self.assertEqual(ev("var.l[0]", **self.scope()), Known(1))
        self.assertEqual(ev("var.l[1]", **self.scope()), self.U)
        self.assertEqual(ev("var.m.a", **self.scope()), self.U)
        self.assertEqual(ev("keys(var.m)", **self.scope()), tup("a"))

    def test_an_operation_that_needs_the_whole_value_is_unknown(self) -> None:
        self.assertEqual(ev("distinct(var.l)", **self.scope()), self.U)
        self.assertEqual(ev('join(",", var.l)', **self.scope()), self.U)
        # an unknown element might itself be a list, so the length of the result is unknown
        self.assertEqual(ev("flatten([var.l, var.l])", **self.scope()), self.U)
        self.assertEqual(ev("flatten([var.u])", **self.scope()), self.U)

    def test_an_unknown_is_never_replaced_by_a_default(self) -> None:
        self.assertEqual(ev('coalesce(var.u, "x")', **self.scope()), self.U)
        self.assertEqual(ev('lookup(var.m, "a", "d")', **self.scope()), self.U)
        self.assertEqual(ev('lookup({a = 1}, var.u, "d")', **self.scope()), self.U)


class TestLimits(unittest.TestCase):
    """C-105. The step count of a tuple of n literals is n + 1 (the tuple and each literal)."""

    def test_steps_at_the_limit_and_one_over(self) -> None:
        at_limit = "[" + ",".join(["0"] * (MAX_STEPS - 1)) + "]"
        over = "[" + ",".join(["0"] * MAX_STEPS) + "]"
        self.assertIsInstance(ev(at_limit), Known)
        self.assertEqual(ev(over), Unsupported("limit.eval_steps"))

    def test_for_elements_at_the_limit_and_one_over(self) -> None:
        scope_ok = {"variables": {"l": known_tuple(Known(i) for i in range(MAX_FOR_ELEMENTS))}}
        scope_over = {
            "variables": {"l": known_tuple(Known(i) for i in range(MAX_FOR_ELEMENTS + 1))}
        }
        ok = ev("[for x in var.l : x]", **scope_ok)
        self.assertIsInstance(ok, Known)
        self.assertEqual(len(ok.value), MAX_FOR_ELEMENTS)  # type: ignore[union-attr]
        self.assertEqual(
            ev("[for x in var.l : x]", **scope_over), Unsupported("limit.for_elements")
        )
        self.assertEqual(
            ev("{for x in var.l : x => x}", **scope_over), Unsupported("limit.for_elements")
        )
        # a condition keeps the result within the limit
        self.assertIsInstance(ev("[for x in var.l : x if x < 5]", **scope_over), Known)

    def test_reference_depth_at_the_limit_and_one_over(self) -> None:
        # local l0 is a literal, l_i is local.l_{i-1}; evaluating local.l_m needs depth m + 2
        def chain(length: int) -> dict[str, Expression]:
            locals_: dict[str, Expression] = {"l0": parse_expression("1")}
            for i in range(1, length + 1):
                locals_[f"l{i}"] = parse_expression(f"local.l{i - 1}")
            return locals_

        longest = MAX_DEPTH - 2
        self.assertEqual(ev(f"local.l{longest}", locals=chain(longest)), Known(1))
        self.assertEqual(
            ev(f"local.l{longest + 1}", locals=chain(longest + 1)), Unsupported("limit.depth")
        )
        self.assertEqual(ev("local.l5000", locals=chain(5000)), Unsupported("limit.depth"))

    def test_no_exception_for_deeply_nested_input(self) -> None:
        text = "(" * 60 + "1" + ")" * 60
        self.assertEqual(ev(text), Known(1))


REGISTRY_NAMES = ("REASONS", "FUNCTION_REASONS", "UNKNOWN_REASONS", "DIAGNOSTICS")


def scan(name: str) -> tuple[set[str], set[str], set[str], set[str]]:
    """(reasons given to Fail/Unsupported/_Abort, prefixes of Unknown reasons, diagnostic codes,
    every other string constant) of one module, not counting the registry tables themselves."""
    source = (ROOT / "core" / "terraform_model" / name).read_text(encoding="utf-8")
    tree = ast.parse(source)
    skipped: set[int] = set()
    for node in ast.walk(tree):
        targets = node.targets if isinstance(node, ast.Assign) else [getattr(node, "target", None)]
        if any(isinstance(t, ast.Name) and t.id in REGISTRY_NAMES for t in targets):
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
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called = node.func.id
            elif isinstance(node.func, ast.Attribute):
                called = node.func.attr
            else:
                continue
            first = node.args[0] if node.args else None
            if called == "report" and len(node.args) >= 1 and isinstance(first, ast.Constant):
                diagnostics.add(first.value)
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                text = first.value
            elif isinstance(first, ast.JoinedStr) and isinstance(first.values[0], ast.Constant):
                text = str(first.values[0].value)
            else:
                continue
            if called in ("Fail", "Unsupported", "_Abort"):
                reasons.add(text.rstrip(":"))
            elif called == "Unknown":
                unknowns.add(text.rstrip(":"))
    return reasons, unknowns, diagnostics, strings


class TestReasonRegistries(unittest.TestCase):
    MODULES = ("convert.py", "functions.py", "evaluate.py")

    def test_every_reason_in_the_source_is_registered_and_every_registered_one_is_used(
        self,
    ) -> None:
        registered = {*convert.REASONS, *functions.FUNCTION_REASONS, *evaluate.REASONS}
        used: set[str] = set()
        strings: set[str] = set()
        for name in self.MODULES:
            reasons, _, _, constants = scan(name)
            used |= reasons
            strings |= constants
        self.assertEqual(sorted(used - registered), [])
        # a reason that is only a table value (the roots of _OTHER_ROOTS) still appears as a string
        unused = registered - used - strings - {"function.not_implemented"}
        self.assertEqual(sorted(unused), [])

    def test_every_unknown_reason_in_the_source_is_registered(self) -> None:
        for name in self.MODULES:
            _, unknowns, _, _ = scan(name)
            self.assertLessEqual(unknowns, set(evaluate.UNKNOWN_REASONS), name)

    def test_the_diagnostic_codes_are_registered(self) -> None:
        _, _, diagnostics, strings = scan("evaluate.py")
        self.assertLessEqual(diagnostics, set(evaluate.DIAGNOSTICS))
        self.assertEqual(sorted(set(evaluate.DIAGNOSTICS) - diagnostics - strings), [])

    def test_the_function_subset_is_exactly_the_prompts_list(self) -> None:
        expected = {
            "toset", "tolist", "tomap", "tostring", "tonumber", "tobool", "concat", "merge",
            "length", "element", "lookup", "contains", "distinct", "flatten", "keys", "values",
            "coalesce", "compact", "lower", "upper", "join", "split", "format", "cidrsubnet",
            "cidrhost",
        }  # fmt: skip
        self.assertEqual(set(functions.FUNCTIONS), expected)

    def test_every_other_function_is_unsupported_with_its_name(self) -> None:
        for name in (
            "abs",
            "max",
            "try",
            "can",
            "regex",
            "jsonencode",
            "file",
            "timestamp",
            "uuid",
            "templatefile",
            "base64encode",
            "provider::p::f",
        ):
            with self.subTest(name=name):
                self.assertEqual(ev(f"{name}(1)"), Unsupported(f"function.not_implemented:{name}"))


class TestPurity(unittest.TestCase):
    def test_the_same_input_gives_the_same_value(self) -> None:
        text = '{for k, v in {b = 1, a = [for x in toset(["z", "y"]) : upper(x)]} : k => v}'
        first = ev(text)
        for _ in range(5):
            self.assertEqual(ev(text), first)

    def test_evaluating_does_not_change_the_scope(self) -> None:
        variables = {"l": tup(3, 1, 2)}
        scope = Scope(variables=variables)
        evaluate_expression(parse_expression("[for x in var.l : x * 2]"), scope)
        self.assertEqual(variables, {"l": tup(3, 1, 2)})
        self.assertEqual(scope.diagnostics, ())

    def test_sets_have_a_canonical_order(self) -> None:
        self.assertEqual(ev('toset(["b", "a", "b"])'), known_set([Known("a"), Known("b")]))


if __name__ == "__main__":
    unittest.main()
