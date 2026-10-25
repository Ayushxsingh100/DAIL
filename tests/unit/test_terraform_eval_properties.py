"""Properties of the evaluator over seeded random expressions (P3a-2 step 6; Doc 12 §17).

Doc 12 §17: "Canonicalization is idempotent. Hash of canonical equivalent states is equal." Here:
evaluation is deterministic; no float ever appears; an expression with an unknown subexpression in
a value-determining position is never fully known; and reordering the keys of an object or the
elements of a set in the source never changes the value.

The generators are deterministic (``tests/eval_generators.py``); a failure names the seed, the
index and the expression text.
"""

from __future__ import annotations

import itertools
import random
import unittest
from decimal import Decimal

from core.domain.hashing import canonical_json
from core.terraform_model.evaluate import evaluate_expression
from core.terraform_model.values import (
    Known,
    Unknown,
    Value,
    first_problem,
    first_problem_value,
    is_fully_known,
    to_canonical,
    walk,
)
from tests import eval_generators as gen

SEEDS = (20261025, 3, 11)
CASES_PER_SEED = 200  # 600 expressions in all

# Each wrapper puts the unknown ``var.u`` where it decides (part of) the value of the result.
UNKNOWN_WRAPPERS = (
    "({e}) + var.u",
    "var.u + ({e})",
    "({e}) == var.u",
    "var.u != ({e})",
    "var.u ? ({e}) : ({e})",
    "[({e}), var.u]",
    '"${{({e})}}-${{var.u}}"',
    "[for x in var.u : ({e})]",
    "{{k = ({e}), j = var.u}}",
    "merge({{a = ({e})}}, var.u)",
    "length(var.u)",
    "({e}) && var.u",
    "var.u || ({e})",
    "coalesce(var.u, ({e}))",
    "concat([({e})], var.u)",
    "upper(var.u)",
    "var.u[0]",
    "var.u.a",
    "[({e}), var.u][1]",
    "tostring(var.u)",
)


def evaluate_text(text: str, scope=None) -> Value:  # type: ignore[no-untyped-def]
    scope = scope if scope is not None else gen.make_scope()
    return evaluate_expression(gen.parse_expression(text), scope)


def expressions() -> list[tuple[int, int, str]]:
    cases = []
    for seed in SEEDS:
        rng = random.Random(seed)
        generator = gen.ExpressionGenerator(rng)
        for index in range(CASES_PER_SEED):
            cases.append((seed, index, generator.expr(rng.randint(1, 5))))
    return cases


def typed_expressions() -> list[tuple[int, int, str]]:
    cases = []
    for seed in SEEDS:
        rng = random.Random(seed + 100)
        generator = gen.TypedGenerator(rng)
        for index in range(CASES_PER_SEED * 2):
            cases.append((seed, index, generator.any(rng.randint(1, 4))))
    return cases


RANDOM_CASES = expressions()  # mostly ill-typed: they test that nothing escapes as an exception
TYPED_CASES = typed_expressions()  # mostly well-typed: they test the values
CASES = RANDOM_CASES + TYPED_CASES


def no_float(value: Value) -> bool:
    for item in walk(value):
        if isinstance(item, Known) and isinstance(item.value, float):
            return False
    return True


class TestGeneratedExpressions(unittest.TestCase):
    def test_there_are_at_least_500_distinct_expressions_of_each_kind(self) -> None:
        for cases in (RANDOM_CASES, TYPED_CASES):
            self.assertGreaterEqual(len({text for _, _, text in cases}), 500)

    def test_the_typed_expressions_mostly_evaluate_to_known_values(self) -> None:
        known = sum(is_fully_known(evaluate_text(text)) for _, _, text in TYPED_CASES)
        self.assertGreater(known, 0.85 * len(TYPED_CASES))

    def test_every_expression_parses(self) -> None:
        for seed, index, text in CASES:
            try:
                gen.parse_expression(text)
            except Exception as error:  # noqa: BLE001 - the report names the case
                self.fail(f"seed {seed} case {index}: {text!r} does not parse: {error}")

    def test_evaluation_is_deterministic(self) -> None:
        for seed, index, text in CASES:
            with self.subTest(seed=seed, index=index):
                first = evaluate_text(text)
                self.assertEqual(first, evaluate_text(text), text)
                self.assertEqual(repr(first), repr(evaluate_text(text)), text)

    def test_no_float_ever_appears_and_every_value_has_a_canonical_form(self) -> None:
        for seed, index, text in CASES:
            value = evaluate_text(text)
            self.assertTrue(no_float(value), f"seed {seed} case {index}: {text}")
            canonical_json(to_canonical(value))  # raises on a float or an unsupported type

    def test_an_unknown_in_a_value_determining_position_is_never_fully_known(self) -> None:
        wrappers = itertools.cycle(UNKNOWN_WRAPPERS)
        for (seed, index, text), wrapper in zip(CASES, wrappers, strict=False):
            wrapped = wrapper.format(e=text)
            with self.subTest(seed=seed, index=index, wrapper=wrapper):
                result = evaluate_text(wrapped)
                self.assertFalse(is_fully_known(result), wrapped)

    def test_the_unknown_itself_is_what_comes_out_when_the_rest_is_a_known_primitive(self) -> None:
        # Stricter than "not fully known": an Unsupported result would also be "not fully known",
        # so with a fully known primitive E the first problem must be the unknown variable itself.
        wrappers = itertools.cycle(UNKNOWN_WRAPPERS)
        checked = 0
        for (seed, index, text), wrapper in zip(TYPED_CASES, wrappers, strict=False):
            base = evaluate_text(text)
            if not (
                isinstance(base, Known)
                and is_fully_known(base)
                and isinstance(base.value, str | int | bool | Decimal)
            ):
                continue
            checked += 1
            wrapped = wrapper.format(e=text)
            with self.subTest(seed=seed, index=index, wrapper=wrapper):
                self.assertEqual(
                    first_problem(evaluate_text(wrapped)), "variable.no_value", wrapped
                )
        self.assertGreater(checked, 250)

    def test_the_unknown_is_what_makes_the_wrapped_typed_expressions_not_known(self) -> None:
        # not vacuous: most wrapped well-typed expressions are Unknown, not Unsupported
        wrappers = itertools.cycle(UNKNOWN_WRAPPERS)
        unknown = 0
        for (_seed, _index, text), wrapper in zip(TYPED_CASES, wrappers, strict=False):
            problem = first_problem_value(evaluate_text(wrapper.format(e=text)))
            unknown += isinstance(problem, Unknown)
        self.assertGreater(unknown, 0.7 * len(TYPED_CASES))

    def test_the_wrapper_list_is_used_in_full(self) -> None:
        self.assertGreaterEqual(len(CASES), len(UNKNOWN_WRAPPERS))

    def test_the_unknown_variable_is_unknown_not_a_default(self) -> None:
        # the property above would be vacuous if var.u evaluated to a known value
        self.assertEqual(evaluate_text("var.u"), gen.scenario_variables()["u"])


class TestOrderInTheSourceNeverMatters(unittest.TestCase):
    ITEMS = ("1", '"b"', "2.5", "true", "null", "[1, 2]", "{x = 1}", "var.s", "local.k0", '"a"')

    def objects(self) -> list[tuple[int, int, list[str]]]:
        cases = []
        for seed in SEEDS:
            rng = random.Random(seed + 1)
            for index in range(70):
                keys = rng.sample(("a", "b", "c", "d", "e"), rng.randint(2, 5))
                cases.append((seed, index, [f"{key} = {rng.choice(self.ITEMS)}" for key in keys]))
        return cases

    def test_object_items_in_any_order(self) -> None:
        for seed, index, items in self.objects():
            baseline = evaluate_text("{" + ", ".join(items) + "}")
            rng = random.Random(index)
            for _ in range(3):
                shuffled = items[:]
                rng.shuffle(shuffled)
                with self.subTest(seed=seed, index=index):
                    self.assertEqual(evaluate_text("{" + ", ".join(shuffled) + "}"), baseline)

    def test_derived_values_follow_the_sorted_keys(self) -> None:
        for seed, index, items in self.objects():
            rng = random.Random(index)
            shuffled = items[:]
            rng.shuffle(shuffled)
            for template in (
                "keys({o})",
                "values({o})",
                "{{for k, v in {o} : k => v}}",
                "[for k, v in {o} : k]",
                "merge({o}, {{zz = 1}})",
            ):
                with self.subTest(seed=seed, index=index, template=template):
                    first = evaluate_text(template.format(o="{" + ", ".join(items) + "}"))
                    second = evaluate_text(template.format(o="{" + ", ".join(shuffled) + "}"))
                    self.assertEqual(first, second)

    def test_set_elements_in_any_order_and_with_duplicates(self) -> None:
        rng = random.Random(7)
        pool = ('"a"', '"b"', '"c"', '"10"', '"x y"')
        for index in range(100):
            elements = [rng.choice(pool) for _ in range(rng.randint(1, 6))]
            baseline = evaluate_text("toset([" + ", ".join(elements) + "])")
            shuffled = elements[:]
            rng.shuffle(shuffled)
            doubled = elements + elements[:2]
            with self.subTest(index=index):
                self.assertEqual(evaluate_text("toset([" + ", ".join(shuffled) + "])"), baseline)
                self.assertEqual(evaluate_text("toset([" + ", ".join(doubled) + "])"), baseline)
                self.assertEqual(
                    evaluate_text("[for x in toset([" + ", ".join(shuffled) + "]) : x]"),
                    evaluate_text("[for x in toset([" + ", ".join(elements) + "]) : x]"),
                )

    def test_numbers_in_sets_sort_by_value(self) -> None:
        rng = random.Random(8)
        for index in range(60):
            numbers = [
                str(rng.choice((1, 2, 3, 10, 20, 100, 25))) for _ in range(rng.randint(1, 6))
            ]
            shuffled = numbers[:]
            rng.shuffle(shuffled)
            with self.subTest(index=index):
                self.assertEqual(
                    evaluate_text("tolist(toset([" + ", ".join(numbers) + "]))"),
                    evaluate_text("tolist(toset([" + ", ".join(shuffled) + "]))"),
                )
        value = evaluate_text("tolist(toset([10, 2, 100, 1]))")
        self.assertEqual(value, evaluate_text("[1, 2, 10, 100]"))


if __name__ == "__main__":
    unittest.main()
