"""The value model (P3a-2 step 2; Doc 04 §17; registry §2.2; C-102).

Expected values are written by hand from the register row C-102 and the propagation rule of the
P3a-2 prompt (Section 3): unsupported beats unknown, and unknown beats known.
"""

from __future__ import annotations

import json
import random
import unittest
from decimal import Decimal, Inexact
from types import MappingProxyType

from core.domain.hashing import canonical_json
from core.terraform_model.values import (
    EMPTY_TUPLE,
    FALSE,
    NULL,
    TRUE,
    Known,
    Ref,
    SetValue,
    Unknown,
    Unsupported,
    Value,
    ValueModelError,
    combine,
    combine_deep,
    first_problem,
    first_problem_value,
    from_json,
    is_fully_known,
    known_object,
    known_set,
    known_tuple,
    normalize_number,
    number_context,
    sort_key,
    to_canonical,
    walk,
)

U = Unknown("variable.no_value")
U2 = Unknown("data_source")
S = Unsupported("function.not_implemented:timestamp")
S2 = Unsupported("template.directive")
K = Known("x")


class TestConstruction(unittest.TestCase):
    def test_primitives(self) -> None:
        for payload in ("s", "", 0, 5, True, False, None, Decimal("1.5")):
            self.assertEqual(Known(payload).value, payload)

    def test_integral_numbers_are_ints(self) -> None:
        self.assertIs(type(Known(Decimal("2")).value), int)
        self.assertEqual(Known(Decimal("1E+3")).value, 1000)
        self.assertIs(type(Known(Decimal("1.0")).value), int)
        self.assertEqual(Known(Decimal("1.0")), Known(1))

    def test_decimals_are_normalized(self) -> None:
        self.assertEqual(str(Known(Decimal("1.50")).value), "1.5")
        self.assertEqual(Known(Decimal("1.50")), Known(Decimal("1.5")))
        self.assertEqual(normalize_number(Decimal("0.100")), Decimal("0.1"))

    def test_a_bool_is_not_a_number(self) -> None:
        self.assertIs(Known(True).value, True)
        with self.assertRaises(ValueModelError):
            normalize_number(True)

    def test_floats_are_refused_everywhere(self) -> None:
        for bad in (1.5, 0.0, float("inf"), float("nan")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueModelError):
                    Known(bad)
                with self.assertRaises(ValueModelError):
                    Known((Known(bad),))
                with self.assertRaises(ValueModelError):
                    from_json(bad)
                with self.assertRaises(ValueModelError):
                    from_json([1, {"a": bad}])

    def test_non_finite_decimals_are_refused(self) -> None:
        for text in ("NaN", "Infinity", "-Infinity", "sNaN"):
            with self.subTest(text=text), self.assertRaises(ValueModelError):
                Known(Decimal(text))

    def test_other_payloads_are_refused(self) -> None:
        for bad in ([], {1}, b"x", object(), (1,), (Known(1), 2), {"a": 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueModelError):
                Known(bad)

    def test_object_keys_are_sorted_strings(self) -> None:
        obj = Known({"b": Known(1), "a": Known(2)})
        self.assertEqual(list(obj.value), ["a", "b"])
        self.assertIsInstance(obj.value, MappingProxyType)
        with self.assertRaises(ValueModelError):
            Known({1: Known(1)})

    def test_an_object_cannot_be_changed(self) -> None:
        obj = known_object({"a": Known(1)})
        with self.assertRaises(TypeError):
            obj.value["a"] = Known(2)  # type: ignore[index]
        with self.assertRaises(AttributeError):
            obj.value = None  # type: ignore[misc]

    def test_reasons_are_required(self) -> None:
        for kind in (Unknown, Unsupported):
            with self.subTest(kind=kind.__name__):
                with self.assertRaises(ValueModelError):
                    kind("")
                with self.assertRaises(ValueModelError):
                    kind(None)  # type: ignore[arg-type]

    def test_a_reference_needs_an_address_and_an_attribute(self) -> None:
        self.assertEqual(Ref("aws_security_group.db", "id").attribute, "id")
        with self.assertRaises(ValueModelError):
            Ref("", "id")
        with self.assertRaises(ValueModelError):
            Ref("a.b", "")

    def test_the_constants(self) -> None:
        self.assertEqual(
            (NULL.value, TRUE.value, FALSE.value, EMPTY_TUPLE.value), (None, True, False, ())
        )

    def test_equality_is_structural(self) -> None:
        self.assertEqual(
            known_tuple([Known(1), U]), known_tuple([Known(1), Unknown("variable.no_value")])
        )
        self.assertNotEqual(known_tuple([Known(1)]), known_tuple([Known(2)]))
        self.assertNotEqual(Known("1"), Known(1))
        self.assertNotEqual(Known(True), Known("true"))
        self.assertEqual(Known({}).value, MappingProxyType({}))  # the empty object


class TestSets(unittest.TestCase):
    def test_a_set_is_sorted_and_deduplicated(self) -> None:
        a = known_set([Known("b"), Known("a"), Known("b")])
        b = known_set([Known("a"), Known("b")])
        self.assertEqual(a, b)
        assert isinstance(a.value, SetValue)
        self.assertEqual(a.value.elements, (Known("a"), Known("b")))

    def test_order_of_the_source_never_changes_a_set(self) -> None:
        rng = random.Random(7)
        items = [Known(i) for i in range(10)] + [Known(str(i)) for i in range(10)]
        reference = known_set(items)
        for _ in range(20):
            shuffled = items[:]
            rng.shuffle(shuffled)
            self.assertEqual(known_set(shuffled), reference)

    def test_numbers_sort_by_value_and_equal_numbers_merge(self) -> None:
        s = known_set([Known(10), Known(2), Known(Decimal("2.0")), Known(Decimal("1.5"))])
        assert isinstance(s.value, SetValue)
        self.assertEqual([e.value for e in s.value.elements], [Decimal("1.5"), 2, 10])  # type: ignore[union-attr]

    def test_unknown_elements_stay_and_come_last(self) -> None:
        s = known_set([U, Known("b"), U2, Known("a"), U])
        assert isinstance(s.value, SetValue)
        self.assertEqual(s.value.elements[:2], (Known("a"), Known("b")))
        self.assertEqual(len(s.value.elements), 5)  # two equal unknowns are not assumed equal
        self.assertFalse(is_fully_known(s))

    def test_kinds_do_not_compare_payloads(self) -> None:
        values = [
            Known(None),
            Known(True),
            Known(1),
            Known("a"),
            Known((Known(1),)),
            Ref("a.b", "id"),
            U,
            S,
        ]
        keys = [sort_key(v) for v in values]
        self.assertEqual(keys, sorted(keys))

    def test_a_set_of_sets_and_objects_is_canonical(self) -> None:
        inner1 = known_set([Known(2), Known(1)])
        inner2 = known_set([Known(1), Known(2)])
        self.assertEqual(known_set([inner1, inner2]), known_set([inner1]))
        o1 = known_object({"b": Known(1), "a": Known(2)})
        o2 = known_object({"a": Known(2), "b": Known(1)})
        self.assertEqual(known_set([o1, o2]), known_set([o1]))


class TestPropagation(unittest.TestCase):
    """combine(): unsupported beats unknown, unknown beats known (Section 3)."""

    def test_two_operands_every_combination(self) -> None:
        table = [
            # (left, right, expected result of combine)
            (K, K, None),
            (K, U, U),
            (U, K, U),
            (K, S, S),
            (S, K, S),
            (U, U2, U),  # the first unknown
            (U2, U, U2),
            (U, S, S),  # unsupported beats unknown, whatever the order
            (S, U, S),
            (S, S2, S),  # the first unsupported
            (S2, S, S2),
            (Ref("a.b", "id"), K, None),  # a reference is known
            (Ref("a.b", "id"), U, U),
        ]
        for left, right, expected in table:
            with self.subTest(left=left, right=right):
                self.assertEqual(combine(left, right), expected)

    def test_three_operands(self) -> None:
        self.assertEqual(combine(K, U, S), S)
        self.assertEqual(combine(U, K, U2), U)
        self.assertEqual(combine(K, K, K), None)
        self.assertEqual(combine(), None)

    def test_combine_looks_at_the_operands_not_inside_them(self) -> None:
        holder = known_tuple([U])
        self.assertIsNone(combine(holder))
        self.assertEqual(combine_deep(holder), U)

    def test_deep_combination_finds_nested_problems(self) -> None:
        nested = known_object({"a": known_tuple([K, known_tuple([U])]), "b": S})
        self.assertEqual(combine_deep(nested), S)
        self.assertEqual(combine_deep(known_tuple([K, U]), K), U)
        self.assertEqual(combine_deep(known_tuple([K]), K), None)
        self.assertEqual(combine_deep(known_tuple([U]), S), S)

    def test_a_collection_with_an_unknown_element_is_still_known(self) -> None:
        collection = known_tuple([Known(1), U])
        self.assertIsInstance(collection, Known)
        self.assertFalse(is_fully_known(collection))
        self.assertEqual(first_problem(collection), "variable.no_value")


class TestWalkOrder(unittest.TestCase):
    def test_walk_is_depth_first_in_canonical_order(self) -> None:
        value = known_object({"b": known_tuple([Known(2), Known(3)]), "a": Known(1)})
        kinds = [
            type(v.value).__name__ if isinstance(v, Known) else type(v).__name__
            for v in walk(value)
        ]
        self.assertEqual(kinds, ["mappingproxy", "int", "tuple", "int", "int"])
        values = [v.value for v in walk(value) if isinstance(v, Known) and isinstance(v.value, int)]
        self.assertEqual(values, [1, 2, 3])

    def test_first_problem_prefers_unsupported_over_an_earlier_unknown(self) -> None:
        value = known_tuple([U, Known(1), S, U2])
        self.assertEqual(first_problem(value), S.reason)
        self.assertEqual(first_problem_value(value), S)

    def test_first_problem_returns_the_first_unknown_in_order(self) -> None:
        self.assertEqual(first_problem(known_tuple([Known(1), U2, U])), U2.reason)
        self.assertEqual(first_problem(known_object({"z": U, "a": U2})), U2.reason)

    def test_no_problem(self) -> None:
        self.assertIsNone(first_problem(known_tuple([Known(1), Ref("a.b", "id")])))
        self.assertIsNone(first_problem(Known("x")))

    def test_deep_values_do_not_recurse(self) -> None:
        value: Value = Known(1)
        for _ in range(5000):
            value = Known((value,))
        self.assertEqual(sum(1 for _ in walk(value)), 5001)
        self.assertTrue(is_fully_known(value))


class TestNumbers(unittest.TestCase):
    def test_exact_operations_succeed(self) -> None:
        with number_context() as context:
            self.assertEqual(context.add(Decimal("0.1"), Decimal("0.2")), Decimal("0.3"))
            self.assertEqual(context.divide(Decimal(1), Decimal(4)), Decimal("0.25"))
            self.assertEqual(
                context.multiply(Decimal(10) ** 60, Decimal(10) ** 60), Decimal(10) ** 120
            )

    def test_an_inexact_result_is_refused_not_rounded(self) -> None:
        with number_context() as context, self.assertRaises(Inexact):
            context.divide(Decimal(1), Decimal(3))


class TestJson(unittest.TestCase):
    def test_from_json(self) -> None:
        value = from_json({"b": [1, "x", None, True], "a": {"c": 2}})
        self.assertEqual(
            value,
            known_object(
                {
                    "a": known_object({"c": Known(2)}),
                    "b": known_tuple([Known(1), Known("x"), NULL, TRUE]),
                }
            ),
        )

    def test_decimals_and_ints_pass_but_floats_do_not(self) -> None:
        self.assertEqual(from_json(Decimal("1.5")), Known(Decimal("1.5")))
        with self.assertRaises(ValueModelError):
            from_json({"a": [1.5]})
        with self.assertRaises(ValueModelError):
            from_json(object())
        with self.assertRaises(ValueModelError):
            from_json({1: 2})

    def test_to_canonical_forms(self) -> None:
        value = known_object(
            {
                "n": Known(Decimal("1.5")),
                "i": Known(3),
                "s": known_set([Known("b"), Known("a")]),
                "r": Ref("aws_vpc.main", "id"),
                "u": U,
                "x": S,
                "t": known_tuple([TRUE, NULL]),
            }
        )
        self.assertEqual(
            to_canonical(value),
            {
                "i": 3,
                "n": {"$decimal": "1.5"},
                "r": {"$ref": "aws_vpc.main", "attribute": "id"},
                "s": {"$set": ["a", "b"]},
                "t": [True, None],
                "u": {"$unknown": "variable.no_value"},
                "x": {"$unsupported": "function.not_implemented:timestamp"},
            },
        )

    def test_the_canonical_form_hashes_with_the_project_json(self) -> None:
        text = canonical_json(to_canonical(from_json({"a": [1, "x"], "b": {"c": Decimal("2.5")}})))
        self.assertEqual(text, '{"a":[1,"x"],"b":{"c":{"$decimal":"2.5"}}}')


def random_value(rng: random.Random, depth: int = 0) -> Value:
    """A random tree of values (seeded), over every kind."""
    choices = ["int", "dec", "str", "bool", "null", "unknown", "unsupported", "ref"]
    if depth < 4:
        choices += ["tuple", "object", "set"]
    kind = rng.choice(choices)
    if kind == "int":
        return Known(rng.randint(-5, 5))
    if kind == "dec":
        return Known(Decimal(rng.randint(-500, 500)) / Decimal(100))
    if kind == "str":
        return Known(rng.choice(["", "a", "b", "é", "x y"]))
    if kind == "bool":
        return Known(rng.random() < 0.5)
    if kind == "null":
        return NULL
    if kind == "unknown":
        return Unknown(rng.choice(["a", "b"]))
    if kind == "unsupported":
        return Unsupported(rng.choice(["c", "d"]))
    if kind == "ref":
        return Ref(rng.choice(["a.b", 'a.b["k"]']), "id")
    items = [random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    if kind == "tuple":
        return known_tuple(items)
    if kind == "set":
        return known_set(items)
    return known_object({rng.choice("abcdef") + str(i): item for i, item in enumerate(items)})


def has_float(data: object) -> bool:
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, float):
            return True
        if isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


class TestPropertiesOfRandomValues(unittest.TestCase):
    SEEDS = (1, 20261025, 99)

    def values(self) -> list[Value]:
        out: list[Value] = []
        for seed in self.SEEDS:
            rng = random.Random(seed)
            out.extend(random_value(rng) for _ in range(300))
        return out

    def test_no_float_anywhere(self) -> None:
        for value in self.values():
            for item in walk(value):
                if isinstance(item, Known):
                    self.assertNotIsInstance(item.value, float)
            self.assertFalse(has_float(to_canonical(value)))
            json.dumps(to_canonical(value))  # serializable

    def test_the_canonical_form_is_deterministic_and_order_independent(self) -> None:
        for seed in self.SEEDS:
            first = random.Random(seed)
            second = random.Random(seed)
            for _ in range(100):
                a, b = random_value(first), random_value(second)
                self.assertEqual(a, b)
                self.assertEqual(canonical_json(to_canonical(a)), canonical_json(to_canonical(b)))

    def test_is_fully_known_agrees_with_first_problem(self) -> None:
        for value in self.values():
            self.assertEqual(is_fully_known(value), first_problem(value) is None)

    def test_a_problem_inside_is_always_found(self) -> None:
        rng = random.Random(5)
        for _ in range(200):
            base = random_value(rng)
            wrapped = known_tuple(
                [Known(1), known_object({"k": known_set([Known(2), base])}), Known(3)]
            )
            for problem in (U, S):
                holder = known_tuple([wrapped, problem])
                self.assertFalse(is_fully_known(holder))
                found = first_problem_value(holder)
                self.assertIsNotNone(found)
            if isinstance(first_problem_value(base), Unsupported):
                self.assertIsInstance(first_problem_value(wrapped), Unsupported)

    def test_kinds_are_totally_ordered(self) -> None:
        values = self.values()[:200]
        keys = sorted(sort_key(v) for v in values)
        self.assertEqual(len(keys), len(values))


if __name__ == "__main__":
    unittest.main()
