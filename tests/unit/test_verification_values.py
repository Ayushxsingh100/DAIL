"""The verifier's reader of the stored value encoding (P5a step 3; C-112, C-144).

Expected values are written by hand from the encoding table of ``core.terraform_model.canonical``
(the module docstring is the specification of C-112). One test, which may import both sides,
checks that ``decode`` undoes ``encode`` on a spread of values.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from core.terraform_model import values as tv
from core.terraform_model.canonical import encode
from core.verification.values import (
    Argument,
    Block,
    Ref,
    SetValue,
    Unknown,
    Unsupported,
    ValueDecodeError,
    decode,
    decode_argument,
    first_problem,
    has_problem,
    has_unresolved,
)


class TestDecode(unittest.TestCase):
    def test_scalars_are_themselves(self) -> None:
        for scalar in ("a", "", 0, -3, 22, True, False, None):
            with self.subTest(scalar=scalar):
                got = decode(scalar)
                self.assertEqual(got, scalar)
                self.assertIs(type(got), type(scalar))

    def test_a_list_becomes_a_tuple_in_order(self) -> None:
        self.assertEqual(decode(["b", 1, None, ["x"]]), ("b", 1, None, ("x",)))

    def test_decimal(self) -> None:
        self.assertEqual(decode({"$dail": "decimal", "value": "1.5"}), Decimal("1.5"))

    def test_set_keeps_the_stored_order(self) -> None:
        got = decode({"$dail": "set", "items": ["b", "a"]})
        self.assertEqual(got, SetValue(("b", "a")))

    def test_unknown_unsupported_and_ref(self) -> None:
        self.assertEqual(
            decode({"$dail": "unknown", "reason": "variable.no_value"}),
            Unknown("variable.no_value"),
        )
        self.assertEqual(
            decode({"$dail": "unsupported", "reason": "function.unsupported"}),
            Unsupported("function.unsupported"),
        )
        self.assertEqual(
            decode({"$dail": "ref", "address": "aws_security_group.app", "attribute": "id"}),
            Ref("aws_security_group.app", "id"),
        )

    def test_an_object_is_a_mapping(self) -> None:
        got = decode({"b": 1, "a": [2]})
        self.assertEqual(dict(got), {"b": 1, "a": (2,)})

    def test_a_user_map_with_the_tag_key_is_unwrapped(self) -> None:
        got = decode({"$dail": "map", "items": {"$dail": "unknown", "x": 1}})
        self.assertEqual(dict(got), {"$dail": "unknown", "x": 1})

    def test_the_decoded_mapping_is_read_only(self) -> None:
        with self.assertRaises(TypeError):
            decode({"a": 1})["b"] = 2  # type: ignore[index]

    def test_malformed_tags_are_refused(self) -> None:
        bad: list[object] = [
            {"$dail": "weird"},
            {"$dail": "unknown"},
            {"$dail": "unknown", "reason": 5},
            {"$dail": "unknown", "reason": "r", "extra": 1},
            {"$dail": "ref", "address": "a"},
            {"$dail": "ref", "address": "a", "attribute": 1},
            {"$dail": "set", "items": "x"},
            {"$dail": "set"},
            {"$dail": "decimal", "value": 5},
            {"$dail": "decimal", "value": "abc"},
            {"$dail": "map", "items": [1]},
            {"$dail": 7},
        ]
        for encoded in bad:
            with self.subTest(encoded=encoded), self.assertRaises(ValueDecodeError):
                decode(encoded)

    def test_floats_and_foreign_types_are_refused(self) -> None:
        for encoded in (1.5, (1, 2), {1: "a"}, object()):
            with self.subTest(encoded=encoded), self.assertRaises(ValueDecodeError):
                decode(encoded)

    def test_nesting_deeper_than_the_domain_limit_is_refused_not_a_crash(self) -> None:
        deep: object = "x"
        for _ in range(200):
            deep = [deep]
        with self.assertRaises(ValueDecodeError):
            decode(deep)

    def test_decode_undoes_the_modelling_encoder(self) -> None:
        samples = [
            tv.Known("tcp"),
            tv.Known(22),
            tv.Known(True),
            tv.Known(None),
            tv.known_tuple([tv.Known("a"), tv.Unknown("variable.no_value")]),
            tv.known_set([tv.Known("b"), tv.Known("a")]),
            tv.known_object({"k": tv.Known(1), "n": tv.known_tuple([])}),
            tv.known_object({"$dail": tv.Known("x")}),
            tv.Unknown("data.source"),
            tv.Unsupported("function.unsupported"),
            tv.Ref("aws_security_group.app", "id"),
            tv.known_tuple([tv.Ref("aws_security_group.app", "id")]),
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                decoded = decode(encode(sample))
                self.assertEqual(has_problem(decoded), _has_problem_in_model(sample))

    def test_decode_gives_the_same_scalars_as_the_model(self) -> None:
        self.assertEqual(decode(encode(tv.Known("tcp"))), "tcp")
        self.assertEqual(decode(encode(tv.Known(22))), 22)
        self.assertEqual(decode(encode(tv.known_tuple([tv.Known("a"), tv.Known("b")]))), ("a", "b"))
        self.assertEqual(
            decode(encode(tv.known_set([tv.Known("b"), tv.Known("a")]))), SetValue(("a", "b"))
        )


def _has_problem_in_model(value: tv.Value) -> bool:
    return any(isinstance(item, tv.Unknown | tv.Unsupported | tv.Ref) for item in tv.walk(value))


class TestProblems(unittest.TestCase):
    def test_a_problem_anywhere_is_found(self) -> None:
        unknown = Unknown("r")
        cases = {
            "unknown": unknown,
            "unsupported": Unsupported("r"),
            "ref": Ref("a.b", "id"),
            "in a tuple": ("x", unknown),
            "in a set": SetValue(("x", unknown)),
            "in a mapping": decode({"k": ["x", {"$dail": "unknown", "reason": "r"}]}),
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                self.assertTrue(has_problem(value))

    def test_no_problem_in_plain_values(self) -> None:
        for value in (
            "x",
            1,
            None,
            ("a", ("b",)),
            SetValue(("a",)),
            decode({"k": [1]}),
            Decimal("1.5"),
        ):
            with self.subTest(value=value):
                self.assertFalse(has_problem(value))

    def test_first_problem_is_the_first_in_reading_order(self) -> None:
        first, second = Unknown("one"), Unsupported("two")
        self.assertEqual(first_problem(("x", first, second)), first)
        self.assertIsNone(first_problem(("x",)))

    def test_a_deep_value_does_not_overflow_the_stack(self) -> None:
        value: object = Unknown("deep")
        for _ in range(5000):
            value = (value,)
        self.assertTrue(has_problem(value))


class TestUnresolved(unittest.TestCase):
    """``has_unresolved``: unknown or unsupported anywhere. A reference is a *resolved* value (it
    names a configured resource), unlike in ``has_problem``, which counts it as not fixed."""

    def test_a_reference_is_resolved(self) -> None:
        ref = Ref("aws_security_group.app", "id")
        for value in (
            ref,
            (ref,),
            SetValue((ref, "x")),
            decode({"k": [{"$dail": "ref", "address": "a.b", "attribute": "id"}]}),
        ):
            with self.subTest(value=value):
                self.assertFalse(has_unresolved(value))
                self.assertTrue(has_problem(value))

    def test_unknown_and_unsupported_are_found_anywhere(self) -> None:
        for value in (
            Unknown("r"),
            Unsupported("r"),
            ("x", Unknown("r")),
            SetValue((Unsupported("r"),)),
            decode({"k": [{"$dail": "unknown", "reason": "r"}]}),
        ):
            with self.subTest(value=value):
                self.assertTrue(has_unresolved(value))

    def test_plain_values_are_resolved(self) -> None:
        for value in ("x", 1, None, ("a", ("b",)), Decimal("1.5")):
            self.assertFalse(has_unresolved(value))

    def test_a_deep_value_does_not_overflow_the_stack(self) -> None:
        value: object = Unknown("deep")
        for _ in range(5000):
            value = (value,)
        self.assertTrue(has_unresolved(value))


class TestArgument(unittest.TestCase):
    def test_attribute_form(self) -> None:
        got = decode_argument({"form": "ATTRIBUTE", "value": ["10.0.0.0/8"]})
        self.assertEqual(
            got, Argument(form="ATTRIBUTE", value=("10.0.0.0/8",), blocks=(), indeterminate=())
        )

    def test_block_forms(self) -> None:
        encoded = {
            "form": "BLOCKS",
            "blocks": [
                {
                    "type": "ingress",
                    "labels": [],
                    "arguments": {
                        "protocol": {"form": "ATTRIBUTE", "value": "tcp"},
                        "cidr_blocks": {"form": "ATTRIBUTE", "value": ["0.0.0.0/0"]},
                    },
                    "from_dynamic": True,
                }
            ],
            "indeterminate": [{"$dail": "unknown", "reason": "for_each.unknown"}],
        }
        got = decode_argument(encoded)
        self.assertEqual(got.form, "BLOCKS")
        self.assertEqual(got.indeterminate, (Unknown("for_each.unknown"),))
        self.assertEqual(len(got.blocks), 1)
        block = got.blocks[0]
        self.assertIsInstance(block, Block)
        self.assertEqual(block.type, "ingress")
        self.assertTrue(block.from_dynamic)
        self.assertEqual(block.arguments["protocol"].value, "tcp")
        self.assertEqual(block.arguments["cidr_blocks"].value, ("0.0.0.0/0",))

    def test_every_form_is_known_and_the_rest_is_refused(self) -> None:
        for form in ("BLOCKS", "DYNAMIC", "MIXED"):
            self.assertEqual(
                decode_argument({"form": form, "blocks": [], "indeterminate": []}).form, form
            )
        for bad in (
            {"form": "WEIRD", "blocks": [], "indeterminate": []},
            {"form": "ATTRIBUTE"},
            {"form": "BLOCKS", "blocks": []},
            {"form": "BLOCKS", "blocks": {}, "indeterminate": []},
            {"form": "BLOCKS", "blocks": [{"type": "x"}], "indeterminate": []},
            "x",
            None,
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueDecodeError):
                decode_argument(bad)


if __name__ == "__main__":
    unittest.main()
