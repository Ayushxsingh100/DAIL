"""Canonical encoding of values and arguments (P3a-3 step 2; Doc 04 §6.1; C-33, C-112).

Expected JSON is written by hand from the table of C-112; the decoder in this file exists only to
prove that the encoding is injective.
"""

from __future__ import annotations

import random
import unittest
from decimal import Decimal

from core.domain.hashing import canonical_json
from core.domain.jsonvalue import validate_json
from core.terraform_model import canonical
from core.terraform_model.canonical import (
    NO_POLICY,
    SET_POLICIES,
    EncodeError,
    SetPolicy,
    encode,
    encode_argument,
    json_depth,
    policy_for,
)
from core.terraform_model.hcl.ast import SourceRange
from core.terraform_model.instances import ArgumentForm, EvaluatedArgument, EvaluatedBlock
from core.terraform_model.values import (
    Known,
    Ref,
    Unknown,
    Unsupported,
    Value,
    known_object,
    known_set,
    known_tuple,
)

RANGE = SourceRange("t.tf", 1, 1, 1, 2, 0, 1)
U = Unknown("variable.no_value")


def attribute(name: str, value: Value) -> EvaluatedArgument:
    return EvaluatedArgument(name, ArgumentForm.ATTRIBUTE, value, (), (), RANGE)


def block(
    type_: str, arguments: dict[str, EvaluatedArgument], *, dynamic: bool = False, labels=()
) -> EvaluatedBlock:  # type: ignore[no-untyped-def]
    return EvaluatedBlock(type_, tuple(labels), arguments, dynamic, RANGE)


def blocks(name: str, form: ArgumentForm, items, reasons=()) -> EvaluatedArgument:  # type: ignore[no-untyped-def]
    return EvaluatedArgument(name, form, None, tuple(items), tuple(reasons), RANGE)


# --- A decoder, for the injectivity proof only ---------------------------------------------------


def decode(encoded: object) -> Value:
    if encoded is None or isinstance(encoded, str | bool | int):
        return Known(encoded)
    if isinstance(encoded, list):
        return Known(tuple(decode(item) for item in encoded))
    assert isinstance(encoded, dict)
    if "$dail" not in encoded:
        return known_object({key: decode(item) for key, item in encoded.items()})
    tag = encoded["$dail"]
    if tag == "decimal":
        return Known(Decimal(encoded["value"]))
    if tag == "set":
        return known_set(decode(item) for item in encoded["items"])
    if tag == "ref":
        return Ref(encoded["address"], encoded["attribute"])
    if tag == "unknown":
        return Unknown(encoded["reason"])
    if tag == "unsupported":
        return Unsupported(encoded["reason"])
    assert tag == "map"
    return known_object({key: decode(item) for key, item in encoded["items"].items()})


KEYS = ("a", "b", "$dail", "$decimal", "$set", "$ref", "items", "form", "value", "reason", "")
STRINGS = ("", "a", "$dail", "unknown", "x y", "é", "10", "true", "null", " ", "0.5")


def random_value(rng: random.Random, depth: int = 0) -> Value:
    kind = rng.random()
    if depth >= 4 or kind < 0.35:
        return rng.choice(
            [
                Known(None),
                Known(True),
                Known(False),
                Known(0),
                Known(1),
                Known(-7),
                Known(10**30),
                Known(Decimal("1.5")),
                Known(Decimal("0.0000001")),
                Known(rng.choice(STRINGS)),
                Known(rng.choice(STRINGS)),
                Ref(rng.choice(("aws_x.y", 'aws_x.y["k"]')), "id"),
                Unknown(rng.choice(("variable.no_value", "data_source", "ref.derived:a.b.id"))),
                Unsupported(rng.choice(("function.not_implemented:abs", "limit.depth"))),
            ]
        )
    if kind < 0.55:
        return known_tuple(random_value(rng, depth + 1) for _ in range(rng.randint(0, 3)))
    if kind < 0.7:
        return known_set(random_value(rng, depth + 1) for _ in range(rng.randint(0, 3)))
    keys = rng.sample(KEYS, rng.randint(0, 3))
    return known_object({key: random_value(rng, depth + 1) for key in keys})


class TestTheTable(unittest.TestCase):
    """Every row of the table of C-112."""

    def test_scalars_encode_as_themselves(self) -> None:
        for value, expected in [
            (Known("abc"), "abc"),
            (Known(""), ""),
            (Known(True), True),
            (Known(False), False),
            (Known(None), None),
            (Known(0), 0),
            (Known(-3), -3),
            (Known(10**30), 10**30),
        ]:
            with self.subTest(value=value):
                result = encode(value)
                self.assertEqual(result, expected)
                self.assertIs(type(result), type(expected))

    def test_a_decimal_is_tagged_with_the_text_terraform_prints(self) -> None:
        cases = [
            (Decimal("1.5"), "1.5"),
            (Decimal("1.50"), "1.5"),
            (Decimal("0.1"), "0.1"),
            (Decimal("-2.25"), "-2.25"),
            (Decimal("1E-7"), "0.0000001"),
            (Decimal("123456789.000000001"), "123456789.000000001"),
        ]
        for number, text in cases:
            with self.subTest(number=number):
                self.assertEqual(encode(Known(number)), {"$dail": "decimal", "value": text})

    def test_an_integral_decimal_is_an_integer(self) -> None:
        self.assertEqual(encode(Known(Decimal("2.0"))), 2)
        self.assertEqual(encode(Known(Decimal("1E+3"))), 1000)

    def test_a_tuple_keeps_its_order(self) -> None:
        self.assertEqual(encode(known_tuple([Known("b"), Known("a"), Known("b")])), ["b", "a", "b"])
        self.assertEqual(encode(known_tuple([])), [])
        self.assertEqual(encode(known_tuple([known_tuple([Known(1)])])), [[1]])

    def test_a_set_is_sorted_by_the_text_of_its_encoded_items(self) -> None:
        value = known_set([Known("b"), Known("a"), Known("c")])
        self.assertEqual(encode(value), {"$dail": "set", "items": ["a", "b", "c"]})
        self.assertEqual(encode(known_set([])), {"$dail": "set", "items": []})
        mixed = known_set([Known(10), Known(2), Known("x"), Known(True), Known(None)])
        texts = [canonical_json(item) for item in encode(mixed)["items"]]  # type: ignore[index]
        self.assertEqual(texts, sorted(texts))
        with_unknown = known_set([Known("a"), U, Unsupported("limit.depth")])
        items = encode(with_unknown)["items"]  # type: ignore[index]
        self.assertEqual(
            [canonical_json(i) for i in items], sorted(canonical_json(i) for i in items)
        )

    def test_an_object_has_sorted_keys(self) -> None:
        result = encode(known_object({"b": Known(1), "a": Known(2)}))
        self.assertEqual(list(result), ["a", "b"])  # type: ignore[call-overload]
        self.assertEqual(canonical_json(result), '{"a":2,"b":1}')
        self.assertEqual(encode(known_object({})), {})

    def test_a_map_with_the_reserved_key_is_escaped(self) -> None:
        value = known_object({"$dail": Known("unknown"), "reason": Known("variable.no_value")})
        self.assertEqual(
            encode(value),
            {"$dail": "map", "items": {"$dail": "unknown", "reason": "variable.no_value"}},
        )
        self.assertNotEqual(encode(value), encode(U))

    def test_other_dollar_keys_are_ordinary(self) -> None:
        self.assertEqual(encode(known_object({"$decimal": Known("1")})), {"$decimal": "1"})
        self.assertEqual(encode(known_object({"$set": Known(1)})), {"$set": 1})

    def test_reference_unknown_and_unsupported(self) -> None:
        self.assertEqual(
            encode(Ref("aws_security_group.app", "id")),
            {"$dail": "ref", "address": "aws_security_group.app", "attribute": "id"},
        )
        self.assertEqual(encode(U), {"$dail": "unknown", "reason": "variable.no_value"})
        self.assertEqual(
            encode(Unsupported("function.not_implemented:abs")),
            {"$dail": "unsupported", "reason": "function.not_implemented:abs"},
        )

    def test_an_unknown_is_not_null_a_string_or_another_reason(self) -> None:
        encodings = [
            encode(v)
            for v in (
                U,
                Unknown("data_source"),
                Unsupported("variable.no_value"),
                Known(None),
                Known("variable.no_value"),
            )
        ]
        self.assertEqual(len({canonical_json(e) for e in encodings}), 5)

    def test_two_unknowns_with_one_reason_encode_identically(self) -> None:
        self.assertEqual(encode(Unknown("data_source")), encode(Unknown("data_source")))

    def test_nested_values(self) -> None:
        value = known_object(
            {
                "cidr_blocks": known_tuple([Known("10.0.0.0/8")]),
                "sg": Ref("aws_security_group.app", "id"),
                "n": known_object({"x": U}),
            }
        )
        self.assertEqual(
            encode(value),
            {
                "cidr_blocks": ["10.0.0.0/8"],
                "n": {"x": {"$dail": "unknown", "reason": "variable.no_value"}},
                "sg": {"$dail": "ref", "address": "aws_security_group.app", "attribute": "id"},
            },
        )

    def test_the_marker_of_a_resource_object_does_not_reach_the_encoding(self) -> None:
        from types import MappingProxyType

        marked = Known(MappingProxyType({"id": Known(1)}), computed_from="aws_x.y")
        self.assertEqual(encode(marked), {"id": 1})

    def test_no_float_and_valid_domain_json(self) -> None:
        rng = random.Random(5)
        for _ in range(300):
            validate_json(encode(random_value(rng)), "value")  # raises on a float

    def test_too_deep_a_value_is_refused_not_a_crash(self) -> None:
        value: Value = Known(1)
        for _ in range(canonical.MAX_ENCODE_DEPTH + 5):
            value = known_tuple([value])
        with self.assertRaises(EncodeError):
            encode(value)
        self.assertEqual(json_depth([[1], {"a": [2]}]), 3)
        self.assertEqual(json_depth(1), 0)


class TestInjectivity(unittest.TestCase):
    SEEDS = (20261025, 3, 11, 424242)

    def test_decoding_the_encoding_gives_the_value_back(self) -> None:
        count = 0
        for seed in self.SEEDS:
            rng = random.Random(seed)
            for index in range(150):
                value = random_value(rng)
                with self.subTest(seed=seed, index=index):
                    self.assertEqual(repr(decode(encode(value))), repr(value))
                count += 1
        self.assertGreaterEqual(count, 500)

    def test_equal_encodings_come_only_from_equal_values(self) -> None:
        by_text: dict[str, str] = {}
        rng = random.Random(99)
        for _ in range(1500):
            value = random_value(rng)
            text = canonical_json(encode(value))
            previous = by_text.setdefault(text, repr(value))
            self.assertEqual(previous, repr(value), text)

    def test_hand_made_collisions_are_avoided(self) -> None:
        pairs = [
            (Known("1"), Known(1)),
            (Known(True), Known(1)),
            (Known(None), Known("null")),
            (Known(Decimal("1.5")), Known("1.5")),
            (
                Known(Decimal("1.5")),
                known_object({"$dail": Known("decimal"), "value": Known("1.5")}),
            ),
            (known_tuple([Known("a")]), known_set([Known("a")])),
            (
                known_set([Known("a")]),
                known_object({"$dail": Known("set"), "items": known_tuple([Known("a")])}),
            ),
            (known_object({}), known_object({"$dail": Known("map"), "items": known_object({})})),
            (
                Ref("a.b", "id"),
                known_object(
                    {"$dail": Known("ref"), "address": Known("a.b"), "attribute": Known("id")}
                ),
            ),
            (Unknown("r"), Unsupported("r")),
            (Unknown("r"), known_object({"$dail": Known("unknown"), "reason": Known("r")})),
            (known_tuple([]), known_object({})),
        ]
        for first, second in pairs:
            with self.subTest(first=first, second=second):
                self.assertNotEqual(canonical_json(encode(first)), canonical_json(encode(second)))


class TestOrderInvariance(unittest.TestCase):
    def test_set_elements_in_any_order(self) -> None:
        rng = random.Random(1)
        for _ in range(100):
            items = [random_value(rng, 2) for _ in range(rng.randint(0, 5))]
            shuffled = items[:]
            rng.shuffle(shuffled)
            self.assertEqual(encode(known_set(items)), encode(known_set(shuffled)))

    def test_object_keys_in_any_order(self) -> None:
        first = known_object({"a": Known(1), "b": Known(2), "c": Known(3)})
        second = known_object({"c": Known(3), "a": Known(1), "b": Known(2)})
        self.assertEqual(canonical_json(encode(first)), canonical_json(encode(second)))


class TestArguments(unittest.TestCase):
    def test_an_attribute(self) -> None:
        self.assertEqual(
            encode_argument(attribute("egress", known_tuple([]))),
            {"form": "ATTRIBUTE", "value": []},
        )
        self.assertEqual(
            encode_argument(attribute("x", U)),
            {"form": "ATTRIBUTE", "value": {"$dail": "unknown", "reason": "variable.no_value"}},
        )

    def test_blocks(self) -> None:
        argument = blocks(
            "rule",
            ArgumentForm.BLOCKS,
            [block("rule", {"from_port": attribute("from_port", Known(22))}, labels=[Known("l")])],
        )
        self.assertEqual(
            encode_argument(argument),
            {
                "form": "BLOCKS",
                "blocks": [
                    {
                        "type": "rule",
                        "labels": ["l"],
                        "arguments": {"from_port": {"form": "ATTRIBUTE", "value": 22}},
                        "from_dynamic": False,
                    }
                ],
                "indeterminate": [],
            },
        )

    def test_dynamic_and_mixed_with_indeterminate_reasons(self) -> None:
        dynamic = blocks(
            "rule",
            ArgumentForm.DYNAMIC,
            [],
            [Unknown("variable.no_value"), Unsupported("dynamic.malformed")],
        )
        encoded = encode_argument(dynamic)
        self.assertEqual(encoded["form"], "DYNAMIC")  # type: ignore[index]
        self.assertEqual(encoded["blocks"], [])  # type: ignore[index]
        reasons = encoded["indeterminate"]  # type: ignore[index]
        self.assertEqual(
            reasons,
            sorted(
                [
                    {"$dail": "unknown", "reason": "variable.no_value"},
                    {"$dail": "unsupported", "reason": "dynamic.malformed"},
                ],
                key=canonical_json,
            ),
        )
        mixed = blocks(
            "rule", ArgumentForm.MIXED, [block("rule", {}), block("rule", {}, dynamic=True)]
        )
        flags = [b["from_dynamic"] for b in encode_argument(mixed)["blocks"]]  # type: ignore[index]
        self.assertEqual(flags, [False, True])

    def test_the_indeterminate_reasons_are_sorted(self) -> None:
        one = blocks("r", ArgumentForm.DYNAMIC, [], [Unknown("b"), Unknown("a")])
        two = blocks("r", ArgumentForm.DYNAMIC, [], [Unknown("a"), Unknown("b")])
        self.assertEqual(encode_argument(one), encode_argument(two))

    def test_the_forms_are_never_confused(self) -> None:
        empty_attribute = encode_argument(attribute("ingress", known_tuple([])))
        no_blocks = encode_argument(blocks("ingress", ArgumentForm.BLOCKS, []))
        dynamic = encode_argument(blocks("ingress", ArgumentForm.DYNAMIC, []))
        texts = {canonical_json(x) for x in (empty_attribute, no_blocks, dynamic)}
        self.assertEqual(len(texts), 3)

    def test_nested_blocks(self) -> None:
        inner = blocks(
            "inner", ArgumentForm.BLOCKS, [block("inner", {"a": attribute("a", Known(1))})]
        )
        outer = blocks("outer", ArgumentForm.BLOCKS, [block("outer", {"inner": inner})])
        encoded = encode_argument(outer)
        self.assertEqual(
            encoded["blocks"][0]["arguments"]["inner"]["blocks"][0]["arguments"]["a"],  # type: ignore[index]
            {"form": "ATTRIBUTE", "value": 1},
        )

    def test_too_deep_blocks_are_refused(self) -> None:
        argument = attribute("a", Known(1))
        for _ in range(canonical.MAX_ENCODE_DEPTH + 5):
            argument = blocks("b", ArgumentForm.BLOCKS, [block("b", {"a": argument})])
        with self.assertRaises(EncodeError):
            encode_argument(argument)


def rule_block(port: int, cidrs: list[str], *, dynamic: bool = False) -> EvaluatedBlock:
    return block(
        "ingress",
        {
            "from_port": attribute("from_port", Known(port)),
            "cidr_blocks": attribute("cidr_blocks", known_tuple([Known(c) for c in cidrs])),
        },
        dynamic=dynamic,
    )


class TestSetLikeArguments(unittest.TestCase):
    SG = policy_for("aws_security_group")

    def test_the_policy_table_is_the_schema_list(self) -> None:
        # written by hand from the provider 6.53.0 schema (C-112)
        expected = {
            "aws_security_group": (
                {"ingress", "egress"},
                {"cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids", "security_groups"},
            ),
            "aws_security_group_rule": (
                {"cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids"},
                {"cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids"},
            ),
            "aws_route_table": ({"route", "propagating_vgws"}, set()),
            "aws_instance": (
                {
                    "security_groups",
                    "vpc_security_group_ids",
                    "secondary_private_ips",
                    "ebs_block_device",
                    "ephemeral_block_device",
                    "network_interface",
                    "secondary_network_interface",
                },
                set(),
            ),
            "aws_db_instance": (
                {"vpc_security_group_ids", "enabled_cloudwatch_logs_exports"},
                set(),
            ),
            "aws_db_subnet_group": ({"subnet_ids"}, set()),
        }
        self.assertEqual(set(SET_POLICIES), set(expected))
        for name, (arguments, nested) in expected.items():
            self.assertEqual(
                (set(SET_POLICIES[name].arguments), set(SET_POLICIES[name].nested)),
                (arguments, nested),
                name,
            )
        for name in (
            "aws_vpc",
            "aws_subnet",
            "aws_route_table_association",
            "aws_internet_gateway",
            "aws_nothing",
        ):
            self.assertEqual(policy_for(name), NO_POLICY)

    def test_inline_blocks_in_any_order_are_one_encoding(self) -> None:
        a, b = rule_block(22, ["10.0.0.0/8"]), rule_block(80, ["0.0.0.0/0"])
        one = blocks("ingress", ArgumentForm.BLOCKS, [a, b])
        two = blocks("ingress", ArgumentForm.BLOCKS, [b, a])
        self.assertEqual(encode_argument(one, self.SG), encode_argument(two, self.SG))
        self.assertNotEqual(encode_argument(one), encode_argument(two))  # no policy: order kept

    def test_a_name_outside_the_policy_keeps_the_block_order(self) -> None:
        a, b = rule_block(22, ["10.0.0.0/8"]), rule_block(80, ["0.0.0.0/0"])
        one = blocks("other", ArgumentForm.BLOCKS, [a, b])
        two = blocks("other", ArgumentForm.BLOCKS, [b, a])
        self.assertNotEqual(encode_argument(one, self.SG), encode_argument(two, self.SG))

    def test_dynamic_and_mixed_blocks_are_sorted_too(self) -> None:
        a, b = rule_block(22, ["10.0.0.0/8"]), rule_block(80, ["0.0.0.0/0"], dynamic=True)
        one = blocks("ingress", ArgumentForm.MIXED, [a, b])
        two = blocks("ingress", ArgumentForm.MIXED, [b, a])
        self.assertEqual(encode_argument(one, self.SG), encode_argument(two, self.SG))

    def test_cidr_lists_inside_blocks_are_sets(self) -> None:
        one = blocks(
            "ingress", ArgumentForm.BLOCKS, [rule_block(22, ["10.0.0.0/8", "192.168.0.0/16"])]
        )
        two = blocks(
            "ingress", ArgumentForm.BLOCKS, [rule_block(22, ["192.168.0.0/16", "10.0.0.0/8"])]
        )
        self.assertEqual(encode_argument(one, self.SG), encode_argument(two, self.SG))

    def test_duplicates_are_kept(self) -> None:
        once = blocks("ingress", ArgumentForm.BLOCKS, [rule_block(22, ["10.0.0.0/8"])])
        twice = blocks("ingress", ArgumentForm.BLOCKS, [rule_block(22, ["10.0.0.0/8"])] * 2)
        self.assertNotEqual(encode_argument(once, self.SG), encode_argument(twice, self.SG))
        cidrs = attribute("cidr_blocks", known_tuple([Known("a"), Known("a")]))
        self.assertEqual(
            encode_argument(cidrs, policy_for("aws_security_group_rule"))["value"],  # type: ignore[index]
            ["a", "a"],
        )

    def test_an_attribute_form_set_is_sorted(self) -> None:
        def element(cidrs: list[str]) -> Value:
            return known_object(
                {"cidr_blocks": known_tuple([Known(c) for c in cidrs]), "from_port": Known(22)}
            )

        one = attribute("ingress", known_tuple([element(["b", "a"]), element(["c"])]))
        two = attribute("ingress", known_tuple([element(["c"]), element(["a", "b"])]))
        self.assertEqual(encode_argument(one, self.SG), encode_argument(two, self.SG))
        self.assertNotEqual(encode_argument(one), encode_argument(two))

    def test_set_typed_attributes_of_other_types(self) -> None:
        instance = policy_for("aws_instance")

        def ids(*names: str) -> EvaluatedArgument:
            return attribute("vpc_security_group_ids", known_tuple([Ref(a, "id") for a in names]))

        self.assertEqual(
            encode_argument(ids("aws_security_group.a", "aws_security_group.b"), instance),
            encode_argument(ids("aws_security_group.b", "aws_security_group.a"), instance),
        )
        self.assertNotEqual(
            encode_argument(ids("aws_security_group.a", "aws_security_group.b")),
            encode_argument(ids("aws_security_group.b", "aws_security_group.a")),
        )

        def subnet_ids(*names: str) -> EvaluatedArgument:
            return attribute("subnet_ids", known_tuple([Known(a) for a in names]))

        self.assertEqual(
            encode_argument(subnet_ids("a", "b"), policy_for("aws_db_subnet_group")),
            encode_argument(subnet_ids("b", "a"), policy_for("aws_db_subnet_group")),
        )

    def test_a_list_typed_argument_keeps_its_order(self) -> None:
        # route_table_association has no set arguments; a plain list keeps its order
        one = attribute("x", known_tuple([Known("a"), Known("b")]))
        two = attribute("x", known_tuple([Known("b"), Known("a")]))
        self.assertNotEqual(
            encode_argument(one, policy_for("aws_vpc")), encode_argument(two, policy_for("aws_vpc"))
        )

    def test_the_route_blocks_of_a_route_table(self) -> None:
        routes = policy_for("aws_route_table")
        r1 = block("route", {"cidr_block": attribute("cidr_block", Known("0.0.0.0/0"))})
        r2 = block("route", {"cidr_block": attribute("cidr_block", Known("10.0.0.0/8"))})
        self.assertEqual(
            encode_argument(blocks("route", ArgumentForm.BLOCKS, [r1, r2]), routes),
            encode_argument(blocks("route", ArgumentForm.BLOCKS, [r2, r1]), routes),
        )

    def test_a_custom_policy(self) -> None:
        policy = SetPolicy(frozenset({"x"}))
        a, b = block("x", {}), block("x", {"k": attribute("k", Known(1))})
        self.assertEqual(
            encode_argument(blocks("x", ArgumentForm.BLOCKS, [a, b]), policy),
            encode_argument(blocks("x", ArgumentForm.BLOCKS, [b, a]), policy),
        )


if __name__ == "__main__":
    unittest.main()
