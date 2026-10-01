"""Domain support modules: errors, ids, JSON values, timestamps, text hashing (P1a step 4)."""

from __future__ import annotations

import hashlib
import unittest
from datetime import UTC, datetime, timedelta, timezone
from types import MappingProxyType

from core.domain.errors import (
    DomainValidationError,
    HashMismatchError,
    IllegalTransitionError,
    StaleParentError,
    UnauthorizedConstructionError,
)
from core.domain.hashing import sha256_text
from core.domain.ids import new_uuid, require_uuid
from core.domain.jsonvalue import (
    freeze_json,
    iso_utc,
    parse_utc,
    thaw_json,
    utc,
    validate_json,
)

UUID_A = "123e4567-e89b-42d3-a456-426614174000"


class TestErrors(unittest.TestCase):
    def test_hierarchy(self) -> None:
        for cls in (
            IllegalTransitionError,
            HashMismatchError,
            UnauthorizedConstructionError,
        ):
            self.assertTrue(issubclass(cls, DomainValidationError))
        self.assertTrue(issubclass(DomainValidationError, ValueError))
        self.assertTrue(issubclass(StaleParentError, IllegalTransitionError))

    def test_illegal_transition_carries_its_fields_and_names_the_rule(self) -> None:
        err = IllegalTransitionError("candidate", "READY", "PROMOTED", "SM-002", "no shortcut")
        self.assertEqual(
            (err.kind, err.current, err.requested, err.rule),
            ("candidate", "READY", "PROMOTED", "SM-002"),
        )
        self.assertIn("SM-002", str(err))
        self.assertIn("READY -> PROMOTED", str(err))

    def test_stale_parent_error_is_sm_010(self) -> None:
        err = StaleParentError("v1", "PROMOTED")
        self.assertEqual(err.rule, "SM-010")
        self.assertEqual(err.kind, "candidate")
        self.assertIn("SM-010", str(err))


class TestIds(unittest.TestCase):
    def test_new_uuid_is_canonical_and_unique(self) -> None:
        first, second = new_uuid(), new_uuid()
        self.assertNotEqual(first, second)
        self.assertEqual(require_uuid(first, "x"), first)

    def test_require_uuid_rejects_everything_else(self) -> None:
        for bad in (
            "state-abc123",
            UUID_A.upper(),
            UUID_A.replace("-", ""),
            f"{{{UUID_A}}}",
            "",
            None,
            12,
        ):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                require_uuid(bad, "field")

    def test_error_names_the_field(self) -> None:
        with self.assertRaises(DomainValidationError) as ctx:
            require_uuid("nope", "candidate_id")
        self.assertIn("candidate_id", str(ctx.exception))


class TestJsonValues(unittest.TestCase):
    def test_valid_values_are_accepted(self) -> None:
        validate_json({"a": [1, "b", True, None, {"c": (1, 2)}], "d": -5}, "payload")

    def test_floats_are_rejected_at_any_depth(self) -> None:
        for bad in (1.5, {"a": 1.0}, [1, [2, {"b": float("nan")}]], {"a": {"b": [0.1]}}):
            with self.subTest(value=repr(bad)), self.assertRaises(DomainValidationError):
                validate_json(bad, "payload")

    def test_other_types_and_non_string_keys_are_rejected(self) -> None:
        for bad in ({1: "x"}, {"a": {1, 2}}, b"bytes", object(), datetime(2026, 1, 1, tzinfo=UTC)):
            with self.subTest(value=repr(bad)), self.assertRaises(DomainValidationError):
                validate_json(bad, "payload")

    def test_error_names_the_path(self) -> None:
        with self.assertRaises(DomainValidationError) as ctx:
            validate_json({"outer": [{"inner": 1.5}]}, "attributes")
        self.assertIn("attributes.outer[0].inner", str(ctx.exception))

    def test_excessive_nesting_is_rejected(self) -> None:
        value: object = "x"
        for _ in range(100):
            value = [value]
        with self.assertRaises(DomainValidationError):
            validate_json(value, "payload")

    def test_freeze_is_deep_and_detached_from_the_input(self) -> None:
        source = {"a": [1, {"b": 2}], "c": "d"}
        frozen = freeze_json(source)
        source["a"].append(3)  # type: ignore[attr-defined]
        source["c"] = "changed"
        self.assertEqual(thaw_json(frozen), {"a": [1, {"b": 2}], "c": "d"})
        self.assertIsInstance(frozen, MappingProxyType)
        with self.assertRaises(TypeError):
            frozen["x"] = 1
        with self.assertRaises(TypeError):
            frozen["a"][0] = 9
        with self.assertRaises(TypeError):
            frozen["a"][1]["b"] = 9

    def test_thaw_returns_plain_json_types(self) -> None:
        thawed = thaw_json(freeze_json({"a": [1, {"b": None}]}))
        self.assertEqual(thawed, {"a": [1, {"b": None}]})
        self.assertIs(type(thawed), dict)
        self.assertIs(type(thawed["a"]), list)
        self.assertIs(type(thawed["a"][1]), dict)

    def test_freeze_accepts_already_frozen_values(self) -> None:
        once = freeze_json({"a": [1]})
        self.assertEqual(thaw_json(freeze_json(once)), {"a": [1]})


class TestTimestamps(unittest.TestCase):
    def test_aware_utc_is_accepted_and_normalized(self) -> None:
        moment = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
        self.assertEqual(utc(moment, "t"), moment)
        self.assertEqual(
            utc(datetime(2026, 10, 1, 12, 0, tzinfo=timezone(timedelta(0))), "t"), moment
        )

    def test_naive_and_non_utc_are_rejected(self) -> None:
        with self.assertRaises(DomainValidationError):
            utc(datetime(2026, 10, 1, 12, 0), "t")
        with self.assertRaises(DomainValidationError):
            utc(datetime(2026, 10, 1, 12, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))), "t")
        with self.assertRaises(DomainValidationError):
            utc("2026-10-01T12:00:00+00:00", "t")

    def test_iso_round_trip(self) -> None:
        moment = datetime(2026, 10, 1, 12, 0, 1, 250000, tzinfo=UTC)
        self.assertEqual(parse_utc(iso_utc(moment), "t"), moment)

    def test_parse_rejects_naive_text_and_garbage(self) -> None:
        for bad in ("2026-10-01T12:00:00", "not a time", 5, None):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                parse_utc(bad, "t")


class TestSha256Text(unittest.TestCase):
    def test_matches_sha256_of_the_utf8_text(self) -> None:
        text = 'resource "aws_vpc" "main" {}\n'
        self.assertEqual(sha256_text(text), hashlib.sha256(text.encode("utf-8")).hexdigest())

    def test_line_endings_are_normalized_to_lf(self) -> None:
        lf = "a\nb\nc\n"
        self.assertEqual(sha256_text("a\r\nb\r\nc\r\n"), sha256_text(lf))
        self.assertEqual(sha256_text("a\rb\rc\r"), sha256_text(lf))
        self.assertEqual(sha256_text("a\r\nb\nc\r"), sha256_text(lf))

    def test_other_differences_still_change_the_hash(self) -> None:
        self.assertNotEqual(sha256_text("a\n"), sha256_text("a"))
        self.assertNotEqual(sha256_text("a "), sha256_text("a"))

    def test_non_ascii_content_hashes_as_utf8(self) -> None:
        text = 'tag = "café"\n'
        self.assertEqual(sha256_text(text), hashlib.sha256(text.encode("utf-8")).hexdigest())


if __name__ == "__main__":
    unittest.main()
