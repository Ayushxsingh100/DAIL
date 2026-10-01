"""Patch (Doc 05 §9, §23, §25; C-33; P1a step 9)."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import unittest
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from core.domain.enums import CandidateSource, PatchFormat
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.patch import Patch

NOW = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)
PARENT = "123e4567-e89b-42d3-a456-426614174000"
REQUEST = "223e4567-e89b-42d3-a456-426614174001"
PATCH_ID = "323e4567-e89b-42d3-a456-426614174002"
HCL = 'resource "aws_security_group" "web" {\n  name = "web"\n}\n'


def make_patch(**overrides: Any) -> Patch:
    fields: dict[str, Any] = {
        "source": CandidateSource.FIXED_PATCH,
        "content": HCL,
        "parent_state_id": PARENT,
        "now": NOW,
        "patch_id": PATCH_ID,
    }
    fields.update(overrides)
    return Patch.create(**fields)


class TestCreate(unittest.TestCase):
    def test_content_hash_is_sha256_of_the_content(self) -> None:
        patch = make_patch()
        self.assertEqual(patch.content_hash, hashlib.sha256(HCL.encode("utf-8")).hexdigest())

    def test_line_endings_do_not_change_the_hash(self) -> None:
        crlf = make_patch(content=HCL.replace("\n", "\r\n"))
        cr = make_patch(content=HCL.replace("\n", "\r"))
        self.assertEqual(crlf.content_hash, make_patch().content_hash)
        self.assertEqual(cr.content_hash, make_patch().content_hash)

    def test_other_content_changes_the_hash(self) -> None:
        self.assertNotEqual(make_patch(content=HCL + " ").content_hash, make_patch().content_hash)

    def test_defaults(self) -> None:
        patch = make_patch()
        self.assertEqual(patch.format, PatchFormat.TERRAFORM_HCL)
        self.assertIsNone(patch.llm_request_id)
        self.assertEqual(dict(patch.metadata), {})
        self.assertEqual(patch.created_at, NOW)
        self.assertEqual(patch.parent_state_id, PARENT)

    def test_patch_id_is_generated_when_omitted(self) -> None:
        first, second = make_patch(patch_id=None), make_patch(patch_id=None)
        self.assertNotEqual(first.patch_id, second.patch_id)

    def test_llm_patch_carries_its_request_id(self) -> None:
        patch = make_patch(source=CandidateSource.LLM, llm_request_id=REQUEST)
        self.assertEqual(patch.llm_request_id, REQUEST)

    def test_metadata_is_kept(self) -> None:
        patch = make_patch(metadata={"origin": "unit", "tags": ["a", "b"]})
        self.assertEqual(patch.metadata["tags"], ("a", "b"))


class TestValidation(unittest.TestCase):
    def assert_rejected(self, **overrides: Any) -> None:
        with self.assertRaises(DomainValidationError):
            make_patch(**overrides)

    def test_content_must_be_a_non_empty_string(self) -> None:
        for bad in ("", None, b"bytes", 5):
            with self.subTest(value=bad):
                self.assert_rejected(content=bad)

    def test_source_must_be_the_enum(self) -> None:
        for bad in ("LLM", None):
            with self.subTest(value=bad):
                self.assert_rejected(source=bad)

    def test_llm_patch_requires_a_request_id(self) -> None:
        self.assert_rejected(source=CandidateSource.LLM)
        self.assert_rejected(source=CandidateSource.LLM, llm_request_id=None)

    def test_fixed_patch_forbids_a_request_id(self) -> None:
        self.assert_rejected(source=CandidateSource.FIXED_PATCH, llm_request_id=REQUEST)

    def test_ids_must_be_uuids(self) -> None:
        self.assert_rejected(patch_id="patch-1")
        self.assert_rejected(parent_state_id="state-1")
        self.assert_rejected(parent_state_id=None)
        self.assert_rejected(source=CandidateSource.LLM, llm_request_id="req-1")

    def test_created_at_must_be_aware_utc(self) -> None:
        self.assert_rejected(now=datetime(2026, 10, 1, 9, 30))
        self.assert_rejected(now=datetime(2026, 10, 1, 9, 30, tzinfo=timezone(timedelta(hours=1))))

    def test_metadata_must_be_a_json_object_without_floats(self) -> None:
        for bad in ([1], "x", {"a": 0.5}, {"a": [1, {"b": 2.0}]}):
            with self.subTest(value=bad):
                self.assert_rejected(metadata=bad)

    def test_format_must_be_the_enum(self) -> None:
        patch = make_patch()
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(patch, format="TERRAFORM_HCL")


class TestImmutabilityAndHash(unittest.TestCase):
    """Doc 05 §23: patch content is immutable after creation."""

    def test_fields_cannot_be_assigned(self) -> None:
        patch = make_patch()
        for field in ("content", "content_hash", "parent_state_id", "source", "metadata"):
            with self.subTest(field=field), self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(patch, field, "x")

    def test_content_change_without_a_matching_hash_is_rejected(self) -> None:
        patch = make_patch()
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(patch, content=HCL + "# changed\n")

    def test_wrong_content_hash_is_rejected(self) -> None:
        patch = make_patch()
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(patch, content_hash="0" * 64)

    def test_nested_metadata_cannot_be_mutated(self) -> None:
        patch = make_patch(metadata={"a": {"b": 1}, "c": [1]})
        with self.assertRaises(TypeError):
            patch.metadata["x"] = 1  # type: ignore[index]
        with self.assertRaises(TypeError):
            patch.metadata["a"]["b"] = 2  # type: ignore[index]
        with self.assertRaises(TypeError):
            patch.metadata["c"][0] = 2  # type: ignore[index]

    def test_mutating_the_callers_metadata_changes_nothing(self) -> None:
        metadata: dict[str, Any] = {"a": {"b": 1}}
        patch = make_patch(metadata=metadata)
        before = patch.to_dict()
        metadata["a"]["b"] = 99
        metadata["new"] = True
        self.assertEqual(patch.to_dict(), before)


class TestSerialization(unittest.TestCase):
    def test_round_trip(self) -> None:
        patch = make_patch(
            source=CandidateSource.LLM, llm_request_id=REQUEST, metadata={"k": [1, "v", None]}
        )
        data = patch.to_dict()
        json.dumps(data)
        self.assertEqual(data["source"], "LLM")
        self.assertEqual(data["format"], "TERRAFORM_HCL")
        self.assertEqual(data["created_at"], "2026-10-01T09:30:00+00:00")
        self.assertEqual(Patch.from_dict(data), patch)

    def test_fixed_patch_round_trips_with_an_explicit_null_request_id(self) -> None:
        data = make_patch().to_dict()
        self.assertIsNone(data["llm_request_id"])
        self.assertEqual(Patch.from_dict(data), make_patch())

    def test_from_dict_revalidates_the_hash(self) -> None:
        good = make_patch().to_dict()
        with self.assertRaises(HashMismatchError):
            Patch.from_dict({**good, "content": HCL + "# tampered\n"})
        with self.assertRaises(HashMismatchError):
            Patch.from_dict({**good, "content_hash": "a" * 64})

    def test_from_dict_revalidates_other_fields(self) -> None:
        good = make_patch().to_dict()
        for key, bad in (
            ("patch_id", "nope"),
            ("source", "HUMAN"),
            ("format", "YAML"),
            ("created_at", "2026-10-01T09:30:00"),
            ("metadata", [1]),
        ):
            with self.subTest(key=key), self.assertRaises(DomainValidationError):
                Patch.from_dict({**good, key: bad})

    def test_from_dict_rejects_missing_and_unknown_keys(self) -> None:
        good = make_patch().to_dict()
        with self.assertRaises(DomainValidationError):
            Patch.from_dict({k: v for k, v in good.items() if k != "content_hash"})
        with self.assertRaises(DomainValidationError):
            Patch.from_dict({**good, "extra": 1})


if __name__ == "__main__":
    unittest.main()
