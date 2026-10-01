"""Normalized Resource (Doc 05 §5.1, §5.2, §28; Doc 04 §6; C-33; P1a step 8)."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import unittest
from datetime import UTC, datetime
from typing import Any

from core.domain.enums import ProvenanceSourceKind, ReferenceResolution, ResourceSupport
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.hashing import canonical_json
from core.domain.resource import Resource
from core.domain.values import Provenance, Reference

NOW = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)
RECORD_A = "123e4567-e89b-42d3-a456-426614174000"
RECORD_B = "223e4567-e89b-42d3-a456-426614174001"


def make_provenance(**overrides: object) -> Provenance:
    fields: dict[str, Any] = {
        "source_kind": ProvenanceSourceKind.TERRAFORM_CONFIG,
        "source_component": "terraform_model",
        "source_reference": "main.tf",
        "observed_at": NOW,
    }
    fields.update(overrides)
    return Provenance(**fields)


def make_reference(address: str = "aws_instance.app", **overrides: object) -> Reference:
    fields: dict[str, Any] = {
        "source_address": address,
        "source_attribute": "vpc_security_group_ids",
        "target_address": "aws_security_group.web",
        "reference_type": "security_group",
        "resolution_status": ReferenceResolution.SUPPORTED,
    }
    fields.update(overrides)
    return Reference(**fields)


def make_resource(**overrides: object) -> Resource:
    fields: dict[str, Any] = {
        "address": "aws_instance.app",
        "resource_type": "aws_instance",
        "logical_identity": {"name": "app"},
        "attributes": {"instance_type": "t3.micro", "tags": {"Name": "app"}},
        "security_attributes": {"ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]},
        "semantic_attributes": {"role": "app"},
        "references": [make_reference()],
        "provenance": make_provenance(),
        "support_status": ResourceSupport.SUPPORTED,
        "record_id": RECORD_A,
    }
    fields.update(overrides)
    return Resource.create(**fields)


class TestCreate(unittest.TestCase):
    def test_create_sets_canonical_json_and_fingerprint(self) -> None:
        res = make_resource()
        self.assertIsInstance(res.canonical_json, str)
        json.loads(res.canonical_json)
        self.assertEqual(res.fingerprint, hashlib.sha256(res.canonical_json.encode()).hexdigest())

    def test_canonical_json_is_the_fingerprint_payload(self) -> None:
        res = make_resource()
        payload = json.loads(res.canonical_json)
        self.assertEqual(
            set(payload),
            {
                "resource_type",
                "logical_identity",
                "attributes",
                "security_attributes",
                "semantic_attributes",
                "references",
            },
        )
        self.assertEqual(res.canonical_json, canonical_json(payload))

    def test_record_id_is_generated_when_omitted(self) -> None:
        a = make_resource(record_id=None)
        b = make_resource(record_id=None)
        self.assertNotEqual(a.record_id, b.record_id)
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_every_support_status_is_representable(self) -> None:
        for status in ResourceSupport:
            self.assertEqual(make_resource(support_status=status).support_status, status)

    def test_references_are_stored_sorted(self) -> None:
        refs = [
            make_reference(target_address="aws_subnet.b", source_attribute="subnet_id"),
            make_reference(target_address="aws_security_group.z"),
            make_reference(target_address="aws_security_group.a"),
        ]
        res = make_resource(references=refs)
        keys = [
            (r.source_attribute, r.target_address, r.reference_type, r.resolution_status)
            for r in res.references
        ]
        self.assertEqual(keys, sorted(keys))
        self.assertIsInstance(res.references, tuple)

    def test_fingerprint_does_not_depend_on_the_resource_address(self) -> None:
        other = make_resource(
            address="aws_instance.renamed", references=[make_reference("aws_instance.renamed")]
        )
        self.assertEqual(other.fingerprint, make_resource().fingerprint)

    def test_support_status_is_not_part_of_the_fingerprint(self) -> None:
        self.assertEqual(
            make_resource(support_status=ResourceSupport.UNSUPPORTED).fingerprint,
            make_resource().fingerprint,
        )


class TestValidation(unittest.TestCase):
    def assert_rejected(
        self, error: type[Exception] = DomainValidationError, **overrides: object
    ) -> None:
        with self.assertRaises(error):
            make_resource(**overrides)

    def test_record_id_must_be_a_uuid(self) -> None:
        for bad in ("res-123", RECORD_A.upper(), 5):
            with self.subTest(value=bad):
                self.assert_rejected(record_id=bad)

    def test_address_and_type_must_be_clean_non_empty_text(self) -> None:
        for field in ("address", "resource_type"):
            for bad in ("", "  ", " aws_instance.app", "aws_instance.app ", None):
                with self.subTest(field=field, value=bad):
                    overrides: dict[str, Any] = {field: bad}
                    if field == "address":
                        overrides["references"] = []
                    self.assert_rejected(**overrides)

    def test_json_payloads_must_be_json_objects(self) -> None:
        for field in (
            "logical_identity",
            "attributes",
            "security_attributes",
            "semantic_attributes",
        ):
            for bad in ([1, 2], "text", 3, None):
                with self.subTest(field=field, value=bad):
                    self.assert_rejected(**{field: bad})

    def test_floats_in_any_payload_are_rejected(self) -> None:
        for field in (
            "logical_identity",
            "attributes",
            "security_attributes",
            "semantic_attributes",
        ):
            with self.subTest(field=field):
                self.assert_rejected(**{field: {"x": [1, {"y": 0.5}]}})

    def test_references_must_be_reference_objects_of_this_resource(self) -> None:
        self.assert_rejected(references=["aws_security_group.web"])
        self.assert_rejected(references=[make_reference("aws_instance.other")])
        self.assert_rejected(references="not a list")

    def test_provenance_must_be_a_provenance(self) -> None:
        self.assert_rejected(provenance={"source_kind": "TERRAFORM_CONFIG"})
        self.assert_rejected(provenance=None)

    def test_support_status_must_be_the_enum(self) -> None:
        self.assert_rejected(support_status="SUPPORTED")
        self.assert_rejected(support_status=None)


class TestHashIntegrity(unittest.TestCase):
    """DATA-INT-010: hashes must be reproducible from canonical content."""

    def test_wrong_fingerprint_is_rejected(self) -> None:
        res = make_resource()
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(res, fingerprint="0" * 64)

    def test_wrong_canonical_json_is_rejected(self) -> None:
        res = make_resource()
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(res, canonical_json="{}")

    def test_semantic_change_without_a_matching_hash_is_rejected(self) -> None:
        res = make_resource()
        for field, value in (
            ("attributes", {"instance_type": "m5.large"}),
            ("security_attributes", {"ingress": []}),
            ("semantic_attributes", {"role": "db"}),
            ("logical_identity", {"name": "other"}),
            ("resource_type", "aws_db_instance"),
            ("references", ()),
        ):
            with self.subTest(field=field), self.assertRaises(HashMismatchError):
                dataclasses.replace(res, **{field: value})

    def test_non_semantic_change_with_replace_is_accepted(self) -> None:
        res = make_resource()
        changed = dataclasses.replace(
            res, record_id=RECORD_B, support_status=ResourceSupport.UNKNOWN
        )
        self.assertEqual(changed.fingerprint, res.fingerprint)
        self.assertEqual(changed.record_id, RECORD_B)


class TestImmutability(unittest.TestCase):
    def test_attributes_cannot_be_assigned(self) -> None:
        res = make_resource()
        for field in ("address", "attributes", "fingerprint", "record_id", "support_status"):
            with self.subTest(field=field), self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(res, field, "x")

    def test_nested_json_cannot_be_mutated(self) -> None:
        res = make_resource()
        with self.assertRaises(TypeError):
            res.attributes["instance_type"] = "x"  # type: ignore[index]
        with self.assertRaises(TypeError):
            res.attributes["tags"]["Name"] = "x"  # type: ignore[index]
        with self.assertRaises(TypeError):
            res.security_attributes["ingress"][0]["port"] = 1  # type: ignore[index]
        with self.assertRaises(TypeError):
            res.security_attributes["ingress"][0] = {}  # type: ignore[index]

    def test_mutating_the_callers_input_changes_nothing(self) -> None:
        attributes: dict[str, Any] = {"instance_type": "t3.micro", "tags": {"Name": "app"}}
        res = make_resource(attributes=attributes)
        before_fingerprint, before_dict = res.fingerprint, res.to_dict()
        attributes["tags"]["Name"] = "evil"
        attributes["extra"] = 1
        self.assertEqual(res.fingerprint, before_fingerprint)
        self.assertEqual(res.to_dict(), before_dict)
        self.assertEqual(res.attributes["tags"]["Name"], "app")


class TestSerialization(unittest.TestCase):
    def test_to_dict_is_json_serializable_with_stable_strings(self) -> None:
        data = make_resource().to_dict()
        json.dumps(data)
        self.assertEqual(data["support_status"], "SUPPORTED")
        self.assertEqual(data["record_id"], RECORD_A)
        self.assertIsInstance(data["references"], list)
        self.assertEqual(data["references"][0]["resolution_status"], "SUPPORTED")
        self.assertIs(type(data["attributes"]), dict)

    def test_round_trip(self) -> None:
        res = make_resource(support_status=ResourceSupport.UNKNOWN)
        self.assertEqual(Resource.from_dict(res.to_dict()), res)

    def test_from_dict_revalidates_the_hashes(self) -> None:
        good = make_resource().to_dict()
        tampered_attributes = {**good, "attributes": {"instance_type": "m5.large"}}
        with self.assertRaises(HashMismatchError):
            Resource.from_dict(tampered_attributes)
        with self.assertRaises(HashMismatchError):
            Resource.from_dict({**good, "fingerprint": "f" * 64})
        with self.assertRaises(HashMismatchError):
            Resource.from_dict({**good, "canonical_json": "{}"})

    def test_from_dict_revalidates_other_fields(self) -> None:
        good = make_resource().to_dict()
        for key, bad in (
            ("record_id", "nope"),
            ("address", ""),
            ("support_status", "MAYBE"),
            ("provenance", {"source_kind": "TERRAFORM_CONFIG"}),
        ):
            with self.subTest(key=key), self.assertRaises(DomainValidationError):
                Resource.from_dict({**good, key: bad})

    def test_from_dict_rejects_missing_and_unknown_keys(self) -> None:
        good = make_resource().to_dict()
        with self.assertRaises(DomainValidationError):
            Resource.from_dict({k: v for k, v in good.items() if k != "fingerprint"})
        with self.assertRaises(DomainValidationError):
            Resource.from_dict({**good, "extra": 1})


class TestEmptyAddressRequirement(unittest.TestCase):
    """Carried over from the old model: an empty address is invalid."""

    def test_empty_address_rejected(self) -> None:
        with self.assertRaises(DomainValidationError):
            make_resource(address="", references=[])


class TestFrozenCarriedOver(unittest.TestCase):
    """Carried over (and narrowed) from the old B017 test: the resource is frozen."""

    def test_resource_is_frozen(self) -> None:
        res = make_resource()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            res.address = "something-else"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
