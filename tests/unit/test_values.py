"""Reference and Provenance value objects (Doc 05 §5.3, §6; Doc 11 §21; C-34; P1a step 7)."""

from __future__ import annotations

import dataclasses
import json
import unittest
from datetime import UTC, datetime, timedelta, timezone

from core.domain.enums import ProvenanceSourceKind, ReferenceResolution
from core.domain.errors import DomainValidationError
from core.domain.values import Provenance, Reference

NOW = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)


def make_reference(**overrides: object) -> Reference:
    fields: dict[str, object] = {
        "source_address": "aws_instance.app",
        "source_attribute": "vpc_security_group_ids",
        "target_address": "aws_security_group.web",
        "reference_type": "security_group",
        "resolution_status": ReferenceResolution.SUPPORTED,
    }
    fields.update(overrides)
    return Reference(**fields)  # type: ignore[arg-type]


def make_provenance(**overrides: object) -> Provenance:
    fields: dict[str, object] = {
        "source_kind": ProvenanceSourceKind.TERRAFORM_CONFIG,
        "source_component": "terraform_model",
        "source_reference": "main.tf",
        "observed_at": NOW,
    }
    fields.update(overrides)
    return Provenance(**fields)  # type: ignore[arg-type]


class TestReference(unittest.TestCase):
    def test_valid_reference_keeps_its_fields(self) -> None:
        ref = make_reference()
        self.assertEqual(ref.source_address, "aws_instance.app")
        self.assertEqual(ref.resolution_status, ReferenceResolution.SUPPORTED)

    def test_each_string_field_must_be_non_empty(self) -> None:
        for name in ("source_address", "source_attribute", "target_address", "reference_type"):
            for bad in ("", "  ", " padded ", None, 3):
                with self.subTest(field=name, value=bad), self.assertRaises(DomainValidationError):
                    make_reference(**{name: bad})

    def test_resolution_status_must_be_the_enum(self) -> None:
        for bad in ("SUPPORTED", None, 1):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                make_reference(resolution_status=bad)

    def test_unknown_and_unsupported_resolution_are_representable(self) -> None:
        for status in (ReferenceResolution.UNKNOWN, ReferenceResolution.UNSUPPORTED):
            self.assertEqual(make_reference(resolution_status=status).resolution_status, status)

    def test_reference_is_frozen(self) -> None:
        ref = make_reference()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ref.target_address = "other"  # type: ignore[misc]

    def test_round_trip(self) -> None:
        ref = make_reference(resolution_status=ReferenceResolution.UNKNOWN)
        data = ref.to_dict()
        json.dumps(data)
        self.assertEqual(data["resolution_status"], "UNKNOWN")
        self.assertIs(type(data["resolution_status"]), str)
        self.assertEqual(Reference.from_dict(data), ref)

    def test_from_dict_revalidates(self) -> None:
        good = make_reference().to_dict()
        for key, bad in (
            ("target_address", ""),
            ("resolution_status", "MAYBE"),
            ("reference_type", None),
        ):
            with self.subTest(key=key), self.assertRaises(DomainValidationError):
                Reference.from_dict({**good, key: bad})

    def test_from_dict_rejects_missing_and_unknown_keys(self) -> None:
        good = make_reference().to_dict()
        missing = {k: v for k, v in good.items() if k != "reference_type"}
        with self.assertRaises(DomainValidationError):
            Reference.from_dict(missing)
        with self.assertRaises(DomainValidationError):
            Reference.from_dict({**good, "extra": "x"})
        with self.assertRaises(DomainValidationError):
            Reference.from_dict(["not", "a", "mapping"])  # type: ignore[arg-type]


class TestProvenance(unittest.TestCase):
    def test_minimal_provenance_uses_explicit_nulls_and_empty_steps(self) -> None:
        prov = make_provenance()
        for name in (
            "tool_name",
            "tool_version",
            "parser_version",
            "normalization_version",
            "algorithm_version",
        ):
            self.assertIsNone(getattr(prov, name), name)
        self.assertEqual(prov.transformation_steps, ())

    def test_required_fields_must_be_non_empty(self) -> None:
        for name in ("source_component", "source_reference"):
            for bad in ("", " ", None, 5):
                with self.subTest(field=name, value=bad), self.assertRaises(DomainValidationError):
                    make_provenance(**{name: bad})

    def test_source_kind_must_be_the_enum(self) -> None:
        for bad in ("TERRAFORM_CONFIG", None):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                make_provenance(source_kind=bad)

    def test_observed_at_must_be_aware_utc(self) -> None:
        with self.assertRaises(DomainValidationError):
            make_provenance(observed_at=datetime(2026, 10, 1, 9, 30))
        with self.assertRaises(DomainValidationError):
            make_provenance(
                observed_at=datetime(2026, 10, 1, 9, 30, tzinfo=timezone(timedelta(hours=2)))
            )
        with self.assertRaises(DomainValidationError):
            make_provenance(observed_at="2026-10-01T09:30:00+00:00")

    def test_optional_fields_reject_empty_strings_rather_than_meaning_null(self) -> None:
        for name in (
            "tool_name",
            "tool_version",
            "parser_version",
            "normalization_version",
            "algorithm_version",
        ):
            for bad in ("", " ", 3):
                with self.subTest(field=name, value=bad), self.assertRaises(DomainValidationError):
                    make_provenance(**{name: bad})

    def test_optional_fields_accept_text(self) -> None:
        prov = make_provenance(
            tool_name="terraform",
            tool_version="1.15.8",
            parser_version="p-1",
            normalization_version="norm-1",
            algorithm_version="sha256",
        )
        self.assertEqual(prov.tool_version, "1.15.8")

    def test_transformation_steps_become_a_tuple_of_non_empty_strings(self) -> None:
        prov = make_provenance(transformation_steps=["parse", "normalize"])
        self.assertEqual(prov.transformation_steps, ("parse", "normalize"))
        for bad in (["parse", ""], "parse", [1], [None], ["  "]):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                make_provenance(transformation_steps=bad)

    def test_source_kinds_cover_doc05_section_6(self) -> None:
        for kind in ProvenanceSourceKind:
            self.assertEqual(make_provenance(source_kind=kind).source_kind, kind)

    def test_provenance_is_frozen(self) -> None:
        prov = make_provenance()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            prov.tool_name = "x"  # type: ignore[misc]

    def test_input_list_mutation_does_not_change_the_object(self) -> None:
        steps = ["parse"]
        prov = make_provenance(transformation_steps=steps)
        steps.append("evil")
        self.assertEqual(prov.transformation_steps, ("parse",))

    def test_round_trip_with_every_field(self) -> None:
        prov = make_provenance(
            tool_name="terraform",
            tool_version="1.15.8",
            parser_version="p-1",
            normalization_version="norm-1",
            algorithm_version="sha256",
            transformation_steps=("parse", "normalize"),
        )
        data = prov.to_dict()
        json.dumps(data)
        self.assertEqual(data["source_kind"], "TERRAFORM_CONFIG")
        self.assertEqual(data["observed_at"], "2026-10-01T09:30:00+00:00")
        self.assertEqual(data["transformation_steps"], ["parse", "normalize"])
        self.assertEqual(Provenance.from_dict(data), prov)

    def test_round_trip_keeps_explicit_nulls(self) -> None:
        data = make_provenance().to_dict()
        self.assertIsNone(data["tool_name"])
        self.assertIn("algorithm_version", data)
        self.assertEqual(Provenance.from_dict(data), make_provenance())

    def test_from_dict_revalidates(self) -> None:
        good = make_provenance().to_dict()
        for key, bad in (
            ("source_kind", "NOWHERE"),
            ("source_component", ""),
            ("observed_at", "2026-10-01T09:30:00"),
            ("transformation_steps", "parse"),
            ("tool_name", ""),
        ):
            with self.subTest(key=key), self.assertRaises(DomainValidationError):
                Provenance.from_dict({**good, key: bad})

    def test_from_dict_rejects_missing_and_unknown_keys(self) -> None:
        good = make_provenance().to_dict()
        with self.assertRaises(DomainValidationError):
            Provenance.from_dict({k: v for k, v in good.items() if k != "observed_at"})
        with self.assertRaises(DomainValidationError):
            Provenance.from_dict({**good, "extra": 1})


if __name__ == "__main__":
    unittest.main()
