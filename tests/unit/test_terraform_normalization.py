"""The normalization outcome (P3a-3 step 6; Doc 04 §4, §24; C-112 to C-118).

Expected values are written by hand from the register rows and the work package.
"""

from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

from core.domain.enums import ResourceSupport
from core.domain.errors import DomainValidationError, UnauthorizedConstructionError
from core.domain.state import resource_set_hash
from core.terraform_model import normalization as module
from core.terraform_model.config import PARSER_VERSION, ParseStatus
from core.terraform_model.evaluation import EVALUATOR_VERSION
from core.terraform_model.normalization import (
    NormalizationOutcome,
    normalize_configuration,
    normalize_directory,
)
from core.terraform_model.normalize import NORMALIZATION_VERSION
from tests.tf_builders import LATER, NOW, evaluate_text, parse_files

OK = ParseStatus.OK
TEXT = "\n".join(
    [
        'variable "n" {}',
        'resource "aws_vpc" "main" {',
        '  cidr_block = "10.0.0.0/16"',
        "}",
        'resource "aws_subnet" "s" {',
        "  count = 2",
        "  vpc_id = aws_vpc.main.id",
        "}",
        'resource "aws_security_group" "app" {',
        "  vpc_id = aws_vpc.main.id",
        "  ingress {",
        '    protocol = "tcp"',
        "    from_port = 22",
        "    to_port = 22",
        '    cidr_blocks = ["0.0.0.0/0"]',
        "  }",
        "}",
        'resource "aws_network_acl" "extra" {',
        "  vpc_id = aws_vpc.main.id",
        "}",
        'resource "aws_instance" "later" {',
        "  count = var.n",
        "  subnet_id = aws_subnet.s[0].id",
        "}",
        'data "aws_ami" "base" {}',
        'resource "aws_instance" "app" {',
        "  ami = data.aws_ami.base.id",
        "}",
        "moved {",
        "  from = aws_subnet.old",
        "  to = aws_subnet.s[0]",
        "}",
        "",
    ]
)


def normalize(text: str = TEXT, variables=None, now=NOW) -> NormalizationOutcome:  # type: ignore[no-untyped-def]
    parsed, evaluated = evaluate_text(text, variables)
    return normalize_configuration(parsed, evaluated, now=now)


class TestResources(unittest.TestCase):
    def setUp(self) -> None:
        self.outcome = normalize()

    def test_the_outcome_is_ok_and_complete(self) -> None:
        self.assertEqual(self.outcome.status, OK, self.outcome.diagnostics)
        self.assertEqual(self.outcome.diagnostics, ())
        self.assertEqual(
            [r.address for r in self.outcome.resources],
            [
                "aws_instance.app",
                "aws_instance.later",
                "aws_network_acl.extra",
                "aws_security_group.app",
                "aws_subnet.s[0]",
                "aws_subnet.s[1]",
                "aws_vpc.main",
            ],
        )

    def test_support_status_per_resource(self) -> None:
        status = {r.address: r.support_status for r in self.outcome.resources}
        self.assertEqual(status["aws_vpc.main"], ResourceSupport.SUPPORTED)
        self.assertEqual(status["aws_security_group.app"], ResourceSupport.SUPPORTED)
        self.assertEqual(status["aws_network_acl.extra"], ResourceSupport.UNSUPPORTED)  # kept
        self.assertEqual(status["aws_instance.later"], ResourceSupport.UNKNOWN)  # no instances

    def test_the_placeholder_is_at_the_keyless_address_with_its_references(self) -> None:
        placeholder = next(r for r in self.outcome.resources if r.address == "aws_instance.later")
        self.assertEqual(dict(placeholder.attributes), {})
        self.assertEqual(
            [
                (r.source_attribute, r.target_address, r.resolution_status.value)
                for r in placeholder.references
            ],
            [("subnet_id", "aws_subnet.s[0]", "SUPPORTED")],
        )

    def test_references_are_attached_to_their_resources(self) -> None:
        by_address = {r.address: r for r in self.outcome.resources}
        subnet = by_address["aws_subnet.s[1]"]
        self.assertEqual(
            [(r.source_attribute, r.target_address) for r in subnet.references],
            [("vpc_id", "aws_vpc.main")],
        )
        self.assertTrue(all(r.source_address == "aws_subnet.s[1]" for r in subnet.references))

    def test_data_sources_are_listed_and_are_not_resources(self) -> None:
        self.assertEqual(self.outcome.data_sources, ("data.aws_ami.base",))
        self.assertNotIn("data.aws_ami.base", [r.address for r in self.outcome.resources])
        app = next(r for r in self.outcome.resources if r.address == "aws_instance.app")
        self.assertEqual(
            [(r.target_address, r.resolution_status.value) for r in app.references],
            [("data.aws_ami.base", "UNKNOWN")],
        )

    def test_moves_are_copied_and_not_applied(self) -> None:
        self.assertEqual(self.outcome.moves, (("aws_subnet.old", "aws_subnet.s[0]"),))
        self.assertIn("aws_subnet.s[0]", [r.address for r in self.outcome.resources])

    def test_the_rule_index(self) -> None:
        group = self.outcome.rule_index["aws_security_group.app"]
        self.assertEqual(len(group.ingress), 1)
        self.assertEqual(group.ingress[0].ipv4_sources, ("0.0.0.0/0",))
        self.assertEqual(list(self.outcome.rule_index), ["aws_security_group.app"])

    def test_the_hashes_and_versions(self) -> None:
        parsed, evaluated = evaluate_text(TEXT)
        outcome = normalize_configuration(parsed, evaluated, now=NOW)
        self.assertEqual(
            outcome.resource_set_hash, resource_set_hash(outcome.resources, "dail-tf-norm-1")
        )
        self.assertEqual(outcome.configuration_hash, parsed.configuration_hash)
        self.assertEqual(outcome.variables_hash, evaluated.variables_hash)
        self.assertEqual(outcome.parser_version, PARSER_VERSION)
        self.assertEqual(outcome.evaluator_version, EVALUATOR_VERSION)
        self.assertEqual(outcome.normalization_version, NORMALIZATION_VERSION)
        for resource in outcome.resources:
            self.assertEqual(resource.provenance.normalization_version, "dail-tf-norm-1")
            self.assertEqual(resource.provenance.parser_version, PARSER_VERSION)
            self.assertEqual(resource.provenance.algorithm_version, EVALUATOR_VERSION)

    def test_a_changed_resource_changes_the_set_hash(self) -> None:
        other = normalize(TEXT.replace("10.0.0.0/16", "10.1.0.0/16"))
        self.assertNotEqual(other.resource_set_hash, self.outcome.resource_set_hash)

    def test_the_same_input_gives_the_same_set_hash_whatever_the_time(self) -> None:
        later = normalize(now=LATER)
        self.assertEqual(later.resource_set_hash, self.outcome.resource_set_hash)
        self.assertEqual(
            [r.fingerprint for r in later.resources],
            [r.fingerprint for r in self.outcome.resources],
        )


class TestFailuresAreNotHidden(unittest.TestCase):
    def test_an_invalid_evaluation_gives_no_resources(self) -> None:
        outcome = normalize('resource "aws_vpc" "v" {\n  a = var.nope\n}\n')
        self.assertEqual(outcome.status, ParseStatus.INVALID)
        self.assertEqual([d.code for d in outcome.diagnostics], ["eval.undeclared_reference"])
        self.assertEqual((outcome.resources, outcome.data_sources, outcome.moves), ((), (), ()))
        self.assertIsNone(outcome.resource_set_hash)
        self.assertEqual(dict(outcome.rule_index), {})

    def test_an_unsupported_evaluation_gives_no_resources(self) -> None:
        outcome = normalize('module "m" {\n  source = "./m"\n}\nresource "aws_vpc" "v" {}\n')
        self.assertEqual(outcome.status, ParseStatus.UNSUPPORTED)
        self.assertEqual(outcome.resources, ())

    def test_the_hashes_stay_when_the_status_is_not_ok(self) -> None:
        parsed, evaluated = evaluate_text('resource "aws_vpc" "v" {\n  a = var.nope\n}\n')
        outcome = normalize_configuration(parsed, evaluated, now=NOW)
        self.assertEqual(outcome.configuration_hash, parsed.configuration_hash)
        self.assertEqual(outcome.variables_hash, evaluated.variables_hash)

    def test_a_different_parse_is_refused(self) -> None:
        parsed, _ = evaluate_text('resource "aws_vpc" "v" {}\n')
        _, evaluated = evaluate_text('resource "aws_vpc" "w" {}\n')
        with self.assertRaises(ValueError):
            normalize_configuration(parsed, evaluated, now=NOW)


class TestGuard(unittest.TestCase):
    def fields(self, outcome: NormalizationOutcome) -> dict[str, object]:
        return {f.name: getattr(outcome, f.name) for f in dataclasses.fields(outcome)}

    def test_it_cannot_be_built_directly(self) -> None:
        outcome = normalize()
        with self.assertRaises(UnauthorizedConstructionError):
            NormalizationOutcome(**self.fields(outcome))
        with self.assertRaises(UnauthorizedConstructionError):
            NormalizationOutcome(**self.fields(outcome), _token=object())

    def test_it_is_frozen(self) -> None:
        outcome = normalize()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            outcome.status = ParseStatus.INVALID  # type: ignore[misc]
        with self.assertRaises(TypeError):
            outcome.rule_index["x"] = None  # type: ignore[index]

    def test_it_checks_what_it_claims(self) -> None:
        outcome = normalize()
        token = module._NORMALIZATION_TOKEN
        fields = self.fields(outcome)
        with self.assertRaises(DomainValidationError):
            NormalizationOutcome(**{**fields, "status": ParseStatus.UNSUPPORTED}, _token=token)
        with self.assertRaises(DomainValidationError):
            NormalizationOutcome(
                **{**fields, "resources": tuple(reversed(outcome.resources))}, _token=token
            )
        with self.assertRaises(DomainValidationError):
            NormalizationOutcome(**{**fields, "resource_set_hash": "0" * 64}, _token=token)
        with self.assertRaises(DomainValidationError):
            NormalizationOutcome(
                **{**fields, "resources": outcome.resources + outcome.resources[:1]}, _token=token
            )
        broken = normalize('module "m" {\n  source = "./m"\n}\n')
        broken_fields = self.fields(broken)
        with self.assertRaises(DomainValidationError):
            NormalizationOutcome(**{**broken_fields, "resources": outcome.resources}, _token=token)
        with self.assertRaises(DomainValidationError):
            NormalizationOutcome(**{**broken_fields, "resource_set_hash": "x"}, _token=token)


class TestFilesAndOrder(unittest.TestCase):
    def test_the_order_of_files_and_resources_never_matters(self) -> None:
        a = 'resource "aws_vpc" "a" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        b = 'resource "aws_subnet" "b" {\n  vpc_id = aws_vpc.a.id\n}\n'
        first = parse_files({"a.tf": a, "b.tf": b})
        second = parse_files({"a.tf": b, "b.tf": a})
        from core.terraform_model.evaluation import evaluate_configuration

        one = normalize_configuration(first, evaluate_configuration(first), now=NOW)
        two = normalize_configuration(second, evaluate_configuration(second), now=NOW)
        self.assertEqual(one.resource_set_hash, two.resource_set_hash)
        self.assertEqual([r.address for r in one.resources], [r.address for r in two.resources])


class TestDirectory(unittest.TestCase):
    def write(self, directory: str, files: dict[str, str]) -> Path:
        for name, text in files.items():
            (Path(directory) / name).write_text(text, encoding="utf-8", newline="\n")
        return Path(directory)

    def test_a_directory_is_parsed_evaluated_and_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                directory,
                {"main.tf": 'variable "v" {}\nresource "aws_vpc" "x" {\n  c = var.v\n}\n'},
            )
            outcome = normalize_directory(path, {"v": "10.0.0.0/16"}, now=NOW)
        self.assertEqual(outcome.status, OK)
        (resource,) = outcome.resources
        self.assertEqual(dict(resource.attributes)["c"]["value"], "10.0.0.0/16")

    def test_a_parse_failure_is_reported_with_no_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, {"main.tf": 'resource "aws_vpc" {\n'})
            outcome = normalize_directory(path, None, now=NOW)
        self.assertEqual(outcome.status, ParseStatus.INVALID)
        self.assertEqual(outcome.resources, ())
        self.assertIsNone(outcome.configuration_hash)
        self.assertGreater(len(outcome.diagnostics), 0)

    def test_an_empty_directory_is_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outcome = normalize_directory(Path(directory), None, now=NOW)
        self.assertEqual(outcome.status, ParseStatus.UNSUPPORTED)

    def test_the_variables_are_part_of_the_hash(self) -> None:
        text = 'variable "v" {\n  default = "d"\n}\nresource "aws_vpc" "x" {\n  c = var.v\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, {"main.tf": text})
            one = normalize_directory(path, {"v": "a"}, now=NOW)
            two = normalize_directory(path, {"v": "b"}, now=NOW)
            none = normalize_directory(path, None, now=NOW)
        self.assertNotEqual(one.variables_hash, two.variables_hash)
        self.assertNotEqual(one.resource_set_hash, two.resource_set_hash)
        self.assertEqual(none.configuration_hash, one.configuration_hash)


if __name__ == "__main__":
    unittest.main()
