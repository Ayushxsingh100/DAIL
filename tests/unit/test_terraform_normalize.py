"""Per-instance normalization (P3a-3 step 3; Doc 04 §5 to §7; C-33, C-113, C-114, C-118).

Expected content is written by hand from the field tables of the work package (Doc 04 §7) and the
register rows C-112 to C-114.
"""

from __future__ import annotations

import unittest
from collections.abc import Mapping
from typing import Any

from core.domain.enums import ProvenanceSourceKind, ResourceSupport
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.terraform_model.config import PARSER_VERSION
from core.terraform_model.evaluation import EVALUATOR_VERSION
from core.terraform_model.normalize import (
    NORMALIZATION_VERSION,
    SUPPORTED_TYPES,
    normalize_indeterminate,
    normalize_instance,
    support_of,
)
from tests.tf_builders import LATER, NOW, evaluate_ok


def attr(value: object) -> dict[str, object]:
    return {"form": "ATTRIBUTE", "value": value}


def norm(text: str, address: str, variables: Mapping[str, object] | None = None) -> Resource:
    _, outcome = evaluate_ok(text, variables)
    return normalize_instance(outcome.instances[address], now=NOW)


def plain(mapping: Any) -> Any:
    return thaw_json(mapping)


class TestPartition(unittest.TestCase):
    def test_every_argument_is_in_attributes_sorted_by_name(self) -> None:
        resource = norm(
            'resource "aws_vpc" "main" {\n'
            "  enable_dns_support = true\n"
            '  cidr_block = "10.0.0.0/16"\n'
            '  tags = { Name = "m" }\n}\n',
            "aws_vpc.main",
        )
        self.assertEqual(list(resource.attributes), ["cidr_block", "enable_dns_support", "tags"])
        self.assertEqual(
            plain(resource.attributes),
            {
                "cidr_block": attr("10.0.0.0/16"),
                "enable_dns_support": attr(True),
                "tags": attr({"Name": "m"}),
            },
        )
        self.assertEqual(resource.address, "aws_vpc.main")
        self.assertEqual(resource.resource_type, "aws_vpc")
        self.assertEqual(resource.support_status, ResourceSupport.SUPPORTED)

    def test_vpc_views(self) -> None:
        resource = norm(
            'resource "aws_vpc" "main" {\n'
            '  cidr_block = "10.0.0.0/16"\n'
            '  tags = { Name = "m" }\n'
            "}\n",
            "aws_vpc.main",
        )
        self.assertEqual(plain(resource.logical_identity), {})
        self.assertEqual(plain(resource.security_attributes), {})
        self.assertEqual(
            plain(resource.semantic_attributes),
            {
                "cidr_block": "10.0.0.0/16",
                "meta": {"count_present": False, "for_each_present": False, "key_kind": "none"},
            },
        )

    def test_subnet_views(self) -> None:
        resource = norm(
            'resource "aws_vpc" "main" {}\n'
            'resource "aws_subnet" "app" {\n'
            "  vpc_id = aws_vpc.main.id\n"
            '  cidr_block = "10.0.1.0/24"\n  availability_zone = "us-east-1a"\n'
            '  map_public_ip_on_launch = false\n  tags = { A = "b" }\n}\n',
            "aws_subnet.app",
        )
        self.assertEqual(plain(resource.security_attributes), {"map_public_ip_on_launch": False})
        semantic = plain(resource.semantic_attributes)
        self.assertEqual(
            {k: semantic[k] for k in ("vpc_id", "cidr_block", "availability_zone")},
            {
                "vpc_id": {"$dail": "ref", "address": "aws_vpc.main", "attribute": "id"},
                "cidr_block": "10.0.1.0/24",
                "availability_zone": "us-east-1a",
            },
        )
        self.assertNotIn("tags", semantic)

    def test_route_table_views(self) -> None:
        resource = norm(
            'resource "aws_vpc" "main" {}\nresource "aws_internet_gateway" "igw" {}\n'
            'resource "aws_route_table" "public" {\n  vpc_id = aws_vpc.main.id\n'
            "  route {\n"
            '    cidr_block = "0.0.0.0/0"\n'
            "    gateway_id = aws_internet_gateway.igw.id\n"
            "  }\n"
            "}\n",
            "aws_route_table.public",
        )
        semantic = plain(resource.semantic_attributes)
        self.assertEqual(semantic["propagating_vgws_present"], False)
        routes = semantic["routes"]
        self.assertEqual(routes["form"], "BLOCKS")
        self.assertEqual(
            routes["blocks"][0]["arguments"]["gateway_id"],
            attr({"$dail": "ref", "address": "aws_internet_gateway.igw", "attribute": "id"}),
        )
        with_vgws = norm(
            'resource "aws_route_table" "t" {\n  propagating_vgws = ["vgw-1"]\n}\n',
            "aws_route_table.t",
        )
        self.assertTrue(plain(with_vgws.semantic_attributes)["propagating_vgws_present"])
        self.assertNotIn("routes", plain(with_vgws.semantic_attributes))

    def test_association_and_gateway_views(self) -> None:
        text = (
            'resource "aws_vpc" "main" {}\n'
            'resource "aws_subnet" "s" {}\n'
            'resource "aws_route_table" "t" {}\n'
            'resource "aws_route_table_association" "a" {\n  subnet_id = aws_subnet.s.id\n'
            "  route_table_id = aws_route_table.t.id\n}\n"
            'resource "aws_internet_gateway" "igw" {\n  vpc_id = aws_vpc.main.id\n}\n'
        )
        association = plain(norm(text, "aws_route_table_association.a").semantic_attributes)
        self.assertEqual(
            sorted(k for k in association if k != "meta"), ["route_table_id", "subnet_id"]
        )
        gateway = plain(norm(text, "aws_internet_gateway.igw").semantic_attributes)
        self.assertEqual(sorted(k for k in gateway if k != "meta"), ["vpc_id"])

    def test_instance_views(self) -> None:
        text = (
            'resource "aws_security_group" "a" {}\nresource "aws_subnet" "s" {}\n'
            'resource "aws_instance" "app" {\n  ami = "ami-1"\n  instance_type = "t3.micro"\n'
            '  subnet_id = aws_subnet.s.id\n  private_ip = "10.0.1.5"\n'
            "  vpc_security_group_ids = [aws_security_group.a.id]\n"
            "  associate_public_ip_address = true\n}\n"
        )
        resource = norm(text, "aws_instance.app")
        self.assertEqual(
            plain(resource.security_attributes),
            {
                "vpc_security_group_ids": [
                    {"$dail": "ref", "address": "aws_security_group.a", "attribute": "id"}
                ],
                "associate_public_ip_address": True,
            },
        )
        semantic = plain(resource.semantic_attributes)
        self.assertEqual(semantic["private_ip"], "10.0.1.5")
        self.assertEqual(semantic["network_interface_present"], False)
        self.assertEqual(semantic["primary_network_interface_present"], False)
        self.assertNotIn("instance_type", semantic)
        self.assertNotIn("ami", semantic)
        with_nic = norm(
            'resource "aws_instance" "i" {\n  network_interface {\n    device_index = 0\n  }\n}\n',
            "aws_instance.i",
        )
        self.assertTrue(plain(with_nic.semantic_attributes)["network_interface_present"])

    def test_security_group_views(self) -> None:
        resource = norm(
            'resource "aws_vpc" "main" {}\nresource "aws_security_group" "db" {\n  name = "db"\n'
            '  description = "Database"\n  vpc_id = aws_vpc.main.id\n  egress = []\n}\n',
            "aws_security_group.db",
        )
        self.assertEqual(plain(resource.logical_identity), {"name": "db"})
        security = plain(resource.security_attributes)
        self.assertEqual(security["forms"], {"ingress": "absent", "egress": "explicit_empty"})
        self.assertEqual(security["inline_indeterminate"], [])
        semantic = plain(resource.semantic_attributes)
        self.assertEqual(
            semantic["vpc_id"], {"$dail": "ref", "address": "aws_vpc.main", "attribute": "id"}
        )
        self.assertNotIn("description", semantic)
        self.assertIn("description", plain(resource.attributes))

    def test_database_views(self) -> None:
        text = (
            'resource "aws_security_group" "db" {}\n'
            'resource "aws_db_subnet_group" "db" {\n'
            '  name = "db"\n'
            "}\n"
            'resource "aws_db_instance" "database" {\n'
            '  identifier = "dail-db"\n'
            '  engine = "postgres"\n'
            "  port = 5432\n"
            "  publicly_accessible = false\n"
            "  db_subnet_group_name = aws_db_subnet_group.db.name\n"
            "  vpc_security_group_ids = [aws_security_group.db.id]\n  allocated_storage = 20\n}\n"
        )
        resource = norm(text, "aws_db_instance.database")
        self.assertEqual(plain(resource.logical_identity), {"identifier": "dail-db"})
        self.assertEqual(
            plain(resource.security_attributes),
            {
                "publicly_accessible": False,
                "vpc_security_group_ids": [
                    {"$dail": "ref", "address": "aws_security_group.db", "attribute": "id"}
                ],
            },
        )
        semantic = plain(resource.semantic_attributes)
        self.assertEqual(
            {k: semantic[k] for k in ("engine", "port", "db_subnet_group_name")},
            {"engine": "postgres", "port": 5432, "db_subnet_group_name": "db"},
        )
        self.assertNotIn("allocated_storage", semantic)

    def test_the_tolerated_type_is_kept_as_unsupported(self) -> None:
        resource = norm(
            'resource "aws_subnet" "a" {}\nresource "aws_db_subnet_group" "db" {\n  name = "db"\n'
            '  subnet_ids = [aws_subnet.a.id]\n  description = "d"\n}\n',
            "aws_db_subnet_group.db",
        )
        self.assertEqual(resource.support_status, ResourceSupport.UNSUPPORTED)
        semantic = plain(resource.semantic_attributes)
        self.assertTrue(semantic["tolerated"])
        self.assertEqual(
            semantic["subnet_ids"], [{"$dail": "ref", "address": "aws_subnet.a", "attribute": "id"}]
        )
        self.assertEqual(plain(resource.logical_identity), {"name": "db"})
        self.assertIn("description", plain(resource.attributes))

    def test_another_unsupported_type_is_kept_complete(self) -> None:
        resource = norm(
            'resource "aws_vpc" "main" {}\nresource "aws_network_acl" "extra" {\n'
            '  vpc_id = aws_vpc.main.id\n  egress {\n    protocol = "-1"\n  }\n}\n',
            "aws_network_acl.extra",
        )
        self.assertEqual(resource.support_status, ResourceSupport.UNSUPPORTED)
        self.assertEqual(sorted(resource.attributes), ["egress", "vpc_id"])
        self.assertEqual(plain(resource.security_attributes), {})
        self.assertNotIn("tolerated", plain(resource.semantic_attributes))

    def test_support_of(self) -> None:
        self.assertEqual(len(SUPPORTED_TYPES), 9)
        for name in SUPPORTED_TYPES:
            self.assertEqual(support_of(name), ResourceSupport.SUPPORTED)
        for name in ("aws_db_subnet_group", "aws_network_acl", "aws_lambda_function", "x"):
            self.assertEqual(support_of(name), ResourceSupport.UNSUPPORTED)


class TestAbsentAndNull(unittest.TestCase):
    def test_absent_is_omitted_and_explicit_null_is_kept(self) -> None:
        absent = norm(
            'resource "aws_db_instance" "d" {\n  engine = "postgres"\n}\n', "aws_db_instance.d"
        )
        null = norm(
            'resource "aws_db_instance" "d" {\n  engine = "postgres"\n  port = null\n}\n',
            "aws_db_instance.d",
        )
        self.assertNotIn("port", plain(absent.semantic_attributes))
        self.assertIn("port", plain(null.semantic_attributes))
        self.assertIsNone(plain(null.semantic_attributes)["port"])
        self.assertNotEqual(absent.fingerprint, null.fingerprint)

    def test_an_unknown_value_is_neither_absent_nor_null(self) -> None:
        text = 'variable "p" {}\nresource "aws_db_instance" "d" {\n  port = var.p\n}\n'
        unknown = norm(text, "aws_db_instance.d")
        self.assertEqual(
            plain(unknown.semantic_attributes)["port"],
            {"$dail": "unknown", "reason": "variable.no_value"},
        )
        null = norm(text, "aws_db_instance.d", {"p": None})
        self.assertIsNone(plain(null.semantic_attributes)["port"])
        self.assertNotEqual(unknown.fingerprint, null.fingerprint)

    def test_an_unsupported_value_stays_visible(self) -> None:
        resource = norm('resource "aws_vpc" "v" {\n  cidr_block = abs(1)\n}\n', "aws_vpc.v")
        expected = {"$dail": "unsupported", "reason": "function.not_implemented:abs"}
        self.assertEqual(plain(resource.attributes)["cidr_block"], attr(expected))
        self.assertEqual(plain(resource.semantic_attributes)["cidr_block"], expected)
        self.assertEqual(resource.support_status, ResourceSupport.SUPPORTED)  # value-level only


class TestIdentityAndMeta(unittest.TestCase):
    def test_the_instance_key_is_in_the_identity(self) -> None:
        _, outcome = evaluate_ok(
            'resource "aws_security_group" "ops" {\n  for_each = toset(["a", "b"])\n'
            '  name = "ops-${each.key}"\n}\n'
            'resource "aws_subnet" "s" {\n  count = 2\n}\n'
        )
        a = normalize_instance(outcome.instances['aws_security_group.ops["a"]'], now=NOW)
        self.assertEqual(plain(a.logical_identity), {"name": "ops-a", "key": "a"})
        self.assertEqual(
            plain(a.semantic_attributes)["meta"],
            {"count_present": False, "for_each_present": True, "key_kind": "str"},
        )
        second = normalize_instance(outcome.instances["aws_subnet.s[1]"], now=NOW)
        self.assertEqual(plain(second.logical_identity), {"key": 1})
        self.assertEqual(
            plain(second.semantic_attributes)["meta"],
            {"count_present": True, "for_each_present": False, "key_kind": "int"},
        )
        self.assertNotEqual(
            normalize_instance(outcome.instances["aws_subnet.s[0]"], now=NOW).fingerprint,
            second.fingerprint,
        )

    def test_meta_arguments_that_change_semantics(self) -> None:
        resource = norm(
            'resource "aws_vpc" "v" {\n  provider = aws.west\n  lifecycle {\n'
            "    create_before_destroy = true\n    prevent_destroy = true\n  }\n}\n",
            "aws_vpc.v",
        )
        meta = plain(resource.semantic_attributes)["meta"]
        self.assertEqual(meta["create_before_destroy"], True)
        self.assertEqual(meta["provider"], "aws.west")
        self.assertNotIn("prevent_destroy", meta)

    def test_absent_meta_fields_are_omitted(self) -> None:
        meta = plain(norm('resource "aws_vpc" "v" {}\n', "aws_vpc.v").semantic_attributes)["meta"]
        self.assertEqual(sorted(meta), ["count_present", "for_each_present", "key_kind"])


class TestProvenance(unittest.TestCase):
    def test_provenance_is_complete_and_has_no_clock(self) -> None:
        resource = norm('\nresource "aws_vpc" "v" {}\n', "aws_vpc.v")
        provenance = resource.provenance
        self.assertEqual(provenance.source_kind, ProvenanceSourceKind.TERRAFORM_CONFIG)
        self.assertEqual(provenance.source_component, "core.terraform_model")
        self.assertEqual(provenance.source_reference, "main.tf:2:aws_vpc.v")
        self.assertEqual(provenance.observed_at, NOW)
        self.assertEqual(provenance.tool_name, "dail-terraform-model")
        self.assertEqual(provenance.tool_version, PARSER_VERSION)
        self.assertEqual(provenance.parser_version, PARSER_VERSION)
        self.assertEqual(provenance.normalization_version, NORMALIZATION_VERSION)
        self.assertEqual(provenance.algorithm_version, EVALUATOR_VERSION)
        self.assertEqual(
            provenance.transformation_steps,
            ("parse", "validate", "evaluate", "expand", "normalize"),
        )
        self.assertEqual(NORMALIZATION_VERSION, "dail-tf-norm-1")

    def test_there_is_no_terraform_cli_version_in_the_provenance(self) -> None:
        text = repr(norm('resource "aws_vpc" "v" {}\n', "aws_vpc.v").provenance.to_dict())
        self.assertNotIn("1.15", text)

    def test_the_caller_supplies_the_time(self) -> None:
        _, outcome = evaluate_ok('resource "aws_vpc" "v" {}\n')
        later = normalize_instance(outcome.instances["aws_vpc.v"], now=LATER)
        self.assertEqual(later.provenance.observed_at, LATER)


class TestDeterminism(unittest.TestCase):
    TEXT = 'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n  tags = { Name = "m" }\n}\n'

    def test_same_semantics_same_fingerprint_and_canonical_json(self) -> None:
        _, outcome = evaluate_ok(self.TEXT)
        first = normalize_instance(outcome.instances["aws_vpc.main"], now=NOW)
        second = normalize_instance(outcome.instances["aws_vpc.main"], now=LATER)
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.canonical_json, second.canonical_json)
        self.assertNotEqual(first.record_id, second.record_id)

    def test_object_key_order_in_the_source_does_not_matter(self) -> None:
        other = (
            'resource "aws_vpc" "main" {\n'
            '  tags = { Name = "m" }\n'
            '  cidr_block = "10.0.0.0/16"\n'
            "}\n"
        )
        self.assertEqual(
            norm(self.TEXT, "aws_vpc.main").fingerprint, norm(other, "aws_vpc.main").fingerprint
        )

    def test_the_address_is_not_part_of_the_fingerprint(self) -> None:
        renamed = self.TEXT.replace('"main"', '"renamed"')
        self.assertEqual(
            norm(self.TEXT, "aws_vpc.main").fingerprint,
            norm(renamed, "aws_vpc.renamed").fingerprint,
        )

    def test_a_tag_change_changes_attributes_and_not_the_views(self) -> None:
        before = norm(self.TEXT, "aws_vpc.main")
        after = norm(self.TEXT.replace('"m"', '"n"'), "aws_vpc.main")
        self.assertNotEqual(before.fingerprint, after.fingerprint)
        self.assertNotEqual(plain(before.attributes), plain(after.attributes))
        self.assertEqual(plain(before.security_attributes), plain(after.security_attributes))
        self.assertEqual(plain(before.semantic_attributes), plain(after.semantic_attributes))

    def test_a_security_change_changes_the_fingerprint(self) -> None:
        a = norm(
            'resource "aws_db_instance" "d" {\n  publicly_accessible = false\n}\n',
            "aws_db_instance.d",
        )
        b = norm(
            'resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}\n',
            "aws_db_instance.d",
        )
        self.assertNotEqual(a.fingerprint, b.fingerprint)
        self.assertEqual(plain(a.security_attributes), {"publicly_accessible": False})

    def test_set_like_arguments_and_blocks_in_any_order(self) -> None:
        def group(first: str, second: str, cidrs: str) -> str:
            def inline(port: str, extra: str) -> str:
                return (
                    "  ingress {\n"
                    f"    from_port = {port}\n"
                    f"    to_port = {port}\n"
                    '    protocol = "tcp"\n'
                    f"{extra}"
                    "  }\n"
                )

            return (
                'resource "aws_security_group" "g" {\n'
                + inline(first, f"    cidr_blocks = {cidrs}\n")
                + inline(second, "")
                + "}\n"
            )

        one = norm(group("22", "80", '["10.0.0.0/8", "192.168.0.0/16"]'), "aws_security_group.g")
        two = norm(group("22", "80", '["192.168.0.0/16", "10.0.0.0/8"]'), "aws_security_group.g")
        self.assertEqual(one.fingerprint, two.fingerprint)
        swapped = norm(
            'resource "aws_security_group" "g" {\n'
            '  ingress {\n    from_port = 80\n    to_port = 80\n    protocol = "tcp"\n  }\n'
            '  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n'
            '    cidr_blocks = ["10.0.0.0/8", "192.168.0.0/16"]\n  }\n}\n',
            "aws_security_group.g",
        )
        self.assertEqual(one.fingerprint, swapped.fingerprint)

    def test_a_list_argument_that_is_not_a_set_keeps_its_order(self) -> None:
        one = norm('resource "aws_vpc" "v" {\n  x = ["a", "b"]\n}\n', "aws_vpc.v")
        two = norm('resource "aws_vpc" "v" {\n  x = ["b", "a"]\n}\n', "aws_vpc.v")
        self.assertNotEqual(one.fingerprint, two.fingerprint)

    def test_vpc_security_group_ids_are_a_set(self) -> None:
        def instance(order: str) -> str:
            return (
                'resource "aws_security_group" "a" {}\nresource "aws_security_group" "b" {}\n'
                f'resource "aws_instance" "i" {{\n  vpc_security_group_ids = [{order}]\n}}\n'
            )

        one = norm(instance("aws_security_group.a.id, aws_security_group.b.id"), "aws_instance.i")
        two = norm(instance("aws_security_group.b.id, aws_security_group.a.id"), "aws_instance.i")
        self.assertEqual(one.fingerprint, two.fingerprint)


class TestDirectionForms(unittest.TestCase):
    def forms(self, body: str, variables: Mapping[str, object] | None = None) -> dict[str, Any]:
        text = 'variable "v" {}\nresource "aws_security_group" "g" {\n' + body + "\n}\n"
        resource = norm(text, "aws_security_group.g", variables)
        return plain(resource.security_attributes)

    def test_absent(self) -> None:
        self.assertEqual(
            self.forms('  name = "g"')["forms"], {"ingress": "absent", "egress": "absent"}
        )

    def test_blocks_and_explicit_empty(self) -> None:
        forms = self.forms("  ingress {\n    from_port = 22\n  }\n  egress = []")["forms"]
        self.assertEqual(forms, {"ingress": "blocks", "egress": "explicit_empty"})

    def test_dynamic_and_mixed(self) -> None:
        dynamic = (
            '  dynamic "ingress" {\n'
            "    for_each = [22]\n"
            "    content {\n"
            "      from_port = ingress.value\n"
            "    }\n"
            "  }"
        )
        self.assertEqual(self.forms(dynamic)["forms"]["ingress"], "dynamic")
        mixed = "  ingress {\n    from_port = 1\n  }\n" + dynamic
        self.assertEqual(self.forms(mixed)["forms"]["ingress"], "mixed")

    def test_a_non_empty_attribute_list_is_blocks(self) -> None:
        forms = self.forms("  ingress = [{ from_port = 22 }]")["forms"]
        self.assertEqual(forms["ingress"], "blocks")

    def test_null_is_absent(self) -> None:
        self.assertEqual(self.forms("  ingress = null")["forms"]["ingress"], "absent")

    def test_an_unresolved_attribute_is_visible(self) -> None:
        view = self.forms("  ingress = var.v")
        self.assertEqual(view["forms"]["ingress"], "unresolved")
        self.assertEqual(
            view["inline_indeterminate"], [{"$dail": "unknown", "reason": "variable.no_value"}]
        )

    def test_an_indeterminate_dynamic_group_is_visible(self) -> None:
        view = self.forms('  dynamic "ingress" {\n    for_each = var.v\n    content {}\n  }')
        self.assertEqual(view["forms"]["ingress"], "dynamic")
        self.assertEqual(
            view["inline_indeterminate"], [{"$dail": "unknown", "reason": "variable.no_value"}]
        )

    def test_an_attribute_that_is_not_a_list_is_unsupported_not_ignored(self) -> None:
        view = self.forms("  ingress = 5")
        self.assertEqual(view["forms"]["ingress"], "unresolved")
        self.assertEqual(
            view["inline_indeterminate"],
            [{"$dail": "unsupported", "reason": "normalize.inline_form"}],
        )


class TestIndeterminateAndLimits(unittest.TestCase):
    def test_the_placeholder_of_a_resource_without_instances(self) -> None:
        _, outcome = evaluate_ok(
            'variable "n" {}\nresource "aws_subnet" "s" {\n  count = var.n\n}\n'
        )
        placeholder = normalize_indeterminate(outcome.indeterminate["aws_subnet.s"], now=NOW)
        self.assertEqual(placeholder.address, "aws_subnet.s")
        self.assertEqual(placeholder.support_status, ResourceSupport.UNKNOWN)
        self.assertEqual(plain(placeholder.attributes), {})
        self.assertEqual(plain(placeholder.security_attributes), {})
        self.assertEqual(
            plain(placeholder.semantic_attributes),
            {
                "indeterminate": {
                    "$dail": "unknown",
                    "reason": "expansion.count_unknown:variable.no_value",
                },
                "meta": {"count_present": True, "for_each_present": False, "key_kind": "unknown"},
            },
        )

    def test_two_placeholders_with_one_reason_are_equal(self) -> None:
        text = 'variable "n" {}\nresource "aws_subnet" "s" {\n  count = var.n\n}\n'
        first = normalize_indeterminate(evaluate_ok(text)[1].indeterminate["aws_subnet.s"], now=NOW)
        second = normalize_indeterminate(
            evaluate_ok(text)[1].indeterminate["aws_subnet.s"], now=NOW
        )
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_only_resources_are_normalized(self) -> None:
        _, outcome = evaluate_ok('data "aws_ami" "x" {}\n')
        with self.assertRaises(ValueError):
            normalize_instance(outcome.instances["data.aws_ami.x"], now=NOW)

    def test_content_nested_deeper_than_the_domain_limit_is_kept_unsupported(self) -> None:
        levels = 30
        text = 'resource "aws_vpc" "v" {\n'
        text += "".join("b {\n" for _ in range(levels)) + "x = 1\n" + "}\n" * levels + "}\n"
        resource = norm(text, "aws_vpc.v")
        self.assertEqual(resource.support_status, ResourceSupport.UNSUPPORTED)
        self.assertEqual(
            plain(resource.attributes),
            {"$content": {"$dail": "unsupported", "reason": "limit.json_depth"}},
        )

    def test_a_modest_nesting_is_fine(self) -> None:
        text = 'resource "aws_vpc" "v" {\n' + "b {\n" * 8 + "x = 1\n" + "}\n" * 8 + "}\n"
        self.assertEqual(norm(text, "aws_vpc.v").support_status, ResourceSupport.SUPPORTED)


if __name__ == "__main__":
    unittest.main()
