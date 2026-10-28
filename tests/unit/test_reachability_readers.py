"""The reader of the INV-FUNC-001 inputs (P5b step 3; registry §6.2, §6.3, §6.6; C-151, C-153).

Expected values are written by hand from the stored shape P3a writes (``Resource.attributes`` in the
C-112 encoding, dumped from the canonical fixture) and from the registry fields §6.6 lists as the
footprint: for ``S`` the ``subnet_id``, ``vpc_security_group_ids``, ``security_groups``,
``private_ip``, ``network_interface`` and ``primary_network_interface``; for ``D`` the
``vpc_security_group_ids``, ``port`` and ``engine``; for a subnet the ``vpc_id`` and ``cidr_block``;
for a VPC the ``cidr_block``; for a route table its routes and ``propagating_vgws``.

A stored shape the reader cannot read raises ``ViewError``; it is never "absent".
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.domain.enums import ResourceSupport
from core.terraform_model.normalization import normalize_directory
from core.verification.cidr import Network
from core.verification.func_view import (
    Fact,
    items_of,
    read_database,
    read_group_network,
    read_instance,
    read_route_table,
    read_subnet,
    read_vpc,
)
from core.verification.values import Ref, Unknown, Unsupported
from core.verification.views import ViewError
from tests import fixture_catalog as fc
from tests.func_builders import attribute, canonical, with_attributes
from tests.identity_builders import NOW
from tests.security_builders import VARS, resources_of

CANON = {r.address: r for r in resources_of(canonical())}
ABSENT = Fact("absent")


def one(text: str, address: str):  # type: ignore[no-untyped-def]
    return next(r for r in resources_of(text) if r.address == address)


def instance(body: str):  # type: ignore[no-untyped-def]
    text = VARS + f'resource "aws_instance" "s" {{\n  ami = "ami-1"\n{body}}}\n'
    return read_instance(one(text, "aws_instance.s"))


def table(body: str):  # type: ignore[no-untyped-def]
    text = VARS + f'resource "aws_route_table" "t" {{\n  vpc_id = "vpc-1"\n{body}}}\n'
    return read_route_table(one(text, "aws_route_table.t"))


def route(body: str):  # type: ignore[no-untyped-def]
    view = table(f"  route {{\n{body}  }}\n")
    (found,) = view.routes
    return found


class TestCanonicalResources(unittest.TestCase):
    def test_the_instance(self) -> None:
        view = read_instance(CANON["aws_instance.app"])
        self.assertEqual(view.address, "aws_instance.app")
        self.assertEqual(view.support, ResourceSupport.SUPPORTED)
        self.assertEqual(view.subnet_id, Fact("known", Ref("aws_subnet.app", "id")))
        self.assertEqual(
            view.vpc_security_group_ids, Fact("known", (Ref("aws_security_group.app", "id"),))
        )
        self.assertEqual((view.security_groups, view.private_ip), (ABSENT, ABSENT))
        self.assertEqual(view.interface_blocks, ())

    def test_the_database(self) -> None:
        view = read_database(CANON["aws_db_instance.database"])
        self.assertEqual((view.port, view.engine), (ABSENT, Fact("known", "postgres")))
        self.assertEqual(
            view.vpc_security_group_ids, Fact("known", (Ref("aws_security_group.db", "id"),))
        )

    def test_subnet_vpc_and_group(self) -> None:
        subnet = read_subnet(CANON["aws_subnet.app"])
        self.assertEqual(subnet.vpc_id, Fact("known", Ref("aws_vpc.main", "id")))
        self.assertEqual(subnet.cidr_block, Fact("known", "10.0.1.0/24"))
        self.assertEqual(read_vpc(CANON["aws_vpc.main"]).cidr_block, Fact("known", "10.0.0.0/16"))
        group = read_group_network(CANON["aws_security_group.db"])
        self.assertEqual(group.vpc_id, Fact("known", Ref("aws_vpc.main", "id")))

    def test_the_route_table(self) -> None:
        view = read_route_table(CANON["aws_route_table.public"])
        self.assertEqual(view.vpc_id, Fact("known", Ref("aws_vpc.main", "id")))
        self.assertFalse(view.propagating_vgws_present)
        self.assertIsNone(view.routes_unresolved)
        (found,) = view.routes
        self.assertEqual(found.state, "ipv4")
        self.assertEqual(found.destination, Network(4, 0, 2**32 - 1))
        self.assertEqual(found.target, "other")


class TestFacts(unittest.TestCase):
    def test_a_literal(self) -> None:
        self.assertEqual(
            instance('  private_ip = "10.0.1.10"\n').private_ip, Fact("known", "10.0.1.10")
        )
        self.assertEqual(
            instance('  subnet_id = "subnet-1"\n').subnet_id, Fact("known", "subnet-1")
        )

    def test_name_based_groups(self) -> None:
        view = instance('  security_groups = ["default"]\n')
        self.assertEqual(view.security_groups, Fact("known", ("default",)))

    def test_a_value_that_cannot_be_fixed_is_unknown_with_its_reason(self) -> None:
        fact = instance("  private_ip = var.u\n").private_ip
        self.assertEqual((fact.state, fact.reason), ("unknown", "variable.no_value"))

    def test_an_explicit_null_is_not_set(self) -> None:
        self.assertEqual(instance("  private_ip = null\n").private_ip, ABSENT)

    def test_a_list_with_an_unresolved_element_is_known_but_its_items_say_so(self) -> None:
        text = (
            VARS
            + 'resource "aws_security_group" "a" {}\n'
            + 'resource "aws_instance" "s" {\n  ami = "ami-1"\n'
            + "  vpc_security_group_ids = [aws_security_group.a.id, var.u]\n}\n"
        )
        view = read_instance(one(text, "aws_instance.s"))
        self.assertEqual(view.vpc_security_group_ids.state, "known")
        items = items_of(view.vpc_security_group_ids)
        self.assertEqual(items[0], Ref("aws_security_group.a", "id"))
        self.assertIsInstance(items[1], Unknown)

    def test_a_list_that_cannot_be_fixed_is_unknown(self) -> None:
        self.assertEqual(
            instance("  vpc_security_group_ids = var.u\n").vpc_security_group_ids.state, "unknown"
        )

    def test_items_of_every_state(self) -> None:
        self.assertEqual(items_of(ABSENT), ())
        self.assertEqual(items_of(Fact("known", "x")), ("x",))
        self.assertEqual(items_of(Fact("known", ("a", "b"))), ("a", "b"))
        self.assertEqual(items_of(Fact("unknown", reason="r")), (Unknown("r"),))
        self.assertEqual(items_of(Fact("unsupported", reason="r")), (Unsupported("r"),))

    def test_an_unsupported_value(self) -> None:
        resource = CANON["aws_db_instance.database"]
        damaged = with_attributes(
            resource,
            {"port": attribute({"$dail": "unsupported", "reason": "function.unsupported"})},
        )
        fact = read_database(damaged).port
        self.assertEqual((fact.state, fact.reason), ("unsupported", "function.unsupported"))

    def test_an_argument_written_as_a_block_where_a_value_is_expected(self) -> None:
        damaged = with_attributes(
            CANON["aws_db_instance.database"],
            {"engine": {"form": "BLOCKS", "blocks": [], "indeterminate": []}},
        )
        fact = read_database(damaged).engine
        self.assertEqual((fact.state, fact.reason), ("unsupported", "form.block"))


class TestRoutes(unittest.TestCase):
    def test_a_local_route(self) -> None:
        found = route('    cidr_block = "10.0.0.0/16"\n    gateway_id = "local"\n')
        self.assertEqual((found.state, found.target), ("ipv4", "local"))
        self.assertEqual(found.destination, Network(4, 10 << 24, (10 << 24) + 2**16 - 1))

    def test_a_route_to_a_nat_gateway_or_an_interface_is_not_local(self) -> None:
        for target in ('nat_gateway_id = "nat-1"', 'network_interface_id = "eni-1"'):
            found = route(f'    cidr_block = "10.0.2.0/24"\n    {target}\n')
            self.assertEqual(found.target, "other", target)

    def test_local_plus_another_target_is_not_local(self) -> None:
        found = route(
            '    cidr_block = "10.0.2.0/24"\n    gateway_id = "local"\n'
            '    nat_gateway_id = "nat-1"\n'
        )
        self.assertEqual(found.target, "other")

    def test_a_route_without_a_target_is_treated_as_not_local(self) -> None:
        self.assertEqual(route('    cidr_block = "10.0.2.0/24"\n').target, "other")

    def test_an_unresolved_target_is_unresolved_unless_it_is_surely_local(self) -> None:
        self.assertEqual(
            route('    cidr_block = "10.0.2.0/24"\n    gateway_id = var.u\n').target, "unresolved"
        )

    def test_an_ipv6_only_route(self) -> None:
        found = route('    ipv6_cidr_block = "::/0"\n    gateway_id = "igw-1"\n')
        self.assertEqual((found.state, found.destination), ("ipv6_only", None))

    def test_a_prefix_list_destination_cannot_be_fixed(self) -> None:
        found = route('    destination_prefix_list_id = "pl-1"\n    gateway_id = "igw-1"\n')
        self.assertEqual(found.state, "unresolved")

    def test_an_unresolved_or_invalid_destination(self) -> None:
        self.assertEqual(
            route('    cidr_block = var.u\n    gateway_id = "igw-1"\n').state, "unresolved"
        )
        self.assertEqual(
            route('    cidr_block = "10.0.0.1/8"\n    gateway_id = "igw-1"\n').state, "unsupported"
        )

    def test_a_route_without_any_destination(self) -> None:
        self.assertEqual(route('    gateway_id = "igw-1"\n').state, "unsupported")

    def test_routes_are_read_in_a_fixed_order(self) -> None:
        one_way = table(
            '  route {\n    cidr_block = "10.0.2.0/24"\n    gateway_id = "local"\n  }\n'
            '  route {\n    cidr_block = "0.0.0.0/0"\n    gateway_id = "igw-1"\n  }\n'
        )
        other = table(
            '  route {\n    cidr_block = "0.0.0.0/0"\n    gateway_id = "igw-1"\n  }\n'
            '  route {\n    cidr_block = "10.0.2.0/24"\n    gateway_id = "local"\n  }\n'
        )
        self.assertEqual(one_way.routes, other.routes)
        self.assertEqual(len(one_way.routes), 2)

    def test_the_reader_orders_routes_whatever_order_it_is_given(self) -> None:
        # P3a already stores routes in a canonical order; the reader does not rely on it
        base = CANON["aws_route_table.public"]
        wide = {"cidr_block": "0.0.0.0/0", "gateway_id": "igw-1"}
        narrow = {"cidr_block": "10.0.2.0/24", "gateway_id": "local"}
        views = [
            read_route_table(with_attributes(base, {"route": attribute(order)}))
            for order in ([wide, narrow], [narrow, wide])
        ]
        self.assertEqual(views[0].routes, views[1].routes)
        self.assertEqual([r.target for r in views[0].routes], ["other", "local"])

    def test_no_routes(self) -> None:
        view = table("")
        self.assertEqual((view.routes, view.routes_unresolved), ((), None))

    def test_an_explicit_empty_route_list_and_one_that_cannot_be_fixed(self) -> None:
        self.assertEqual(table("  route = []\n").routes, ())
        self.assertIsNotNone(table("  route = var.u\n").routes_unresolved)

    def test_a_dynamic_route_block_that_cannot_be_expanded(self) -> None:
        body = (
            '  dynamic "route" {\n    for_each = var.u\n    content {\n'
            '      cidr_block = "10.0.2.0/24"\n      gateway_id = "local"\n    }\n  }\n'
        )
        view = table(body)
        self.assertEqual(view.routes, ())
        self.assertIsNotNone(view.routes_unresolved)

    def test_propagating_vgws_even_when_empty(self) -> None:
        self.assertFalse(table("").propagating_vgws_present)
        self.assertTrue(table("  propagating_vgws = []\n").propagating_vgws_present)
        self.assertTrue(table('  propagating_vgws = ["vgw-1"]\n').propagating_vgws_present)


class TestInterfaceBlocks(unittest.TestCase):
    def test_none(self) -> None:
        self.assertEqual(instance("").interface_blocks, ())

    def test_each_kind(self) -> None:
        net = instance(
            '  network_interface {\n    device_index = 0\n    network_interface_id = "eni-1"\n  }\n'
        )
        self.assertEqual(net.interface_blocks, ("network_interface",))
        primary = instance(
            '  primary_network_interface {\n    network_interface_id = "eni-1"\n  }\n'
        )
        self.assertEqual(primary.interface_blocks, ("primary_network_interface",))

    def test_both_kinds_are_listed_in_a_fixed_order(self) -> None:
        both = instance(
            '  primary_network_interface {\n    network_interface_id = "eni-1"\n  }\n'
            '  network_interface {\n    device_index = 1\n    network_interface_id = "eni-2"\n  }\n'
        )
        self.assertEqual(both.interface_blocks, ("network_interface", "primary_network_interface"))

    def test_a_dynamic_block_that_cannot_be_expanded_counts_as_present(self) -> None:
        body = (
            '  dynamic "network_interface" {\n    for_each = var.u\n    content {\n'
            '      device_index = 0\n      network_interface_id = "eni-1"\n    }\n  }\n'
        )
        self.assertEqual(instance(body).interface_blocks, ("network_interface",))

    def test_a_value_that_cannot_be_fixed_counts_as_present(self) -> None:
        # attribute form: `network_interface = var.u` might be any number of blocks
        self.assertEqual(
            instance("  network_interface = var.u\n").interface_blocks, ("network_interface",)
        )

    def test_an_empty_list_is_no_block(self) -> None:
        self.assertEqual(instance("  network_interface = []\n").interface_blocks, ())


class TestPlaceholdersAndErrors(unittest.TestCase):
    def test_a_placeholder_is_read_with_its_support_status_so_it_is_not_taken_for_absent(
        self,
    ) -> None:
        text = VARS + 'resource "aws_instance" "p" {\n  count = var.u\n  ami = "ami-1"\n}\n'
        view = read_instance(one(text, "aws_instance.p"))
        self.assertEqual(view.support, ResourceSupport.UNKNOWN)

    def test_a_stored_value_the_reader_cannot_read_is_an_error(self) -> None:
        base = CANON["aws_instance.app"]
        for bad in (
            {"subnet_id": {"form": "ATTRIBUTE"}},
            {"subnet_id": "plain"},
            {"subnet_id": attribute({"$dail": "weird"})},
            {"subnet_id": attribute({"$dail": "ref", "address": "a"})},
            {"private_ip": {"form": "WEIRD"}},
        ):
            with self.subTest(bad=bad), self.assertRaises(ViewError):
                read_instance(with_attributes(base, bad))

    def test_a_resource_of_the_wrong_type_is_an_error(self) -> None:
        with self.assertRaises(ViewError):
            read_instance(CANON["aws_db_instance.database"])
        with self.assertRaises(ViewError):
            read_route_table(CANON["aws_subnet.app"])
        with self.assertRaises(ViewError):
            read_database(CANON["aws_instance.app"])

    def test_a_damaged_route_table_is_an_error(self) -> None:
        base = CANON["aws_route_table.public"]
        for bad in (
            {"route": {"form": "WEIRD"}},
            {"route": {"form": "BLOCKS", "blocks": [{"type": "route"}], "indeterminate": []}},
            {"route": attribute(["not an object"])},
            {"route": attribute([{"cidr_block": {"$dail": "weird"}}])},
        ):
            with self.subTest(bad=bad), self.assertRaises(ViewError):
                read_route_table(with_attributes(base, bad))


class TestEveryFixture(unittest.TestCase):
    def test_every_functional_resource_of_every_fixture_can_be_read(self) -> None:
        readers = {
            "aws_instance": read_instance,
            "aws_db_instance": read_database,
            "aws_subnet": read_subnet,
            "aws_vpc": read_vpc,
            "aws_security_group": read_group_network,
            "aws_route_table": read_route_table,
        }
        folders = {fx.data["config"] for fx in fc.load_all().values()}
        folders |= {fx.data["parent"] for fx in fc.load_all().values() if fx.data.get("parent")}
        read = 0
        for folder in sorted(folders):
            outcome = normalize_directory(Path(fc.REPO_ROOT) / folder, None, now=NOW)
            for resource in outcome.resources:
                reader = readers.get(resource.resource_type)
                if reader is not None:
                    with self.subTest(folder=folder, resource=resource.address):
                        self.assertEqual(reader(resource).address, resource.address)
                    read += 1
        self.assertGreater(read, 100)


if __name__ == "__main__":
    unittest.main()
