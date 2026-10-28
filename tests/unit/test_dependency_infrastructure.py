"""Typed infrastructure edges and unresolved slots (P3c step 4; Doc 07 §16-§18, §23-§24, §36.2;
C-133 items 4, 5, 7).

The slot table below is typed in from the Doc 07 §16 table and the argument names of C-112; it is
compared with ``core.dependency.slots.SLOTS`` and also drives the generated scenarios, so a row
missing from the engine's table fails both checks.
"""

from __future__ import annotations

import unittest

from core.dependency.slots import REFERENCE_ARGUMENTS, SLOTS
from core.domain.enums import DependencyStatus, ResourceSupport
from core.domain.graph import DerivationRule, EdgeType, GraphEdge, Relationship
from tests.graph_builders import (
    BASELINE,
    BASELINE_INFRASTRUCTURE_EDGES,
    edges_of,
    fixture_resources,
    hand_ref,
    hand_resource,
    resources_of,
)

K, UC, UN = (
    DependencyStatus.KNOWN,
    DependencyStatus.UNCERTAIN,
    DependencyStatus.UNSUPPORTED,
)
R = Relationship

# Doc 07 §16: (source type, argument, target type, relationship).
SECTION_16 = (
    ("aws_subnet", "vpc_id", "aws_vpc", R.SUBNET_BELONGS_TO_VPC),
    ("aws_route_table", "vpc_id", "aws_vpc", R.ROUTE_TABLE_BELONGS_TO_VPC),
    ("aws_route_table_association", "subnet_id", "aws_subnet", R.ASSOCIATES_SUBNET),
    ("aws_route_table_association", "route_table_id", "aws_route_table", R.ASSOCIATES_ROUTE_TABLE),
    ("aws_internet_gateway", "vpc_id", "aws_vpc", R.IGW_ATTACHED_TO_VPC),
    ("aws_instance", "subnet_id", "aws_subnet", R.INSTANCE_IN_SUBNET),
    (
        "aws_instance",
        "vpc_security_group_ids",
        "aws_security_group",
        R.INSTANCE_USES_SECURITY_GROUP,
    ),
    ("aws_instance", "security_groups", "aws_security_group", R.INSTANCE_USES_SECURITY_GROUP),
    ("aws_db_instance", "vpc_security_group_ids", "aws_security_group", R.DB_USES_SECURITY_GROUP),
    (
        "aws_security_group_rule",
        "security_group_id",
        "aws_security_group",
        R.RULE_BELONGS_TO_SECURITY_GROUP,
    ),
)

# A resource block per type, written so that nothing but the slot argument varies.
TARGET_BLOCK = {
    "aws_vpc": 'resource "aws_vpc" "t" { cidr_block = "10.0.0.0/16" }',
    "aws_subnet": 'resource "aws_subnet" "t" { cidr_block = "10.0.1.0/24" }',
    "aws_route_table": 'resource "aws_route_table" "t" { }',
    "aws_security_group": 'resource "aws_security_group" "t" { name = "t" }',
}
OTHER_TARGET = {
    "aws_vpc": "aws_subnet",
    "aws_subnet": "aws_vpc",
    "aws_route_table": "aws_vpc",
    "aws_security_group": "aws_vpc",
}
SET_ARGUMENTS = {"vpc_security_group_ids", "security_groups"}
OTHER_ARGUMENT = {
    # the other required slot arguments of a source type, so a scenario varies only one
    ("aws_route_table_association", "subnet_id"): 'route_table_id = "rtb-1"',
    ("aws_route_table_association", "route_table_id"): 'subnet_id = "subnet-1"',
}


def scenario(source: str, argument: str, expression: str | None) -> str:
    """Configuration text with one ``source`` whose ``argument`` is ``expression`` (absent if
    ``None``), next to a block of every target type and a variable without a value."""
    value = "" if expression is None else f"{argument} = {expression}"
    extra = OTHER_ARGUMENT.get((source, argument), "")
    blocks = "\n".join(TARGET_BLOCK.values())
    return f"""
variable "unset" {{}}
{blocks}
resource "{source}" "x" {{
  {value}
  {extra}
}}
"""


def element(argument: str, expression: str) -> str:
    return f"[{expression}]" if argument in SET_ARGUMENTS else expression


def infrastructure(edges: tuple[GraphEdge, ...], source: str) -> list[GraphEdge]:
    return [
        e
        for e in edges
        if e.edge_type is EdgeType.INFRASTRUCTURE and e.source_node_id == f"RESOURCE:{source}"
    ]


class TestSlotTable(unittest.TestCase):
    def test_the_slot_table_is_the_section_16_table(self) -> None:
        engine = {
            (slot.source_type, argument, slot.target_type, slot.relationship)
            for slot in SLOTS
            for argument in slot.arguments
        }
        self.assertEqual(engine, set(SECTION_16))

    def test_the_nine_relationships_each_have_a_slot(self) -> None:
        self.assertEqual(len({slot.relationship for slot in SLOTS}), 9)

    def test_the_instance_security_group_arguments_are_one_slot(self) -> None:
        group = [s for s in SLOTS if s.relationship is R.INSTANCE_USES_SECURITY_GROUP]
        self.assertEqual(len(group), 1)
        self.assertEqual(set(group[0].arguments), {"vpc_security_group_ids", "security_groups"})

    def test_the_rule_source_group_is_a_reference_argument_not_a_slot(self) -> None:
        self.assertEqual(
            [(r.source_type, r.argument) for r in REFERENCE_ARGUMENTS],
            [("aws_security_group_rule", "source_security_group_id")],
        )
        self.assertNotIn("source_security_group_id", {a for s in SLOTS for a in s.arguments})


class TestEverySlot(unittest.TestCase):
    """The six cases of C-133 item 4 for every row of the section 16 table."""

    def run_case(self, source: str, argument: str, expression: str | None) -> list[GraphEdge]:
        text = scenario(
            source, argument, None if expression is None else element(argument, expression)
        )
        _, edges = edges_of(resources_of(text))
        return infrastructure(edges, f"{source}.x")

    def only(self, found: list[GraphEdge], relationship: Relationship) -> list[GraphEdge]:
        return [e for e in found if e.relationship is relationship]

    def test_s1_a_reference_to_the_target_type_is_a_typed_edge(self) -> None:
        for source, argument, target, relationship in SECTION_16:
            with self.subTest(source=source, argument=argument):
                found = self.only(self.run_case(source, argument, f"{target}.t.id"), relationship)
                typed = [e for e in found if e.target_node_id == f"RESOURCE:{target}.t"]
                self.assertEqual(len(typed), 1)
                self.assertIs(typed[0].status, K)
                self.assertIs(typed[0].evidence.derivation_rule, DerivationRule.SLOT_REFERENCE)
                self.assertEqual(typed[0].attributes["argument"], argument)

    def test_s2_an_unknown_value_is_an_uncertain_edge_to_the_unresolved_node(self) -> None:
        for source, argument, _target, relationship in SECTION_16:
            with self.subTest(source=source, argument=argument):
                found = self.only(self.run_case(source, argument, "var.unset"), relationship)
                node = f"SEMANTIC:UNRESOLVED:{source}.x#{argument}"
                edges = [e for e in found if e.target_node_id == node]
                self.assertEqual(len(edges), 1)
                self.assertIs(edges[0].status, UC)
                self.assertIs(edges[0].evidence.derivation_rule, DerivationRule.SLOT_UNKNOWN_VALUE)
                self.assertEqual(edges[0].attributes["reason"], "variable.no_value")

    def test_s2_an_unsupported_value_is_an_unsupported_edge_to_the_unresolved_node(self) -> None:
        for source, argument, _target, relationship in SECTION_16:
            with self.subTest(source=source, argument=argument):
                found = self.only(self.run_case(source, argument, "timestamp()"), relationship)
                node = f"SEMANTIC:UNRESOLVED:{source}.x#{argument}"
                edges = [e for e in found if e.target_node_id == node]
                self.assertEqual(len(edges), 1)
                self.assertIs(edges[0].status, UN)
                self.assertIs(
                    edges[0].evidence.derivation_rule, DerivationRule.SLOT_UNSUPPORTED_VALUE
                )

    def test_s3_a_literal_id_is_an_unsupported_edge_to_the_external_node(self) -> None:
        for source, argument, _target, relationship in SECTION_16:
            with self.subTest(source=source, argument=argument):
                found = self.only(self.run_case(source, argument, '"x-123"'), relationship)
                node = f"SEMANTIC:EXTERNAL:{source}.x#{argument}"
                edges = [e for e in found if e.target_node_id == node]
                self.assertEqual(len(edges), 1)
                self.assertIs(edges[0].status, UN)
                self.assertIs(edges[0].evidence.derivation_rule, DerivationRule.EXTERNAL_OBJECT)

    def test_s4_an_absent_argument_is_an_uncertain_edge(self) -> None:
        for source, argument, _target, relationship in SECTION_16:
            with self.subTest(source=source, argument=argument):
                found = self.only(self.run_case(source, argument, None), relationship)
                self.assertGreaterEqual(len(found), 1)
                for edge in found:
                    self.assertIs(edge.status, UC)
                    self.assertIs(edge.evidence.derivation_rule, DerivationRule.UNSET)
                    self.assertTrue(edge.target_node_id.startswith("SEMANTIC:UNRESOLVED:"))

    def test_s4_a_null_argument_is_an_uncertain_edge(self) -> None:
        for source, argument, _target, relationship in SECTION_16:
            with self.subTest(source=source, argument=argument):
                found = self.only(self.run_case(source, argument, "null"), relationship)
                self.assertGreaterEqual(len(found), 1)
                self.assertTrue(all(e.status is UC for e in found))
                # the instance's two-argument slot reports what each argument was: "null+unset"
                for edge in found:
                    reasons = set(str(edge.attributes["reason"]).split("+"))
                    self.assertTrue(reasons <= {"null", "unset"} and "null" in reasons, reasons)

    def test_a_reference_to_the_wrong_type_is_no_typed_edge_but_an_uncertain_one(self) -> None:
        for source, argument, target, relationship in SECTION_16:
            with self.subTest(source=source, argument=argument):
                wrong = OTHER_TARGET[target]
                found = self.only(self.run_case(source, argument, f"{wrong}.t.id"), relationship)
                self.assertFalse(any(e.target_node_id == f"RESOURCE:{wrong}.t" for e in found))
                mismatch = [
                    e for e in found if e.evidence.derivation_rule is DerivationRule.TYPE_MISMATCH
                ]
                self.assertEqual(len(mismatch), 1)
                self.assertIs(mismatch[0].status, UC)
                self.assertEqual(mismatch[0].attributes["reason"], f"type_mismatch:{wrong}")

    def test_the_wrong_type_reference_keeps_its_reference_edge(self) -> None:
        text = scenario("aws_instance", "subnet_id", "aws_vpc.t.id")
        _, edges = edges_of(resources_of(text))
        self.assertTrue(
            any(
                e.edge_type is EdgeType.TERRAFORM_REFERENCE
                and e.source_node_id == "RESOURCE:aws_instance.x"
                and e.target_node_id == "RESOURCE:aws_vpc.t"
                for e in edges
            )
        )


class TestSlotDetails(unittest.TestCase):
    def test_an_empty_security_group_list_is_unset_not_silence(self) -> None:
        text = scenario("aws_db_instance", "vpc_security_group_ids", "[]")
        _, edges = edges_of(resources_of(text))
        found = infrastructure(edges, "aws_db_instance.x")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].attributes["reason"], "empty")
        self.assertIs(found[0].status, UC)

    def test_a_list_with_a_reference_a_literal_and_an_unknown_gives_three_edges(self) -> None:
        text = """
variable "sg" {}
resource "aws_security_group" "app" { name = "app" }
resource "aws_instance" "x" {
  ami = "a"
  vpc_security_group_ids = [aws_security_group.app.id, "sg-123", var.sg]
}
"""
        _, edges = edges_of(resources_of(text))
        found = {
            e.target_node_id: e
            for e in infrastructure(edges, "aws_instance.x")
            if e.relationship is R.INSTANCE_USES_SECURITY_GROUP
        }
        self.assertEqual(
            set(found),
            {
                "RESOURCE:aws_security_group.app",
                "SEMANTIC:EXTERNAL:aws_instance.x#vpc_security_group_ids",
                "SEMANTIC:UNRESOLVED:aws_instance.x#vpc_security_group_ids",
            },
        )
        self.assertIs(found["RESOURCE:aws_security_group.app"].status, K)
        self.assertIs(found["SEMANTIC:EXTERNAL:aws_instance.x#vpc_security_group_ids"].status, UN)
        self.assertIs(found["SEMANTIC:UNRESOLVED:aws_instance.x#vpc_security_group_ids"].status, UC)

    def test_both_instance_security_group_arguments_can_contribute(self) -> None:
        text = """
resource "aws_security_group" "a" { name = "a" }
resource "aws_security_group" "b" { name = "b" }
resource "aws_instance" "x" {
  ami = "a"
  vpc_security_group_ids = [aws_security_group.a.id]
  security_groups = [aws_security_group.b.id]
}
"""
        _, edges = edges_of(resources_of(text))
        targets = {
            e.target_node_id
            for e in infrastructure(edges, "aws_instance.x")
            if e.relationship is R.INSTANCE_USES_SECURITY_GROUP
        }
        self.assertEqual(
            targets, {"RESOURCE:aws_security_group.a", "RESOURCE:aws_security_group.b"}
        )

    def test_an_absent_second_argument_does_not_add_noise_when_the_first_is_set(self) -> None:
        text = """
resource "aws_security_group" "a" { name = "a" }
resource "aws_instance" "x" {
  ami = "a"
  subnet_id = "subnet-1"
  vpc_security_group_ids = [aws_security_group.a.id]
}
"""
        _, edges = edges_of(resources_of(text))
        unset = [
            e
            for e in infrastructure(edges, "aws_instance.x")
            if e.evidence.derivation_rule is DerivationRule.UNSET
        ]
        self.assertEqual(unset, [])

    def test_a_slot_with_neither_argument_names_both_in_one_unresolved_node(self) -> None:
        text = 'resource "aws_instance" "x" {\n  ami = "a"\n}\n'
        _, edges = edges_of(resources_of(text))
        nodes = {
            e.target_node_id
            for e in infrastructure(edges, "aws_instance.x")
            if e.relationship is R.INSTANCE_USES_SECURITY_GROUP
        }
        self.assertEqual(
            nodes, {"SEMANTIC:UNRESOLVED:aws_instance.x#vpc_security_group_ids+security_groups"}
        )

    def test_a_set_valued_argument_is_read_element_by_element(self) -> None:
        text = """
resource "aws_security_group" "a" { name = "a" }
resource "aws_security_group" "b" { name = "b" }
resource "aws_db_instance" "x" {
  identifier = "d"
  vpc_security_group_ids = toset([aws_security_group.a.id, aws_security_group.b.id])
}
"""
        _, edges = edges_of(resources_of(text))
        targets = {e.target_node_id for e in infrastructure(edges, "aws_db_instance.x")}
        self.assertEqual(
            targets, {"RESOURCE:aws_security_group.a", "RESOURCE:aws_security_group.b"}
        )

    def test_the_typed_edge_to_an_unsupported_target_of_the_right_type_is_unsupported(self) -> None:
        resources = [
            hand_resource("aws_vpc.main", support=ResourceSupport.UNSUPPORTED),
            hand_resource(
                "aws_subnet.s",
                attributes={
                    "vpc_id": {
                        "form": "ATTRIBUTE",
                        "value": {"$dail": "ref", "address": "aws_vpc.main", "attribute": "id"},
                    }
                },
                references=[hand_ref("aws_subnet.s", "aws_vpc.main", "vpc_id")],
            ),
        ]
        _, edges = edges_of(resources)
        typed = [
            e
            for e in infrastructure(edges, "aws_subnet.s")
            if e.relationship is R.SUBNET_BELONGS_TO_VPC
        ]
        self.assertEqual(len(typed), 1)
        self.assertIs(typed[0].status, UN)

    def test_a_ref_without_a_matching_reference_is_uncertain(self) -> None:
        # the Resource says Ref(...) but lists no Reference for it: DAIL cannot confirm the edge
        resources = [
            hand_resource("aws_vpc.main"),
            hand_resource(
                "aws_subnet.s",
                attributes={
                    "vpc_id": {
                        "form": "ATTRIBUTE",
                        "value": {"$dail": "ref", "address": "aws_vpc.main", "attribute": "id"},
                    }
                },
            ),
        ]
        _, edges = edges_of(resources)
        typed = [
            e
            for e in infrastructure(edges, "aws_subnet.s")
            if e.relationship is R.SUBNET_BELONGS_TO_VPC
        ]
        self.assertIs(typed[0].status, UC)

    def test_a_ref_to_an_address_outside_the_state_is_uncertain_and_kept(self) -> None:
        resources = [
            hand_resource(
                "aws_subnet.s",
                attributes={
                    "vpc_id": {
                        "form": "ATTRIBUTE",
                        "value": {"$dail": "ref", "address": "aws_vpc.gone", "attribute": "id"},
                    }
                },
                references=[hand_ref("aws_subnet.s", "aws_vpc.gone", "vpc_id")],
            )
        ]
        parts, edges = edges_of(resources)
        typed = [
            e
            for e in infrastructure(edges, "aws_subnet.s")
            if e.relationship is R.SUBNET_BELONGS_TO_VPC
        ]
        self.assertEqual(typed[0].target_node_id, "RESOURCE:aws_vpc.gone")
        self.assertIs(typed[0].status, UC)
        self.assertTrue(parts.has_node("RESOURCE:aws_vpc.gone"))

    def test_an_argument_in_block_form_is_unsupported(self) -> None:
        resources = [
            hand_resource(
                "aws_subnet.s",
                attributes={"vpc_id": {"form": "BLOCKS", "blocks": [], "indeterminate": []}},
            )
        ]
        _, edges = edges_of(resources)
        typed = infrastructure(edges, "aws_subnet.s")
        self.assertEqual(len(typed), 1)
        self.assertIs(typed[0].status, UN)
        self.assertEqual(typed[0].attributes["reason"], "form:BLOCKS")

    def test_a_nested_list_element_is_an_external_object_with_its_shape(self) -> None:
        resources = [
            hand_resource(
                "aws_subnet.s",
                attributes={"vpc_id": {"form": "ATTRIBUTE", "value": [["x"]]}},
            )
        ]
        _, edges = edges_of(resources)
        typed = infrastructure(edges, "aws_subnet.s")
        self.assertEqual(typed[0].attributes["reason"], "collection")
        self.assertIs(typed[0].evidence.derivation_rule, DerivationRule.EXTERNAL_OBJECT)

    def test_a_placeholder_source_gets_an_uncertain_edge_for_every_slot_of_its_type(self) -> None:
        text = """
variable "n" {}
resource "aws_instance" "x" {
  count = var.n
  ami = "a"
}
"""
        _, edges = edges_of(resources_of(text))
        found = infrastructure(edges, "aws_instance.x")
        self.assertEqual(
            sorted(e.relationship.value for e in found),
            ["INSTANCE_IN_SUBNET", "INSTANCE_USES_SECURITY_GROUP"],
        )
        for edge in found:
            self.assertIs(edge.status, UC)
            self.assertEqual(edge.attributes["reason"], "placeholder")

    def test_an_unsupported_source_has_no_typed_edges_but_keeps_its_reference_edges(self) -> None:
        text = """
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_network_acl" "extra" { vpc_id = aws_vpc.main.id }
"""
        _, edges = edges_of(resources_of(text))
        self.assertEqual(infrastructure(edges, "aws_network_acl.extra"), [])
        refs = [e for e in edges if e.source_node_id == "RESOURCE:aws_network_acl.extra"]
        self.assertEqual(len(refs), 1)
        self.assertIs(refs[0].edge_type, EdgeType.TERRAFORM_REFERENCE)

    def test_a_typed_edge_and_its_reference_edge_are_different_classes(self) -> None:
        text = """
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_subnet" "s" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
"""
        _, edges = edges_of(resources_of(text))
        between = [
            e
            for e in edges
            if e.source_node_id == "RESOURCE:aws_subnet.s"
            and e.target_node_id == "RESOURCE:aws_vpc.main"
        ]
        self.assertEqual(
            sorted(e.edge_type.value for e in between), ["INFRASTRUCTURE", "TERRAFORM_REFERENCE"]
        )


class TestRuleSourceGroup(unittest.TestCase):
    BASE = """
variable "app_sg_id" {}
resource "aws_security_group" "app" { name = "app" }
resource "aws_security_group" "db" { name = "db" }
"""

    def rule(self, source: str | None) -> list[GraphEdge]:
        line = "" if source is None else f"source_security_group_id = {source}"
        text = f"""{self.BASE}
resource "aws_security_group_rule" "r" {{
  type = "ingress"
  protocol = "tcp"
  from_port = 5432
  to_port = 5432
  security_group_id = aws_security_group.db.id
  {line}
}}
"""
        _, edges = edges_of(resources_of(text))
        return [
            e
            for e in edges
            if e.source_node_id == "RESOURCE:aws_security_group_rule.r"
            and e.relationship is not R.RULE_BELONGS_TO_SECURITY_GROUP
            and e.attributes.get("source_attribute", e.attributes.get("argument"))
            == "source_security_group_id"
        ]

    def test_a_reference_is_only_the_reference_edge(self) -> None:
        found = self.rule("aws_security_group.app.id")
        self.assertEqual(len(found), 1)
        self.assertIs(found[0].edge_type, EdgeType.TERRAFORM_REFERENCE)
        self.assertEqual(found[0].target_node_id, "RESOURCE:aws_security_group.app")

    def test_an_unknown_source_group_is_an_uncertain_edge_to_the_unresolved_node(self) -> None:
        found = self.rule("var.app_sg_id")
        self.assertEqual(len(found), 1)
        edge = found[0]
        self.assertEqual(
            edge.target_node_id,
            "SEMANTIC:UNRESOLVED:aws_security_group_rule.r#source_security_group_id",
        )
        self.assertIs(edge.status, UC)
        self.assertIs(edge.edge_type, EdgeType.TERRAFORM_REFERENCE)
        self.assertIs(edge.relationship, R.REFERENCE)
        self.assertEqual(edge.attributes["source_attribute"], "source_security_group_id")

    def test_an_unsupported_source_group_is_unsupported(self) -> None:
        found = self.rule("timestamp()")
        self.assertEqual(len(found), 1)
        self.assertIs(found[0].status, UN)

    def test_a_literal_source_group_is_an_external_object(self) -> None:
        found = self.rule('"sg-0123"')
        self.assertEqual(len(found), 1)
        self.assertEqual(
            found[0].target_node_id,
            "SEMANTIC:EXTERNAL:aws_security_group_rule.r#source_security_group_id",
        )
        self.assertIs(found[0].status, UN)

    def test_an_absent_source_group_is_no_edge(self) -> None:
        # a rule may use cidr_blocks instead; the rule node's determinate flag carries the rest
        self.assertEqual(self.rule(None), [])

    def test_null_is_no_edge(self) -> None:
        self.assertEqual(self.rule("null"), [])


class TestCanonicalBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self.parts, self.edges = edges_of(fixture_resources(BASELINE))
        self.infra = [e for e in self.edges if e.edge_type is EdgeType.INFRASTRUCTURE]

    def test_there_are_thirteen_typed_edges_all_known(self) -> None:
        self.assertEqual(len(self.infra), 13)
        self.assertTrue(all(e.status is K for e in self.infra))

    def test_they_are_the_hand_derived_ones(self) -> None:
        got = {
            (
                e.source_node_id.removeprefix("RESOURCE:"),
                e.target_node_id.removeprefix("RESOURCE:"),
                e.relationship,
            )
            for e in self.infra
        }
        self.assertEqual(got, set(BASELINE_INFRASTRUCTURE_EDGES))

    def test_the_baseline_has_no_unresolved_or_external_edge(self) -> None:
        self.assertEqual(
            [n.node_id for n in self.parts.nodes if n.node_id.startswith("SEMANTIC:")], []
        )

    def test_rds_subnet_placement_is_not_an_invented_typed_edge(self) -> None:
        # no section 16 row covers db_subnet_group_name; only the UNSUPPORTED reference edge exists
        database = [
            e for e in self.edges if e.source_node_id == "RESOURCE:aws_db_instance.database"
        ]
        typed = [e for e in database if e.edge_type is EdgeType.INFRASTRUCTURE]
        self.assertEqual([e.target_node_id for e in typed], ["RESOURCE:aws_security_group.db"])


class TestOrderIndependence(unittest.TestCase):
    def test_resource_order_does_not_change_the_edges(self) -> None:
        resources = list(fixture_resources(BASELINE))
        _, forward = edges_of(resources)
        _, backward = edges_of(reversed(resources))
        self.assertEqual(forward, backward)


if __name__ == "__main__":
    unittest.main()
