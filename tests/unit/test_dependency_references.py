"""Reference edges (P3c step 3; Doc 07 §15, §23-§24; C-133 items 1, 2, 3, 6).

"References are not silently discarded." Expected edge sets for the canonical baseline are the
literals in ``tests.graph_builders`` (derived by hand from the ``.tf`` text), never read back from
the engine.
"""

from __future__ import annotations

import unittest

from core.dependency.edges import EdgeDraft, finalize, status_of_resolution, worst
from core.domain.enums import DependencyStatus, ReferenceResolution, ResourceSupport
from core.domain.graph import DerivationRule, EdgeType, GraphEdge, Relationship
from tests.graph_builders import (
    BASELINE,
    BASELINE_REFERENCE_EDGES,
    fixture_resources,
    hand_provenance,
    hand_ref,
    hand_resource,
    reference_edges_of,
    resources_of,
)

K, UC, UN = (
    DependencyStatus.KNOWN,
    DependencyStatus.UNCERTAIN,
    DependencyStatus.UNSUPPORTED,
)


def triples(edges: tuple[GraphEdge, ...]) -> set[tuple[str, str, DependencyStatus]]:
    return {
        (
            e.source_node_id.removeprefix("RESOURCE:"),
            e.target_node_id.removeprefix("RESOURCE:"),
            e.status,
        )
        for e in edges
    }


def one(edges: tuple[GraphEdge, ...], source: str, target: str) -> GraphEdge:
    found = [
        e
        for e in edges
        if e.source_node_id == f"RESOURCE:{source}" and e.target_node_id == f"RESOURCE:{target}"
    ]
    assert len(found) == 1, (source, target, found)
    return found[0]


class TestCanonicalBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self.parts, self.edges = reference_edges_of(fixture_resources(BASELINE))

    def test_there_are_twenty_reference_edges(self) -> None:
        self.assertEqual(len(self.edges), 20)

    def test_the_edge_set_and_statuses_are_the_hand_derived_ones(self) -> None:
        self.assertEqual(triples(self.edges), set(BASELINE_REFERENCE_EDGES))

    def test_every_edge_is_a_reference_edge_with_evidence_and_provenance(self) -> None:
        for edge in self.edges:
            with self.subTest(edge=edge.edge_key[:8]):
                self.assertIs(edge.edge_type, EdgeType.TERRAFORM_REFERENCE)
                self.assertIs(edge.relationship, Relationship.REFERENCE)
                self.assertIs(edge.evidence.derivation_rule, DerivationRule.REFERENCE)
                self.assertTrue(edge.provenance)
                self.assertTrue(edge.evidence.source_fact)
                self.assertTrue(edge.evidence.target_fact)

    def test_every_reference_of_every_resource_has_an_edge(self) -> None:
        expected = {
            (r.address, ref.source_attribute, ref.target_address)
            for r in fixture_resources(BASELINE)
            for ref in r.references
        }
        got = {
            (
                e.source_node_id.removeprefix("RESOURCE:"),
                e.attributes["source_attribute"],
                e.target_node_id.removeprefix("RESOURCE:"),
            )
            for e in self.edges
        }
        self.assertEqual(got, expected)

    def test_the_route_to_the_internet_gateway_is_a_reference_edge(self) -> None:
        # Doc 07 §17: IGW routes arrive as TERRAFORM_REFERENCE edges (the plan's reading)
        edge = one(self.edges, "aws_route_table.public", "aws_internet_gateway.igw")
        self.assertEqual(edge.attributes["source_attribute"], "route[0].gateway_id")

    def test_the_rule_to_its_source_group_is_a_reference_edge(self) -> None:
        edge = one(self.edges, "aws_security_group_rule.app_to_db_5432", "aws_security_group.app")
        self.assertEqual(edge.attributes["source_attribute"], "source_security_group_id")
        self.assertIs(edge.status, K)

    def test_the_rds_subnet_placement_is_unsupported(self) -> None:
        # the known gap: aws_db_subnet_group is not a supported type (Doc 07 §23)
        edge = one(self.edges, "aws_db_instance.database", "aws_db_subnet_group.db")
        self.assertIs(edge.status, UN)
        self.assertEqual(edge.attributes["source_attribute"], "db_subnet_group_name")

    def test_the_subnet_group_node_is_present_and_unsupported(self) -> None:
        node = self.parts.nodes
        group = next(n for n in node if n.node_id == "RESOURCE:aws_db_subnet_group.db")
        self.assertEqual(group.attributes["support_status"], "UNSUPPORTED")


class TestEdgeStatus(unittest.TestCase):
    def test_an_unsupported_source_makes_its_edges_unsupported_although_they_resolved(self) -> None:
        resources = resources_of("""
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_network_acl" "extra" { vpc_id = aws_vpc.main.id }
""")
        _, edges = reference_edges_of(resources)
        edge = one(edges, "aws_network_acl.extra", "aws_vpc.main")
        self.assertIs(edge.status, UN)

    def test_an_unsupported_target_makes_the_edge_unsupported(self) -> None:
        resources = resources_of("""
resource "aws_db_subnet_group" "db" { name = "db" }
resource "aws_db_instance" "d" {
  identifier = "d"
  db_subnet_group_name = aws_db_subnet_group.db.name
}
""")
        _, edges = reference_edges_of(resources)
        self.assertIs(one(edges, "aws_db_instance.d", "aws_db_subnet_group.db").status, UN)

    def test_the_target_status_counts_even_when_the_reference_says_supported(self) -> None:
        # C-133 item 2 takes the worst of the reference, the source and the target in the state
        resources = [
            hand_resource("aws_db_subnet_group.db", support=ResourceSupport.UNSUPPORTED),
            hand_resource(
                "aws_db_instance.d",
                references=[hand_ref("aws_db_instance.d", "aws_db_subnet_group.db", "x")],
            ),
        ]
        _, edges = reference_edges_of(resources)
        self.assertIs(one(edges, "aws_db_instance.d", "aws_db_subnet_group.db").status, UN)

    def test_a_placeholder_target_status_counts_even_when_the_reference_says_supported(
        self,
    ) -> None:
        resources = [
            hand_resource("aws_vpc.main", support=ResourceSupport.UNKNOWN),
            hand_resource(
                "aws_subnet.s", references=[hand_ref("aws_subnet.s", "aws_vpc.main", "vpc_id")]
            ),
        ]
        _, edges = reference_edges_of(resources)
        self.assertIs(one(edges, "aws_subnet.s", "aws_vpc.main").status, UC)

    def test_a_supported_edge_between_supported_resources_is_known(self) -> None:
        resources = resources_of("""
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_subnet" "s" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
""")
        _, edges = reference_edges_of(resources)
        self.assertIs(one(edges, "aws_subnet.s", "aws_vpc.main").status, K)

    def test_an_unknown_reference_gives_an_uncertain_edge(self) -> None:
        resources = resources_of("""
data "aws_ami" "x" { most_recent = true }
resource "aws_instance" "a" { ami = data.aws_ami.x.id }
""")
        parts, edges = reference_edges_of(resources)
        edge = one(edges, "aws_instance.a", "data.aws_ami.x")
        self.assertIs(edge.status, UC)
        node = next(n for n in parts.nodes if n.node_id == "RESOURCE:data.aws_ami.x")
        self.assertEqual(node.attributes["kind"], "data")

    def test_a_placeholder_source_gives_uncertain_edges(self) -> None:
        resources = resources_of("""
variable "n" {}
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_subnet" "ph" {
  count = var.n
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
""")
        _, edges = reference_edges_of(resources)
        self.assertIs(one(edges, "aws_subnet.ph", "aws_vpc.main").status, UC)

    def test_a_placeholder_target_gives_an_uncertain_edge_to_the_placeholder(self) -> None:
        resources = resources_of("""
variable "n" {}
resource "aws_subnet" "ph" {
  count = var.n
  cidr_block = "10.0.1.0/24"
}
resource "aws_instance" "a" {
  ami = "x"
  subnet_id = aws_subnet.ph[0].id
}
""")
        parts, edges = reference_edges_of(resources)
        edge = one(edges, "aws_instance.a", "aws_subnet.ph")
        self.assertIs(edge.status, UC)
        self.assertIs(edge.evidence.derivation_rule, DerivationRule.REFERENCE)
        self.assertTrue(parts.has_node("RESOURCE:aws_subnet.ph"))

    def test_the_worst_of_the_three_wins(self) -> None:
        self.assertIs(worst(K, UC), UC)
        self.assertIs(worst(UC, UN), UN)
        self.assertIs(worst(UN, K, UC), UN)
        self.assertIs(worst(K), K)
        self.assertIs(worst(), K)

    def test_resolution_maps_to_the_edge_status(self) -> None:
        self.assertIs(status_of_resolution(ReferenceResolution.SUPPORTED), K)
        self.assertIs(status_of_resolution(ReferenceResolution.UNKNOWN), UC)
        self.assertIs(status_of_resolution(ReferenceResolution.UNSUPPORTED), UN)

    def test_depends_on_is_a_reference_edge_too(self) -> None:
        resources = resources_of("""
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_instance" "a" {
  ami = "x"
  depends_on = [aws_vpc.main]
}
""")
        _, edges = reference_edges_of(resources)
        edge = one(edges, "aws_instance.a", "aws_vpc.main")
        self.assertEqual(edge.attributes["reference_type"], "DEPENDS_ON")
        self.assertEqual(edge.attributes["source_attribute"], "depends_on")


class TestBlockFanOut(unittest.TestCase):
    TEXT = """
variable "i" {}
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_subnet" "s" {
  count = 2
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
resource "aws_instance" "unknown_index" {
  ami = "x"
  subnet_id = aws_subnet.s[var.i].id
}
resource "aws_instance" "no_index" {
  ami = "x"
  subnet_id = aws_subnet.s.id
}
resource "aws_instance" "fixed" {
  ami = "x"
  subnet_id = aws_subnet.s[0].id
}
"""

    def setUp(self) -> None:
        self.parts, self.edges = reference_edges_of(resources_of(self.TEXT))

    def test_an_unknown_index_gives_one_edge_per_instance(self) -> None:
        for name in ("unknown_index", "no_index"):
            with self.subTest(source=name):
                source = f"aws_instance.{name}"
                targets = sorted(
                    e.target_node_id for e in self.edges if e.source_node_id == f"RESOURCE:{source}"
                )
                self.assertEqual(targets, ["RESOURCE:aws_subnet.s[0]", "RESOURCE:aws_subnet.s[1]"])

    def test_fan_out_edges_are_uncertain_with_the_fanout_rule_and_the_block(self) -> None:
        for edge in self.edges:
            if edge.source_node_id == "RESOURCE:aws_instance.unknown_index":
                self.assertIs(edge.status, UC)
                self.assertIs(edge.evidence.derivation_rule, DerivationRule.BLOCK_FANOUT)
                self.assertEqual(edge.attributes["via_block"], "aws_subnet.s")

    def test_no_edge_ends_at_the_dangling_block_address(self) -> None:
        self.assertFalse(any(e.target_node_id == "RESOURCE:aws_subnet.s" for e in self.edges))
        self.assertFalse(self.parts.has_node("RESOURCE:aws_subnet.s"))

    def test_a_fixed_index_is_an_ordinary_known_edge(self) -> None:
        edge = one(self.edges, "aws_instance.fixed", "aws_subnet.s[0]")
        self.assertIs(edge.status, K)
        self.assertIs(edge.evidence.derivation_rule, DerivationRule.REFERENCE)
        self.assertNotIn("via_block", edge.attributes)

    def test_fan_out_takes_the_worst_status_of_each_instance(self) -> None:
        resources = [
            hand_resource("aws_subnet.s[0]"),
            hand_resource("aws_subnet.s[1]", support=ResourceSupport.UNSUPPORTED),
            hand_resource(
                "aws_instance.a",
                references=[
                    hand_ref(
                        "aws_instance.a", "aws_subnet.s", "subnet_id", ReferenceResolution.UNKNOWN
                    )
                ],
            ),
        ]
        _, edges = reference_edges_of(resources)
        self.assertIs(one(edges, "aws_instance.a", "aws_subnet.s[0]").status, UC)
        self.assertIs(one(edges, "aws_instance.a", "aws_subnet.s[1]").status, UN)

    def test_a_for_each_block_fans_out_over_its_keys(self) -> None:
        text = """
resource "aws_subnet" "s" {
  for_each = toset(["a", "b"])
  cidr_block = "10.0.1.0/24"
}
resource "aws_instance" "x" {
  ami = "x"
  subnet_id = aws_subnet.s.id
}
"""
        _, edges = reference_edges_of(resources_of(text))
        got = sorted(
            e.target_node_id for e in edges if e.source_node_id == "RESOURCE:aws_instance.x"
        )
        self.assertEqual(got, ['RESOURCE:aws_subnet.s["a"]', 'RESOURCE:aws_subnet.s["b"]'])


class TestTargetsOutsideTheState(unittest.TestCase):
    def test_an_absent_address_gets_an_absent_node_and_an_uncertain_edge(self) -> None:
        resources = [
            hand_resource(
                "aws_instance.a",
                references=[hand_ref("aws_instance.a", "aws_subnet.gone", "subnet_id")],
            )
        ]
        parts, edges = reference_edges_of(resources)
        edge = one(edges, "aws_instance.a", "aws_subnet.gone")
        self.assertIs(edge.status, UC)
        node = next(n for n in parts.nodes if n.node_id == "RESOURCE:aws_subnet.gone")
        self.assertEqual(node.attributes["kind"], "absent")
        self.assertEqual(node.attributes["resource_type"], "aws_subnet")

    def test_a_module_object_gets_a_module_node_and_an_unsupported_edge(self) -> None:
        resources = [
            hand_resource(
                "aws_instance.a",
                references=[
                    hand_ref(
                        "aws_instance.a",
                        "module.net.aws_subnet.s",
                        "subnet_id",
                        ReferenceResolution.UNSUPPORTED,
                    )
                ],
            )
        ]
        parts, edges = reference_edges_of(resources)
        self.assertIs(one(edges, "aws_instance.a", "module.net.aws_subnet.s").status, UN)
        node = next(n for n in parts.nodes if n.node_id == "RESOURCE:module.net.aws_subnet.s")
        self.assertEqual(node.attributes["kind"], "module")

    def test_an_indexed_address_outside_the_state_is_absent_not_fanned_out(self) -> None:
        resources = [
            hand_resource("aws_subnet.s[0]"),
            hand_resource(
                "aws_instance.a",
                references=[hand_ref("aws_instance.a", "aws_subnet.s[7]", "subnet_id")],
            ),
        ]
        parts, edges = reference_edges_of(resources)
        edge = one(edges, "aws_instance.a", "aws_subnet.s[7]")
        self.assertIs(edge.status, UC)
        self.assertEqual(
            next(n for n in parts.nodes if n.ref_id == "aws_subnet.s[7]").attributes["kind"],
            "absent",
        )


class TestCollapse(unittest.TestCase):
    def _draft(self, status: DependencyStatus, rule: DerivationRule, fact: str) -> EdgeDraft:
        return EdgeDraft(
            source_node_id="RESOURCE:a.x",
            target_node_id="RESOURCE:a.y",
            edge_type=EdgeType.TERRAFORM_REFERENCE,
            relationship=Relationship.REFERENCE,
            status=status,
            attributes={"source_attribute": "p"},
            rule=rule,
            source_fact=fact,
            target_fact="t",
            provenance=(hand_provenance(),),
        )

    def test_identical_edges_collapse_to_one_with_the_worst_status(self) -> None:
        edges = finalize(
            [
                self._draft(K, DerivationRule.REFERENCE, "b"),
                self._draft(UC, DerivationRule.REFERENCE, "a"),
            ]
        )
        self.assertEqual(len(edges), 1)
        self.assertIs(edges[0].status, UC)
        self.assertIs(edges[0].evidence.status, UC)

    def test_the_evidence_of_the_first_in_order_is_kept(self) -> None:
        edges = finalize(
            [
                self._draft(K, DerivationRule.REFERENCE, "zz"),
                self._draft(K, DerivationRule.REFERENCE, "aa"),
            ]
        )
        self.assertEqual(edges[0].evidence.source_fact, "aa")
        edges = finalize(
            [
                self._draft(K, DerivationRule.REFERENCE, "aa"),
                self._draft(K, DerivationRule.BLOCK_FANOUT, "aa"),
            ]
        )
        self.assertIs(edges[0].evidence.derivation_rule, DerivationRule.BLOCK_FANOUT)

    def test_collapse_does_not_depend_on_draft_order(self) -> None:
        drafts = [
            self._draft(K, DerivationRule.REFERENCE, "b"),
            self._draft(UN, DerivationRule.BLOCK_FANOUT, "a"),
            self._draft(UC, DerivationRule.REFERENCE, "c"),
        ]
        self.assertEqual(finalize(drafts), finalize(reversed(drafts)))

    def test_edges_with_different_attributes_are_not_merged(self) -> None:
        resources = [
            hand_resource("aws_vpc.main"),
            hand_resource(
                "aws_subnet.s",
                references=[
                    hand_ref("aws_subnet.s", "aws_vpc.main", "vpc_id"),
                    hand_ref("aws_subnet.s", "aws_vpc.main", "tags"),
                    hand_ref(
                        "aws_subnet.s", "aws_vpc.main", "depends_on", reference_type="DEPENDS_ON"
                    ),
                ],
            ),
        ]
        _, edges = reference_edges_of(resources)
        self.assertEqual(len(edges), 3)

    def test_the_same_triple_with_two_statuses_collapses_to_the_worst(self) -> None:
        resources = [
            hand_resource("aws_vpc.main"),
            hand_resource(
                "aws_subnet.s",
                references=[
                    hand_ref("aws_subnet.s", "aws_vpc.main", "vpc_id"),
                    hand_ref("aws_subnet.s", "aws_vpc.main", "vpc_id", ReferenceResolution.UNKNOWN),
                ],
            ),
        ]
        _, edges = reference_edges_of(resources)
        self.assertEqual(len(edges), 1)
        self.assertIs(edges[0].status, UC)


class TestOrderIndependence(unittest.TestCase):
    def test_resource_order_does_not_change_the_edges(self) -> None:
        resources = list(fixture_resources(BASELINE))
        _, forward = reference_edges_of(resources)
        _, backward = reference_edges_of(reversed(resources))
        self.assertEqual(forward, backward)


if __name__ == "__main__":
    unittest.main()
