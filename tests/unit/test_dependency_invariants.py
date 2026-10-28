"""Invariant scope and semantic edges (P3c step 5; Doc 07 §19, §23, §37; C-134).

The invariant definitions are declared in ``tests.graph_builders`` from registry-v1.0 §2.7, §3.5,
§5.4 and §6.6; nothing in the code defines them yet (R4 of the P3c prompt).
"""

from __future__ import annotations

import unittest

from core.dependency.errors import DependencyInputError
from core.dependency.invariants import SemanticBinding, check_invariants
from core.domain.enums import DependencyStatus, ProvenanceSourceKind, ResourceSupport
from core.domain.graph import DerivationRule, EdgeType, GraphEdge, Relationship
from tests.graph_builders import (
    BASELINE,
    NORMALIZATION,
    fixture_resources,
    func_001,
    func_binding,
    hand_resource,
    invariant_edges_of,
    make_invariant,
    resources_of,
    sec_001,
    sec_002,
    sec_003,
)

K, UC, UN = (
    DependencyStatus.KNOWN,
    DependencyStatus.UNCERTAIN,
    DependencyStatus.UNSUPPORTED,
)
R = Relationship
BASE = fixture_resources(BASELINE)


def from_invariant(
    edges: tuple[GraphEdge, ...], invariant_id: str, version: int = 1
) -> list[GraphEdge]:
    return [e for e in edges if e.source_node_id == f"INVARIANT:{invariant_id}:{version}"]


def targets(edges: list[GraphEdge]) -> set[str]:
    return {e.target_node_id for e in edges}


class TestScopeByType(unittest.TestCase):
    def test_sec_001_is_connected_to_every_group_and_rule_of_the_baseline(self) -> None:
        _, edges = invariant_edges_of(BASE, [sec_001()])
        found = from_invariant(edges, "INV-SEC-001")
        self.assertEqual(
            targets(found),
            {
                "RESOURCE:aws_security_group.app",
                "RESOURCE:aws_security_group.db",
                "RESOURCE:aws_security_group_rule.app_ssh_public",
                "RESOURCE:aws_security_group_rule.app_egress_all",
                "RESOURCE:aws_security_group_rule.app_to_db_5432",
            },
        )
        for edge in found:
            self.assertIs(edge.edge_type, EdgeType.INVARIANT_SCOPE)
            self.assertIs(edge.relationship, R.SCOPE)
            self.assertIs(edge.status, K)
            self.assertIs(edge.evidence.derivation_rule, DerivationRule.SCOPE_TYPE)

    def test_sec_002_has_the_same_scope_as_sec_001(self) -> None:
        _, edges = invariant_edges_of(BASE, [sec_001(), sec_002()])
        self.assertEqual(
            targets(from_invariant(edges, "INV-SEC-001")),
            targets(from_invariant(edges, "INV-SEC-002")),
        )

    def test_sec_003_is_connected_to_the_database(self) -> None:
        _, edges = invariant_edges_of(BASE, [sec_003()])
        found = from_invariant(edges, "INV-SEC-003")
        self.assertEqual(targets(found), {"RESOURCE:aws_db_instance.database"})
        self.assertIs(found[0].status, K)

    def test_an_unsupported_resource_of_a_scoped_type_is_connected_and_unsupported(self) -> None:
        # registry §2.7: aws_default_security_group is relevant-unsupported for SEC-001
        text = """
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_default_security_group" "d" { vpc_id = aws_vpc.main.id }
"""
        _, edges = invariant_edges_of(resources_of(text), [sec_001()])
        found = from_invariant(edges, "INV-SEC-001")
        self.assertEqual(targets(found), {"RESOURCE:aws_default_security_group.d"})
        self.assertIs(found[0].status, UN)

    def test_a_placeholder_of_a_scoped_type_is_connected_and_uncertain(self) -> None:
        text = """
variable "n" {}
resource "aws_security_group" "p" {
  count = var.n
  name = "p"
}
"""
        _, edges = invariant_edges_of(resources_of(text), [sec_001()])
        found = from_invariant(edges, "INV-SEC-001")
        self.assertEqual(targets(found), {"RESOURCE:aws_security_group.p"})
        self.assertIs(found[0].status, UC)

    def test_a_scoped_type_with_no_resource_gives_no_edge_but_keeps_the_node(self) -> None:
        text = 'resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }'
        parts, edges = invariant_edges_of(resources_of(text), [sec_003()])
        self.assertEqual(from_invariant(edges, "INV-SEC-003"), [])
        self.assertTrue(parts.has_node("INVARIANT:INV-SEC-003:1"))

    def test_each_instance_of_a_scoped_type_is_connected(self) -> None:
        text = """
resource "aws_security_group" "g" {
  count = 2
  name = "g"
}
"""
        _, edges = invariant_edges_of(resources_of(text), [sec_001()])
        self.assertEqual(
            targets(from_invariant(edges, "INV-SEC-001")),
            {"RESOURCE:aws_security_group.g[0]", "RESOURCE:aws_security_group.g[1]"},
        )

    def test_the_invariant_node_has_category_and_name_only(self) -> None:
        parts, _ = invariant_edges_of(BASE, [sec_001()])
        node = next(n for n in parts.nodes if n.node_id == "INVARIANT:INV-SEC-001:1")
        self.assertEqual(
            dict(node.attributes), {"category": "SECURITY", "name": "INV-SEC-001 name"}
        )
        self.assertEqual(node.ref_id, "INV-SEC-001")


class TestFunctionalInvariant(unittest.TestCase):
    def setUp(self) -> None:
        self.parts, self.edges = invariant_edges_of(BASE, [func_001()], [func_binding()])
        self.found = from_invariant(self.edges, "INV-FUNC-001")

    def by(self, relationship: Relationship) -> list[GraphEdge]:
        return [e for e in self.found if e.relationship is relationship]

    def test_the_scope_names_the_two_endpoints(self) -> None:
        self.assertEqual(
            targets(self.by(R.SCOPE)),
            {"RESOURCE:aws_instance.app", "RESOURCE:aws_db_instance.database"},
        )
        for edge in self.by(R.SCOPE):
            self.assertIs(edge.evidence.derivation_rule, DerivationRule.SCOPE_RESOURCE)
            self.assertIs(edge.status, K)

    def test_source_destination_and_port_are_connected(self) -> None:
        self.assertEqual(targets(self.by(R.SOURCE)), {"RESOURCE:aws_instance.app"})
        self.assertEqual(targets(self.by(R.DESTINATION)), {"RESOURCE:aws_db_instance.database"})
        self.assertEqual(targets(self.by(R.PROTOCOL_PORT)), {"SEMANTIC:TCP/5432"})
        for relationship in (R.SOURCE, R.DESTINATION, R.PROTOCOL_PORT):
            edge = self.by(relationship)[0]
            self.assertIs(edge.edge_type, EdgeType.INVARIANT_SEMANTIC)
            self.assertIs(edge.status, K)
            self.assertIs(edge.evidence.derivation_rule, DerivationRule.SEMANTIC_BINDING)

    def test_the_port_node_is_a_semantic_node(self) -> None:
        node = next(n for n in self.parts.nodes if n.node_id == "SEMANTIC:TCP/5432")
        self.assertEqual(node.node_type.value, "SEMANTIC")
        self.assertEqual(dict(node.attributes), {"kind": "protocol_port"})

    def test_the_network_context_is_not_materialised_as_invariant_edges(self) -> None:
        # C-134: subnet, VPC, security groups and rules are reachable through the endpoints
        self.assertEqual(
            targets(self.found),
            {
                "RESOURCE:aws_instance.app",
                "RESOURCE:aws_db_instance.database",
                "SEMANTIC:TCP/5432",
            },
        )

    def test_no_edge_carries_an_impact_flag(self) -> None:
        for edge in self.edges:
            self.assertEqual(dict(edge.attributes), {})

    def test_a_deleted_endpoint_is_an_uncertain_edge_to_an_absent_node(self) -> None:
        without_db = [r for r in BASE if r.address != "aws_db_instance.database"]
        parts, edges = invariant_edges_of(without_db, [func_001()], [func_binding()])
        found = from_invariant(edges, "INV-FUNC-001")
        absent = [e for e in found if e.target_node_id == "RESOURCE:aws_db_instance.database"]
        self.assertEqual(sorted(e.relationship.value for e in absent), ["DESTINATION", "SCOPE"])
        for edge in absent:
            self.assertIs(edge.status, UC)
        node = next(n for n in parts.nodes if n.node_id == "RESOURCE:aws_db_instance.database")
        self.assertEqual(node.attributes["kind"], "absent")
        self.assertEqual(node.attributes["resource_type"], "aws_db_instance")

    def test_the_present_endpoint_stays_known_when_the_other_is_deleted(self) -> None:
        without_db = [r for r in BASE if r.address != "aws_db_instance.database"]
        _, edges = invariant_edges_of(without_db, [func_001()], [func_binding()])
        known = [
            e
            for e in from_invariant(edges, "INV-FUNC-001")
            if e.target_node_id == "RESOURCE:aws_instance.app"
        ]
        self.assertTrue(known and all(e.status is K for e in known))

    def test_an_unsupported_endpoint_is_unsupported(self) -> None:
        resources = [
            hand_resource("aws_instance.app"),
            hand_resource("aws_db_instance.database", support=ResourceSupport.UNSUPPORTED),
        ]
        _, edges = invariant_edges_of(resources, [func_001()], [func_binding()])
        statuses = {
            e.relationship.value: e.status
            for e in from_invariant(edges, "INV-FUNC-001")
            if e.target_node_id == "RESOURCE:aws_db_instance.database"
        }
        self.assertEqual(statuses, {"SCOPE": UN, "DESTINATION": UN})

    def test_a_placeholder_endpoint_is_uncertain(self) -> None:
        text = """
variable "n" {}
resource "aws_instance" "app" {
  ami = "a"
  subnet_id = "s"
}
resource "aws_db_instance" "database" {
  count = var.n
  identifier = "d"
}
"""
        _, edges = invariant_edges_of(resources_of(text), [func_001()], [func_binding()])
        db = [
            e
            for e in from_invariant(edges, "INV-FUNC-001")
            if e.target_node_id == "RESOURCE:aws_db_instance.database"
        ]
        self.assertEqual(len(db), 2)
        self.assertTrue(all(e.status is UC for e in db))

    def test_an_endpoint_that_is_a_block_with_instances_fans_out(self) -> None:
        text = """
resource "aws_instance" "app" {
  count = 2
  ami = "a"
}
resource "aws_db_instance" "database" { identifier = "d" }
"""
        _, edges = invariant_edges_of(resources_of(text), [func_001()], [func_binding()])
        found = from_invariant(edges, "INV-FUNC-001")
        instances = {e.target_node_id: e for e in found if "aws_instance" in e.target_node_id}
        self.assertEqual(
            set(instances), {"RESOURCE:aws_instance.app[0]", "RESOURCE:aws_instance.app[1]"}
        )
        self.assertFalse(any(e.target_node_id == "RESOURCE:aws_instance.app" for e in found))
        for edge in instances.values():
            self.assertIs(edge.status, UC)
            self.assertIs(edge.evidence.derivation_rule, DerivationRule.BLOCK_FANOUT)


class TestMissingBinding(unittest.TestCase):
    def test_a_functional_invariant_without_a_binding_gets_an_uncertain_edge(self) -> None:
        parts, edges = invariant_edges_of(BASE, [func_001()])
        found = [e for e in from_invariant(edges, "INV-FUNC-001") if e.relationship is R.BINDING]
        self.assertEqual(len(found), 1)
        edge = found[0]
        self.assertEqual(edge.target_node_id, "SEMANTIC:UNRESOLVED:INV-FUNC-001#binding")
        self.assertIs(edge.status, UC)
        self.assertIs(edge.edge_type, EdgeType.INVARIANT_SEMANTIC)
        self.assertIs(edge.evidence.derivation_rule, DerivationRule.BINDING_MISSING)
        self.assertTrue(parts.has_node("SEMANTIC:UNRESOLVED:INV-FUNC-001#binding"))

    def test_a_bound_functional_invariant_has_no_missing_binding_edge(self) -> None:
        _, edges = invariant_edges_of(BASE, [func_001()], [func_binding()])
        self.assertFalse(any(e.relationship is R.BINDING for e in edges))

    def test_a_security_invariant_needs_no_binding(self) -> None:
        _, edges = invariant_edges_of(BASE, [sec_001(), sec_003()])
        self.assertFalse(any(e.edge_type is EdgeType.INVARIANT_SEMANTIC for e in edges))


class TestInputs(unittest.TestCase):
    def test_a_binding_for_an_invariant_that_is_not_given_is_refused(self) -> None:
        with self.assertRaises(DependencyInputError):
            check_invariants([sec_001()], [func_binding()])

    def test_a_duplicate_invariant_id_and_version_is_refused(self) -> None:
        with self.assertRaises(DependencyInputError):
            check_invariants([sec_001(), sec_001()], [])

    def test_two_versions_of_one_invariant_are_two_nodes_and_both_get_the_binding(self) -> None:
        parts, edges = invariant_edges_of(BASE, [func_001(2), func_001(1)], [func_binding()])
        self.assertTrue(parts.has_node("INVARIANT:INV-FUNC-001:1"))
        self.assertTrue(parts.has_node("INVARIANT:INV-FUNC-001:2"))
        for version in (1, 2):
            found = from_invariant(edges, "INV-FUNC-001", version)
            self.assertIn("SEMANTIC:TCP/5432", targets(found))

    def test_only_invariant_objects_and_bindings_are_accepted(self) -> None:
        with self.assertRaises(DependencyInputError):
            check_invariants(["INV-SEC-001"], [])  # type: ignore[list-item]
        with self.assertRaises(DependencyInputError):
            check_invariants([sec_001()], ["x"])  # type: ignore[list-item]

    def test_binding_fields_are_validated(self) -> None:
        good = ("INV-FUNC-001", "a.s", "a.d", "TCP", 5432)
        SemanticBinding(*good)
        for index, bad in (
            (0, ""),
            (1, " a.s"),
            (2, ""),
            (3, "tcp"),
            (3, "T CP"),
            (3, ""),
            (4, -1),
            (4, 65536),
            (4, True),
            (4, "5432"),
        ):
            values = list(good)
            values[index] = bad
            with self.subTest(index=index, bad=bad), self.assertRaises(DependencyInputError):
                SemanticBinding(*values)  # type: ignore[arg-type]

    def test_the_inputs_may_come_in_any_order(self) -> None:
        one = invariant_edges_of(BASE, [func_001(), sec_001(), sec_003()], [func_binding()])[1]
        two = invariant_edges_of(
            reversed(BASE), [sec_003(), func_001(), sec_001()], [func_binding()]
        )[1]
        self.assertEqual(one, two)


class TestEvidenceAndProvenance(unittest.TestCase):
    def test_every_invariant_edge_has_derived_provenance_and_evidence(self) -> None:
        _, edges = invariant_edges_of(BASE, [func_001(), sec_001()], [func_binding()])
        self.assertTrue(edges)
        for edge in edges:
            with self.subTest(edge=edge.evidence.source_fact):
                self.assertEqual(len(edge.provenance), 1)
                self.assertIs(edge.provenance[0].source_kind, ProvenanceSourceKind.DERIVED)
                self.assertEqual(edge.provenance[0].algorithm_version, "dail-graph-1")
                self.assertTrue(edge.evidence.source_fact)
                self.assertTrue(edge.evidence.target_fact)

    def test_a_scope_address_that_is_also_scoped_by_type_keeps_the_explicit_rule(self) -> None:
        both = make_invariant(
            "INV-SEC-009",
            resources=("aws_security_group.app",),
            resource_types=("aws_security_group",),
        )
        _, edges = invariant_edges_of(BASE, [both])
        app = [e for e in edges if e.target_node_id == "RESOURCE:aws_security_group.app"]
        self.assertEqual(len(app), 1)
        self.assertIs(app[0].evidence.derivation_rule, DerivationRule.SCOPE_RESOURCE)

    def test_the_normalization_version_constant_matches_the_front_end(self) -> None:
        self.assertEqual(NORMALIZATION, "dail-tf-norm-1")


if __name__ == "__main__":
    unittest.main()
