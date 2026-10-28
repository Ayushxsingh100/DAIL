"""``build_graph`` end to end (P3c steps 6 and 7; Doc 07 §20, §31, §36.2-§36.3, §37; C-131, C-132).

Step 6 holds the input checks and the shape of a built graph; step 7 adds the fixtures.
"""

from __future__ import annotations

import unittest
from datetime import timedelta

from core.dependency.build import build_graph
from core.dependency.errors import DependencyInputError
from core.dependency.versions import GRAPH_ALGORITHM_VERSION
from core.domain.enums import DependencyStatus, InvariantCategory, ProvenanceSourceKind
from core.domain.errors import DomainValidationError
from core.domain.graph import (
    DependencyGraph,
    DerivationRule,
    EdgeType,
    GraphEdge,
    GraphNode,
    Relationship,
)
from tests import fixture_catalog as fc
from tests.domain_builders import at, uid
from tests.graph_builders import (
    BASELINE,
    BASELINE_INFRASTRUCTURE_EDGES,
    BASELINE_REFERENCE_EDGES,
    NORMALIZATION,
    NOW,
    STATE,
    fixture_resources,
    func_001,
    func_binding,
    hand_resource,
    make_invariant,
    sec_001,
    sec_002,
    sec_003,
)


def build(resources, invariants=(), bindings=(), **kwargs):  # type: ignore[no-untyped-def]
    return build_graph(resources, invariants, bindings, state_id=STATE, now=NOW, **kwargs)


class TestBuildInputs(unittest.TestCase):
    def test_the_algorithm_and_normalization_versions_are_recorded(self) -> None:
        built = build(fixture_resources(BASELINE))
        self.assertEqual(GRAPH_ALGORITHM_VERSION, "dail-graph-1")
        self.assertEqual(built.algorithm_version, "dail-graph-1")
        self.assertEqual(built.graph_version, "dail-graph-1")
        self.assertEqual(built.normalization_version, NORMALIZATION)

    def test_a_resource_without_a_normalization_version_is_refused(self) -> None:
        bare = hand_resource("aws_vpc.main")
        no_version = type(bare).create(
            address="aws_vpc.other",
            resource_type="aws_vpc",
            logical_identity={},
            attributes={},
            security_attributes={},
            semantic_attributes={},
            references=(),
            provenance=type(bare.provenance)(
                source_kind=ProvenanceSourceKind.TERRAFORM_CONFIG,
                source_component="fixture",
                source_reference="main.tf",
                observed_at=at(0),
            ),
            support_status=bare.support_status,
        )
        with self.assertRaises(DependencyInputError):
            build([bare, no_version])

    def test_two_normalization_versions_are_refused(self) -> None:
        first = hand_resource("aws_vpc.a")
        other = type(first).create(
            address="aws_vpc.b",
            resource_type="aws_vpc",
            logical_identity={},
            attributes={},
            security_attributes={},
            semantic_attributes={},
            references=(),
            provenance=type(first.provenance)(
                source_kind=ProvenanceSourceKind.TERRAFORM_CONFIG,
                source_component="fixture",
                source_reference="main.tf",
                observed_at=at(0),
                normalization_version="dail-tf-norm-2",
            ),
            support_status=first.support_status,
        )
        with self.assertRaises(DependencyInputError):
            build([first, other])

    def test_duplicate_addresses_are_refused(self) -> None:
        with self.assertRaises(DependencyInputError):
            build([hand_resource("aws_vpc.a"), hand_resource("aws_vpc.a")])

    def test_only_resources_are_accepted(self) -> None:
        with self.assertRaises(DependencyInputError):
            build(["aws_vpc.a"])
        with self.assertRaises(DependencyInputError):
            build("aws_vpc.a")

    def test_duplicate_invariant_versions_and_unknown_bindings_are_refused(self) -> None:
        resources = fixture_resources(BASELINE)
        with self.assertRaises(DependencyInputError):
            build(resources, [sec_001(), sec_001()])
        with self.assertRaises(DependencyInputError):
            build(resources, [sec_001()], [func_binding()])

    def test_an_empty_state_needs_a_normalization_version(self) -> None:
        with self.assertRaises(DependencyInputError):
            build([], [func_001()], [func_binding()])
        built = build([], [func_001()], [func_binding()], normalization_version=NORMALIZATION)
        self.assertEqual(built.normalization_version, NORMALIZATION)

    def test_a_different_given_version_is_refused(self) -> None:
        with self.assertRaises(DependencyInputError):
            build(fixture_resources(BASELINE), normalization_version="dail-tf-norm-9")

    def test_an_empty_state_with_a_deleted_endpoint_still_has_uncertain_edges(self) -> None:
        built = build([], [func_001()], [func_binding()], normalization_version=NORMALIZATION)
        absent = [n for n in built.nodes if n.attributes.get("kind") == "absent"]
        self.assertEqual(
            sorted(n.ref_id for n in absent), ["aws_db_instance.database", "aws_instance.app"]
        )
        self.assertTrue(
            all(
                e.status.value == "UNCERTAIN"
                for e in built.edges
                if e.edge_type is EdgeType.INVARIANT_SCOPE
            )
        )

    def test_a_bad_state_id_or_clock_is_refused(self) -> None:
        resources = fixture_resources(BASELINE)
        with self.assertRaises(DomainValidationError):
            build_graph(resources, [], state_id="not-a-uuid", now=NOW)
        with self.assertRaises(DomainValidationError):
            build_graph(resources, [], state_id=STATE, now=NOW.replace(tzinfo=None))


class TestBuiltGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.graph = build(
            fixture_resources(BASELINE), [sec_001(), sec_003(), func_001()], [func_binding()]
        )

    def test_the_graph_is_a_dependency_graph_for_the_state(self) -> None:
        self.assertIsInstance(self.graph, DependencyGraph)
        self.assertEqual(self.graph.state_id, STATE)
        self.assertEqual(self.graph.created_at, NOW)

    def test_nodes_and_edges_are_sorted_by_their_stable_ids(self) -> None:
        ids = [n.node_id for n in self.graph.nodes]
        keys = [e.edge_key for e in self.graph.edges]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(keys, sorted(keys))

    def test_every_resource_is_a_node(self) -> None:
        resources = {f"RESOURCE:{r.address}" for r in fixture_resources(BASELINE)}
        self.assertTrue(resources <= {n.node_id for n in self.graph.nodes})

    def test_the_reference_and_infrastructure_edge_counts_of_the_baseline(self) -> None:
        classes = [e.edge_type for e in self.graph.edges]
        self.assertEqual(classes.count(EdgeType.TERRAFORM_REFERENCE), len(BASELINE_REFERENCE_EDGES))
        self.assertEqual(classes.count(EdgeType.INFRASTRUCTURE), len(BASELINE_INFRASTRUCTURE_EDGES))

    def test_every_edge_has_evidence_and_provenance(self) -> None:
        for edge in self.graph.edges:
            self.assertTrue(edge.provenance)
            self.assertTrue(edge.evidence.source_fact)
            self.assertTrue(edge.evidence.target_fact)

    def test_the_graph_survives_a_round_trip(self) -> None:
        self.assertEqual(DependencyGraph.from_dict(self.graph.to_dict()), self.graph)

    def test_ids_and_the_clock_do_not_reach_the_hash(self) -> None:
        other = build_graph(
            fixture_resources(BASELINE),
            [sec_001(), sec_003(), func_001()],
            [func_binding()],
            state_id=uid(42),
            now=NOW + timedelta(days=30),
        )
        self.assertNotEqual(other.graph_id, self.graph.graph_id)
        self.assertEqual(other.graph_hash, self.graph.graph_hash)


# --- Step 7: the fixtures ---------------------------------------------------------------------

PATCH_SAFE = "fixtures/canonical_regression/patch_safe"
UNKNOWN = "fixtures/dependency/func_unknown_dependency_unknown_v1"
UNSUPPORTED = "fixtures/dependency/func_unsupported_relationship_unsupported_v1"
AMBIGUOUS = "fixtures/identity/ambiguous_identity_uncertain_v1"
AMBIGUOUS_PARENT = "fixtures/identity/ambiguous_identity_parent_v1"
RDS_DELETED = "fixtures/impact/rds_deleted_dependency_fail_v1"
SG_CREATED = "fixtures/impact/sg_created_resource_fail_v1"
SG_REPLACED = "fixtures/impact/sg_replacement_resource_promote_v1"

K, UC, UN = (
    DependencyStatus.KNOWN,
    DependencyStatus.UNCERTAIN,
    DependencyStatus.UNSUPPORTED,
)
STANDARD_INVARIANTS = (sec_001, sec_002, sec_003, func_001)


def fixture_graph(folder: str, *, bindings: bool = True) -> DependencyGraph:
    """The graph of a fixture folder under the four registry invariants (R4)."""
    return build(
        fixture_resources(folder),
        [make() for make in STANDARD_INVARIANTS],
        [func_binding()] if bindings else [],
    )


def edges_from(built: DependencyGraph, node_id: str) -> list[GraphEdge]:
    return [e for e in built.edges if e.source_node_id == node_id]


def node_of(built: DependencyGraph, node_id: str) -> GraphNode:
    found = built.node(node_id)
    assert found is not None, node_id
    return found


def count(built: DependencyGraph, edge_type: EdgeType) -> int:
    return sum(1 for e in built.edges if e.edge_type is edge_type)


class TestCanonicalBaselineGraph(unittest.TestCase):
    """The 20 reference edges and 13 typed edges derived by hand from the .tf text."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.graph = fixture_graph(BASELINE)

    def test_the_reference_edges_are_the_hand_derived_ones(self) -> None:
        got = {
            (
                e.source_node_id.removeprefix("RESOURCE:"),
                e.target_node_id.removeprefix("RESOURCE:"),
                e.status,
            )
            for e in self.graph.edges
            if e.edge_type is EdgeType.TERRAFORM_REFERENCE
        }
        self.assertEqual(got, set(BASELINE_REFERENCE_EDGES))
        self.assertEqual(count(self.graph, EdgeType.TERRAFORM_REFERENCE), 20)

    def test_the_infrastructure_edges_are_the_hand_derived_ones(self) -> None:
        got = {
            (
                e.source_node_id.removeprefix("RESOURCE:"),
                e.target_node_id.removeprefix("RESOURCE:"),
                e.relationship,
            )
            for e in self.graph.edges
            if e.edge_type is EdgeType.INFRASTRUCTURE
        }
        self.assertEqual(got, set(BASELINE_INFRASTRUCTURE_EDGES))
        self.assertEqual(count(self.graph, EdgeType.INFRASTRUCTURE), 13)

    def test_the_edges_that_touch_the_subnet_group_are_unsupported_and_no_other_is(self) -> None:
        group = "RESOURCE:aws_db_subnet_group.db"
        resource_classes = (EdgeType.TERRAFORM_REFERENCE, EdgeType.INFRASTRUCTURE)
        for edge in self.graph.edges:
            if edge.edge_type not in resource_classes:
                continue
            touches = group in (edge.source_node_id, edge.target_node_id)
            self.assertEqual(edge.status is UN, touches, edge.evidence.source_fact)

    def test_the_baseline_has_no_uncertain_edge_between_resources(self) -> None:
        resource_classes = (EdgeType.TERRAFORM_REFERENCE, EdgeType.INFRASTRUCTURE)
        self.assertFalse(
            any(e.status is UC for e in self.graph.edges if e.edge_type in resource_classes)
        )

    def test_the_rule_nodes_keep_the_canonical_rule_summary(self) -> None:
        ssh = node_of(self.graph, "RESOURCE:aws_security_group_rule.app_ssh_public").attributes
        self.assertEqual(ssh["direction"], "INGRESS")
        self.assertEqual(ssh["protocol"], "TCP")
        self.assertEqual((ssh["from_port"], ssh["to_port"]), (22, 22))
        self.assertTrue(ssh["determinate"])
        self.assertFalse(ssh["unsupported"])
        self.assertIsInstance(ssh["rule_key"], str)
        egress = node_of(self.graph, "RESOURCE:aws_security_group_rule.app_egress_all").attributes
        self.assertEqual((egress["direction"], egress["protocol"]), ("EGRESS", "ALL"))

    def test_the_group_nodes_keep_the_inline_forms(self) -> None:
        db = node_of(self.graph, "RESOURCE:aws_security_group.db").attributes
        self.assertEqual(
            dict(db["inline_forms"]), {"egress": "explicit_empty", "ingress": "absent"}
        )
        self.assertEqual(list(db["inline_rule_keys"]), [])
        self.assertEqual(list(db["inline_indeterminate"]), [])

    def test_the_four_invariants_and_the_port_are_nodes(self) -> None:
        ids = {n.node_id for n in self.graph.nodes}
        for wanted in (
            "INVARIANT:INV-SEC-001:1",
            "INVARIANT:INV-SEC-002:1",
            "INVARIANT:INV-SEC-003:1",
            "INVARIANT:INV-FUNC-001:1",
            "SEMANTIC:TCP/5432",
        ):
            self.assertIn(wanted, ids)


class TestDependencyFixtures(unittest.TestCase):
    RULE = "RESOURCE:aws_security_group_rule.app_to_db_5432"
    UNRESOLVED = (
        "SEMANTIC:UNRESOLVED:aws_security_group_rule.app_to_db_5432#source_security_group_id"
    )

    def test_unknown_dependency_gives_an_uncertain_edge_and_an_indeterminate_rule(self) -> None:
        built = fixture_graph(UNKNOWN)
        unresolved = [
            e for e in edges_from(built, self.RULE) if e.target_node_id == self.UNRESOLVED
        ]
        self.assertEqual(len(unresolved), 1)
        self.assertIs(unresolved[0].status, UC)
        self.assertEqual(unresolved[0].attributes["reason"], "variable.no_value")
        self.assertIsNotNone(built.node(self.UNRESOLVED))
        self.assertFalse(node_of(built, self.RULE).attributes["determinate"])

    def test_unknown_dependency_keeps_the_known_part_of_the_rule(self) -> None:
        built = fixture_graph(UNKNOWN)
        owner = [
            e
            for e in edges_from(built, self.RULE)
            if e.relationship is Relationship.RULE_BELONGS_TO_SECURITY_GROUP
        ]
        self.assertEqual([e.target_node_id for e in owner], ["RESOURCE:aws_security_group.db"])
        self.assertIs(owner[0].status, K)
        # the source group is no longer a reference edge to a group
        refs = [
            e
            for e in edges_from(built, self.RULE)
            if e.edge_type is EdgeType.TERRAFORM_REFERENCE
            and e.target_node_id == "RESOURCE:aws_security_group.app"
        ]
        self.assertEqual(refs, [])

    def test_unknown_dependency_edge_counts(self) -> None:
        # patch_safe = baseline without the public SSH rule: 19 references and 12 typed edges;
        # this fixture replaces the rule's source reference by one unresolved edge
        built = fixture_graph(UNKNOWN)
        self.assertEqual(count(built, EdgeType.INFRASTRUCTURE), 12)
        self.assertEqual(count(built, EdgeType.TERRAFORM_REFERENCE), 19)
        unresolved = [e for e in built.edges if e.target_node_id.startswith("SEMANTIC:UNRESOLVED:")]
        self.assertEqual(len(unresolved), 1)

    def test_unsupported_relationship_keeps_the_acl_as_an_unsupported_node(self) -> None:
        built = fixture_graph(UNSUPPORTED)
        acl = node_of(built, "RESOURCE:aws_network_acl.extra")
        self.assertEqual(acl.attributes["support_status"], "UNSUPPORTED")
        out = edges_from(built, acl.node_id)
        self.assertEqual([e.target_node_id for e in out], ["RESOURCE:aws_vpc.main"])
        self.assertIs(out[0].status, UN)
        self.assertIs(out[0].edge_type, EdgeType.TERRAFORM_REFERENCE)

    def test_unsupported_relationship_acl_appears_in_a_scope_that_names_its_type(self) -> None:
        # registry §2.7: aws_network_acl is relevant-unsupported for INV-FUNC-001
        scoped = make_invariant(
            "INV-FUNC-001",
            category=InvariantCategory.FUNCTIONAL,
            resources=("aws_instance.app", "aws_db_instance.database"),
            resource_types=("aws_network_acl",),
        )
        built = build(fixture_resources(UNSUPPORTED), [scoped], [func_binding()])
        scope = [
            e
            for e in edges_from(built, "INVARIANT:INV-FUNC-001:1")
            if e.target_node_id == "RESOURCE:aws_network_acl.extra"
        ]
        self.assertEqual(len(scope), 1)
        self.assertIs(scope[0].status, UN)
        self.assertIs(scope[0].evidence.derivation_rule, DerivationRule.SCOPE_TYPE)

    def test_unsupported_relationship_has_no_typed_edge_from_the_acl(self) -> None:
        built = fixture_graph(UNSUPPORTED)
        typed = [
            e
            for e in edges_from(built, "RESOURCE:aws_network_acl.extra")
            if e.edge_type is EdgeType.INFRASTRUCTURE
        ]
        self.assertEqual(typed, [])


class TestOtherFixtures(unittest.TestCase):
    def test_ambiguous_identity_candidate_has_the_two_instances_as_nodes(self) -> None:
        built = fixture_graph(AMBIGUOUS)
        ids = {n.node_id for n in built.nodes}
        a, b = 'RESOURCE:aws_security_group.ops["a"]', 'RESOURCE:aws_security_group.ops["b"]'
        self.assertIn(a, ids)
        self.assertIn(b, ids)
        self.assertNotIn("RESOURCE:aws_security_group.ops", ids)
        for node_id in (a, b):
            out = edges_from(built, node_id)
            self.assertEqual([e.target_node_id for e in out], ["RESOURCE:aws_vpc.main"])
        scope = {e.target_node_id for e in edges_from(built, "INVARIANT:INV-SEC-001:1")}
        self.assertTrue({a, b} <= scope)

    def test_ambiguous_identity_parent_has_the_single_group_as_a_node(self) -> None:
        built = fixture_graph(AMBIGUOUS_PARENT)
        ids = {n.node_id for n in built.nodes}
        self.assertIn("RESOURCE:aws_security_group.ops", ids)
        self.assertFalse(any('ops["' in node_id for node_id in ids))

    def test_ambiguous_identity_graphs_differ_in_structure(self) -> None:
        self.assertNotEqual(
            fixture_graph(AMBIGUOUS).graph_hash, fixture_graph(AMBIGUOUS_PARENT).graph_hash
        )

    def test_rds_deleted_binding_ends_at_an_absent_node(self) -> None:
        built = fixture_graph(RDS_DELETED)
        database = node_of(built, "RESOURCE:aws_db_instance.database")
        self.assertEqual(database.attributes["kind"], "absent")
        self.assertNotIn("RESOURCE:aws_db_subnet_group.db", {n.node_id for n in built.nodes})
        into = [e for e in built.edges if e.target_node_id == database.node_id]
        self.assertEqual(
            sorted((e.source_node_id, e.relationship.value) for e in into),
            [
                ("INVARIANT:INV-FUNC-001:1", "DESTINATION"),
                ("INVARIANT:INV-FUNC-001:1", "SCOPE"),
            ],
        )
        self.assertTrue(all(e.status is UC for e in into))

    def test_rds_deleted_has_no_edge_for_sec_003(self) -> None:
        built = fixture_graph(RDS_DELETED)
        self.assertEqual(edges_from(built, "INVARIANT:INV-SEC-003:1"), [])

    def test_the_parent_of_rds_deleted_has_the_database_as_a_known_resource(self) -> None:
        built = fixture_graph(PATCH_SAFE)
        self.assertEqual(
            node_of(built, "RESOURCE:aws_db_instance.database").attributes["kind"], "resource"
        )
        into = [e for e in built.edges if e.target_node_id == "RESOURCE:aws_db_instance.database"]
        self.assertTrue(into and all(e.status is K for e in into))

    def test_sg_created_has_the_new_group_in_the_sec_001_scope(self) -> None:
        built = fixture_graph(SG_CREATED)
        for invariant in ("INV-SEC-001", "INV-SEC-002"):
            scope = {e.target_node_id: e for e in edges_from(built, f"INVARIANT:{invariant}:1")}
            self.assertIn("RESOURCE:aws_security_group.bastion", scope)
            self.assertIs(scope["RESOURCE:aws_security_group.bastion"].status, K)
        parent = fixture_graph(PATCH_SAFE)
        self.assertNotIn(
            "RESOURCE:aws_security_group.bastion",
            {e.target_node_id for e in edges_from(parent, "INVARIANT:INV-SEC-001:1")},
        )

    def test_sg_created_group_keeps_its_inline_rule_in_the_node(self) -> None:
        built = fixture_graph(SG_CREATED)
        bastion = node_of(built, "RESOURCE:aws_security_group.bastion").attributes
        self.assertEqual(len(bastion["inline_rule_keys"]), 1)
        self.assertEqual(bastion["inline_forms"]["ingress"], "blocks")

    def test_sg_replacement_has_the_same_graph_hash_as_its_parent(self) -> None:
        # a ForceNew name change does not change the structure (C-132: no raw attribute values)
        self.assertEqual(
            fixture_graph(SG_REPLACED).graph_hash, fixture_graph(PATCH_SAFE).graph_hash
        )

    def test_the_replacement_changes_the_resource_but_not_the_graph(self) -> None:
        parent = {r.address: r for r in fixture_resources(PATCH_SAFE)}
        child = {r.address: r for r in fixture_resources(SG_REPLACED)}
        before, after = parent["aws_security_group.db"], child["aws_security_group.db"]
        self.assertNotEqual(before.fingerprint, after.fingerprint)
        self.assertEqual(
            [e.edge_key for e in fixture_graph(SG_REPLACED).edges],
            [e.edge_key for e in fixture_graph(PATCH_SAFE).edges],
        )


class TestEveryFixture(unittest.TestCase):
    @staticmethod
    def folders() -> list[str]:
        found: set[str] = set()
        for fixture in fc.load_all().values():
            for key in ("config", "parent"):
                if fixture.data[key] is not None:
                    found.add(fixture.data[key])
        return sorted(found)

    def test_every_fixture_configuration_builds_a_graph(self) -> None:
        folders = self.folders()
        # every directory that holds Terraform text is a configuration some fixture points at
        on_disk = sorted(
            path.parent.relative_to(fc.REPO_ROOT).as_posix()
            for path in (fc.REPO_ROOT / "fixtures").rglob("main.tf")
        )
        self.assertEqual(folders, on_disk)
        self.assertEqual(len(folders), 16)
        for folder in folders:
            with self.subTest(folder=folder):
                built = fixture_graph(folder)
                self.assertTrue(built.nodes)
                self.assertTrue(built.edges)

    def test_every_edge_of_every_fixture_has_evidence_and_provenance(self) -> None:
        for folder in self.folders():
            built = fixture_graph(folder)
            for edge in built.edges:
                with self.subTest(folder=folder, edge=edge.evidence.source_fact):
                    self.assertTrue(edge.provenance)
                    self.assertTrue(edge.evidence.source_fact)
                    self.assertTrue(edge.evidence.target_fact)
                    self.assertIsInstance(edge.evidence.derivation_rule, DerivationRule)

    def test_every_graph_is_the_same_when_built_again(self) -> None:
        for folder in self.folders():
            with self.subTest(folder=folder):
                self.assertEqual(fixture_graph(folder).graph_hash, fixture_graph(folder).graph_hash)

    def test_every_graph_survives_a_round_trip(self) -> None:
        for folder in self.folders():
            with self.subTest(folder=folder):
                built = fixture_graph(folder)
                self.assertEqual(DependencyGraph.from_dict(built.to_dict()), built)


if __name__ == "__main__":
    unittest.main()
