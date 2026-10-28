"""The dependency graph domain types (P3c step 2; Doc 05 §11, Doc 07 §20-§22, §27-§29; C-132).

Expectations come from the specification text: the four edge classes, the node-id formats of Doc 07
§21, the edge-key inputs of §22 (the status is not one of them), the structural hash of C-132 and
the guards a reader of the graph can rely on.
"""

from __future__ import annotations

import dataclasses
import unittest
from datetime import timedelta

from core.domain.enums import DependencyStatus
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.graph import (
    DERIVATION_DEFINITIONS,
    INFRASTRUCTURE_RELATIONSHIPS,
    RELATIONSHIPS_BY_TYPE,
    DependencyEvidence,
    DependencyGraph,
    DerivationRule,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    Relationship,
    edge_key_of,
    resource_node_id,
)
from tests.domain_builders import at, uid
from tests.graph_builders import (
    ALGORITHM,
    NORMALIZATION,
    edge,
    graph,
    inode,
    ref_edge,
    rnode,
    snode,
    triangle,
)

SUBNET_TYPES = (
    "SUBNET_BELONGS_TO_VPC",
    "ROUTE_TABLE_BELONGS_TO_VPC",
    "ASSOCIATES_SUBNET",
    "ASSOCIATES_ROUTE_TABLE",
    "IGW_ATTACHED_TO_VPC",
    "INSTANCE_IN_SUBNET",
    "INSTANCE_USES_SECURITY_GROUP",
    "DB_USES_SECURITY_GROUP",
    "RULE_BELONGS_TO_SECURITY_GROUP",
)


class TestVocabularies(unittest.TestCase):
    def test_edge_classes_are_the_four_of_doc_05(self) -> None:
        self.assertEqual(
            {e.value for e in EdgeType},
            {"TERRAFORM_REFERENCE", "INFRASTRUCTURE", "INVARIANT_SCOPE", "INVARIANT_SEMANTIC"},
        )

    def test_node_types_are_the_three_of_doc_05(self) -> None:
        self.assertEqual({n.value for n in NodeType}, {"RESOURCE", "INVARIANT", "SEMANTIC"})

    def test_infrastructure_relationships_are_the_nine_of_doc_07_s16(self) -> None:
        self.assertEqual({r.value for r in INFRASTRUCTURE_RELATIONSHIPS}, set(SUBNET_TYPES))

    def test_every_relationship_belongs_to_exactly_one_class(self) -> None:
        for relationship in Relationship:
            owners = [t for t, rels in RELATIONSHIPS_BY_TYPE.items() if relationship in rels]
            self.assertEqual(len(owners), 1, relationship)

    def test_the_derivation_vocabulary_is_the_closed_list_of_c_133(self) -> None:
        self.assertEqual(
            {r.value for r in DerivationRule},
            {
                "REFERENCE",
                "BLOCK_FANOUT",
                "SLOT_REFERENCE",
                "SLOT_UNKNOWN_VALUE",
                "SLOT_UNSUPPORTED_VALUE",
                "EXTERNAL_OBJECT",
                "UNSET",
                "TYPE_MISMATCH",
                "SCOPE_RESOURCE",
                "SCOPE_TYPE",
                "SEMANTIC_BINDING",
                "BINDING_MISSING",
            },
        )
        self.assertEqual(set(DERIVATION_DEFINITIONS), set(DerivationRule))

    def test_dependency_status_is_known_uncertain_unsupported(self) -> None:
        self.assertEqual({s.value for s in DependencyStatus}, {"KNOWN", "UNCERTAIN", "UNSUPPORTED"})


class TestNode(unittest.TestCase):
    def test_resource_node_id_is_resource_colon_address(self) -> None:
        self.assertEqual(rnode("aws_vpc.main").node_id, "RESOURCE:aws_vpc.main")

    def test_instance_addresses_keep_their_key(self) -> None:
        node = rnode('aws_security_group.ops["a"]')
        self.assertEqual(node.node_id, 'RESOURCE:aws_security_group.ops["a"]')

    def test_invariant_node_id_has_id_and_version(self) -> None:
        self.assertEqual(inode("INV-FUNC-001", 2).node_id, "INVARIANT:INV-FUNC-001:2")

    def test_semantic_node_id(self) -> None:
        self.assertEqual(snode("TCP/5432").node_id, "SEMANTIC:TCP/5432")

    def test_node_id_must_match_type_and_ref_id(self) -> None:
        bad = (
            ("RESOURCE:other", NodeType.RESOURCE, "aws_vpc.main"),
            ("aws_vpc.main", NodeType.RESOURCE, "aws_vpc.main"),
            ("SEMANTIC:aws_vpc.main", NodeType.RESOURCE, "aws_vpc.main"),
            ("RESOURCE:aws_vpc.main", NodeType.SEMANTIC, "aws_vpc.main"),
            ("INVARIANT:INV-SEC-001", NodeType.INVARIANT, "INV-SEC-001"),
            ("INVARIANT:INV-SEC-001:0", NodeType.INVARIANT, "INV-SEC-001"),
            ("INVARIANT:INV-SEC-001:x", NodeType.INVARIANT, "INV-SEC-001"),
            ("INVARIANT:INV-SEC-002:1", NodeType.INVARIANT, "INV-SEC-001"),
        )
        for node_id, node_type, ref_id in bad:
            with self.subTest(node_id=node_id), self.assertRaises(DomainValidationError):
                GraphNode(node_id=node_id, node_type=node_type, ref_id=ref_id, attributes={})

    def test_attributes_must_be_json_without_floats(self) -> None:
        with self.assertRaises(DomainValidationError):
            rnode("aws_vpc.main", ratio=1.5)
        with self.assertRaises(DomainValidationError):
            GraphNode(
                node_id="RESOURCE:a.b", node_type=NodeType.RESOURCE, ref_id="a.b", attributes=[]  # type: ignore[arg-type]
            )

    def test_attributes_are_frozen(self) -> None:
        source = {"kind": "resource"}
        node = GraphNode(
            node_id="RESOURCE:a.b", node_type=NodeType.RESOURCE, ref_id="a.b", attributes=source
        )
        source["kind"] = "changed"
        self.assertEqual(node.attributes["kind"], "resource")
        with self.assertRaises(TypeError):
            node.attributes["kind"] = "x"  # type: ignore[index]

    def test_a_node_is_frozen(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            rnode("a.b").ref_id = "x"  # type: ignore[misc]

    def test_round_trip(self) -> None:
        for node in (rnode("a.b", flag=True), inode(), snode("UNRESOLVED:a.b#c")):
            with self.subTest(node=node.node_id):
                self.assertEqual(GraphNode.from_dict(node.to_dict()), node)

    def test_from_dict_refuses_extra_and_missing_keys(self) -> None:
        data = rnode("a.b").to_dict()
        with self.assertRaises(DomainValidationError):
            GraphNode.from_dict({**data, "extra": 1})
        del data["ref_id"]
        with self.assertRaises(DomainValidationError):
            GraphNode.from_dict(data)


class TestEdge(unittest.TestCase):
    def test_the_key_is_the_hash_of_source_class_relationship_target_attributes(self) -> None:
        item = ref_edge("a.x", "a.y", attributes={"source_attribute": "p"})
        self.assertEqual(
            item.edge_key,
            edge_key_of(
                "RESOURCE:a.x",
                EdgeType.TERRAFORM_REFERENCE,
                Relationship.REFERENCE,
                "RESOURCE:a.y",
                {"source_attribute": "p"},
            ),
        )
        self.assertEqual(len(item.edge_key), 64)

    def test_each_key_input_changes_the_key(self) -> None:
        base = ref_edge("a.x", "a.y")
        others = (
            ref_edge("a.z", "a.y"),
            ref_edge("a.x", "a.z"),
            ref_edge("a.x", "a.y", attributes={"source_attribute": "other"}),
            edge(
                "RESOURCE:a.x",
                "RESOURCE:a.y",
                edge_type=EdgeType.INFRASTRUCTURE,
                relationship=Relationship.SUBNET_BELONGS_TO_VPC,
            ),
            edge(
                "RESOURCE:a.x",
                "RESOURCE:a.y",
                edge_type=EdgeType.INFRASTRUCTURE,
                relationship=Relationship.INSTANCE_IN_SUBNET,
            ),
        )
        keys = {base.edge_key} | {other.edge_key for other in others}
        self.assertEqual(len(keys), 1 + len(others))

    def test_the_status_is_not_part_of_the_key(self) -> None:
        # Doc 07 §22: edge_key = SHA256(source_node + edge_type + target_node + attributes)
        known = ref_edge("a.x", "a.y", status=DependencyStatus.KNOWN)
        uncertain = ref_edge("a.x", "a.y", status=DependencyStatus.UNCERTAIN)
        self.assertEqual(known.edge_key, uncertain.edge_key)

    def test_evidence_text_and_provenance_are_not_part_of_the_key(self) -> None:
        one = ref_edge("a.x", "a.y", source_fact="one", target_fact="1")
        two = ref_edge("a.x", "a.y", source_fact="two", target_fact="2")
        self.assertEqual(one.edge_key, two.edge_key)

    def test_a_relationship_outside_its_class_is_refused(self) -> None:
        for edge_type, relationship in (
            (EdgeType.TERRAFORM_REFERENCE, Relationship.SUBNET_BELONGS_TO_VPC),
            (EdgeType.INFRASTRUCTURE, Relationship.REFERENCE),
            (EdgeType.INFRASTRUCTURE, Relationship.SCOPE),
            (EdgeType.INVARIANT_SCOPE, Relationship.SOURCE),
            (EdgeType.INVARIANT_SEMANTIC, Relationship.SCOPE),
        ):
            with (
                self.subTest(edge_type=edge_type, relationship=relationship),
                self.assertRaises(DomainValidationError),
            ):
                edge(
                    "RESOURCE:a.x",
                    "RESOURCE:a.y",
                    edge_type=edge_type,
                    relationship=relationship,
                )

    def test_bad_enum_values_are_refused(self) -> None:
        with self.assertRaises(DomainValidationError):
            edge("RESOURCE:a.x", "RESOURCE:a.y", edge_type="INFRASTRUCTURE")  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            edge("RESOURCE:a.x", "RESOURCE:a.y", relationship="REFERENCE")  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            edge("RESOURCE:a.x", "RESOURCE:a.y", status="KNOWN")  # type: ignore[arg-type]

    def test_a_tampered_key_is_detected(self) -> None:
        good = ref_edge("a.x", "a.y")
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(good, edge_key="0" * 64)

    def test_a_changed_field_with_the_old_key_is_detected(self) -> None:
        good = ref_edge("a.x", "a.y")
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(good, target_node_id="RESOURCE:a.z")
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(good, attributes={"source_attribute": "tampered"})

    def test_the_evidence_must_describe_the_edge(self) -> None:
        good = ref_edge("a.x", "a.y")
        other_status = dataclasses.replace(good.evidence, status=DependencyStatus.UNSUPPORTED)
        other_target = dataclasses.replace(good.evidence, target="RESOURCE:a.z")
        other_rel = dataclasses.replace(
            good.evidence,
            edge_type=EdgeType.INFRASTRUCTURE,
            relationship=Relationship.INSTANCE_IN_SUBNET,
        )
        for evidence in (other_status, other_target, other_rel):
            with self.subTest(evidence=evidence), self.assertRaises(DomainValidationError):
                dataclasses.replace(good, evidence=evidence)

    def test_provenance_is_required(self) -> None:
        good = ref_edge("a.x", "a.y")
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(good, provenance=())
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(good, provenance=("main.tf",))  # type: ignore[arg-type]

    def test_evidence_fields_are_validated(self) -> None:
        good = ref_edge("a.x", "a.y").evidence
        for field in ("source", "target", "source_fact", "target_fact"):
            with self.subTest(field=field), self.assertRaises(DomainValidationError):
                dataclasses.replace(good, **{field: ""})
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(good, derivation_rule="REFERENCE")  # type: ignore[arg-type]

    def test_edge_attributes_reject_floats(self) -> None:
        with self.assertRaises(DomainValidationError):
            ref_edge("a.x", "a.y", attributes={"ratio": 0.5})

    def test_round_trip(self) -> None:
        item = edge(
            "RESOURCE:a.x",
            "SEMANTIC:UNRESOLVED:a.x#subnet_id",
            edge_type=EdgeType.INFRASTRUCTURE,
            relationship=Relationship.INSTANCE_IN_SUBNET,
            status=DependencyStatus.UNCERTAIN,
            attributes={"argument": "subnet_id", "reason": "unset"},
            rule=DerivationRule.UNSET,
        )
        self.assertEqual(GraphEdge.from_dict(item.to_dict()), item)
        self.assertEqual(DependencyEvidence.from_dict(item.evidence.to_dict()), item.evidence)


class TestGraph(unittest.TestCase):
    def test_create_sorts_nodes_by_node_id_and_edges_by_key(self) -> None:
        built = graph(
            [rnode("b.b"), rnode("a.a"), inode(), snode("TCP/5432")],
            [ref_edge("b.b", "a.a"), ref_edge("a.a", "b.b")],
        )
        ids = [node.node_id for node in built.nodes]
        self.assertEqual(ids, sorted(ids))
        keys = [item.edge_key for item in built.edges]
        self.assertEqual(keys, sorted(keys))

    def test_graph_version_is_the_algorithm_version(self) -> None:
        built = triangle()
        self.assertEqual(built.graph_version, ALGORITHM)
        self.assertEqual(built.algorithm_version, ALGORITHM)
        self.assertEqual(built.normalization_version, NORMALIZATION)
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, graph_version="other")

    def test_a_cycle_is_valid(self) -> None:
        self.assertEqual(len(triangle().edges), 3)

    def test_a_self_loop_is_valid(self) -> None:
        built = graph([rnode("a.a")], [ref_edge("a.a", "a.a")])
        self.assertEqual(len(built.edges), 1)

    def test_a_dangling_endpoint_is_refused(self) -> None:
        with self.assertRaises(DomainValidationError):
            graph([rnode("a.a")], [ref_edge("a.a", "a.missing")])
        with self.assertRaises(DomainValidationError):
            graph([rnode("a.b")], [ref_edge("a.missing", "a.b")])

    def test_a_duplicate_node_is_refused(self) -> None:
        with self.assertRaises(DomainValidationError):
            graph([rnode("a.a"), rnode("a.a")], [])

    def test_a_duplicate_edge_key_is_refused(self) -> None:
        with self.assertRaises(DomainValidationError):
            graph([rnode("a.a"), rnode("a.b")], [ref_edge("a.a", "a.b"), ref_edge("a.a", "a.b")])

    def test_unsorted_nodes_or_edges_are_refused(self) -> None:
        built = graph(
            [rnode("a.a"), rnode("a.b")], [ref_edge("a.a", "a.b"), ref_edge("a.b", "a.a")]
        )
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, nodes=tuple(reversed(built.nodes)))
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, edges=tuple(reversed(built.edges)))

    def test_edge_classes_start_at_the_right_node_type(self) -> None:
        # reference and infrastructure edges start at a resource; invariant edges at an invariant
        with self.assertRaises(DomainValidationError):
            graph([inode(), rnode("a.a")], [edge("INVARIANT:INV-SEC-001:1", "RESOURCE:a.a")])
        with self.assertRaises(DomainValidationError):
            graph(
                [rnode("a.a"), rnode("a.b")],
                [
                    edge(
                        "RESOURCE:a.a",
                        "RESOURCE:a.b",
                        edge_type=EdgeType.INVARIANT_SCOPE,
                        relationship=Relationship.SCOPE,
                        rule=DerivationRule.SCOPE_TYPE,
                    )
                ],
            )
        ok = graph(
            [inode(), rnode("a.a")],
            [
                edge(
                    "INVARIANT:INV-SEC-001:1",
                    "RESOURCE:a.a",
                    edge_type=EdgeType.INVARIANT_SCOPE,
                    relationship=Relationship.SCOPE,
                    attributes={},
                    rule=DerivationRule.SCOPE_TYPE,
                )
            ],
        )
        self.assertEqual(len(ok.edges), 1)

    def test_the_hash_is_recomputed_and_a_tampered_hash_is_detected(self) -> None:
        built = triangle()
        self.assertEqual(len(built.graph_hash), 64)
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(built, graph_hash="0" * 64)

    def test_changed_content_with_the_old_hash_is_detected(self) -> None:
        built = triangle()
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(built, nodes=built.nodes[:2], edges=())
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(built, normalization_version="dail-tf-norm-2")

    def test_the_hash_ignores_ids_time_provenance_and_evidence_text(self) -> None:
        one = triangle()
        other = graph(
            [rnode("t.a"), rnode("t.b"), rnode("t.c")],
            [
                ref_edge("t.a", "t.b", source_fact="different", target_fact="words"),
                ref_edge("t.b", "t.c", source_fact="x"),
                ref_edge("t.c", "t.a", rule=DerivationRule.BLOCK_FANOUT),
            ],
            state_id=uid(99),
            now=at(500),
            graph_id=uid(77),
        )
        self.assertNotEqual(one.graph_id, other.graph_id)
        self.assertNotEqual(one.created_at, other.created_at)
        self.assertEqual(one.graph_hash, other.graph_hash)

    def test_the_hash_ignores_input_order(self) -> None:
        nodes = [rnode("t.a"), rnode("t.b"), rnode("t.c")]
        edges = [ref_edge("t.a", "t.b"), ref_edge("t.b", "t.c"), ref_edge("t.c", "t.a")]
        self.assertEqual(
            graph(nodes, edges).graph_hash, graph(reversed(nodes), reversed(edges)).graph_hash
        )

    def test_the_hash_depends_on_every_structural_part(self) -> None:
        base = triangle().graph_hash
        nodes = [rnode("t.a"), rnode("t.b"), rnode("t.c")]
        edges = [ref_edge("t.a", "t.b"), ref_edge("t.b", "t.c"), ref_edge("t.c", "t.a")]
        variants = {
            "algorithm": graph(nodes, edges, algorithm_version="dail-graph-2"),
            "normalization": graph(nodes, edges, normalization_version="dail-tf-norm-2"),
            "node attribute": graph(
                [rnode("t.a", support_status="UNSUPPORTED"), *nodes[1:]], edges
            ),
            "extra node": graph([*nodes, rnode("t.d")], edges),
            "edge status": graph(
                nodes, [ref_edge("t.a", "t.b", status=DependencyStatus.UNCERTAIN), *edges[1:]]
            ),
            "edge attribute": graph(
                nodes, [ref_edge("t.a", "t.b", attributes={"source_attribute": "z"}), *edges[1:]]
            ),
            "missing edge": graph(nodes, edges[:2]),
        }
        for name, variant in variants.items():
            with self.subTest(change=name):
                self.assertNotEqual(variant.graph_hash, base)
        self.assertEqual(len({v.graph_hash for v in variants.values()}), len(variants))

    def test_ids_and_time_are_validated(self) -> None:
        built = triangle()
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, graph_id="not-a-uuid")
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, state_id="not-a-uuid")
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, created_at=built.created_at.replace(tzinfo=None))
        with self.assertRaises(DomainValidationError):
            graph([], [], now=at(0).astimezone(tz=None).replace(tzinfo=None))

    def test_round_trip_keeps_the_hash(self) -> None:
        built = graph(
            [rnode("t.a"), inode(), snode("UNRESOLVED:t.a#x")],
            [
                edge(
                    "RESOURCE:t.a",
                    "SEMANTIC:UNRESOLVED:t.a#x",
                    edge_type=EdgeType.INFRASTRUCTURE,
                    relationship=Relationship.INSTANCE_IN_SUBNET,
                    status=DependencyStatus.UNCERTAIN,
                    attributes={"argument": "x", "reason": "unset"},
                    rule=DerivationRule.UNSET,
                )
            ],
        )
        again = DependencyGraph.from_dict(built.to_dict())
        self.assertEqual(again, built)
        self.assertEqual(again.graph_hash, built.graph_hash)
        self.assertEqual(again.created_at, built.created_at + timedelta(0))

    def test_from_dict_checks_the_hash(self) -> None:
        data = triangle().to_dict()
        data["graph_hash"] = "f" * 64
        with self.assertRaises(HashMismatchError):
            DependencyGraph.from_dict(data)

    def test_lookup_helpers(self) -> None:
        built = triangle()
        self.assertIsNotNone(built.node(resource_node_id("t.a")))
        self.assertIsNone(built.node("RESOURCE:nope"))
        self.assertEqual(len(built.edges_from(resource_node_id("t.a"))), 1)
        self.assertEqual(len(built.edges_to(resource_node_id("t.a"))), 1)


if __name__ == "__main__":
    unittest.main()
