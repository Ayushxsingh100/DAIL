"""``build_graph`` end to end (P3c steps 6 and 7; Doc 07 §20, §31, §36.2-§36.3, §37; C-131, C-132).

Step 6 holds the input checks and the shape of a built graph; step 7 adds the fixtures.
"""

from __future__ import annotations

import unittest
from datetime import timedelta

from core.dependency.build import build_graph
from core.dependency.errors import DependencyInputError
from core.dependency.versions import GRAPH_ALGORITHM_VERSION
from core.domain.enums import ProvenanceSourceKind
from core.domain.errors import DomainValidationError
from core.domain.graph import DependencyGraph, EdgeType
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
    sec_001,
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


if __name__ == "__main__":
    unittest.main()
