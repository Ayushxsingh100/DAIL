"""The traversal helper (P3c step 6; Doc 07 §25, Doc 08 §11-§12, Doc 15 §10.2; C-135).

Expected reachability sets for the canonical baseline are derived by hand from the ``.tf`` text,
not from the engine: who depends on what is read off the references.
"""

from __future__ import annotations

import random
import unittest

from core.dependency.build import build_graph
from core.dependency.errors import DependencyInputError
from core.dependency.traversal import Direction, reachable
from core.domain.enums import DependencyStatus
from core.domain.graph import DependencyGraph, GraphEdge
from tests.graph_builders import (
    BASELINE,
    NOW,
    STATE,
    fixture_resources,
    graph,
    ref_edge,
    rnode,
    triangle,
)

K, UC, UN = (
    DependencyStatus.KNOWN,
    DependencyStatus.UNCERTAIN,
    DependencyStatus.UNSUPPORTED,
)
F, V = Direction.FORWARD, Direction.REVERSE


def rid(address: str) -> str:
    return f"RESOURCE:{address}"


def chain() -> DependencyGraph:
    """a -> b -> c, and d on its own."""
    return graph(
        [rnode("t.a"), rnode("t.b"), rnode("t.c"), rnode("t.d")],
        [ref_edge("t.a", "t.b"), ref_edge("t.b", "t.c")],
    )


class TestDirections(unittest.TestCase):
    def test_forward_follows_source_to_target(self) -> None:
        found = reachable(chain(), [rid("t.a")], direction=F)
        self.assertEqual(found.visited, (rid("t.a"), rid("t.b"), rid("t.c")))

    def test_reverse_follows_target_to_source(self) -> None:
        found = reachable(chain(), [rid("t.c")], direction=V)
        self.assertEqual(found.visited, (rid("t.a"), rid("t.b"), rid("t.c")))

    def test_the_other_direction_finds_nothing_more(self) -> None:
        self.assertEqual(reachable(chain(), [rid("t.c")], direction=F).visited, (rid("t.c"),))
        self.assertEqual(reachable(chain(), [rid("t.a")], direction=V).visited, (rid("t.a"),))

    def test_an_unconnected_node_is_not_visited(self) -> None:
        for direction in (F, V):
            found = reachable(chain(), [rid("t.a")], direction=direction)
            self.assertNotIn(rid("t.d"), found.visited)

    def test_start_nodes_are_visited_and_have_no_via(self) -> None:
        found = reachable(chain(), [rid("t.a"), rid("t.d")], direction=F)
        self.assertIn(rid("t.a"), found.visited)
        self.assertIn(rid("t.d"), found.visited)
        self.assertNotIn(rid("t.a"), found.via)
        self.assertNotIn(rid("t.d"), found.via)
        self.assertEqual(found.path_to(rid("t.d")), ())

    def test_several_start_nodes_are_merged(self) -> None:
        found = reachable(chain(), [rid("t.b"), rid("t.d")], direction=F)
        self.assertEqual(found.visited, (rid("t.b"), rid("t.c"), rid("t.d")))

    def test_no_start_nodes_visit_nothing(self) -> None:
        found = reachable(chain(), [], direction=F)
        self.assertEqual(found.visited, ())

    def test_visited_is_sorted(self) -> None:
        found = reachable(chain(), [rid("t.d"), rid("t.a")], direction=F)
        self.assertEqual(list(found.visited), sorted(found.visited))


class TestCycles(unittest.TestCase):
    def test_a_cycle_terminates_and_visits_each_node_once(self) -> None:
        for direction in (F, V):
            found = reachable(triangle(), [rid("t.a")], direction=direction)
            self.assertEqual(found.visited, (rid("t.a"), rid("t.b"), rid("t.c")))
            self.assertEqual(len(found.via), 2)

    def test_a_self_loop_terminates(self) -> None:
        looped = graph([rnode("t.a")], [ref_edge("t.a", "t.a")])
        found = reachable(looped, [rid("t.a")], direction=F)
        self.assertEqual(found.visited, (rid("t.a"),))

    def test_two_cycles_sharing_a_node_terminate(self) -> None:
        both = graph(
            [rnode("t.a"), rnode("t.b"), rnode("t.c")],
            [
                ref_edge("t.a", "t.b"),
                ref_edge("t.b", "t.a"),
                ref_edge("t.b", "t.c"),
                ref_edge("t.c", "t.b"),
            ],
        )
        found = reachable(both, [rid("t.a")], direction=F)
        self.assertEqual(len(found.visited), 3)

    def test_the_path_in_a_cycle_is_a_simple_path(self) -> None:
        found = reachable(triangle(), [rid("t.a")], direction=F)
        path = found.path_to(rid("t.c"))
        self.assertEqual([e.target_node_id for e in path], [rid("t.b"), rid("t.c")])


class TestPaths(unittest.TestCase):
    def test_forward_path_runs_from_start_to_node(self) -> None:
        found = reachable(chain(), [rid("t.a")], direction=F)
        path = found.path_to(rid("t.c"))
        self.assertEqual(
            [(e.source_node_id, e.target_node_id) for e in path],
            [(rid("t.a"), rid("t.b")), (rid("t.b"), rid("t.c"))],
        )

    def test_reverse_path_runs_from_start_towards_the_dependents(self) -> None:
        found = reachable(chain(), [rid("t.c")], direction=V)
        path = found.path_to(rid("t.a"))
        self.assertEqual(
            [(e.source_node_id, e.target_node_id) for e in path],
            [(rid("t.b"), rid("t.c")), (rid("t.a"), rid("t.b"))],
        )

    def test_a_node_that_was_not_reached_has_no_path(self) -> None:
        found = reachable(chain(), [rid("t.a")], direction=F)
        with self.assertRaises(DependencyInputError):
            found.path_to(rid("t.d"))
        with self.assertRaises(DependencyInputError):
            found.path_to("RESOURCE:nowhere")

    def test_via_holds_edge_keys_of_edges_in_the_graph(self) -> None:
        built = chain()
        keys = {e.edge_key for e in built.edges}
        found = reachable(built, [rid("t.a")], direction=F)
        self.assertTrue(set(found.via.values()) <= keys)

    def diamond(self, reverse_input: bool = False) -> DependencyGraph:
        nodes = [rnode("t.a"), rnode("t.b"), rnode("t.c"), rnode("t.d")]
        edges = [
            ref_edge("t.a", "t.b"),
            ref_edge("t.a", "t.c"),
            ref_edge("t.b", "t.d"),
            ref_edge("t.c", "t.d"),
        ]
        if reverse_input:
            nodes, edges = nodes[::-1], edges[::-1]
        return graph(nodes, edges)

    def test_among_equal_length_paths_the_lower_first_edge_key_wins(self) -> None:
        built = self.diamond()
        to_b = next(
            e
            for e in built.edges
            if e.target_node_id == rid("t.b") and e.source_node_id == rid("t.a")
        )
        to_c = next(
            e
            for e in built.edges
            if e.target_node_id == rid("t.c") and e.source_node_id == rid("t.a")
        )
        winner = "t.b" if to_b.edge_key < to_c.edge_key else "t.c"
        found = reachable(built, [rid("t.a")], direction=F)
        path = found.path_to(rid("t.d"))
        self.assertEqual(len(path), 2)
        self.assertEqual(path[0].target_node_id, rid(winner))
        self.assertEqual(path[1].source_node_id, rid(winner))

    def test_swapping_the_input_order_changes_nothing(self) -> None:
        one = reachable(self.diamond(), [rid("t.a")], direction=F)
        two = reachable(self.diamond(reverse_input=True), [rid("t.a")], direction=F)
        self.assertEqual(one.path_to(rid("t.d")), two.path_to(rid("t.d")))
        self.assertEqual(dict(one.via), dict(two.via))
        self.assertEqual(one.visited, two.visited)

    def test_a_shuffled_graph_gives_the_same_reachability(self) -> None:
        rng = random.Random(20261028)
        base = fixture_resources(BASELINE)
        reference = build_graph(base, [], state_id=STATE, now=NOW)
        start = [rid("aws_db_instance.database")]
        expected = reachable(reference, start, direction=F)
        for _ in range(5):
            shuffled = list(base)
            rng.shuffle(shuffled)
            again = build_graph(shuffled, [], state_id=STATE, now=NOW)
            got = reachable(again, start, direction=F)
            self.assertEqual(got.visited, expected.visited)
            self.assertEqual(dict(got.via), dict(expected.via))


class TestStatuses(unittest.TestCase):
    def mixed(self) -> DependencyGraph:
        return graph(
            [rnode("t.a"), rnode("t.b"), rnode("t.c"), rnode("t.d")],
            [
                ref_edge("t.a", "t.b", status=K),
                ref_edge("t.a", "t.c", status=UC),
                ref_edge("t.a", "t.d", status=UN),
            ],
        )

    def test_uncertain_and_unsupported_edges_are_traversed_by_default(self) -> None:
        found = reachable(self.mixed(), [rid("t.a")], direction=F)
        self.assertEqual(len(found.visited), 4)

    def test_the_filter_can_exclude_statuses(self) -> None:
        only_known = reachable(
            self.mixed(), [rid("t.a")], direction=F, edge_filter=lambda e: e.status is K
        )
        self.assertEqual(only_known.visited, (rid("t.a"), rid("t.b")))
        no_unsupported = reachable(
            self.mixed(), [rid("t.a")], direction=F, edge_filter=lambda e: e.status is not UN
        )
        self.assertEqual(no_unsupported.visited, (rid("t.a"), rid("t.b"), rid("t.c")))

    def test_the_filter_sees_each_edge_object(self) -> None:
        seen: list[GraphEdge] = []

        def record(edge: GraphEdge) -> bool:
            seen.append(edge)
            return True

        reachable(self.mixed(), [rid("t.a")], direction=F, edge_filter=record)
        self.assertEqual(len(seen), 3)
        self.assertTrue(all(isinstance(e, GraphEdge) for e in seen))


class TestInputs(unittest.TestCase):
    def test_an_unknown_start_node_is_refused(self) -> None:
        with self.assertRaises(DependencyInputError):
            reachable(chain(), ["RESOURCE:nowhere"], direction=F)
        with self.assertRaises(DependencyInputError):
            reachable(chain(), [rid("t.a"), "RESOURCE:nowhere"], direction=V)

    def test_a_bare_string_is_not_a_collection_of_start_nodes(self) -> None:
        with self.assertRaises(DependencyInputError):
            reachable(chain(), rid("t.a"), direction=F)

    def test_the_direction_must_be_a_direction(self) -> None:
        with self.assertRaises(DependencyInputError):
            reachable(chain(), [rid("t.a")], direction="FORWARD")  # type: ignore[arg-type]

    def test_the_graph_is_not_changed(self) -> None:
        built = chain()
        before = built.to_dict()
        reachable(built, [rid("t.a")], direction=F)
        reachable(built, [rid("t.c")], direction=V)
        self.assertEqual(built.to_dict(), before)

    def test_repeated_calls_give_equal_results(self) -> None:
        built = triangle()
        self.assertEqual(
            reachable(built, [rid("t.a")], direction=F),
            reachable(built, [rid("t.a")], direction=F),
        )


class TestCanonicalBaseline(unittest.TestCase):
    """Reachability read off the .tf text of the canonical baseline."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.graph = build_graph(fixture_resources(BASELINE), [], state_id=STATE, now=NOW)

    def visited(self, start: str, direction: Direction, **kwargs) -> set[str]:  # type: ignore[no-untyped-def]
        found = reachable(self.graph, [rid(start)], direction=direction, **kwargs)
        return {n.removeprefix("RESOURCE:") for n in found.visited}

    def test_the_database_depends_on_its_group_the_subnet_group_the_subnets_and_the_vpc(
        self,
    ) -> None:
        self.assertEqual(
            self.visited("aws_db_instance.database", F),
            {
                "aws_db_instance.database",
                "aws_security_group.db",
                "aws_db_subnet_group.db",
                "aws_subnet.db_a",
                "aws_subnet.db_b",
                "aws_vpc.main",
            },
        )

    def test_without_the_unsupported_edges_the_subnet_group_is_not_reached(self) -> None:
        self.assertEqual(
            self.visited("aws_db_instance.database", F, edge_filter=lambda e: e.status is not UN),
            {"aws_db_instance.database", "aws_security_group.db", "aws_vpc.main"},
        )

    def test_the_instance_depends_on_its_subnet_its_group_and_the_vpc(self) -> None:
        self.assertEqual(
            self.visited("aws_instance.app", F),
            {"aws_instance.app", "aws_subnet.app", "aws_security_group.app", "aws_vpc.main"},
        )

    def test_the_database_group_affects_its_rule_and_the_database(self) -> None:
        self.assertEqual(
            self.visited("aws_security_group.db", V),
            {
                "aws_security_group.db",
                "aws_security_group_rule.app_to_db_5432",
                "aws_db_instance.database",
            },
        )

    def test_the_app_group_affects_its_three_rules_and_the_instance(self) -> None:
        self.assertEqual(
            self.visited("aws_security_group.app", V),
            {
                "aws_security_group.app",
                "aws_security_group_rule.app_ssh_public",
                "aws_security_group_rule.app_egress_all",
                "aws_security_group_rule.app_to_db_5432",
                "aws_instance.app",
            },
        )

    def test_the_vpc_affects_every_other_resource(self) -> None:
        affected = self.visited("aws_vpc.main", V)
        self.assertEqual(len(affected), 15)
        self.assertEqual(affected, {n.ref_id for n in self.graph.nodes})

    def test_the_path_from_the_rule_to_the_vpc_is_a_chain_of_edges(self) -> None:
        found = reachable(self.graph, [rid("aws_security_group_rule.app_to_db_5432")], direction=F)
        path = found.path_to(rid("aws_vpc.main"))
        self.assertEqual(len(path), 2)
        self.assertEqual(path[0].source_node_id, rid("aws_security_group_rule.app_to_db_5432"))
        self.assertEqual(path[-1].target_node_id, rid("aws_vpc.main"))
        for first, second in zip(path, path[1:], strict=False):
            self.assertEqual(first.target_node_id, second.source_node_id)


if __name__ == "__main__":
    unittest.main()
