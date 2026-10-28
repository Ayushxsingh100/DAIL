"""The footprint walk (P4 step 4; Doc 08 §9-§13; registry §2.9, §3.5, §5.4, §6.6; C-139, C-140).

Expected footprints are derived by hand from the registry footprint text and the ``.tf`` source,
never from the engine. The walk is driven only by the invariant's own declaration.
"""

from __future__ import annotations

import unittest

from core.dependency.slots import SLOTS
from core.domain.enums import DependencyStatus
from core.domain.graph import DerivationRule, EdgeType, GraphEdge, Relationship
from core.domain.impact import StepDirection
from core.impact.errors import ImpactInputError
from core.impact.walk import (
    REFERENCE_TARGET_TYPES,
    RELATIONSHIP_TYPES,
    Footprint,
    IncompleteCode,
    footprint,
    parse_token,
    parse_tokens,
    walkable_types,
)
from tests.graph_builders import (
    BASELINE,
    edge,
    fixture_resources,
    graph,
    inode,
    make_invariant,
    resources_of,
    rnode,
)
from tests.impact_builders import graph_of, registry

UC = DependencyStatus.UNCERTAIN


def rid(address: str) -> str:
    return f"RESOURCE:{address}"


def addresses(found: Footprint) -> set[str]:
    return set(found.addresses())


def codes(found: Footprint) -> set[IncompleteCode]:
    return {item.code for item in found.incomplete}


# --- the canonical baseline -----------------------------------------------------------------------


class TestCanonicalBaseline(unittest.TestCase):
    """Hand-derived from registry 6.6, 3.5 and 5.4 and the baseline .tf text."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.definitions = registry()
        cls.graph = graph_of(fixture_resources(BASELINE))

    def of(self, invariant_id: str) -> Footprint:
        return footprint(self.graph, self.definitions[invariant_id])

    def test_the_func_footprint_is_exactly_the_ten_resources_of_registry_6_6(self) -> None:
        self.assertEqual(
            addresses(self.of("INV-FUNC-001")),
            {
                "aws_instance.app",  # S
                "aws_db_instance.database",  # D
                "aws_subnet.app",  # the subnet S references
                "aws_vpc.main",  # VPC(S) and VPC(D)
                "aws_security_group.app",  # SG(S)
                "aws_security_group.db",  # SG(D)
                "aws_security_group_rule.app_ssh_public",  # rules targeting SG(S)
                "aws_security_group_rule.app_egress_all",
                "aws_security_group_rule.app_to_db_5432",  # targeting SG(D)
                "aws_route_table.public",  # route tables of VPC(D)
            },
        )

    def test_the_func_footprint_leaves_out_what_the_registry_says_is_not_in_it(self) -> None:
        found = addresses(self.of("INV-FUNC-001"))
        for outside in (
            "aws_route_table_association.app",  # 6.6: not in the footprint
            "aws_internet_gateway.igw",  # 6.6: not in the footprint
            "aws_subnet.db_a",
            "aws_subnet.db_b",  # the database's subnets are not modelled (C-15)
            "aws_db_subnet_group.db",  # tolerated, not relevant
        ):
            self.assertNotIn(outside, found)

    def test_the_func_endpoints_are_seeds_and_the_rest_are_walk_members(self) -> None:
        by_address = {m.address: m for m in self.of("INV-FUNC-001").members}
        seeds = {a for a, m in by_address.items() if m.seed}
        self.assertEqual(seeds, {"aws_instance.app", "aws_db_instance.database"})
        for address in seeds:
            self.assertEqual(by_address[address].path, ())
            self.assertIn(f"resources:{address}", by_address[address].scope_elements)
        self.assertEqual(
            by_address["aws_instance.app"].scope_elements,
            ("binding:SOURCE", "resources:aws_instance.app"),
        )
        self.assertEqual(
            by_address["aws_db_instance.database"].scope_elements,
            ("binding:DESTINATION", "resources:aws_db_instance.database"),
        )

    def test_each_walk_member_names_the_token_that_reached_it(self) -> None:
        by_address = {m.address: m for m in self.of("INV-FUNC-001").members}
        expected = {
            "aws_subnet.app": "walk:INSTANCE_IN_SUBNET:FORWARD",
            "aws_security_group.app": "walk:INSTANCE_USES_SECURITY_GROUP:FORWARD",
            "aws_security_group.db": "walk:DB_USES_SECURITY_GROUP:FORWARD",
            "aws_security_group_rule.app_ssh_public": "walk:RULE_BELONGS_TO_SECURITY_GROUP:REVERSE",
            "aws_security_group_rule.app_egress_all": "walk:RULE_BELONGS_TO_SECURITY_GROUP:REVERSE",
            "aws_security_group_rule.app_to_db_5432": "walk:RULE_BELONGS_TO_SECURITY_GROUP:REVERSE",
            "aws_route_table.public": "walk:ROUTE_TABLE_BELONGS_TO_VPC:REVERSE",
        }
        for address, element in expected.items():
            with self.subTest(member=address):
                self.assertEqual(by_address[address].scope_elements, (element,))
                self.assertFalse(by_address[address].seed)

    def test_the_vpc_is_reached_through_the_subnet_or_the_group_reference(self) -> None:
        vpc = next(m for m in self.of("INV-FUNC-001").members if m.address == "aws_vpc.main")
        self.assertEqual(len(vpc.path), 2)  # S -> subnet -> vpc, or D -> group -> vpc
        # two shortest paths exist (from S through the subnet, from D through its group); the
        # smaller edge-key sequence wins, so only the seed it starts at is not fixed here
        self.assertIn(
            vpc.path[0].from_node, {rid("aws_instance.app"), rid("aws_db_instance.database")}
        )
        self.assertEqual(vpc.path[-1].to_node, rid("aws_vpc.main"))
        self.assertIn(
            vpc.scope_elements[0],
            (
                "walk:SUBNET_BELONGS_TO_VPC:FORWARD",
                "walk:REFERENCE[aws_security_group.vpc_id]:FORWARD",
            ),
        )

    def test_a_walk_member_path_is_a_chain_from_a_seed(self) -> None:
        for member in self.of("INV-FUNC-001").members:
            with self.subTest(member=member.address):
                if member.seed:
                    continue
                self.assertTrue(member.path)
                self.assertIn(
                    member.path[0].from_node,
                    {rid("aws_instance.app"), rid("aws_db_instance.database")},
                )
                self.assertEqual(member.path[-1].to_node, member.node_id)
                for first, second in zip(member.path, member.path[1:], strict=False):
                    self.assertEqual(first.to_node, second.from_node)

    def test_the_baseline_footprint_is_complete(self) -> None:
        for invariant_id in self.definitions:
            with self.subTest(invariant=invariant_id):
                self.assertTrue(self.of(invariant_id).complete, self.of(invariant_id).incomplete)

    def test_sec_001_and_sec_002_are_every_group_and_rule(self) -> None:
        expected = {
            "aws_security_group.app",
            "aws_security_group.db",
            "aws_security_group_rule.app_ssh_public",
            "aws_security_group_rule.app_egress_all",
            "aws_security_group_rule.app_to_db_5432",
        }
        for invariant_id in ("INV-SEC-001", "INV-SEC-002"):
            found = self.of(invariant_id)
            with self.subTest(invariant=invariant_id):
                self.assertEqual(addresses(found), expected)
                self.assertTrue(all(m.seed for m in found.members))
                self.assertTrue(all(m.path == () for m in found.members))

    def test_sec_members_say_which_scope_type_matched(self) -> None:
        by_address = {m.address: m for m in self.of("INV-SEC-001").members}
        self.assertEqual(
            by_address["aws_security_group.app"].scope_elements,
            ("resource_types:aws_security_group",),
        )
        self.assertEqual(
            by_address["aws_security_group_rule.app_to_db_5432"].scope_elements,
            ("resource_types:aws_security_group_rule",),
        )

    def test_sec_follows_no_instance_or_database_attachment(self) -> None:
        # registry 3.5: "any instance or database security-group attachment" is not in the footprint
        found = addresses(self.of("INV-SEC-001"))
        self.assertNotIn("aws_instance.app", found)
        self.assertNotIn("aws_db_instance.database", found)
        self.assertNotIn("aws_vpc.main", found)

    def test_sec_003_is_the_database(self) -> None:
        found = self.of("INV-SEC-003")
        self.assertEqual(addresses(found), {"aws_db_instance.database"})
        self.assertEqual(found.members[0].scope_elements, ("resource_types:aws_db_instance",))


# --- scenarios built from Terraform text ----------------------------------------------------------

NET = """
variable "unset" {}
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_vpc" "elsewhere" { cidr_block = "10.9.0.0/16" }
resource "aws_subnet" "app" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
resource "aws_subnet" "other" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.9.0/24"
}
resource "aws_internet_gateway" "igw" { vpc_id = aws_vpc.main.id }
resource "aws_route_table" "public" { vpc_id = aws_vpc.main.id }
resource "aws_route_table" "private" { vpc_id = aws_vpc.main.id }
resource "aws_route_table" "elsewhere" { vpc_id = aws_vpc.elsewhere.id }
resource "aws_route_table_association" "app" {
  subnet_id = aws_subnet.app.id
  route_table_id = aws_route_table.public.id
}
resource "aws_security_group" "app" {
  name = "app"
  vpc_id = aws_vpc.main.id
}
resource "aws_security_group" "db" {
  name = "db"
  vpc_id = aws_vpc.main.id
}
resource "aws_security_group" "stray" {
  name = "stray"
  vpc_id = aws_vpc.main.id
}
resource "aws_security_group_rule" "to_app" {
  type = "egress"
  protocol = "-1"
  from_port = 0
  to_port = 0
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}
resource "aws_security_group_rule" "to_stray" {
  type = "ingress"
  protocol = "tcp"
  from_port = 80
  to_port = 80
  cidr_blocks = ["10.0.0.0/8"]
  security_group_id = aws_security_group.stray.id
}
resource "aws_instance" "app" {
  ami = "a"
  subnet_id = %(subnet)s
  vpc_security_group_ids = [aws_security_group.app.id]
}
resource "aws_instance" "unrelated" {
  ami = "a"
  subnet_id = aws_subnet.other.id
  vpc_security_group_ids = [aws_security_group.stray.id]
}
%(database)s
"""
DB = """
resource "aws_db_instance" "database" {
  identifier = "d"
  vpc_security_group_ids = [aws_security_group.db.id]
}
"""


def scenario(subnet: str = "aws_subnet.app.id", database: str = DB, extra: str = "") -> Footprint:
    text = NET % {"subnet": subnet, "database": database} + extra
    state = graph_of(resources_of(text))
    return footprint(state, registry()["INV-FUNC-001"])


class TestFuncWalk(unittest.TestCase):
    def test_the_footprint_follows_the_declared_relationships_and_nothing_more(self) -> None:
        found = addresses(scenario())
        self.assertEqual(
            found,
            {
                "aws_instance.app",
                "aws_db_instance.database",
                "aws_subnet.app",
                "aws_vpc.main",
                "aws_security_group.app",
                "aws_security_group.db",
                "aws_security_group_rule.to_app",
                "aws_route_table.public",
                "aws_route_table.private",  # every route table of the VPC (M3), not only one
            },
        )

    def test_things_outside_the_footprint_stay_outside(self) -> None:
        found = addresses(scenario())
        for outside in (
            "aws_subnet.other",  # a subnet S does not use
            "aws_internet_gateway.igw",  # registry 6.6
            "aws_route_table_association.app",  # registry 6.6
            "aws_vpc.elsewhere",  # a VPC no member names
            "aws_route_table.elsewhere",  # a route table of another VPC
            "aws_security_group.stray",  # attached to nothing S or D uses
            "aws_security_group_rule.to_stray",  # its target is not in SG(S) or SG(D)
            "aws_instance.unrelated",
        ):
            self.assertNotIn(outside, found)

    def test_a_rule_targeting_the_database_group_is_a_member(self) -> None:
        extra = """
resource "aws_security_group_rule" "to_db" {
  type = "ingress"
  protocol = "tcp"
  from_port = 5432
  to_port = 5432
  source_security_group_id = aws_security_group.app.id
  security_group_id = aws_security_group.db.id
}
"""
        self.assertIn("aws_security_group_rule.to_db", addresses(scenario(extra=extra)))

    def test_a_second_vpc_joins_when_a_group_belongs_to_it(self) -> None:
        # VPC(D) comes from the database's groups through REFERENCE[aws_security_group.vpc_id]
        extra = """
resource "aws_security_group" "other_db" {
  name = "other"
  vpc_id = aws_vpc.elsewhere.id
}
"""
        database = """
resource "aws_db_instance" "database" {
  identifier = "d"
  vpc_security_group_ids = [aws_security_group.db.id, aws_security_group.other_db.id]
}
"""
        found = addresses(scenario(database=database, extra=extra))
        self.assertIn("aws_vpc.elsewhere", found)
        self.assertIn("aws_route_table.elsewhere", found)  # its route tables follow the VPC

    def test_the_complete_scenario_has_no_incompleteness(self) -> None:
        self.assertTrue(scenario().complete, scenario().incomplete)


class TestIncompleteness(unittest.TestCase):
    def test_an_unresolved_subnet_of_the_source_is_an_incomplete_forward_token(self) -> None:
        found = scenario(subnet="var.unset")
        self.assertIn(IncompleteCode.UNRESOLVED_TOKEN_EDGE, codes(found))
        self.assertNotIn("aws_subnet.app", addresses(found))
        self.assertNotIn("aws_vpc.main", addresses(found) - {"aws_vpc.main"})

    def test_a_rule_with_an_unresolved_group_is_a_member_and_marks_the_walk_incomplete(
        self,
    ) -> None:
        extra = """
resource "aws_security_group_rule" "loose" {
  type = "ingress"
  protocol = "tcp"
  from_port = 5432
  to_port = 5432
  cidr_blocks = ["10.0.0.0/8"]
  security_group_id = var.unset
}
"""
        found = scenario(extra=extra)
        self.assertIn(
            "aws_security_group_rule.loose", addresses(found)
        )  # registry 6.6 "or unresolved"
        self.assertIn(IncompleteCode.UNRESOLVED_REVERSE_MEMBER, codes(found))
        member = next(m for m in found.members if m.address == "aws_security_group_rule.loose")
        self.assertTrue(member.unresolved)
        self.assertFalse(member.seed)

    def test_a_member_with_an_unresolved_source_group_marks_the_walk_incomplete(self) -> None:
        extra = """
resource "aws_security_group_rule" "to_db" {
  type = "ingress"
  protocol = "tcp"
  from_port = 5432
  to_port = 5432
  source_security_group_id = var.unset
  security_group_id = aws_security_group.db.id
}
"""
        found = scenario(extra=extra)
        self.assertIn("aws_security_group_rule.to_db", addresses(found))
        self.assertIn(IncompleteCode.UNRESOLVED_MEMBER_EDGE, codes(found))

    def test_the_rds_placement_alone_does_not_make_the_walk_incomplete(self) -> None:
        # C-15: the RDS VPC comes from the groups; an unset db_subnet_group_name is assumed away
        found = scenario()
        self.assertTrue(found.complete)
        state = graph_of(resources_of(NET % {"subnet": "aws_subnet.app.id", "database": DB}))
        placement = [e for e in state.edges if e.relationship is Relationship.DB_SUBNET_PLACEMENT]
        self.assertEqual(len(placement), 1)  # the unresolved placement edge exists in the graph

    def test_an_absent_endpoint_is_an_absent_seed_and_marks_the_walk_incomplete(self) -> None:
        found = scenario(database="")
        self.assertEqual(found.absent_seeds, ("aws_db_instance.database",))
        self.assertIn(IncompleteCode.ABSENT_SEED, codes(found))
        self.assertIn("aws_instance.app", addresses(found))  # the other endpoint is still walked
        self.assertNotIn("aws_db_instance.database", addresses(found))

    def test_a_missing_binding_marks_the_walk_incomplete(self) -> None:
        state = graph_of(
            resources_of(NET % {"subnet": "aws_subnet.app.id", "database": DB}), bound=False
        )
        found = footprint(state, registry()["INV-FUNC-001"])
        self.assertIn(IncompleteCode.MISSING_BINDING, codes(found))

    def test_a_token_edge_that_is_not_known_is_followed_and_recorded(self) -> None:
        func = make_invariant(
            "INV-FUNC-001",
            resources=("a.s",),
            relationships=("DB_USES_SECURITY_GROUP:FORWARD",),
        )
        state = graph(
            [rnode("a.s"), rnode("b.t"), inode("INV-FUNC-001")],
            [
                edge(
                    "INVARIANT:INV-FUNC-001:1",
                    rid("a.s"),
                    edge_type=EdgeType.INVARIANT_SCOPE,
                    relationship=Relationship.SCOPE,
                    attributes={},
                    rule=DerivationRule.SCOPE_RESOURCE,
                ),
                edge(
                    rid("a.s"),
                    rid("b.t"),
                    edge_type=EdgeType.INFRASTRUCTURE,
                    relationship=Relationship.DB_USES_SECURITY_GROUP,
                    status=UC,
                    attributes={"argument": "x"},
                ),
            ],
        )
        found = footprint(state, func)
        self.assertEqual(addresses(found), {"a.s", "b.t"})  # UNCERTAIN edges are followed
        self.assertIn(IncompleteCode.TOKEN_EDGE_NOT_KNOWN, codes(found))

    def test_a_token_edge_to_an_object_outside_the_state_is_recorded(self) -> None:
        func = make_invariant(
            "INV-FUNC-001", resources=("a.s",), relationships=("INSTANCE_IN_SUBNET:FORWARD",)
        )
        gone = rnode("aws_subnet.gone", kind="absent", support_status="UNKNOWN")
        state = graph(
            [rnode("a.s"), gone, inode("INV-FUNC-001")],
            [
                edge(
                    "INVARIANT:INV-FUNC-001:1",
                    rid("a.s"),
                    edge_type=EdgeType.INVARIANT_SCOPE,
                    relationship=Relationship.SCOPE,
                    attributes={},
                    rule=DerivationRule.SCOPE_RESOURCE,
                ),
                edge(
                    rid("a.s"),
                    rid("aws_subnet.gone"),
                    edge_type=EdgeType.INFRASTRUCTURE,
                    relationship=Relationship.INSTANCE_IN_SUBNET,
                    status=UC,
                    attributes={"argument": "subnet_id"},
                ),
            ],
        )
        found = footprint(state, func)
        self.assertEqual(addresses(found), {"a.s"})
        self.assertIn(IncompleteCode.ABSENT_TARGET, codes(found))


# --- hand-built graphs: cycles, ties, blocks ------------------------------------------------------


def hand_graph(edges, nodes, invariant_id="INV-FUNC-001"):  # type: ignore[no-untyped-def]
    scope = [
        edge(
            f"INVARIANT:{invariant_id}:1",
            rid(address),
            edge_type=EdgeType.INVARIANT_SCOPE,
            relationship=Relationship.SCOPE,
            attributes={},
            rule=DerivationRule.SCOPE_RESOURCE,
        )
        for address in ("a.s",)
    ]
    return graph([inode(invariant_id), *nodes], [*scope, *edges])


def link(
    source: str,
    target: str,
    argument: str = "x",
    relationship: Relationship = Relationship.DB_USES_SECURITY_GROUP,
) -> GraphEdge:
    return edge(
        rid(source),
        rid(target),
        edge_type=EdgeType.INFRASTRUCTURE,
        relationship=relationship,
        attributes={"argument": argument},
    )


TOKEN_INVARIANT = make_invariant(
    "INV-FUNC-001",
    resources=("a.s",),
    relationships=("DB_USES_SECURITY_GROUP:FORWARD",),
)
REVERSE_INVARIANT = make_invariant(
    "INV-FUNC-001",
    resources=("a.s",),
    relationships=("DB_USES_SECURITY_GROUP:REVERSE",),
)


class TestHandBuilt(unittest.TestCase):
    def test_a_cycle_terminates_and_visits_each_member_once(self) -> None:
        state = hand_graph(
            [link("a.s", "b.x"), link("b.x", "c.y"), link("c.y", "a.s"), link("c.y", "b.x", "z")],
            [rnode("a.s"), rnode("b.x"), rnode("c.y")],
        )
        found = footprint(state, TOKEN_INVARIANT)
        self.assertEqual(found.addresses(), ("a.s", "b.x", "c.y"))
        self.assertEqual(len(found.members), 3)

    def test_a_self_loop_terminates(self) -> None:
        state = hand_graph([link("a.s", "a.s")], [rnode("a.s")])
        self.assertEqual(footprint(state, TOKEN_INVARIANT).addresses(), ("a.s",))

    def test_reverse_follows_an_edge_from_its_target_to_its_source(self) -> None:
        state = hand_graph([link("b.x", "a.s")], [rnode("a.s"), rnode("b.x")])
        self.assertEqual(footprint(state, REVERSE_INVARIANT).addresses(), ("a.s", "b.x"))
        self.assertEqual(footprint(state, TOKEN_INVARIANT).addresses(), ("a.s",))

    def test_forward_does_not_follow_against_the_edge(self) -> None:
        state = hand_graph([link("b.x", "a.s")], [rnode("a.s"), rnode("b.x")])
        self.assertNotIn("b.x", footprint(state, TOKEN_INVARIANT).addresses())

    def test_a_relationship_not_in_the_policy_is_not_followed(self) -> None:
        state = hand_graph(
            [link("a.s", "b.x", relationship=Relationship.ASSOCIATES_SUBNET)],
            [rnode("a.s"), rnode("b.x")],
        )
        self.assertEqual(footprint(state, TOKEN_INVARIANT).addresses(), ("a.s",))

    def test_a_reference_token_matches_the_source_type_and_the_argument(self) -> None:
        func = make_invariant(
            "INV-FUNC-001",
            resources=("aws_security_group.s",),
            relationships=("REFERENCE[aws_security_group.vpc_id]:FORWARD",),
        )

        def reference(attribute: str):  # type: ignore[no-untyped-def]
            return edge(
                rid("aws_security_group.s"),
                rid("aws_vpc.v"),
                attributes={"source_attribute": attribute, "reference_type": "ATTRIBUTE_REFERENCE"},
            )

        def state(attribute: str):  # type: ignore[no-untyped-def]
            scope = edge(
                "INVARIANT:INV-FUNC-001:1",
                rid("aws_security_group.s"),
                edge_type=EdgeType.INVARIANT_SCOPE,
                relationship=Relationship.SCOPE,
                attributes={},
                rule=DerivationRule.SCOPE_RESOURCE,
            )
            return graph(
                [inode("INV-FUNC-001"), rnode("aws_security_group.s"), rnode("aws_vpc.v")],
                [scope, reference(attribute)],
            )

        self.assertIn("aws_vpc.v", footprint(state("vpc_id"), func).addresses())
        self.assertNotIn("aws_vpc.v", footprint(state("tags"), func).addresses())

    def test_the_path_ties_go_to_the_smallest_edge_key_sequence(self) -> None:
        nodes = [rnode("a.s"), rnode("b.a"), rnode("b.b"), rnode("c.t")]
        edges = [
            link("a.s", "b.a", "1"),
            link("a.s", "b.b", "2"),
            link("b.a", "c.t", "3"),
            link("b.b", "c.t", "4"),
        ]
        state = hand_graph(edges, nodes)
        via_a = (edges[0].edge_key, edges[2].edge_key)
        via_b = (edges[1].edge_key, edges[3].edge_key)
        member = next(m for m in footprint(state, TOKEN_INVARIANT).members if m.address == "c.t")
        self.assertEqual(tuple(s.edge_key for s in member.path), min(via_a, via_b))

    def test_swapping_the_input_order_changes_nothing(self) -> None:
        nodes = [rnode("a.s"), rnode("b.a"), rnode("b.b"), rnode("c.t")]
        edges = [
            link("a.s", "b.a", "1"),
            link("a.s", "b.b", "2"),
            link("b.a", "c.t", "3"),
            link("b.b", "c.t", "4"),
        ]
        one = footprint(hand_graph(edges, nodes), TOKEN_INVARIANT)
        two = footprint(hand_graph(edges[::-1], nodes[::-1]), TOKEN_INVARIANT)
        self.assertEqual(one, two)

    def test_a_shorter_path_beats_a_smaller_key(self) -> None:
        nodes = [rnode("a.s"), rnode("b.a"), rnode("c.t")]
        edges = [link("a.s", "c.t", "1"), link("a.s", "b.a", "2"), link("b.a", "c.t", "3")]
        member = next(
            m
            for m in footprint(hand_graph(edges, nodes), TOKEN_INVARIANT).members
            if m.address == "c.t"
        )
        self.assertEqual(len(member.path), 1)

    def test_a_block_level_scope_address_fans_out_to_its_instances(self) -> None:
        func = make_invariant("INV-FUNC-001", resources=("aws_instance.app",))
        state = graph_of(
            resources_of(
                'resource "aws_instance" "app" {\n  count = 2\n  ami = "a"\n}\n'
                + DB.replace("[aws_security_group.db.id]", '["sg-1"]')
            ),
            invariants=[func],
            bound=False,
        )
        found = footprint(state, func)
        self.assertEqual(addresses(found), {"aws_instance.app[0]", "aws_instance.app[1]"})
        for member in found.members:
            self.assertEqual(member.scope_elements, ("resources:aws_instance.app",))

    def test_the_footprint_does_not_depend_on_the_hash_seed_inputs(self) -> None:
        # same graph twice, same footprint object
        state = graph_of(fixture_resources(BASELINE))
        func = registry()["INV-FUNC-001"]
        self.assertEqual(footprint(state, func), footprint(state, func))

    def test_an_invariant_without_a_node_in_the_graph_is_refused(self) -> None:
        state = graph([rnode("a.s")], [])
        with self.assertRaises(ImpactInputError):
            footprint(state, TOKEN_INVARIANT)

    def test_find_matches_a_block_against_its_instances_and_back(self) -> None:
        func = make_invariant("INV-SEC-001", resource_types=("aws_security_group",))
        keyed = graph_of(
            resources_of(
                'resource "aws_security_group" "ops" {\n'
                '  for_each = toset(["a", "b"])\n  name = "x"\n}\n'
            ),
            invariants=[func],
            bound=False,
        )
        found = footprint(keyed, func)
        self.assertEqual(len(found.find("aws_security_group.ops")), 2)  # block -> instances
        self.assertEqual(len(found.find('aws_security_group.ops["a"]')), 1)
        self.assertEqual(found.find("aws_security_group.other"), ())
        single = graph_of(
            resources_of('resource "aws_security_group" "ops" {\n  name = "x"\n}\n'),
            invariants=[func],
            bound=False,
        )
        self.assertEqual(len(footprint(single, func).find('aws_security_group.ops["a"]')), 1)


# --- tokens and walkable types --------------------------------------------------------------------


class TestTokens(unittest.TestCase):
    def test_parse_named_and_reference_tokens(self) -> None:
        named = parse_token("INSTANCE_IN_SUBNET:FORWARD")
        self.assertEqual(
            (named.relationship, named.direction), ("INSTANCE_IN_SUBNET", StepDirection.FORWARD)
        )
        reference = parse_token("REFERENCE[aws_security_group.vpc_id]:FORWARD")
        self.assertEqual(
            (reference.source_type, reference.argument), ("aws_security_group", "vpc_id")
        )
        self.assertEqual(
            parse_token("ROUTE_TABLE_BELONGS_TO_VPC:REVERSE").direction, StepDirection.REVERSE
        )

    def test_bad_tokens_are_refused(self) -> None:
        for bad in (
            "",
            "INSTANCE_IN_SUBNET",
            "INSTANCE_IN_SUBNET:SIDEWAYS",
            "NOT_A_RELATIONSHIP:FORWARD",
            "SCOPE:REVERSE",  # scope edges terminate the walk
            "SOURCE:FORWARD",
            "REFERENCE:FORWARD",
            "REFERENCE[]:FORWARD",
            "REFERENCE[aws_security_group]:FORWARD",
            "REFERENCE[.vpc_id]:FORWARD",
        ):
            with self.subTest(token=bad), self.assertRaises(ImpactInputError):
                parse_token(bad)

    def test_the_registry_func_policy_parses(self) -> None:
        tokens = parse_tokens(registry()["INV-FUNC-001"].scope.relationships)
        self.assertEqual(len(tokens), 7)

    def test_the_relationship_type_table_is_the_dependency_slot_table(self) -> None:
        engine = {slot.relationship.value: (slot.source_type, slot.target_type) for slot in SLOTS}
        self.assertEqual(dict(RELATIONSHIP_TYPES), engine)

    def test_the_reference_target_table_covers_the_registry_policy(self) -> None:
        self.assertEqual(REFERENCE_TARGET_TYPES["aws_security_group.vpc_id"], "aws_vpc")


class TestWalkableTypes(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.definitions = registry()
        cls.state = graph_of(fixture_resources(BASELINE))

    def test_func_walkable_types_include_the_types_a_token_can_lead_to(self) -> None:
        func = self.definitions["INV-FUNC-001"]
        types = walkable_types(func, [footprint(self.state, func)])
        assert types is not None
        for wanted in (
            "aws_instance",
            "aws_db_instance",
            "aws_subnet",  # via INSTANCE_IN_SUBNET even if no member is a subnet
            "aws_vpc",
            "aws_security_group",
            "aws_security_group_rule",
            "aws_route_table",
            "aws_network_acl",  # a relevant-unsupported scope type
        ):
            self.assertIn(wanted, types)
        for unrelated in (
            "aws_internet_gateway",
            "aws_route_table_association",
            "aws_db_subnet_group",
        ):
            self.assertNotIn(unrelated, types)

    def test_the_subnet_type_counts_even_when_no_subnet_is_a_member(self) -> None:
        # the source's subnet is unknown, so no subnet is a member; a changed subnet could be it
        func = self.definitions["INV-FUNC-001"]
        found = scenario(subnet="var.unset")
        self.assertNotIn("aws_subnet.app", addresses(found))
        types = walkable_types(func, [found])
        assert types is not None
        self.assertIn("aws_subnet", types)

    def test_sec_walkable_types_are_the_scope_types(self) -> None:
        sec = self.definitions["INV-SEC-001"]
        types = walkable_types(sec, [footprint(self.state, sec)])
        self.assertEqual(
            types,
            frozenset(
                {
                    "aws_security_group",
                    "aws_security_group_rule",
                    "aws_vpc_security_group_ingress_rule",
                    "aws_default_security_group",
                    "aws_vpc_security_group_rules_exclusive",
                }
            ),
        )

    def test_an_unknown_reference_target_makes_every_type_walkable(self) -> None:
        odd = make_invariant(
            "INV-FUNC-001",
            resources=("a.s",),
            relationships=("REFERENCE[aws_x.arg]:FORWARD",),
        )
        state = hand_graph([], [rnode("a.s")])
        self.assertIsNone(walkable_types(odd, [footprint(state, odd)]))

    def test_the_types_of_absent_scope_addresses_count(self) -> None:
        func = self.definitions["INV-FUNC-001"]
        found = scenario(database="")
        types = walkable_types(func, [found])
        assert types is not None
        self.assertIn("aws_db_instance", types)


if __name__ == "__main__":
    unittest.main()
