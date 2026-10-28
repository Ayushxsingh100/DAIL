"""The four registry-v1.0 invariants as data (P4 step 2; Doc 08 §7-§8, §13; registry §2.7, §3.5,
§5.4, §6.6, §10; C-139).

Every expectation here is typed by hand from the registry text. As a third, independent source the
§2.7 lists are also read from ``docs/specs/INVARIANT_REGISTRY_v1.md`` itself, so the code, the test
and the specification cannot drift apart without a failure.
"""

from __future__ import annotations

import re
import unittest
from datetime import timedelta
from pathlib import Path

from core.dependency.build import build_graph
from core.dependency.invariants import SemanticBinding
from core.domain.enums import InvariantCategory
from core.domain.errors import DomainValidationError
from core.domain.invariant import Invariant
from core.domain.registry_v1 import registry_v1_invariants
from tests.domain_builders import at
from tests.graph_builders import BASELINE, STATE, fixture_resources

REGISTRY = Path(__file__).resolve().parents[2] / "docs" / "specs" / "INVARIANT_REGISTRY_v1.md"
NOW = at(0)

# Registry §2.7, typed by hand.
SEC_RELEVANT_UNSUPPORTED = {
    "aws_vpc_security_group_ingress_rule",
    "aws_default_security_group",
    "aws_vpc_security_group_rules_exclusive",
}
FUNC_RELEVANT_UNSUPPORTED = {
    "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule",
    "aws_default_security_group",
    "aws_network_interface",
    "aws_network_interface_attachment",
    "aws_network_interface_sg_attachment",
    "aws_network_acl",
    "aws_network_acl_rule",
    "aws_network_acl_association",
    "aws_default_network_acl",
    "aws_route",
    "aws_default_route_table",
    "aws_main_route_table_association",
    "aws_vpc_ipv4_cidr_block_association",
    "aws_vpc_peering_connection",
    "aws_ec2_transit_gateway_vpc_attachment",
    "aws_vpc_endpoint",
    "aws_vpc_security_group_rules_exclusive",
    "aws_vpc_security_group_vpc_association",
    "aws_vpn_gateway_route_propagation",
    "aws_vpc_route_server_propagation",
    "aws_default_subnet",
    "aws_default_vpc",
    "aws_vpc_peering_connection_accepter",
    "aws_vpc_peering_connection_options",
    "aws_ec2_transit_gateway_vpc_attachment_accepter",
}
# The walk policy of C-139: the relationship classes the registry footprint of INV-FUNC-001 needs.
FUNC_WALK = [
    "DB_USES_SECURITY_GROUP:FORWARD",
    "INSTANCE_IN_SUBNET:FORWARD",
    "INSTANCE_USES_SECURITY_GROUP:FORWARD",
    "REFERENCE[aws_security_group.vpc_id]:FORWARD",
    "ROUTE_TABLE_BELONGS_TO_VPC:REVERSE",
    "RULE_BELONGS_TO_SECURITY_GROUP:REVERSE",
    "SUBNET_BELONGS_TO_VPC:FORWARD",
]


def by_id(definitions: tuple[Invariant, ...]) -> dict[str, Invariant]:
    return {definition.invariant_id: definition for definition in definitions}


def build(**kwargs: str) -> dict[str, Invariant]:
    values = {"source": "aws_instance.app", "destination": "aws_db_instance.database", **kwargs}
    return by_id(registry_v1_invariants(NOW, **values))


class TestIdentities(unittest.TestCase):
    def setUp(self) -> None:
        self.definitions = build()

    def test_exactly_the_four_invariants_at_version_one(self) -> None:
        self.assertEqual(
            sorted(self.definitions), ["INV-FUNC-001", "INV-SEC-001", "INV-SEC-002", "INV-SEC-003"]
        )
        for definition in self.definitions.values():
            self.assertEqual(definition.version, 1)

    def test_the_result_is_sorted_by_id(self) -> None:
        ids = [d.invariant_id for d in registry_v1_invariants(NOW, source="a.s", destination="a.d")]
        self.assertEqual(ids, sorted(ids))

    def test_names_and_categories_follow_registry_sections_3_to_6(self) -> None:
        expected = {
            "INV-SEC-001": ("No public SSH ingress", InvariantCategory.SECURITY),
            "INV-SEC-002": ("No public PostgreSQL ingress", InvariantCategory.SECURITY),
            "INV-SEC-003": ("RDS not publicly accessible", InvariantCategory.SECURITY),
            "INV-FUNC-001": (
                "Application can reach database on TCP/5432",
                InvariantCategory.FUNCTIONAL,
            ),
        }
        for invariant_id, (name, category) in expected.items():
            with self.subTest(invariant=invariant_id):
                self.assertEqual(self.definitions[invariant_id].name, name)
                self.assertIs(self.definitions[invariant_id].category, category)

    def test_verifier_identities_follow_registry_section_10(self) -> None:
        expected = {
            "INV-SEC-001": "dail.verify.public_ingress",
            "INV-SEC-002": "dail.verify.public_ingress",
            "INV-SEC-003": "dail.verify.rds_public_flag",
            "INV-FUNC-001": "dail.verify.reachability_cfg",
        }
        for invariant_id, verifier in expected.items():
            with self.subTest(invariant=invariant_id):
                self.assertEqual(self.definitions[invariant_id].verifier_id, verifier)
                self.assertEqual(self.definitions[invariant_id].verifier_version, "1")

    def test_the_predicate_is_a_pointer_to_the_registry_not_an_executable(self) -> None:
        sections = {
            "INV-SEC-001": "§3",
            "INV-SEC-002": "§4",
            "INV-SEC-003": "§5",
            "INV-FUNC-001": "§6",
        }
        for invariant_id, section in sections.items():
            predicate = self.definitions[invariant_id].predicate
            with self.subTest(invariant=invariant_id):
                self.assertEqual(predicate["registry"], "registry-v1.0")
                self.assertEqual(predicate["section"], section)
        self.assertEqual(self.definitions["INV-SEC-001"].predicate["parameters"]["p"], 22)
        self.assertEqual(self.definitions["INV-SEC-002"].predicate["parameters"]["p"], 5432)

    def test_the_functional_predicate_names_its_bindings(self) -> None:
        parameters = self.definitions["INV-FUNC-001"].predicate["parameters"]
        self.assertEqual(parameters["S"], "aws_instance.app")
        self.assertEqual(parameters["D"], "aws_db_instance.database")
        self.assertEqual(parameters["port"], 5432)


class TestScopes(unittest.TestCase):
    def setUp(self) -> None:
        self.definitions = build()

    def test_sec_001_and_sec_002_scope_every_group_and_rule_and_the_three_unsupported_types(
        self,
    ) -> None:
        wanted = {"aws_security_group", "aws_security_group_rule", *SEC_RELEVANT_UNSUPPORTED}
        for invariant_id in ("INV-SEC-001", "INV-SEC-002"):
            scope = self.definitions[invariant_id].scope
            with self.subTest(invariant=invariant_id):
                self.assertEqual(set(scope.resource_types), wanted)
                self.assertEqual(scope.resources, ())
                self.assertEqual(scope.relationships, ())

    def test_sec_003_scopes_the_database_type_only(self) -> None:
        scope = self.definitions["INV-SEC-003"].scope
        self.assertEqual(scope.resource_types, ("aws_db_instance",))
        self.assertEqual(scope.resources, ())
        self.assertEqual(scope.relationships, ())

    def test_func_scopes_the_two_bindings_and_the_26_unsupported_types(self) -> None:
        scope = self.definitions["INV-FUNC-001"].scope
        self.assertEqual(set(scope.resources), {"aws_instance.app", "aws_db_instance.database"})
        self.assertEqual(len(FUNC_RELEVANT_UNSUPPORTED), 26)
        self.assertEqual(set(scope.resource_types), FUNC_RELEVANT_UNSUPPORTED)
        self.assertEqual(len(scope.resource_types), 26)

    def test_func_walk_policy_is_exactly_the_seven_tokens(self) -> None:
        self.assertEqual(list(self.definitions["INV-FUNC-001"].scope.relationships), FUNC_WALK)

    def test_the_walk_policy_leaves_out_what_the_registry_says_is_not_in_the_footprint(
        self,
    ) -> None:
        # registry 6.6 "Not in the footprint": associations, the internet gateway; C-15: no
        # subnet group
        tokens = " ".join(self.definitions["INV-FUNC-001"].scope.relationships)
        for relationship in ("ASSOCIATES_SUBNET", "ASSOCIATES_ROUTE_TABLE", "IGW_ATTACHED_TO_VPC"):
            self.assertNotIn(relationship, tokens)
        self.assertNotIn("DB_SUBNET_PLACEMENT", tokens)

    def test_the_security_invariants_follow_no_instance_or_database_attachment(self) -> None:
        # registry 3.5 "Not in the footprint: any instance or database security-group attachment"
        for invariant_id in ("INV-SEC-001", "INV-SEC-002", "INV-SEC-003"):
            self.assertEqual(self.definitions[invariant_id].scope.relationships, ())

    def test_scope_lists_are_sorted_and_duplicate_free(self) -> None:
        for definition in self.definitions.values():
            scope = definition.scope
            for name in ("resources", "resource_types", "relationships", "properties"):
                values = list(getattr(scope, name))
                with self.subTest(invariant=definition.invariant_id, field=name):
                    self.assertEqual(values, sorted(set(values)))

    def test_footprint_properties_are_named(self) -> None:
        sec = self.definitions["INV-SEC-001"].scope.properties
        self.assertIn("rule.security_group_id", sec)
        self.assertIn("rule.source_security_group_id", sec)
        self.assertIn("ingress.cidr_blocks", sec)
        # registry 3.5 "Not in the footprint": vpc_id, name, description, tags, egress contents
        for excluded in ("vpc_id", "name", "description", "tags"):
            self.assertNotIn(excluded, sec)
        self.assertEqual(
            self.definitions["INV-SEC-003"].scope.properties,
            ("aws_db_instance.existence", "aws_db_instance.publicly_accessible"),
        )

    def test_func_footprint_properties_include_the_endpoints_fields(self) -> None:
        props = self.definitions["INV-FUNC-001"].scope.properties
        for wanted in ("S.subnet_id", "S.vpc_security_group_ids", "D.port", "D.engine"):
            self.assertIn(wanted, props)
        # registry 6.6: publicly_accessible, tags and names are not in the footprint
        self.assertNotIn("D.publicly_accessible", props)


class TestAgainstTheRegistryFile(unittest.TestCase):
    """The §2.7 table, read from the specification file."""

    @classmethod
    def setUpClass(cls) -> None:
        text = REGISTRY.read_text(encoding="utf-8")
        start = text.index("### 2.7 Unsupported constructs")
        end = text.index("### 2.8")
        cls.rows: dict[str, set[str]] = {}
        for line in text[start:end].splitlines():
            if line.startswith("| INV-"):
                label, cell = line.split("|")[1:3]
                cls.rows[label.strip()] = set(re.findall(r"`([a-z0-9_]+)`", cell))

    def test_the_file_has_the_three_rows(self) -> None:
        self.assertEqual(
            set(self.rows), {"INV-SEC-001, INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"}
        )

    def test_the_sec_list_in_the_file_is_the_code_list(self) -> None:
        self.assertEqual(self.rows["INV-SEC-001, INV-SEC-002"], SEC_RELEVANT_UNSUPPORTED)
        scope = build()["INV-SEC-001"].scope
        self.assertEqual(
            set(scope.resource_types) - {"aws_security_group", "aws_security_group_rule"},
            self.rows["INV-SEC-001, INV-SEC-002"],
        )

    def test_the_func_list_in_the_file_is_the_code_list(self) -> None:
        self.assertEqual(self.rows["INV-FUNC-001"], FUNC_RELEVANT_UNSUPPORTED)
        self.assertEqual(
            set(build()["INV-FUNC-001"].scope.resource_types), self.rows["INV-FUNC-001"]
        )

    def test_sec_003_has_no_relevant_unsupported_type(self) -> None:
        self.assertEqual(self.rows["INV-SEC-003"], set())  # the cell says "none"


class TestOnTheCanonicalBaselineGraph(unittest.TestCase):
    """The scope edges of the definitions in a P3c graph of the canonical baseline, hand-derived."""

    @classmethod
    def setUpClass(cls) -> None:
        definitions = registry_v1_invariants(
            NOW, source="aws_instance.app", destination="aws_db_instance.database"
        )
        binding = SemanticBinding(
            "INV-FUNC-001", "aws_instance.app", "aws_db_instance.database", "TCP", 5432
        )
        cls.graph = build_graph(
            fixture_resources(BASELINE), definitions, [binding], state_id=STATE, now=NOW
        )

    def targets(self, invariant_id: str, relationship: str | None = None) -> set[str]:
        return {
            e.target_node_id.removeprefix("RESOURCE:")
            for e in self.graph.edges
            if e.source_node_id == f"INVARIANT:{invariant_id}:1"
            and (relationship is None or e.relationship.value == relationship)
        }

    def test_sec_001_and_sec_002_reach_both_groups_and_the_three_rules(self) -> None:
        expected = {
            "aws_security_group.app",
            "aws_security_group.db",
            "aws_security_group_rule.app_ssh_public",
            "aws_security_group_rule.app_egress_all",
            "aws_security_group_rule.app_to_db_5432",
        }
        self.assertEqual(self.targets("INV-SEC-001"), expected)
        self.assertEqual(self.targets("INV-SEC-002"), expected)

    def test_sec_003_reaches_the_database(self) -> None:
        self.assertEqual(self.targets("INV-SEC-003"), {"aws_db_instance.database"})

    def test_func_reaches_its_endpoints_and_the_port(self) -> None:
        self.assertEqual(
            self.targets("INV-FUNC-001", "SCOPE"), {"aws_instance.app", "aws_db_instance.database"}
        )
        self.assertEqual(self.targets("INV-FUNC-001", "SOURCE"), {"aws_instance.app"})
        self.assertEqual(self.targets("INV-FUNC-001", "DESTINATION"), {"aws_db_instance.database"})
        self.assertEqual(self.targets("INV-FUNC-001", "PROTOCOL_PORT"), {"SEMANTIC:TCP/5432"})

    def test_all_four_invariant_nodes_are_in_the_graph(self) -> None:
        ids = {n.node_id for n in self.graph.nodes if n.node_type.value == "INVARIANT"}
        self.assertEqual(
            ids,
            {
                "INVARIANT:INV-SEC-001:1",
                "INVARIANT:INV-SEC-002:1",
                "INVARIANT:INV-SEC-003:1",
                "INVARIANT:INV-FUNC-001:1",
            },
        )


class TestBuilding(unittest.TestCase):
    def test_it_is_deterministic(self) -> None:
        one = registry_v1_invariants(
            NOW, source="aws_instance.app", destination="aws_db_instance.d"
        )
        two = registry_v1_invariants(
            NOW, source="aws_instance.app", destination="aws_db_instance.d"
        )
        self.assertEqual([d.definition_hash() for d in one], [d.definition_hash() for d in two])

    def test_the_clock_is_not_part_of_the_definition(self) -> None:
        one = build()
        later = by_id(
            registry_v1_invariants(
                NOW + timedelta(days=9),
                source="aws_instance.app",
                destination="aws_db_instance.database",
            )
        )
        for invariant_id in one:
            self.assertEqual(
                one[invariant_id].definition_hash(), later[invariant_id].definition_hash()
            )
        self.assertNotEqual(one["INV-SEC-001"].created_at, later["INV-SEC-001"].created_at)

    def test_other_bindings_change_only_the_functional_invariant(self) -> None:
        base = build()
        other = build(source="aws_instance.web", destination="aws_db_instance.main")
        self.assertEqual(
            set(other["INV-FUNC-001"].scope.resources), {"aws_instance.web", "aws_db_instance.main"}
        )
        for invariant_id in ("INV-SEC-001", "INV-SEC-002", "INV-SEC-003"):
            self.assertEqual(
                base[invariant_id].definition_hash(), other[invariant_id].definition_hash()
            )
        self.assertNotEqual(
            base["INV-FUNC-001"].definition_hash(), other["INV-FUNC-001"].definition_hash()
        )

    def test_bad_bindings_are_refused(self) -> None:
        for source, destination in (
            ("", "aws_db_instance.d"),
            ("aws_instance.a", ""),
            (" aws_instance.a", "aws_db_instance.d"),
            ("aws_instance.a", "aws_instance.a"),
        ):
            with (
                self.subTest(source=source, destination=destination),
                self.assertRaises(DomainValidationError),
            ):
                registry_v1_invariants(NOW, source=source, destination=destination)

    def test_a_naive_clock_is_refused(self) -> None:
        with self.assertRaises(DomainValidationError):
            registry_v1_invariants(
                NOW.replace(tzinfo=None), source="aws_instance.a", destination="aws_db_instance.d"
            )


if __name__ == "__main__":
    unittest.main()
