"""The canonical fixtures through normalization (P3a-3 step 7; Doc 04 §16, §24; C-89).

The change classes come from each fixture's hand-written ``expected.json`` (spec-derived, C-89);
nothing is computed from the implementation. If a fixture and the normalization disagree, the
test fails and reports the address and the canonical JSON difference: the disagreement is review
material, and neither the code nor the fixture is changed to hide it.
"""

from __future__ import annotations

import dataclasses
import difflib
import unittest
from typing import Any

from core.domain.enums import ResourceSupport
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.terraform_model.config import ParseStatus, load_configuration
from core.terraform_model.hcl.ast import ScopeTraversal
from core.terraform_model.normalization import NormalizationOutcome, normalize_directory
from core.terraform_model.security_rules import index_rules, rules_of
from tests import fixture_catalog as fc
from tests.tf_builders import NOW

ROOT = fc.REPO_ROOT
OK = ParseStatus.OK
BASELINE = "fixtures/canonical_regression/baseline"
SG_CREATED = "fixtures/impact/sg_created_resource_fail_v1"
UNKNOWN_FIXTURE = "fixtures/dependency/func_unknown_dependency_unknown_v1"
UNSUPPORTED_FIXTURE = "fixtures/dependency/func_unsupported_relationship_unsupported_v1"
NINE_TYPES = {
    "aws_vpc",
    "aws_subnet",
    "aws_route_table",
    "aws_route_table_association",
    "aws_internet_gateway",
    "aws_instance",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_db_instance",
}

_CACHE: dict[tuple[str, str], NormalizationOutcome] = {}


def normalized(folder: str, variables: dict[str, object] | None = None) -> NormalizationOutcome:
    key = (folder, repr(sorted((variables or {}).items())))
    if key not in _CACHE:
        _CACHE[key] = normalize_directory(ROOT / folder, variables, now=NOW)
    return _CACHE[key]


def by_address(outcome: NormalizationOutcome) -> dict[str, Resource]:
    return {resource.address: resource for resource in outcome.resources}


def plain(mapping: Any) -> Any:
    return thaw_json(mapping)


def diff_text(parent: Resource, candidate: Resource) -> str:
    one = parent.canonical_json.replace(",", ",\n").splitlines()
    two = candidate.canonical_json.replace(",", ",\n").splitlines()
    return "\n".join(difflib.unified_diff(one, two, "parent", "candidate", lineterm="", n=1))


class TestEveryFixture(unittest.TestCase):
    def test_every_fixture_normalizes_ok(self) -> None:
        folders = fc.terraform_roots(ROOT)
        self.assertEqual(len(folders), 16)
        for folder in folders:
            with self.subTest(folder=folder):
                outcome = normalized(folder)
                self.assertEqual(outcome.status, OK, outcome.diagnostics)
                self.assertEqual(outcome.diagnostics, ())
                self.assertGreater(len(outcome.resources), 0)

    def test_all_nine_supported_types_and_the_tolerated_type_appear(self) -> None:
        supported: set[str] = set()
        tolerated = 0
        for folder in fc.terraform_roots(ROOT):
            for resource in normalized(folder).resources:
                if resource.support_status is ResourceSupport.SUPPORTED:
                    supported.add(resource.resource_type)
                if resource.resource_type == "aws_db_subnet_group":
                    self.assertEqual(resource.support_status, ResourceSupport.UNSUPPORTED)
                    self.assertTrue(plain(resource.semantic_attributes)["tolerated"])
                    tolerated += 1
        self.assertEqual(supported, NINE_TYPES)
        self.assertGreater(tolerated, 0)

    def test_nothing_is_unknown_except_what_the_fixture_leaves_open(self) -> None:
        for folder in fc.terraform_roots(ROOT):
            statuses = {r.support_status for r in normalized(folder).resources}
            with self.subTest(folder=folder):
                self.assertNotIn(ResourceSupport.UNKNOWN, statuses)

    def test_normalizing_twice_gives_identical_resources(self) -> None:
        for folder in fc.terraform_roots(ROOT):
            second = normalize_directory(ROOT / folder, None, now=NOW)
            first = normalized(folder)
            with self.subTest(folder=folder):
                self.assertEqual(first.resource_set_hash, second.resource_set_hash)
                self.assertEqual(
                    [(r.address, r.fingerprint, r.canonical_json) for r in first.resources],
                    [(r.address, r.fingerprint, r.canonical_json) for r in second.resources],
                )


class TestChangeClassesOfExpectedJson(unittest.TestCase):
    """Doc 04 §6.2: fingerprint changes correspond to relevant semantic changes."""

    def check(self, data: dict[str, Any]) -> list[str]:
        parent = by_address(normalized(data["parent"]))
        candidate = by_address(normalized(data["config"]))
        declared = data["changes"]["resources"]
        problems: list[str] = []
        for address in sorted(set(parent) | set(candidate)):
            entry = declared.get(address)
            change = entry["change"] if entry else data["changes"]["default"]
            if change == "UNCERTAIN":
                continue  # identity is P3b's
            in_parent, in_candidate = address in parent, address in candidate
            if change == "CREATED":
                if in_parent or not in_candidate:
                    problems.append(
                        f"{address}: CREATED but parent={in_parent} candidate={in_candidate}"
                    )
            elif change == "DELETED":
                if in_candidate or not in_parent:
                    problems.append(
                        f"{address}: DELETED but parent={in_parent} candidate={in_candidate}"
                    )
            elif not (in_parent and in_candidate):
                problems.append(
                    f"{address}: {change} but parent={in_parent} candidate={in_candidate}"
                )
            elif (
                change == "UNCHANGED"
                and parent[address].fingerprint != candidate[address].fingerprint
            ):
                problems.append(
                    f"{address}: UNCHANGED but the fingerprints differ\n"
                    + diff_text(parent[address], candidate[address])
                )
            elif change in ("MODIFIED", "REPLACED") and (
                parent[address].fingerprint == candidate[address].fingerprint
            ):
                problems.append(f"{address}: {change} but the fingerprints are equal")
        for address in declared:
            neither = address not in parent and address not in candidate
            if neither and declared[address]["change"] != "UNCERTAIN":
                problems.append(f"{address}: named in expected.json but in neither state")
        return problems

    def test_every_transition_and_process_fixture(self) -> None:
        checked = 0
        for fixture_id, fixture in sorted(fc.load_all().items()):
            data = fixture.data
            if data["kind"] == "baseline" or not data.get("changes") or data["parent"] is None:
                continue
            with self.subTest(fixture=fixture_id):
                problems = self.check(data)
                self.assertEqual(problems, [], "\n".join(problems))
            checked += 1
        self.assertGreaterEqual(checked, 18)

    def test_the_replaced_group_changes_and_its_dependents_do_not(self) -> None:
        parent = by_address(normalized("fixtures/canonical_regression/patch_safe"))
        candidate = by_address(normalized("fixtures/impact/sg_replacement_resource_promote_v1"))
        self.assertNotEqual(
            parent["aws_security_group.db"].fingerprint,
            candidate["aws_security_group.db"].fingerprint,
        )
        for address in ("aws_db_instance.database", "aws_security_group_rule.app_to_db_5432"):
            self.assertEqual(parent[address].fingerprint, candidate[address].fingerprint, address)


class TestBaselineRules(unittest.TestCase):
    def setUp(self) -> None:
        self.outcome = normalized(BASELINE)
        self.resources = by_address(self.outcome)

    def test_the_public_ssh_rule_is_the_rule_of_doc_04_16_1(self) -> None:
        (rule,) = rules_of(self.resources["aws_security_group_rule.app_ssh_public"])
        self.assertEqual(
            rule.core_json(),
            {
                "direction": "INGRESS",
                "protocol": "TCP",
                "from_port": 22,
                "to_port": 22,
                "ipv4_sources": ["0.0.0.0/0"],
                "ipv6_sources": [],
                "source_security_groups": [],
                "prefix_list_ids": [],
                "self": False,
                "target_security_group": "aws_security_group.app",
                "determinate": True,
                "unsupported": False,
                "problems": [],
            },
        )
        self.assertEqual(rule.origin, "RULE_RESOURCE")
        self.assertEqual(rule.target_security_group, "aws_security_group.app")

    def test_the_database_rule_has_the_app_group_as_its_source(self) -> None:
        (rule,) = rules_of(self.resources["aws_security_group_rule.app_to_db_5432"])
        self.assertEqual(rule.source_security_groups, ("aws_security_group.app",))
        self.assertEqual((rule.protocol, rule.from_port, rule.to_port), ("TCP", 5432, 5432))
        self.assertEqual(rule.target_security_group, "aws_security_group.db")
        self.assertEqual((rule.ipv4_sources, rule.ipv6_sources), ((), ()))
        self.assertTrue(rule.determinate)

    def test_the_egress_rule_of_the_app_group_is_all_to_everywhere(self) -> None:
        (rule,) = rules_of(self.resources["aws_security_group_rule.app_egress_all"])
        self.assertEqual(
            (rule.direction, rule.protocol, rule.from_port, rule.to_port, rule.ipv4_sources),
            ("EGRESS", "ALL", None, None, ("0.0.0.0/0",)),
        )

    def test_the_db_group_has_explicit_empty_egress_and_no_ingress(self) -> None:
        security = plain(self.resources["aws_security_group.db"].security_attributes)
        self.assertEqual(security["forms"], {"ingress": "absent", "egress": "explicit_empty"})
        self.assertEqual(security["inline_rules"], [])
        app = plain(self.resources["aws_security_group.app"].security_attributes)
        self.assertEqual(app["forms"], {"ingress": "absent", "egress": "absent"})

    def test_the_index_has_the_two_groups_with_their_separate_rules(self) -> None:
        index = self.outcome.rule_index
        self.assertEqual(list(index), ["aws_security_group.app", "aws_security_group.db"])
        self.assertEqual(len(index["aws_security_group.app"].ingress), 1)
        self.assertEqual(len(index["aws_security_group.app"].egress), 1)
        self.assertEqual(len(index["aws_security_group.db"].ingress), 1)
        self.assertEqual(index["aws_security_group.db"].egress, ())

    def test_the_public_ssh_predicate_is_machine_detectable_from_the_index(self) -> None:
        # Doc 04 §24: not the invariant (P5), only that the facts are there to read
        rules = self.outcome.rule_index["aws_security_group.app"].ingress
        public = [
            r for r in rules
            if r.protocol == "TCP" and r.from_port is not None and r.to_port is not None
            and r.from_port <= 22 <= r.to_port and "0.0.0.0/0" in r.ipv4_sources
        ]  # fmt: skip
        self.assertEqual(len(public), 1)

    def test_the_ec2_to_rds_topology_is_represented(self) -> None:
        instance = plain(self.resources["aws_instance.app"].security_attributes)
        self.assertEqual(
            instance["vpc_security_group_ids"],
            [{"$dail": "ref", "address": "aws_security_group.app", "attribute": "id"}],
        )
        database = plain(self.resources["aws_db_instance.database"].security_attributes)
        self.assertEqual(
            database["vpc_security_group_ids"],
            [{"$dail": "ref", "address": "aws_security_group.db", "attribute": "id"}],
        )
        self.assertIs(database["publicly_accessible"], False)

    def test_references_of_the_baseline(self) -> None:
        instance = self.resources["aws_instance.app"]
        found = {
            (r.source_attribute, r.target_address, r.resolution_status.value)
            for r in instance.references
        }
        self.assertEqual(
            found,
            {
                ("subnet_id", "aws_subnet.app", "SUPPORTED"),
                ("vpc_security_group_ids", "aws_security_group.app", "SUPPORTED"),
            },
        )
        database = self.resources["aws_db_instance.database"]
        found = {
            (r.source_attribute, r.target_address, r.resolution_status.value)
            for r in database.references
        }
        self.assertEqual(
            found,
            {
                ("db_subnet_group_name", "aws_db_subnet_group.db", "UNSUPPORTED"),
                ("vpc_security_group_ids", "aws_security_group.db", "SUPPORTED"),
            },
        )


class TestOtherFixtures(unittest.TestCase):
    def test_the_created_group_has_an_inline_ssh_rule(self) -> None:
        resources = by_address(normalized(SG_CREATED))
        bastion = resources["aws_security_group.bastion"]
        security = plain(bastion.security_attributes)
        self.assertEqual(security["forms"], {"ingress": "blocks", "egress": "explicit_empty"})
        (rule,) = rules_of(bastion)
        self.assertEqual(rule.origin, "INLINE")
        self.assertEqual(
            (rule.direction, rule.protocol, rule.from_port, rule.to_port, rule.ipv4_sources),
            ("INGRESS", "TCP", 22, 22, ("0.0.0.0/0",)),
        )
        self.assertEqual(rule.target_security_group, "aws_security_group.bastion")
        self.assertEqual(security["inline_rules"][0]["target_security_group"], "SELF")

    def test_the_inline_rule_equals_the_separate_one_of_the_baseline(self) -> None:
        (inline,) = rules_of(by_address(normalized(SG_CREATED))["aws_security_group.bastion"])
        (separate,) = rules_of(
            by_address(normalized(BASELINE))["aws_security_group_rule.app_ssh_public"]
        )
        one = inline.core_json()
        two = separate.core_json()
        one.pop("target_security_group")
        two.pop("target_security_group")
        self.assertEqual(one, two)

    def test_an_unset_variable_makes_the_rule_indeterminate(self) -> None:
        resources = by_address(normalized(UNKNOWN_FIXTURE))
        (rule,) = rules_of(resources["aws_security_group_rule.app_to_db_5432"])
        self.assertEqual(rule.source_security_groups, ())
        self.assertEqual(rule.problems, ("variable.no_value",))
        self.assertEqual((rule.determinate, rule.unsupported), (False, False))
        self.assertEqual(rule.target_security_group, "aws_security_group.db")

    def test_the_same_fixture_with_a_value_has_an_external_source(self) -> None:
        resources = by_address(normalized(UNKNOWN_FIXTURE, {"app_sg_id": "sg-0123abcd"}))
        (rule,) = rules_of(resources["aws_security_group_rule.app_to_db_5432"])
        self.assertEqual(rule.source_security_groups, ("EXTERNAL:sg-0123abcd",))
        self.assertEqual(rule.problems, ())
        self.assertTrue(rule.determinate)
        references = resources["aws_security_group_rule.app_to_db_5432"].references
        self.assertEqual(
            [(r.source_attribute, r.target_address) for r in references],
            [("security_group_id", "aws_security_group.db")],
        )

    def test_with_and_without_the_value_the_fingerprints_differ(self) -> None:
        without = by_address(normalized(UNKNOWN_FIXTURE))["aws_security_group_rule.app_to_db_5432"]
        with_value = by_address(normalized(UNKNOWN_FIXTURE, {"app_sg_id": "sg-0123abcd"}))[
            "aws_security_group_rule.app_to_db_5432"
        ]
        self.assertNotEqual(without.fingerprint, with_value.fingerprint)

    def test_the_extra_network_acl_is_kept_as_unsupported(self) -> None:
        resources = by_address(normalized(UNSUPPORTED_FIXTURE))
        acl = resources["aws_network_acl.extra"]
        self.assertEqual(acl.support_status, ResourceSupport.UNSUPPORTED)
        self.assertEqual(plain(acl.security_attributes), {})
        self.assertIn("vpc_id", acl.attributes)
        self.assertEqual(
            [(r.target_address, r.resolution_status.value) for r in acl.references],
            [("aws_vpc.main", "SUPPORTED")],
        )

    def test_the_ambiguous_fixture_has_two_instances_with_keys(self) -> None:
        resources = by_address(normalized("fixtures/identity/ambiguous_identity_uncertain_v1"))
        a = resources['aws_security_group.ops["a"]']
        self.assertEqual(plain(a.logical_identity), {"name": "ops-a", "key": "a"})
        self.assertEqual(
            plain(resources['aws_security_group.ops["b"]'].logical_identity)["key"], "b"
        )
        self.assertNotIn("aws_security_group.ops", resources)

    def test_index_rules_of_every_fixture_has_every_group(self) -> None:
        for folder in fc.terraform_roots(ROOT):
            outcome = normalized(folder)
            groups = {
                r.address for r in outcome.resources if r.resource_type == "aws_security_group"
            }
            with self.subTest(folder=folder):
                self.assertTrue(groups <= set(index_rules(outcome.resources)))


class TestNoTraversalIsLost(unittest.TestCase):
    """Every resource traversal in the raw tree has a reference (written separately from the
    implementation: a generic walk over the syntax tree)."""

    @staticmethod
    def nodes(value: Any) -> Any:
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, ScopeTraversal):
                yield item
            if dataclasses.is_dataclass(item) and not isinstance(item, type):
                stack.extend(getattr(item, f.name) for f in dataclasses.fields(item))
            elif isinstance(item, tuple | list):
                stack.extend(item)

    @staticmethod
    def keyless(address: str) -> str:
        return address.split("[", 1)[0]

    def raw_pairs(self, folder: str) -> set[tuple[str, str]]:
        parse = load_configuration(ROOT / folder)
        assert parse.configuration is not None
        parsed = parse.configuration
        declared = {f"{t}.{n}" for (t, n) in parsed.resources}
        data = {f"data.{t}.{n}" for (t, n) in parsed.data_sources}
        pairs: set[tuple[str, str]] = set()
        for (type_, name), decl in parsed.resources.items():
            for node in self.nodes(decl.block):
                root, steps = node.root, node.steps
                if root == "data" and len(steps) >= 2:
                    target = f"data.{steps[0].name}.{steps[1].name}"  # type: ignore[union-attr]
                    assert target in data
                elif steps and f"{root}.{steps[0].name}" in declared:  # type: ignore[union-attr]
                    target = f"{root}.{steps[0].name}"  # type: ignore[union-attr]
                else:
                    continue
                pairs.add((f"{type_}.{name}", target))
        return pairs

    def test_the_references_cover_the_traversals_of_every_fixture(self) -> None:
        for folder in fc.terraform_roots(ROOT):
            outcome = normalized(folder)
            found = {
                (self.keyless(r.address), self.keyless(ref.target_address))
                for r in outcome.resources
                for ref in r.references
            }
            raw = self.raw_pairs(folder)
            with self.subTest(folder=folder):
                self.assertEqual(found, raw)

    def test_the_raw_walker_finds_something(self) -> None:
        self.assertGreater(len(self.raw_pairs(BASELINE)), 15)


if __name__ == "__main__":
    unittest.main()
