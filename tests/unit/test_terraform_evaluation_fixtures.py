"""The canonical fixtures through the evaluator (P3a-2 step 6; Doc 04 §17; registry §2.2, §2.6).

Every expectation is written by hand from reading the ``.tf`` files and the registry text (the
quoted rules of the work package); none is computed by the evaluator. Instance counts come from
reading the differences between each fixture and the baseline: a fixture with one resource fewer
or more has one instance fewer or more.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.terraform_model.config import ParsedConfiguration, ParseStatus, load_configuration
from core.terraform_model.evaluation import EvaluationOutcome, evaluate_configuration
from core.terraform_model.instances import ArgumentForm
from core.terraform_model.values import (
    Known,
    Ref,
    Unknown,
    Value,
    first_problem,
    known_tuple,
)
from tests import fixture_catalog as fc

ROOT = fc.REPO_ROOT
OK = ParseStatus.OK

BASELINE = "fixtures/canonical_regression/baseline"
UNKNOWN_FIXTURE = "fixtures/dependency/func_unknown_dependency_unknown_v1"
SG_CREATED = "fixtures/impact/sg_created_resource_fail_v1"
AMBIGUOUS = "fixtures/identity/ambiguous_identity_uncertain_v1"

# Read from baseline/main.tf, sorted as strings: 15 resource blocks, none with count or for_each.
BASELINE_ADDRESSES = [
    "aws_db_instance.database",
    "aws_db_subnet_group.db",
    "aws_instance.app",
    "aws_internet_gateway.igw",
    "aws_route_table.public",
    "aws_route_table_association.app",
    "aws_security_group.app",
    "aws_security_group.db",
    "aws_security_group_rule.app_egress_all",
    "aws_security_group_rule.app_ssh_public",
    "aws_security_group_rule.app_to_db_5432",
    "aws_subnet.app",
    "aws_subnet.db_a",
    "aws_subnet.db_b",
    "aws_vpc.main",
]

# Baseline is 15. patch_regression drops app_ssh_public and app_to_db_5432 (13); patch_safe drops
# app_ssh_public (14); the unsupported-relationship fixture drops app_ssh_public and adds an
# aws_network_acl (15); ambiguous parent drops app_ssh_public and adds ops (15); ambiguous
# uncertain drops app_ssh_public and adds ops["a"] and ops["b"] (16); sg_created drops
# app_ssh_public and adds bastion (15); and so on, counted from the diffs.
EXPECTED_COUNTS = {
    "fixtures/canonical_regression/baseline": 15,
    "fixtures/canonical_regression/patch_regression": 13,
    "fixtures/canonical_regression/patch_safe": 14,
    "fixtures/dependency/func_unknown_dependency_unknown_v1": 14,
    "fixtures/dependency/func_unsupported_relationship_unsupported_v1": 15,
    "fixtures/identity/ambiguous_identity_parent_v1": 15,
    "fixtures/identity/ambiguous_identity_uncertain_v1": 16,
    "fixtures/impact/sg_created_resource_fail_v1": 15,
    "fixtures/impact/sg_replacement_resource_promote_v1": 14,
}


def parse(folder: str) -> ParsedConfiguration:
    outcome = load_configuration(ROOT / folder)
    assert outcome.status is OK, (folder, outcome.diagnostics)
    assert outcome.configuration is not None
    return outcome.configuration


def evaluate(folder: str, variables: dict[str, object] | None = None) -> EvaluationOutcome:
    return evaluate_configuration(parse(folder), variables)


def tup(*items: Value) -> Value:
    return known_tuple(items)


class TestEveryFixture(unittest.TestCase):
    def test_every_fixture_evaluates_ok_with_no_variables(self) -> None:
        folders = fc.terraform_roots(ROOT)
        self.assertEqual(len(folders), 16)
        for folder in folders:
            with self.subTest(folder=folder):
                outcome = evaluate(folder)
                self.assertEqual(outcome.status, OK, outcome.diagnostics)
                self.assertEqual(outcome.diagnostics, ())
                self.assertEqual(dict(outcome.indeterminate), {})
                self.assertEqual(outcome.moves, ())
                self.assertGreater(len(outcome.instances), 0)

    def test_no_fixture_has_a_count_or_for_each_except_the_ambiguous_one(self) -> None:
        for folder in fc.terraform_roots(ROOT):
            with self.subTest(folder=folder):
                keys = [i.key for i in evaluate(folder).instances.values()]
                expected_keys = ["a", "b"] if folder == AMBIGUOUS else []
                self.assertEqual([k for k in keys if k is not None], expected_keys)

    def test_the_number_of_instances(self) -> None:
        for folder, count in EXPECTED_COUNTS.items():
            with self.subTest(folder=folder):
                self.assertEqual(len(evaluate(folder).instances), count)

    def test_only_the_unknown_dependency_fixture_has_a_value_that_is_not_known(self) -> None:
        for folder in fc.terraform_roots(ROOT):
            problems = []
            for instance in evaluate(folder).instances.values():
                for name, argument in instance.arguments.items():
                    if argument.value is not None and first_problem(argument.value) is not None:
                        problems.append((instance.address, name))
                    for block in argument.blocks:
                        for inner_argument in block.arguments.values():
                            if inner_argument.value is not None:
                                self.assertIsNone(first_problem(inner_argument.value))
            expected = (
                [("aws_security_group_rule.app_to_db_5432", "source_security_group_id")]
                if folder == UNKNOWN_FIXTURE
                else []
            )
            with self.subTest(folder=folder):
                self.assertEqual(problems, expected)

    def test_evaluating_twice_gives_the_same_outcome(self) -> None:
        for folder in fc.terraform_roots(ROOT):
            with self.subTest(folder=folder):
                self.assertEqual(evaluate(folder), evaluate(folder))

    def test_the_hashes_follow_the_inputs(self) -> None:
        parsed = parse(BASELINE)
        outcome = evaluate_configuration(parsed)
        self.assertEqual(outcome.configuration_hash, parsed.configuration_hash)
        other = evaluate("fixtures/canonical_regression/patch_safe")
        self.assertNotEqual(outcome.configuration_hash, other.configuration_hash)
        self.assertEqual(outcome.variables_hash, other.variables_hash)  # no variables in both


class TestCanonicalBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self.outcome = evaluate(BASELINE)

    def test_the_instance_addresses(self) -> None:
        self.assertEqual(list(self.outcome.instances), BASELINE_ADDRESSES)

    def test_every_instance_is_a_resource_without_a_key(self) -> None:
        for address, instance in self.outcome.instances.items():
            self.assertEqual(
                (instance.kind, instance.key, instance.determinate), ("resource", None, True)
            )
            self.assertEqual(address, f"{instance.type}.{instance.name}")

    def test_the_database_rule_connects_the_app_group_to_the_db_group(self) -> None:
        rule = self.outcome.instances["aws_security_group_rule.app_to_db_5432"]
        self.assertEqual(
            rule.arguments["source_security_group_id"].value, Ref("aws_security_group.app", "id")
        )
        self.assertEqual(
            rule.arguments["security_group_id"].value, Ref("aws_security_group.db", "id")
        )
        self.assertEqual(rule.arguments["from_port"].value, Known(5432))
        self.assertEqual(rule.arguments["to_port"].value, Known(5432))
        self.assertEqual(rule.arguments["protocol"].value, Known("tcp"))
        self.assertEqual(rule.arguments["type"].value, Known("ingress"))

    def test_the_public_ssh_rule(self) -> None:
        rule = self.outcome.instances["aws_security_group_rule.app_ssh_public"]
        self.assertEqual(rule.arguments["cidr_blocks"].value, tup(Known("0.0.0.0/0")))
        self.assertEqual(
            (rule.arguments["from_port"].value, rule.arguments["to_port"].value),
            (Known(22), Known(22)),
        )
        self.assertEqual(
            rule.arguments["security_group_id"].value, Ref("aws_security_group.app", "id")
        )

    def test_the_db_group_has_an_explicit_empty_egress_and_no_ingress(self) -> None:
        group = self.outcome.instances["aws_security_group.db"]
        egress = group.arguments["egress"]
        self.assertEqual((egress.form, egress.value), (ArgumentForm.ATTRIBUTE, Known(())))
        self.assertNotIn("ingress", group.arguments)

    def test_the_app_group_has_neither_direction(self) -> None:
        group = self.outcome.instances["aws_security_group.app"]
        self.assertNotIn("ingress", group.arguments)
        self.assertNotIn("egress", group.arguments)

    def test_the_instance_references_its_subnet_and_group(self) -> None:
        instance = self.outcome.instances["aws_instance.app"]
        self.assertEqual(instance.arguments["subnet_id"].value, Ref("aws_subnet.app", "id"))
        self.assertEqual(
            instance.arguments["vpc_security_group_ids"].value,
            tup(Ref("aws_security_group.app", "id")),
        )
        self.assertEqual(instance.arguments["associate_public_ip_address"].value, Known(True))
        self.assertEqual(instance.arguments["instance_type"].value, Known("t3.micro"))

    def test_the_database_takes_the_name_of_its_subnet_group_as_a_value_not_a_reference(
        self,
    ) -> None:
        # registry 2.2: a reference to an argument that is itself resolved is that argument's value
        database = self.outcome.instances["aws_db_instance.database"]
        self.assertEqual(database.arguments["db_subnet_group_name"].value, Known("db"))
        self.assertEqual(
            database.arguments["vpc_security_group_ids"].value,
            tup(Ref("aws_security_group.db", "id")),
        )
        self.assertEqual(database.arguments["publicly_accessible"].value, Known(False))
        self.assertEqual(database.arguments["allocated_storage"].value, Known(20))
        self.assertEqual(database.arguments["manage_master_user_password"].value, Known(True))

    def test_the_subnet_group_lists_its_two_subnets(self) -> None:
        group = self.outcome.instances["aws_db_subnet_group.db"]
        self.assertEqual(
            group.arguments["subnet_ids"].value,
            tup(Ref("aws_subnet.db_a", "id"), Ref("aws_subnet.db_b", "id")),
        )

    def test_the_route_table_has_one_route_block(self) -> None:
        table = self.outcome.instances["aws_route_table.public"]
        route = table.arguments["route"]
        self.assertEqual(route.form, ArgumentForm.BLOCKS)
        (block,) = route.blocks
        self.assertEqual(block.arguments["cidr_block"].value, Known("0.0.0.0/0"))
        self.assertEqual(block.arguments["gateway_id"].value, Ref("aws_internet_gateway.igw", "id"))
        self.assertFalse(block.from_dynamic)

    def test_the_vpc_and_subnets(self) -> None:
        self.assertEqual(
            self.outcome.instances["aws_vpc.main"].arguments["enable_dns_hostnames"].value,
            Known(True),
        )
        subnet = self.outcome.instances["aws_subnet.db_b"]
        self.assertEqual(subnet.arguments["availability_zone"].value, Known("us-east-1b"))
        self.assertEqual(subnet.arguments["vpc_id"].value, Ref("aws_vpc.main", "id"))

    def test_the_baseline_has_no_variables_or_locals(self) -> None:
        self.assertEqual((dict(self.outcome.variables), dict(self.outcome.locals)), ({}, {}))


class TestSecurityGroupCreated(unittest.TestCase):
    def test_the_new_group_has_an_ingress_block_and_an_explicit_empty_egress(self) -> None:
        outcome = evaluate(SG_CREATED)
        self.assertIn("aws_security_group.bastion", outcome.instances)
        group = outcome.instances["aws_security_group.bastion"]
        ingress = group.arguments["ingress"]
        self.assertEqual(ingress.form, ArgumentForm.BLOCKS)
        self.assertIsNone(ingress.value)
        (block,) = ingress.blocks
        self.assertEqual(block.arguments["from_port"].value, Known(22))
        self.assertEqual(block.arguments["to_port"].value, Known(22))
        self.assertEqual(block.arguments["cidr_blocks"].value, tup(Known("0.0.0.0/0")))
        egress = group.arguments["egress"]
        self.assertEqual(
            (egress.form, egress.value, egress.blocks), (ArgumentForm.ATTRIBUTE, Known(()), ())
        )

    def test_the_other_groups_keep_their_forms(self) -> None:
        outcome = evaluate(SG_CREATED)
        app = outcome.instances["aws_security_group.app"]
        self.assertEqual(app.arguments["ingress"].form, ArgumentForm.ATTRIBUTE)  # explicit empty
        self.assertNotIn("egress", app.arguments)
        db = outcome.instances["aws_security_group.db"]
        self.assertNotIn("ingress", db.arguments)
        self.assertEqual(db.arguments["egress"].form, ArgumentForm.ATTRIBUTE)


class TestAmbiguousIdentity(unittest.TestCase):
    def test_for_each_makes_two_instances(self) -> None:
        outcome = evaluate(AMBIGUOUS)
        ops = {a: i for a, i in outcome.instances.items() if a.startswith("aws_security_group.ops")}
        self.assertEqual(list(ops), ['aws_security_group.ops["a"]', 'aws_security_group.ops["b"]'])
        self.assertEqual(ops['aws_security_group.ops["a"]'].arguments["name"].value, Known("ops-a"))
        self.assertEqual(ops['aws_security_group.ops["b"]'].arguments["name"].value, Known("ops-b"))
        self.assertEqual([i.key for i in ops.values()], ["a", "b"])
        for instance in ops.values():
            self.assertEqual(instance.arguments["ingress"].value, Known(()))
            self.assertEqual(instance.arguments["egress"].value, Known(()))
            self.assertEqual(instance.arguments["vpc_id"].value, Ref("aws_vpc.main", "id"))

    def test_there_is_no_bare_ops_instance(self) -> None:
        self.assertNotIn("aws_security_group.ops", evaluate(AMBIGUOUS).instances)

    def test_the_parent_has_the_bare_address(self) -> None:
        outcome = evaluate("fixtures/identity/ambiguous_identity_parent_v1")
        ops = outcome.instances["aws_security_group.ops"]
        self.assertEqual((ops.key, ops.arguments["name"].value), (None, Known("ops")))


class TestUnknownDependency(unittest.TestCase):
    def test_without_a_value_the_variable_is_unknown(self) -> None:
        outcome = evaluate(UNKNOWN_FIXTURE)
        rule = outcome.instances["aws_security_group_rule.app_to_db_5432"]
        self.assertEqual(
            rule.arguments["source_security_group_id"].value, Unknown("variable.no_value")
        )
        self.assertEqual(
            rule.arguments["security_group_id"].value, Ref("aws_security_group.db", "id")
        )
        self.assertEqual(dict(outcome.variables), {"app_sg_id": Unknown("variable.no_value")})
        self.assertEqual(outcome.status, OK)

    def test_with_a_value_it_is_an_external_literal_not_a_reference(self) -> None:
        outcome = evaluate(UNKNOWN_FIXTURE, {"app_sg_id": "sg-0123abcd"})
        rule = outcome.instances["aws_security_group_rule.app_to_db_5432"]
        value = rule.arguments["source_security_group_id"].value
        self.assertEqual(value, Known("sg-0123abcd"))
        self.assertNotIsInstance(value, Ref)
        self.assertEqual(dict(outcome.variables), {"app_sg_id": Known("sg-0123abcd")})

    def test_a_scenario_value_for_a_variable_the_fixture_lacks_is_unsupported(self) -> None:
        outcome = evaluate(BASELINE, {"app_sg_id": "sg-0123abcd"})
        self.assertEqual(outcome.status, ParseStatus.UNSUPPORTED)
        self.assertEqual([d.code for d in outcome.diagnostics], ["eval.undeclared_variable_value"])


class TestOtherFixtureFacts(unittest.TestCase):
    def test_the_replacement_fixture_renames_the_db_group(self) -> None:
        outcome = evaluate("fixtures/impact/sg_replacement_resource_promote_v1")
        self.assertEqual(
            outcome.instances["aws_security_group.db"].arguments["name"].value, Known("db-v2")
        )

    def test_the_unsupported_relationship_fixture_has_the_extra_acl(self) -> None:
        outcome = evaluate("fixtures/dependency/func_unsupported_relationship_unsupported_v1")
        acl = outcome.instances["aws_network_acl.extra"]
        self.assertEqual(acl.arguments["vpc_id"].value, Ref("aws_vpc.main", "id"))

    def test_the_regression_patch_has_no_database_rule(self) -> None:
        outcome = evaluate("fixtures/canonical_regression/patch_regression")
        self.assertNotIn("aws_security_group_rule.app_to_db_5432", outcome.instances)
        self.assertNotIn("aws_security_group_rule.app_ssh_public", outcome.instances)

    def test_the_safe_patch_keeps_the_database_rule_and_drops_public_ssh(self) -> None:
        outcome = evaluate("fixtures/canonical_regression/patch_safe")
        self.assertIn("aws_security_group_rule.app_to_db_5432", outcome.instances)
        self.assertNotIn("aws_security_group_rule.app_ssh_public", outcome.instances)

    def test_the_fixture_files_are_only_read(self) -> None:
        before = {p: p.read_bytes() for p in Path(ROOT / "fixtures").rglob("*") if p.is_file()}
        for folder in fc.terraform_roots(ROOT):
            evaluate(folder)
        after = {p: p.read_bytes() for p in Path(ROOT / "fixtures").rglob("*") if p.is_file()}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
