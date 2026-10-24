"""The 20 canonical fixtures through the configuration loader (P3a-1 step 5; Doc 04 §15; C-86).

Every fixture directory named by ``tests/fixture_catalog.py`` loads with status OK and no
diagnostics. The expectations below are hand-listed from reading the ``.tf`` files (``grep`` counts
and the files themselves); none is computed from the loader's output.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.terraform_model.config import (
    PARSER_VERSION,
    ParsedConfiguration,
    ParseOutcome,
    ParseStatus,
    load_configuration,
)
from core.terraform_model.hcl.ast import (
    Attribute,
    Block,
    FunctionCall,
    Literal,
    LiteralKind,
    ScopeTraversal,
    Template,
    TemplateInterpolation,
    TemplateLiteral,
    Tuple,
)
from tests import fixture_catalog as fc

ROOT = fc.REPO_ROOT

# Number of `resource` blocks in each fixture directory (grep -c '^resource ' main.tf).
RESOURCE_COUNTS = {
    "fixtures/canonical_regression/baseline": 15,
    "fixtures/canonical_regression/patch_regression": 13,
    "fixtures/canonical_regression/patch_safe": 14,
    "fixtures/dependency/func_unknown_dependency_unknown_v1": 14,
    "fixtures/dependency/func_unsupported_relationship_unsupported_v1": 15,
    "fixtures/identity/ambiguous_identity_parent_v1": 15,
    "fixtures/identity/ambiguous_identity_uncertain_v1": 15,
    "fixtures/impact/rds_deleted_dependency_fail_v1": 12,
    "fixtures/impact/sg_created_resource_fail_v1": 15,
    "fixtures/impact/sg_replacement_resource_promote_v1": 14,
    "fixtures/verification/ec2_rds_5432_break_fail_v1": 13,
    "fixtures/verification/ec2_rds_5432_pass_v1": 14,
    "fixtures/verification/rds_publicly_accessible_fail_v1": 14,
    "fixtures/verification/sg_private_postgres_pass_v1": 14,
    "fixtures/verification/sg_private_ssh_pass_v1": 15,
    "fixtures/verification/sg_public_postgres_fail_v1": 14,
}

# The canonical baseline, read from fixtures/canonical_regression/baseline/main.tf.
BASELINE_ADDRESSES = {
    ("aws_vpc", "main"),
    ("aws_subnet", "app"),
    ("aws_subnet", "db_a"),
    ("aws_subnet", "db_b"),
    ("aws_internet_gateway", "igw"),
    ("aws_route_table", "public"),
    ("aws_route_table_association", "app"),
    ("aws_security_group", "app"),
    ("aws_security_group", "db"),
    ("aws_security_group_rule", "app_ssh_public"),
    ("aws_security_group_rule", "app_egress_all"),
    ("aws_security_group_rule", "app_to_db_5432"),
    ("aws_instance", "app"),
    ("aws_db_subnet_group", "db"),
    ("aws_db_instance", "database"),
}


def load(folder: str) -> ParseOutcome:
    return load_configuration(ROOT / folder)


def config_of(folder: str) -> ParsedConfiguration:
    outcome = load(folder)
    assert outcome.status is ParseStatus.OK, outcome.diagnostics
    assert outcome.configuration is not None
    return outcome.configuration


def attribute_names(items: tuple[Attribute | Block, ...]) -> list[str]:
    return [item.name for item in items if isinstance(item, Attribute)]


def block_types(items: tuple[Attribute | Block, ...]) -> list[str]:
    return [item.type for item in items if isinstance(item, Block)]


class TestEveryFixtureLoads(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = fc.load_all()

    def folders(self) -> set[str]:
        found: set[str] = set()
        for fixture in self.fixtures.values():
            found.add(fixture.data["config"])
            if fixture.data["parent"] is not None:
                found.add(fixture.data["parent"])
        return found

    def test_the_catalog_has_twenty_fixtures_over_sixteen_configuration_folders(self) -> None:
        self.assertEqual(len(self.fixtures), 20)
        self.assertEqual(self.folders(), set(RESOURCE_COUNTS))

    def test_every_fixture_config_and_parent_loads_ok_without_diagnostics(self) -> None:
        for fixture in self.fixtures.values():
            for role in ("config", "parent"):
                folder = fixture.data[role]
                if folder is None:
                    continue
                with self.subTest(fixture=fixture.fixture_id, role=role):
                    outcome = load(folder)
                    self.assertEqual(outcome.status, ParseStatus.OK, outcome.diagnostics)
                    self.assertEqual(outcome.diagnostics, ())
                    self.assertIsNotNone(outcome.configuration)
                    self.assertEqual(outcome.parser_version, PARSER_VERSION)

    def test_each_folder_has_exactly_main_and_versions(self) -> None:
        for folder in RESOURCE_COUNTS:
            with self.subTest(folder=folder):
                self.assertEqual(set(config_of(folder).files), {"main.tf", "versions.tf"})
                # Local artifacts of `terraform init` (.terraform/, .terraform.lock.hcl) may sit
                # beside the files and are not Terraform source.
                self.assertEqual(
                    {path.name for path in (ROOT / folder).iterdir() if path.suffix == ".tf"},
                    {"main.tf", "versions.tf"},
                )
                self.assertTrue((ROOT / folder / "expected.json").is_file())

    def test_resource_counts(self) -> None:
        for folder, count in RESOURCE_COUNTS.items():
            with self.subTest(folder=folder):
                self.assertEqual(len(config_of(folder).resources), count)

    def test_no_provider_blocks_no_data_sources_no_modules_no_moved(self) -> None:
        # C-86: no provider block anywhere before P9; the fixtures are plain resource blocks.
        for folder in RESOURCE_COUNTS:
            with self.subTest(folder=folder):
                config = config_of(folder)
                self.assertEqual(config.providers, ())
                self.assertEqual(len(config.data_sources), 0)
                self.assertEqual(len(config.modules), 0)
                self.assertEqual(config.moved, ())
                self.assertEqual(len(config.locals), 0)
                self.assertEqual(len(config.outputs), 0)
                self.assertEqual(config.other_blocks, ())

    def test_versions_tf_is_one_terraform_block_with_required_providers(self) -> None:
        for folder in RESOURCE_COUNTS:
            with self.subTest(folder=folder):
                (terraform,) = config_of(folder).terraform_blocks
                self.assertEqual(terraform.file, "versions.tf")
                items = terraform.block.body.items
                self.assertEqual(attribute_names(items), ["required_version"])
                self.assertEqual(block_types(items), ["required_providers"])

    def test_no_provisioners_so_no_flagged_constructs(self) -> None:
        for folder in RESOURCE_COUNTS:
            with self.subTest(folder=folder):
                for resource in config_of(folder).resources.values():
                    self.assertEqual(resource.provisioners, ())

    def test_loading_is_stable_across_runs(self) -> None:
        for folder in RESOURCE_COUNTS:
            with self.subTest(folder=folder):
                first, second = load(folder), load(folder)
                self.assertEqual(first, second)
                assert first.configuration is not None and second.configuration is not None
                self.assertEqual(
                    first.configuration.configuration_hash, second.configuration.configuration_hash
                )


class TestHandListedExpectations(unittest.TestCase):
    def test_the_canonical_baseline_has_fifteen_resources(self) -> None:
        config = config_of("fixtures/canonical_regression/baseline")
        self.assertEqual(set(config.resources), BASELINE_ADDRESSES)
        self.assertEqual(len(config.resources), 15)

    def test_patch_safe_and_patch_regression_are_the_baseline_minus_rules(self) -> None:
        safe = set(config_of("fixtures/canonical_regression/patch_safe").resources)
        regression = set(config_of("fixtures/canonical_regression/patch_regression").resources)
        self.assertEqual(safe, BASELINE_ADDRESSES - {("aws_security_group_rule", "app_ssh_public")})
        self.assertEqual(
            regression,
            BASELINE_ADDRESSES
            - {
                ("aws_security_group_rule", "app_ssh_public"),
                ("aws_security_group_rule", "app_to_db_5432"),
            },
        )

    def test_the_for_each_fixture_has_a_for_each_meta_argument(self) -> None:
        config = config_of("fixtures/identity/ambiguous_identity_uncertain_v1")
        ops = config.resources[("aws_security_group", "ops")]
        self.assertIsNotNone(ops.for_each)
        self.assertIsNone(ops.count)
        assert ops.for_each is not None
        call = ops.for_each.expr
        self.assertIsInstance(call, FunctionCall)
        assert isinstance(call, FunctionCall)
        self.assertEqual(call.name, "toset")
        (argument,) = call.args
        assert isinstance(argument, Tuple)
        self.assertEqual(
            [e.value for e in argument.elements if isinstance(e, Literal)],
            ["a", "b"],
        )
        # The template string "ops-${each.key}" stays in the remaining body.
        name = next(
            item for item in ops.body.items if isinstance(item, Attribute) and item.name == "name"
        )
        assert isinstance(name.expr, Template)
        literal, interpolation = name.expr.parts
        self.assertIsInstance(literal, TemplateLiteral)
        self.assertEqual(literal.text, "ops-")  # type: ignore[union-attr]
        assert isinstance(interpolation, TemplateInterpolation)
        self.assertIsInstance(interpolation.expr, ScopeTraversal)
        assert isinstance(interpolation.expr, ScopeTraversal)
        self.assertEqual(interpolation.expr.root, "each")
        self.assertEqual([step.name for step in interpolation.expr.steps], ["key"])  # type: ignore[union-attr]

    def test_only_the_for_each_fixture_uses_for_each(self) -> None:
        for folder in RESOURCE_COUNTS:
            with self.subTest(folder=folder):
                with_for_each = [
                    key
                    for key, resource in config_of(folder).resources.items()
                    if resource.for_each is not None
                ]
                if folder.endswith("ambiguous_identity_uncertain_v1"):
                    self.assertEqual(with_for_each, [("aws_security_group", "ops")])
                else:
                    self.assertEqual(with_for_each, [])
                for resource in config_of(folder).resources.values():
                    self.assertIsNone(resource.count)
                    self.assertIsNone(resource.depends_on)
                    self.assertEqual(resource.dynamic_blocks, ())

    def test_the_parent_of_the_for_each_fixture_has_an_unexpanded_ops_group(self) -> None:
        config = config_of("fixtures/identity/ambiguous_identity_parent_v1")
        self.assertIn(("aws_security_group", "ops"), config.resources)
        self.assertIsNone(config.resources[("aws_security_group", "ops")].for_each)

    def test_the_variable_fixture_declares_app_sg_id(self) -> None:
        config = config_of("fixtures/dependency/func_unknown_dependency_unknown_v1")
        self.assertEqual(list(config.variables), ["app_sg_id"])
        variable = config.variables["app_sg_id"]
        self.assertEqual(attribute_names(variable.block.body.items), ["type"])
        for folder in RESOURCE_COUNTS:
            if not folder.endswith("func_unknown_dependency_unknown_v1"):
                with self.subTest(folder=folder):
                    self.assertEqual(len(config_of(folder).variables), 0)

    def test_baseline_database_group_has_egress_as_an_empty_tuple_attribute(self) -> None:
        config = config_of("fixtures/canonical_regression/baseline")
        db = config.resources[("aws_security_group", "db")]
        egress = [
            item for item in db.body.items if isinstance(item, Attribute) and item.name == "egress"
        ]
        self.assertEqual(len(egress), 1)
        self.assertIsInstance(egress[0].expr, Tuple)
        assert isinstance(egress[0].expr, Tuple)
        self.assertEqual(egress[0].expr.elements, ())
        # No block of that name and no ingress at all.
        self.assertNotIn("egress", block_types(db.body.items))
        self.assertNotIn("ingress", attribute_names(db.body.items) + block_types(db.body.items))

    def test_baseline_app_group_leaves_both_directions_absent(self) -> None:
        # Registry §2.6 (C-84): an absent argument is neither a block nor an explicit empty list.
        config = config_of("fixtures/canonical_regression/baseline")
        app = config.resources[("aws_security_group", "app")]
        names = attribute_names(app.body.items) + block_types(app.body.items)
        self.assertEqual(sorted(names), ["description", "name", "vpc_id"])
        self.assertNotIn("ingress", names)
        self.assertNotIn("egress", names)

    def test_sg_created_resource_fixture_keeps_the_three_inline_rule_forms_distinct(self) -> None:
        config = config_of("fixtures/impact/sg_created_resource_fail_v1")
        bastion = config.resources[("aws_security_group", "bastion")]
        # An `ingress` BLOCK and an `egress = []` ATTRIBUTE on the same group.
        self.assertEqual(block_types(bastion.body.items), ["ingress"])
        egress = [
            item
            for item in bastion.body.items
            if isinstance(item, Attribute) and item.name == "egress"
        ]
        self.assertEqual(len(egress), 1)
        assert isinstance(egress[0].expr, Tuple)
        self.assertEqual(egress[0].expr.elements, ())
        self.assertNotIn("ingress", attribute_names(bastion.body.items))
        self.assertNotIn("egress", block_types(bastion.body.items))
        # The app group of that fixture has `ingress = []` (explicit empty) and no blocks.
        app = config.resources[("aws_security_group", "app")]
        ingress = [
            item
            for item in app.body.items
            if isinstance(item, Attribute) and item.name == "ingress"
        ]
        self.assertEqual(len(ingress), 1)
        assert isinstance(ingress[0].expr, Tuple)
        self.assertEqual(ingress[0].expr.elements, ())
        self.assertEqual(block_types(app.body.items), [])

    def test_the_bastion_ingress_block_is_a_block_with_attributes(self) -> None:
        config = config_of("fixtures/impact/sg_created_resource_fail_v1")
        bastion = config.resources[("aws_security_group", "bastion")]
        (ingress,) = (i for i in bastion.body.items if isinstance(i, Block))
        self.assertEqual(ingress.type, "ingress")
        self.assertEqual(ingress.labels, ())
        self.assertFalse(ingress.one_line)
        self.assertIn("from_port", attribute_names(ingress.body.items))
        self.assertIn("cidr_blocks", attribute_names(ingress.body.items))

    def test_route_table_keeps_its_nested_route_block(self) -> None:
        config = config_of("fixtures/canonical_regression/baseline")
        table = config.resources[("aws_route_table", "public")]
        self.assertEqual(block_types(table.body.items), ["route"])
        self.assertEqual(attribute_names(table.body.items), ["vpc_id"])

    def test_references_are_kept_as_traversals(self) -> None:
        config = config_of("fixtures/canonical_regression/baseline")
        subnet = config.resources[("aws_subnet", "app")]
        vpc_id = next(
            i for i in subnet.body.items if isinstance(i, Attribute) and i.name == "vpc_id"
        )
        self.assertIsInstance(vpc_id.expr, ScopeTraversal)
        assert isinstance(vpc_id.expr, ScopeTraversal)
        self.assertEqual(
            (vpc_id.expr.root, [step.name for step in vpc_id.expr.steps]),  # type: ignore[union-attr]
            ("aws_vpc", ["main", "id"]),
        )
        database = config.resources[("aws_db_instance", "database")]
        public = next(
            i
            for i in database.body.items
            if isinstance(i, Attribute) and i.name == "publicly_accessible"
        )
        self.assertEqual(public.expr, Literal(LiteralKind.BOOL, False, "false", public.expr.range))

    def test_the_two_hand_edited_fixture_pairs_differ_in_their_hashes(self) -> None:
        base = config_of("fixtures/canonical_regression/baseline")
        safe = config_of("fixtures/canonical_regression/patch_safe")
        self.assertNotEqual(base.configuration_hash, safe.configuration_hash)
        self.assertEqual(base.files["versions.tf"], safe.files["versions.tf"])
        self.assertNotEqual(base.files["main.tf"], safe.files["main.tf"])

    def test_fixture_files_are_read_from_the_working_tree_only(self) -> None:
        # The loader reads only the folder it is given: the expected.json beside the files is
        # not Terraform and is ignored.
        config = config_of("fixtures/canonical_regression/baseline")
        self.assertNotIn("expected.json", config.files)
        self.assertTrue(
            (Path(ROOT) / "fixtures/canonical_regression/baseline/expected.json").exists()
        )


if __name__ == "__main__":
    unittest.main()
