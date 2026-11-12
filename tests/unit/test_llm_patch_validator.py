"""The patch validator and candidate build (P7b; Doc 10 §12-§15, §22, §39.2, §39.4;
Doc 03 §4.5-§4.7; C-188 to C-192).

Expected values come from the work package text:

C-188 "An LLM patch is a set of complete Terraform ``resource`` blocks. For each address in
``changed_addresses``: if the patch holds a block for it and the parent has it, the block replaces
the parent's block (MODIFY); if the patch holds a block and the parent does not have it, the
block is added (CREATE); if the patch holds no block for it, the parent's block is removed (DELETE).
Everything else in the parent configuration is copied byte for byte."
C-189 the application rules; C-190 the scope; C-191 the operation check; C-192 the failure classes.
Section 4 of the work package, checks 2 to 11.
"""

from __future__ import annotations

import json
import secrets
import string
import unittest
from typing import Any

from core.domain.change_scope import OperationType
from core.domain.enums import CandidateSource
from llm.schemas.records import FailureClass
from llm.validation.parser import PARSER_VERSION, parse_response
from llm.validation.patch import PATCH_FILE, VALIDATOR_VERSION, ValidationOutcome
from tests.llm_patch_builders import (
    BASELINE,
    DELETE_ONLY,
    NEW_RULE,
    PATCH_ID,
    REQUEST_ID,
    SG_APP,
    SG_APP_CLOSED,
    SSH_RULE,
    WorkRoot,
    repair,
    scope,
    tree_digest,
    trusted,
    validator,
)

F = FailureClass
OP = OperationType


def block(kind: str, name: str, *lines: str) -> str:
    return f'resource "{kind}" "{name}" {{\n' + "".join(f"  {line}\n" for line in lines) + "}\n"


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.work = WorkRoot()
        self.addCleanup(self.work.close)
        self.parent_before = tree_digest(BASELINE)

    def tearDown(self) -> None:
        # the parent directory is never written (C-189, Doc 03 §4.6)
        self.assertEqual(tree_digest(BASELINE), self.parent_before)

    def run_patch(self, patch: str, changed: list[str], **kwargs: Any) -> ValidationOutcome:
        change_scope = kwargs.pop("change_scope", None)
        parsed = parse_response(repair(patch, changed, **kwargs))
        self.assertIsNone(parsed.failure_class, parsed.errors)
        assert parsed.response is not None
        self.before = set(self.work.path.iterdir())
        return validator(self.work.path, change_scope).validate(
            parsed.response, request_id=REQUEST_ID, patch_id=PATCH_ID
        )

    def assert_fails(self, outcome: ValidationOutcome, failure: FailureClass) -> None:
        self.assertIs(outcome.failure_class, failure, outcome.errors)
        self.assertIsNone(outcome.build)
        self.assertTrue(outcome.errors)
        self.assertEqual(outcome.validator_version, VALIDATOR_VERSION)
        # nothing of a refused build is left behind
        self.assertEqual(set(self.work.path.iterdir()), self.before)

    def assert_builds(self, outcome: ValidationOutcome) -> None:
        self.assertIsNone(outcome.failure_class, outcome.errors)
        self.assertIsNotNone(outcome.build)


def _text(path: Any) -> str:
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


class TestApplication(Case):
    def test_modify_replaces_the_parent_block_in_place(self) -> None:
        outcome = self.run_patch(SG_APP_CLOSED, [SG_APP])
        self.assert_builds(outcome)
        assert outcome.build is not None
        main = _text(outcome.build.candidate_dir / "main.tf")
        parent = _text(BASELINE / "main.tf")
        start = parent.index('resource "aws_security_group" "app" {')
        end = parent.index("}\n", start) + 1
        self.assertEqual(main, parent[:start] + SG_APP_CLOSED.rstrip("\n") + parent[end:])
        self.assertEqual(
            (outcome.build.candidate_dir / "versions.tf").read_bytes(),
            (BASELINE / "versions.tf").read_bytes(),
        )
        self.assertFalse((outcome.build.candidate_dir / PATCH_FILE).exists())
        self.assertEqual(outcome.operations, ((SG_APP, OP.MODIFY),))

    def test_delete_removes_the_parent_block_bytes(self) -> None:
        outcome = self.run_patch(DELETE_ONLY, [SSH_RULE])
        self.assert_builds(outcome)
        assert outcome.build is not None
        main = _text(outcome.build.candidate_dir / "main.tf")
        self.assertNotIn('"app_ssh_public"', main)
        parent = _text(BASELINE / "main.tf")
        start = parent.index('resource "aws_security_group_rule" "app_ssh_public" {')
        end = parent.index("}\n", start) + 1
        self.assertEqual(main, parent[:start] + parent[end:])
        self.assertEqual(outcome.operations, ((SSH_RULE, OP.DELETE),))

    def test_create_writes_one_new_file_in_changed_addresses_order(self) -> None:
        second = NEW_RULE.replace('"app_https"', '"app_http"').replace("443", "80")
        outcome = self.run_patch(
            NEW_RULE + "\n" + second,
            ["aws_security_group_rule.app_http", "aws_security_group_rule.app_https"],
        )
        self.assert_builds(outcome)
        assert outcome.build is not None
        created = _text(outcome.build.candidate_dir / PATCH_FILE)
        self.assertLess(created.index('"app_http"'), created.index('"app_https"'))
        self.assertEqual(
            _text(outcome.build.candidate_dir / "main.tf"), _text(BASELINE / "main.tf")
        )
        self.assertEqual(
            outcome.operations,
            (
                ("aws_security_group_rule.app_http", OP.CREATE),
                ("aws_security_group_rule.app_https", OP.CREATE),
            ),
        )

    def test_the_candidate_lives_in_a_fresh_isolated_directory(self) -> None:
        one = self.run_patch(SG_APP_CLOSED, [SG_APP])
        two = self.run_patch(SG_APP_CLOSED, [SG_APP])
        assert one.build is not None and two.build is not None
        self.assertNotEqual(one.build.candidate_dir, two.build.candidate_dir)
        for build in (one.build, two.build):
            self.assertEqual(build.candidate_dir.parent.parent, self.work.path)
            self.assertNotEqual(build.candidate_dir.resolve(), BASELINE.resolve())

    def test_the_same_patch_on_the_same_parent_gives_the_same_candidate(self) -> None:
        one = self.run_patch(
            SG_APP_CLOSED + "\n" + NEW_RULE, [SG_APP, "aws_security_group_rule.app_https", SSH_RULE]
        )
        two = self.run_patch(
            SG_APP_CLOSED + "\n" + NEW_RULE, [SG_APP, "aws_security_group_rule.app_https", SSH_RULE]
        )
        assert one.build is not None and two.build is not None
        self.assertEqual(one.build.tree_hash, two.build.tree_hash)
        self.assertEqual(tree_digest(one.build.candidate_dir), tree_digest(two.build.candidate_dir))
        self.assertEqual(one.build.patch.content_hash, two.build.patch.content_hash)
        self.assertEqual(one.build.resource_set_hash, two.build.resource_set_hash)

    def test_the_patch_record_is_an_llm_patch_with_one_parent(self) -> None:
        outcome = self.run_patch(SG_APP_CLOSED, [SG_APP])
        assert outcome.build is not None
        patch = outcome.build.patch
        self.assertIs(patch.source, CandidateSource.LLM)
        self.assertEqual(patch.llm_request_id, REQUEST_ID)
        self.assertEqual(patch.parent_state_id, trusted().state_id)
        self.assertEqual(patch.patch_id, PATCH_ID)
        self.assertEqual(patch.content, SG_APP_CLOSED)
        self.assertEqual(patch.metadata["tree_hash"], outcome.build.tree_hash)
        self.assertEqual(patch.metadata["validator_version"], VALIDATOR_VERSION)


class TestSyntaxAndBlocks(Case):
    def test_hcl_syntax_error_is_invalid_output(self) -> None:
        self.assert_fails(
            self.run_patch('resource "aws_security_group" "app" {\n', [SG_APP]), F.INVALID_OUTPUT
        )
        self.assert_builds(self.run_patch(SG_APP_CLOSED, [SG_APP]))

    def test_only_resource_blocks_at_top_level(self) -> None:
        for extra in (
            'provider "aws" {\n  region = "eu-west-1"\n}\n',
            'terraform {\n  backend "s3" {}\n}\n',
            'module "m" {\n  source = "./m"\n}\n',
            'data "aws_vpc" "x" {}\n',
            'variable "v" {}\n',
            "locals {\n  a = 1\n}\n",
            'output "o" {\n  value = 1\n}\n',
            "moved {\n  from = aws_vpc.a\n  to = aws_vpc.b\n}\n",
            'import {\n  to = aws_vpc.main\n  id = "x"\n}\n',
            "removed {\n  from = aws_vpc.main\n}\n",
            'check "c" {}\n',
            'region = "eu-west-1"\n',
        ):
            with self.subTest(extra=extra.split("\n")[0]):
                self.assert_fails(
                    self.run_patch(SG_APP_CLOSED + extra, [SG_APP]), F.POLICY_VIOLATION
                )

    def test_provisioner_and_connection_are_policy_violations(self) -> None:
        for inner in (
            'provisioner "local-exec" {\n    command = "echo hi"\n  }',
            'connection {\n    host = "x"\n  }',
        ):
            with self.subTest(inner=inner.split()[0]):
                patch = SG_APP_CLOSED.replace("}\n", f"  {inner}\n}}\n")
                self.assert_fails(self.run_patch(patch, [SG_APP]), F.POLICY_VIOLATION)

    def test_a_dynamic_block_is_unsupported(self) -> None:
        patch = SG_APP_CLOSED.replace(
            "  ingress     = []\n",
            '  dynamic "ingress" {\n    for_each = []\n    content {}\n  }\n',
        )
        self.assert_fails(self.run_patch(patch, [SG_APP]), F.UNSUPPORTED)

    def test_a_lifecycle_block_must_equal_the_parents(self) -> None:
        patch = SG_APP_CLOSED.replace("}\n", "  lifecycle {\n    prevent_destroy = false\n  }\n}\n")
        self.assert_fails(self.run_patch(patch, [SG_APP]), F.POLICY_VIOLATION)
        # the parent's aws_security_group.app has no lifecycle block; none passes
        self.assert_builds(self.run_patch(SG_APP_CLOSED, [SG_APP]))


class TestBoundaries(Case):
    def test_a_block_for_an_address_not_listed(self) -> None:
        outcome = self.run_patch(SG_APP_CLOSED + "\n" + NEW_RULE, [SG_APP])
        self.assert_fails(outcome, F.INVALID_OUTPUT)

    def test_two_blocks_for_one_address(self) -> None:
        self.assert_fails(
            self.run_patch(SG_APP_CLOSED + "\n" + SG_APP_CLOSED, [SG_APP]), F.INVALID_OUTPUT
        )

    def test_delete_of_an_address_the_parent_does_not_have(self) -> None:
        self.assert_fails(
            self.run_patch(DELETE_ONLY, ["aws_security_group_rule.nowhere"]), F.INVALID_OUTPUT
        )

    def test_instance_and_module_addresses_are_invalid_output(self) -> None:
        for address in (
            "aws_security_group.app[0]",
            'aws_security_group.app["a"]',
            "module.m.aws_vpc.v",
        ):
            with self.subTest(address=address):
                parsed = parse_response(repair(SG_APP_CLOSED, [address]))
                self.assertIs(parsed.failure_class, F.INVALID_OUTPUT)

    def test_a_file_path_is_not_an_address(self) -> None:
        parsed = parse_response(repair(SG_APP_CLOSED, ["core/verification/public_ingress.py"]))
        self.assertIs(parsed.failure_class, F.INVALID_OUTPUT)
        self.assertEqual(PARSER_VERSION, "dail-llm-parser-2")

    def test_a_resource_block_needs_two_labels(self) -> None:
        self.assert_fails(
            self.run_patch('resource "aws_vpc" {\n}\n', ["aws_vpc.main"]), F.INVALID_OUTPUT
        )


class TestScope(Case):
    def test_modify_outside_resource_addresses(self) -> None:
        outcome = self.run_patch(SG_APP_CLOSED, [SG_APP], change_scope=scope(addresses=[SSH_RULE]))
        self.assert_fails(outcome, F.POLICY_VIOLATION)

    def test_delete_outside_resource_addresses(self) -> None:
        outcome = self.run_patch(DELETE_ONLY, [SSH_RULE], change_scope=scope(addresses=[SG_APP]))
        self.assert_fails(outcome, F.POLICY_VIOLATION)

    def test_create_of_an_allowed_type_at_a_new_address_passes(self) -> None:
        # the P7a limit (C-187 (3)) this package removes: a new address needs no scope entry
        outcome = self.run_patch(
            NEW_RULE, ["aws_security_group_rule.app_https"], change_scope=scope(addresses=[SG_APP])
        )
        self.assert_builds(outcome)

    def test_create_of_a_type_outside_resource_types(self) -> None:
        outcome = self.run_patch(
            NEW_RULE,
            ["aws_security_group_rule.app_https"],
            change_scope=scope(types=["aws_security_group"]),
        )
        self.assert_fails(outcome, F.POLICY_VIOLATION)

    def test_a_type_outside_the_supported_model_is_unsupported(self) -> None:
        patch = block("aws_lambda_function", "f", 'function_name = "f"')
        outcome = self.run_patch(
            patch, ["aws_lambda_function.f"], change_scope=scope(types=["aws_lambda_function"])
        )
        self.assert_fails(outcome, F.UNSUPPORTED)

    def test_the_attribute_restriction(self) -> None:
        allowed = scope(attributes=["ingress"])
        self.assert_builds(self.run_patch(SG_APP_CLOSED, [SG_APP], change_scope=allowed))
        renamed = SG_APP_CLOSED.replace('"Application security group"', '"changed"')
        self.assert_fails(
            self.run_patch(renamed, [SG_APP], change_scope=allowed), F.POLICY_VIOLATION
        )
        # empty attributes: no restriction
        self.assert_builds(self.run_patch(renamed, [SG_APP], change_scope=scope()))

    def test_operation_check_rejects_a_replaced_pair_when_replace_is_not_allowed(self) -> None:
        renamed = SG_APP_CLOSED.replace('name        = "app"', 'name        = "app-v2"')
        no_replace = scope(operations=[OP.CREATE, OP.MODIFY, OP.DELETE])
        self.assert_fails(
            self.run_patch(renamed, [SG_APP], change_scope=no_replace), F.POLICY_VIOLATION
        )
        self.assert_builds(self.run_patch(renamed, [SG_APP], change_scope=scope()))

    def test_operation_check_counts_an_uncertain_pair_as_replace(self) -> None:
        # RT-1: a name that is not resolved on one side leaves replacement undecided: UNCERTAIN
        # (aws_vpc.main.arn is computed by the provider and not set in the configuration)
        patch = SG_APP_CLOSED.replace('name        = "app"', "name        = aws_vpc.main.arn")
        no_replace = scope(operations=[OP.CREATE, OP.MODIFY, OP.DELETE])
        self.assert_fails(
            self.run_patch(patch, [SG_APP], change_scope=no_replace), F.POLICY_VIOLATION
        )
        self.assert_builds(self.run_patch(patch, [SG_APP], change_scope=scope()))

    def test_operation_check_rejects_delete_when_delete_is_not_allowed(self) -> None:
        no_delete = scope(operations=[OP.CREATE, OP.MODIFY, OP.REPLACE])
        self.assert_fails(
            self.run_patch(DELETE_ONLY, [SSH_RULE], change_scope=no_delete), F.POLICY_VIOLATION
        )


class TestCredentialsAndIds(Case):
    def test_a_new_secret_literal_is_a_policy_violation(self) -> None:
        password = "pw-" + secrets.token_hex(8)
        patch = block("aws_security_group", "app", 'name = "app"', f'password = "{password}"')
        self.assert_fails(self.run_patch(patch, [SG_APP]), F.POLICY_VIOLATION)

    def test_a_secret_argument_from_a_variable_is_allowed_only_when_declared(self) -> None:
        patch = block("aws_security_group", "app", 'name = "app"', "password = var.db_password")
        # var.db_password is not declared in the candidate: reference check (INVALID_OUTPUT)
        self.assert_fails(self.run_patch(patch, [SG_APP]), F.INVALID_OUTPUT)

    def test_an_aws_access_key_id_anywhere_is_a_policy_violation(self) -> None:
        key = (
            "AK"
            + "IA"
            + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
        )
        patch = SG_APP_CLOSED.replace('"Application security group"', f'"key {key}"')
        self.assert_fails(self.run_patch(patch, [SG_APP]), F.POLICY_VIOLATION)

    def test_a_private_key_header_is_a_policy_violation(self) -> None:
        header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        patch = SG_APP_CLOSED.replace('"Application security group"', f'"{header}"')
        self.assert_fails(self.run_patch(patch, [SG_APP]), F.POLICY_VIOLATION)

    def test_an_invented_aws_id_is_a_policy_violation(self) -> None:
        for value in (
            "sg-0abc1234",
            "subnet-0123456789abcdef0",
            "i-deadbeef",
            "arn:aws:iam::123456789012:role/x",
        ):
            with self.subTest(value=value):
                patch = SG_APP_CLOSED.replace('"Application security group"', f'"{value}"')
                self.assert_fails(self.run_patch(patch, [SG_APP]), F.POLICY_VIOLATION)

    def test_an_aws_id_of_the_parent_text_is_not_invented(self) -> None:
        # the baseline names ami-0123456789abcdef0 (aws_instance.app)
        patch = SG_APP_CLOSED.replace('"Application security group"', '"ami-0123456789abcdef0"')
        self.assert_builds(self.run_patch(patch, [SG_APP]))

    def test_strings_that_only_look_like_ids_pass(self) -> None:
        for value in ("sg-app", "subnet-xyz12345", "vpc-0ABC1234"):
            with self.subTest(value=value):
                patch = SG_APP_CLOSED.replace('"Application security group"', f'"{value}"')
                self.assert_builds(self.run_patch(patch, [SG_APP]))


class TestReferencesAndConstruction(Case):
    def assert_undeclared(self, outcome: ValidationOutcome) -> None:
        # check 9 itself reports it (P3 would also refuse the candidate later)
        self.assert_fails(outcome, F.INVALID_OUTPUT)
        self.assertIn("reference is not declared in the candidate", outcome.errors[0])

    def test_a_reference_to_an_undeclared_resource(self) -> None:
        patch = SG_APP_CLOSED.replace("aws_vpc.main.id", "aws_vpc.other.id")
        self.assert_undeclared(self.run_patch(patch, [SG_APP]))

    def test_a_reference_to_a_deleted_resource(self) -> None:
        patch = NEW_RULE.replace(
            "aws_security_group.app.id", "aws_security_group_rule.app_ssh_public.id"
        )
        outcome = self.run_patch(patch, ["aws_security_group_rule.app_https", SSH_RULE])
        self.assert_undeclared(outcome)

    def test_undeclared_local_and_data_roots(self) -> None:
        for expr in ("local.x", "data.aws_vpc.main.id"):
            with self.subTest(expr=expr):
                patch = SG_APP_CLOSED.replace("aws_vpc.main.id", expr)
                self.assert_undeclared(self.run_patch(patch, [SG_APP]))

    def test_a_declared_reference_passes(self) -> None:
        self.assert_builds(self.run_patch(NEW_RULE, ["aws_security_group_rule.app_https"]))

    def test_the_built_directory_is_normalized(self) -> None:
        outcome = self.run_patch(SG_APP_CLOSED, [SG_APP])
        assert outcome.build is not None
        self.assertTrue(outcome.build.resource_set_hash)
        self.assertNotEqual(outcome.build.resource_set_hash, trusted().resource_set_hash())

    def test_a_wrong_parent_directory_is_refused(self) -> None:
        from llm.validation.patch import PatchValidator
        from tests.identity_builders import NOW
        from tests.llm_patch_builders import REPO_ROOT

        with self.assertRaises(ValueError):
            PatchValidator(
                parent_dir=REPO_ROOT / "fixtures" / "canonical_regression" / "patch_safe",
                trusted=trusted(),
                scope=scope(),
                work_root=self.work.path,
                variables=None,
                now=NOW,
            )


class TestRecordShape(Case):
    def test_the_outcome_names_its_version_and_is_json(self) -> None:
        outcome = self.run_patch(SG_APP_CLOSED, [SG_APP])
        data = outcome.to_dict()
        self.assertEqual(data["validator_version"], VALIDATOR_VERSION)
        self.assertIsNone(data["failure_class"])
        self.assertEqual(data["patch_id"], PATCH_ID)
        self.assertEqual(data["operations"], [[SG_APP, "MODIFY"]])
        json.dumps(data)


if __name__ == "__main__":
    unittest.main()
