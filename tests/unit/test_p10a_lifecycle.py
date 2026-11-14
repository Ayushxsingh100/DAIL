"""The lifecycle rule of the patch validator (P10a work package Section 3.2; decision 6, C-221).

Section 3.2: "a MODIFY block for an address whose parent block has a ``lifecycle`` block must
contain that lifecycle block, compared as now. Otherwise POLICY_VIOLATION. Validator version ->
``dail-patch-validator-2``. Tests: dropped -> refused; kept unchanged -> passes; parent without
lifecycle -> unchanged behaviour."
Decision 6: "A patch that drops the parent's ``lifecycle`` block is refused: POLICY_VIOLATION before
DAIL, counted as an invalid patch."

The parent with a lifecycle block is the canonical baseline with one ``lifecycle`` block added to
``aws_security_group.app`` (in a temporary copy; the fixture is never written).
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from core.terraform_model.normalization import normalize_directory
from llm.schemas.records import FailureClass
from llm.validation.parser import parse_response
from llm.validation.patch import VALIDATOR_VERSION, PatchValidator, ValidationOutcome
from tests.identity_builders import NOW
from tests.impact_builders import registry
from tests.llm_patch_builders import (
    BASELINE,
    PARENT_NAME,
    PATCH_ID,
    REQUEST_ID,
    SG_APP,
    SG_APP_CLOSED,
    WorkRoot,
    repair,
    scope,
)
from tests.promotion_pipeline import trusted_from

F = FailureClass
SG_APP_PARENT = (
    'resource "aws_security_group" "app" {\n'
    '  name        = "app"\n'
    '  description = "Application security group"\n'
    "  vpc_id      = aws_vpc.main.id\n"
    "}\n"
)
LIFECYCLE = "  lifecycle {\n    create_before_destroy = true\n  }\n"
SG_APP_WITH_LIFECYCLE = SG_APP_PARENT.replace("}\n", LIFECYCLE + "}\n")
# the repair keeps the parent's lifecycle block unchanged (whitespace differs: compared as now)
CLOSED_KEEPS = SG_APP_CLOSED.replace(
    "}\n", "  lifecycle {\n      create_before_destroy   =   true\n  }\n}\n"
)
CLOSED_CHANGES = SG_APP_CLOSED.replace(
    "}\n", "  lifecycle {\n    create_before_destroy = false\n  }\n}\n"
)


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.work = WorkRoot()
        self.addCleanup(self.work.close)
        holder = tempfile.TemporaryDirectory(prefix="dail-p10a-lifecycle-")
        self.addCleanup(holder.cleanup)
        self.parent = Path(holder.name) / "parent"
        shutil.copytree(BASELINE, self.parent)
        main = self.parent / "main.tf"
        text = main.read_bytes().decode("utf-8").replace("\r\n", "\n")
        self.assertEqual(text.count(SG_APP_PARENT), 1)
        main.write_bytes(text.replace(SG_APP_PARENT, SG_APP_WITH_LIFECYCLE).encode("utf-8"))

    def validator(self, parent: Path) -> PatchValidator:
        outcome = normalize_directory(parent, None, now=NOW)
        definitions = list(registry("aws_instance.app", "aws_db_instance.database").values())
        trusted = trusted_from(PARENT_NAME, outcome.resources, definitions)
        return PatchValidator(
            parent_dir=parent,
            trusted=trusted,
            scope=scope(),
            work_root=self.work.path,
            variables=None,
            now=NOW,
        )

    def run_patch(self, parent: Path, patch: str) -> ValidationOutcome:
        parsed = parse_response(repair(patch, [SG_APP]))
        assert parsed.response is not None, parsed.errors
        return self.validator(parent).validate(
            parsed.response, request_id=REQUEST_ID, patch_id=PATCH_ID
        )


class TestLifecycleRule(Case):
    def test_the_version_is_2(self) -> None:
        self.assertEqual(VALIDATOR_VERSION, "dail-patch-validator-2")

    def test_a_modify_that_drops_the_parents_lifecycle_block_is_refused(self) -> None:
        outcome = self.run_patch(self.parent, SG_APP_CLOSED)
        self.assertIs(outcome.failure_class, F.POLICY_VIOLATION, outcome.errors)
        self.assertIsNone(outcome.build)
        self.assertIn("lifecycle", " ".join(outcome.errors))

    def test_a_modify_that_keeps_it_unchanged_passes(self) -> None:
        outcome = self.run_patch(self.parent, CLOSED_KEEPS)
        self.assertIsNone(outcome.failure_class, outcome.errors)
        self.assertIsNotNone(outcome.build)

    def test_a_modify_that_changes_it_is_still_refused(self) -> None:
        outcome = self.run_patch(self.parent, CLOSED_CHANGES)
        self.assertIs(outcome.failure_class, F.POLICY_VIOLATION, outcome.errors)

    def test_a_parent_without_lifecycle_is_unchanged(self) -> None:
        # as before: no lifecycle block passes, an added one is refused
        self.assertIsNone(self.run_patch(BASELINE, SG_APP_CLOSED).failure_class)
        added = SG_APP_CLOSED.replace("}\n", LIFECYCLE + "}\n")
        self.assertIs(self.run_patch(BASELINE, added).failure_class, F.POLICY_VIOLATION)


if __name__ == "__main__":
    unittest.main()
