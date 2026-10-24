"""Fixture loading (M1, Doc 15 §21 "basic fixture loading works"; D2 step 6, Package 2).

The fixtures are hand-written data (C-86 to C-90). These tests load them, check the schema strictly
and check that the values agree with each other. They never compute an expected value into a file.
Each check has a negative test that feeds it wrong data, so a check that can no longer fail
is itself caught.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tests import fixture_catalog as fc


class TestFixtureData(unittest.TestCase):
    """The committed fixtures (acceptance checks 1-7)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = fc.load_all()

    def test_twenty_fixtures_with_unique_ids_and_every_doc12_name_once(self) -> None:
        self.assertEqual(len(self.fixtures), 20)
        ids = [f.fixture_id for f in self.fixtures.values()]
        self.assertEqual(len(set(ids)), 20)
        for fid in ids:
            self.assertRegex(fid, r"^[a-z0-9]+(_[a-z0-9]+)+_v[0-9]+$")
        names = [
            f.data["doc12_fixture"]
            for f in self.fixtures.values()
            if f.data["doc12_fixture"] is not None
        ]
        self.assertEqual(sorted(names), sorted(fc.DOC12_NAMES))
        self.assertEqual(fc.collection_problems(self.fixtures), [])

    def test_the_three_canonical_fixtures_use_the_existing_folders(self) -> None:
        for folder in ("baseline", "patch_safe", "patch_regression"):
            self.assertIn(f"fixtures/canonical_regression/{folder}", self.fixtures)

    def test_every_expected_json_is_well_formed(self) -> None:
        problems = [
            p
            for folder, fx in self.fixtures.items()
            for p in fc.structure_problems(folder, fx.data)
        ]
        self.assertEqual(problems, [])

    def test_terraform_roots_are_referenced_and_have_no_provider_block(self) -> None:
        self.assertEqual(fc.terraform_problems(fc.REPO_ROOT, self.fixtures), [])
        self.assertEqual(len(fc.terraform_roots(fc.REPO_ROOT)), 16)

    def test_every_config_folder_has_main_and_versions(self) -> None:
        for fx in self.fixtures.values():
            root = fc.REPO_ROOT / fx.data["config"]
            self.assertTrue((root / "main.tf").is_file(), fx.folder)
            self.assertTrue((root / "versions.tf").is_file(), fx.folder)

    def test_versions_and_lock_are_copies_of_the_infrastructure_pins(self) -> None:
        pins = fc.REPO_ROOT / "infrastructure" / "terraform"
        for root in fc.terraform_roots(fc.REPO_ROOT):
            for name in ("versions.tf", ".terraform.lock.hcl"):
                same = (fc.REPO_ROOT / root / name).read_bytes().replace(b"\r\n", b"\n") == (
                    pins / name
                ).read_bytes().replace(b"\r\n", b"\n")
                self.assertTrue(same, f"{root}/{name} differs from infrastructure/terraform/{name}")

    def test_registry_tag_and_commit_are_exact(self) -> None:
        for fx in self.fixtures.values():
            self.assertEqual(
                fx.data["registry"],
                {
                    "tag": "registry-v1.0",
                    "commit": "80d161ded595f26b7a339d3351ba335434d7ee32",
                    "invariant_registry_version": 1,
                },
            )

    def test_enum_values_are_valid(self) -> None:
        for fx in self.fixtures.values():
            for entry in fx.data["results"].values():
                self.assertIn(entry["result"], fc.RESULT_VALUES)
            if fx.data["changes"]:
                for entry in fx.data["changes"]["resources"].values():
                    self.assertIn(entry["change"], fc.CHANGE_VALUES)
                    self.assertTrue(
                        entry["identity"] is None or entry["identity"] in fc.IDENTITY_VALUES
                    )
            if fx.data["decision"]:
                self.assertTrue(set(fx.data["decision"]["allowed"]) <= fc.DECISION_VALUES)

    def test_impact_decision_and_parent_consistency(self) -> None:
        self.assertEqual(fc.consistency_problems(self.fixtures), [])

    def test_replacement_fixture_shows_oracle_affected_can_be_empty(self) -> None:
        fx = self.fixtures["fixtures/impact/sg_replacement_resource_promote_v1"]
        self.assertEqual(fx.data["impact"]["oracle_affected"], [])
        self.assertNotEqual(fx.data["impact"]["required_affected"], [])

    def test_all_problems_is_empty_on_the_committed_fixtures(self) -> None:
        self.assertEqual(fc.all_problems(), [])

    def test_fixtures_contain_no_secret_looking_text(self) -> None:
        pattern = re.compile(
            r"AKIA[0-9A-Z]{16}|(?<![A-Za-z_])password\s*=|secret_key|access_key"
            r"|BEGIN [A-Z ]*PRIVATE KEY",
            re.IGNORECASE,
        )
        for path in sorted((fc.REPO_ROOT / "fixtures").rglob("*")):
            if path.is_file() and path.suffix in {".tf", ".json", ".md", ".hcl"}:
                self.assertIsNone(pattern.search(path.read_text(encoding="utf-8")), str(path))


class TestChecksCanFail(unittest.TestCase):
    """Acceptance check 8: wrong data is rejected."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = fc.load_all()

    def fixture(self, folder: str) -> fc.Fixture:
        original = self.fixtures[folder]
        return fc.Fixture(folder, copy.deepcopy(original.data))

    def with_changed(self, folder: str, mutate: Any) -> dict[str, fc.Fixture]:
        fixtures = dict(self.fixtures)
        fx = self.fixture(folder)
        mutate(fx.data)
        fixtures[folder] = fx
        return fixtures

    # --- a temporary corrupted copy of the whole fixtures tree is rejected ---
    def corrupted_copy(self, mutate: Any) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(
                fc.REPO_ROOT / "fixtures",
                root / "fixtures",
                ignore=shutil.ignore_patterns(".terraform"),
            )
            self.assertEqual(fc.all_problems(root), [], "the untouched copy must be clean")
            mutate(root)
            return fc.all_problems(root)

    @staticmethod
    def edit_json(root: Path, folder: str, change: Any) -> None:
        path = root / folder / "expected.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        change(data)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def test_an_unknown_key_is_rejected(self) -> None:
        problems = self.corrupted_copy(
            lambda r: self.edit_json(
                r, "fixtures/canonical_regression/baseline", lambda d: d.update(extra=1)
            )
        )
        self.assertTrue(any("keys differ" in p for p in problems), problems)

    def test_a_missing_key_is_rejected(self) -> None:
        problems = self.corrupted_copy(
            lambda r: self.edit_json(
                r, "fixtures/canonical_regression/baseline", lambda d: d.pop("process")
            )
        )
        self.assertTrue(any("keys differ" in p for p in problems), problems)

    def test_a_wrong_truth_changed_is_rejected(self) -> None:
        def wrong(data: dict) -> None:
            data["impact"]["truth_changed"] = ["INV-SEC-001", "INV-SEC-003"]

        problems = self.corrupted_copy(
            lambda r: self.edit_json(r, "fixtures/canonical_regression/patch_safe", wrong)
        )
        self.assertTrue(any("truth_changed" in p for p in problems), problems)

    def test_a_provider_block_is_rejected(self) -> None:
        def add(root: Path) -> None:
            path = root / "fixtures/canonical_regression/baseline/main.tf"
            path.write_text(
                path.read_text(encoding="utf-8")
                + '\nprovider "aws" {\n  region = "us-east-1"\n}\n',
                encoding="utf-8",
            )

        problems = self.corrupted_copy(add)
        self.assertTrue(any("provider block" in p for p in problems), problems)

    def test_an_unreferenced_terraform_root_is_rejected(self) -> None:
        def add(root: Path) -> None:
            (root / "fixtures/identity/orphan").mkdir()
            (root / "fixtures/identity/orphan/main.tf").write_text("# orphan\n", encoding="utf-8")

        problems = self.corrupted_copy(add)
        self.assertTrue(any("no fixture references" in p for p in problems), problems)

    def test_an_invalid_result_value_is_rejected(self) -> None:
        def bad(data: dict) -> None:
            data["results"]["INV-FUNC-001"]["result"] = "PASSED"

        problems = self.corrupted_copy(
            lambda r: self.edit_json(r, "fixtures/canonical_regression/baseline", bad)
        )
        self.assertTrue(any("not a VerificationResult" in p for p in problems), problems)

    def test_a_wrong_registry_commit_is_rejected(self) -> None:
        def bad(data: dict) -> None:
            data["registry"]["commit"] = "0" * 40

        problems = self.corrupted_copy(
            lambda r: self.edit_json(r, "fixtures/canonical_regression/baseline", bad)
        )
        self.assertTrue(any("registry must be" in p for p in problems), problems)

    def test_a_duplicate_fixture_id_is_rejected(self) -> None:
        def bad(data: dict) -> None:
            data["fixture_id"] = "canonical_baseline_eligible_v1"

        problems = self.corrupted_copy(
            lambda r: self.edit_json(r, "fixtures/canonical_regression/patch_safe", bad)
        )
        self.assertTrue(any("duplicate fixture ids" in p for p in problems), problems)

    # --- in-memory corruptions of the cross-fixture checks ---
    def test_promote_after_a_fail_is_rejected(self) -> None:
        fixtures = self.with_changed(
            "fixtures/verification/ec2_rds_5432_break_fail_v1",
            lambda d: d["decision"].update(allowed=["PROMOTE"]),
        )
        self.assertTrue(fc.consistency_problems(fixtures))

    def test_promote_allowed_with_an_unknown_result_is_rejected(self) -> None:
        fixtures = self.with_changed(
            "fixtures/dependency/func_unknown_dependency_unknown_v1",
            lambda d: d["decision"].update(allowed=["PROMOTE", "RETRY"]),
        )
        self.assertTrue(
            any("PROMOTE is not allowed" in p for p in fc.consistency_problems(fixtures))
        )

    def test_promote_allowed_with_a_verifier_error_override_is_rejected(self) -> None:
        fixtures = self.with_changed(
            "fixtures/adversarial/process_verifier_error_escalate_v1",
            lambda d: d["decision"].update(allowed=["PROMOTE"]),
        )
        self.assertTrue(fc.consistency_problems(fixtures))

    def test_a_stale_parent_that_may_promote_is_rejected(self) -> None:
        fixtures = self.with_changed(
            "fixtures/adversarial/process_stale_parent_reject_v1",
            lambda d: d["decision"].update(allowed=["PROMOTE"]),
        )
        self.assertTrue(any("stale parent" in p for p in fc.consistency_problems(fixtures)))

    def test_an_oracle_affected_outside_required_affected_is_rejected(self) -> None:
        fixtures = self.with_changed(
            "fixtures/verification/rds_publicly_accessible_fail_v1",
            lambda d: d["impact"].update(oracle_affected=["INV-SEC-001", "INV-SEC-003"]),
        )
        self.assertTrue(
            any("oracle_affected is not inside" in p for p in fc.consistency_problems(fixtures))
        )

    def test_an_ineligible_parent_is_rejected(self) -> None:
        def undeclare(data: dict) -> None:
            data["parent_remediation_targets"] = []

        fixtures = self.with_changed("fixtures/canonical_regression/patch_safe", undeclare)
        self.assertTrue(
            any("not a declared remediation target" in p for p in fc.consistency_problems(fixtures))
        )

    def test_a_baseline_with_an_undeclared_fail_is_rejected(self) -> None:
        def undeclare(data: dict) -> None:
            data["baseline"]["remediation_targets"] = []

        fixtures = self.with_changed("fixtures/canonical_regression/baseline", undeclare)
        self.assertTrue(
            any("not a declared remediation target" in p for p in fc.consistency_problems(fixtures))
        )

    def test_a_parent_whose_function_fails_is_rejected(self) -> None:
        def break_function(data: dict) -> None:
            data["results"]["INV-FUNC-001"]["result"] = "FAIL"

        fixtures = self.with_changed("fixtures/canonical_regression/patch_safe", break_function)
        self.assertTrue(
            any("INV-FUNC-001 must be PASS" in p for p in fc.consistency_problems(fixtures))
        )

    def test_a_wrong_doc12_name_count_is_rejected(self) -> None:
        fixtures = self.with_changed(
            "fixtures/canonical_regression/patch_safe",
            lambda d: d.update(doc12_fixture="baseline_safe"),
        )
        self.assertTrue(any("baseline_safe" in p for p in fc.collection_problems(fixtures)))

    def test_an_sec_clause_that_contradicts_its_result_is_rejected(self) -> None:
        def bad(data: dict) -> None:
            data["results"]["INV-SEC-001"]["clauses"]["ipv4"] = "FAIL"

        folder = "fixtures/canonical_regression/patch_safe"
        fx = self.fixture(folder)
        bad(fx.data)
        self.assertTrue(
            any(
                "FAIL clause makes the result FAIL" in p
                for p in fc.structure_problems(folder, fx.data)
            )
        )


if __name__ == "__main__":
    unittest.main()
