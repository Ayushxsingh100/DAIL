"""Repository structure contract (Doc 14 §3, §18; Doc 04 §15; Doc 02 §26; P0-close Step 10)."""

from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

STEP4_DIRECTORIES = (
    "core/terraform_model",
    "core/identity",
    "core/dependency",
    "core/impact",
    "core/verification",
    "core/promotion",
    "core/application",
    "llm",
    "llm/adapter",
    "llm/prompts",
    "llm/schemas",
    "llm/validation",
    "tests/unit",
    "tests/integration",
    "tests/contract",
    "tests/adversarial",
    "tests/e2e",
    "fixtures/canonical_regression/baseline",
    "fixtures/canonical_regression/patch_safe",
    "fixtures/canonical_regression/patch_regression",
    "fixtures/identity",
    "fixtures/dependency",
    "fixtures/impact",
    "fixtures/verification",
    "fixtures/adversarial",
    "infrastructure/terraform/modules",
    "infrastructure/terraform/environments/dev",
    "infrastructure/terraform/environments/test",
    "infrastructure/terraform/environments/experiment",
    "infrastructure/terraform/environments/staging",
    "infrastructure/terraform/policies",
    "config/base",
    "config/environments",
    "requirements",
)

PYTHON_PACKAGES = (
    "core/terraform_model",
    "core/identity",
    "core/dependency",
    "core/impact",
    "core/verification",
    "core/promotion",
    "core/application",
    "llm",
    "llm/adapter",
    "llm/prompts",
    "llm/schemas",
    "llm/validation",
    "tests/integration",
    "tests/contract",
    "tests/adversarial",
    "tests/e2e",
)

BASE_CONFIG_AREAS = (
    "application",
    "database",
    "artifact_store",
    "llm",
    "verification",
    "promotion",
    "experiments",
    "observability",
)
ENVIRONMENTS = ("dev", "test", "experiment", "staging")

REQUIRED_ADRS = (
    "ADR-001-modular-monolith.md",
    "ADR-002-python-3.12-and-dependency-management.md",
    "ADR-004-sqlite-through-persistence-abstraction.md",
    "ADR-009-deterministic-fixed-patch-core-before-llm.md",
    "ADR-010-independent-oracle-separation.md",
    "ADR-011-relational-trusted-state-lineage.md",
    "ADR-012-state-indexed-verification.md",
    "ADR-013-terrapreserve-separate-repository.md",
)
REMOVED_ADR_PREFIXES = ("ADR-002-relational", "ADR-003-state", "ADR-004-stdlib")


class TestRepositoryStructure(unittest.TestCase):
    def test_step4_directories_exist(self) -> None:
        missing = [d for d in STEP4_DIRECTORIES if not (REPO_ROOT / d).is_dir()]
        self.assertEqual(missing, [])

    def test_new_python_packages_have_init_files(self) -> None:
        missing = [p for p in PYTHON_PACKAGES if not (REPO_ROOT / p / "__init__.py").is_file()]
        self.assertEqual(missing, [])

    def test_base_and_environment_config_files_exist(self) -> None:
        for area in BASE_CONFIG_AREAS:
            with self.subTest(area=area):
                self.assertTrue((REPO_ROOT / "config" / "base" / f"{area}.toml").is_file())
        for env in ENVIRONMENTS:
            with self.subTest(environment=env):
                self.assertTrue((REPO_ROOT / "config" / "environments" / f"{env}.toml").is_file())

    def test_versions_tf_and_env_example_exist(self) -> None:
        self.assertTrue((REPO_ROOT / "infrastructure" / "terraform" / "versions.tf").is_file())
        self.assertTrue((REPO_ROOT / ".env.example").is_file())

    def test_required_adrs_exist_and_old_names_are_gone(self) -> None:
        adr_dir = REPO_ROOT / "docs" / "adr"
        for name in REQUIRED_ADRS:
            with self.subTest(adr=name):
                self.assertTrue((adr_dir / name).is_file())
        leftovers = [p.name for p in adr_dir.iterdir() if p.name.startswith(REMOVED_ADR_PREFIXES)]
        self.assertEqual(leftovers, [])

    def test_decisions_register_and_build_sequence_exist(self) -> None:
        self.assertTrue((REPO_ROOT / "docs" / "DECISIONS_REGISTER.md").is_file())
        self.assertTrue((REPO_ROOT / "docs" / "BUILD_SEQUENCE.md").is_file())

    def test_no_benchmark_oracle_or_apps_directory(self) -> None:
        for name in ("benchmark", "oracle", "apps"):
            with self.subTest(directory=name):
                self.assertFalse((REPO_ROOT / name).exists())

    def test_phase_gates_does_not_claim_p1_or_p2_passed(self) -> None:
        text = (REPO_ROOT / "docs" / "PHASE_GATES.md").read_text(encoding="utf-8")
        self.assertNotIn("P1 — Domain Foundation: PASSED", text)
        self.assertNotIn("P2 — Evidence Foundation: PASSED", text)


if __name__ == "__main__":
    unittest.main()
