"""Health check tests (Doc 14 §30; P0-close Step 7)."""

from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from core.application.config import ResolvedConfig, load_config
from core.application.health import EXPECTED_TABLES, run_health_checks
from core.persistence.schema import initialize_database

BASE_FILES: dict[str, str] = {
    "application": "config_schema_version = 1\n",
    "database": 'path = ".local/dail.db"\n',
    "artifact_store": 'root = ".local/artifacts"\n',
    "llm": 'generation_enabled = false\nprovider = "fake"\n',
    "verification": "# no keys yet\n",
    "promotion": "automatic_enabled = false\n",
    "experiments": "# no keys yet\n",
    "observability": 'log_level = "INFO"\n',
}

# Built at runtime so the source file never contains a secret-shaped literal.
FAKE_SECRET = "sk-live-" + "fedcba9876543210" * 2


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class HealthTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.db_path = self.repo / ".local" / "dail.db"
        self.artifacts = self.repo / ".local" / "artifacts"

    def config(
        self, dev_env: str = "# none\n", environ: dict[str, str] | None = None
    ) -> ResolvedConfig:
        cfg_dir = self.repo / "config"
        (cfg_dir / "base").mkdir(parents=True, exist_ok=True)
        (cfg_dir / "environments").mkdir(parents=True, exist_ok=True)
        for area, text in BASE_FILES.items():
            (cfg_dir / "base" / f"{area}.toml").write_text(text)
        for env in ("dev", "test", "experiment", "staging"):
            (cfg_dir / "environments" / f"{env}.toml").write_text(
                dev_env if env == "dev" else "# none\n"
            )
        return load_config(cfg_dir, environment="dev", environ=environ or {})

    def init_db(self) -> None:
        initialize_database(self.db_path)

    def results(self, cfg: ResolvedConfig) -> dict[str, tuple[str, str]]:
        return {r.name: (r.status, r.detail) for r in run_health_checks(cfg, self.repo)}


class TestHealthChecks(HealthTestCase):
    def test_all_five_checks_are_reported_in_order(self) -> None:
        names = [r.name for r in run_health_checks(self.config(), self.repo)]
        self.assertEqual(
            names, ["liveness", "readiness", "database", "artifact_store", "llm_provider"]
        )

    def test_liveness_and_readiness_pass_with_a_resolved_config(self) -> None:
        res = self.results(self.config())
        self.assertEqual(res["liveness"][0], "PASS")
        self.assertEqual(res["readiness"][0], "PASS")

    def test_fresh_schema_initialized_database_passes(self) -> None:
        self.init_db()
        self.artifacts.mkdir(parents=True)
        res = self.results(self.config())
        self.assertEqual(res["database"][0], "PASS", res["database"][1])

    def test_expected_tables_match_the_real_ddl_exactly(self) -> None:
        self.init_db()
        with closing(sqlite3.connect(self.db_path)) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
            }
        self.assertEqual(tables, set(EXPECTED_TABLES))

    def test_missing_database_fails(self) -> None:
        res = self.results(self.config())
        self.assertEqual(res["database"][0], "FAIL")
        self.assertIn("not found", res["database"][1])
        self.assertFalse(self.db_path.exists(), "the check must not create the database")

    def test_database_missing_one_table_fails(self) -> None:
        self.init_db()
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute("DROP TABLE schema_meta")
            conn.commit()
        res = self.results(self.config())
        self.assertEqual(res["database"][0], "FAIL")
        self.assertIn("schema_meta", res["database"][1])

    def test_database_check_does_not_modify_the_file(self) -> None:
        self.init_db()
        before = _sha256(self.db_path)
        cfg = self.config()
        for _ in range(3):
            run_health_checks(cfg, self.repo)
        self.assertEqual(_sha256(self.db_path), before)
        leftovers = [p.name for p in self.db_path.parent.iterdir() if p.name != "dail.db"]
        self.assertEqual(leftovers, [], "no journal or WAL files may be left behind")

    def test_artifact_root_missing_fails(self) -> None:
        self.init_db()
        res = self.results(self.config())
        self.assertEqual(res["artifact_store"][0], "FAIL")
        self.assertIn("not found", res["artifact_store"][1])

    def test_artifact_root_present_and_writable_passes(self) -> None:
        self.artifacts.mkdir(parents=True)
        res = self.results(self.config())
        self.assertEqual(res["artifact_store"][0], "PASS")

    def test_artifact_root_that_is_a_file_fails(self) -> None:
        self.artifacts.parent.mkdir(parents=True)
        self.artifacts.write_text("not a directory")
        res = self.results(self.config())
        self.assertEqual(res["artifact_store"][0], "FAIL")

    def test_llm_provider_skipped_when_generation_disabled(self) -> None:
        res = self.results(self.config())
        self.assertEqual(res["llm_provider"][0], "SKIPPED")

    def test_llm_provider_passes_when_enabled_with_fake(self) -> None:
        cfg = self.config(dev_env="[llm]\ngeneration_enabled = true\n")
        self.assertIs(cfg.get("llm.generation_enabled"), True)
        res = self.results(cfg)
        self.assertEqual(res["llm_provider"][0], "PASS")

    def test_secret_values_never_appear_in_any_detail(self) -> None:
        self.init_db()
        self.artifacts.mkdir(parents=True)
        environ = {
            "CSX__LLM__API_KEY_REF": "env:DAIL_TEST_LLM_KEY",
            "DAIL_TEST_LLM_KEY": FAKE_SECRET,
        }
        cfg = self.config(dev_env="[llm]\ngeneration_enabled = true\n", environ=environ)
        self.assertEqual(cfg.get("llm.api_key_ref"), "env:DAIL_TEST_LLM_KEY")
        for result in run_health_checks(cfg, self.repo):
            with self.subTest(check=result.name):
                self.assertNotIn(FAKE_SECRET, result.detail)
                self.assertNotIn("DAIL_TEST_LLM_KEY", result.detail)

    def test_details_use_repository_relative_paths_only(self) -> None:
        self.init_db()
        self.artifacts.mkdir(parents=True)
        for result in run_health_checks(self.config(), self.repo):
            with self.subTest(check=result.name):
                self.assertNotIn(str(self.repo), result.detail)
                self.assertNotIn(str(self.repo.resolve()), result.detail)


if __name__ == "__main__":
    unittest.main()
