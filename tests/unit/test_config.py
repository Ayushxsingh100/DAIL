"""Configuration loader tests (Doc 14 §14-15, §17, §37-38; P0-close Step 6).

Standard-library unittest only. Every test builds its own temporary config
directory and passes an explicit ``environ`` mapping, so nothing depends on
the developer's shell.
"""

from __future__ import annotations

import dataclasses
import tempfile
import unittest
from collections.abc import Iterator, Mapping
from pathlib import Path

from core.application.config import (
    CONFIG_SCHEMA_VERSION,
    ENVIRONMENTS,
    SCHEMA,
    ConfigError,
    ResolvedConfig,
    load_config,
    resolve_secret,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

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
FAKE_SECRET = "sk-live-" + "0123456789abcdef" * 2


class TrackingEnviron(Mapping[str, str]):
    """A read-only environ that records every key the loader asks for."""

    def __init__(self, data: dict[str, str]) -> None:
        self._data = dict(data)
        self.accessed: set[str] = set()

    def __getitem__(self, key: str) -> str:
        self.accessed.add(key)
        return self._data[key]

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str):
            self.accessed.add(key)
        return key in self._data

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


class ConfigTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def make_config(
        self,
        base: dict[str, str | None] | None = None,
        envs: dict[str, str | None] | None = None,
        extra_base_files: dict[str, str] | None = None,
        name: str = "config",
    ) -> Path:
        """Write a config dir. A value of None in ``base``/``envs`` omits that file."""
        root = self.tmp / name
        (root / "base").mkdir(parents=True)
        (root / "environments").mkdir()
        merged_base: dict[str, str | None] = dict(BASE_FILES)
        merged_base.update(base or {})
        for area, text in merged_base.items():
            if text is not None:
                (root / "base" / f"{area}.toml").write_text(text)
        for fname, text in (extra_base_files or {}).items():
            (root / "base" / fname).write_text(text)
        merged_envs: dict[str, str | None] = {e: "# no overrides\n" for e in ENVIRONMENTS}
        merged_envs.update(envs or {})
        for env, text in merged_envs.items():
            if text is not None:
                (root / "environments" / f"{env}.toml").write_text(text)
        return root

    def assert_problem(self, err: ConfigError, *fragments: str) -> None:
        joined = "\n".join(err.problems)
        for fragment in fragments:
            self.assertIn(fragment, joined)

    def load_error(self, config_dir: Path, **kwargs: object) -> ConfigError:
        with self.assertRaises(ConfigError) as ctx:
            load_config(config_dir, **kwargs)  # type: ignore[arg-type]
        return ctx.exception


class TestDefaultsAndPrecedence(ConfigTestCase):
    def test_defaults_and_base_files_load(self) -> None:
        cfg = load_config(self.make_config(), environ={})
        self.assertEqual(cfg.environment, "dev")
        self.assertEqual(cfg.schema_version, CONFIG_SCHEMA_VERSION)
        self.assertEqual(cfg.get("database.path"), ".local/dail.db")
        self.assertEqual(cfg.get("artifact_store.root"), ".local/artifacts")
        self.assertIs(cfg.get("llm.generation_enabled"), False)
        self.assertEqual(cfg.get("llm.provider"), "fake")
        self.assertIsNone(cfg.get("llm.api_key_ref"))
        self.assertIs(cfg.get("promotion.automatic_enabled"), False)
        self.assertEqual(cfg.get("observability.log_level"), "INFO")
        self.assertEqual(cfg.sources["database.path"], "VERSIONED_FILE")
        self.assertEqual(cfg.sources["llm.api_key_ref"], "DEFAULT")
        self.assertEqual(set(cfg.values), {k.area for k in SCHEMA} | {"verification", "experiments"})

    def test_versioned_file_overrides_default(self) -> None:
        cfg = load_config(self.make_config(base={"observability": "# empty\n"}), environ={})
        self.assertEqual(cfg.get("observability.log_level"), "INFO")
        self.assertEqual(cfg.sources["observability.log_level"], "DEFAULT")
        cfg = load_config(self.make_config(base={"observability": 'log_level = "WARN"\n'},
                                           name="c2"), environ={})
        self.assertEqual(cfg.get("observability.log_level"), "WARN")
        self.assertEqual(cfg.sources["observability.log_level"], "VERSIONED_FILE")

    def test_environment_file_overrides_versioned_file(self) -> None:
        cfg_dir = self.make_config(envs={"test": '[observability]\nlog_level = "ERROR"\n'})
        cfg = load_config(cfg_dir, environment="test", environ={})
        self.assertEqual(cfg.get("observability.log_level"), "ERROR")
        self.assertEqual(cfg.sources["observability.log_level"], "ENVIRONMENT_FILE")

    def test_environment_variable_overrides_environment_file(self) -> None:
        cfg_dir = self.make_config(envs={"test": '[database]\npath = "from-env-file.db"\n'})
        cfg = load_config(
            cfg_dir, environment="test", environ={"CSX__DATABASE__PATH": "from-env-var.db"}
        )
        self.assertEqual(cfg.get("database.path"), "from-env-var.db")
        self.assertEqual(cfg.sources["database.path"], "ENVIRONMENT_VARIABLE")

    def test_runtime_override_overrides_environment_variable(self) -> None:
        cfg = load_config(
            self.make_config(),
            environ={"CSX__OBSERVABILITY__LOG_LEVEL": "WARN"},
            runtime_overrides={"observability.log_level": "TRACE"},
        )
        self.assertEqual(cfg.get("observability.log_level"), "TRACE")
        self.assertEqual(cfg.sources["observability.log_level"], "RUNTIME_OVERRIDE")


class TestEnvironmentSelection(ConfigTestCase):
    def test_explicit_argument_beats_csx_env(self) -> None:
        cfg = load_config(self.make_config(), environment="staging", environ={"CSX_ENV": "test"})
        self.assertEqual(cfg.environment, "staging")

    def test_csx_env_used_when_no_argument(self) -> None:
        cfg = load_config(self.make_config(), environ={"CSX_ENV": "experiment"})
        self.assertEqual(cfg.environment, "experiment")

    def test_default_environment_is_dev(self) -> None:
        self.assertEqual(load_config(self.make_config(), environ={}).environment, "dev")

    def test_production_is_rejected(self) -> None:
        err = self.load_error(self.make_config(), environment="production", environ={})
        self.assert_problem(err, "environment 'production' is not allowed")
        err = self.load_error(self.make_config(name="c2"), environ={"CSX_ENV": "production"})
        self.assert_problem(err, "environment 'production' is not allowed")

    def test_typo_environment_is_rejected(self) -> None:
        err = self.load_error(self.make_config(), environment="prod-typo", environ={})
        self.assert_problem(err, "environment 'prod-typo' is not allowed")


class TestRejectedInAnyLayer(ConfigTestCase):
    def test_unknown_key_in_base_file(self) -> None:
        cfg_dir = self.make_config(base={"database": 'path = "x.db"\npaht = "typo.db"\n'})
        self.assert_problem(self.load_error(cfg_dir, environ={}), "unknown key 'database.paht'")

    def test_unknown_key_in_environment_file(self) -> None:
        cfg_dir = self.make_config(envs={"dev": "[promotion]\nautomatic_enable = true\n"})
        self.assert_problem(
            self.load_error(cfg_dir, environ={}), "unknown key 'promotion.automatic_enable'"
        )

    def test_unknown_key_in_environment_variable(self) -> None:
        err = self.load_error(self.make_config(), environ={"CSX__DATABASE__PAHT": "x.db"})
        self.assert_problem(err, "unknown key 'database.paht'")

    def test_unknown_key_in_runtime_override(self) -> None:
        err = self.load_error(
            self.make_config(), environ={}, runtime_overrides={"observability.level": "INFO"}
        )
        self.assert_problem(err, "unknown key 'observability.level'")

    def test_unknown_area_in_environment_file(self) -> None:
        cfg_dir = self.make_config(envs={"dev": '[observabilty]\nlog_level = "DEBUG"\n'})
        self.assert_problem(self.load_error(cfg_dir, environ={}), "unknown area 'observabilty'")

    def test_unknown_area_in_environment_variable(self) -> None:
        err = self.load_error(self.make_config(), environ={"CSX__DATABSE__PATH": "x.db"})
        self.assert_problem(err, "unknown area 'databse'")

    def test_unknown_base_file(self) -> None:
        cfg_dir = self.make_config(extra_base_files={"databse.toml": 'path = "x.db"\n'})
        self.assert_problem(
            self.load_error(cfg_dir, environ={}),
            "base/databse.toml: unknown base configuration file",
        )

    def test_missing_base_file(self) -> None:
        cfg_dir = self.make_config(base={"promotion": None})
        self.assert_problem(
            self.load_error(cfg_dir, environ={}),
            "base/promotion.toml: missing base configuration file",
        )

    def test_missing_environment_file(self) -> None:
        cfg_dir = self.make_config(envs={"staging": None})
        self.assert_problem(
            self.load_error(cfg_dir, environment="staging", environ={}),
            "environments/staging.toml: missing environment configuration file",
        )

    def test_toml_syntax_error_in_base_file(self) -> None:
        cfg_dir = self.make_config(base={"database": 'path = ".local/dail.db\n'})
        self.assert_problem(
            self.load_error(cfg_dir, environ={}), "base/database.toml: TOML parse error"
        )

    def test_toml_syntax_error_in_environment_file(self) -> None:
        cfg_dir = self.make_config(envs={"dev": "[observability\nlog_level = 'DEBUG'\n"})
        self.assert_problem(
            self.load_error(cfg_dir, environ={}), "environments/dev.toml: TOML parse error"
        )

    def test_stray_csx_variable_is_rejected(self) -> None:
        err = self.load_error(self.make_config(), environ={"CSX_FOO": "1"})
        self.assert_problem(err, "environment variable CSX_FOO: unrecognized CSX_ variable")

    def test_malformed_csx_key_variable_is_rejected(self) -> None:
        # Single underscore between area and key: a typo that would otherwise be ignored.
        err = self.load_error(self.make_config(), environ={"CSX__PROMOTION_AUTOMATIC_ENABLED": "false"})
        self.assert_problem(err, "CSX__PROMOTION_AUTOMATIC_ENABLED: unrecognized CSX_ variable")


class TestTypes(ConfigTestCase):
    def test_bool_string_yes_is_rejected(self) -> None:
        err = self.load_error(self.make_config(), environ={"CSX__LLM__GENERATION_ENABLED": "yes"})
        self.assert_problem(err, "llm.generation_enabled: expected exactly 'true' or 'false'")

    def test_bool_strings_other_than_true_false_are_rejected(self) -> None:
        for raw in ("True", "FALSE", "1", "0", ""):
            with self.subTest(raw=raw):
                err = self.load_error(
                    self.make_config(name=f"c-{raw or 'empty'}"),
                    environ={"CSX__PROMOTION__AUTOMATIC_ENABLED": raw},
                )
                self.assert_problem(err, "promotion.automatic_enabled: expected exactly")

    def test_int_string_1a_is_rejected(self) -> None:
        err = self.load_error(
            self.make_config(), environ={"CSX__APPLICATION__CONFIG_SCHEMA_VERSION": "1a"}
        )
        self.assert_problem(err, "application.config_schema_version: expected a plain")

    def test_int_as_toml_string_is_rejected(self) -> None:
        cfg_dir = self.make_config(base={"application": 'config_schema_version = "1"\n'})
        self.assert_problem(
            self.load_error(cfg_dir, environ={}),
            "application.config_schema_version: expected an integer",
        )

    def test_bool_as_toml_string_is_rejected(self) -> None:
        cfg_dir = self.make_config(base={"promotion": 'automatic_enabled = "false"\n'})
        self.assert_problem(
            self.load_error(cfg_dir, environ={}), "promotion.automatic_enabled: expected a boolean"
        )

    def test_enum_value_outside_allowed_set_is_rejected(self) -> None:
        err = self.load_error(self.make_config(), environ={"CSX__OBSERVABILITY__LOG_LEVEL": "VERBOSE"})
        self.assert_problem(err, "observability.log_level: expected one of ERROR, WARN, INFO")
        cfg_dir = self.make_config(base={"llm": 'generation_enabled = false\nprovider = "openai"\n'},
                                   name="c2")
        self.assert_problem(
            self.load_error(cfg_dir, environ={}), "llm.provider: expected one of fake"
        )


class TestSecrets(ConfigTestCase):
    def test_literal_secret_is_rejected_and_never_echoed(self) -> None:
        err = self.load_error(self.make_config(), environ={"CSX__LLM__API_KEY_REF": FAKE_SECRET})
        self.assert_problem(err, "llm.api_key_ref: expected a secret reference of the form env:NAME")
        self.assertNotIn(FAKE_SECRET, str(err))
        self.assertNotIn(FAKE_SECRET, "\n".join(err.problems))

    def test_env_reference_is_stored_and_the_secret_is_never_read(self) -> None:
        environ = TrackingEnviron({"CSX__LLM__API_KEY_REF": "env:CSX_LLM_API_KEY"})
        cfg = load_config(self.make_config(), environ=environ)
        self.assertEqual(cfg.get("llm.api_key_ref"), "env:CSX_LLM_API_KEY")
        self.assertEqual(cfg.sources["llm.api_key_ref"], "ENVIRONMENT_VARIABLE")
        self.assertNotIn("CSX_LLM_API_KEY", environ.accessed)

    def test_resolve_secret_returns_the_environment_value(self) -> None:
        value = resolve_secret("env:DAIL_TEST_KEY", environ={"DAIL_TEST_KEY": FAKE_SECRET})
        self.assertEqual(value, FAKE_SECRET)

    def test_resolve_secret_fails_when_variable_missing(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            resolve_secret("env:DAIL_TEST_KEY", environ={})
        self.assert_problem(ctx.exception, "environment variable DAIL_TEST_KEY is not set")

    def test_resolve_secret_rejects_malformed_reference(self) -> None:
        with self.assertRaises(ConfigError):
            resolve_secret(FAKE_SECRET, environ={})


class TestSchemaVersion(ConfigTestCase):
    def test_mismatch_is_rejected(self) -> None:
        cfg_dir = self.make_config(base={"application": "config_schema_version = 2\n"})
        self.assert_problem(
            self.load_error(cfg_dir, environ={}), "does not match the loader's CONFIG_SCHEMA_VERSION"
        )

    def test_set_from_environment_file_is_rejected(self) -> None:
        cfg_dir = self.make_config(envs={"dev": "[application]\nconfig_schema_version = 1\n"})
        self.assert_problem(
            self.load_error(cfg_dir, environ={}),
            "environments/dev.toml: application.config_schema_version may only be set in "
            "config/base/application.toml",
        )

    def test_set_from_environment_variable_is_rejected(self) -> None:
        err = self.load_error(
            self.make_config(), environ={"CSX__APPLICATION__CONFIG_SCHEMA_VERSION": "1"}
        )
        self.assert_problem(err, "may only be set in config/base/application.toml")


class TestRuntimeOverrides(ConfigTestCase):
    def test_log_level_override_is_applied_and_recorded(self) -> None:
        cfg = load_config(
            self.make_config(), environ={}, runtime_overrides={"observability.log_level": "TRACE"}
        )
        self.assertEqual(cfg.get("observability.log_level"), "TRACE")
        self.assertEqual(cfg.overrides_applied, ("observability.log_level",))

    def test_override_of_any_other_key_is_rejected(self) -> None:
        valid_values: dict[str, object] = {
            "application.config_schema_version": 1,
            "database.path": "other.db",
            "artifact_store.root": "other-artifacts",
            "llm.generation_enabled": False,
            "llm.provider": "fake",
            "llm.api_key_ref": "env:DAIL_TEST_KEY",
            "promotion.automatic_enabled": False,
        }
        others = {k.dotted for k in SCHEMA if not k.runtime_overridable}
        self.assertEqual(set(valid_values), others)
        for dotted, value in valid_values.items():
            with self.subTest(key=dotted):
                err = self.load_error(
                    self.make_config(name=f"c-{dotted}"),
                    environ={},
                    runtime_overrides={dotted: value},
                )
                self.assert_problem(err, f"{dotted} is not runtime-overridable")


class TestSafetyFlags(ConfigTestCase):
    FLAGS = (
        ("promotion.automatic_enabled", "CSX__PROMOTION__AUTOMATIC_ENABLED", "promotion",
         "automatic_enabled"),
        ("llm.generation_enabled", "CSX__LLM__GENERATION_ENABLED", "llm", "generation_enabled"),
    )

    def test_enabling_by_environment_variable_is_rejected(self) -> None:
        for dotted, var, _area, _name in self.FLAGS:
            with self.subTest(flag=dotted):
                err = self.load_error(self.make_config(name=f"c-{var}"), environ={var: "true"})
                self.assert_problem(
                    err,
                    f"safety-critical flag {dotted} can only be enabled in a reviewed "
                    "configuration file",
                )

    def test_disabling_by_environment_variable_is_accepted(self) -> None:
        for dotted, var, area, name in self.FLAGS:
            with self.subTest(flag=dotted):
                # Enabled in the reviewed environment file, then stopped by the env var.
                cfg_dir = self.make_config(
                    envs={"dev": f"[{area}]\n{name} = true\n"}, name=f"c-{var}"
                )
                cfg = load_config(cfg_dir, environ={var: "false"})
                self.assertIs(cfg.safety_flags()[dotted], False)
                self.assertEqual(cfg.sources[dotted], "ENVIRONMENT_VARIABLE")

    def test_enabling_in_environment_file_is_accepted(self) -> None:
        for dotted, _var, area, name in self.FLAGS:
            with self.subTest(flag=dotted):
                cfg_dir = self.make_config(
                    envs={"experiment": f"[{area}]\n{name} = true\n"}, name=f"c-{area}"
                )
                cfg = load_config(cfg_dir, environment="experiment", environ={})
                self.assertIs(cfg.safety_flags()[dotted], True)

    def test_enabling_by_runtime_override_is_rejected(self) -> None:
        for dotted, _var, area, _name in self.FLAGS:
            with self.subTest(flag=dotted):
                err = self.load_error(
                    self.make_config(name=f"c-{area}"),
                    environ={},
                    runtime_overrides={dotted: True},
                )
                self.assert_problem(err, f"safety-critical flag {dotted} can only be enabled")

    def test_safety_flags_default_to_conservative(self) -> None:
        cfg = load_config(self.make_config(base={"llm": 'provider = "fake"\n',
                                                 "promotion": "# empty\n"}), environ={})
        self.assertEqual(
            cfg.safety_flags(),
            {"llm.generation_enabled": False, "promotion.automatic_enabled": False},
        )


class TestErrorsHashesAndImmutability(ConfigTestCase):
    def test_all_problems_are_reported_together(self) -> None:
        cfg_dir = self.make_config(base={"promotion": None})
        err = self.load_error(
            cfg_dir,
            environ={"CSX_FOO": "1", "CSX__OBSERVABILITY__LOG_LEVEL": "LOUD"},
        )
        self.assertEqual(len(err.problems), 3)
        self.assert_problem(
            err,
            "base/promotion.toml: missing base configuration file",
            "CSX_FOO: unrecognized CSX_ variable",
            "observability.log_level: expected one of",
        )
        self.assertEqual(list(err.problems), sorted(err.problems))

    def test_config_hash_is_stable_across_repeated_loads(self) -> None:
        cfg_dir = self.make_config()
        hashes = {load_config(cfg_dir, environ={}).config_hash for _ in range(5)}
        self.assertEqual(len(hashes), 1)

    def test_config_hash_ignores_key_order_in_toml(self) -> None:
        a = self.make_config(
            base={"llm": 'generation_enabled = false\nprovider = "fake"\n'}, name="a"
        )
        b = self.make_config(
            base={"llm": 'provider = "fake"\ngeneration_enabled = false\n'}, name="b"
        )
        self.assertEqual(
            load_config(a, environ={}).config_hash, load_config(b, environ={}).config_hash
        )

    def test_config_hash_changes_when_any_value_changes(self) -> None:
        base_hash = load_config(self.make_config(), environ={}).config_hash
        variants = {
            "db": {"database": 'path = "other.db"\n'},
            "art": {"artifact_store": 'root = "other"\n'},
            "log": {"observability": 'log_level = "WARN"\n'},
        }
        for label, base in variants.items():
            with self.subTest(change=label):
                other = load_config(self.make_config(base=base, name=label), environ={})
                self.assertNotEqual(other.config_hash, base_hash)
        env_changed = load_config(self.make_config(name="env"), environment="test", environ={})
        self.assertNotEqual(env_changed.config_hash, base_hash)
        flag_on = load_config(
            self.make_config(envs={"dev": "[promotion]\nautomatic_enabled = true\n"}, name="f"),
            environ={},
        )
        self.assertNotEqual(flag_on.config_hash, base_hash)

    def test_values_cannot_be_mutated(self) -> None:
        cfg = load_config(self.make_config(), environ={})
        with self.assertRaises(TypeError):
            cfg.values["promotion"]["automatic_enabled"] = True  # type: ignore[index]
        with self.assertRaises(TypeError):
            cfg.values["promotion"] = {}  # type: ignore[index]
        with self.assertRaises(TypeError):
            cfg.sources["promotion.automatic_enabled"] = "RUNTIME_OVERRIDE"  # type: ignore[index]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            cfg.environment = "staging"  # type: ignore[misc]
        self.assertIs(cfg.get("promotion.automatic_enabled"), False)

    def test_run_metadata_has_exactly_five_fields(self) -> None:
        cfg = load_config(self.make_config(), environ={})
        meta = cfg.run_metadata()
        self.assertEqual(
            set(meta),
            {"environment", "schema_version", "config_hash", "safety_flags", "overrides_applied"},
        )
        self.assertEqual(meta["config_hash"], cfg.config_hash)
        self.assertEqual(meta["safety_flags"], cfg.safety_flags())

    def test_get_unknown_key_raises(self) -> None:
        cfg = load_config(self.make_config(), environ={})
        with self.assertRaises(KeyError):
            cfg.get("promotion.nonexistent")


class TestRepositoryConfig(unittest.TestCase):
    def test_real_config_loads_for_all_four_environments(self) -> None:
        for env in ENVIRONMENTS:
            with self.subTest(environment=env):
                cfg = load_config(REPO_ROOT / "config", environment=env, environ={})
                self.assertIsInstance(cfg, ResolvedConfig)
                self.assertEqual(
                    cfg.safety_flags(),
                    {"llm.generation_enabled": False, "promotion.automatic_enabled": False},
                )


if __name__ == "__main__":
    unittest.main()
