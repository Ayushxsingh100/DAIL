"""Validated, fail-closed configuration (Doc 14 §14-15, §17, §37-38).

Configuration is data under ``config/``; this module is the only code that
reads it. Standard library only (``tomllib``, ``dataclasses``,
``types.MappingProxyType``).

Precedence (Doc 14 §15), later layers override earlier ones:

1. ``DEFAULT``              built-in schema defaults
2. ``VERSIONED_FILE``       ``config/base/<area>.toml`` (flat keys, no header)
3. ``ENVIRONMENT_FILE``     ``config/environments/<env>.toml`` (``[area]`` tables)
4. ``ENVIRONMENT_VARIABLE`` ``CSX__<AREA>__<KEY>`` (also where secret references go)
5. ``RUNTIME_OVERRIDE``     ``runtime_overrides``; only keys marked runtime-overridable

Fail-closed: every problem in every layer is collected, and a single
``ConfigError`` listing all of them is raised. Nothing falls back to a
permissive value (Doc 14 §15). Problem messages name keys, layers and files,
never the offending value, so a misplaced secret is never echoed.

Safety-flag rule (N-07, an interpretation of Doc 14 §15 and §37): a
safety-critical flag may be set to its conservative value from any layer that
accepts the key (that is the emergency stop), but may be set to its
non-conservative value only in a reviewed configuration file.

Secrets: a ``secret_ref`` value is a reference of the form ``env:NAME``. The
loader validates and stores the reference string only; it never reads or
stores the secret. ``resolve_secret`` reads the referenced variable at use time.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from core.domain.hashing import content_hash

CONFIG_SCHEMA_VERSION: int = 1

AREAS: tuple[str, ...] = (
    "application",
    "database",
    "artifact_store",
    "llm",
    "verification",
    "promotion",
    "experiments",
    "observability",
)
ENVIRONMENTS: tuple[str, ...] = ("dev", "test", "experiment", "staging")
DEFAULT_ENVIRONMENT = "dev"
ENV_SELECTOR_VARIABLE = "CSX_ENV"
ENV_VARIABLE_PREFIX = "CSX_"
ENV_KEY_PREFIX = "CSX__"
LOG_LEVELS: tuple[str, ...] = ("ERROR", "WARN", "INFO", "DEBUG", "TRACE")  # Doc 11 §15

BASE_DIR_NAME = "base"
ENVIRONMENTS_DIR_NAME = "environments"
SCHEMA_VERSION_KEY = "application.config_schema_version"

_SECRET_REF_PATTERN = re.compile(r"env:[A-Z][A-Z0-9_]*")
_ENV_SEGMENT_PATTERN = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*")
_DIGITS_PATTERN = re.compile(r"[0-9]+")


class ConfigLayer(str, Enum):
    """Configuration layers in precedence order (Doc 14 §15)."""

    DEFAULT = "DEFAULT"
    VERSIONED_FILE = "VERSIONED_FILE"
    ENVIRONMENT_FILE = "ENVIRONMENT_FILE"
    ENVIRONMENT_VARIABLE = "ENVIRONMENT_VARIABLE"
    RUNTIME_OVERRIDE = "RUNTIME_OVERRIDE"


class ValueType(str, Enum):
    INT = "int"
    BOOL = "bool"
    PATH = "path"
    ENUM = "enum"
    SECRET_REF = "secret_ref"


@dataclass(frozen=True)
class ConfigKey:
    """One schema entry. ``conservative_value`` is meaningful only when safety-critical."""

    area: str
    name: str
    type: ValueType
    default: Any
    safety_critical: bool
    conservative_value: Any
    runtime_overridable: bool
    allowed: tuple[str, ...] | None
    spec_ref: str

    @property
    def dotted(self) -> str:
        return f"{self.area}.{self.name}"


SCHEMA: tuple[ConfigKey, ...] = (
    ConfigKey(
        area="application",
        name="config_schema_version",
        type=ValueType.INT,
        default=CONFIG_SCHEMA_VERSION,
        safety_critical=False,
        conservative_value=None,
        runtime_overridable=False,
        allowed=None,
        spec_ref="Doc 14 §14-15",
    ),
    ConfigKey(
        area="database",
        name="path",
        type=ValueType.PATH,
        default=".local/dail.db",
        safety_critical=False,
        conservative_value=None,
        runtime_overridable=False,
        allowed=None,
        spec_ref="Doc 14 §12, §14",
    ),
    ConfigKey(
        area="artifact_store",
        name="root",
        type=ValueType.PATH,
        default=".local/artifacts",
        safety_critical=False,
        conservative_value=None,
        runtime_overridable=False,
        allowed=None,
        spec_ref="Doc 14 §13-14",
    ),
    ConfigKey(
        area="llm",
        name="generation_enabled",
        type=ValueType.BOOL,
        default=False,
        safety_critical=True,
        conservative_value=False,
        runtime_overridable=False,
        allowed=None,
        spec_ref="Doc 14 §37-38",
    ),
    ConfigKey(
        area="llm",
        name="provider",
        type=ValueType.ENUM,
        default="fake",
        safety_critical=False,
        conservative_value=None,
        runtime_overridable=False,
        allowed=("fake",),
        spec_ref="Doc 01 FR-LLM-006; Doc 14 §12",
    ),
    ConfigKey(
        area="llm",
        name="api_key_ref",
        type=ValueType.SECRET_REF,
        default=None,
        safety_critical=False,
        conservative_value=None,
        runtime_overridable=False,
        allowed=None,
        spec_ref="Doc 14 §16",
    ),
    ConfigKey(
        area="promotion",
        name="automatic_enabled",
        type=ValueType.BOOL,
        default=False,
        safety_critical=True,
        conservative_value=False,
        runtime_overridable=False,
        allowed=None,
        spec_ref="Doc 14 §37-38",
    ),
    ConfigKey(
        area="observability",
        name="log_level",
        type=ValueType.ENUM,
        default="INFO",
        safety_critical=False,
        conservative_value=None,
        runtime_overridable=True,
        allowed=LOG_LEVELS,
        spec_ref="Doc 11 §15",
    ),
)

_SCHEMA_BY_KEY: dict[str, ConfigKey] = {k.dotted: k for k in SCHEMA}


class ConfigError(Exception):
    """Raised once, with every problem found, when configuration is unsafe or invalid."""

    problems: tuple[str, ...]

    def __init__(self, problems: Iterable[str]) -> None:
        self.problems = tuple(sorted(set(problems)))
        super().__init__("invalid configuration: " + "; ".join(self.problems))


@dataclass(frozen=True)
class ResolvedConfig:
    """The validated result of ``load_config``. Read-only."""

    environment: str
    schema_version: int
    values: Mapping[str, Mapping[str, Any]]
    sources: Mapping[str, str]
    overrides_applied: tuple[str, ...]

    def get(self, dotted_key: str) -> Any:
        area, sep, name = dotted_key.partition(".")
        if not sep or area not in self.values or name not in self.values[area]:
            raise KeyError(dotted_key)
        return self.values[area][name]

    def safety_flags(self) -> dict[str, bool]:
        return {k.dotted: bool(self.get(k.dotted)) for k in SCHEMA if k.safety_critical}

    @property
    def config_hash(self) -> str:
        return content_hash(
            {
                "schema_version": self.schema_version,
                "environment": self.environment,
                "values": {area: dict(keys) for area, keys in self.values.items()},
            }
        )

    def run_metadata(self) -> dict[str, Any]:
        """Active configuration for run/deployment metadata (Doc 14 §38)."""
        return {
            "environment": self.environment,
            "schema_version": self.schema_version,
            "config_hash": self.config_hash,
            "safety_flags": self.safety_flags(),
            "overrides_applied": list(self.overrides_applied),
        }


def _expected(key: ConfigKey, from_environment_variable: bool) -> str:
    if key.type is ValueType.BOOL:
        return "exactly 'true' or 'false'" if from_environment_variable else "a boolean"
    if key.type is ValueType.INT:
        if from_environment_variable:
            return "a plain non-negative integer (digits only)"
        return "an integer"
    if key.type is ValueType.PATH:
        return "a non-empty path string"
    if key.type is ValueType.ENUM:
        return "one of " + ", ".join(key.allowed or ())
    return "a secret reference of the form env:NAME (literal secrets are never accepted)"


def _coerce(key: ConfigKey, raw: object, from_environment_variable: bool) -> tuple[bool, Any]:
    """Return (ok, value). Environment variables arrive as strings and are parsed strictly."""
    if from_environment_variable:
        if not isinstance(raw, str):
            return False, None
        if key.type is ValueType.BOOL:
            if raw == "true":
                return True, True
            if raw == "false":
                return True, False
            return False, None
        if key.type is ValueType.INT:
            if _DIGITS_PATTERN.fullmatch(raw):
                return True, int(raw)
            return False, None
    if key.type is ValueType.BOOL:
        return (True, raw) if isinstance(raw, bool) else (False, None)
    if key.type is ValueType.INT:
        ok = isinstance(raw, int) and not isinstance(raw, bool)
        return (True, raw) if ok else (False, None)
    if key.type is ValueType.PATH:
        return (True, raw) if isinstance(raw, str) and raw != "" else (False, None)
    if key.type is ValueType.ENUM:
        ok = isinstance(raw, str) and raw in (key.allowed or ())
        return (True, raw) if ok else (False, None)
    ok = isinstance(raw, str) and _SECRET_REF_PATTERN.fullmatch(raw) is not None
    return (True, raw) if ok else (False, None)


class _Loader:
    def __init__(self) -> None:
        self.problems: list[str] = []
        self.values: dict[str, dict[str, Any]] = {area: {} for area in AREAS}
        self.sources: dict[str, str] = {}
        self.overrides_applied: list[str] = []
        for key in SCHEMA:
            self.values[key.area][key.name] = key.default
            self.sources[key.dotted] = ConfigLayer.DEFAULT.value

    def apply(self, key: ConfigKey, raw: object, layer: ConfigLayer, where: str) -> bool:
        from_env = layer is ConfigLayer.ENVIRONMENT_VARIABLE
        ok = True
        if key.dotted == SCHEMA_VERSION_KEY and layer is not ConfigLayer.VERSIONED_FILE:
            self.problems.append(
                f"{where}: {key.dotted} may only be set in config/base/application.toml"
            )
            ok = False
        if layer is ConfigLayer.RUNTIME_OVERRIDE and not key.runtime_overridable:
            self.problems.append(f"{where}: {key.dotted} is not runtime-overridable")
            ok = False
        valid, value = _coerce(key, raw, from_env)
        if not valid:
            self.problems.append(f"{where}: {key.dotted}: expected {_expected(key, from_env)}")
            return False
        if (
            key.safety_critical
            and value != key.conservative_value
            and layer in (ConfigLayer.ENVIRONMENT_VARIABLE, ConfigLayer.RUNTIME_OVERRIDE)
        ):
            self.problems.append(
                f"{where}: safety-critical flag {key.dotted} can only be enabled in a "
                "reviewed configuration file"
            )
            ok = False
        if (
            key.dotted == SCHEMA_VERSION_KEY
            and layer is ConfigLayer.VERSIONED_FILE
            and value != CONFIG_SCHEMA_VERSION
        ):
            self.problems.append(
                f"{where}: {key.dotted} does not match the loader's "
                f"CONFIG_SCHEMA_VERSION ({CONFIG_SCHEMA_VERSION})"
            )
            ok = False
        if not ok:
            return False
        self.values[key.area][key.name] = value
        self.sources[key.dotted] = layer.value
        return True

    def read_toml(self, path: Path, where: str) -> dict[str, Any] | None:
        try:
            with path.open("rb") as handle:
                return tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            self.problems.append(f"{where}: TOML parse error: {exc}")
        except OSError as exc:
            self.problems.append(f"{where}: cannot read file ({exc.strerror})")
        return None

    def load_base_files(self, config_dir: Path) -> None:
        base_dir = config_dir / BASE_DIR_NAME
        expected_names = {f"{area}.toml" for area in AREAS}
        present: set[str] = set()
        if base_dir.is_dir():
            for entry in sorted(base_dir.iterdir()):
                if entry.name.startswith("."):
                    continue
                if entry.name not in expected_names or not entry.is_file():
                    self.problems.append(
                        f"{BASE_DIR_NAME}/{entry.name}: unknown base configuration file "
                        f"(expected one of: {', '.join(sorted(expected_names))})"
                    )
                    continue
                present.add(entry.name)
        for area in AREAS:
            name = f"{area}.toml"
            where = f"{BASE_DIR_NAME}/{name}"
            if name not in present:
                self.problems.append(f"{where}: missing base configuration file")
                continue
            data = self.read_toml(base_dir / name, where)
            if data is None:
                continue
            for key_name in sorted(data):
                key = _SCHEMA_BY_KEY.get(f"{area}.{key_name}")
                if key is None:
                    self.problems.append(f"{where}: unknown key '{area}.{key_name}'")
                    continue
                self.apply(key, data[key_name], ConfigLayer.VERSIONED_FILE, where)

    def load_environment_file(self, config_dir: Path, environment: str) -> None:
        where = f"{ENVIRONMENTS_DIR_NAME}/{environment}.toml"
        path = config_dir / ENVIRONMENTS_DIR_NAME / f"{environment}.toml"
        if not path.is_file():
            self.problems.append(f"{where}: missing environment configuration file")
            return
        data = self.read_toml(path, where)
        if data is None:
            return
        for area in sorted(data):
            if area not in AREAS:
                self.problems.append(f"{where}: unknown area '{area}'")
                continue
            table = data[area]
            if not isinstance(table, dict):
                self.problems.append(f"{where}: area '{area}' must be a [{area}] table")
                continue
            for key_name in sorted(table):
                key = _SCHEMA_BY_KEY.get(f"{area}.{key_name}")
                if key is None:
                    self.problems.append(f"{where}: unknown key '{area}.{key_name}'")
                    continue
                self.apply(key, table[key_name], ConfigLayer.ENVIRONMENT_FILE, where)

    def load_environment_variables(self, environ: Mapping[str, str]) -> None:
        for name in sorted(environ):
            if not name.startswith(ENV_VARIABLE_PREFIX) or name == ENV_SELECTOR_VARIABLE:
                continue
            parts = name[len(ENV_KEY_PREFIX) :].split("__")
            well_formed = (
                name.startswith(ENV_KEY_PREFIX)
                and len(parts) == 2
                and all(_ENV_SEGMENT_PATTERN.fullmatch(p) for p in parts)
            )
            if not well_formed:
                self.problems.append(
                    f"environment variable {name}: unrecognized CSX_ variable (only "
                    f"{ENV_SELECTOR_VARIABLE} and CSX__<AREA>__<KEY> are accepted)"
                )
                continue
            area, key_name = parts[0].lower(), parts[1].lower()
            if area not in AREAS:
                self.problems.append(f"environment variable {name}: unknown area '{area}'")
                continue
            key = _SCHEMA_BY_KEY.get(f"{area}.{key_name}")
            if key is None:
                self.problems.append(
                    f"environment variable {name}: unknown key '{area}.{key_name}'"
                )
                continue
            self.apply(
                key, environ[name], ConfigLayer.ENVIRONMENT_VARIABLE, f"environment variable {name}"
            )

    def load_runtime_overrides(self, runtime_overrides: Mapping[str, object]) -> None:
        for dotted in sorted(runtime_overrides):
            where = f"runtime override {dotted}"
            key = _SCHEMA_BY_KEY.get(dotted)
            if key is None:
                self.problems.append(f"{where}: unknown key '{dotted}'")
                continue
            if self.apply(key, runtime_overrides[dotted], ConfigLayer.RUNTIME_OVERRIDE, where):
                self.overrides_applied.append(dotted)


def _select_environment(
    environment: str | None, environ: Mapping[str, str], problems: list[str]
) -> str | None:
    if environment is not None:
        selected = environment
    elif ENV_SELECTOR_VARIABLE in environ:
        selected = environ[ENV_SELECTOR_VARIABLE]
    else:
        selected = DEFAULT_ENVIRONMENT
    if selected not in ENVIRONMENTS:
        problems.append(
            f"environment '{selected}' is not allowed (allowed: {', '.join(ENVIRONMENTS)})"
        )
        return None
    return selected


def load_config(
    config_dir: Path,
    environment: str | None = None,
    environ: Mapping[str, str] | None = None,
    runtime_overrides: Mapping[str, object] | None = None,
) -> ResolvedConfig:
    """Load, merge and validate configuration. Deterministic for identical inputs.

    ``environ`` defaults to ``os.environ``; tests pass an explicit mapping.
    Raises ``ConfigError`` listing every problem found.
    """
    env_map: Mapping[str, str] = os.environ if environ is None else environ
    loader = _Loader()
    selected = _select_environment(environment, env_map, loader.problems)
    loader.load_base_files(Path(config_dir))
    if selected is not None:
        loader.load_environment_file(Path(config_dir), selected)
    loader.load_environment_variables(env_map)
    loader.load_runtime_overrides(runtime_overrides or {})
    if loader.problems or selected is None:
        raise ConfigError(loader.problems)
    frozen_values = MappingProxyType(
        {area: MappingProxyType(dict(keys)) for area, keys in loader.values.items()}
    )
    return ResolvedConfig(
        environment=selected,
        schema_version=int(loader.values["application"]["config_schema_version"]),
        values=frozen_values,
        sources=MappingProxyType(dict(loader.sources)),
        overrides_applied=tuple(sorted(loader.overrides_applied)),
    )


def resolve_secret(ref: str, environ: Mapping[str, str] | None = None) -> str:
    """Read the secret that ``ref`` (``env:NAME``) points to, at use time.

    Raises ``ConfigError`` if the reference is malformed or the variable is
    missing or empty. The error never contains the secret value.
    """
    env_map: Mapping[str, str] = os.environ if environ is None else environ
    if not isinstance(ref, str) or _SECRET_REF_PATTERN.fullmatch(ref) is None:
        raise ConfigError(["secret reference must have the form env:NAME"])
    name = ref[len("env:") :]
    value = env_map.get(name)
    if not value:
        raise ConfigError([f"secret reference {ref}: environment variable {name} is not set"])
    return value
