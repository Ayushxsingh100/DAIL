"""Health checks (Doc 14 §30).

Five checks: liveness, readiness, database, artifact_store, llm_provider.
They never write, never touch the network, and never include secret values,
environment-variable values or absolute machine paths in their output
("Health checks must not expose secrets or sensitive infrastructure details").
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from core.application.config import ResolvedConfig

PASS = "PASS"
FAIL = "FAIL"
SKIPPED = "SKIPPED"

# Every table created by LocalStorage.initialize_schema() (core/domain/storage.py)
# and EvidenceStore.initialize_schema() (evidence/store.py). tests/unit/test_health.py
# checks this constant against the real DDL.
EXPECTED_TABLES: frozenset[str] = frozenset(
    {
        # core/domain/storage.py
        "trusted_state",
        "candidate_state",
        "invariant",
        "schema_meta",
        # evidence/store.py
        "evidence_payload",
        "evidence_record",
        "validity_transition",
        "evidence_supersession",
        "audit_event",
    }
)


@dataclass(frozen=True)
class HealthCheckResult:
    name: str  # liveness | readiness | database | artifact_store | llm_provider
    status: str  # PASS | FAIL | SKIPPED
    detail: str  # secret-free, repository-relative paths only


def _display_path(configured: str, resolved: Path, repo_root: Path) -> str:
    """Repository-relative display; never reveal an absolute path outside the repository."""
    if not Path(configured).is_absolute():
        return configured
    try:
        return resolved.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return "<absolute path outside the repository>"


def _check_database(config: ResolvedConfig, repo_root: Path) -> HealthCheckResult:
    configured = str(config.get("database.path"))
    path = repo_root / configured
    shown = _display_path(configured, path, repo_root)
    if not path.is_file():
        return HealthCheckResult("database", FAIL, f"database file not found: {shown}")
    uri = f"{path.resolve().as_uri()}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
    except sqlite3.Error as exc:
        return HealthCheckResult(
            "database", FAIL, f"cannot open {shown} read-only ({type(exc).__name__})"
        )
    if integrity is None or integrity[0] != "ok":
        return HealthCheckResult("database", FAIL, f"integrity_check failed for {shown}")
    missing = sorted(EXPECTED_TABLES - tables)
    if missing:
        return HealthCheckResult(
            "database", FAIL, f"{shown} is missing tables: {', '.join(missing)}"
        )
    return HealthCheckResult(
        "database",
        PASS,
        f"{shown}: opened read-only, integrity ok, {len(EXPECTED_TABLES)} expected tables present",
    )


def _check_artifact_store(config: ResolvedConfig, repo_root: Path) -> HealthCheckResult:
    configured = str(config.get("artifact_store.root"))
    path = repo_root / configured
    shown = _display_path(configured, path, repo_root)
    if not path.exists():
        return HealthCheckResult("artifact_store", FAIL, f"artifact root not found: {shown}")
    if not path.is_dir():
        return HealthCheckResult("artifact_store", FAIL, f"artifact root is not a directory: {shown}")
    if not os.access(path, os.W_OK):
        return HealthCheckResult("artifact_store", FAIL, f"artifact root is not writable: {shown}")
    return HealthCheckResult("artifact_store", PASS, f"{shown}: directory exists and is writable")


def _check_llm_provider(config: ResolvedConfig) -> HealthCheckResult:
    if not config.get("llm.generation_enabled"):
        return HealthCheckResult(
            "llm_provider", SKIPPED, "LLM generation disabled (llm.generation_enabled = false)"
        )
    provider = config.get("llm.provider")
    if provider == "fake":
        return HealthCheckResult(
            "llm_provider", PASS, "provider 'fake' (deterministic, offline; no network access)"
        )
    return HealthCheckResult("llm_provider", FAIL, "configured LLM provider is not supported")


def run_health_checks(config: ResolvedConfig, repo_root: Path) -> tuple[HealthCheckResult, ...]:
    """Run the five Doc 14 §30 checks. Read-only; no network; secret-free output."""
    return (
        HealthCheckResult("liveness", PASS, "process is running"),
        HealthCheckResult(
            "readiness",
            PASS,
            f"configuration loaded and validated (environment {config.environment}, "
            f"schema version {config.schema_version})",
        ),
        _check_database(config, repo_root),
        _check_artifact_store(config, repo_root),
        _check_llm_provider(config),
    )
