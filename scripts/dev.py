"""Local development commands (Doc 14 §12). Standard library only, cross-platform.

Usage (from anywhere):
    python scripts/dev.py bootstrap   # Python 3.12 check, dev config, .local/, schemas,
                                      # tests, health checks
    python scripts/dev.py test        # python -m unittest discover -s tests -p "test_*.py"
    python scripts/dev.py lint        # black --check . ; ruff check . ; mypy
    python scripts/dev.py health      # one line per health check; exit 1 on any FAIL

Exit codes: 0 success, 1 failure, 2 wrong Python version or missing dev toolchain.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"
REQUIRED_PYTHON = (3, 12)
TEST_COMMAND = ("-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py")
LINT_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("black", "--check", "."),
    ("ruff", "check", "."),
    ("mypy",),
)

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_ENVIRONMENT = 2


def _ensure_repo_on_path() -> None:
    """Allow ``import core`` when this file is run as ``python scripts/dev.py``."""
    root = str(REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def _python_version_ok() -> bool:
    return sys.version_info[:2] == REQUIRED_PYTHON


def _run(command: list[str]) -> int:
    print("$ " + " ".join(command), flush=True)
    return subprocess.run(command, cwd=REPO_ROOT, check=False).returncode


def cmd_test(_args: argparse.Namespace) -> int:
    return _run([sys.executable, *TEST_COMMAND])


def cmd_lint(_args: argparse.Namespace) -> int:
    missing = [tool[0] for tool in LINT_COMMANDS if shutil.which(tool[0]) is None]
    if missing:
        print(
            f"dev toolchain not installed: see README (lockfile install). Missing: "
            f"{', '.join(missing)}",
            file=sys.stderr,
        )
        return EXIT_ENVIRONMENT
    failures = [" ".join(tool) for tool in LINT_COMMANDS if _run(list(tool)) != 0]
    if failures:
        print(f"lint FAILED: {'; '.join(failures)}", file=sys.stderr)
        return EXIT_FAILURE
    print("lint: all checks passed")
    return EXIT_OK


def _print_health(results: tuple[tuple[str, str, str], ...]) -> bool:
    """Print one line per check; return True if any check FAILed."""
    for name, status, detail in results:
        print(f"{name}: {status} - {detail}")
    return any(status == "FAIL" for _name, status, _detail in results)


def cmd_health(_args: argparse.Namespace) -> int:
    _ensure_repo_on_path()
    from core.application.config import ConfigError, load_config
    from core.application.health import run_health_checks

    try:
        config = load_config(CONFIG_DIR)
    except ConfigError as exc:
        failed = _print_health(
            (
                ("liveness", "PASS", "process is running"),
                ("readiness", "FAIL", f"configuration invalid ({len(exc.problems)} problems)"),
            )
        )
        for problem in exc.problems:
            print(f"  - {problem}")
        return EXIT_FAILURE if failed else EXIT_OK
    results = tuple((r.name, r.status, r.detail) for r in run_health_checks(config, REPO_ROOT))
    return EXIT_FAILURE if _print_health(results) else EXIT_OK


def cmd_bootstrap(_args: argparse.Namespace) -> int:
    version = ".".join(str(part) for part in sys.version_info[:3])
    if not _python_version_ok():
        print(
            f"bootstrap requires Python 3.12.x (Doc 14 §7); found {version}. "
            "Run it with python3.12.",
            file=sys.stderr,
        )
        return EXIT_ENVIRONMENT
    print(f"== Python {version}")

    _ensure_repo_on_path()
    from core.application.config import ConfigError, load_config
    from core.application.health import run_health_checks
    from core.domain.storage import LocalStorage
    from evidence.store import EvidenceStore

    print("== Loading configuration (environment: dev)")
    try:
        config = load_config(CONFIG_DIR, environment="dev")
    except ConfigError as exc:
        print("configuration invalid:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  - {problem}", file=sys.stderr)
        return EXIT_FAILURE
    print(f"   config_hash {config.config_hash}; safety flags {config.safety_flags()}")

    print("== Creating .local/ and the artifact root")
    (REPO_ROOT / ".local").mkdir(exist_ok=True)
    (REPO_ROOT / str(config.get("artifact_store.root"))).mkdir(parents=True, exist_ok=True)

    print("== Initializing local storage and evidence schemas")
    db_path = REPO_ROOT / str(config.get("database.path"))
    LocalStorage(db_path).initialize_schema()
    EvidenceStore(db_path).initialize_schema()

    print("== Running tests (standard library unittest, no secrets, no network)")
    tests_rc = _run([sys.executable, *TEST_COMMAND])

    print("== Health checks")
    results = tuple((r.name, r.status, r.detail) for r in run_health_checks(config, REPO_ROOT))
    health_failed = _print_health(results)

    if tests_rc != 0 or health_failed:
        print("bootstrap FAILED", file=sys.stderr)
        return EXIT_FAILURE
    print("bootstrap complete")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dev.py", description="cloudspartanx local commands")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, handler, help_text in (
        ("bootstrap", cmd_bootstrap, "fresh-clone bootstrap (Doc 15 §7.3)"),
        ("test", cmd_test, "run the unittest suite"),
        ("lint", cmd_lint, "black --check, ruff check, mypy"),
        ("health", cmd_health, "run the Doc 14 §30 health checks"),
    ):
        sub.add_parser(name, help=help_text).set_defaults(handler=handler)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = args.handler
    result: int = handler(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
