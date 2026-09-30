"""Architecture boundary contract (Doc 02 §15, Doc 14 §5; P0-close Step 10).

Parses every ``.py`` file under ``core/``, ``evidence/``, ``llm/`` and
``scripts/`` with ``ast`` (nothing is imported or executed), resolves relative
imports to absolute module names, and enforces:

R1  core.domain.* imports only the standard library and core.domain.*.
R2  nothing in core.* outside core.application imports core.application.
R3  nothing in core.* or evidence.* imports llm, experiments, scripts, apps,
    benchmark or oracle.
R4  evidence.* imports from core only core.domain.*.
R5  core.identity, core.dependency, core.impact and core.verification do not
    import core.promotion (Doc 02 §15).
R6  core.terraform_model imports no other core.* package, no evidence, and no
    sqlite3.
R7  core.* and evidence.* import no third-party package (sys.stdlib_module_names).
    The per-package allowlist is empty; ADR-005 adds networkx for core.dependency
    in P3c.
ORACLE  nothing in this repository imports the TerraPreserve oracle (ADR-010).

A self-test feeds in-memory sources that break each rule, so a checker that
can no longer fail is itself caught.
"""

from __future__ import annotations

import ast
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKED_ROOTS = ("core", "evidence", "llm", "scripts")
R3_FORBIDDEN_TOP_LEVEL = frozenset({"llm", "experiments", "scripts", "apps", "benchmark", "oracle"})
R5_ENGINES = ("core.identity", "core.dependency", "core.impact", "core.verification")
# ADR-010: the oracle lives in the TerraPreserve repository. Any top-level
# module named oracle or starting with "terrapreserve" is treated as the oracle.
ORACLE_TOP_LEVEL_PREFIXES = ("oracle", "terrapreserve")
# R7 per-package third-party allowlist. Empty until P3c (ADR-005: networkx in core.dependency).
THIRD_PARTY_ALLOWLIST: dict[str, frozenset[str]] = {}
SKIP_DIRS = frozenset({".git", ".venv", "venv", ".local", "__pycache__", "build", "dist",
                       ".mypy_cache", ".ruff_cache", ".pytest_cache", "node_modules"})


@dataclass(frozen=True)
class Violation:
    rule: str
    module: str
    imported: str

    def __str__(self) -> str:
        return f"{self.rule}: {self.module} imports {self.imported}"


def _within(name: str, package: str) -> bool:
    return name == package or name.startswith(package + ".")


def _top(name: str) -> str:
    return name.split(".", 1)[0]


def collect_imports(source: str, module: str, is_package: bool) -> set[str]:
    """Absolute names of everything ``source`` imports.

    ``from X import a`` records ``X.a`` (so ``from core import application`` is
    seen as ``core.application``); a star import records ``X``.
    """
    tree = ast.parse(source)
    package_parts = module.split(".") if is_package else module.split(".")[:-1]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                keep = len(package_parts) - (node.level - 1)
                if keep <= 0:
                    raise ValueError(f"relative import beyond top-level package in {module}")
                base_parts = package_parts[:keep]
                if node.module:
                    base_parts = base_parts + node.module.split(".")
                base = ".".join(base_parts)
            else:
                base = node.module or ""
            for alias in node.names:
                found.add(base if alias.name == "*" else f"{base}.{alias.name}")
    return found


def check_module(module: str, imports: set[str]) -> list[Violation]:
    violations: list[Violation] = []
    in_core = _within(module, "core")
    in_evidence = _within(module, "evidence")
    for name in sorted(imports):
        top = _top(name)
        is_stdlib = top in sys.stdlib_module_names
        if _within(module, "core.domain") and not (is_stdlib or _within(name, "core.domain")):
            violations.append(Violation("R1", module, name))
        if (
            in_core
            and not _within(module, "core.application")
            and _within(name, "core.application")
        ):
            violations.append(Violation("R2", module, name))
        if (in_core or in_evidence) and top in R3_FORBIDDEN_TOP_LEVEL:
            violations.append(Violation("R3", module, name))
        if in_evidence and top == "core" and not _within(name, "core.domain"):
            violations.append(Violation("R4", module, name))
        if any(_within(module, e) for e in R5_ENGINES) and _within(name, "core.promotion"):
            violations.append(Violation("R5", module, name))
        if _within(module, "core.terraform_model") and (
            (top == "core" and not _within(name, "core.terraform_model"))
            or top in ("evidence", "sqlite3")
        ):
            violations.append(Violation("R6", module, name))
        if (in_core or in_evidence) and not is_stdlib and top not in ("core", "evidence"):
            package = ".".join(module.split(".")[:2])
            if top not in THIRD_PARTY_ALLOWLIST.get(package, frozenset()):
                violations.append(Violation("R7", module, name))
        if top.startswith(ORACLE_TOP_LEVEL_PREFIXES):
            violations.append(Violation("ORACLE", module, name))
    return violations


def module_name(path: Path) -> tuple[str, bool]:
    rel = path.relative_to(REPO_ROOT).with_suffix("")
    parts = list(rel.parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    return ".".join(parts), is_package


def iter_python_files(roots: tuple[str, ...] | None = None) -> list[Path]:
    bases = [REPO_ROOT / r for r in roots] if roots else [REPO_ROOT]
    files: list[Path] = []
    for base in bases:
        for path in sorted(base.rglob("*.py")):
            if not SKIP_DIRS.intersection(path.relative_to(REPO_ROOT).parts):
                files.append(path)
    return files


def check_repository(roots: tuple[str, ...] | None = CHECKED_ROOTS) -> list[Violation]:
    violations: list[Violation] = []
    for path in iter_python_files(roots):
        module, is_package = module_name(path)
        imports = collect_imports(path.read_text(encoding="utf-8"), module, is_package)
        violations.extend(check_module(module, imports))
    return violations


class TestCheckerSelfTest(unittest.TestCase):
    """The checker must report violations it is fed; otherwise the boundary test proves nothing."""

    def rules_for(self, module: str, source: str, is_package: bool = False) -> set[str]:
        return {v.rule for v in check_module(module, collect_imports(source, module, is_package))}

    def test_r1_and_r7_violations_are_reported(self) -> None:
        self.assertIn("R1", self.rules_for("core.domain.bad", "from core.identity import x\n"))
        rules = self.rules_for("core.domain.bad", "import networkx\n")
        self.assertIn("R1", rules)
        self.assertIn("R7", rules)
        self.assertIn("R7", self.rules_for("evidence.bad", "from pydantic import BaseModel\n"))

    def test_each_remaining_rule_is_reported(self) -> None:
        cases = {
            "R2": ("core.identity.bad", "from core import application\n"),
            "R3": ("evidence.bad", "import llm.adapter\n"),
            "R4": ("evidence.bad", "from core.identity import engine\n"),
            "R5": ("core.impact.bad", "from core.promotion import controller\n"),
            "R6": ("core.terraform_model.bad", "import sqlite3\n"),
            "ORACLE": ("scripts.bad", "from oracle import reachability\n"),
        }
        for rule, (module, source) in cases.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, self.rules_for(module, source))

    def test_r6_rejects_any_other_core_package_and_evidence(self) -> None:
        self.assertIn("R6", self.rules_for("core.terraform_model.bad", "from core.domain import x\n"))
        self.assertIn("R6", self.rules_for("core.terraform_model.bad", "import evidence.store\n"))

    def test_relative_imports_are_resolved(self) -> None:
        self.assertEqual(
            collect_imports("from ..promotion import controller\n", "core.impact.engine", False),
            {"core.promotion.controller"},
        )
        self.assertEqual(
            collect_imports("from . import enums\n", "core.domain", True), {"core.domain.enums"}
        )
        self.assertIn(
            "R5", self.rules_for("core.impact.engine", "from ..promotion import controller\n")
        )
        self.assertIn("R2", self.rules_for("core.domain", "from ..application import config\n",
                                           is_package=True))

    def test_allowed_imports_are_not_reported(self) -> None:
        self.assertEqual(self.rules_for("core.domain.ok", "import json\nfrom .enums import X\n"), set())
        self.assertEqual(self.rules_for("evidence.ok", "from core.domain.hashing import h\n"), set())
        self.assertEqual(
            self.rules_for("core.application.ok", "from core.domain import storage\n"), set()
        )


class TestArchitectureBoundaries(unittest.TestCase):
    def test_checked_packages_exist(self) -> None:
        for root in CHECKED_ROOTS:
            self.assertTrue((REPO_ROOT / root).is_dir(), root)
        self.assertGreater(len(iter_python_files(CHECKED_ROOTS)), 10)

    def test_rules_r1_to_r7_hold(self) -> None:
        violations = check_repository(CHECKED_ROOTS)
        self.assertEqual(violations, [], "\n".join(str(v) for v in violations))

    def test_no_oracle_imports_anywhere_in_the_repository(self) -> None:
        violations = [v for v in check_repository(None) if v.rule == "ORACLE"]
        self.assertEqual(violations, [], "\n".join(str(v) for v in violations))

    def test_scripts_import_only_stdlib_and_first_party(self) -> None:
        """A14: no third-party imports in scripts/ (core/ and evidence/ are covered by R7)."""
        offenders = []
        for path in iter_python_files(("scripts",)):
            module, is_package = module_name(path)
            for name in collect_imports(path.read_text(encoding="utf-8"), module, is_package):
                top = _top(name)
                if top not in sys.stdlib_module_names and top not in ("core", "evidence"):
                    offenders.append(f"{module} imports {name}")
        self.assertEqual(offenders, [], "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
