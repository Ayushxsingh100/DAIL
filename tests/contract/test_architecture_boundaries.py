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
R6  core.terraform_model imports the standard library (except sqlite3) and
    core.domain.*; no other core.* package and no evidence (C-27, ADR-014).
R7  core.* and evidence.* import no third-party package (sys.stdlib_module_names).
    The per-package allowlist is empty; ADR-005 adds networkx for core.dependency
    in P3c.
R8  promotion authority (SM-001, SM-002): the attribute ``promote`` on ``TrustedState`` and any
    reference to ``mark_promoted`` appear only in core.domain.state and core.promotion.*.
R9  no lifecycle bypass through deserialization: ``from_dict`` on TrustedState, CandidateState,
    InvariantRef and InvariantEvaluation is referenced only inside core.domain.*; and the
    construction-guard token names (``_TRUSTED_TOKEN``, ``_CANDIDATE_TOKEN``, ``_REF_TOKEN``,
    ``_EVALUATION_TOKEN``, ``_PROOF_TOKEN``) are imported or accessed only in the module that
    defines them.
R10 determinism in core.domain: no ``datetime.now``/``utcnow``, ``date.today``, ``time.time`` or
    ``random``, and ``uuid4`` only in core.domain.ids.
R11 ``sqlite3`` is imported only in core.persistence.*, evidence.* and core.application.health
    (C-43, P1b).
R12 core.persistence.* imports only the standard library, core.domain.* and itself (P1b). R1
    already keeps core.domain from importing core.persistence.
R13 ``core.domain.codec`` (the route back from stored data into lifecycle objects, C-48) is
    imported only by core.persistence.*; tests are exempt (they are not checked roots).
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
# R11: the only places that may import sqlite3 (C-43).
R11_ALLOWED_MODULES = ("core.persistence", "evidence", "core.application.health")
# R13: the only importers of core.domain.codec (C-48).
R13_CODEC = "core.domain.codec"
R13_ALLOWED_MODULES = ("core.persistence",)
# R7 per-package third-party allowlist. Empty until P3c (ADR-005: networkx in core.dependency).
THIRD_PARTY_ALLOWLIST: dict[str, frozenset[str]] = {}
SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        ".local",
        "__pycache__",
        "build",
        "dist",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "node_modules",
    }
)


@dataclass(frozen=True)
class Violation:
    rule: str
    module: str
    imported: str

    def __str__(self) -> str:
        if self.rule in SOURCE_RULES:
            return f"{self.rule}: {self.module} uses {self.imported}"
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
        if _within(name, R13_CODEC) and not any(_within(module, a) for a in R13_ALLOWED_MODULES):
            violations.append(Violation("R13", module, name))
        if top == "sqlite3" and not any(_within(module, a) for a in R11_ALLOWED_MODULES):
            violations.append(Violation("R11", module, name))
        if (
            _within(module, "core.persistence")
            and not is_stdlib
            and not (_within(name, "core.domain") or _within(name, "core.persistence"))
        ):
            violations.append(Violation("R12", module, name))
        if in_evidence and top == "core" and not _within(name, "core.domain"):
            violations.append(Violation("R4", module, name))
        if any(_within(module, e) for e in R5_ENGINES) and _within(name, "core.promotion"):
            violations.append(Violation("R5", module, name))
        if _within(module, "core.terraform_model") and (
            (
                top == "core"
                and not _within(name, "core.terraform_model")
                and not _within(name, "core.domain")
            )
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


# --- Source-level rules R8 to R10 (P1a step 14) ---------------------------------------------------

SOURCE_RULES = frozenset({"R8", "R9", "R10"})
# R8: only the state module and the Promotion Controller package may create a trusted state from a
# candidate or mark a candidate promoted (SM-001, SM-002).
R8_ALLOWED_MODULES = ("core.domain.state", "core.promotion")
# R9: these classes are rebuilt from data only inside core.domain; the repository adapter goes
# through core.domain.codec (C-48).
R9_LIFECYCLE_CLASSES = frozenset(
    {"TrustedState", "CandidateState", "InvariantRef", "InvariantEvaluation"}
)
# R10: (receiver, attribute) pairs that read the clock, in core.domain.
R10_CLOCK_CALLS = frozenset(
    {("datetime", "now"), ("datetime", "utcnow"), ("date", "today"), ("time", "time")}
)
R10_UUID4_MODULE = "core.domain.ids"
# R9: each construction-guard token belongs to exactly one module (Doc 06 §30).
R9_GUARD_TOKEN_HOMES = {
    "_TRUSTED_TOKEN": "core.domain.state",
    "_CANDIDATE_TOKEN": "core.domain.state",
    "_REF_TOKEN": "core.domain.invariant",
    "_EVALUATION_TOKEN": "core.domain.invariant",
    "_PROOF_TOKEN": "core.domain.invariant",
}


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> the name it was imported as, so ``T.promote`` and ``dt.now`` are seen through
    ``import ... as``/``from ... import ... as``."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    names[alias.asname] = alias.name.split(".")[-1]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.asname:
                    names[alias.asname] = alias.name
    return names


def _receiver(expr: ast.expr, aliases: dict[str, str]) -> str | None:
    """The name an attribute is read from: a (possibly aliased) name, or the last attribute."""
    if isinstance(expr, ast.Name):
        return aliases.get(expr.id, expr.id)
    if isinstance(expr, ast.Attribute):
        return expr.attr
    return None


def check_source(module: str, source: str) -> list[Violation]:
    """R8, R9 and R10 on one module's source (nothing is imported or executed)."""
    tree = ast.parse(source)
    aliases = _import_aliases(tree)
    found: list[Violation] = []
    in_domain = _within(module, "core.domain")
    r8_allowed = any(_within(module, allowed) for allowed in R8_ALLOWED_MODULES)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            receiver = _receiver(node.value, aliases)
            if node.attr == "promote" and receiver == "TrustedState" and not r8_allowed:
                found.append(Violation("R8", module, "TrustedState.promote"))
            if node.attr == "mark_promoted" and not r8_allowed:
                found.append(Violation("R8", module, "mark_promoted"))
            if node.attr == "from_dict" and receiver in R9_LIFECYCLE_CLASSES and not in_domain:
                found.append(Violation("R9", module, f"{receiver}.from_dict"))
            if R9_GUARD_TOKEN_HOMES.get(node.attr, module) != module:
                found.append(Violation("R9", module, node.attr))
            if in_domain:
                if (receiver, node.attr) in R10_CLOCK_CALLS:
                    found.append(Violation("R10", module, f"{receiver}.{node.attr}"))
                if receiver == "random":
                    found.append(Violation("R10", module, f"random.{node.attr}"))
                if node.attr == "uuid4" and module != R10_UUID4_MODULE:
                    found.append(Violation("R10", module, "uuid4"))
        elif isinstance(node, ast.Name):
            original = aliases.get(node.id, node.id)
            if R9_GUARD_TOKEN_HOMES.get(original, module) != module:
                found.append(Violation("R9", module, original))
            if original == "mark_promoted" and not r8_allowed:
                found.append(Violation("R8", module, "mark_promoted"))
            if original == "uuid4" and in_domain and module != R10_UUID4_MODULE:
                found.append(Violation("R10", module, "uuid4"))
        elif isinstance(node, ast.ImportFrom):
            imported = {alias.name for alias in node.names}
            for name in sorted(imported):
                if R9_GUARD_TOKEN_HOMES.get(name, module) != module:
                    found.append(Violation("R9", module, name))
            if "mark_promoted" in imported and not r8_allowed:
                found.append(Violation("R8", module, "mark_promoted"))
            if in_domain and node.module == "random":
                found.append(Violation("R10", module, "random"))
            if in_domain and "uuid4" in imported and module != R10_UUID4_MODULE:
                found.append(Violation("R10", module, "uuid4"))
        elif isinstance(node, ast.Import) and in_domain:
            if any(alias.name.split(".")[0] == "random" for alias in node.names):
                found.append(Violation("R10", module, "random"))
    return found


def check_repository_source(roots: tuple[str, ...] | None = CHECKED_ROOTS) -> list[Violation]:
    violations: list[Violation] = []
    for path in iter_python_files(roots):
        module, _ = module_name(path)
        violations.extend(check_source(module, path.read_text(encoding="utf-8")))
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

    def test_r6_rejects_any_other_core_package_evidence_and_sqlite3(self) -> None:
        # C-27 / ADR-014: core.domain.* is allowed; every other core.* package,
        # evidence and sqlite3 stay forbidden.
        module = "core.terraform_model.bad"
        for source in (
            "from core.identity import x\n",
            "from core.application import config\n",
            "import evidence.store\n",
            "import sqlite3\n",
        ):
            with self.subTest(source=source.strip()):
                self.assertIn("R6", self.rules_for(module, source))

    def test_r6_allows_core_domain_and_the_standard_library(self) -> None:
        module = "core.terraform_model.ok"
        for source in (
            "from core.domain.enums import X\n",
            "from core.domain import hashing\n",
            "import json\nimport re\n",
        ):
            with self.subTest(source=source.strip().splitlines()[0]):
                self.assertNotIn("R6", self.rules_for(module, source))

    def test_r1_keeps_the_domain_from_importing_the_persistence_adapter(self) -> None:
        for source in (
            "from core.persistence import sqlite\n",
            "import core.persistence.schema\n",
            "from core.persistence.sqlite import SqliteUnitOfWork\n",
            "from ..persistence import schema\n",
        ):
            with self.subTest(source=source.strip()):
                self.assertIn("R1", self.rules_for("core.domain.bad", source, is_package=False))

    def test_r11_reports_sqlite3_outside_the_allowed_modules(self) -> None:
        for module in (
            "core.domain.bad",
            "core.identity.bad",
            "core.promotion.bad",
            "core.application.config",
            "core.application.bad",
            "core.terraform_model.bad",
            "llm.bad",
            "scripts.bad",
            "scripts.dev",
        ):
            for source in (
                "import sqlite3\n",
                "from sqlite3 import connect\n",
                "import sqlite3 as db\n",
            ):
                with self.subTest(module=module, source=source.strip()):
                    self.assertIn("R11", self.rules_for(module, source))

    def test_r11_allows_sqlite3_in_the_three_places_c_43_names(self) -> None:
        for module in (
            "core.persistence.schema",
            "core.persistence.sqlite",
            "core.persistence",
            "evidence.store",
            "evidence.bad",
            "core.application.health",
        ):
            with self.subTest(module=module):
                self.assertNotIn("R11", self.rules_for(module, "import sqlite3\n"))

    def test_r11_does_not_extend_to_a_module_that_merely_shares_a_prefix(self) -> None:
        for module in ("core.persistence_extra", "evidencex.bad", "core.application.healthy"):
            with self.subTest(module=module):
                self.assertIn("R11", self.rules_for(module, "import sqlite3\n"))

    def test_r13_reports_the_codec_imported_outside_the_persistence_package(self) -> None:
        sources = (
            "from core.domain import codec\n",
            "import core.domain.codec\n",
            "from core.domain.codec import rebuild_trusted_state\n",
            "from core.domain.codec import rebuild_candidate as rc\n",
        )
        for module in (
            "core.application.bad",
            "core.promotion.bad",
            "llm.bad",
            "experiments.bad",
            "core.identity.bad",
            "evidence.bad",
            "scripts.bad",
            "core.domain.bad",
            "core.persistence_extra",
        ):
            for source in sources:
                with self.subTest(module=module, source=source.strip()):
                    self.assertIn("R13", self.rules_for(module, source))

    def test_r13_reports_a_relative_import_of_the_codec(self) -> None:
        self.assertIn("R13", self.rules_for("core.domain.bad", "from . import codec\n"))
        self.assertIn("R13", self.rules_for("core.domain.bad", "from .codec import x\n"))

    def test_r13_allows_the_persistence_package(self) -> None:
        sources = (
            "from core.domain import codec\n",
            "from core.domain.codec import rebuild_trusted_state, rebuild_candidate\n",
            "from ..domain import codec\n",
        )
        for module in ("core.persistence.sqlite", "core.persistence.schema"):
            for source in sources:
                with self.subTest(module=module, source=source.strip()):
                    self.assertNotIn("R13", self.rules_for(module, source))
        self.assertNotIn(
            "R13", self.rules_for("core.persistence", "from core.domain import codec\n", True)
        )

    def test_r13_does_not_report_other_domain_modules(self) -> None:
        for source in ("from core.domain import state\n", "from core.domain.hashing import h\n"):
            self.assertNotIn("R13", self.rules_for("core.application.ok", source))

    def test_r12_reports_anything_but_the_standard_library_and_core_domain(self) -> None:
        module = "core.persistence.bad"
        for source in (
            "from core.application import config\n",
            "from core.identity import engine\n",
            "from core.promotion import controller\n",
            "import evidence.store\n",
            "import llm.adapter\n",
            "import networkx\n",
            "from pydantic import BaseModel\n",
            "import sqlalchemy\n",
        ):
            with self.subTest(source=source.strip()):
                self.assertIn("R12", self.rules_for(module, source))

    def test_r12_allows_the_standard_library_core_domain_and_its_own_package(self) -> None:
        module = "core.persistence.sqlite"
        for source in (
            "import sqlite3\nimport json\nfrom pathlib import Path\n",
            "from core.domain.state import TrustedState\n",
            "from core.domain import codec\n",
            "from core.persistence.schema import open_connection\n",
            "from .schema import open_connection\n",
        ):
            with self.subTest(source=source.splitlines()[0]):
                self.assertNotIn("R12", self.rules_for(module, source))

    def test_r12_applies_only_to_the_persistence_package(self) -> None:
        self.assertNotIn("R12", self.rules_for("core.application.health", "import sqlite3\n"))
        self.assertNotIn("R12", self.rules_for("evidence.store", "import sqlite3\n"))

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
        self.assertIn(
            "R2",
            self.rules_for("core.domain", "from ..application import config\n", is_package=True),
        )

    def test_allowed_imports_are_not_reported(self) -> None:
        self.assertEqual(
            self.rules_for("core.domain.ok", "import json\nfrom .enums import X\n"), set()
        )
        self.assertEqual(
            self.rules_for("evidence.ok", "from core.domain.hashing import h\n"), set()
        )
        self.assertEqual(
            self.rules_for("core.application.ok", "from core.domain import storage\n"), set()
        )


class TestSourceRulesSelfTest(unittest.TestCase):
    """R8 to R10 are source-level rules; each must fail on a source that breaks it."""

    def rules(self, module: str, source: str) -> set[str]:
        return {v.rule for v in check_source(module, source)}

    # --- R8: promotion authority (SM-001, SM-002) -------------------------------------------

    def test_r8_fires_on_trusted_state_promote_outside_the_allowed_modules(self) -> None:
        for module in ("core.identity.bad", "core.application.bad", "evidence.bad", "scripts.bad"):
            for source in (
                "from core.domain.state import TrustedState\nTrustedState.promote(candidate=c)\n",
                "import core.domain.state as s\ns.TrustedState.promote(candidate=c)\n",
                "from core.domain.state import TrustedState as T\nT.promote(candidate=c)\n",
                "from core.domain import state\nstate.TrustedState.promote(candidate=c)\n",
            ):
                with self.subTest(module=module, source=source.splitlines()[-1]):
                    self.assertIn("R8", self.rules(module, source))

    def test_r8_fires_on_any_reference_to_mark_promoted(self) -> None:
        for source in (
            "from core.domain.state import mark_promoted\n",
            "from core.domain.state import mark_promoted as mp\nmp(c, s)\n",
            "from core.domain import state\nstate.mark_promoted(c, s)\n",
            "mark_promoted(c, s)\n",
        ):
            with self.subTest(source=source.splitlines()[-1]):
                self.assertIn("R8", self.rules("core.impact.bad", source))

    def test_r8_allows_the_state_module_and_the_promotion_package(self) -> None:
        use = "TrustedState.promote(candidate=c)\nmark_promoted(c, s)\n"
        for module in ("core.domain.state", "core.promotion.controller", "core.promotion"):
            with self.subTest(module=module):
                self.assertNotIn("R8", self.rules(module, use))

    def test_r8_ignores_unrelated_promote_calls(self) -> None:
        source = "controller.promote()\nTrustedState.establish_baseline()\nx = TrustedState\n"
        self.assertNotIn("R8", self.rules("core.impact.ok", source))

    # --- R9: no lifecycle bypass through deserialization ---------------------------------------

    def test_r9_fires_on_from_dict_of_the_lifecycle_classes_outside_the_domain(self) -> None:
        for cls in ("TrustedState", "CandidateState", "InvariantRef", "InvariantEvaluation"):
            for module in ("core.application.bad", "core.promotion.bad", "evidence.bad", "llm.bad"):
                with self.subTest(cls=cls, module=module):
                    self.assertIn("R9", self.rules(module, f"x = {cls}.from_dict(data)\n"))

    def test_r9_follows_aliases_and_module_attributes(self) -> None:
        for source in (
            "from core.domain.state import TrustedState as T\nT.from_dict(d)\n",
            "import core.domain.state as s\ns.CandidateState.from_dict(d)\n",
            "from core.domain import invariant\ninvariant.InvariantRef.from_dict(d)\n",
        ):
            with self.subTest(source=source.splitlines()[-1]):
                self.assertIn("R9", self.rules("core.application.bad", source))

    def test_r9_allows_the_domain_and_other_classes(self) -> None:
        self.assertNotIn("R9", self.rules("core.domain.storage", "TrustedState.from_dict(d)\n"))
        self.assertNotIn("R9", self.rules("core.domain.state", "InvariantRef.from_dict(d)\n"))
        self.assertNotIn("R9", self.rules("core.application.ok", "Resource.from_dict(d)\n"))
        self.assertNotIn("R9", self.rules("core.application.ok", "Patch.from_dict(d)\n"))

    # --- R9 (guard tokens): the construction-guard token names stay in their module ------------

    def test_r9_fires_on_guard_token_names_outside_their_defining_module(self) -> None:
        for source in (
            "from core.domain.state import _TRUSTED_TOKEN\n",
            "from core.domain.state import _CANDIDATE_TOKEN as t\nx = t\n",
            "from core.domain.invariant import _REF_TOKEN\n",
            "from core.domain import state\nx = state._TRUSTED_TOKEN\n",
            "import core.domain.invariant as inv\nx = inv._EVALUATION_TOKEN\n",
            "x = _CANDIDATE_TOKEN\n",
            "from core.domain.invariant import _PROOF_TOKEN\n",
            "from core.domain import invariant\nx = invariant._PROOF_TOKEN\n",
        ):
            for module in (
                "core.application.bad",
                "core.promotion.bad",
                "evidence.bad",
                "scripts.bad",
            ):
                with self.subTest(module=module, source=source.splitlines()[0]):
                    self.assertIn("R9", self.rules(module, source))

    def test_r9_keeps_each_token_in_its_own_defining_module(self) -> None:
        # Another module of the domain may not borrow a token either.
        self.assertIn("R9", self.rules("core.domain.state", "x = _REF_TOKEN\n"))
        self.assertIn("R9", self.rules("core.domain.state", "x = _EVALUATION_TOKEN\n"))
        self.assertIn("R9", self.rules("core.domain.state", "x = _PROOF_TOKEN\n"))
        self.assertIn("R9", self.rules("core.domain.invariant", "x = _TRUSTED_TOKEN\n"))
        self.assertIn("R9", self.rules("core.domain.storage", "x = _CANDIDATE_TOKEN\n"))
        self.assertIn(
            "R9",
            self.rules("core.domain.storage", "from core.domain.state import _TRUSTED_TOKEN\n"),
        )

    def test_r9_allows_the_tokens_in_their_defining_modules(self) -> None:
        state_use = "_TRUSTED_TOKEN = object()\n_CANDIDATE_TOKEN = object()\nx = _TRUSTED_TOKEN\n"
        invariant_use = (
            "_REF_TOKEN = object()\n_EVALUATION_TOKEN = object()\n_PROOF_TOKEN = object()\n"
            "x = _REF_TOKEN\ny = _PROOF_TOKEN\n"
        )
        self.assertNotIn("R9", self.rules("core.domain.state", state_use))
        self.assertNotIn("R9", self.rules("core.domain.invariant", invariant_use))

    def test_r9_ignores_other_private_names(self) -> None:
        source = "from core.domain.state import _resources\nx = _TOKEN_COUNT + other._token\n"
        self.assertNotIn("R9", self.rules("core.application.ok", source))

    # --- R10: determinism in core.domain -------------------------------------------------------

    def test_r10_fires_on_clock_and_random_calls_in_the_domain(self) -> None:
        for source in (
            "from datetime import datetime\ndatetime.now()\n",
            "import datetime\ndatetime.datetime.now()\n",
            "from datetime import datetime\ndatetime.utcnow()\n",
            "from datetime import date\ndate.today()\n",
            "import time\ntime.time()\n",
            "import random\nrandom.random()\n",
            "from random import choice\n",
            "from datetime import datetime as dt\ndt.now()\n",
            "import time as t\nt.time()\n",
            "import random as r\nr.shuffle(x)\n",
        ):
            with self.subTest(source=source.splitlines()[-1]):
                self.assertIn("R10", self.rules("core.domain.bad", source))

    def test_r10_fires_on_uuid4_outside_ids(self) -> None:
        for source in (
            "import uuid\nuuid.uuid4()\n",
            "from uuid import uuid4\n",
            "from uuid import uuid4 as u\nu()\n",
            "from core.domain import ids\nids.uuid4()\n",
        ):
            with self.subTest(source=source.splitlines()[-1]):
                self.assertIn("R10", self.rules("core.domain.state", source))

    def test_r10_allows_uuid4_in_ids_and_deterministic_datetime_use(self) -> None:
        self.assertNotIn("R10", self.rules("core.domain.ids", "import uuid\nuuid.uuid4()\n"))
        deterministic = (
            "from datetime import UTC, datetime\n"
            "datetime(2026, 1, 1, tzinfo=UTC)\n"
            "datetime.fromisoformat(s)\n"
            "import uuid\nuuid.UUID(s)\n"
            "import time\nx = time.strftime\n"
        )
        self.assertNotIn("R10", self.rules("core.domain.jsonvalue", deterministic))

    def test_r10_applies_only_to_the_domain(self) -> None:
        source = (
            "import uuid, random\nfrom datetime import datetime\n" "datetime.now()\nuuid.uuid4()\n"
        )
        self.assertNotIn("R10", self.rules("core.application.health", source))
        self.assertNotIn("R10", self.rules("evidence.ids", source))
        self.assertNotIn("R10", self.rules("scripts.dev", source))


class TestArchitectureBoundaries(unittest.TestCase):
    def test_checked_packages_exist(self) -> None:
        for root in CHECKED_ROOTS:
            self.assertTrue((REPO_ROOT / root).is_dir(), root)
        self.assertGreater(len(iter_python_files(CHECKED_ROOTS)), 10)

    def test_rules_r1_to_r7_hold(self) -> None:
        violations = check_repository(CHECKED_ROOTS)
        self.assertEqual(violations, [], "\n".join(str(v) for v in violations))

    def test_rules_r8_to_r10_hold(self) -> None:
        violations = check_repository_source(CHECKED_ROOTS)
        self.assertEqual(violations, [], "\n".join(str(v) for v in violations))

    def test_the_only_sqlite3_importers_are_exactly_the_modules_c_43_names(self) -> None:
        importers = set()
        for path in iter_python_files(CHECKED_ROOTS):
            module, is_package = module_name(path)
            if any(
                _top(name) == "sqlite3"
                for name in collect_imports(path.read_text(encoding="utf-8"), module, is_package)
            ):
                importers.add(module)
        self.assertEqual(
            importers,
            {
                "core.persistence.schema",
                "core.persistence.sqlite",
                "core.application.health",
                "evidence.store",
            },
        )

    def test_the_only_codec_importer_is_the_sqlite_adapter(self) -> None:
        importers = set()
        for path in iter_python_files(CHECKED_ROOTS):
            module, is_package = module_name(path)
            if any(
                _within(name, R13_CODEC)
                for name in collect_imports(path.read_text(encoding="utf-8"), module, is_package)
            ):
                importers.add(module)
        self.assertEqual(importers, {"core.persistence.sqlite"})

    def test_the_persistence_package_exists_and_is_checked(self) -> None:
        checked = {module_name(p)[0] for p in iter_python_files(CHECKED_ROOTS)}
        self.assertTrue(
            {"core.persistence.schema", "core.persistence.sqlite", "core.domain.repositories"}
            <= checked
        )

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
