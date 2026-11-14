"""Label blinding of the experiment harness (P8a; work package §4.2, "Blinding").

"Trial execution never reads oracle labels. Labels are used only for scoring, which is P8b."
§4.2: "Gives execution only: scenario_id, family, split, template_id or lineage id, the step
directories and hashes, target.kind, target.invariant_id, protected_invariants, endpoints (for the
INV-FUNC-001 bindings) and the primary variable_values. Never labels, gt_class, oracle,
mutation_record, intent, variable_values_alt or anything else. A contract test fails if any module
used by trial execution reads one of those fields (for example by parsing the sources with ast)."

P8b (work package Step 2): ``experiments/scoring/`` is the only package that reads label fields.
(a) No other module of ``experiments/`` names one: neither the execution modules (the top-level
modules of ``experiments/``) nor ``experiments/metrics/`` and ``experiments/report/``, which consume
scoring's output. (b) No execution module imports ``experiments.scoring``, ``experiments.metrics``
or ``experiments.report``, so trial execution cannot reach a label even indirectly. The check parses
each source with ``ast`` and reports any use of a forbidden field name: a string constant that is
not a docstring (a key, a ``get`` or ``getattr`` argument, a set or list member), an attribute, a
name or a keyword argument. A self-test feeds sources that read each field, so a checker that can no
longer fail is caught.

P10a (work package Section 3.3): "Extend the blinding contract test: ``experiments/generation/``
names no label field and no ``description``, ``intent``, ``mutation_record`` or later step, and
never opens ``step_1`` or beyond. Show the test failing on a mutant." (c) Every module of
``experiments/generation/`` is checked for the label fields and for ``description`` (TerraPreserve's
``target.description``); a later step is any string naming ``step_<n>`` with n >= 1, and any use of
a scenario's ``steps`` other than ``steps[0]`` or ``steps[:1]`` (an index, a loop, a slice past S0).
The invariant's own registry statement reaches the task through ``experiments.task_text``, which
reads a DAIL ``Invariant`` only. (d) No generation module imports ``experiments.scoring``,
``.metrics`` or ``.report``. A dynamic check is in
``tests.unit.test_p10a_generation.TestNoLaterStep``: generation, replay and export run with the
later step directories deleted.
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS = REPO_ROOT / "experiments"
FORBIDDEN = frozenset(
    {"labels", "gt_class", "oracle", "mutation_record", "intent", "variable_values_alt"}
)
# P8b: the only package that reads label fields.
SCORING_PACKAGE = EXPERIMENTS / "scoring"
ANALYSIS_PACKAGES = ("experiments.scoring", "experiments.metrics", "experiments.report")
# P10a: the generation package.
GENERATION_PACKAGE = EXPERIMENTS / "generation"
GENERATION_FORBIDDEN = FORBIDDEN | {"description"}
LATER_STEP = re.compile(r"step_0*[1-9][0-9]*")


def _docstrings(tree: ast.AST) -> set[int]:
    """The ids of the constant nodes that are docstrings or other bare string statements."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            found.add(id(node.value))
    return found


def label_reads(source: str) -> list[str]:
    """Every use of a forbidden field name in ``source``, as 'line: name'."""
    tree = ast.parse(source)
    skip = _docstrings(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        name: str | None = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            name = node.value if node.value in FORBIDDEN else None
        elif isinstance(node, ast.Attribute) and node.attr in FORBIDDEN:
            name = node.attr
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN:
            name = node.id
        elif isinstance(node, ast.keyword) and node.arg in FORBIDDEN:
            name = node.arg
        if name is not None:
            found.append(f"{getattr(node, 'lineno', '?')}: {name}")
    return found


def _first_step_only(node: ast.Subscript) -> bool:
    """``steps[0]`` or ``steps[:1]``."""
    index = node.slice
    if isinstance(index, ast.Constant):
        return index.value == 0
    if isinstance(index, ast.Slice):
        return (
            index.lower is None
            and index.step is None
            and isinstance(index.upper, ast.Constant)
            and index.upper.value == 1
        )
    return False


def generation_reads(source: str) -> list[str]:
    """(c): label fields, ``description``, a later step's name, and any use of ``steps`` other than
    ``steps[0]`` or ``steps[:1]``, as 'line: what'."""
    tree = ast.parse(source)
    skip = _docstrings(tree)
    found: list[str] = []
    allowed_steps: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "steps"
            and _first_step_only(node)
        ):
            allowed_steps.add(id(node.value))
    for node in ast.walk(tree):
        name: str | None = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            if node.value in GENERATION_FORBIDDEN:
                name = node.value
            elif LATER_STEP.search(node.value):
                name = f"later step {node.value!r}"
        elif isinstance(node, ast.Attribute):
            if node.attr in GENERATION_FORBIDDEN:
                name = node.attr
            elif node.attr == "steps" and id(node) not in allowed_steps:
                name = "steps other than steps[0] or steps[:1]"
        elif isinstance(node, ast.Name) and node.id in GENERATION_FORBIDDEN:
            name = node.id
        elif isinstance(node, ast.keyword) and node.arg in GENERATION_FORBIDDEN:
            name = node.arg
        if name is not None:
            found.append(f"{getattr(node, 'lineno', '?')}: {name}")
    return found


def generation_modules() -> list[Path]:
    return sorted(p for p in GENERATION_PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def non_scoring_modules() -> list[Path]:
    """Every module of experiments/ outside experiments/scoring/ (check (a))."""
    return sorted(
        p
        for p in EXPERIMENTS.rglob("*.py")
        if "__pycache__" not in p.parts and SCORING_PACKAGE not in p.parents
    )


def execution_modules() -> list[Path]:
    """The modules trial execution runs: the top-level modules of experiments/ (check (b))."""
    return sorted(EXPERIMENTS.glob("*.py"))


def analysis_imports(source: str) -> list[str]:
    """Every import of experiments.scoring, experiments.metrics or experiments.report."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                names = [f"experiments.{node.module or ''}"] + [
                    f"experiments.{alias.name}" for alias in node.names
                ]
            else:
                base = node.module or ""
                names = [base] + [f"{base}.{alias.name}" for alias in node.names]
        for name in names:
            if any(name == p or name.startswith(p + ".") for p in ANALYSIS_PACKAGES):
                found.append(f"{node.lineno}: {name}")
    return found


class TestBlinding(unittest.TestCase):
    def test_no_module_outside_scoring_reads_a_label_field(self) -> None:
        modules = non_scoring_modules()
        self.assertTrue(modules, "experiments/ has no module to check")
        self.assertIn(EXPERIMENTS / "loader.py", modules)
        self.assertIn(EXPERIMENTS / "metrics" / "extractor.py", modules)
        self.assertIn(EXPERIMENTS / "report" / "build.py", modules)
        for path in modules:
            with self.subTest(module=path.relative_to(REPO_ROOT).as_posix()):
                self.assertEqual(label_reads(path.read_text(encoding="utf-8")), [])

    def test_the_scoring_package_is_the_one_exception(self) -> None:
        # P8b replaces P8a's "no scoring module exists yet": the scoring package exists and reads
        # labels; it is the only part of experiments/ the check (a) skips
        self.assertTrue((SCORING_PACKAGE / "labels.py").is_file())
        reads = label_reads((SCORING_PACKAGE / "labels.py").read_text(encoding="utf-8"))
        self.assertTrue(reads, "the scoring package should be where labels are read")

    def test_execution_never_imports_scoring_metrics_or_report(self) -> None:
        modules = execution_modules()
        self.assertIn(EXPERIMENTS / "trial.py", modules)
        self.assertIn(EXPERIMENTS / "__main__.py", modules)
        for path in modules:
            with self.subTest(module=path.relative_to(REPO_ROOT).as_posix()):
                self.assertEqual(analysis_imports(path.read_text(encoding="utf-8")), [])


class TestGenerationBlinding(unittest.TestCase):
    def test_generation_names_no_label_description_or_later_step(self) -> None:
        modules = generation_modules()
        self.assertIn(GENERATION_PACKAGE / "run.py", modules)
        self.assertIn(GENERATION_PACKAGE / "task.py", modules)
        for path in modules:
            with self.subTest(module=path.relative_to(REPO_ROOT).as_posix()):
                self.assertEqual(generation_reads(path.read_text(encoding="utf-8")), [])

    def test_generation_never_imports_scoring_metrics_or_report(self) -> None:
        for path in generation_modules():
            with self.subTest(module=path.relative_to(REPO_ROOT).as_posix()):
                self.assertEqual(analysis_imports(path.read_text(encoding="utf-8")), [])


class TestTheGenerationCheckerCanFail(unittest.TestCase):
    def test_each_kind_of_read_is_found(self) -> None:
        for source in (
            'text = doc["target"]["description"]\n',
            "text = target.description\n",
            'value = doc.get("intent")\n',
            'value = doc["mutation_record"]\n',
            'value = doc["labels"]\n',
            "later = scenario.steps[1]\n",
            "last = scenario.steps[-1]\n",
            "rest = scenario.steps[1:]\n",
            "both = scenario.steps[:2]\n",
            "for step in scenario.steps:\n    pass\n",
            "count = len(scenario.steps)\n",
            'path = base / "step_1"\n',
            'path = base / f"step_{k}" / "step_12"\n',
        ):
            with self.subTest(source=source.strip()):
                self.assertNotEqual(generation_reads(source), [])

    def test_s0_is_allowed(self) -> None:
        source = (
            '"""Never the description, nor step_1."""\n'
            "first = scenario.steps[0]\n"
            "only = scenario.steps[:1]\n"
            'path = base / "step_0"\n'
        )
        self.assertEqual(generation_reads(source), [])


class TestTheCheckerCanFail(unittest.TestCase):
    def test_each_kind_of_read_is_found(self) -> None:
        for source in (
            'value = data["labels"]\n',
            'value = data.get("gt_class")\n',
            'value = getattr(scenario, "oracle")\n',
            "value = scenario.intent\n",
            'wanted = {"mutation_record"}\n',
            'keys = ["scenario_id", "variable_values_alt"]\n',
            "def f(labels):\n    return labels\n",
            "call(oracle=1)\n",
            'value = data[f"{prefix}"] or data["labels"]\n',
        ):
            with self.subTest(source=source.strip()):
                self.assertNotEqual(label_reads(source), [])

    def test_each_kind_of_analysis_import_is_found(self) -> None:
        for source in (
            "import experiments.scoring\n",
            "from experiments.metrics import extractor\n",
            "from experiments.report.build import build_report\n",
            "from .scoring import labels\n",
            "from . import metrics\n",
        ):
            with self.subTest(source=source.strip()):
                self.assertNotEqual(analysis_imports(source), [])
        self.assertEqual(analysis_imports("from experiments.loader import load\n"), [])

    def test_docstrings_and_allowed_fields_are_not_findings(self) -> None:
        source = (
            '"""This module never reads labels, gt_class or the oracle."""\n'
            "def f(data):\n"
            '    """Not the intent."""\n'
            '    return data["variable_values"], data["scenario_id"], data["target"]\n'
        )
        self.assertEqual(label_reads(source), [])


if __name__ == "__main__":
    unittest.main()
