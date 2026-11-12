"""Label blinding of the experiment harness (P8a; work package §4.2, "Blinding").

"Trial execution never reads oracle labels. Labels are used only for scoring, which is P8b."
§4.2: "Gives execution only: scenario_id, family, split, template_id or lineage id, the step
directories and hashes, target.kind, target.invariant_id, protected_invariants, endpoints (for the
INV-FUNC-001 bindings) and the primary variable_values. Never labels, gt_class, oracle,
mutation_record, intent, variable_values_alt or anything else. A contract test fails if any module
used by trial execution reads one of those fields (for example by parsing the sources with ast)."

Every module of ``experiments/`` is used by trial execution in P8a (scoring is P8b, and a scoring
module would be listed here by name as the one exception). The check parses each source with ``ast``
and reports any use of a forbidden field name: a string constant that is not a docstring (a key, a
``get`` or ``getattr`` argument, a set or list member), an attribute, a name or a keyword argument.
A self-test feeds sources that read each field, so a checker that can no longer fail is caught.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS = REPO_ROOT / "experiments"
FORBIDDEN = frozenset(
    {"labels", "gt_class", "oracle", "mutation_record", "intent", "variable_values_alt"}
)
# P8b's scoring module(s) will be the only exception; none exists in P8a.
SCORING_MODULES: frozenset[str] = frozenset()


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


def execution_modules() -> list[Path]:
    return sorted(
        p
        for p in EXPERIMENTS.rglob("*.py")
        if "__pycache__" not in p.parts and p.stem not in SCORING_MODULES
    )


class TestBlinding(unittest.TestCase):
    def test_no_execution_module_reads_a_label_field(self) -> None:
        modules = execution_modules()
        self.assertTrue(modules, "experiments/ has no module to check")
        self.assertIn(EXPERIMENTS / "loader.py", modules)
        for path in modules:
            with self.subTest(module=path.relative_to(REPO_ROOT).as_posix()):
                self.assertEqual(label_reads(path.read_text(encoding="utf-8")), [])

    def test_no_scoring_module_exists_yet(self) -> None:
        self.assertEqual(SCORING_MODULES, frozenset())


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
