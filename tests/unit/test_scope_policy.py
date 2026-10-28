"""The verification scope policy interface (P4 step 8; Doc 03 §24; Doc 08 §26; C-142).

The DAIL policy returns the impact work set and the baseline checks unchanged. Stateful Full and
Stateless are P8 and are not built here. The policy lives in the application layer, never in the
domain, and nothing below the application layer may import it (rule R2).
"""

from __future__ import annotations

import ast
import unittest
from collections.abc import Sequence
from pathlib import Path

from core.application.scope_policy import DailScopePolicy, VerificationScopePolicy
from core.domain.impact import ImpactReport, VerificationWorkItem
from core.domain.invariant import Invariant
from tests.impact_builders import NET, impact_between, registry

REPO_ROOT = Path(__file__).resolve().parents[2]
CHANGED = NET.replace('identifier = "d"', 'identifier = "e"') + (
    'resource "aws_subnet" "new" {\n  cidr_block = "10.0.7.0/24"\n}\n'
)


class FakePolicy:
    """A policy that selects nothing: it satisfies the interface without inheriting from it."""

    def select(
        self, report: ImpactReport, protected: Sequence[Invariant]
    ) -> tuple[VerificationWorkItem, ...]:
        del report, protected
        return ()


def imports_of(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


class TestDailScopePolicy(unittest.TestCase):
    def setUp(self) -> None:
        self.report = impact_between(NET, CHANGED)
        self.protected = list(registry().values())

    def test_it_returns_exactly_the_work_items_of_the_report(self) -> None:
        selected = DailScopePolicy().select(self.report, self.protected)
        self.assertEqual(selected, self.report.verification_work)
        self.assertEqual(len(selected), 3)  # two impacted invariants and one created resource

    def test_it_keeps_the_baseline_checks(self) -> None:
        selected = DailScopePolicy().select(self.report, self.protected)
        self.assertIn("RESOURCE:aws_subnet.new", {item.target_id for item in selected})

    def test_it_adds_nothing_and_drops_nothing(self) -> None:
        selected = DailScopePolicy().select(self.report, self.protected)
        self.assertEqual(
            {i.sort_key() for i in selected}, {i.sort_key() for i in self.report.verification_work}
        )
        self.assertEqual(len(selected), len(self.report.verification_work))

    def test_an_unchanged_state_selects_nothing(self) -> None:
        report = impact_between(NET, NET)
        self.assertEqual(DailScopePolicy().select(report, self.protected), ())

    def test_it_does_not_depend_on_the_protected_list_it_is_given(self) -> None:
        # the impact work set is already derived from the protected invariants
        self.assertEqual(
            DailScopePolicy().select(self.report, []),
            DailScopePolicy().select(self.report, self.protected),
        )

    def test_it_is_deterministic(self) -> None:
        policy = DailScopePolicy()
        self.assertEqual(
            policy.select(self.report, self.protected), policy.select(self.report, self.protected)
        )

    def test_no_selected_item_is_optional(self) -> None:
        # Doc 08 §26: priority never makes a required invariant optional
        for item in DailScopePolicy().select(self.report, self.protected):
            self.assertEqual(item.priority.value, "BLOCKING")


class TestInterface(unittest.TestCase):
    def test_the_dail_policy_satisfies_the_interface(self) -> None:
        self.assertIsInstance(DailScopePolicy(), VerificationScopePolicy)

    def test_a_policy_that_does_not_inherit_satisfies_it_too(self) -> None:
        policy: VerificationScopePolicy = FakePolicy()  # the type checker verifies this line
        self.assertIsInstance(policy, VerificationScopePolicy)
        self.assertEqual(policy.select(impact_between(NET, CHANGED), []), ())

    def test_an_object_without_select_is_not_a_policy(self) -> None:
        self.assertNotIsInstance(object(), VerificationScopePolicy)


class TestBoundaries(unittest.TestCase):
    def test_the_policy_module_imports_only_the_domain_and_the_impact_engine(self) -> None:
        names = imports_of(REPO_ROOT / "core" / "application" / "scope_policy.py")
        for name in names:
            top = name.split(".")[0]
            if top == "core":
                self.assertTrue(
                    name.startswith(("core.domain", "core.impact")), f"scope_policy imports {name}"
                )

    def test_nothing_in_the_domain_or_the_impact_engine_imports_the_application_layer(self) -> None:
        for package in ("domain", "impact"):
            for path in sorted((REPO_ROOT / "core" / package).rglob("*.py")):
                with self.subTest(module=path.relative_to(REPO_ROOT).as_posix()):
                    names = imports_of(path)
                    self.assertFalse(
                        any(
                            n == "core.application" or n.startswith("core.application.")
                            for n in names
                        )
                    )

    def test_the_policy_is_not_part_of_the_domain(self) -> None:
        self.assertFalse((REPO_ROOT / "core" / "domain" / "scope_policy.py").exists())
        self.assertTrue((REPO_ROOT / "core" / "application" / "scope_policy.py").exists())


if __name__ == "__main__":
    unittest.main()
