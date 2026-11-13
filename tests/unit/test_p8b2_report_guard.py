"""The report guard (P8b-2, work package Change 2; C-216).

"The dev report gets a table of every non-PASS required check by verifier, result and reason, per
condition (from the records). A test fails if any baseline item in a report has reason
invariant.unknown while the run's definitions hold the invariant. This makes a systemic error
visible instead of hiding it in a rate."
"""

from __future__ import annotations

import json
import unittest

from experiments.metrics.extractor import baseline_guard, extract
from experiments.metrics.model import Transition, WorkRow
from experiments.report.build import build_report
from experiments.report.render import render_markdown
from experiments.scoring.identity import load_identity_table
from tests.fixture_catalog import REPO_ROOT
from tests.metrics_builders import GATES, scenarios

UNKNOWN_DEF = "invariant.unknown"


def transition(rows: tuple[WorkRow, ...], required: tuple[tuple[str, str], ...]) -> Transition:
    return Transition(
        "t", "Z", "C", 1, "EVALUATED", "REJECT", (), required, GATES + rows, frozenset(), (), None
    )


def baseline_row(address: str, result: str, reason: str | None) -> WorkRow:
    return WorkRow(
        f"RESOURCE:{address}", "RESOURCE", result, True, "impact", "CREATED_BASELINE",
        "dail.verify.public_ingress", reason,
    )  # fmt: skip


def report_for(rows: tuple[WorkRow, ...], held: list[str]) -> dict:  # type: ignore[type-arg]
    required = (("CONSISTENCY", "VERIFIED"), ("STRUCTURAL", "VERIFIED")) + tuple(
        (r.target_id, "VERIFIED") for r in rows
    )
    x = extract(
        experiment_id="e",
        transitions=[transition(rows, required)],
        scored=scenarios(),
        baselines={},
        identity=load_identity_table(),
    )
    definition = {
        "experiment_id": "e",
        "name": "n",
        "version": "1",
        "condition_set": ["C"],
        "pins": {"verifiers": {"invariants": {i: {} for i in held}}},
    }
    return build_report(definition=definition, statuses={"t": "COMPLETED"}, extraction=x)


class TestNonPassTable(unittest.TestCase):
    def test_every_non_pass_required_check_is_tabled(self) -> None:
        rows = (
            baseline_row("aws_security_group.a", "UNSUPPORTED", UNKNOWN_DEF),
            baseline_row("aws_security_group.b", "UNSUPPORTED", UNKNOWN_DEF),
            baseline_row("aws_security_group_rule.r", "FAIL", "predicate.violated"),
        )
        report = report_for(rows, ["INV-SEC-001"])
        table = report["lists"]["non_pass_checks"]
        self.assertEqual(
            table,
            [
                {
                    "condition": "C",
                    "kind": "RESOURCE:aws_security_group",
                    "verifier_id": "dail.verify.public_ingress",
                    "result": "UNSUPPORTED",
                    "reason": UNKNOWN_DEF,
                    "count": 2,
                },
                {
                    "condition": "C",
                    "kind": "RESOURCE:aws_security_group_rule",
                    "verifier_id": "dail.verify.public_ingress",
                    "result": "FAIL",
                    "reason": "predicate.violated",
                    "count": 1,
                },
            ],
        )
        self.assertIn("Non-PASS required checks", render_markdown(report))


class TestGuard(unittest.TestCase):
    def test_an_unknown_definition_while_it_is_held_is_flagged(self) -> None:
        rows = (baseline_row("aws_security_group.a", "UNSUPPORTED", UNKNOWN_DEF),)
        self.assertEqual(len(baseline_guard(report_for(rows, ["INV-SEC-001"]))), 1)

    def test_it_is_not_flagged_when_the_definition_is_absent(self) -> None:
        rows = (baseline_row("aws_security_group.a", "UNSUPPORTED", UNKNOWN_DEF),)
        self.assertEqual(baseline_guard(report_for(rows, ["INV-SEC-003"])), [])

    def test_the_committed_dev_report_has_no_such_item(self) -> None:
        report = json.loads((REPO_ROOT / "docs" / "P8_DEV_PILOT.json").read_text(encoding="utf-8"))
        self.assertIn("non_pass_checks", report["lists"])
        self.assertEqual(baseline_guard(report), [])


if __name__ == "__main__":
    unittest.main()
