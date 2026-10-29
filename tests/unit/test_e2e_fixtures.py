"""Every fixture with a parent, through ``evaluate`` and through the P6a test pipeline (P6c step 5;
Doc 12 §5-§7, §14; Doc 09 Appendix A; C-22, C-45, C-170).

The P6a pipeline (``tests/promotion_pipeline.py``) builds the trusted state from the parent's own
``expected.json`` and runs the engines by hand; ``evaluate`` establishes the parent as a baseline
through the database (the engines' own statuses) and runs the same engines. For each fixture the two
must give the same decision, the same reason, the same blocking conditions, the same required
checks and the same proof plan. A difference is a defect in one of them and is reported, not
reconciled: this test compares, it does not choose a side.

The comparison leaves out what cannot be equal by construction: the ids (the two sides mint their
own), the detail texts of the conditions (they quote ids), and the policy version label.

HAND EXPECTATIONS for ``kind == "transition"`` fixtures: the decision is one of the fixture's own
``decision.allowed`` values (hand-written data, C-89).
"""

from __future__ import annotations

import unittest
from typing import Any

from core.application.chain import describe_chain
from core.application.orchestrator import ResultKind
from core.domain.promotion import DecisionOutcome
from tests.domain_builders import uid
from tests.promotion_commit_builders import check_database
from tests.promotion_orchestrator_builders import OrchestratorCase
from tests.promotion_pipeline import ROOT, fixtures_with_a_parent, pipeline


def view(outcome: DecisionOutcome) -> dict[str, Any]:
    d = outcome.decision
    return {
        "decision": d.decision,
        "reason": d.reason,
        "conditions": sorted(
            (c.code.value, c.decision.value, c.target) for c in d.blocking_conditions
        ),
        "checks": [(c.target_id, c.kind, c.source) for c in d.required_checks],
        "plan": [(e.invariant_id, e.invariant_version, e.source) for e in outcome.proof_plan],
    }


class TestTheDifferential(OrchestratorCase):
    def test_there_are_eighteen_fixtures_with_a_parent(self) -> None:
        """The P6c prompt says 17; the repository holds 20 fixtures, 2 of them baselines."""
        self.assertEqual(len(fixtures_with_a_parent()), 18)

    def test_evaluate_and_the_p6a_pipeline_agree_on_every_fixture(self) -> None:
        seen: set[str] = set()
        for fixture_id, fixture in fixtures_with_a_parent().items():
            data = fixture.data
            with self.subTest(fixture=fixture_id):
                self.fresh_database()
                v0 = self.baseline(ROOT / data["parent"]).state
                result = self.evaluate(self.request(v0, ROOT / data["config"]))
                self.assertIsNotNone(result.outcome, result.kind)
                assert result.outcome is not None
                run = pipeline(fixture)
                reference = run.decide(run.policy(automatic_enabled=True), decision_id=uid(9300))
                self.assertEqual(view(result.outcome), view(reference))
                seen.add(result.outcome.decision.decision.value)
                if data["kind"] == "transition":
                    allowed = data["decision"]["allowed"]
                    self.assertIn(result.outcome.decision.decision.value, allowed)
        # the comparison is not vacuous: the fixtures reach more than one kind of decision
        self.assertTrue({"PROMOTE", "REJECT"} <= seen, seen)
        self.assertGreaterEqual(len(seen), 3, seen)

    def test_every_chain_is_complete_and_the_database_is_sound(self) -> None:
        for fixture_id, fixture in fixtures_with_a_parent().items():
            data = fixture.data
            with self.subTest(fixture=fixture_id):
                self.fresh_database()
                v0 = self.baseline(ROOT / data["parent"]).state
                result = self.evaluate(self.request(v0, ROOT / data["config"]))
                with self.uow() as u:
                    chain = describe_chain(u, result.candidate.candidate_id)
                self.assertEqual(chain.problems(), [])
                self.assertEqual(check_database(self.path), [])
                self.assertIsNot(result.kind, ResultKind.CONSTRUCTION_FAILED)


class TestReportsAreDeterministic(OrchestratorCase):
    """R1 of the P6c prompt: a rerun recomputes the reports, so two runs of the pipeline on one
    input must give the same reports (up to the random ids the engines draw)."""

    def test_two_runs_give_the_same_reports(self) -> None:
        for fixture_id, fixture in fixtures_with_a_parent().items():
            with self.subTest(fixture=fixture_id):
                a, b = pipeline(fixture), pipeline(fixture)
                self.assertEqual(a.impact.content_hash, b.impact.content_hash)
                self.assertEqual(a.verification.content_hash, b.verification.content_hash)
                self.assertEqual(a.inputs.identity.content_hash, b.inputs.identity.content_hash)
                self.assertEqual(
                    a.inputs.candidate_graph.graph_hash, b.inputs.candidate_graph.graph_hash
                )


if __name__ == "__main__":
    unittest.main()
