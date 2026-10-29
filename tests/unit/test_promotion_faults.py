"""Fault cases of the decision (P6a step 6; Doc 12 §19, Doc 09 §37, Doc 06 §20 and §27).

Each fault yields a known non-PROMOTE decision and leaves the trusted state unchanged: a verifier
crash is a VERIFIER_ERROR that escalates, a report or an impact report that no longer matches its
hash cannot make a complete decision, a stale candidate is rejected, a truncated report has no proof
for what it lacks, and a missing STRUCTURAL item is missing evidence.
"""

from __future__ import annotations

import dataclasses
import unittest

from core.domain.enums import DecisionType, VerificationResult
from core.domain.promotion import DecisionReason
from core.domain.verification import VerificationReport
from tests.domain_builders import uid
from tests.promotion_builders import (
    FUNC1,
    SEC1,
    World,
    make_world,
    report_of,
    run,
    target,
    trusted_state,
)
from tests.promotion_pipeline import fixtures_with_a_parent, pipeline, with_failing_reachability

D, R = DecisionType, DecisionReason
SAFE = "canonical_safe_repair_promote_v1"


def untouched(world: World) -> tuple[str, dict[str, object]]:
    return world.trusted.state_hash, world.trusted.to_dict()


class TestFaults(unittest.TestCase):
    def check(self, world: World, decision: DecisionType, reason: DecisionReason) -> None:
        before = untouched(world)
        out = run(world)
        self.assertEqual((out.decision.decision, out.decision.reason), (decision, reason))
        self.assertEqual(untouched(world), before)

    def test_a_verifier_crash_is_a_verifier_error_that_escalates(self) -> None:
        run_ = pipeline(fixtures_with_a_parent()[SAFE], verifiers=with_failing_reachability())
        func = next(r for r in run_.verification.results if r.invariant_id == "INV-FUNC-001")
        self.assertEqual(func.result, VerificationResult.VERIFIER_ERROR)
        before = run_.trusted.to_dict()
        out = run_.decide()
        self.assertEqual(
            (out.decision.decision, out.decision.reason), (D.ESCALATE, R.VERIFIER_ERROR)
        )
        self.assertEqual(run_.trusted.to_dict(), before)

    def test_a_report_that_no_longer_matches_its_hash_cannot_promote(self) -> None:
        world = make_world()
        object.__setattr__(world.verification, "content_hash", "0" * 64)
        self.check(world, D.ESCALATE, R.DECISION_INCOMPLETE)

    def test_an_impact_report_that_no_longer_matches_its_hash_cannot_promote(self) -> None:
        world = make_world(affected=(SEC1, FUNC1, "INV-SEC-002", "INV-SEC-003"), carry=())
        object.__setattr__(world.impact, "graph_version", "tampered")
        self.check(world, D.ESCALATE, R.DECISION_INCOMPLETE)

    def test_a_candidate_whose_hash_is_not_the_reports_has_no_fresh_proof(self) -> None:
        world = make_world()
        object.__setattr__(world.candidate, "state_hash", "1" * 64)
        out = run(world)
        self.assertEqual(out.decision.decision, D.REJECT)
        self.assertIn(R.EVIDENCE_STALE, [c.code for c in out.decision.blocking_conditions])

    def test_a_stale_candidate_is_rejected(self) -> None:
        world = dataclasses.replace(make_world(), trusted=trusted_state(state_id=uid(2)))
        self.check(world, D.REJECT, R.STALE_PARENT)

    def test_a_truncated_report_has_no_proof_for_what_it_lacks(self) -> None:
        world = make_world()
        kept = list(world.verification.results)[:2]
        truncated = dataclasses.replace(world, verification=report_of(world.candidate, kept))
        before = untouched(truncated)
        out = run(truncated)
        self.assertEqual(
            (out.decision.decision, out.decision.reason), (D.REJECT, R.INSUFFICIENT_EVIDENCE)
        )
        self.assertEqual(untouched(truncated), before)
        missing = {c.target for c in out.decision.blocking_conditions}
        held = {r.target_id for r in kept}
        self.assertTrue(missing)
        self.assertFalse(missing & held)

    def test_an_empty_report_proves_nothing_that_needs_a_result(self) -> None:
        world = make_world()
        empty = VerificationReport.create(
            candidate_id=world.candidate.candidate_id,
            candidate_hash=world.candidate.state_hash or "",
            results=[],
            verifier_invocations=0,
            verifier_set_version="dail-verify-1",
        )
        out = run(dataclasses.replace(world, verification=empty))
        self.assertEqual(
            (out.decision.decision, out.decision.reason), (D.REJECT, R.INSUFFICIENT_EVIDENCE)
        )
        targets = {c.target for c in out.decision.blocking_conditions}
        self.assertIn("STRUCTURAL", targets)
        self.assertIn("CONSISTENCY", targets)
        self.assertIn(target(SEC1), targets)

    def test_a_missing_structural_item_is_missing_evidence(self) -> None:
        self.check(make_world(results={"STRUCTURAL": None}), D.REJECT, R.INSUFFICIENT_EVIDENCE)


if __name__ == "__main__":
    unittest.main()
