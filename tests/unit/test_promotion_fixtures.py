"""``decide`` on the real pipeline and the fixtures (P6a step 6; Doc 12 §5-§7, Doc 09 §33-§34,
Doc 06 §25-§26; C-22, C-45, C-159).

The trusted state ``v0`` is built from the parent fixture directory with the statuses of the
parent's own hand-written ``expected.json`` (C-89). Then the real pipeline runs: normalisation, identity,
graphs, impact with the prior proofs, the DAIL scope policy, the verification engine, ``decide``.

HAND EXPECTATIONS (written before the first run, from the canonical scenario of CLAUDE.md and the
``expected.json`` of the three canonical fixtures):

* ``canonical_regression/baseline`` is v0: INV-SEC-001 FAIL (public SSH open), INV-SEC-002,
  INV-SEC-003 and INV-FUNC-001 PASS, so v0 has SEC-001 VIOLATED and the other three PROTECTED.
* ``patch_safe`` (fixes SSH, keeps the path): all four invariants PASS, the declared remediation
  target INV-SEC-001 is met, ``decision.allowed`` is PROMOTE. A VIOLATED invariant cannot be carried
  forward, so INV-SEC-001 is VERIFIED; the proof source of each other invariant follows the engine's
  own impact report: VERIFIED if the candidate affects it, CARRIED_FORWARD if it is unaffected and
  its evidence eligible.
* ``patch_regression`` (fixes SSH, removes the path): INV-FUNC-001 FAIL, ``decision.allowed`` is
  REJECT, and the blocking condition is the failed functional check.
* With the Stateful-Full policy (C-22) and every invariant verified again, ``patch_safe`` promotes
  with nothing carried forward; the regression is still rejected.
* After a REJECT, v0 is still the current state and the next attempt starts from it (Doc 06 §25).

For the other fixtures the reviewer's ``decision.allowed`` is the cross-check: the decision must be
one of them. Where a fixture does not fit, the test says so rather than bend.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from functools import cache

from core.domain.enums import CandidateStatus, DecisionType, InvariantStatus
from core.domain.promotion import DecisionOutcome, DecisionReason, ProofSource
from core.promotion.decide import completeness_problems
from core.promotion.lifecycle import candidate_after
from tests import fixture_catalog as fc
from tests.promotion_pipeline import (
    PipelineRun,
    fixtures_with_a_parent,
    pipeline,
    with_failing_reachability,
)

D, R = DecisionType, DecisionReason
SAFE = "canonical_safe_repair_promote_v1"
REGRESSION = "canonical_security_repair_breaks_function_reject_v1"
FUNC, SEC1 = "INV-FUNC-001", "INV-SEC-001"


@cache
def run_of(fixture_id: str, *, stateful_full: bool = False, fault: bool = False) -> PipelineRun:
    fixture = fixtures_with_a_parent()[fixture_id]
    verifiers = with_failing_reachability() if fault else None
    if verifiers is None:
        return pipeline(fixture, stateful_full=stateful_full)
    return pipeline(fixture, stateful_full=stateful_full, verifiers=verifiers)


def sources(outcome: DecisionOutcome) -> dict[str, ProofSource]:
    return {e.invariant_id: e.source for e in outcome.proof_plan}


class TestCanonicalTransitions(unittest.TestCase):
    def test_v0_has_public_ssh_open_and_the_database_path_protected(self) -> None:
        statuses = {r.invariant_id: r.status for r in run_of(SAFE).trusted.invariant_refs}
        self.assertEqual(
            statuses,
            {
                "INV-FUNC-001": InvariantStatus.PROTECTED,
                "INV-SEC-001": InvariantStatus.VIOLATED,
                "INV-SEC-002": InvariantStatus.PROTECTED,
                "INV-SEC-003": InvariantStatus.PROTECTED,
            },
        )

    def test_the_safe_repair_is_promoted(self) -> None:
        run = run_of(SAFE)
        outcome = run.decide()
        self.assertEqual(
            (outcome.decision.decision, outcome.decision.reason), (D.PROMOTE, R.ALL_REQUIRED_PROVEN)
        )
        self.assertEqual(outcome.decision.blocking_conditions, ())

    def test_the_ssh_repair_is_verified_and_the_rest_follow_the_engines_impact_report(self) -> None:
        run = run_of(SAFE)
        got = sources(run.decide())
        self.assertEqual(got[SEC1], ProofSource.VERIFIED)  # its reference is VIOLATED
        impact = run.impact
        for ref in run.trusted.invariant_refs:
            key = (ref.invariant_id, ref.invariant_version)
            with self.subTest(invariant=ref.invariant_id):
                if impact.affected_for(*key) is not None:
                    self.assertEqual(got[ref.invariant_id], ProofSource.VERIFIED)
                else:
                    self.assertTrue(
                        impact.carry_forward_ok(
                            *key,
                            candidate_id=run.candidate.candidate_id,
                            parent_state_id=run.trusted.state_id,
                        )
                    )
                    self.assertEqual(ref.status, InvariantStatus.PROTECTED)
                    self.assertEqual(got[ref.invariant_id], ProofSource.CARRIED_FORWARD)

    def test_at_least_one_invariant_is_carried_and_at_least_one_is_verified(self) -> None:
        # the point of DAIL: the canonical repair re-verifies less than everything
        got = sources(run_of(SAFE).decide())
        self.assertIn(ProofSource.CARRIED_FORWARD, got.values())
        self.assertIn(ProofSource.VERIFIED, got.values())

    def test_the_repair_that_breaks_the_database_path_is_rejected(self) -> None:
        outcome = run_of(REGRESSION).decide()
        self.assertEqual(
            (outcome.decision.decision, outcome.decision.reason),
            (D.REJECT, R.REQUIRED_CHECK_FAILED),
        )
        self.assertEqual(
            [c.target for c in outcome.decision.blocking_conditions], [f"INVARIANT:{FUNC}:1"]
        )
        self.assertNotIn(FUNC, sources(outcome))
        self.assertEqual(sources(outcome)[SEC1], ProofSource.VERIFIED)  # SSH is fixed all the same

    def test_with_stateful_full_nothing_is_carried_forward(self) -> None:
        run = run_of(SAFE, stateful_full=True)
        outcome = run.decide(run.policy(stateful_full=True))
        self.assertEqual(outcome.decision.decision, D.PROMOTE)
        self.assertEqual(set(sources(outcome).values()), {ProofSource.VERIFIED})
        self.assertEqual(len(outcome.proof_plan), 4)

    def test_stateful_full_policy_without_the_extra_verification_has_no_proof(self) -> None:
        run = run_of(SAFE)  # DAIL scope: the unaffected invariant was not verified
        outcome = run.decide(run.policy(stateful_full=True))
        self.assertEqual(
            (outcome.decision.decision, outcome.decision.reason),
            (D.REJECT, R.INSUFFICIENT_EVIDENCE),
        )
        self.assertNotIn(ProofSource.CARRIED_FORWARD, sources(outcome).values())

    def test_stateful_full_still_rejects_the_regression(self) -> None:
        run = run_of(REGRESSION, stateful_full=True)
        outcome = run.decide(run.policy(stateful_full=True))
        self.assertEqual(outcome.decision.decision, D.REJECT)
        self.assertEqual(outcome.decision.reason, R.REQUIRED_CHECK_FAILED)

    def test_the_rejection_leaves_v0_current_and_the_next_attempt_starts_from_it(self) -> None:
        bad, good = run_of(REGRESSION), run_of(SAFE)
        before = (bad.trusted.state_hash, bad.trusted.to_dict())
        rejected = candidate_after(bad.decide().decision, bad.candidate, bad.trusted)
        self.assertEqual(rejected.status, CandidateStatus.REJECTED)
        self.assertEqual((bad.trusted.state_hash, bad.trusted.to_dict()), before)
        # the second attempt has the same parent and is promotable against the unchanged state
        self.assertEqual(good.candidate.parent_state_id, bad.candidate.parent_state_id)
        self.assertEqual(good.candidate.parent_state_id, bad.trusted.state_id)
        second = good.decide()
        self.assertEqual(second.decision.decision, D.PROMOTE)
        promotable = candidate_after(second.decision, good.candidate, bad.trusted)
        self.assertEqual(promotable.status, CandidateStatus.PROMOTABLE)


class TestEveryFixtureWithAParent(unittest.TestCase):
    """The cross-check against the reviewer's ``decision.allowed`` (hand-written data)."""

    def decision_for(self, fixture_id: str) -> DecisionOutcome:
        fixture = fixtures_with_a_parent()[fixture_id]
        kind = (fixture.data.get("process") or {}).get("kind")
        if kind == "stale_parent":
            run = run_of(fixture_id)
            return run.decide(trusted=run.newer_trusted())
        if kind == "verifier_fault":
            return run_of(fixture_id, fault=True).decide()
        return run_of(fixture_id).decide()

    def test_the_decision_is_one_the_reviewer_allows(self) -> None:
        for fixture_id, fixture in fixtures_with_a_parent().items():
            with self.subTest(fixture=fixture_id):
                outcome = self.decision_for(fixture_id)
                self.assertIn(outcome.decision.decision.value, fixture.data["decision"]["allowed"])

    def test_nothing_is_promoted_unless_every_expected_result_is_pass(self) -> None:
        for fixture_id, fixture in fixtures_with_a_parent().items():
            expected = [v["result"] for v in fixture.data["results"].values()]
            outcome = self.decision_for(fixture_id)
            if any(result != "PASS" for result in expected):
                with self.subTest(fixture=fixture_id):
                    self.assertNotEqual(outcome.decision.decision, D.PROMOTE)

    def test_a_promote_needs_the_proof_of_every_invariant_of_the_state(self) -> None:
        for fixture_id in fixtures_with_a_parent():
            outcome = self.decision_for(fixture_id)
            if outcome.decision.decision is not D.PROMOTE:
                continue
            run = run_of(fixture_id)
            with self.subTest(fixture=fixture_id):
                self.assertEqual(
                    sorted(sources(outcome)),
                    sorted(r.invariant_id for r in run.trusted.invariant_refs),
                )

    def test_every_decision_is_complete_and_preserves_what_it_needs(self) -> None:
        for fixture_id in fixtures_with_a_parent():
            outcome = self.decision_for(fixture_id)
            run = run_of(fixture_id)
            decision = outcome.decision
            with self.subTest(fixture=fixture_id):
                self.assertEqual(decision.candidate_id, run.candidate.candidate_id)
                self.assertEqual(decision.parent_state_id, run.candidate.parent_state_id)
                if decision.decision is D.PROMOTE:
                    self.assertTrue(decision.supporting_results)
                else:
                    self.assertTrue(decision.blocking_conditions)
                self.assertEqual(
                    completeness_problems(
                        run.candidate,
                        decision.parent_state_id,
                        decision.supporting_results,
                        run.impact,
                        run.verification,
                        run.policy(),
                    ),
                    [],
                )

    def test_the_stale_parent_process_fixture_is_rejected_as_stale(self) -> None:
        outcome = self.decision_for("process_stale_parent_reject_v1")
        self.assertEqual(
            (outcome.decision.decision, outcome.decision.reason), (D.REJECT, R.STALE_PARENT)
        )

    def test_the_verifier_error_process_fixture_is_escalated(self) -> None:
        outcome = self.decision_for("process_verifier_error_escalate_v1")
        self.assertEqual(
            (outcome.decision.decision, outcome.decision.reason), (D.ESCALATE, R.VERIFIER_ERROR)
        )
        self.assertEqual(
            [c.target for c in outcome.decision.blocking_conditions], [f"INVARIANT:{FUNC}:1"]
        )

    def test_each_decision_applies_to_the_candidate_without_touching_the_trusted_state(
        self,
    ) -> None:
        wanted = {
            D.PROMOTE: CandidateStatus.PROMOTABLE,
            D.REJECT: CandidateStatus.REJECTED,
            D.RETRY: CandidateStatus.RETRY_REQUIRED,
            D.ESCALATE: CandidateStatus.ESCALATED,
        }
        for fixture_id in fixtures_with_a_parent():
            outcome = self.decision_for(fixture_id)
            run = run_of(fixture_id)
            before = run.trusted.state_hash
            moved = candidate_after(outcome.decision, run.candidate, run.trusted)
            with self.subTest(fixture=fixture_id):
                self.assertEqual(moved.status, wanted[outcome.decision.decision])
                self.assertEqual(run.trusted.state_hash, before)


class TestDeterminism(unittest.TestCase):
    SCRIPT = (
        "import sys, json\n"
        "sys.path.insert(0, '.')\n"
        "from tests.promotion_pipeline import fixtures_with_a_parent, pipeline\n"
        "ids = ['canonical_safe_repair_promote_v1',"
        " 'canonical_security_repair_breaks_function_reject_v1', 'sg_private_ssh_pass_v1']\n"
        "out = {}\n"
        "for fid in ids:\n"
        "    run = pipeline(fixtures_with_a_parent()[fid])\n"
        "    d = run.decide()\n"
        "    out[fid] = [d.decision.content_hash, d.evidence.content_hash,"
        " [e.source.value for e in d.proof_plan]]\n"
        "print(json.dumps(out, sort_keys=True))\n"
    )

    def test_the_decision_does_not_depend_on_the_hash_seed(self) -> None:
        answers = set()
        for seed in ("0", "1", "424242"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            done = subprocess.run(
                [sys.executable, "-I", "-c", self.SCRIPT],
                capture_output=True,
                text=True,
                env=env,
                cwd=str(fc.REPO_ROOT),
                check=False,
            )
            self.assertEqual(done.returncode, 0, done.stderr[-600:])
            answers.add(done.stdout.strip())
        self.assertEqual(len(answers), 1)
        self.assertEqual(
            set(json.loads(answers.pop())), {SAFE, REGRESSION, "sg_private_ssh_pass_v1"}
        )


if __name__ == "__main__":
    unittest.main()
