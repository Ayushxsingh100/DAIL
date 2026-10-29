"""The canonical lifecycle through the database (P6c step 5; Doc 12 §14, Doc 06 §25-§26, Doc 09 §33,
§34, Doc 15 §13.3 and §23 M3 inputs; C-22, C-45, C-164, C-170, C-173).

HAND EXPECTATIONS (CLAUDE.md, the fixtures' own ``expected.json`` and the P6b prompt):

* Doc 12 §14, the eleven steps: 1 create the initial Trusted State (version 0, public SSH open:
  INV-SEC-001 VIOLATED, the other three PROTECTED); 2 generate a candidate from the current parent;
  3 analyze it; 4 verify the affected invariants (at least the three the fixture names as
  ``required_affected``: INV-FUNC-001, INV-SEC-001, INV-SEC-002); 5 reject the unsafe candidate
  (INV-FUNC-001 is the only failing required check); 6 confirm Trusted State is unchanged;
  7 generate the safe candidate; 8 promote it atomically; 9 confirm the new Trusted State has the
  parent, the version and the evidence: version 1, parent version 0, INV-SEC-001 VERIFIED (a
  VIOLATED reference cannot be carried), INV-SEC-003 CARRIED_FORWARD (unaffected, eligible
  evidence), every reference carrying the binding record bound to version 1; 10 attempt to promote
  a stale candidate (written against version 0 after version 1 exists); 11 confirm it cannot
  advance the state: REJECT STALE_PARENT, version 1 still current, two states in all;
* a third candidate, written against version 1, carries what it leaves unaffected forward through
  version 1's binding record and is promoted into version 2.
"""

from __future__ import annotations

import unittest
from typing import Any

from core.application.chain import describe_chain
from core.application.orchestrator import EvaluationResult, ResultKind
from core.domain.enums import CandidateStatus, DecisionType, InvariantStatus, ProofOrigin
from core.domain.evidence import EvidenceContext, EvidenceKind
from core.domain.promotion import DecisionReason, ProofSource
from core.promotion import ids as pids
from evidence.service import EvidenceService
from tests.promotion_commit_builders import check_database
from tests.promotion_orchestrator_builders import (
    FIXTURES,
    PATCH_REGRESSION_DIR,
    PATCH_SAFE_DIR,
    OrchestratorCase,
)

SEC1, SEC2, SEC3, FUNC = "INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"
NEXT_DIR = FIXTURES / "verification" / "ec2_rds_5432_pass_v1"
REQUIRED_AFFECTED = {FUNC, SEC1, SEC2}  # fixtures/canonical_regression/*/expected.json


class TestTheTwelveStepLifecycle(OrchestratorCase):
    def chain_problems(self, result: EvaluationResult) -> list[str]:
        with self.uow() as u:
            return describe_chain(u, result.candidate.candidate_id).problems()

    def test_doc_12_14_steps_1_to_11(self) -> None:
        # 1 create the initial Trusted State
        baseline = self.baseline()
        v0 = baseline.state
        self.assertEqual(v0.version, 0)
        self.assertEqual(
            {r.invariant_id: r.status for r in v0.invariant_refs},
            {
                SEC1: InvariantStatus.VIOLATED,
                SEC2: InvariantStatus.PROTECTED,
                SEC3: InvariantStatus.PROTECTED,
                FUNC: InvariantStatus.PROTECTED,
            },
        )

        # 2 generate a candidate from the current parent, 3 analyze, 4 verify, 5 reject
        unsafe = self.evaluate(self.request(v0, PATCH_REGRESSION_DIR, n=1))
        self.assertEqual(unsafe.candidate.parent_state_id, v0.state_id)
        assert unsafe.impact is not None and unsafe.verification is not None
        self.assertEqual(self.chain_problems(unsafe), [])
        self.assertIn(
            "IMPACT", [e.kind.value for e in self.records(unsafe) if e.kind is EvidenceKind.IMPACT]
        )
        verified = {
            r.invariant_id for r in unsafe.verification.results if r.invariant_id is not None
        }
        self.assertTrue(verified >= REQUIRED_AFFECTED, verified)
        self.assertIs(unsafe.kind, ResultKind.REJECTED)
        assert unsafe.decision is not None
        self.assertIs(unsafe.decision.decision, DecisionType.REJECT)
        failing = {
            c.target
            for c in unsafe.decision.blocking_conditions
            if c.code is DecisionReason.REQUIRED_CHECK_FAILED
        }
        self.assertEqual(failing, {f"INVARIANT:{FUNC}:1"})
        self.assertIs(unsafe.candidate.status, CandidateStatus.REJECTED)

        # 6 confirm Trusted State is unchanged
        self.assertEqual(self.current(), v0)
        self.assertEqual(self.count("trusted_states"), 1)
        self.assertEqual(self.count("lineage_heads"), 1)
        self.assertEqual(self.read_state(v0.state_id), v0)

        # 7 generate the safe candidate and, in parallel, a second one that will become stale
        stale_request = self.request(v0, PATCH_SAFE_DIR, n=3)

        # 8 promote atomically
        safe = self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=2))
        self.assertIs(safe.kind, ResultKind.PROMOTED)
        assert safe.state is not None and safe.decision is not None and safe.outcome is not None
        self.assertEqual(self.chain_problems(safe), [])
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(self.current(), safe.state)

        # 9 the new Trusted State: parent, version, evidence
        v1 = safe.state
        self.assertEqual((v1.version, v1.parent_state_id), (1, v0.state_id))
        self.assertEqual(v1.commit_decision_id, safe.decision.decision_id)
        by = {r.invariant_id: r for r in v1.invariant_refs}
        self.assertEqual({r.status for r in v1.invariant_refs}, {InvariantStatus.PROTECTED})
        self.assertIs(by[SEC1].origin, ProofOrigin.VERIFIED)
        self.assertIs(by[SEC3].origin, ProofOrigin.CARRIED_FORWARD)
        plan = {e.invariant_id: e.source for e in safe.outcome.proof_plan}
        self.assertIs(plan[SEC1], ProofSource.VERIFIED)
        self.assertIs(plan[SEC3], ProofSource.CARRIED_FORWARD)
        self.assertEqual(
            {i: (s is ProofSource.VERIFIED) for i, s in plan.items()},
            {i: by[i].origin is ProofOrigin.VERIFIED for i in plan},
        )
        binding_id = pids.evidence_id_for(safe.decision.decision_id)
        for invariant_id, ref in by.items():
            self.assertIn(binding_id, ref.evidence_ids, invariant_id)
        self.assertIn(binding_id, v1.evidence_refs)
        service = EvidenceService()
        with self.uow() as u:
            binding = u.evidence.get(binding_id)
            assert binding is not None
            self.assertIs(binding.kind, EvidenceKind.STATE)
            self.assertEqual((binding.state_id, binding.state_hash), (v1.state_id, v1.state_hash))
            self.assertTrue(
                service.usable_as_proof(u, binding_id, EvidenceContext.state(v1.state_id)).usable
            )
            # the sources' evidence is proof for their own context, not for version 1 (C-52, C-164)
            carried = [e for e in by[SEC3].evidence_ids if e != binding_id]
            self.assertTrue(carried)
            for evidence_id in carried:
                self.assertFalse(
                    service.usable_as_proof(
                        u, evidence_id, EvidenceContext.state(v1.state_id)
                    ).usable
                )
                self.assertTrue(
                    service.usable_as_proof(
                        u, evidence_id, EvidenceContext.state(v0.state_id)
                    ).usable
                )

        # 10 attempt to promote a stale candidate, 11 confirm it cannot advance the state
        stale = self.evaluate(stale_request)
        self.assertIs(stale.kind, ResultKind.STALE)
        assert stale.decision is not None
        self.assertIs(stale.decision.decision, DecisionType.REJECT)
        self.assertIs(stale.decision.reason, DecisionReason.STALE_PARENT)
        self.assertIs(stale.candidate.status, CandidateStatus.REJECTED)
        self.assertEqual(self.current(), v1)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(self.chain_problems(stale), [])
        self.assertEqual(check_database(self.path), [])

    def records(self, result: EvaluationResult) -> list[Any]:
        with self.uow() as u:
            return list(u.evidence.list_for_candidate(result.candidate.candidate_id))

    def read_state(self, state_id: str) -> Any:
        with self.uow() as u:
            return u.trusted_states.get(state_id)


class TestAThirdCandidateCarriesThroughVersionOnesBinding(OrchestratorCase):
    def test_a_candidate_from_version_one_is_promoted_into_version_two(self) -> None:
        v0 = self.baseline().state
        first = self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=1))
        assert first.state is not None
        v1 = first.state
        second = self.evaluate(self.request(v1, NEXT_DIR, n=2))
        self.assertIs(second.kind, ResultKind.PROMOTED)
        assert (
            second.state is not None and second.outcome is not None and second.decision is not None
        )
        v2 = second.state
        self.assertEqual((v2.version, v2.parent_state_id), (2, v1.state_id))
        self.assertEqual(self.current(), v2)
        carried = [
            e.invariant_id
            for e in second.outcome.proof_plan
            if e.source is ProofSource.CARRIED_FORWARD
        ]
        self.assertTrue(carried, "the third candidate leaves something unaffected")
        v1_binding = pids.evidence_id_for(v1.commit_decision_id or "")
        v2_binding = pids.evidence_id_for(second.decision.decision_id)
        by = {r.invariant_id: r for r in v2.invariant_refs}
        for invariant_id in carried:
            with self.subTest(invariant=invariant_id):
                self.assertIn(v1_binding, by[invariant_id].evidence_ids)
                self.assertIn(v2_binding, by[invariant_id].evidence_ids)
        for invariant_id, ref in by.items():
            self.assertIn(v2_binding, ref.evidence_ids, invariant_id)
        with self.uow() as u:
            for result in (first, second):
                self.assertEqual(describe_chain(u, result.candidate.candidate_id).problems(), [])
        self.assertEqual(check_database(self.path), [])


if __name__ == "__main__":
    unittest.main()
