"""The evidence chains of Doc 11 §51.3, end to end (P6c step 5; Doc 11 §12, §41-§44, §51.3; Doc 06
§27-§28; Doc 09 §20-§25; C-57, C-170, C-172, C-173).

Each test runs the real orchestrator on fixtures, reads the chain back with ``describe_chain``,
asserts that ``problems() == []`` and asserts the exact ordered event types and the evidence kinds.

HAND EXPECTATIONS (Doc 11 §41-§44, the C-172 order, the fixtures):

* every evaluated candidate: CANDIDATE_CREATED, IDENTITY_COMPLETED, DEPENDENCY_COMPLETED,
  IMPACT_COMPLETED, one VERIFICATION_COMPLETED per result; its bound evidence is STATE, IDENTITY,
  DEPENDENCY, IMPACT and one VERIFICATION record per result;
* then: safe promotion PROMOTION_DECIDED, PROMOTION_REQUESTED, STATE_PROMOTED; rejection
  PROMOTION_DECIDED, CANDIDATE_REJECTED; retry PROMOTION_DECIDED, RETRY_SCHEDULED; escalation
  PROMOTION_DECIDED, ESCALATED;
* the stale parent chain has the same stages (the stages ran against the recorded parent, C-173) and
  ends as a rejection, reason STALE_PARENT;
* a construction failure is CANDIDATE_CREATED, ERROR_OCCURRED with no decision;
* retry: ``func_unknown_dependency_unknown_v1`` is RETRY at the first attempt; the same problem at
  the policy's attempt budget (3) is an ESCALATE ``RETRY_BUDGET_EXHAUSTED``.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from core.application.chain import EvidenceChain, describe_chain
from core.application.orchestrator import EvaluationResult, ResultKind
from core.domain.enums import CandidateStatus, DecisionType
from core.domain.evidence import EvidenceKind
from core.domain.promotion import DecisionReason
from core.verification.dispatch import DEFAULT_VERIFIERS, REACHABILITY_CFG
from tests.promotion_orchestrator_builders import (
    PATCH_REGRESSION_DIR,
    PATCH_SAFE_DIR,
    OrchestratorCase,
    config_with,
)
from tests.promotion_pipeline import ROOT, failing_reachability, fixtures_with_a_parent

HEAD = ["CANDIDATE_CREATED", "IDENTITY_COMPLETED", "DEPENDENCY_COMPLETED", "IMPACT_COMPLETED"]
KINDS = ["STATE", "IDENTITY", "DEPENDENCY", "IMPACT"]


class ChainCase(OrchestratorCase):
    def chain(self, result: EvaluationResult) -> EvidenceChain:
        with self.uow() as u:
            return describe_chain(u, result.candidate.candidate_id)

    def assert_chain(self, result: EvaluationResult, tail: list[str]) -> EvidenceChain:
        """The chain of a candidate that was evaluated: no problem, the exact order."""
        assert result.verification is not None
        n = len(result.verification.results)
        chain = self.chain(result)
        self.assertEqual(chain.problems(), [])
        self.assertEqual(chain.event_types(), [*HEAD, *["VERIFICATION_COMPLETED"] * n, *tail])
        self.assertEqual(chain.evidence_kinds(), [*KINDS, *["VERIFICATION"] * n])
        return chain

    def fixture(self, fixture_id: str) -> Any:
        return fixtures_with_a_parent()[fixture_id].data


class TestSafePromotion(ChainCase):
    def test_candidate_identity_dependency_impact_verification_decision_state(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, PATCH_SAFE_DIR))
        self.assertIs(result.kind, ResultKind.PROMOTED)
        chain = self.assert_chain(
            result, ["PROMOTION_DECIDED", "PROMOTION_REQUESTED", "STATE_PROMOTED"]
        )
        assert chain.state is not None and chain.binding is not None
        self.assertEqual(chain.state, result.state)
        self.assertEqual(chain.binding.state_id, chain.state.state_id)
        self.assertIs(chain.candidate.status, CandidateStatus.PROMOTED)


class TestRejectedCandidate(ChainCase):
    def test_impact_evidence_verification_decision_reject_and_the_state_unchanged(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, PATCH_REGRESSION_DIR))
        self.assertIs(result.kind, ResultKind.REJECTED)
        chain = self.assert_chain(result, ["PROMOTION_DECIDED", "CANDIDATE_REJECTED"])
        self.assertIsNone(chain.state)
        self.assertEqual(self.current(), v0)
        # Doc 11 §42: verification SEC PASS, FUNC FAIL
        assert result.verification is not None
        by = {r.target_id: r.result.value for r in result.verification.results}
        self.assertEqual(by["INVARIANT:INV-SEC-001:1"], "PASS")
        self.assertEqual(by["INVARIANT:INV-FUNC-001:1"], "FAIL")


class TestRetry(ChainCase):
    FIXTURE = "func_unknown_dependency_unknown_v1"

    def test_retry_then_the_budget_ends_in_an_escalation(self) -> None:
        data = self.fixture(self.FIXTURE)
        v0 = self.baseline(ROOT / data["parent"]).state
        directory = ROOT / data["config"]
        first = self.evaluate(self.request(v0, directory, n=1, attempt=1))
        self.assertIs(first.kind, ResultKind.RETRY_REQUIRED)
        self.assertIs(first.candidate.status, CandidateStatus.RETRY_REQUIRED)
        self.assert_chain(first, ["PROMOTION_DECIDED", "RETRY_SCHEDULED"])
        self.assertEqual(self.current(), v0)
        second = self.evaluate(self.request(v0, directory, n=2, attempt=3))
        self.assertIs(second.kind, ResultKind.ESCALATED)
        assert second.decision is not None
        self.assertIs(second.decision.decision, DecisionType.ESCALATE)
        self.assertIs(second.decision.reason, DecisionReason.RETRY_BUDGET_EXHAUSTED)
        self.assert_chain(second, ["PROMOTION_DECIDED", "ESCALATED"])
        self.assertEqual(self.current(), v0)
        self.assertEqual(self.count("trusted_states"), 1)


class TestEscalationByVerifierError(ChainCase):
    FIXTURE = "process_verifier_error_escalate_v1"

    def test_a_verifier_error_is_an_escalation_and_nothing_is_promoted(self) -> None:
        data = self.fixture(self.FIXTURE)
        v0 = self.baseline(ROOT / data["parent"]).state
        table = {**DEFAULT_VERIFIERS, REACHABILITY_CFG: failing_reachability}
        result = self.evaluate(self.request(v0, ROOT / data["config"]), verifiers=table)
        self.assertIs(result.kind, ResultKind.ESCALATED)
        assert result.decision is not None
        self.assertIs(result.decision.reason, DecisionReason.VERIFIER_ERROR)
        self.assertIn(
            "VERIFIER_ERROR",
            {r.result.value for r in (result.verification.results if result.verification else ())},
        )
        self.assert_chain(result, ["PROMOTION_DECIDED", "ESCALATED"])
        self.assertEqual(self.current(), v0)
        self.assertEqual(data["decision"]["allowed"], ["ESCALATE"])


class TestStaleParent(ChainCase):
    def test_the_stale_candidate_has_the_whole_chain_and_ends_as_a_stale_rejection(self) -> None:
        v0 = self.baseline().state
        stale_request = self.request(v0, PATCH_SAFE_DIR, n=2)
        winner = self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=1))
        assert winner.state is not None
        stale = self.evaluate(stale_request)
        self.assertIs(stale.kind, ResultKind.STALE)
        chain = self.assert_chain(stale, ["PROMOTION_DECIDED", "CANDIDATE_REJECTED"])
        [decision] = chain.decisions
        self.assertIs(decision.reason, DecisionReason.STALE_PARENT)
        self.assertIs(decision.decision, DecisionType.REJECT)
        self.assertEqual(decision.parent_state_id, v0.state_id)
        self.assertEqual(self.current(), winner.state)
        self.assertEqual(chain.head_state_id, winner.state.state_id)
        self.assertEqual(self.count("trusted_states"), 2)

    def test_the_process_fixture_describes_this_case(self) -> None:
        data = self.fixture("process_stale_parent_reject_v1")
        self.assertEqual(data["decision"]["allowed"], ["REJECT"])
        self.assertEqual(data["process"]["kind"], "stale_parent")


class TestConstructionFailure(ChainCase):
    def test_an_unparseable_directory_is_a_failed_candidate_and_an_error(self) -> None:
        v0 = self.baseline().state
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (tmp / "main.tf").write_text('resource "aws_instance" "x" {{{\n', encoding="utf-8")
        request = self.request(v0, tmp)
        result = self.evaluate(request)
        self.assertIs(result.kind, ResultKind.CONSTRUCTION_FAILED)
        chain = self.chain(result)
        self.assertEqual(chain.problems(), [])
        self.assertEqual(chain.event_types(), ["CANDIDATE_CREATED", "ERROR_OCCURRED"])
        self.assertEqual(chain.evidence_kinds(), [])
        self.assertEqual(chain.decisions, ())
        self.assertIs(chain.candidate.status, CandidateStatus.FAILED)
        with self.uow() as u:
            errors = [
                e
                for e in u.evidence.list_for_correlation(request.context.correlation_id)
                if e.kind is EvidenceKind.ERROR
            ]
        self.assertEqual(len(errors), 1)
        self.assertEqual(self.current(), v0)


class TestEmergencySwitch(ChainCase):
    automatic_enabled = False

    def test_a_would_be_promote_is_an_audited_escalation(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, PATCH_SAFE_DIR))
        self.assertIs(result.kind, ResultKind.ESCALATED)
        assert result.decision is not None
        self.assertIs(result.decision.reason, DecisionReason.AUTOMATIC_PROMOTION_DISABLED)
        chain = self.assert_chain(result, ["PROMOTION_DECIDED", "ESCALATED"])
        self.assertIsNone(chain.state)
        self.assertEqual(self.current(), v0)
        self.assertEqual(self.count("trusted_states"), 1)

    def test_the_same_candidate_is_promoted_with_the_switch_on(self) -> None:
        """The switch is the only difference: the pipeline and its evidence are the same."""
        v0 = self.baseline().state
        off = self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=1))
        on = self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=2), config=config_with(True))
        self.assertIs(off.kind, ResultKind.ESCALATED)
        self.assertIs(on.kind, ResultKind.PROMOTED)
        assert off.outcome is not None and on.outcome is not None
        self.assertEqual(
            [(e.invariant_id, e.source) for e in off.outcome.proof_plan],
            [(e.invariant_id, e.source) for e in on.outcome.proof_plan],
        )


if __name__ == "__main__":
    unittest.main()
