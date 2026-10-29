"""``EvaluationOrchestrator.evaluate`` (P6c step 4; Doc 03 §15; Doc 06 §20, §27; Doc 09 §20, §25,
§26, §40; Doc 11 §43; C-170, C-172, C-173, C-174).

HAND EXPECTATIONS (CLAUDE.md, the prompt and the fixtures' own ``expected.json``):

* the stages run in the order of the objective: normalize, identity, graphs, impact, scope policy,
  verify, decide, record the decision, commit only a PROMOTE;
* ``patch_safe`` from the canonical baseline is PROMOTED into version 1; ``patch_regression`` is
  REJECTED (INV-FUNC-001 is the only failing check) and version 0 stays current; every decision is
  stored;
* with ``promotion.automatic_enabled`` false a would-be PROMOTE is an audited ESCALATE with
  ``AUTOMATIC_PROMOTION_DISABLED`` and no state change; the orchestrator refuses to start when the
  flag is not a bool;
* a directory that does not normalize leaves a FAILED candidate, an ERROR record, no decision and
  the state unchanged; a verifier crash is a VERIFIER_ERROR result and an ESCALATE;
* a candidate whose parent is no longer current is REJECTED ``STALE_PARENT`` and the state stays;
* the same request again is a duplicate (nothing written); the same ids with another directory
  raise ``ConflictingDuplicateError``;
* the orchestrator's source names no verification result, invariant status or PASS/FAIL/UNKNOWN.
"""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from core.application import ids as oids
from core.application.chain import describe_chain
from core.application.orchestrator import EvaluationOrchestrator, ResultKind
from core.application.scope_policy import DailScopePolicy
from core.domain.audit import AuditEventType
from core.domain.enums import CandidateStatus, DecisionType, VerificationResult
from core.domain.errors import DomainValidationError
from core.domain.evidence import EvidenceKind
from core.domain.promotion import ConflictingDuplicateError, DecisionReason
from core.promotion import ids as pids
from core.verification.dispatch import DEFAULT_VERIFIERS, REACHABILITY_CFG
from core.verification.outcome import PredicateOutcome
from tests.domain_builders import uid
from tests.pipeline_builders import fixed_clock
from tests.promotion_commit_builders import InjectedFault, dump
from tests.promotion_orchestrator_builders import (
    PATCH_REGRESSION_DIR,
    PATCH_SAFE_DIR,
    OrchestratorCase,
    config_with,
)

REPO = Path(__file__).resolve().parents[2]
SEC1, SEC3, FUNC = "INV-SEC-001", "INV-SEC-003", "INV-FUNC-001"


def raising(_definition: Any, _inputs: Any) -> Any:
    raise RuntimeError("the reachability verifier crashed")


def unknown(_definition: Any, _inputs: Any) -> Any:
    from core.domain.verification import VerificationReason

    return PredicateOutcome(
        VerificationResult.UNKNOWN, VerificationReason.RULE_INDETERMINATE, None, {}, ()
    )


class TestTheSourceCoordinatesOnly(unittest.TestCase):
    """C-170 (1): no decision logic. The source is read with ``ast`` and never imported."""

    FORBIDDEN = {"VerificationResult", "InvariantStatus", "PASS", "FAIL", "UNKNOWN"}

    def names(self) -> set[str]:
        tree = ast.parse((REPO / "core" / "application" / "orchestrator.py").read_text("utf-8"))
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                found.add(node.id)
            elif isinstance(node, ast.Attribute):
                found.add(node.attr)
            elif isinstance(node, ast.alias):
                found.add(node.name.split(".")[-1])
                if node.asname:
                    found.add(node.asname)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                found.add(node.value)
        return found

    def test_it_names_none_of_the_result_vocabulary(self) -> None:
        self.assertEqual(self.names() & self.FORBIDDEN, set())

    def test_the_check_can_fail(self) -> None:
        """The scan finds each forbidden word in a source that uses it."""
        for source in (
            "from core.domain.enums import VerificationResult\n",
            "if r.status is InvariantStatus.PROTECTED: pass\n",
            "x = PASS\n",
            "if r.result == 'FAIL': pass\n",
            "y = a.UNKNOWN\n",
        ):
            with self.subTest(source=source):
                tree = ast.parse(source)
                found = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Name):
                        found.add(node.id)
                    elif isinstance(node, ast.Attribute):
                        found.add(node.attr)
                    elif isinstance(node, ast.alias):
                        found.add(node.name)
                    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                        found.add(node.value)
                self.assertTrue(found & self.FORBIDDEN, source)

    def test_it_has_no_if_on_an_invariant_id(self) -> None:
        tree = ast.parse((REPO / "core" / "application" / "orchestrator.py").read_text("utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.If | ast.IfExp | ast.While):
                tested = {n.attr for n in ast.walk(node.test) if isinstance(n, ast.Attribute)} | {
                    n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)
                }
                self.assertEqual(
                    tested & {"invariant_id", "invariant_version", "result", "reason"},
                    set(),
                    f"line {node.lineno}",
                )


class TestConstruction(OrchestratorCase):
    def test_a_flag_that_is_not_a_bool_stops_startup(self) -> None:
        class Config:
            def get(self, key: str) -> Any:
                return "yes" if key == "promotion.automatic_enabled" else None

        with self.assertRaises(DomainValidationError):
            self.orchestrator(config=Config())  # type: ignore[arg-type]

    def test_a_missing_flag_stops_startup(self) -> None:
        class Config:
            def get(self, key: str) -> Any:
                raise KeyError(key)

        with self.assertRaises(DomainValidationError):
            self.orchestrator(config=Config())  # type: ignore[arg-type]

    def test_the_real_configuration_starts_it_with_the_flag_off(self) -> None:
        self.assertIsInstance(self.orchestrator(config=config_with(False)), EvaluationOrchestrator)

    def test_other_arguments_are_checked(self) -> None:
        for bad in (
            {"scope_policy": object()},
            {"clock": "now"},
            {"policy_version": ""},
            {"checkpoint": 3},
        ):
            with self.subTest(bad=bad), self.assertRaises(DomainValidationError):
                self.orchestrator(**bad)
        with self.assertRaises(DomainValidationError):
            EvaluationOrchestrator(
                "not a factory",  # type: ignore[arg-type]
                config=config_with(True),
                scope_policy=DailScopePolicy(),
                clock=fixed_clock(60),
                policy_version="p",
            )


class TestTheRequest(OrchestratorCase):
    def test_bad_requests_are_refused_before_anything_is_written(self) -> None:
        v0 = self.baseline().state
        before = dump(self.path)
        good = self.request(v0, PATCH_SAFE_DIR)
        import dataclasses

        for bad in (
            {"candidate_id": "x"},
            {"lineage_id": "x"},
            {"attempt_number": 0},
            {"attempt_number": True},
            {"candidate_sequence": 0},
            {"candidate_dir": "fixtures"},
            {"definitions": ()},
            {"bindings": [1]},
            {"context": object()},
            {"patch": "diff"},
        ):
            with self.subTest(bad=bad), self.assertRaises(DomainValidationError):
                dataclasses.replace(good, **bad)
        self.assertEqual(dump(self.path), before)

    def test_only_a_fixed_patch_is_accepted(self) -> None:
        import dataclasses

        from core.domain.enums import CandidateSource
        from core.domain.patch import Patch

        v0 = self.baseline().state
        llm = Patch.create(
            source=CandidateSource.LLM,
            content="x\n",
            parent_state_id=v0.state_id,
            now=v0.created_at,
            llm_request_id=uid(1),
        )
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(self.request(v0, PATCH_SAFE_DIR), patch=llm)

    def test_a_request_without_a_baseline_is_refused(self) -> None:
        import dataclasses

        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)
        other = dataclasses.replace(request, lineage_id=uid(999))
        with self.assertRaises(DomainValidationError):
            self.evaluate(other)

    def test_a_patch_for_a_state_that_is_not_stored_is_refused(self) -> None:
        import dataclasses

        from core.domain.enums import CandidateSource
        from core.domain.patch import Patch

        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)
        patch = Patch.create(
            source=CandidateSource.FIXED_PATCH,
            content="x\n",
            parent_state_id=uid(98765),
            now=v0.created_at,
        )
        with self.assertRaises(DomainValidationError):
            self.evaluate(dataclasses.replace(request, patch=patch))


class TestTheStageOrder(OrchestratorCase):
    def test_the_stages_run_in_the_order_of_the_objective(self) -> None:
        import core.application.orchestrator as module

        v0 = self.baseline().state
        calls: list[str] = []

        def spy(name: str) -> Any:
            real = getattr(module, name)

            def wrapper(*args: Any, **kwargs: Any) -> Any:
                calls.append(name)
                return real(*args, **kwargs)

            return wrapper

        class Scope(DailScopePolicy):
            def select(self, *args: Any, **kwargs: Any) -> Any:
                calls.append("select")
                return super().select(*args, **kwargs)

        names = (
            "normalize_directory",
            "compare",
            "build_graph",
            "compute_impact",
            "run_work_set",
            "decide",
            "record_decision",
            "commit_promotion",
        )
        patches = [mock.patch.object(module, n, spy(n)) for n in names]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.evaluate(self.request(v0, PATCH_SAFE_DIR), scope_policy=Scope())
        self.assertEqual(
            calls,
            [
                "normalize_directory",
                "compare",
                "build_graph",  # the parent's graph
                "build_graph",  # the candidate's graph
                "compute_impact",
                "select",
                "run_work_set",
                "decide",
                "record_decision",
                "commit_promotion",
            ],
        )

    def test_a_non_promote_never_reaches_the_commit(self) -> None:
        import core.application.orchestrator as module

        v0 = self.baseline().state
        with mock.patch.object(module, "commit_promotion") as commit:
            result = self.evaluate(self.request(v0, PATCH_REGRESSION_DIR))
        self.assertIs(result.kind, ResultKind.REJECTED)
        commit.assert_not_called()


class TestTheCanonicalDecisions(OrchestratorCase):
    def test_the_safe_repair_is_promoted_into_version_one(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, PATCH_SAFE_DIR))
        self.assertIs(result.kind, ResultKind.PROMOTED)
        assert result.state is not None and result.decision is not None
        self.assertEqual(result.state.version, 1)
        self.assertEqual(result.state.parent_state_id, v0.state_id)
        self.assertEqual(self.current(), result.state)
        self.assertIs(result.decision.decision, DecisionType.PROMOTE)
        self.assertEqual(result.decision.committed_state_id, result.state.state_id)
        self.assertIs(result.candidate.status, CandidateStatus.PROMOTED)
        self.assertFalse(result.duplicate)

    def test_the_regression_is_rejected_and_version_zero_stays(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, PATCH_REGRESSION_DIR))
        self.assertIs(result.kind, ResultKind.REJECTED)
        assert result.decision is not None
        self.assertIs(result.decision.decision, DecisionType.REJECT)
        self.assertEqual(self.current(), v0)
        self.assertEqual(self.count("trusted_states"), 1)
        self.assertEqual(
            {c.target for c in result.decision.blocking_conditions if c.target.startswith("INV")},
            {f"INVARIANT:{FUNC}:1"},
        )
        self.assertIs(result.candidate.status, CandidateStatus.REJECTED)

    def test_every_decision_is_stored(self) -> None:
        v0 = self.baseline().state
        rejected = self.evaluate(self.request(v0, PATCH_REGRESSION_DIR, n=1))
        promoted = self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=2))
        with self.uow() as u:
            for result in (rejected, promoted):
                assert result.decision is not None
                self.assertEqual(u.decisions.get(result.decision.decision_id), result.decision)
        self.assertEqual(
            rejected.decision.decision_id if rejected.decision else None,
            oids.decision_id_for(uid(3401), 1),
        )

    def test_the_chains_are_complete(self) -> None:
        v0 = self.baseline().state
        a = self.evaluate(self.request(v0, PATCH_REGRESSION_DIR, n=1))
        b = self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=2))
        with self.uow() as u:
            for result in (a, b):
                self.assertEqual(describe_chain(u, result.candidate.candidate_id).problems(), [])

    def test_the_result_carries_the_reports_for_the_caller(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, PATCH_SAFE_DIR))
        assert result.impact is not None and result.verification is not None
        self.assertEqual(result.impact.candidate_id, result.candidate.candidate_id)
        self.assertEqual(result.verification.candidate_id, result.candidate.candidate_id)
        self.assertEqual(
            set(result.evidence_ids), {r.verification_id for r in result.verification.results}
        )


class TestTheEmergencySwitch(OrchestratorCase):
    automatic_enabled = False

    def test_a_would_be_promote_is_an_audited_escalate(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, PATCH_SAFE_DIR))
        self.assertIs(result.kind, ResultKind.ESCALATED)
        assert result.decision is not None
        self.assertIs(result.decision.decision, DecisionType.ESCALATE)
        self.assertIs(result.decision.reason, DecisionReason.AUTOMATIC_PROMOTION_DISABLED)
        self.assertEqual(self.current(), v0)
        self.assertEqual(self.count("trusted_states"), 1)
        self.assertIs(result.candidate.status, CandidateStatus.ESCALATED)
        with self.uow() as u:
            types = [
                e.event_type for e in u.audit.list_for_candidate(result.candidate.candidate_id)
            ]
        self.assertIn(AuditEventType.ESCALATED, types)
        self.assertNotIn(AuditEventType.STATE_PROMOTED, types)
        self.assertNotIn(AuditEventType.PROMOTION_REQUESTED, types)


class TestVerifierFailures(OrchestratorCase):
    def test_a_crashing_verifier_is_a_verifier_error_and_an_escalate(self) -> None:
        v0 = self.baseline().state
        table = {**DEFAULT_VERIFIERS, REACHABILITY_CFG: raising}
        result = self.evaluate(self.request(v0, PATCH_SAFE_DIR), verifiers=table)
        self.assertIs(result.kind, ResultKind.ESCALATED)
        assert result.decision is not None and result.verification is not None
        self.assertIs(result.decision.reason, DecisionReason.VERIFIER_ERROR)
        self.assertIn(
            VerificationResult.VERIFIER_ERROR, {r.result for r in result.verification.results}
        )
        self.assertEqual(self.current(), v0)

    def test_an_unknown_result_is_a_retry_and_the_budget_ends_in_an_escalate(self) -> None:
        v0 = self.baseline().state
        table = {**DEFAULT_VERIFIERS, REACHABILITY_CFG: unknown}
        first = self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=1, attempt=1), verifiers=table)
        self.assertIs(first.kind, ResultKind.RETRY_REQUIRED)
        self.assertIs(first.candidate.status, CandidateStatus.RETRY_REQUIRED)
        with self.uow() as u:
            types = [e.event_type for e in u.audit.list_for_candidate(first.candidate.candidate_id)]
        self.assertEqual(types[-1], AuditEventType.RETRY_SCHEDULED)
        last = self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=2, attempt=3), verifiers=table)
        self.assertIs(last.kind, ResultKind.ESCALATED)
        assert last.decision is not None
        self.assertIs(last.decision.reason, DecisionReason.RETRY_BUDGET_EXHAUSTED)
        self.assertEqual(self.current(), v0)


class TestConstructionFailure(OrchestratorCase):
    def broken_dir(self) -> Path:
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (tmp / "main.tf").write_text('resource "aws_instance" {{{\n', encoding="utf-8")
        return tmp

    def test_the_candidate_fails_with_an_error_record_and_no_decision(self) -> None:
        v0 = self.baseline().state
        request = self.request(v0, self.broken_dir())
        result = self.evaluate(request)
        self.assertIs(result.kind, ResultKind.CONSTRUCTION_FAILED)
        self.assertIs(result.candidate.status, CandidateStatus.FAILED)
        self.assertIsNone(result.decision)
        self.assertIsNone(result.state)
        self.assertEqual(self.count("promotion_decisions"), 0)
        self.assertEqual(self.current(), v0)
        with self.uow() as u:
            errors = [
                e
                for e in u.evidence.list_for_correlation(request.context.correlation_id)
                if e.kind is EvidenceKind.ERROR
            ]
            types = [e.event_type for e in u.audit.list_for_candidate(request.candidate_id)]
        self.assertEqual(len(errors), 1)
        self.assertEqual(types, [AuditEventType.CANDIDATE_CREATED, AuditEventType.ERROR_OCCURRED])
        with self.uow() as u:
            self.assertEqual(describe_chain(u, request.candidate_id).problems(), [])

    def test_a_rerun_is_a_duplicate(self) -> None:
        v0 = self.baseline().state
        request = self.request(v0, self.broken_dir())
        first = self.evaluate(request)
        before = dump(self.path)
        second = self.evaluate(request)
        self.assertIs(second.kind, ResultKind.CONSTRUCTION_FAILED)
        self.assertTrue(second.duplicate)
        self.assertEqual(second.candidate, first.candidate)
        self.assertEqual(dump(self.path), before)


class TestTheStaleRoute(OrchestratorCase):
    def test_a_candidate_written_against_v0_is_stale_once_v1_exists(self) -> None:
        v0 = self.baseline().state
        stale_request = self.request(v0, PATCH_SAFE_DIR, n=2)
        winner = self.evaluate(self.request(v0, PATCH_SAFE_DIR, n=1))
        self.assertIs(winner.kind, ResultKind.PROMOTED)
        result = self.evaluate(stale_request)
        self.assertIs(result.kind, ResultKind.STALE)
        assert result.decision is not None
        self.assertIs(result.decision.decision, DecisionType.REJECT)
        self.assertIs(result.decision.reason, DecisionReason.STALE_PARENT)
        self.assertEqual(
            result.decision.decision_id,
            pids.rejection_decision_id_for(oids.decision_id_for(stale_request.candidate_id, 1)),
        )
        self.assertEqual(self.current(), winner.state)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertIs(result.candidate.status, CandidateStatus.REJECTED)
        with self.uow() as u:
            chain = describe_chain(u, stale_request.candidate_id)
        self.assertEqual(chain.problems(), [])
        self.assertEqual(chain.evidence_kinds()[:4], ["STATE", "IDENTITY", "DEPENDENCY", "IMPACT"])


class TestTheParentMovesWhileDeciding(OrchestratorCase):
    """The window between ``decide`` and ``record_decision``: another promotion lands there, and
    ``record_decision`` refuses a PROMOTE for a candidate whose parent is no longer current
    (SM-010).
    The orchestrator turns that refusal into what Doc 09 §25 and Doc 06 §27 require: a stale
    rejection, with the state unchanged; it does not let the refusal escape."""

    def test_a_promotion_that_lands_between_decide_and_record_decision(self) -> None:
        import core.application.orchestrator as module

        v0 = self.baseline().state
        late = self.request(v0, PATCH_SAFE_DIR, n=2)
        real = module.decide
        landed: list[Any] = []

        def decide_then_let_another_promotion_land(*args: Any, **kwargs: Any) -> Any:
            outcome = real(*args, **kwargs)
            if not landed:
                landed.append(None)  # first: the nested evaluation passes through here as well
                landed[0] = self.orchestrator().evaluate(self.request(v0, PATCH_SAFE_DIR, n=1))
            return outcome

        with mock.patch.object(module, "decide", decide_then_let_another_promotion_land):
            result = self.evaluate(late)
        self.assertEqual(landed[0].kind, ResultKind.PROMOTED)
        self.assertIs(result.kind, ResultKind.STALE)
        assert result.decision is not None
        self.assertIs(result.decision.reason, DecisionReason.STALE_PARENT)
        self.assertEqual(self.current(), landed[0].state)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertIs(result.candidate.status, CandidateStatus.REJECTED)
        with self.uow() as u:
            self.assertEqual(describe_chain(u, late.candidate_id).problems(), [])


class TestIdempotency(OrchestratorCase):
    def test_the_same_request_again_writes_nothing(self) -> None:
        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)
        first = self.evaluate(request)
        before = dump(self.path)
        second = self.evaluate(request)
        self.assertEqual(dump(self.path), before)
        self.assertIs(second.kind, ResultKind.DUPLICATE)
        self.assertTrue(second.duplicate)
        self.assertEqual(second.state, first.state)
        self.assertEqual(second.decision, first.decision)

    def test_a_rejection_again_is_a_duplicate_with_the_same_kind(self) -> None:
        v0 = self.baseline().state
        request = self.request(v0, PATCH_REGRESSION_DIR)
        self.evaluate(request)
        before = dump(self.path)
        again = self.evaluate(request)
        self.assertIs(again.kind, ResultKind.REJECTED)
        self.assertTrue(again.duplicate)
        self.assertEqual(dump(self.path), before)

    def test_another_directory_under_the_same_ids_conflicts_and_changes_nothing(self) -> None:
        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)
        self.evaluate(request)
        before = dump(self.path)
        import dataclasses

        with self.assertRaises(ConflictingDuplicateError):
            self.evaluate(dataclasses.replace(request, candidate_dir=PATCH_REGRESSION_DIR))
        self.assertEqual(dump(self.path), before)

    def test_another_patch_under_the_same_candidate_conflicts(self) -> None:
        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)
        self.evaluate(request)
        import dataclasses

        other = self.request(v0, PATCH_SAFE_DIR, n=1)
        from core.domain.enums import CandidateSource
        from core.domain.patch import Patch

        patch = Patch.create(
            source=CandidateSource.FIXED_PATCH,
            content="a different patch\n",
            parent_state_id=v0.state_id,
            now=v0.created_at,
            patch_id=uid(3999),
        )
        with self.assertRaises(ConflictingDuplicateError):
            self.evaluate(dataclasses.replace(other, patch=patch))


class TestFailureOutsideDecisions(OrchestratorCase):
    def test_an_exception_in_a_stage_propagates_and_leaves_the_candidate_analyzing(self) -> None:
        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)

        def boom(name: str) -> None:
            if name == "after_impact":
                raise InjectedFault(name)

        with self.assertRaises(InjectedFault):
            self.evaluate(request, checkpoint=boom)
        self.assertEqual(self.current(), v0)
        with self.uow() as u:
            stored = u.candidates.get(request.candidate_id)
            chain = describe_chain(u, request.candidate_id)
        assert stored is not None
        self.assertIs(stored.status, CandidateStatus.ANALYZING)
        self.assertEqual(chain.event_types()[-1], "ERROR_OCCURRED")
        self.assertEqual(chain.problems(finished=False), [])

    def test_a_rerun_completes_with_exactly_one_new_state(self) -> None:
        v0 = self.baseline().state
        request = self.request(v0, PATCH_SAFE_DIR)

        def boom(name: str) -> None:
            if name == "after_verification":
                raise InjectedFault(name)

        with self.assertRaises(InjectedFault):
            self.evaluate(request, checkpoint=boom)
        result = self.evaluate(request)
        self.assertIs(result.kind, ResultKind.PROMOTED)
        self.assertEqual(self.count("trusted_states"), 2)
        with self.uow() as u:
            self.assertEqual(describe_chain(u, request.candidate_id).problems(), [])

    def test_the_clock_is_the_injected_one(self) -> None:
        v0 = self.baseline().state
        ticks = {"n": 0}

        def clock() -> Any:
            ticks["n"] += 1
            return fixed_clock(60)()

        self.evaluate(self.request(v0, PATCH_SAFE_DIR), clock=clock)
        self.assertGreater(ticks["n"], 0)


if __name__ == "__main__":
    unittest.main()
