"""Builders for the P6c tests (chain checker, orchestrator, end-to-end suites). Not a test module.

``ChainCase`` writes the evidence chain of one candidate by hand: it records the stages through the
production ``StageRecorder`` and then decides, records and commits with the P6a/P6b functions, in
the order of C-172. It is a *reference writer* for the checker tests: the checker
(``core.application.chain``) is shown to accept what it writes and to fire when a record is
missing, out of order or tampered. The orchestrator itself is tested in ``test_orchestrator.py``
with ``describe_chain`` on the chains it writes.
"""

from __future__ import annotations

from typing import Any

from core.application import ids as oids
from core.application.recorder import StageRecorder
from core.domain.audit import AuditEventType
from core.domain.enums import DecisionType
from core.domain.patch import Patch
from core.domain.promotion import DecisionOutcome
from core.domain.state import TrustedState
from core.promotion.commit import CommitResult, commit_promotion, record_decision
from core.promotion.decide import decide
from tests.domain_builders import patch_for, uid
from tests.identity_builders import NOW as PIPELINE_NOW
from tests.promotion_commit_builders import CONTEXT, NOW
from tests.promotion_pipeline import PipelineRun, fixtures_with_a_parent, pipeline
from tests.promotion_pipeline_commit import PipelineCommitCase

SAFE = "canonical_safe_repair_promote_v1"
REGRESSION = "canonical_security_repair_breaks_function_reject_v1"
STAGES = ("state", "identity", "dependency", "impact", "verification")


def run_for(
    fixture_id: str, *, candidate_id: str | None = None, sequence: int = 1, patch_n: int = 7
) -> PipelineRun:
    """The real P6a pipeline on one fixture (uncached: every call draws new report ids)."""
    options: dict[str, Any] = {"sequence": sequence, "patch_n": patch_n}
    if candidate_id is not None:
        options["candidate_id"] = candidate_id
    return pipeline(fixtures_with_a_parent()[fixture_id], **options)


class ChainCase(PipelineCommitCase):
    """A database in which chains are written the way the orchestrator writes them."""

    def setUp(self) -> None:
        super().setUp()
        self.recorder = StageRecorder(CONTEXT)
        self.patch_numbers: dict[str, int] = {}

    def patch_of(self, run: PipelineRun) -> Patch:
        return patch_for(run.trusted, n=self.patch_numbers.get(run.candidate.candidate_id, 7))

    # --- the pieces ----------------------------------------------------------------------------

    def current_state(self, run: PipelineRun) -> TrustedState:
        with self.uow() as u:
            state = u.trusted_states.get_current(run.trusted.lineage_id)
        assert state is not None
        return state

    def emit_created(self, run: PipelineRun, *, attempt: int = 1) -> None:
        cid = run.candidate.candidate_id
        patch = self.patch_of(run)
        with self.uow() as u:
            self.recorder.emit(
                u,
                AuditEventType.CANDIDATE_CREATED,
                event_id=oids.event_id_for(cid, attempt, AuditEventType.CANDIDATE_CREATED),
                payload={
                    "parent_state_id": run.trusted.state_id,
                    "patch_id": patch.patch_id,
                    "source": patch.source.value,
                },
                when=NOW,
                candidate_id=cid,
            )

    def record_stage(self, run: PipelineRun, stage: str, *, attempt: int = 1) -> Any:
        """One stage, in a unit of work of its own (a crash after it leaves it)."""
        c, at = run.candidate, PIPELINE_NOW
        with self.uow() as u:
            if stage == "state":
                return self.recorder.record_candidate(
                    u, c, self.patch_of(run), attempt_number=attempt, at=at
                )
            if stage == "identity":
                return self.recorder.record_identity(
                    u, c, run.inputs.identity, attempt_number=attempt, at=at, when=NOW
                )
            if stage == "dependency":
                return self.recorder.record_dependency(
                    u, c, run.inputs.candidate_graph, attempt_number=attempt, at=at, when=NOW
                )
            if stage == "impact":
                return self.recorder.record_impact(
                    u, c, run.impact, attempt_number=attempt, at=at, when=NOW
                )
            return self.recorder.record_verification(
                u, c, run.verification, attempt_number=attempt, when=NOW
            )

    def decide_and_record(
        self, run: PipelineRun, *, attempt: int = 1, decision_id: str | None = None, **policy: Any
    ) -> tuple[DecisionOutcome, Any]:
        """``decide`` against the current state, then ``record_decision``."""
        cid = run.candidate.candidate_id
        chosen = decision_id or oids.decision_id_for(cid, attempt)
        policy_object = run.policy(**policy)
        outcome = decide(
            run.candidate,
            self.current_state(run),
            run.impact,
            run.verification,
            policy_object,
            decision_id=chosen,
            now=PIPELINE_NOW,
            attempt_number=attempt,
        )
        with self.uow() as u:
            record_decision(u, outcome, run.candidate, CONTEXT, now=NOW)
        return outcome, policy_object

    def request_and_commit(
        self,
        run: PipelineRun,
        outcome: DecisionOutcome,
        policy: Any,
        evidence_ids: dict[str, str],
        *,
        attempt: int = 1,
    ) -> CommitResult:
        cid = run.candidate.candidate_id
        decision = outcome.decision
        with self.uow() as u:
            self.recorder.emit(
                u,
                AuditEventType.PROMOTION_REQUESTED,
                event_id=oids.event_id_for(cid, attempt, AuditEventType.PROMOTION_REQUESTED),
                payload={
                    "decision_id": decision.decision_id,
                    "parent_state_id": decision.parent_state_id,
                },
                when=NOW,
                candidate_id=cid,
                decision_id=decision.decision_id,
            )
        return commit_promotion(
            lambda: self.uow(),
            outcome,
            run.candidate,
            run.impact,
            run.verification,
            policy,
            evidence_ids,
            CONTEXT,
            now=NOW,
            attempt_number=attempt,
        )

    # --- whole chains --------------------------------------------------------------------------

    def write_chain(
        self,
        run: PipelineRun,
        *,
        attempt: int = 1,
        order: tuple[str, ...] = STAGES,
        stages: tuple[str, ...] | None = None,
        decide_now: bool = True,
        **policy: Any,
    ) -> tuple[DecisionOutcome | None, CommitResult | None]:
        """CANDIDATE_CREATED, the stages (``order``, optionally only ``stages``), the decision, and
        for a PROMOTE the request and the commit. The candidate must be stored (``self.store``)."""
        self.emit_created(run, attempt=attempt)
        evidence_ids: dict[str, str] = {}
        for stage in order:
            if stages is not None and stage not in stages:
                continue
            found = self.record_stage(run, stage, attempt=attempt)
            if stage == "verification":
                evidence_ids = found
        if not decide_now:
            return None, None
        outcome, used = self.decide_and_record(run, attempt=attempt, **policy)
        if outcome.decision.decision is not DecisionType.PROMOTE:
            return outcome, None
        return outcome, self.request_and_commit(run, outcome, used, evidence_ids, attempt=attempt)

    def promoted_chain(self, *, fixture_id: str = SAFE) -> PipelineRun:
        """Install the world of ``fixture_id`` and promote its candidate with a complete chain."""
        run = run_for(fixture_id)
        self.install(run)
        self.store(run)
        outcome, result = self.write_chain(run)
        assert outcome is not None and result is not None and result.state is not None
        return run

    def rejected_chain(self) -> PipelineRun:
        run = run_for(REGRESSION)
        self.install(run)
        self.store(run)
        outcome, result = self.write_chain(run)
        assert outcome is not None and outcome.decision.decision is DecisionType.REJECT
        assert result is None
        return run

    def second_candidate(self, fixture_id: str = SAFE) -> PipelineRun:
        """A candidate written against v0 beside the first (candidate id, sequence and patch of
        its own); it is stale once the first is promoted."""
        run = run_for(fixture_id, candidate_id=uid(3998), sequence=2, patch_n=8)
        self.patch_numbers[run.candidate.candidate_id] = 8
        self.store(run, sequence=2, patch_n=8)
        return run
