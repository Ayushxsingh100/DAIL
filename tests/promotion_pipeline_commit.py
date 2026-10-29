"""The real pipeline's runs, stored in a database and committed (P6b step 6). Not a test module.

``tests/promotion_pipeline.py`` (P6a) runs normalisation, identity, graphs, impact, the scope
policy, the verification engine and ``decide`` on a fixture. ``PipelineCommitCase`` puts such a
run in a SQLite file the way P6c's orchestrator will: the registry definitions, the trusted state
with its evidence, the candidate walked to ANALYZING, and the evidence record of every
verification result (this is the helper the P6b prompt allows in place of a pipeline that records
evidence; nothing here is production code). ``decide`` is the real one; nothing computes an
expected decision.
"""

from __future__ import annotations

from typing import Any

from core.domain.enums import CandidateStatus
from core.domain.state import (
    CandidateState,
    TrustedState,
    finish_building,
    start_building,
    transition_candidate,
)
from core.promotion.commit import CommitResult, commit_promotion, record_decision
from core.verification.engine import to_evidence_submission
from tests.domain_builders import patch_for, uid
from tests.identity_builders import NOW as PIPELINE_NOW
from tests.persistence_builders import RepoCase, seed_evidence
from tests.promotion_commit_builders import CONTEXT, NOW
from tests.promotion_pipeline import PipelineRun


class PipelineCommitCase(RepoCase):
    def install(self, run: PipelineRun) -> None:
        """The definitions and the trusted state of ``run`` (with the evidence it links to)."""
        with self.uow() as u:
            for definition in run.definitions:
                u.invariants.register_definition(definition)
            self.seeded_evidence += seed_evidence(u, run.trusted, bound=True)
            u.trusted_states.save_baseline(run.trusted)

    def store(self, run: PipelineRun, *, sequence: int = 1, patch_n: int = 7) -> CandidateState:
        """The candidate of ``run``, walked CREATED to ANALYZING exactly as the pipeline did."""
        patch = patch_for(run.trusted, n=patch_n)
        created = CandidateState.create(
            parent=run.trusted,
            patch=patch,
            candidate_sequence=sequence,
            now=PIPELINE_NOW,
            candidate_id=run.candidate.candidate_id,
        )
        building = start_building(created)
        ready = finish_building(building, run.candidate.resources)
        analyzing = transition_candidate(ready, CandidateStatus.ANALYZING)
        assert analyzing == run.candidate
        with self.uow() as u:
            u.patches.save(patch)
            u.candidates.create(created)
            for step in (building, ready, analyzing):
                u.candidates.save_transition(step)
        return analyzing

    def store_results(self, run: PipelineRun, *, first: int) -> dict[str, str]:
        """The evidence record of every verification result of ``run``, by verification id."""
        found: dict[str, str] = {}
        with self.uow() as u:
            for index, result in enumerate(run.verification.results, start=first):
                evidence_id = uid(8800 + index)
                u.evidence.append(
                    to_evidence_submission(
                        result,
                        evidence_id=evidence_id,
                        run_id=CONTEXT.run_id,
                        attempt_id=CONTEXT.attempt_id,
                        correlation_id=CONTEXT.correlation_id,
                        operation_id=CONTEXT.operation_id,
                        parent_state_id=run.trusted.state_id,
                    )
                )
                found[result.verification_id] = evidence_id
        return found

    def prepare(
        self, run: PipelineRun, *, sequence: int = 1, patch_n: int = 7, first: int = 0
    ) -> dict[str, str]:
        """Store the candidate and the evidence of its results; return the evidence-id map."""
        self.store(run, sequence=sequence, patch_n=patch_n)
        return self.store_results(run, first=first)

    def promote(
        self,
        run: PipelineRun,
        evidence_ids: dict[str, str],
        *,
        decision_id: str,
        stateful_full: bool = False,
        record: bool = True,
        **options: Any,
    ) -> tuple[Any, CommitResult | None]:
        """``decide``, ``record_decision``, and, for a PROMOTE, ``commit_promotion``."""
        policy = run.policy(stateful_full=stateful_full)
        outcome = run.decide(policy, decision_id=decision_id)
        if record:
            with self.uow() as u:
                record_decision(u, outcome, run.candidate, CONTEXT, now=NOW)
        if outcome.decision.decision.value != "PROMOTE":
            return outcome, None
        result = commit_promotion(
            lambda: self.uow(),
            outcome,
            run.candidate,
            run.impact,
            run.verification,
            policy,
            evidence_ids,
            CONTEXT,
            now=NOW,
            **options,
        )
        return outcome, result

    def current(self, run: PipelineRun) -> TrustedState:
        with self.uow() as u:
            state = u.trusted_states.get_current(run.trusted.lineage_id)
        assert state is not None
        return state

    def status(self, candidate_id: str) -> str:
        return str(
            self.scalar("SELECT status FROM candidates WHERE candidate_id = ?", (candidate_id,))
        )
