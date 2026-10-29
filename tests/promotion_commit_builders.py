"""Builders for the commit tests (P6b steps 5 and 6). Not a test module.

``CommitCase`` stores the canonical world of ``tests/promotion_builders.py`` in a real SQLite file:
the four registry definitions, the baseline v0 (with evidence bound to it), and the candidate walked
to ANALYZING or PROMOTABLE. It also stores the evidence of every verification result the way the
verification engine's ``to_evidence_submission`` does (candidate-bound, with the candidate's hash),
which P6c's orchestrator will do in production, and gives the commit a factory that opens units of
work on the file (with an optional fault-injection checkpoint).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any

from core.domain.enums import CandidateStatus
from core.domain.repositories import UnitOfWork
from core.domain.state import CandidateState, TrustedState
from core.promotion.commit import CommitResult, PromotionContext, commit_promotion
from core.verification.engine import to_evidence_submission
from tests.domain_builders import at, patch_for, uid
from tests.persistence_builders import RepoCase, seed_evidence, stages
from tests.promotion_builders import (
    BASELINE_ITEM,
    FUNC1,
    SEC1,
    SEC2,
    SEC3,
    World,
    impact_for,
    make_world,
    record,
    report_of,
    run,
    target,
)

CONTEXT = PromotionContext(
    run_id=uid(0x7A01),
    correlation_id=uid(0x7A02),
    operation_id=uid(0x7A03),
    attempt_id=uid(0x7A04),
    actor_id=None,
)
NOW = at(30)


class CommitCase(RepoCase):
    """A database holding a baseline and the PROMOTABLE candidate of ``make_world()``."""

    stored_status = CandidateStatus.PROMOTABLE

    def setUp(self) -> None:
        super().setUp()
        self.world: World = make_world(candidate_status=self.stored_status)
        self.install(self.world)
        self.evidence_ids: dict[str, str] = self.store_results(self.world)

    # --- installing a world --------------------------------------------------------------------

    def install(self, world: World, *, n: int = 1) -> None:
        """Register the definitions, store the baseline and walk the candidate."""
        with self.uow() as u:
            for definition in world.definitions.values():
                u.invariants.register_definition(definition)
            self.seeded_evidence += seed_evidence(u, world.trusted, bound=True)
            u.trusted_states.save_baseline(world.trusted)
        self.store_candidate(world, n=n)

    def store_candidate(self, world: World, *, n: int = 1, sequence: int = 1) -> CandidateState:
        upto = 4 if world.candidate.status is CandidateStatus.PROMOTABLE else 3
        steps = stages(world.trusted, list(world.candidate.resources), n=n, sequence=sequence)
        with self.uow() as u:
            u.patches.save(patch_for(world.trusted, n=n))
            u.candidates.create(steps[0])
            for step in steps[1 : upto + 1]:
                u.candidates.save_transition(step)
        assert steps[upto].candidate_id == world.candidate.candidate_id
        assert steps[upto].state_hash == world.candidate.state_hash
        return steps[upto]

    def store_results(self, world: World, *, first: int = 0) -> dict[str, str]:
        """The evidence record of every verification result, by verification id."""
        found: dict[str, str] = {}
        with self.uow() as u:
            for index, result in enumerate(world.verification.results, start=first):
                evidence_id = uid(8800 + index)
                u.evidence.append(
                    to_evidence_submission(
                        result,
                        evidence_id=evidence_id,
                        run_id=CONTEXT.run_id,
                        attempt_id=CONTEXT.attempt_id,
                        correlation_id=CONTEXT.correlation_id,
                        operation_id=CONTEXT.operation_id,
                        parent_state_id=world.trusted.state_id,
                    )
                )
                found[result.verification_id] = evidence_id
        return found

    # --- committing ----------------------------------------------------------------------------

    def factory(self, checkpoint: Callable[[str], None] | None = None) -> Callable[[], UnitOfWork]:
        return lambda: self.uow(checkpoint=checkpoint)

    def commit(
        self,
        world: World | None = None,
        *,
        outcome: Any = None,
        checkpoint: Callable[[str], None] | None = None,
        evidence_ids: dict[str, str] | None = None,
        **options: Any,
    ) -> CommitResult:
        chosen = world or self.world
        return commit_promotion(
            self.factory(checkpoint),
            outcome or run(chosen),
            chosen.candidate,
            chosen.impact,
            chosen.verification,
            chosen.policy,
            self.evidence_ids if evidence_ids is None else evidence_ids,
            CONTEXT,
            now=NOW,
            **options,
        )

    # --- reading -------------------------------------------------------------------------------

    def current(self) -> TrustedState:
        with self.uow() as u:
            state = u.trusted_states.get_current(self.world.trusted.lineage_id)
        assert state is not None
        return state

    def candidate_status(self, candidate_id: str | None = None) -> str:
        return self.scalar(
            "SELECT status FROM candidates WHERE candidate_id = ?",
            (candidate_id or self.world.candidate.candidate_id,),
        )

    def audit_types(self) -> list[str]:
        with self.uow() as u:
            events = u.audit.list_for_candidate(self.world.candidate.candidate_id)
        return [e.event_type.value for e in events]

    def next_world(self, state: TrustedState, *, sequence: int = 2, n: int = 2) -> World:
        """A second candidate from ``state`` (a promoted state): INV-FUNC-001 is affected, the other
        three are unaffected with eligible evidence."""
        from tests.domain_builders import analyzing_candidate, canonical_resources

        candidate = analyzing_candidate(
            state,
            canonical_resources(ssh_open=False, db_path=True),
            sequence=sequence,
            n=n,
        )
        candidate = dataclasses.replace(candidate) if False else candidate
        impact = impact_for(state, candidate, affected=(FUNC1,), carry=(SEC1, SEC2, SEC3))
        definition = self.world.definitions[FUNC1]
        records = [
            record(candidate, "STRUCTURAL", n=1),
            record(candidate, "CONSISTENCY", n=2),
            record(candidate, target(FUNC1), definition=definition, n=3),
            record(candidate, BASELINE_ITEM, n=4),
        ]
        return dataclasses.replace(
            self.world,
            trusted=state,
            candidate=candidate,
            impact=impact,
            verification=report_of(candidate, records),
            records={r.target_id: r for r in records},
        )
