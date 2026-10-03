"""P2 exit gate, end to end (Doc 11 §41, §42; Doc 15 §9.2).

Replays the paper's canonical scenario (public SSH + working EC2->RDS path) through the real P1
domain objects, the real ``EvidenceService`` and the real SQLite repositories on ONE database, and
checks the two evidence chains Doc 11 requires: the safe-promotion chain and the rejected-candidate
chain. Every evidence id a trusted state links to is a real evidence record (C-39); nothing is
synthetic.

Migrated by P2-fix step 4 from the interim-store version; the safe chain no longer supersedes
v0's evidence with candidate evidence (C-53, Doc 06 §10, §15).
"""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.domain.audit import AuditEventType
from core.domain.enums import (
    CandidateSource,
    CandidateStatus,
    InvariantCategory,
    InvariantStatus,
    ProvenanceSourceKind,
    ResourceSupport,
    VerificationResult,
)
from core.domain.evidence import EvidenceContext, EvidenceKind, EvidenceValidity
from core.domain.ids import new_uuid
from core.domain.invariant import InvariantEvaluation, InvariantProof
from core.domain.patch import Patch
from core.domain.resource import Resource
from core.domain.state import (
    CandidateState,
    TrustedState,
    finish_building,
    mark_promoted,
    start_building,
    transition_candidate,
)
from core.domain.values import Provenance
from core.persistence.schema import initialize_database
from core.persistence.sqlite import SqliteUnitOfWork
from evidence.ids import CorrelationContext
from evidence.service import EvidenceService
from tests.domain_builders import invariant

LINEAGE = "00000000-0000-4000-8000-0000000000aa"
NOW = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
K = EvidenceKind
V = EvidenceValidity
T = AuditEventType


def _resource(ssh: str) -> Resource:
    """A minimal valid normalized resource for the web node."""
    return Resource.create(
        address="aws_security_group.web-node",
        resource_type="aws_security_group",
        logical_identity={"name": "web-node"},
        attributes={"ssh": ssh},
        security_attributes={},
        semantic_attributes={},
        references=[],
        provenance=Provenance(
            source_kind=ProvenanceSourceKind.TERRAFORM_CONFIG,
            source_component="test",
            source_reference="main.tf",
            observed_at=NOW,
        ),
        support_status=ResourceSupport.SUPPORTED,
    )


def _patch(parent: TrustedState, content: str) -> Patch:
    return Patch.create(
        source=CandidateSource.FIXED_PATCH,
        content=content,
        parent_state_id=parent.state_id,
        now=NOW,
    )


def _provenance() -> Provenance:
    return Provenance(
        source_kind=ProvenanceSourceKind.DERIVED,
        source_component="p2-gate",
        source_reference="fixture",
        observed_at=NOW,
        algorithm_version="gate-1",
    )


def _verified_proof(
    parent: TrustedState, candidate: CandidateState, evidence_id: str
) -> InvariantProof:
    """INV-FUNC-001 re-verified PASS for ``candidate``: evaluation -> result -> proof (C-40)."""
    ref = next(r for r in parent.invariant_refs if r.invariant_id == "INV-FUNC-001")
    evaluation = InvariantEvaluation.affect(ref, candidate, "ssh rule changed")
    done = evaluation.start_reverification().apply_result(
        VerificationResult.PASS, [evidence_id], NOW
    )
    return done.to_proof()


class TestP2Gate(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "dail.db"
        initialize_database(self.db)
        self.svc = EvidenceService()
        self.base_ctx = CorrelationContext.new()  # the baseline's own workflow
        self.ctx = CorrelationContext.new(self.base_ctx.run_id)  # a candidate workflow, same run
        # v0 and its evidence: the evidence ids are chosen first, so the state can link to them
        self.e_func0 = new_uuid()
        self.s0 = TrustedState.establish_baseline(
            lineage_id=LINEAGE,
            resources=[_resource("ssh-open")],
            invariant_proofs=[
                InvariantProof.for_baseline(
                    invariant_id="INV-FUNC-001",
                    invariant_version=1,
                    status=InvariantStatus.PROTECTED,
                    evidence_ids=(self.e_func0,),
                    verified_at=NOW,
                )
            ],
            evidence_refs=[self.e_func0],
            normalization_version="norm-1",
            invariant_registry_version=1,
            now=NOW,
        )
        with SqliteUnitOfWork(self.db) as uow:
            uow.invariants.register_definition(
                invariant("INV-FUNC-001", InvariantCategory.FUNCTIONAL)
            )
            # evidence about v0 may be written before v0 itself: the foreign key is deferred
            self._record(
                uow,
                self.base_ctx,
                K.VERIFICATION,
                {"invariant": "INV-FUNC-001", "result": "PASS"},
                evidence_id=self.e_func0,
                state_id=self.s0.state_id,
                state_hash=self.s0.state_hash,
            )
            self._record(
                uow,
                self.base_ctx,
                K.STATE,
                {"version": 0, "state_hash": self.s0.state_hash},
                state_id=self.s0.state_id,
                state_hash=self.s0.state_hash,
            )
            uow.trusted_states.save_baseline(self.s0)
            self._event(
                uow,
                self.base_ctx,
                T.STATE_CREATED,
                {
                    "lineage_id": LINEAGE,
                    "version": 0,
                    "parent_state_id": None,
                    "state_hash": self.s0.state_hash,
                },
                state_id=self.s0.state_id,
            )
        self.v0_ctx = EvidenceContext.state(self.s0.state_id)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # --- helpers ------------------------------------------------------------------------------

    def _record(
        self, uow: Any, ctx: CorrelationContext, kind: K, payload: Any, **binding: Any
    ) -> Any:
        return self.svc.record(
            uow,
            kind=kind,
            event_name=f"{kind.value.lower()}_recorded",
            payload=payload,
            ctx=ctx,
            provenance=_provenance(),
            now=NOW,
            **binding,
        ).record

    def _event(
        self, uow: Any, ctx: CorrelationContext, event_type: T, payload: Any, **cols: Any
    ) -> Any:
        return self.svc.append_audit_event(
            uow, event_type=event_type, ctx=ctx, payload=payload, now=NOW, **cols
        ).event

    def _candidate(self, patch_content: str, sequence: int = 1) -> CandidateState:
        patch = _patch(self.s0, patch_content)
        with SqliteUnitOfWork(self.db) as uow:
            uow.patches.save(patch)  # the raw patch is retained apart from its candidate
        return CandidateState.create(
            parent=self.s0, patch=patch, candidate_sequence=sequence, now=NOW
        )

    def _save_candidate(self, candidate: CandidateState) -> None:
        with SqliteUnitOfWork(self.db) as uow:
            uow.candidates.create(candidate)

    def _save_transition(self, candidate: CandidateState) -> None:
        with SqliteUnitOfWork(self.db) as uow:
            uow.candidates.save_transition(candidate)

    def _load_candidate(self, candidate_id: str) -> CandidateState | None:
        with SqliteUnitOfWork(self.db) as uow:
            return uow.candidates.get(candidate_id)

    def _count(self, table: str) -> int:
        with closing(sqlite3.connect(self.db)) as conn:
            return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def _lineage(self, state_id: str) -> list[TrustedState]:
        with SqliteUnitOfWork(self.db) as uow:
            return uow.trusted_states.lineage(state_id)

    def _to_analyzing(self, candidate: CandidateState, ssh: str) -> CandidateState:
        """Build the candidate and move it to ANALYZING, storing each step (Doc 06 section 5)."""
        for step in (
            start_building,
            lambda c: finish_building(c, [_resource(ssh)]),
            lambda c: transition_candidate(c, CandidateStatus.ANALYZING),
        ):
            candidate = step(candidate)
            self._save_transition(candidate)
        return candidate

    def _created_event(self, candidate: CandidateState) -> None:
        with SqliteUnitOfWork(self.db) as uow:
            self._event(
                uow,
                self.attempt_ctx,
                T.CANDIDATE_CREATED,
                {
                    "parent_state_id": self.s0.state_id,
                    "patch_id": candidate.patch_id,
                    "source": candidate.source.value,
                },
                candidate_id=candidate.candidate_id,
            )

    def _for_candidate(self, candidate: CandidateState) -> dict[str, Any]:
        """The binding of evidence about ``candidate``: its attempt, parent and state hash."""
        return {
            "candidate_id": candidate.candidate_id,
            "parent_state_id": candidate.parent_state_id,
            "state_hash": candidate.state_hash,
        }

    # --- tests --------------------------------------------------------------------------------

    def test_domain_and_evidence_tables_coexist_in_one_database(self) -> None:
        self.assertEqual(self._count("trusted_states"), 1)
        with SqliteUnitOfWork(self.db) as uow:
            # v0's state evidence and its verification evidence, linked from the state itself
            kinds = {e.kind for e in self.svc.evidence_for_state(uow, self.s0.state_id)}
            self.assertEqual(kinds, {K.VERIFICATION, K.STATE})
            for evidence_id in self.s0.evidence_refs:
                self.assertIsNotNone(uow.evidence.get(evidence_id))

    def test_rejected_candidate_chain(self) -> None:
        """Doc 11 §42. Candidate 1 fixes SSH but breaks EC2->RDS. v0's evidence becomes INVALID
        *for c1* (with the impact reference); it stays VALID for v0 (Doc 06 §15, C-52). The failing
        verification is recorded; the candidate is rejected; the trusted state does not advance."""
        self.attempt_ctx = self.ctx.with_attempt()
        c1 = self._candidate('remove "ssh"; narrow "ec2_to_rds"\n')
        self._save_candidate(c1)
        self._created_event(c1)
        c1 = self._to_analyzing(c1, "ssh-closed")
        c1_ctx = EvidenceContext.candidate(c1.candidate_id)

        with SqliteUnitOfWork(self.db) as uow:
            impact = self._record(
                uow,
                self.attempt_ctx,
                K.IMPACT,
                {"affected": ["INV-SEC-001", "INV-FUNC-001"]},
                **self._for_candidate(c1),
            )
            self._event(uow, self.attempt_ctx, T.IMPACT_COMPLETED, {}, candidate_id=c1.candidate_id)
            self._event(
                uow,
                self.attempt_ctx,
                T.INVARIANT_AFFECTED,
                {"invariant_id": "INV-FUNC-001", "invariant_version": 1, "reason": "ec2_to_rds"},
                state_id=self.s0.state_id,
                candidate_id=c1.candidate_id,
            )
            # Impact invalidates v0's evidence for INV-FUNC-001 ... for c1
            self.svc.invalidate(
                uow,
                self.e_func0,
                context=c1_ctx,
                reason="INV-FUNC-001 affected by candidate",
                ctx=self.attempt_ctx,
                impact_ref=impact.evidence_id,
                now=NOW,
            )
            # ... so the old PASS is INVALID for c1 (Doc 11 §7), but it still describes v0 and
            # "a rejected candidate does not consume or rewrite the evidence attached to the
            # active Trusted State" (Doc 06 §15): usable for v0.
            self.assertIs(self.svc.validity_in(uow, self.e_func0, c1_ctx), V.INVALID)
            self.assertIs(self.svc.validity_in(uow, self.e_func0, self.v0_ctx), V.VALID)
            self.assertTrue(self.svc.usable_as_proof(uow, self.e_func0, self.v0_ctx).usable)
            self.assertFalse(self.svc.usable_as_proof(uow, self.e_func0, c1_ctx).usable)
            self.assertEqual(
                self.svc.resolve_payload(uow, self.e_func0)["result"], "PASS"
            )  # history kept

            # Fresh verification against the candidate FAILS.
            v = self._record(
                uow,
                self.attempt_ctx,
                K.VERIFICATION,
                {"invariant": "INV-FUNC-001", "result": "FAIL"},
                **self._for_candidate(c1),
            )
            self._event(
                uow,
                self.attempt_ctx,
                T.VERIFICATION_COMPLETED,
                {
                    "verification_id": new_uuid(),
                    "target": c1.candidate_id,
                    "result": "FAIL",
                    "verifier_id": "func-001",
                    "verifier_version": "1",
                },
                candidate_id=c1.candidate_id,
            )
        c1 = transition_candidate(c1, CandidateStatus.REJECTED)
        self._save_transition(c1)
        with SqliteUnitOfWork(self.db) as uow:
            self._event(
                uow, self.attempt_ctx, T.CANDIDATE_REJECTED, {}, candidate_id=c1.candidate_id
            )

        with SqliteUnitOfWork(self.db) as uow:
            self.assertTrue(self.svc.usable_as_proof(uow, v.evidence_id, c1_ctx).usable)
            # The whole chain, in order, reconstructable from one correlation id:
            chain = [
                e.event_type
                for e in self.svc.events_for_correlation(uow, self.attempt_ctx.correlation_id)
            ]
            self.assertEqual(
                chain,
                [
                    T.CANDIDATE_CREATED,
                    T.IMPACT_COMPLETED,
                    T.INVARIANT_AFFECTED,
                    T.EVIDENCE_VALIDITY_CHANGED,
                    T.VERIFICATION_COMPLETED,
                    T.CANDIDATE_REJECTED,
                ],
            )
            # The rejected candidate's records all remain.
            self.assertEqual(len(self.svc.evidence_for_candidate(uow, c1.candidate_id)), 2)
        # Trusted state did not advance; the rejected candidate remains.
        self.assertEqual(self._count("trusted_states"), 1)
        self.assertIsNotNone(self._load_candidate(c1.candidate_id))

    def test_safe_promotion_chain(self) -> None:
        """Doc 11 §41. Candidate 2 fixes SSH and preserves the DB path. A repeated verification
        supersedes the first one *about the same candidate*; the lineage back to genesis stays
        intact. (The interim test superseded v0's evidence with candidate evidence: withdrawn,
        C-53.)"""
        self.attempt_ctx = self.ctx.with_attempt()
        c2 = self._candidate('remove "ssh"\n')
        self._save_candidate(c2)
        self._created_event(c2)
        c2 = self._to_analyzing(c2, "ssh-closed")
        c2_ctx = EvidenceContext.candidate(c2.candidate_id)

        with SqliteUnitOfWork(self.db) as uow:
            self._record(
                uow,
                self.attempt_ctx,
                K.IMPACT,
                {"affected": ["INV-SEC-001"]},
                **self._for_candidate(c2),
            )
            self._event(uow, self.attempt_ctx, T.IMPACT_COMPLETED, {}, candidate_id=c2.candidate_id)
            first_pass = self._record(
                uow,
                self.attempt_ctx,
                K.VERIFICATION,
                {"invariant": "INV-FUNC-001", "result": "PASS"},
                **self._for_candidate(c2),
            )
            # the verification is repeated (a corrected artifact): it supersedes the first one
            new_pass = self._record(
                uow,
                self.attempt_ctx,
                K.VERIFICATION,
                {"invariant": "INV-FUNC-001", "result": "PASS", "run": 2},
                **self._for_candidate(c2),
            )
            self.svc.supersede(
                uow,
                first_pass.evidence_id,
                new_pass.evidence_id,
                reason="re-verified on the same candidate",
                ctx=self.attempt_ctx,
                now=NOW,
            )
            self._event(
                uow,
                self.attempt_ctx,
                T.VERIFICATION_COMPLETED,
                {
                    "verification_id": new_uuid(),
                    "target": c2.candidate_id,
                    "result": "PASS",
                    "verifier_id": "func-001",
                    "verifier_version": "1",
                },
                candidate_id=c2.candidate_id,
            )
        c2 = transition_candidate(c2, CandidateStatus.PROMOTABLE)
        self._save_transition(c2)

        decision_id = new_uuid()
        with SqliteUnitOfWork(self.db) as uow:
            self._record(
                uow,
                self.attempt_ctx,
                K.PROMOTION,
                {"decision": "PROMOTE", "preconditions": ["verified"]},
                **self._for_candidate(c2),
            )
            self._event(
                uow,
                self.attempt_ctx,
                T.PROMOTION_DECIDED,
                {"parent_state_id": self.s0.state_id, "decision": "PROMOTE", "policy_version": "1"},
                candidate_id=c2.candidate_id,
                decision_id=decision_id,
            )
        s1 = TrustedState.promote(
            candidate=c2,
            current=self.s0,
            decision_id=decision_id,
            invariant_proofs=[_verified_proof(self.s0, c2, new_pass.evidence_id)],
            evidence_refs=[new_pass.evidence_id],
            invariant_registry_version=1,
            now=NOW,
        )
        c2 = mark_promoted(c2, s1)
        with SqliteUnitOfWork(self.db) as uow:  # one transaction (Doc 05 section 32)
            uow.trusted_states.save_promoted(s1)
            uow.candidates.save_transition(c2)
            self._event(
                uow,
                self.attempt_ctx,
                T.STATE_PROMOTED,
                {"parent_state_id": self.s0.state_id},
                state_id=s1.state_id,
                decision_id=decision_id,
            )

        self.assertEqual([s.version for s in self._lineage(s1.state_id)], [1, 0])
        with SqliteUnitOfWork(self.db) as uow:
            # the first verification is superseded, never deleted; the repeat is VALID and proof
            self.assertIs(self.svc.validity_in(uow, first_pass.evidence_id, c2_ctx), V.SUPERSEDED)
            self.assertIs(self.svc.validity_in(uow, new_pass.evidence_id, c2_ctx), V.VALID)
            self.assertFalse(self.svc.usable_as_proof(uow, first_pass.evidence_id, c2_ctx).usable)
            self.assertTrue(self.svc.usable_as_proof(uow, new_pass.evidence_id, c2_ctx).usable)
            self.assertEqual(
                self.svc.supersession_chain(uow, new_pass.evidence_id),
                (first_pass.evidence_id, new_pass.evidence_id),
            )
            # v0's own evidence is untouched by a promotion elsewhere in the lineage
            self.assertIs(self.svc.validity_in(uow, self.e_func0, self.v0_ctx), V.VALID)
            types = [
                e.event_type
                for e in self.svc.events_for_correlation(uow, self.attempt_ctx.correlation_id)
            ]
            # the new state links to evidence that exists
            for evidence_id in s1.evidence_refs:
                self.assertIsNotNone(uow.evidence.get(evidence_id))
        self.assertIn(T.STATE_PROMOTED, types)
        self.assertEqual(types[-1], T.STATE_PROMOTED)
        self.assertIn(T.EVIDENCE_VALIDITY_CHANGED, types)  # the supersession (C-57)
        self.assertEqual(self._count("trusted_states"), 2)

    def test_list_for_attempt_returns_exactly_the_attempts_records(self) -> None:
        """Doc 05 §26: ``list_for_attempt(attempt_id)``. Two candidates, two attempts: each attempt
        sees its own records and nothing else, and v0's baseline evidence (no attempt) is in
        neither.
        """
        contexts = {}
        records: dict[str, list[str]] = {}
        for n, content in enumerate(('remove "ssh"\n', 'remove "ssh"; narrow "ec2_to_rds"\n'), 1):
            ctx = self.ctx.with_attempt()
            candidate = self._candidate(content, sequence=n)
            self._save_candidate(candidate)
            candidate = self._to_analyzing(candidate, "ssh-closed")
            with SqliteUnitOfWork(self.db) as uow:
                records[ctx.attempt_id or ""] = [
                    self._record(
                        uow,
                        ctx,
                        kind,
                        {"n": n, "kind": kind.value},
                        **self._for_candidate(candidate),
                    ).evidence_id
                    for kind in (K.IMPACT, K.VERIFICATION)
                ]
            contexts[n] = ctx
        with SqliteUnitOfWork(self.db) as uow:
            for attempt_id, expected in records.items():
                got = [e.evidence_id for e in self.svc.evidence_for_attempt(uow, attempt_id)]
                self.assertEqual(got, expected)
            self.assertEqual(
                self.svc.evidence_for_attempt(uow, self.base_ctx.attempt_id or new_uuid()), ()
            )
            every_attempt_record = {r for ids in records.values() for r in ids}
            self.assertNotIn(self.e_func0, every_attempt_record)

    def test_the_chains_join_to_the_trusted_state_lineage(self) -> None:
        """Doc 11 §40 (lineage queries): every record of a chain joins to the lineage it belongs
        to, through its candidate or through its trusted state."""
        self.test_rejected_candidate_chain()
        with closing(sqlite3.connect(self.db)) as conn:
            via_candidate = {
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT c.lineage_id FROM evidence_events e "
                    "JOIN candidates c ON c.candidate_id = e.candidate_id"
                )
            }
            via_state = {
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT s.lineage_id FROM evidence_events e "
                    "JOIN trusted_states s ON s.state_id = e.state_id"
                )
            }
            unjoined = conn.execute(
                "SELECT COUNT(*) FROM evidence_events e WHERE e.candidate_id IS NULL "
                "AND e.state_id IS NULL"
            ).fetchone()[0]
        self.assertEqual(via_candidate, {LINEAGE})
        self.assertEqual(via_state, {LINEAGE})
        self.assertEqual(unjoined, 0)  # every record of the gate scenario is bound to something


if __name__ == "__main__":
    unittest.main()
