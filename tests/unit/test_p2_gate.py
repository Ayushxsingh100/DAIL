"""P2 exit gate, end to end.

Replays the paper's canonical scenario (public SSH + working EC2->RDS path)
through the real P1 domain objects and the real P2 evidence store on ONE
shared database, then checks the two evidence chains Doc 11 Section 51.3
requires: a safe-promotion chain and a rejected-candidate chain.
"""

import tempfile
import unittest
import uuid
from datetime import UTC, datetime
from pathlib import Path

from core.domain.enums import (
    CandidateSource,
    CandidateStatus,
    InvariantStatus,
    ProvenanceSourceKind,
    ResourceSupport,
)
from core.domain.invariant import InvariantProof
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
from core.domain.storage import LocalStorage
from core.domain.values import Provenance
from evidence.ids import CorrelationContext
from evidence.models import AuditEventType, EvidenceType, EvidenceValidity
from evidence.store import EvidenceStore

LINEAGE = "00000000-0000-4000-8000-0000000000aa"
NOW = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def _uid(n: int) -> str:
    return str(uuid.UUID(int=n))


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


def _proof(evidence_n: int) -> InvariantProof:
    """INV-FUNC-001 PROTECTED. The P2 evidence ids are not UUIDs (Doc 05 §3), so a synthetic
    UUID stands in for the evidence reference here."""
    return InvariantProof.for_baseline(
        invariant_id="INV-FUNC-001",
        invariant_version=1,
        status=InvariantStatus.PROTECTED,
        evidence_ids=(_uid(evidence_n),),
        verified_at=NOW,
    )


class TestP2Gate(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "dail.db"
        self.domain = LocalStorage(self.db)
        self.domain.initialize_schema()
        self.store = EvidenceStore(self.db)  # same file as the domain tables
        self.store.initialize_schema()
        self.ctx = CorrelationContext.new()
        self.s0 = TrustedState.establish_baseline(
            lineage_id=LINEAGE,
            resources=[_resource("ssh-open")],
            invariant_proofs=[_proof(9001)],
            evidence_refs=[_uid(9001)],
            normalization_version="norm-1",
            invariant_registry_version=1,
            now=NOW,
        )
        self.domain.save_trusted_state(self.s0)
        # Baseline evidence: INV-FUNC-001 verified PASS on the trusted state.
        self.baseline_func = self._evidence(
            EvidenceType.VERIFICATION,
            {"invariant": "INV-FUNC-001", "result": "PASS"},
            state_id=self.s0.state_id,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _evidence(self, etype, payload, **binding):
        return self.store.put_evidence(
            evidence_type=etype,
            payload=payload,
            ctx=self.ctx,
            source_component="test",
            source_type="fixture",
            algorithm_or_verifier_version="test-1",
            **binding,
        ).record

    def _event(self, etype, **kw):
        return self.store.append_audit_event(event_type=etype, ctx=self.ctx, payload={}, **kw).event

    def _candidate(self, patch_content: str, sequence: int = 1) -> CandidateState:
        return CandidateState.create(
            parent=self.s0,
            patch=_patch(self.s0, patch_content),
            candidate_sequence=sequence,
            now=NOW,
        )

    def _to_analyzing(self, candidate: CandidateState, ssh: str) -> CandidateState:
        """Build the candidate and move it to ANALYZING, storing each step (Doc 06 section 5)."""
        for step in (
            start_building,
            lambda c: finish_building(c, [_resource(ssh)]),
            lambda c: transition_candidate(c, CandidateStatus.ANALYZING),
        ):
            candidate = step(candidate)
            self.domain.update_candidate(candidate)
        return candidate

    def test_domain_and_evidence_tables_coexist_in_one_database(self) -> None:
        self.assertEqual(self.domain.count_trusted_states(), 1)
        self.assertEqual(len(self.store.evidence_for_state(self.s0.state_id)), 1)

    def test_rejected_candidate_chain(self) -> None:
        """Candidate 1: fixes SSH but breaks EC2->RDS. Baseline evidence must
        be invalidated by impact analysis; the failing verification must be
        recorded; the candidate is rejected; trusted state does not advance."""
        c1 = self._candidate('remove "ssh"; narrow "ec2_to_rds"\n')
        self.domain.save_candidate(c1)
        self._event(
            AuditEventType.CANDIDATE_CREATED,
            candidate_id=c1.candidate_id,
            state_id=self.s0.state_id,
        )
        impact = self._evidence(
            EvidenceType.IMPACT,
            {"affected": ["INV-SEC-001", "INV-FUNC-001"]},
            candidate_id=c1.candidate_id,
        )
        self._event(AuditEventType.IMPACT_COMPLETED, candidate_id=c1.candidate_id)

        # Impact invalidates the baseline evidence for INV-FUNC-001 ...
        self.store.invalidate(
            self.baseline_func.evidence_id,
            reason="INV-FUNC-001 affected by candidate",
            ctx=self.ctx,
            candidate_id=c1.candidate_id,
            impact_report_ref=impact.evidence_id,
        )
        # ... so the old PASS is no longer proof, even though it is still on record.
        self.assertFalse(
            self.store.usable_as_proof(
                self.baseline_func.evidence_id, state_id=self.s0.state_id
            ).usable
        )
        self.assertEqual(
            self.store.resolve_payload(self.baseline_func)["result"], "PASS"
        )  # history kept

        # Fresh verification against the candidate FAILS.
        v = self._evidence(
            EvidenceType.VERIFICATION,
            {"invariant": "INV-FUNC-001", "result": "FAIL"},
            candidate_id=c1.candidate_id,
        )
        self._event(AuditEventType.VERIFICATION_COMPLETED, candidate_id=c1.candidate_id)
        c1 = self._to_analyzing(c1, "ssh-closed")
        c1 = transition_candidate(c1, CandidateStatus.REJECTED)
        self.domain.update_candidate(c1)
        self._event(AuditEventType.CANDIDATE_REJECTED, candidate_id=c1.candidate_id)

        self.assertTrue(
            self.store.usable_as_proof(v.evidence_id, candidate_id=c1.candidate_id).usable
        )
        # The whole chain, in order, reconstructable from one correlation id:
        chain = [e.event_type for e in self.store.events_for_correlation(self.ctx.correlation_id)]
        self.assertEqual(
            chain,
            [
                AuditEventType.CANDIDATE_CREATED,
                AuditEventType.IMPACT_COMPLETED,
                AuditEventType.EVIDENCE_INVALIDATED,
                AuditEventType.VERIFICATION_COMPLETED,
                AuditEventType.CANDIDATE_REJECTED,
            ],
        )
        # Trusted state did not advance; the rejected candidate and all evidence remain.
        self.assertEqual(self.domain.count_trusted_states(), 1)
        self.assertIsNotNone(self.domain.load_candidate(c1.candidate_id))
        self.assertEqual(len(self.store.evidence_for_candidate(c1.candidate_id)), 2)

    def test_safe_promotion_chain(self) -> None:
        """Candidate 2: fixes SSH, preserves the DB path. Evidence supersedes
        the old, and the lineage back to genesis stays intact."""
        c2 = self._candidate('remove "ssh"\n')
        self.domain.save_candidate(c2)
        self._event(
            AuditEventType.CANDIDATE_CREATED,
            candidate_id=c2.candidate_id,
            state_id=self.s0.state_id,
        )
        new_pass = self._evidence(
            EvidenceType.VERIFICATION,
            {"invariant": "INV-FUNC-001", "result": "PASS"},
            candidate_id=c2.candidate_id,
        )
        self._event(AuditEventType.VERIFICATION_COMPLETED, candidate_id=c2.candidate_id)
        c2 = self._to_analyzing(c2, "ssh-closed")
        c2 = transition_candidate(c2, CandidateStatus.PROMOTABLE)
        self.domain.update_candidate(c2)
        s1 = TrustedState.promote(
            candidate=c2,
            current=self.s0,
            decision_id=_uid(9100),
            invariant_proofs=[_proof(9002)],
            evidence_refs=[_uid(9002)],
            invariant_registry_version=1,
            now=NOW,
        )
        c2 = mark_promoted(c2, s1)
        self.domain.update_candidate(c2)
        self.domain.save_trusted_state(s1)
        self._event(
            AuditEventType.STATE_PROMOTED, candidate_id=c2.candidate_id, state_id=s1.state_id
        )
        # Baseline evidence is superseded by the re-verification, never deleted.
        self.store.supersede(
            self.baseline_func.evidence_id,
            new_pass.evidence_id,
            reason="re-verified on promoted candidate",
            ctx=self.ctx,
        )

        self.assertEqual(
            [s.version for s in self.domain.trusted_state_lineage(s1.state_id)], [1, 0]
        )
        self.assertEqual(
            self.store.current_validity(self.baseline_func.evidence_id), EvidenceValidity.SUPERSEDED
        )
        self.assertEqual(self.store.current_validity(new_pass.evidence_id), EvidenceValidity.VALID)
        types = [e.event_type for e in self.store.events_for_correlation(self.ctx.correlation_id)]
        self.assertEqual(types[-1], AuditEventType.EVIDENCE_SUPERSEDED)
        self.assertIn(AuditEventType.STATE_PROMOTED, types)


if __name__ == "__main__":
    unittest.main()
