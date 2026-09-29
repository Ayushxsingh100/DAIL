"""P2 exit gate, end to end.

Replays the paper's canonical scenario (public SSH + working EC2->RDS path)
through the real P1 domain objects and the real P2 evidence store on ONE
shared database, then checks the two evidence chains Doc 11 Section 51.3
requires: a safe-promotion chain and a rejected-candidate chain.
"""
import tempfile
import unittest
from pathlib import Path

from core.domain.state import CandidateState, TrustedState
from core.domain.storage import LocalStorage
from evidence.ids import CorrelationContext
from evidence.models import AuditEventType, EvidenceType, EvidenceValidity
from evidence.store import EvidenceStore


class TestP2Gate(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "dail.db"
        self.domain = LocalStorage(self.db)
        self.domain.initialize_schema()
        self.store = EvidenceStore(self.db)  # same file as the domain tables
        self.store.initialize_schema()
        self.ctx = CorrelationContext.new()
        self.s0 = TrustedState.genesis(content_payload={"web-node": "ssh-open"}, invariant_registry_version=1)
        self.domain.save_trusted_state(self.s0)
        # Baseline evidence: INV-FUNC-001 verified PASS on the trusted state.
        self.baseline_func = self._evidence(
            EvidenceType.VERIFICATION, {"invariant": "INV-FUNC-001", "result": "PASS"},
            state_id=self.s0.state_id)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _evidence(self, etype, payload, **binding):
        return self.store.put_evidence(
            evidence_type=etype, payload=payload, ctx=self.ctx, source_component="test",
            source_type="fixture", algorithm_or_verifier_version="test-1", **binding).record

    def _event(self, etype, **kw):
        return self.store.append_audit_event(event_type=etype, ctx=self.ctx, payload={}, **kw).event

    def test_domain_and_evidence_tables_coexist_in_one_database(self) -> None:
        self.assertEqual(self.domain.count_trusted_states(), 1)
        self.assertEqual(len(self.store.evidence_for_state(self.s0.state_id)), 1)

    def test_rejected_candidate_chain(self) -> None:
        """Candidate 1: fixes SSH but breaks EC2->RDS. Baseline evidence must
        be invalidated by impact analysis; the failing verification must be
        recorded; the candidate is rejected; trusted state does not advance."""
        c1 = CandidateState.build(parent=self.s0, patch_payload={"remove": "ssh", "also": "narrow ec2_to_rds"})
        self.domain.save_candidate(c1)
        self._event(AuditEventType.CANDIDATE_CREATED, candidate_id=c1.candidate_id, state_id=self.s0.state_id)
        impact = self._evidence(EvidenceType.IMPACT,
                                {"affected": ["INV-SEC-001", "INV-FUNC-001"]}, candidate_id=c1.candidate_id)
        self._event(AuditEventType.IMPACT_COMPLETED, candidate_id=c1.candidate_id)

        # Impact invalidates the baseline evidence for INV-FUNC-001 ...
        self.store.invalidate(self.baseline_func.evidence_id, reason="INV-FUNC-001 affected by candidate",
                              ctx=self.ctx, candidate_id=c1.candidate_id, impact_report_ref=impact.evidence_id)
        # ... so the old PASS is no longer proof, even though it is still on record.
        self.assertFalse(self.store.usable_as_proof(self.baseline_func.evidence_id,
                                                    state_id=self.s0.state_id).usable)
        self.assertEqual(self.store.resolve_payload(self.baseline_func)["result"], "PASS")  # history kept

        # Fresh verification against the candidate FAILS.
        v = self._evidence(EvidenceType.VERIFICATION, {"invariant": "INV-FUNC-001", "result": "FAIL"},
                           candidate_id=c1.candidate_id)
        self._event(AuditEventType.VERIFICATION_COMPLETED, candidate_id=c1.candidate_id)
        c1.mark_under_verification()
        c1.mark_rejected()
        self.domain.update_candidate_status(c1)
        self._event(AuditEventType.CANDIDATE_REJECTED, candidate_id=c1.candidate_id)

        self.assertTrue(self.store.usable_as_proof(v.evidence_id, candidate_id=c1.candidate_id).usable)
        # The whole chain, in order, reconstructable from one correlation id:
        chain = [e.event_type for e in self.store.events_for_correlation(self.ctx.correlation_id)]
        self.assertEqual(chain, [
            AuditEventType.CANDIDATE_CREATED, AuditEventType.IMPACT_COMPLETED,
            AuditEventType.EVIDENCE_INVALIDATED, AuditEventType.VERIFICATION_COMPLETED,
            AuditEventType.CANDIDATE_REJECTED])
        # Trusted state did not advance; the rejected candidate and all evidence remain.
        self.assertEqual(self.domain.count_trusted_states(), 1)
        self.assertIsNotNone(self.domain.load_candidate(c1.candidate_id))
        self.assertEqual(len(self.store.evidence_for_candidate(c1.candidate_id)), 2)

    def test_safe_promotion_chain(self) -> None:
        """Candidate 2: fixes SSH, preserves the DB path. Evidence supersedes
        the old, and the lineage back to genesis stays intact."""
        c2 = CandidateState.build(parent=self.s0, patch_payload={"remove": "ssh"})
        self.domain.save_candidate(c2)
        self._event(AuditEventType.CANDIDATE_CREATED, candidate_id=c2.candidate_id, state_id=self.s0.state_id)
        new_pass = self._evidence(EvidenceType.VERIFICATION, {"invariant": "INV-FUNC-001", "result": "PASS"},
                                  candidate_id=c2.candidate_id)
        self._event(AuditEventType.VERIFICATION_COMPLETED, candidate_id=c2.candidate_id)
        c2.mark_under_verification()
        c2.mark_promoted()
        self.domain.update_candidate_status(c2)
        s1 = TrustedState.promoted_from(candidate=c2, parent=self.s0, content_payload={"web-node": "ssh-closed"},
                                        invariant_registry_version=1)
        self.domain.save_trusted_state(s1)
        self._event(AuditEventType.STATE_PROMOTED, candidate_id=c2.candidate_id, state_id=s1.state_id)
        # Baseline evidence is superseded by the re-verification, never deleted.
        self.store.supersede(self.baseline_func.evidence_id, new_pass.evidence_id,
                             reason="re-verified on promoted candidate", ctx=self.ctx)

        self.assertEqual([s.version for s in self.domain.trusted_state_lineage(s1.state_id)], [2, 1])
        self.assertEqual(self.store.current_validity(self.baseline_func.evidence_id), EvidenceValidity.SUPERSEDED)
        self.assertEqual(self.store.current_validity(new_pass.evidence_id), EvidenceValidity.VALID)
        types = [e.event_type for e in self.store.events_for_correlation(self.ctx.correlation_id)]
        self.assertEqual(types[-1], AuditEventType.EVIDENCE_SUPERSEDED)
        self.assertIn(AuditEventType.STATE_PROMOTED, types)


if __name__ == "__main__":
    unittest.main()
