import sqlite3
import tempfile
import unittest
from pathlib import Path

from evidence.ids import CorrelationContext
from evidence.models import AuditEventType, EvidenceType, EvidenceValidity
from evidence.store import (
    ConflictingDuplicateEventError,
    EvidenceConflictError,
    EvidenceNotFoundError,
    EvidenceStore,
    IntegrityStatus,
    InvalidValidityTransition,
)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "e.db"
        self.store = EvidenceStore(self.db)
        self.store.initialize_schema()
        self.ctx = CorrelationContext.new()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def put(self, payload=None, **kw):
        base = dict(
            evidence_type=EvidenceType.VERIFICATION,
            payload=payload if payload is not None else {"result": "PASS"},
            ctx=self.ctx, source_component="verification", source_type="checkov",
            algorithm_or_verifier_version="checkov==3.2.526",
            state_id="state-1", candidate_id=None,
        )
        base.update(kw)
        return self.store.put_evidence(**base)

    def raw(self, sql: str, params: tuple = ()) -> None:
        conn = sqlite3.connect(self.db)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()


class TestPersistAndResolve(_Base):
    """Exit criterion: evidence persists and resolves."""

    def test_round_trip(self) -> None:
        res = self.put({"result": "PASS", "predicate": "ckv_aws_24"})
        rec = self.store.get_evidence(res.record.evidence_id)
        self.assertEqual(rec, res.record)
        self.assertEqual(self.store.resolve_payload(rec), {"predicate": "ckv_aws_24", "result": "PASS"})
        self.assertTrue(rec.payload_ref.startswith("cas:"))

    def test_unknown_evidence_raises(self) -> None:
        with self.assertRaises(EvidenceNotFoundError):
            self.store.get_evidence("evd-nope")

    def test_secret_is_never_written_to_disk(self) -> None:
        self.put({"result": "PASS", "config": {"password": "hunter2-SUPERSECRET"}})
        self.assertNotIn(b"hunter2-SUPERSECRET", self.db.read_bytes())

    def test_redaction_is_recorded_on_the_record(self) -> None:
        res = self.put({"config": {"password": "x"}})
        self.assertEqual(res.redaction_count, 1)
        self.assertEqual(res.record.redaction_policy_version, "redaction-policy-1")
        clean = self.put({"result": "PASS"})
        self.assertIsNone(clean.record.redaction_policy_version)

    def test_hash_covers_redacted_content(self) -> None:
        a = self.put({"config": {"password": "one"}})
        b = self.put({"config": {"password": "two"}})
        self.assertEqual(a.record.content_hash, b.record.content_hash)  # both redact to same


class TestDuplicateHandling(_Base):
    """Exit criterion: duplicate events are handled."""

    def test_same_evidence_id_same_content_is_a_duplicate_not_a_second_row(self) -> None:
        first = self.put(evidence_id="evd-fixed")
        second = self.put(evidence_id="evd-fixed")
        self.assertFalse(first.duplicate)
        self.assertTrue(second.duplicate)
        self.assertEqual(len(self.store.evidence_for_state("state-1")), 1)

    def test_same_evidence_id_different_content_conflicts(self) -> None:
        self.put({"result": "PASS"}, evidence_id="evd-fixed")
        with self.assertRaises(EvidenceConflictError):
            self.put({"result": "FAIL"}, evidence_id="evd-fixed")

    def test_duplicate_audit_event_creates_no_second_row(self) -> None:
        kw = dict(event_type=AuditEventType.IMPACT_COMPLETED, ctx=self.ctx,
                  payload={"affected": ["INV-SEC-001"]}, event_id="evt-once")
        a = self.store.append_audit_event(**kw)
        b = self.store.append_audit_event(**kw)
        self.assertFalse(a.duplicate)
        self.assertTrue(b.duplicate)
        self.assertEqual(a.event.sequence, b.event.sequence)
        self.assertEqual(self.store.count_events(), 1)

    def test_conflicting_reuse_of_event_id_raises(self) -> None:
        self.store.append_audit_event(event_type=AuditEventType.IMPACT_COMPLETED, ctx=self.ctx,
                                      payload={"a": 1}, event_id="evt-x")
        with self.assertRaises(ConflictingDuplicateEventError):
            self.store.append_audit_event(event_type=AuditEventType.IMPACT_COMPLETED, ctx=self.ctx,
                                          payload={"a": 2}, event_id="evt-x")

    def test_audit_sequence_is_monotonic(self) -> None:
        seqs = [
            self.store.append_audit_event(event_type=AuditEventType.STATE_CREATED, ctx=self.ctx,
                                          payload={"i": i}).event.sequence
            for i in range(5)
        ]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), 5)


class TestHashesVerify(_Base):
    """Exit criterion: hashes verify (and tampering is detected)."""

    def test_intact_evidence_verifies(self) -> None:
        rec = self.put().record
        self.assertEqual(self.store.verify_integrity(rec), IntegrityStatus.VALID)

    def test_tampered_payload_is_detected(self) -> None:
        rec = self.put({"result": "FAIL"}).record
        # Simulate out-of-band tampering by defeating the trigger first.
        self.raw("DROP TRIGGER evidence_payload_no_update")
        self.raw("UPDATE evidence_payload SET payload_json = ? WHERE content_hash = ?",
                 ('{"result":"PASS"}', rec.content_hash))
        self.assertEqual(self.store.verify_integrity(rec), IntegrityStatus.TAMPERED)

    def test_missing_payload_is_detected(self) -> None:
        rec = self.put().record
        self.raw("DROP TRIGGER evidence_payload_no_delete")
        self.raw("DELETE FROM evidence_payload WHERE content_hash = ?", (rec.content_hash,))
        self.assertEqual(self.store.verify_integrity(rec), IntegrityStatus.MISSING_PAYLOAD)


class TestAppendOnly(_Base):
    def test_evidence_record_cannot_be_updated_or_deleted(self) -> None:
        rec = self.put().record
        with self.assertRaises(sqlite3.DatabaseError):
            self.raw("UPDATE evidence_record SET validity='VALID', content_hash='x' WHERE evidence_id=?",
                     (rec.evidence_id,))
        with self.assertRaises(sqlite3.DatabaseError):
            self.raw("DELETE FROM evidence_record WHERE evidence_id=?", (rec.evidence_id,))

    def test_audit_event_cannot_be_updated_or_deleted(self) -> None:
        self.store.append_audit_event(event_type=AuditEventType.STATE_CREATED, ctx=self.ctx, payload={})
        with self.assertRaises(sqlite3.DatabaseError):
            self.raw("UPDATE audit_event SET event_type='X'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.raw("DELETE FROM audit_event")

    def test_validity_transitions_cannot_be_rewritten(self) -> None:
        rec = self.put().record
        self.store.invalidate(rec.evidence_id, reason="impact", ctx=self.ctx)
        with self.assertRaises(sqlite3.DatabaseError):
            self.raw("DELETE FROM validity_transition")


class TestInvalidationPreservesHistory(_Base):
    """Exit criterion: invalidation preserves history."""

    def test_invalidation_keeps_original_record_and_payload(self) -> None:
        rec = self.put({"result": "PASS"}, candidate_id="cand-1").record
        tr = self.store.invalidate(
            rec.evidence_id, reason="INV-FUNC-001 affected by candidate",
            ctx=self.ctx, candidate_id="cand-1", impact_report_ref="impact-7")
        self.assertEqual(self.store.current_validity(rec.evidence_id), EvidenceValidity.INVALID)
        # original record untouched, payload still resolvable and intact
        again = self.store.get_evidence(rec.evidence_id)
        self.assertEqual(again, rec)
        self.assertEqual(again.validity, EvidenceValidity.VALID)  # the *initial* validity
        self.assertEqual(self.store.resolve_payload(again), {"result": "PASS"})
        self.assertEqual(self.store.verify_integrity(again), IntegrityStatus.VALID)
        # transition recorded with reason and impact reference
        hist = self.store.validity_history(rec.evidence_id)
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0].transition_id, tr.transition_id)
        self.assertEqual(hist[0].impact_report_ref, "impact-7")
        self.assertEqual(hist[0].from_validity, EvidenceValidity.VALID)

    def test_invalidation_appends_an_audit_event(self) -> None:
        rec = self.put().record
        self.store.invalidate(rec.evidence_id, reason="impact", ctx=self.ctx)
        types = [e.event_type for e in self.store.events_for_correlation(self.ctx.correlation_id)]
        self.assertIn(AuditEventType.EVIDENCE_INVALIDATED, types)

    def test_invalid_evidence_can_never_become_valid_again(self) -> None:
        rec = self.put().record
        self.store.invalidate(rec.evidence_id, reason="impact", ctx=self.ctx)
        with self.assertRaises(InvalidValidityTransition):
            self.store.change_validity(rec.evidence_id, EvidenceValidity.VALID,
                                       reason="pretend it is fine", ctx=self.ctx)

    def test_a_reason_is_mandatory(self) -> None:
        rec = self.put().record
        with self.assertRaises(ValueError):
            self.store.invalidate(rec.evidence_id, reason="  ", ctx=self.ctx)

    def test_invalidating_unknown_evidence_raises(self) -> None:
        with self.assertRaises(EvidenceNotFoundError):
            self.store.invalidate("evd-nope", reason="x", ctx=self.ctx)

    def test_uncertain_can_be_resolved(self) -> None:
        rec = self.put().record
        self.store.change_validity(rec.evidence_id, EvidenceValidity.UNCERTAIN, reason="?", ctx=self.ctx)
        self.store.change_validity(rec.evidence_id, EvidenceValidity.VALID, reason="confirmed", ctx=self.ctx)
        self.assertEqual(self.store.current_validity(rec.evidence_id), EvidenceValidity.VALID)
        self.assertEqual(len(self.store.validity_history(rec.evidence_id)), 2)


class TestSupersession(_Base):
    def test_supersede_keeps_old_evidence_auditable(self) -> None:
        old = self.put({"v": 1}).record
        new = self.put({"v": 2}).record
        self.store.supersede(old.evidence_id, new.evidence_id, reason="re-verified", ctx=self.ctx)
        self.assertEqual(self.store.current_validity(old.evidence_id), EvidenceValidity.SUPERSEDED)
        self.assertEqual(self.store.superseded_by(old.evidence_id), new.evidence_id)
        self.assertEqual(self.store.resolve_payload(self.store.get_evidence(old.evidence_id)), {"v": 1})

    def test_cannot_supersede_with_invalid_evidence(self) -> None:
        old, new = self.put({"v": 1}).record, self.put({"v": 2}).record
        self.store.invalidate(new.evidence_id, reason="impact", ctx=self.ctx)
        with self.assertRaises(InvalidValidityTransition):
            self.store.supersede(old.evidence_id, new.evidence_id, reason="x", ctx=self.ctx)

    def test_cannot_supersede_itself(self) -> None:
        rec = self.put().record
        with self.assertRaises(ValueError):
            self.store.supersede(rec.evidence_id, rec.evidence_id, reason="x", ctx=self.ctx)

    def test_cannot_be_superseded_twice(self) -> None:
        a, b, c = (self.put({"v": i}).record for i in range(3))
        self.store.supersede(a.evidence_id, b.evidence_id, reason="x", ctx=self.ctx)
        with self.assertRaises(InvalidValidityTransition):  # SUPERSEDED is terminal
            self.store.supersede(a.evidence_id, c.evidence_id, reason="y", ctx=self.ctx)


class TestProofGate(_Base):
    """Doc 11 Sections 8/45/50: evidence that isn't VALID, bound, and intact is not proof."""

    def test_valid_bound_intact_evidence_is_usable(self) -> None:
        rec = self.put(candidate_id="cand-1", state_id=None).record
        self.assertTrue(self.store.usable_as_proof(rec.evidence_id, candidate_id="cand-1").usable)

    def test_invalidated_evidence_is_not_proof(self) -> None:
        rec = self.put(candidate_id="cand-1", state_id=None).record
        self.store.invalidate(rec.evidence_id, reason="impact", ctx=self.ctx)
        check = self.store.usable_as_proof(rec.evidence_id, candidate_id="cand-1")
        self.assertFalse(check.usable)
        self.assertTrue(any("INVALID" in r for r in check.reasons))

    def test_evidence_for_a_different_candidate_is_not_proof(self) -> None:
        rec = self.put(candidate_id="cand-1", state_id=None).record
        self.assertFalse(self.store.usable_as_proof(rec.evidence_id, candidate_id="cand-2").usable)

    def test_evidence_for_a_different_state_is_not_proof(self) -> None:
        rec = self.put(state_id="state-1").record
        self.assertFalse(self.store.usable_as_proof(rec.evidence_id, state_id="state-2").usable)

    def test_unbound_evidence_is_never_proof(self) -> None:
        rec = self.put(state_id=None, candidate_id=None).record
        self.assertFalse(rec.is_bound)
        self.assertFalse(self.store.usable_as_proof(rec.evidence_id, state_id="state-1").usable)

    def test_no_expected_binding_fails_closed(self) -> None:
        rec = self.put().record
        self.assertFalse(self.store.usable_as_proof(rec.evidence_id).usable)

    def test_tampered_evidence_is_not_proof(self) -> None:
        rec = self.put({"result": "FAIL"}, state_id="state-1").record
        self.raw("DROP TRIGGER evidence_payload_no_update")
        self.raw("UPDATE evidence_payload SET payload_json=? WHERE content_hash=?",
                 ('{"result":"PASS"}', rec.content_hash))
        check = self.store.usable_as_proof(rec.evidence_id, state_id="state-1")
        self.assertFalse(check.usable)
        self.assertTrue(any("TAMPERED" in r for r in check.reasons))

    def test_unknown_evidence_is_not_proof(self) -> None:
        self.assertFalse(self.store.usable_as_proof("evd-nope", state_id="s").usable)


class TestLineageQueries(_Base):
    """Exit criterion: lineage queries work."""

    def test_queries_by_state_candidate_and_correlation(self) -> None:
        a = self.put({"n": 1}, state_id="state-1").record
        b = self.put({"n": 2}, state_id=None, candidate_id="cand-1").record
        other_ctx = CorrelationContext.new()
        self.store.put_evidence(
            evidence_type=EvidenceType.IMPACT, payload={"n": 3}, ctx=other_ctx,
            source_component="impact", source_type="engine",
            algorithm_or_verifier_version="1", state_id="state-1")
        self.assertEqual(len(self.store.evidence_for_state("state-1")), 2)
        self.assertEqual([r.evidence_id for r in self.store.evidence_for_candidate("cand-1")], [b.evidence_id])
        self.assertEqual({r.evidence_id for r in self.store.evidence_for_correlation(self.ctx.correlation_id)},
                         {a.evidence_id, b.evidence_id})

    def test_events_come_back_in_append_order(self) -> None:
        for t in (AuditEventType.CANDIDATE_CREATED, AuditEventType.IMPACT_COMPLETED,
                  AuditEventType.VERIFICATION_COMPLETED, AuditEventType.CANDIDATE_REJECTED):
            self.store.append_audit_event(event_type=t, ctx=self.ctx, payload={}, candidate_id="cand-1")
        got = [e.event_type for e in self.store.events_for_correlation(self.ctx.correlation_id)]
        self.assertEqual(got, [AuditEventType.CANDIDATE_CREATED, AuditEventType.IMPACT_COMPLETED,
                               AuditEventType.VERIFICATION_COMPLETED, AuditEventType.CANDIDATE_REJECTED])
        self.assertEqual(len(self.store.events_for_candidate("cand-1")), 4)

    def test_correlation_is_isolated_between_workflows(self) -> None:
        self.store.append_audit_event(event_type=AuditEventType.STATE_CREATED, ctx=self.ctx, payload={})
        other = CorrelationContext.new()
        self.store.append_audit_event(event_type=AuditEventType.STATE_CREATED, ctx=other, payload={})
        self.assertEqual(len(self.store.events_for_correlation(self.ctx.correlation_id)), 1)


if __name__ == "__main__":
    unittest.main()
