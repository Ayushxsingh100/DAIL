"""EvidenceService on the schema-5 repositories (Doc 11; Doc 05 §16, §26; C-50 to C-58).

This file carries over the 37 tests of the interim evidence store (``test_evidence_store.py``,
retired by P2-fix step 4) onto the service: each keeps its assertion meaning, adapted to per-context
validity (C-52), UUID ids (C-55), ``evidence://`` references (C-56) and the 19 audit event types
(C-57). The retirement table in the P2-fix report lists every old test and where it went.
"""

from __future__ import annotations

import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime
from typing import Any

from core.domain.audit import (
    ActorType,
    AuditEventType,
    ConflictingDuplicateEventError,
)
from core.domain.errors import DomainValidationError, IllegalTransitionError, PersistenceError
from core.domain.evidence import (
    ArtifactRef,
    EvidenceConflictError,
    EvidenceContext,
    EvidenceKind,
    EvidenceNotFoundError,
    EvidenceValidity,
    IntegrityStatus,
    TransitionScope,
)
from evidence.ids import CorrelationContext
from evidence.service import EvidenceService
from tests.domain_builders import at, baseline, uid
from tests.evidence_builders import prov
from tests.persistence_builders import seed_evidence
from tests.service_builders import ServiceCase

K = EvidenceKind
V = EvidenceValidity


class TestPersistAndResolve(ServiceCase):
    """Exit criterion: evidence persists and resolves."""

    def test_round_trip(self) -> None:
        rec = self.put({"result": "PASS", "predicate": "ckv_aws_24"})
        with self.uow() as u:
            self.assertEqual(u.evidence.get(rec.evidence_id), rec)
            self.assertEqual(
                self.svc.resolve_payload(u, rec.evidence_id),
                {"predicate": "ckv_aws_24", "result": "PASS"},
            )
        # C-56: the reference is evidence://<type>/<hash> (the interim store wrote cas:<hash>)
        self.assertTrue(rec.payload_ref.startswith("evidence://verification/"))

    def test_unknown_evidence_raises(self) -> None:
        with self.uow() as u, self.assertRaises(EvidenceNotFoundError):
            self.svc.resolve_payload(u, uid(0xDEAD))

    def test_secret_is_never_written_to_disk(self) -> None:
        self.put({"result": "PASS", "config": {"password": "hunter2-SUPERSECRET"}})
        self.assertNotIn(b"hunter2-SUPERSECRET", self.path.read_bytes())

    def test_redaction_is_recorded_on_the_record(self) -> None:
        with self.uow() as u:
            res = self.svc.record(
                u,
                kind=K.VERIFICATION,
                event_name="v",
                payload={"config": {"password": "x"}},
                ctx=self.ctx,
                provenance=prov(),
                state_id=self.v0.state_id,
                state_hash=self.v0.state_hash,
            )
        self.assertEqual(res.redaction_count, 1)
        self.assertEqual(res.record.redaction_policy_version, "redaction-policy-1")
        clean = self.put({"result": "PASS"})
        self.assertIsNone(clean.redaction_policy_version)

    def test_hash_covers_redacted_content(self) -> None:
        a = self.put({"config": {"password": "one"}})
        b = self.put({"config": {"password": "two"}})
        self.assertEqual(a.content_hash, b.content_hash)  # both redact to the same payload


class TestDuplicateHandling(ServiceCase):
    """Exit criterion: duplicate events are handled."""

    def test_same_evidence_id_same_content_is_a_duplicate_not_a_second_row(self) -> None:
        fixed = uid(0xE01)
        first = self.put(evidence_id=fixed)
        with self.uow() as u:
            second = self.svc.record(
                u,
                kind=K.VERIFICATION,
                event_name="verification_completed",
                payload={"result": "PASS"},
                ctx=self.ctx,
                provenance=prov(),
                state_id=self.v0.state_id,
                state_hash=self.v0.state_hash,
                evidence_id=fixed,
                now=at(500),
            )
            self.assertTrue(second.duplicate)
            self.assertEqual(second.record, first)  # the stored record, not the redelivery
            self.assertEqual(len(self.svc.evidence_for_state(u, self.v0.state_id)), 1)

    def test_same_evidence_id_different_content_conflicts(self) -> None:
        fixed = uid(0xE02)
        self.put({"result": "PASS"}, evidence_id=fixed)
        with self.assertRaises(EvidenceConflictError):
            self.put({"result": "FAIL"}, evidence_id=fixed)

    def test_duplicate_audit_event_creates_no_second_row(self) -> None:
        kw: dict[str, Any] = {
            "event_type": AuditEventType.IMPACT_COMPLETED,
            "ctx": self.ctx,
            "payload": {"affected": ["INV-SEC-001"]},
            "event_id": uid(0xA01),
        }
        with self.uow() as u:
            a = self.svc.append_audit_event(u, **kw)
            b = self.svc.append_audit_event(u, **kw)
            self.assertFalse(a.duplicate)
            self.assertTrue(b.duplicate)
            self.assertEqual(a.event.sequence, b.event.sequence)
            self.assertEqual(len(self.svc.events_for_correlation(u, self.ctx.correlation_id)), 1)

    def test_conflicting_reuse_of_event_id_raises(self) -> None:
        with self.uow() as u:
            self.svc.append_audit_event(
                u,
                event_type=AuditEventType.IMPACT_COMPLETED,
                ctx=self.ctx,
                payload={"a": 1},
                event_id=uid(0xA02),
            )
        with self.uow() as u, self.assertRaises(ConflictingDuplicateEventError):
            self.svc.append_audit_event(
                u,
                event_type=AuditEventType.IMPACT_COMPLETED,
                ctx=self.ctx,
                payload={"a": 2},
                event_id=uid(0xA02),
            )

    def test_audit_sequence_is_monotonic(self) -> None:
        with self.uow() as u:
            seqs = [
                self.svc.append_audit_event(
                    u, event_type=AuditEventType.LLM_REQUESTED, ctx=self.ctx, payload={"i": i}
                ).event.sequence
                for i in range(5)
            ]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), 5)

    def test_d4_a_redelivered_event_for_another_candidate_is_a_conflict(self) -> None:
        """The interim store compared only the payload hash and the event type."""
        kw: dict[str, Any] = {
            "event_type": AuditEventType.CANDIDATE_REJECTED,
            "ctx": self.ctx,
            "payload": {"reason": "ssh"},
            "event_id": uid(0xA03),
        }
        with self.uow() as u:
            self.svc.append_audit_event(u, candidate_id=self.c1.candidate_id, **kw)
        with self.uow() as u, self.assertRaises(ConflictingDuplicateEventError):
            self.svc.append_audit_event(u, candidate_id=self.c2.candidate_id, **kw)


class TestHashesVerify(ServiceCase):
    """Exit criterion: hashes verify (and tampering is detected)."""

    def test_intact_evidence_verifies(self) -> None:
        rec = self.put()
        with self.uow() as u:
            self.assertIs(self.svc.verify_integrity(u, rec.evidence_id), IntegrityStatus.VALID)

    def test_tampered_payload_is_detected(self) -> None:
        rec = self.put({"result": "FAIL"})
        # simulate out-of-band tampering: triggers dropped, the stored text edited
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json = ? WHERE content_hash = ?",
            ('{"result":"PASS"}', rec.content_hash),
        )
        with self.uow() as u:
            self.assertIs(self.svc.verify_integrity(u, rec.evidence_id), IntegrityStatus.TAMPERED)

    def test_missing_payload_is_detected(self) -> None:
        rec = self.put()
        self.tamper("DELETE FROM evidence_artifacts WHERE content_hash = ?", (rec.content_hash,))
        with self.uow() as u:
            self.assertIs(
                self.svc.verify_integrity(u, rec.evidence_id), IntegrityStatus.MISSING_PAYLOAD
            )

    def test_a_stored_payload_that_is_no_longer_json_is_tampered(self) -> None:
        rec = self.put()
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("PRAGMA ignore_check_constraints = ON")  # an attacker with file access
            conn.execute("DROP TRIGGER evidence_artifacts_no_update")
            conn.execute(
                "UPDATE evidence_artifacts SET payload_json = ? WHERE content_hash = ?",
                ('{"result":"PASS"', rec.content_hash),  # truncated
            )
            conn.commit()
        with self.uow() as u:
            self.assertIs(self.svc.verify_integrity(u, rec.evidence_id), IntegrityStatus.TAMPERED)


class TestAppendOnly(ServiceCase):
    def plain(self, sql: str) -> None:
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute(sql)
            conn.commit()

    def test_evidence_record_cannot_be_updated_or_deleted(self) -> None:
        self.put()
        with self.assertRaises(sqlite3.DatabaseError):
            self.plain("UPDATE evidence_events SET validity = 'UNCERTAIN'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.plain("DELETE FROM evidence_events")
        self.assertEqual(self.count("evidence_events"), 1)

    def test_audit_event_cannot_be_updated_or_deleted(self) -> None:
        with self.uow() as u:
            self.svc.append_audit_event(
                u, event_type=AuditEventType.LLM_REQUESTED, ctx=self.ctx, payload={}
            )
        with self.assertRaises(sqlite3.DatabaseError):
            self.plain("UPDATE audit_events SET event_type = 'ESCALATED'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.plain("DELETE FROM audit_events")

    def test_validity_transitions_cannot_be_rewritten(self) -> None:
        rec = self.put()
        with self.uow() as u:
            self.svc.change_validity(
                u,
                rec.evidence_id,
                context=self.v0_ctx,
                to=V.UNCERTAIN,
                reason="impact",
                ctx=self.ctx,
            )
        with self.assertRaises(sqlite3.DatabaseError):
            self.plain("DELETE FROM evidence_validity_transitions")
        with self.assertRaises(sqlite3.DatabaseError):
            self.plain("UPDATE evidence_validity_transitions SET reason = 'edited'")


class TestInvalidationPreservesHistory(ServiceCase):
    """Exit criterion: invalidation preserves history."""

    def test_invalidation_keeps_original_record_and_payload(self) -> None:
        rec = self.put({"result": "PASS"})
        impact = self.impact_for(self.c1)
        with self.uow() as u:
            tr = self.svc.invalidate(
                u,
                rec.evidence_id,
                context=self.c1_ctx,
                reason="INV-FUNC-001 affected by candidate",
                ctx=self.ctx,
                impact_ref=impact.evidence_id,
            ).transition
        with self.uow() as u:
            self.assertIs(self.svc.validity_in(u, rec.evidence_id, self.c1_ctx), V.INVALID)
            # original record untouched, payload still resolvable and intact
            again = u.evidence.get(rec.evidence_id)
            self.assertEqual(again, rec)
            assert again is not None
            self.assertIs(again.validity, V.VALID)  # the *initial* validity
            self.assertEqual(self.svc.resolve_payload(u, rec.evidence_id), {"result": "PASS"})
            self.assertIs(self.svc.verify_integrity(u, rec.evidence_id), IntegrityStatus.VALID)
            # transition recorded with reason and impact reference
            hist = self.svc.validity_history(u, rec.evidence_id)
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0].transition_id, tr.transition_id)
        self.assertEqual(hist[0].impact_ref, impact.evidence_id)
        self.assertIs(hist[0].to_validity, V.INVALID)
        self.assertEqual(hist[0].reason, "INV-FUNC-001 affected by candidate")

    def test_invalidation_appends_an_audit_event(self) -> None:
        rec = self.put()
        impact = self.impact_for(self.c1)
        with self.uow() as u:
            self.svc.invalidate(
                u,
                rec.evidence_id,
                context=self.c1_ctx,
                reason="impact",
                ctx=self.ctx,
                impact_ref=impact.evidence_id,
            )
            types = [
                e.event_type for e in self.svc.events_for_correlation(u, self.ctx.correlation_id)
            ]
        # C-57: one event type, EVIDENCE_VALIDITY_CHANGED, replaces EVIDENCE_INVALIDATED
        self.assertIn(AuditEventType.EVIDENCE_VALIDITY_CHANGED, types)

    def test_invalid_evidence_can_never_become_valid_again(self) -> None:
        rec = self.put()
        with self.uow() as u:
            self.svc.invalidate(
                u, rec.evidence_id, context=self.v0_ctx, reason="impact", ctx=self.ctx
            )
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            self.svc.change_validity(
                u,
                rec.evidence_id,
                context=self.v0_ctx,
                to=V.VALID,
                reason="pretend it is fine",
                ctx=self.ctx,
            )
        with self.uow() as u:
            self.assertIs(self.svc.validity_in(u, rec.evidence_id, self.v0_ctx), V.INVALID)

    def test_a_reason_is_mandatory(self) -> None:
        rec = self.put()
        with self.uow() as u, self.assertRaises(ValueError):
            self.svc.invalidate(u, rec.evidence_id, context=self.v0_ctx, reason="  ", ctx=self.ctx)

    def test_invalidating_unknown_evidence_raises(self) -> None:
        with self.uow() as u, self.assertRaises(EvidenceNotFoundError):
            self.svc.invalidate(u, uid(0xDEAD), context=self.v0_ctx, reason="x", ctx=self.ctx)

    def test_uncertain_can_be_resolved(self) -> None:
        rec = self.put()
        with self.uow() as u:
            self.svc.change_validity(
                u, rec.evidence_id, context=self.v0_ctx, to=V.UNCERTAIN, reason="?", ctx=self.ctx
            )
            self.svc.change_validity(
                u,
                rec.evidence_id,
                context=self.v0_ctx,
                to=V.VALID,
                reason="confirmed",
                ctx=self.ctx,
            )
        with self.uow() as u:
            self.assertIs(self.svc.validity_in(u, rec.evidence_id, self.v0_ctx), V.VALID)
            self.assertEqual(len(self.svc.validity_history(u, rec.evidence_id)), 2)

    def test_a_reason_with_a_secret_is_redacted_before_it_is_stored(self) -> None:
        rec = self.put()
        with self.uow() as u:
            tr = self.svc.change_validity(
                u,
                rec.evidence_id,
                context=self.v0_ctx,
                to=V.UNCERTAIN,
                reason="rechecking with password=hunter2-SUPERSECRET",
                ctx=self.ctx,
            ).transition
        self.assertNotIn("hunter2", tr.reason)
        self.assertNotIn(b"hunter2-SUPERSECRET", self.path.read_bytes())


class TestSupersession(ServiceCase):
    def test_supersede_keeps_old_evidence_auditable(self) -> None:
        old, new = self.put({"v": 1}), self.put({"v": 2})
        with self.uow() as u:
            self.svc.supersede(
                u, old.evidence_id, new.evidence_id, reason="re-verified", ctx=self.ctx
            )
        with self.uow() as u:
            self.assertIs(self.svc.validity_in(u, old.evidence_id, self.v0_ctx), V.SUPERSEDED)
            self.assertEqual(u.evidence.superseded_by(old.evidence_id), new.evidence_id)
            self.assertEqual(self.svc.resolve_payload(u, old.evidence_id), {"v": 1})
            self.assertIs(self.svc.validity_in(u, new.evidence_id, self.v0_ctx), V.VALID)

    def test_cannot_supersede_with_invalid_evidence(self) -> None:
        old, new = self.put({"v": 1}), self.put({"v": 2})
        with self.uow() as u:
            self.svc.invalidate(
                u, new.evidence_id, context=self.v0_ctx, reason="impact", ctx=self.ctx
            )
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            self.svc.supersede(u, old.evidence_id, new.evidence_id, reason="x", ctx=self.ctx)

    def test_cannot_supersede_itself(self) -> None:
        rec = self.put()
        with self.uow() as u, self.assertRaises(ValueError):
            self.svc.supersede(u, rec.evidence_id, rec.evidence_id, reason="x", ctx=self.ctx)

    def test_cannot_be_superseded_twice(self) -> None:
        a, b, c = (self.put({"v": i}) for i in range(3))
        with self.uow() as u:
            self.svc.supersede(u, a.evidence_id, b.evidence_id, reason="x", ctx=self.ctx)
        with self.uow() as u, self.assertRaises(IllegalTransitionError):  # SUPERSEDED is terminal
            self.svc.supersede(u, a.evidence_id, c.evidence_id, reason="y", ctx=self.ctx)

    def test_d2_evidence_about_a_state_is_not_superseded_by_candidate_evidence(self) -> None:
        about_v0 = self.put({"v": 1})
        about_c1 = self.put_for(self.c1, {"v": 2})
        with self.uow() as u, self.assertRaises(IllegalTransitionError) as caught:
            self.svc.supersede(
                u, about_v0.evidence_id, about_c1.evidence_id, reason="re-verified", ctx=self.ctx
            )
        self.assertIn("C-53", str(caught.exception))

    def test_d2_llm_evidence_about_vn_is_not_superseded_by_another_candidates_verification(
        self,
    ) -> None:
        llm = self.put({"model": "m"}, kind=K.LLM, event_name="llm_completed")
        other = self.put_for(self.c2, {"result": "PASS"})
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            self.svc.supersede(u, llm.evidence_id, other.evidence_id, reason="x", ctx=self.ctx)

    def test_the_chain_is_returned_oldest_to_newest_from_any_member(self) -> None:
        recs = [self.put({"v": i}) for i in range(3)]
        lone = self.put_for(self.c1, {"v": 9})
        with self.uow() as u:
            self.svc.supersede(
                u, recs[0].evidence_id, recs[1].evidence_id, reason="a", ctx=self.ctx
            )
            self.svc.supersede(
                u, recs[1].evidence_id, recs[2].evidence_id, reason="b", ctx=self.ctx
            )
        with self.uow() as u:
            expected = tuple(r.evidence_id for r in recs)
            for rec in recs:
                self.assertEqual(self.svc.supersession_chain(u, rec.evidence_id), expected)
            self.assertEqual(self.svc.supersession_chain(u, lone.evidence_id), (lone.evidence_id,))

    def test_a_chain_for_unknown_evidence_raises(self) -> None:
        with self.uow() as u, self.assertRaises(EvidenceNotFoundError):
            self.svc.supersession_chain(u, uid(0xDEAD))


class TestProofGate(ServiceCase):
    """Doc 11 Sections 8/45/50: evidence that isn't VALID, bound, and intact is not proof."""

    def check(self, evidence_id: str, expected: Any) -> Any:
        with self.uow() as u:
            return self.svc.usable_as_proof(u, evidence_id, expected)

    def test_valid_bound_intact_evidence_is_usable(self) -> None:
        rec = self.put_for(self.c1)
        self.assertTrue(self.check(rec.evidence_id, self.c1_ctx).usable)
        rec_state = self.put()
        self.assertTrue(self.check(rec_state.evidence_id, self.v0_ctx).usable)

    def test_invalidated_evidence_is_not_proof(self) -> None:
        rec = self.put_for(self.c1)
        impact = self.impact_for(self.c1)
        with self.uow() as u:
            self.svc.invalidate(
                u,
                rec.evidence_id,
                context=self.c1_ctx,
                reason="impact",
                ctx=self.ctx,
                impact_ref=impact.evidence_id,
            )
        result = self.check(rec.evidence_id, self.c1_ctx)
        self.assertFalse(result.usable)
        self.assertTrue(any("INVALID" in r for r in result.reasons))

    def test_evidence_for_a_different_candidate_is_not_proof(self) -> None:
        rec = self.put_for(self.c1)
        self.assertFalse(self.check(rec.evidence_id, self.c2_ctx).usable)

    def test_evidence_for_a_different_state_is_not_proof(self) -> None:
        rec = self.put()
        self.assertFalse(self.check(rec.evidence_id, EvidenceContext.state(uid(0x99))).usable)

    def test_unbound_evidence_is_never_proof(self) -> None:
        rec = self.put(state_id=None, state_hash=None)
        self.assertFalse(rec.is_bound)
        self.assertFalse(self.check(rec.evidence_id, self.v0_ctx).usable)

    def test_no_expected_binding_fails_closed(self) -> None:
        rec = self.put()
        result = self.check(rec.evidence_id, None)
        self.assertFalse(result.usable)
        self.assertGreaterEqual(len(result.reasons), 1)

    def test_tampered_evidence_is_not_proof(self) -> None:
        rec = self.put({"result": "FAIL"})
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json=? WHERE content_hash=?",
            ('{"result":"PASS"}', rec.content_hash),
        )
        result = self.check(rec.evidence_id, self.v0_ctx)
        self.assertFalse(result.usable)
        self.assertTrue(any("TAMPERED" in r for r in result.reasons))

    def test_unknown_evidence_is_not_proof(self) -> None:
        self.assertFalse(self.check(uid(0xDEAD), self.v0_ctx).usable)

    def test_evidence_that_is_not_a_proof_kind_is_never_proof(self) -> None:
        for kind in (K.LLM, K.ERROR, K.EXPERIMENT):
            with self.subTest(kind=kind):
                rec = self.put({"k": kind.value}, kind=kind, event_name="x")
                result = self.check(rec.evidence_id, self.v0_ctx)
                self.assertFalse(result.usable)
                self.assertTrue(any(r.startswith("P2") for r in result.reasons))

    def test_a_state_hash_that_differs_from_the_state_is_not_proof(self) -> None:
        rec = self.put(state_hash="cd" * 32)  # P6: not the stored hash of v0
        result = self.check(rec.evidence_id, self.v0_ctx)
        self.assertFalse(result.usable)
        self.assertTrue(any(r.startswith("P6") for r in result.reasons))

    def test_an_exception_while_checking_makes_the_evidence_unusable(self) -> None:
        rec = self.put()

        class Broken:
            @property
            def evidence(self) -> Any:
                raise RuntimeError("the database is gone")

        result = EvidenceService().usable_as_proof(Broken(), rec.evidence_id, self.v0_ctx)  # type: ignore[arg-type]
        self.assertFalse(result.usable)
        self.assertIn("RuntimeError", result.reasons[0])

    def test_every_failed_condition_is_listed(self) -> None:
        rec = self.put({"k": 1}, kind=K.LLM, event_name="x", state_hash="cd" * 32)
        with self.uow() as u:
            self.svc.change_validity(
                u, rec.evidence_id, context=self.v0_ctx, to=V.UNCERTAIN, reason="?", ctx=self.ctx
            )
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json=? WHERE content_hash=?",
            ('{"k":2}', rec.content_hash),
        )
        prefixes = {r[:2] for r in self.check(rec.evidence_id, self.v0_ctx).reasons}
        self.assertEqual(prefixes, {"P2", "P4", "P5", "P6"})


class TestIntegrityFailure(ServiceCase):
    """Doc 11 §46: mark the failure, emit ERROR_OCCURRED, invalidate, block, preserve."""

    def tamper_payload(self, rec: Any) -> None:
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json=? WHERE content_hash=?",
            ('{"result":"FAIL"}', rec.content_hash),
        )

    def test_an_intact_record_changes_nothing(self) -> None:
        rec = self.put()
        with self.uow() as u:
            self.assertIs(
                self.svc.record_integrity_failure(u, rec.evidence_id, ctx=self.ctx),
                IntegrityStatus.VALID,
            )
        self.assertEqual(self.count("evidence_validity_transitions"), 0)
        self.assertEqual(self.count("audit_events"), 0)

    def test_a_tampered_record_is_invalidated_everywhere_and_an_error_event_is_emitted(
        self,
    ) -> None:
        rec = self.put({"result": "PASS"})
        self.tamper_payload(rec)
        with self.uow() as u:
            status = self.svc.record_integrity_failure(u, rec.evidence_id, ctx=self.ctx)
        self.assertIs(status, IntegrityStatus.TAMPERED)
        with self.uow() as u:
            for context in (self.v0_ctx, self.c1_ctx, self.c2_ctx):
                self.assertIs(self.svc.validity_in(u, rec.evidence_id, context), V.INVALID)
            (transition,) = self.svc.validity_history(u, rec.evidence_id)
            self.assertIs(transition.scope, TransitionScope.RECORD)
            self.assertTrue(transition.reason.startswith("INTEGRITY:"))
            events = self.svc.events_for_correlation(u, self.ctx.correlation_id)
            self.assertEqual(
                [e.event_type for e in events],
                [AuditEventType.EVIDENCE_VALIDITY_CHANGED, AuditEventType.ERROR_OCCURRED],
            )
            error = events[-1]
            payload = u.evidence.resolve(ArtifactRef.parse(error.payload_ref))
            self.assertEqual(error.state_id, self.v0.state_id)
            # the failure record itself is preserved: the record, and the tampered artifact
            self.assertIsNotNone(u.evidence.get(rec.evidence_id))
        self.assertEqual(payload["evidence_id"], rec.evidence_id)
        self.assertEqual(payload["integrity_status"], "TAMPERED")
        self.assertFalse(self.check(rec.evidence_id, self.v0_ctx).usable)

    def check(self, evidence_id: str, context: EvidenceContext) -> Any:
        with self.uow() as u:
            return self.svc.usable_as_proof(u, evidence_id, context)

    def test_a_missing_payload_is_an_integrity_failure_too(self) -> None:
        rec = self.put()
        self.tamper("DELETE FROM evidence_artifacts WHERE content_hash = ?", (rec.content_hash,))
        with self.uow() as u:
            status = self.svc.record_integrity_failure(u, rec.evidence_id, ctx=self.ctx)
        self.assertIs(status, IntegrityStatus.MISSING_PAYLOAD)
        self.assertFalse(self.check(rec.evidence_id, self.v0_ctx).usable)

    def test_it_is_idempotent(self) -> None:
        rec = self.put()
        self.tamper_payload(rec)
        for _ in range(3):
            with self.uow() as u:
                self.svc.record_integrity_failure(u, rec.evidence_id, ctx=self.ctx)
        self.assertEqual(self.count("evidence_validity_transitions"), 1)
        self.assertEqual(self.count("audit_events", "event_type = 'ERROR_OCCURRED'"), 1)

    def test_it_is_idempotent_across_operations(self) -> None:
        rec = self.put()
        self.tamper_payload(rec)
        with self.uow() as u:
            self.svc.record_integrity_failure(u, rec.evidence_id, ctx=self.ctx)
        with self.uow() as u:
            self.svc.record_integrity_failure(u, rec.evidence_id, ctx=self.ctx.new_operation())
        self.assertEqual(self.count("audit_events", "event_type = 'ERROR_OCCURRED'"), 1)

    def test_a_record_that_was_already_invalid_keeps_its_one_record_transition(self) -> None:
        rec = self.put()
        with self.uow() as u:
            self.svc.invalidate(
                u, rec.evidence_id, context=self.v0_ctx, reason="impact", ctx=self.ctx
            )
        self.tamper_payload(rec)
        with self.uow() as u:
            self.svc.record_integrity_failure(u, rec.evidence_id, ctx=self.ctx)
        self.assertEqual(self.count("evidence_validity_transitions", "scope = 'RECORD'"), 1)

    def test_unknown_evidence_raises(self) -> None:
        with self.uow() as u, self.assertRaises(EvidenceNotFoundError):
            self.svc.record_integrity_failure(u, uid(0xDEAD), ctx=self.ctx)


class TestRecord(ServiceCase):
    """What the service adds on top of the repository."""

    def test_ids_come_from_the_context_and_the_record_is_bound(self) -> None:
        rec = self.put_for(self.c1)
        self.assertEqual(rec.run_id, self.ctx.run_id)
        self.assertEqual(rec.attempt_id, self.attempt_ctx.attempt_id)
        self.assertEqual(rec.correlation_id, self.ctx.correlation_id)
        self.assertEqual(rec.operation_id, self.ctx.operation_id)
        self.assertEqual(rec.candidate_id, self.c1.candidate_id)

    def test_a_candidate_record_needs_the_attempt_from_the_context(self) -> None:
        with self.uow() as u, self.assertRaises(DomainValidationError):
            self.svc.record(
                u,
                kind=K.VERIFICATION,
                event_name="v",
                payload={"r": 1},
                ctx=self.ctx,  # no attempt_id
                provenance=prov(),
                candidate_id=self.c1.candidate_id,
                parent_state_id=self.c1.parent_state_id,
                state_hash=self.c1.state_hash,
            )

    def test_a_payload_with_a_float_is_refused(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.put({"score": 0.5})

    def test_a_secret_is_redacted_before_it_is_hashed_and_stored(self) -> None:
        raw = {"config": {"password": "hunter2"}, "engine": "postgres"}
        rec = self.put(raw)
        with self.uow() as u:
            self.assertEqual(
                self.svc.resolve_payload(u, rec.evidence_id),
                {"config": {"password": "[REDACTED]"}, "engine": "postgres"},
            )

    def test_the_input_payload_is_not_mutated(self) -> None:
        raw = {"password": "hunter2"}
        self.put(raw)
        self.assertEqual(raw, {"password": "hunter2"})

    def test_the_default_clock_is_utc_and_an_explicit_time_is_kept(self) -> None:
        self.assertEqual(self.put().created_at.tzinfo, UTC)
        self.assertEqual(self.put({"k": 2}, now=at(77)).created_at, at(77))
        self.assertLess(
            abs((datetime.now(UTC) - self.put({"k": 3}).created_at).total_seconds()), 60
        )

    def test_a_record_and_its_state_commit_together(self) -> None:
        new_state = baseline(state_id=uid(0x77), lineage_id=uid(0xCC))
        with self.uow() as u:
            self.svc.record(
                u,
                kind=K.STATE,
                event_name="state_created",
                payload={"version": 0},
                ctx=self.ctx,
                provenance=prov(),
                state_id=new_state.state_id,
                state_hash=new_state.state_hash,
            )
            seed_evidence(u, new_state)
            u.trusted_states.save_baseline(new_state)
        self.assertEqual(self.count("evidence_events", "state_id = ?", (uid(0x77),)), 1)


class TestAuditEvents(ServiceCase):
    def test_required_payload_keys_are_enforced(self) -> None:
        with self.uow() as u, self.assertRaises(DomainValidationError):
            self.svc.append_audit_event(
                u,
                event_type=AuditEventType.CANDIDATE_CREATED,
                ctx=self.ctx,
                payload={"patch_id": uid(1)},
                candidate_id=self.c1.candidate_id,
            )

    def test_a_complete_event_is_stored_with_its_actor(self) -> None:
        with self.uow() as u:
            result = self.svc.append_audit_event(
                u,
                event_type=AuditEventType.CANDIDATE_CREATED,
                ctx=self.ctx,
                payload={
                    "parent_state_id": self.v0.state_id,
                    "patch_id": self.c1.patch_id,
                    "source": "FIXED_PATCH",
                },
                candidate_id=self.c1.candidate_id,
                actor_type=ActorType.AUTOMATION,
                actor_id="controller",
            )
        self.assertEqual(result.event.actor_type, ActorType.AUTOMATION)
        self.assertEqual(result.event.actor_id, "controller")

    def test_the_payload_is_redacted_before_it_is_stored(self) -> None:
        with self.uow() as u:
            result = self.svc.append_audit_event(
                u,
                event_type=AuditEventType.LLM_REQUESTED,
                ctx=self.ctx,
                payload={"model": "m", "api_key": "sk-live-abc"},
            )
            payload = u.evidence.resolve(ArtifactRef.parse(result.event.payload_ref))
        self.assertEqual(payload["api_key"], "[REDACTED]")
        self.assertNotIn(b"sk-live-abc", self.path.read_bytes())

    def test_a_float_payload_is_refused(self) -> None:
        with self.uow() as u, self.assertRaises(DomainValidationError):
            self.svc.append_audit_event(
                u, event_type=AuditEventType.LLM_REQUESTED, ctx=self.ctx, payload={"t": 0.5}
            )

    def test_a_failed_unit_of_work_leaves_no_event(self) -> None:
        with self.assertRaises(PersistenceError), self.uow() as u:
            self.svc.append_audit_event(
                u, event_type=AuditEventType.LLM_REQUESTED, ctx=self.ctx, payload={}
            )
            self.svc.record(  # evidence about a state that never commits: the commit fails
                u,
                kind=K.STATE,
                event_name="state_created",
                payload={"v": 0},
                ctx=self.ctx,
                provenance=prov(),
                state_id=uid(0x1234),
                state_hash="ab" * 32,
            )
        self.assertEqual(self.count("audit_events"), 0)


class TestLineageQueries(ServiceCase):
    """Exit criterion: lineage queries work."""

    def test_queries_by_state_candidate_run_attempt_and_correlation(self) -> None:
        a = self.put({"n": 1})
        b = self.put_for(self.c1, {"n": 2})
        other_ctx = CorrelationContext.new()
        c = self.put({"n": 3}, ctx=other_ctx)
        with self.uow() as u:
            svc = self.svc
            self.assertEqual(
                [r.evidence_id for r in svc.evidence_for_state(u, self.v0.state_id)],
                [a.evidence_id, c.evidence_id],
            )
            self.assertEqual(
                [r.evidence_id for r in svc.evidence_for_candidate(u, self.c1.candidate_id)],
                [b.evidence_id],
            )
            self.assertEqual(
                {r.evidence_id for r in svc.evidence_for_correlation(u, self.ctx.correlation_id)},
                {a.evidence_id, b.evidence_id},
            )
            self.assertEqual(
                {r.evidence_id for r in svc.evidence_for_run(u, self.ctx.run_id)},
                {a.evidence_id, b.evidence_id},
            )
            self.assertEqual(
                [
                    r.evidence_id
                    for r in svc.evidence_for_attempt(u, self.attempt_ctx.attempt_id or "")
                ],
                [b.evidence_id],
            )

    def test_events_come_back_in_append_order(self) -> None:
        cid = self.c1.candidate_id
        events = [
            (
                AuditEventType.CANDIDATE_CREATED,
                {
                    "parent_state_id": self.v0.state_id,
                    "patch_id": self.c1.patch_id,
                    "source": "FIXED_PATCH",
                },
            ),
            (AuditEventType.IMPACT_COMPLETED, {}),
            (
                AuditEventType.VERIFICATION_COMPLETED,
                {
                    "verification_id": uid(0x501),
                    "target": "candidate",
                    "result": "PASS",
                    "verifier_id": "v",
                    "verifier_version": "1",
                },
            ),
            (AuditEventType.CANDIDATE_REJECTED, {}),
        ]
        with self.uow() as u:
            for event_type, payload in events:
                self.svc.append_audit_event(
                    u, event_type=event_type, ctx=self.ctx, payload=payload, candidate_id=cid
                )
            got = [
                e.event_type for e in self.svc.events_for_correlation(u, self.ctx.correlation_id)
            ]
            self.assertEqual(got, [t for t, _ in events])
            self.assertEqual(len(self.svc.events_for_candidate(u, cid)), 4)

    def test_correlation_is_isolated_between_workflows(self) -> None:
        other = CorrelationContext.new()
        with self.uow() as u:
            self.svc.append_audit_event(
                u, event_type=AuditEventType.IMPACT_COMPLETED, ctx=self.ctx, payload={}
            )
            self.svc.append_audit_event(
                u, event_type=AuditEventType.IMPACT_COMPLETED, ctx=other, payload={}
            )
            self.assertEqual(len(self.svc.events_for_correlation(u, self.ctx.correlation_id)), 1)

    def test_validity_history_can_be_limited_to_one_context(self) -> None:
        rec = self.put()
        impact = self.impact_for(self.c1)
        with self.uow() as u:
            self.svc.change_validity(
                u, rec.evidence_id, context=self.v0_ctx, to=V.UNCERTAIN, reason="a", ctx=self.ctx
            )
            self.svc.invalidate(
                u,
                rec.evidence_id,
                context=self.c1_ctx,
                reason="b",
                ctx=self.ctx,
                impact_ref=impact.evidence_id,
            )
            self.assertEqual(
                [t.reason for t in self.svc.validity_history(u, rec.evidence_id)], ["a", "b"]
            )
            self.assertEqual(
                [t.reason for t in self.svc.validity_history(u, rec.evidence_id, self.v0_ctx)],
                ["a"],
            )
            self.assertEqual(
                [t.reason for t in self.svc.validity_history(u, rec.evidence_id, self.c1_ctx)],
                ["b"],
            )


if __name__ == "__main__":
    unittest.main()
