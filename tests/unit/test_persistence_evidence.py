"""The SQLite evidence and audit repositories (Doc 05 §16, §26, §32; Doc 11 §4, §32, §33, §38, §44;
C-42, C-43, C-52, C-53, C-59; P2-fix step 3).

Expected behaviour comes from the P2-fix prompt's rules A1 to A6 and from C-52 and C-53.
"""

from __future__ import annotations

import ast
import dataclasses
import re
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from core.domain import repositories
from core.domain.audit import (
    AuditEventType,
    ConflictingDuplicateEventError,
)
from core.domain.errors import (
    DomainValidationError,
    IllegalTransitionError,
    PersistenceError,
)
from core.domain.evidence import (
    ArtifactRef,
    BrokenReferenceError,
    EvidenceConflictError,
    EvidenceContext,
    EvidenceKind,
    EvidenceNotFoundError,
    EvidenceValidity,
    SupersessionRequest,
    TransitionRequest,
    TransitionScope,
    effective_validity,
)
from core.domain.hashing import canonical_json, content_hash
from core.persistence import sqlite as sqlite_module
from core.persistence.sqlite import SqliteUnitOfWork
from tests.domain_builders import at, baseline, uid
from tests.evidence_builders import (
    CORR,
    OP,
    audit_submission,
    candidate_submission,
    eid,
    state_submission,
    submission,
)
from tests.persistence_builders import SAFE, SAFE_OTHER, Boom, RepoCase

K = EvidenceKind
V = EvidenceValidity
CONTEXT, RECORD = TransitionScope.CONTEXT, TransitionScope.RECORD


def request(
    n: int,
    evidence_id: str,
    to: EvidenceValidity,
    *,
    scope: TransitionScope = CONTEXT,
    context: EvidenceContext | None = None,
    reason: str = "because",
    impact_ref: str | None = None,
) -> TransitionRequest:
    return TransitionRequest(
        transition_id=uid(0x6100 + n),
        evidence_id=evidence_id,
        scope=scope,
        context=context,
        to_validity=to,
        reason=reason,
        impact_ref=impact_ref,
        correlation_id=CORR,
        operation_id=OP,
        created_at=at(8),
    )


def supersession(n: int, old: str, new: str, reason: str = "re-verified") -> SupersessionRequest:
    return SupersessionRequest(
        transition_id=uid(0x6200 + n),
        old_evidence_id=old,
        new_evidence_id=new,
        reason=reason,
        correlation_id=CORR,
        operation_id=OP,
        created_at=at(9),
    )


class EvidenceCase(RepoCase):
    """A database with trusted state v0 (SSH open) and two candidates of it at ANALYZING."""

    def setUp(self) -> None:
        super().setUp()
        self.v0 = self.seed()
        stages_1 = self.store_stages(self.v0, SAFE, n=1, sequence=1, upto=3)
        stages_2 = self.store_stages(self.v0, SAFE_OTHER, n=2, sequence=2, upto=3)
        self.c1, self.c2 = stages_1[3], stages_2[3]
        self.ctx_v0 = EvidenceContext.state(self.v0.state_id)
        self.ctx_c1 = EvidenceContext.candidate(self.c1.candidate_id)
        self.ctx_c2 = EvidenceContext.candidate(self.c2.candidate_id)

    def append(self, *subs: Any) -> None:
        with self.uow() as u:
            for sub in subs:
                u.evidence.append(sub)

    def read_evidence(self, n: int) -> Any:
        with self.uow() as u:
            return u.evidence.get(eid(n))

    def validity_in(self, n: int, context: EvidenceContext) -> EvidenceValidity:
        with self.uow() as u:
            event = u.evidence.get(eid(n))
            assert event is not None
            return effective_validity(event, context, u.evidence.transitions(eid(n)))


class TestAppendAndRead(EvidenceCase):
    def test_a_record_round_trips_and_its_payload_resolves(self) -> None:
        sub = state_submission(1, self.v0, payload={"result": "PASS", "predicate": "ckv_aws_24"})
        with self.uow() as u:
            result = u.evidence.append(sub)
        self.assertFalse(result.duplicate)
        with self.uow() as u:
            stored = u.evidence.get(eid(1))
            assert stored is not None
            self.assertEqual(stored, sub.event)
            self.assertEqual(
                u.evidence.resolve(ArtifactRef.parse(stored.payload_ref)),
                {"result": "PASS", "predicate": "ckv_aws_24"},
            )
        self.assertEqual(stored.payload_ref, f"evidence://verification/{stored.content_hash}")

    def test_the_stored_payload_is_the_canonical_text(self) -> None:
        sub = state_submission(1, self.v0, payload={"b": 1, "a": [2, 3]})
        self.append(sub)
        self.assertEqual(
            self.scalar("SELECT payload_json FROM evidence_artifacts"), '{"a":[2,3],"b":1}'
        )

    def test_unknown_evidence_is_none_and_a_transition_on_it_raises(self) -> None:
        with self.uow() as u:
            self.assertIsNone(u.evidence.get(eid(99)))
            with self.assertRaises(EvidenceNotFoundError):
                u.evidence.append_transition(request(1, eid(99), V.INVALID, context=self.ctx_v0))

    def test_a_broken_reference_raises(self) -> None:
        ref = ArtifactRef("verification", "ab" * 32)
        with self.uow() as u, self.assertRaises(BrokenReferenceError) as caught:
            u.evidence.resolve(ref)
        self.assertIsInstance(caught.exception, PersistenceError)
        self.assertIn(ref.uri, str(caught.exception))

    def test_identical_payloads_share_one_artifact(self) -> None:
        self.append(
            state_submission(1, self.v0, payload={"same": 1}),
            state_submission(2, self.v0, payload={"same": 1}),
        )
        self.assertEqual(self.count("evidence_artifacts"), 1)
        self.assertEqual(self.count("evidence_events"), 2)

    def test_resolve_and_append_refuse_foreign_argument_types(self) -> None:
        with self.uow() as u:
            with self.assertRaises(DomainValidationError):
                u.evidence.resolve("evidence://verification/" + "ab" * 32)  # type: ignore[arg-type]
            with self.assertRaises(DomainValidationError):
                u.evidence.append(state_submission(1, self.v0).event)  # type: ignore[arg-type]
            with self.assertRaises(DomainValidationError):
                u.audit.append(state_submission(1, self.v0))  # type: ignore[arg-type]


class TestAppendRules(EvidenceCase):
    """A1 to A4."""

    def test_a1_a_payload_that_does_not_match_its_hash_is_refused(self) -> None:
        sub = state_submission(1, self.v0)
        object.__setattr__(sub, "payload_json", canonical_json({"result": "FAIL", "n": 1}))
        with self.uow() as u, self.assertRaises(DomainValidationError):
            u.evidence.append(sub)
        self.assertEqual(self.count("evidence_events"), 0)
        self.assertEqual(self.count("evidence_artifacts"), 0)

    def test_a1_a_non_canonical_payload_is_refused(self) -> None:
        sub = state_submission(1, self.v0, payload={"a": 1})
        object.__setattr__(sub, "payload_json", '{"a": 1}')
        with self.uow() as u, self.assertRaises(DomainValidationError):
            u.evidence.append(sub)
        self.assertEqual(self.count("evidence_artifacts"), 0)

    def test_a1_a_secret_appended_directly_through_the_port_is_refused(self) -> None:
        sub = state_submission(1, self.v0, payload={"engine": "postgres"})
        secret = {"engine": "postgres", "password": "hunter2-SUPERSECRET"}
        digest = content_hash(secret)
        digest_event = dataclasses.replace(
            sub.event, content_hash=digest, payload_ref=f"evidence://verification/{digest}"
        )
        object.__setattr__(sub, "event", digest_event)
        object.__setattr__(sub, "payload_json", canonical_json(secret))
        with self.uow() as u, self.assertRaises(DomainValidationError) as caught:
            u.evidence.append(sub)
        self.assertIn("§28", str(caught.exception))
        self.assertNotIn(b"hunter2-SUPERSECRET", self.path.read_bytes())
        self.assertEqual(self.count("evidence_artifacts"), 0)

    def test_a1_an_audit_payload_that_does_not_match_its_hash_is_refused(self) -> None:
        sub = audit_submission(1, payload={"a": 1})
        object.__setattr__(sub, "payload_json", '{"a":2}')
        with self.uow() as u, self.assertRaises(DomainValidationError):
            u.audit.append(sub)
        self.assertEqual(self.count("audit_events"), 0)
        self.assertEqual(self.count("evidence_artifacts"), 0)

    def test_a1_a_non_canonical_audit_payload_is_refused(self) -> None:
        sub = audit_submission(1, payload={"a": 1})
        object.__setattr__(sub, "payload_json", '{"a": 1}')
        with self.uow() as u, self.assertRaises(DomainValidationError):
            u.audit.append(sub)
        self.assertEqual(self.count("audit_events"), 0)

    def test_a1_an_audit_secret_appended_directly_through_the_port_is_refused(self) -> None:
        sub = audit_submission(1, payload={"engine": "postgres"})
        secret = {"engine": "postgres", "password": "hunter2-SUPERSECRET"}
        digest = content_hash(secret)
        object.__setattr__(sub, "payload_hash", digest)
        object.__setattr__(sub, "payload_ref", f"evidence://audit/{digest}")
        object.__setattr__(sub, "payload_json", canonical_json(secret))
        with self.uow() as u, self.assertRaises(DomainValidationError) as caught:
            u.audit.append(sub)
        self.assertIn("§28", str(caught.exception))
        self.assertNotIn(b"hunter2-SUPERSECRET", self.path.read_bytes())
        self.assertEqual(self.count("audit_events"), 0)

    def test_a2_an_artifact_that_exists_with_different_text_refuses_the_append(self) -> None:
        self.append(state_submission(1, self.v0, payload={"v": 1}))
        digest = self.scalar("SELECT content_hash FROM evidence_artifacts")
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json = ? WHERE content_hash = ?",
            ('{"v":2}', digest),
        )
        with self.uow() as u, self.assertRaises(PersistenceError) as caught:
            u.evidence.append(state_submission(2, self.v0, payload={"v": 1}))
        self.assertIn("A2", str(caught.exception))
        self.assertEqual(self.count("evidence_events"), 1)

    def test_a3_the_adapter_never_uses_or_replace_or_or_ignore(self) -> None:
        source = Path(sqlite_module.__file__).read_text(encoding="utf-8").upper()
        # the module docstring and comments name the rule; only SQL statements matter here
        statements = [
            node.value
            for node in ast.walk(ast.parse(Path(sqlite_module.__file__).read_text("utf-8")))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        for text in statements:
            self.assertIsNone(re.match(r"\s*(INSERT|REPLACE)\s+OR\s", text, re.IGNORECASE), text)
        self.assertIn("EVIDENCE_EVENTS", source)

    def test_a4_a_stored_row_that_fails_validation_is_refused_on_read(self) -> None:
        self.append(state_submission(1, self.v0))
        self.tamper(
            "UPDATE evidence_events SET event_name = 'edited' WHERE evidence_id = ?", (eid(1),)
        )
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.evidence.get(eid(1))

    def test_a4_an_edited_content_json_is_refused_on_read(self) -> None:
        self.append(state_submission(1, self.v0))
        self.tamper(
            "UPDATE evidence_events SET content_json = "
            "replace(content_json, 'verification_completed', 'edited') WHERE evidence_id = ?",
            (eid(1),),
        )
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.evidence.get(eid(1))

    def test_a4_a_content_json_that_breaks_a_domain_rule_is_refused(self) -> None:
        self.append(state_submission(1, self.v0))
        self.tamper(
            "UPDATE evidence_events SET content_json = replace(content_json, 'verification', "
            "'cas:xyz') WHERE evidence_id = ?",
            (eid(1),),
        )
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.evidence.list_for_state(self.v0.state_id)

    def test_a_stored_audit_row_is_revalidated_on_read(self) -> None:
        with self.uow() as u:
            u.audit.append(audit_submission(1))
        self.tamper("UPDATE audit_events SET timestamp = 'yesterday'")
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.audit.get(uid(0x8001))


class TestListsAndOrdering(EvidenceCase):
    def test_lists_come_back_in_append_order_not_timestamp_order(self) -> None:
        later = state_submission(1, self.v0, created_at=at(50))
        earlier = state_submission(2, self.v0, created_at=at(5))
        self.append(later, earlier)
        with self.uow() as u:
            self.assertEqual(
                [e.evidence_id for e in u.evidence.list_for_state(self.v0.state_id)],
                [eid(1), eid(2)],
            )

    def test_every_list_query_finds_its_records(self) -> None:
        a = state_submission(1, self.v0)
        b = candidate_submission(2, self.c1, kind=K.IMPACT)
        other_run = state_submission(3, self.v0, run_id=uid(0x9101), correlation_id=uid(0x9102))
        self.append(a, b, other_run)
        with self.uow() as u:

            def ids(events: Any) -> list[str]:
                return [e.evidence_id for e in events]

            self.assertEqual(ids(u.evidence.list_for_state(self.v0.state_id)), [eid(1), eid(3)])
            self.assertEqual(ids(u.evidence.list_for_candidate(self.c1.candidate_id)), [eid(2)])
            self.assertEqual(ids(u.evidence.list_for_correlation(CORR)), [eid(1), eid(2)])
            self.assertEqual(ids(u.evidence.list_for_correlation(uid(0x9102))), [eid(3)])
            self.assertEqual(ids(u.evidence.list_for_run(uid(0x9101))), [eid(3)])
            self.assertEqual(u.evidence.list_for_state(uid(0xFFFF)), ())

    def test_list_for_attempt_returns_exactly_that_attempts_records(self) -> None:
        first = candidate_submission(1, self.c1, kind=K.IMPACT)
        second = candidate_submission(2, self.c1, attempt_id=uid(0x9201))
        third = candidate_submission(3, self.c2, attempt_id=uid(0x9201))
        baseline_record = state_submission(4, self.v0)  # no attempt
        self.append(first, second, third, baseline_record)
        with self.uow() as u:
            self.assertEqual(
                [e.evidence_id for e in u.evidence.list_for_attempt(uid(0x9201))],
                [eid(2), eid(3)],
            )
            self.assertEqual(
                [e.evidence_id for e in u.evidence.list_for_attempt(uid(0x9002))], [eid(1)]
            )

    def test_audit_sequences_are_strictly_increasing(self) -> None:
        with self.uow() as u:
            events = [u.audit.append(audit_submission(n)).event for n in range(1, 6)]
        self.assertEqual([e.sequence for e in events], sorted(e.sequence for e in events))
        self.assertEqual(len({e.sequence for e in events}), 5)
        with self.uow() as u:
            self.assertEqual(
                [e.event_id for e in u.audit.list_for_correlation(CORR)],
                [e.event_id for e in events],
            )

    def test_audit_lists_are_scoped(self) -> None:
        with self.uow() as u:
            u.audit.append(audit_submission(1, correlation_id=uid(0x9301)))
            u.audit.append(
                audit_submission(
                    2, AuditEventType.CANDIDATE_REJECTED, candidate_id=self.c1.candidate_id
                )
            )
            u.audit.append(audit_submission(3, candidate_id=self.c1.candidate_id))
            self.assertEqual(len(u.audit.list_for_correlation(uid(0x9301))), 1)
            self.assertEqual(
                [e.event_id for e in u.audit.list_for_candidate(self.c1.candidate_id)],
                [uid(0x8002), uid(0x8003)],
            )


class TestIdempotency(EvidenceCase):
    """A6 and Doc 11 §38."""

    def test_a_redelivered_record_is_a_duplicate_and_adds_no_row(self) -> None:
        first = state_submission(1, self.v0, created_at=at(5))
        again = state_submission(1, self.v0, created_at=at(500))
        with self.uow() as u:
            one = u.evidence.append(first)
            two = u.evidence.append(again)
        self.assertFalse(one.duplicate)
        self.assertTrue(two.duplicate)
        self.assertEqual(two.record.created_at, at(5))  # the stored record, not the redelivery
        self.assertEqual(self.count("evidence_events"), 1)

    def test_a_redelivery_with_any_changed_field_is_a_conflict(self) -> None:
        self.append(state_submission(1, self.v0))
        changes: dict[str, dict[str, Any]] = {
            "payload": {"payload": {"result": "FAIL"}},
            "event_name": {"event_name": "other"},
            "run": {"run_id": uid(0x9101)},
            "operation": {"operation_id": uid(0x9102)},
            "kind": {"kind": K.CONFIGURATION},
            "validity": {"validity": V.UNCERTAIN},
            "state_hash": {"state_hash": "cd" * 32},
            "schema_version": {"schema_version": "2"},
            "provenance_version": {
                "provenance": dataclasses.replace(
                    state_submission(1, self.v0).event.provenance, algorithm_version="verifier-2"
                )
            },
        }
        for label, change in changes.items():
            with (
                self.subTest(change=label),
                self.uow() as u,
                self.assertRaises(EvidenceConflictError),
            ):
                u.evidence.append(state_submission(1, self.v0, **change))
        self.assertEqual(self.count("evidence_events"), 1)

    def test_a_redelivered_audit_event_is_a_duplicate(self) -> None:
        with self.uow() as u:
            one = u.audit.append(audit_submission(1, timestamp=at(6)))
            two = u.audit.append(audit_submission(1, timestamp=at(600)))
        self.assertFalse(one.duplicate)
        self.assertTrue(two.duplicate)
        self.assertEqual(one.event.sequence, two.event.sequence)
        self.assertEqual(self.count("audit_events"), 1)

    def test_d4_a_redelivery_with_another_candidate_is_not_a_duplicate(self) -> None:
        """The 2c9b668 store compared only payload_hash and event_type."""
        kwargs = {"event_type": AuditEventType.CANDIDATE_REJECTED}
        with self.uow() as u:
            u.audit.append(audit_submission(1, candidate_id=self.c1.candidate_id, **kwargs))
        for label, change in {
            "candidate_id": {"candidate_id": self.c2.candidate_id},
            "state_id": {"candidate_id": self.c1.candidate_id, "state_id": self.v0.state_id},
            "correlation_id": {"candidate_id": self.c1.candidate_id, "correlation_id": uid(0x9401)},
            "operation_id": {"candidate_id": self.c1.candidate_id, "operation_id": uid(0x9402)},
            "decision_id": {"candidate_id": self.c1.candidate_id, "decision_id": uid(0x9403)},
            "actor_id": {"candidate_id": self.c1.candidate_id, "actor_id": "someone"},
            "event_version": {"candidate_id": self.c1.candidate_id, "event_version": 2},
            "payload": {"candidate_id": self.c1.candidate_id, "payload": {"n": 99}},
        }.items():
            with (
                self.subTest(change=label),
                self.uow() as u,
                self.assertRaises(ConflictingDuplicateEventError),
            ):
                u.audit.append(audit_submission(1, **kwargs, **change))
        self.assertEqual(self.count("audit_events"), 1)

    def test_a_redelivered_transition_adds_no_second_row_and_no_second_event(self) -> None:
        self.append(state_submission(1, self.v0))
        req = request(1, eid(1), V.UNCERTAIN, context=self.ctx_v0)
        with self.uow() as u:
            one = u.evidence.append_transition(req)
            two = u.evidence.append_transition(req)
        self.assertFalse(one.duplicate)
        self.assertTrue(two.duplicate)
        self.assertEqual(one.transition, two.transition)
        self.assertEqual(self.count("evidence_validity_transitions"), 1)
        self.assertEqual(self.count("audit_events", "event_type = 'EVIDENCE_VALIDITY_CHANGED'"), 1)

    def test_a_redelivered_transition_with_a_changed_field_is_a_conflict(self) -> None:
        self.append(state_submission(1, self.v0), state_submission(2, self.v0))
        with self.uow() as u:
            u.evidence.append_transition(request(1, eid(1), V.UNCERTAIN, context=self.ctx_v0))
        for label, other in {
            "reason": request(1, eid(1), V.UNCERTAIN, context=self.ctx_v0, reason="different"),
            "target": request(1, eid(1), V.INVALID, context=self.ctx_v0),
            "evidence": request(1, eid(2), V.UNCERTAIN, context=self.ctx_v0),
            "context": request(1, eid(1), V.UNCERTAIN, context=self.ctx_c1),
        }.items():
            with (
                self.subTest(change=label),
                self.uow() as u,
                self.assertRaises(EvidenceConflictError),
            ):
                u.evidence.append_transition(other)
        self.assertEqual(self.count("evidence_validity_transitions"), 1)

    def test_concurrent_identical_appends_from_two_connections_give_one_row(self) -> None:
        sub = state_submission(1, self.v0)
        barrier = threading.Barrier(2)
        results: list[Any] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                barrier.wait(timeout=10)
                with SqliteUnitOfWork(self.path, timeout=20.0) as u:
                    results.append(u.evidence.append(sub).duplicate)
            except BaseException as exc:  # noqa: BLE001 - reported below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(self.count("evidence_events"), 1)
        self.assertEqual(self.count("evidence_artifacts"), 1)

    def test_concurrent_identical_audit_appends_give_one_row(self) -> None:
        sub = audit_submission(1)
        barrier = threading.Barrier(2)
        results: list[Any] = []

        def worker() -> None:
            barrier.wait(timeout=10)
            with SqliteUnitOfWork(self.path, timeout=20.0) as u:
                results.append(u.audit.append(sub).duplicate)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(self.count("audit_events"), 1)


class TestTransitions(EvidenceCase):
    """C-52 through the repository: legality, the impact reference, history and the audit event."""

    def setUp(self) -> None:
        super().setUp()
        self.append(
            state_submission(1, self.v0),  # E1: about v0
            candidate_submission(2, self.c1, kind=K.IMPACT),  # the impact report for c1
        )

    def invalidate_for_c1(self, n: int = 1) -> Any:
        with self.uow() as u:
            return u.evidence.append_transition(
                request(n, eid(1), V.INVALID, context=self.ctx_c1, impact_ref=eid(2))
            )

    def test_d1_invalid_for_a_candidate_leaves_the_state_valid(self) -> None:
        result = self.invalidate_for_c1()
        self.assertFalse(result.duplicate)
        self.assertIs(self.validity_in(1, self.ctx_c1), V.INVALID)
        self.assertIs(self.validity_in(1, self.ctx_v0), V.VALID)
        self.assertIs(self.validity_in(1, self.ctx_c2), V.UNCERTAIN)  # R4, never VALID
        self.assertEqual(self.count("evidence_events"), 2)  # the record itself is untouched

    def test_the_transition_records_its_from_validity_and_impact_reference(self) -> None:
        stored = self.invalidate_for_c1().transition
        self.assertIs(stored.from_validity, V.UNCERTAIN)  # R4 in a foreign context
        self.assertIs(stored.to_validity, V.INVALID)
        self.assertIs(stored.scope, CONTEXT)
        self.assertEqual(stored.context, self.ctx_c1)
        self.assertEqual(stored.impact_ref, eid(2))
        with self.uow() as u:
            self.assertEqual(u.evidence.transitions(eid(1)), (stored,))
            self.assertEqual(u.evidence.transitions(eid(2)), ())

    def test_the_audit_event_is_appended_in_the_same_step(self) -> None:
        self.invalidate_for_c1()
        with self.uow() as u:
            events = u.audit.list_for_correlation(CORR)
            self.assertEqual(
                [e.event_type for e in events], [AuditEventType.EVIDENCE_VALIDITY_CHANGED]
            )
            payload = u.evidence.resolve(ArtifactRef.parse(events[0].payload_ref))
        self.assertEqual(events[0].candidate_id, self.c1.candidate_id)
        self.assertIsNone(events[0].state_id)
        self.assertEqual(payload["evidence_id"], eid(1))
        self.assertEqual(payload["scope"], "CONTEXT")
        self.assertEqual(payload["context_kind"], "CANDIDATE")
        self.assertEqual(payload["context_id"], self.c1.candidate_id)
        self.assertEqual(payload["from_validity"], "UNCERTAIN")
        self.assertEqual(payload["to_validity"], "INVALID")
        self.assertEqual(payload["impact_ref"], eid(2))
        self.assertIsNone(payload["superseded_by"])

    def test_a_failed_transition_changes_nothing(self) -> None:
        before = self.snapshot_counts() | {
            t: self.count(t)
            for t in ("evidence_events", "evidence_validity_transitions", "audit_events")
        }
        for label, req in {
            "no impact_ref": request(1, eid(1), V.INVALID, context=self.ctx_c1),
            "impact_ref is not IMPACT": request(
                1, eid(1), V.INVALID, context=self.ctx_c1, impact_ref=eid(1)
            ),
            "valid to valid": request(1, eid(1), V.VALID, context=self.ctx_v0),
            "to superseded": request(1, eid(1), V.SUPERSEDED, context=self.ctx_v0),
            "to redacted": request(1, eid(1), V.REDACTED, context=self.ctx_v0),
            "record scope needs INTEGRITY": request(1, eid(1), V.INVALID, scope=RECORD),
        }.items():
            with (
                self.subTest(case=label),
                self.uow() as u,
                self.assertRaises(IllegalTransitionError),
            ):
                u.evidence.append_transition(req)
        after = self.snapshot_counts() | {
            t: self.count(t)
            for t in ("evidence_events", "evidence_validity_transitions", "audit_events")
        }
        self.assertEqual(before, after)

    def test_the_impact_reference_must_name_impact_evidence_for_that_candidate(self) -> None:
        self.append(candidate_submission(3, self.c2, kind=K.IMPACT))  # an impact report for c2
        with self.uow() as u, self.assertRaises(IllegalTransitionError) as caught:
            u.evidence.append_transition(
                request(1, eid(1), V.INVALID, context=self.ctx_c1, impact_ref=eid(3))
            )
        self.assertIn("impact_ref", str(caught.exception))
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            u.evidence.append_transition(
                request(1, eid(1), V.INVALID, context=self.ctx_c1, impact_ref=eid(77))
            )

    def test_invalid_is_terminal_in_its_context_but_the_state_can_still_change(self) -> None:
        self.invalidate_for_c1()
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            u.evidence.append_transition(request(2, eid(1), V.VALID, context=self.ctx_c1))
        with self.uow() as u:
            u.evidence.append_transition(request(3, eid(1), V.UNCERTAIN, context=self.ctx_v0))
        self.assertIs(self.validity_in(1, self.ctx_v0), V.UNCERTAIN)
        self.assertIs(self.validity_in(1, self.ctx_c1), V.INVALID)

    def test_uncertain_can_be_resolved_to_valid_in_an_own_context_only(self) -> None:
        with self.uow() as u:
            u.evidence.append_transition(request(1, eid(1), V.UNCERTAIN, context=self.ctx_v0))
            u.evidence.append_transition(request(2, eid(1), V.VALID, context=self.ctx_v0))
        self.assertIs(self.validity_in(1, self.ctx_v0), V.VALID)
        self.assertEqual(self.count("evidence_validity_transitions"), 2)
        with self.uow() as u, self.assertRaises(IllegalTransitionError):  # a foreign context
            u.evidence.append_transition(request(3, eid(1), V.VALID, context=self.ctx_c2))

    def test_an_integrity_failure_is_a_record_scope_invalid_and_is_terminal(self) -> None:
        with self.uow() as u:
            u.evidence.append_transition(
                request(1, eid(1), V.INVALID, scope=RECORD, reason="INTEGRITY: hash mismatch")
            )
        for context in (self.ctx_v0, self.ctx_c1, self.ctx_c2):
            self.assertIs(self.validity_in(1, context), V.INVALID)
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            u.evidence.append_transition(
                request(2, eid(1), V.INVALID, scope=RECORD, reason="INTEGRITY: again")
            )
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            u.evidence.append_transition(request(3, eid(1), V.UNCERTAIN, context=self.ctx_v0))

    def test_a_failure_later_in_the_unit_of_work_rolls_the_transition_and_event_back(self) -> None:
        with self.assertRaises(Boom), self.uow() as u:
            u.evidence.append_transition(
                request(1, eid(1), V.INVALID, context=self.ctx_c1, impact_ref=eid(2))
            )
            raise Boom
        self.assertEqual(self.count("evidence_validity_transitions"), 0)
        self.assertEqual(self.count("audit_events"), 0)

    def test_transitions_come_back_in_sequence_order(self) -> None:
        with self.uow() as u:
            u.evidence.append_transition(request(1, eid(1), V.UNCERTAIN, context=self.ctx_v0))
            u.evidence.append_transition(
                request(2, eid(1), V.INVALID, context=self.ctx_c1, impact_ref=eid(2))
            )
            u.evidence.append_transition(request(3, eid(1), V.VALID, context=self.ctx_v0))
            seqs = [t.seq for t in u.evidence.transitions(eid(1))]
            ids = [t.transition_id for t in u.evidence.transitions(eid(1))]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(ids, [uid(0x6101), uid(0x6102), uid(0x6103)])


class TestSupersession(EvidenceCase):
    """C-53 (D2) through the repository."""

    def test_a_replacement_for_the_same_thing_supersedes(self) -> None:
        self.append(state_submission(1, self.v0), state_submission(2, self.v0, payload={"v": 2}))
        with self.uow() as u:
            result = u.evidence.supersede(supersession(1, eid(1), eid(2)))
            self.assertEqual(u.evidence.superseded_by(eid(1)), eid(2))
            self.assertEqual(u.evidence.supersedes(eid(2)), eid(1))
            self.assertIsNone(u.evidence.superseded_by(eid(2)))
            self.assertIsNone(u.evidence.supersedes(eid(1)))
        self.assertIs(result.transition.scope, RECORD)
        self.assertIs(result.transition.to_validity, V.SUPERSEDED)
        self.assertEqual(result.transition.superseded_by, eid(2))
        self.assertIs(result.transition.from_validity, V.VALID)
        self.assertIs(self.validity_in(1, self.ctx_v0), V.SUPERSEDED)
        self.assertIs(self.validity_in(2, self.ctx_v0), V.VALID)
        # nothing was deleted and the old payload still resolves
        with self.uow() as u:
            old = u.evidence.get(eid(1))
            assert old is not None
            self.assertEqual(
                u.evidence.resolve(ArtifactRef.parse(old.payload_ref))["result"], "PASS"
            )

    def test_supersession_writes_the_row_the_transition_and_the_audit_event_together(self) -> None:
        self.append(state_submission(1, self.v0), state_submission(2, self.v0, payload={"v": 2}))
        with self.uow() as u:
            u.evidence.supersede(supersession(1, eid(1), eid(2)))
        self.assertEqual(self.count("evidence_supersessions"), 1)
        self.assertEqual(self.count("evidence_validity_transitions", "scope = 'RECORD'"), 1)
        with self.uow() as u:
            (event,) = u.audit.list_for_correlation(CORR)
            payload = u.evidence.resolve(ArtifactRef.parse(event.payload_ref))
        self.assertEqual(event.event_type, AuditEventType.EVIDENCE_VALIDITY_CHANGED)
        self.assertEqual(payload["superseded_by"], eid(2))
        self.assertIsNone(payload["context_id"])

    def test_d2_evidence_about_a_state_is_not_superseded_by_candidate_evidence(self) -> None:
        self.append(
            state_submission(1, self.v0),
            candidate_submission(2, self.c1),  # VERIFICATION about candidate c1
        )
        with self.uow() as u, self.assertRaises(IllegalTransitionError) as caught:
            u.evidence.supersede(supersession(1, eid(1), eid(2)))
        self.assertIn("C-53", str(caught.exception))
        self.assertEqual(self.count("evidence_supersessions"), 0)
        self.assertEqual(self.count("evidence_validity_transitions"), 0)

    def test_d2_llm_evidence_about_vn_is_not_superseded_by_another_candidates_verification(
        self,
    ) -> None:
        self.append(
            state_submission(1, self.v0, kind=K.LLM),
            candidate_submission(2, self.c2, kind=K.VERIFICATION),
        )
        with self.uow() as u, self.assertRaises(IllegalTransitionError):
            u.evidence.supersede(supersession(1, eid(1), eid(2)))

    def test_every_other_c53_refusal(self) -> None:
        self.append(
            state_submission(1, self.v0),
            state_submission(2, self.v0, kind=K.CONFIGURATION),  # a different kind
            state_submission(3, self.v0, validity=V.UNCERTAIN),  # not VALID
            submission(4, state_id=None, state_hash=None),  # unbound
            submission(5, state_id=None, state_hash=None, payload={"u": 5}),  # unbound
            state_submission(6, self.v0, payload={"v": 6}),
        )
        cases = {
            "itself": (eid(1), eid(1)),
            "different kind": (eid(1), eid(2)),
            "new is UNCERTAIN": (eid(1), eid(3)),
            "both unbound": (eid(4), eid(5)),
        }
        for label, (old, new) in cases.items():
            with (
                self.subTest(case=label),
                self.uow() as u,
                self.assertRaises(IllegalTransitionError),
            ):
                u.evidence.supersede(supersession(1, old, new))
        self.assertEqual(self.count("evidence_supersessions"), 0)
        with self.uow() as u, self.assertRaises(EvidenceNotFoundError):
            u.evidence.supersede(supersession(1, eid(1), eid(99)))

    def test_a_record_cannot_be_superseded_twice_and_a_superseded_record_cannot_replace(
        self,
    ) -> None:
        self.append(
            state_submission(1, self.v0),
            state_submission(2, self.v0, payload={"v": 2}),
            state_submission(3, self.v0, payload={"v": 3}),
        )
        with self.uow() as u:
            u.evidence.supersede(supersession(1, eid(1), eid(2)))
        with self.uow() as u, self.assertRaises(IllegalTransitionError):  # old already superseded
            u.evidence.supersede(supersession(2, eid(1), eid(3)))
        with self.uow() as u, self.assertRaises(IllegalTransitionError):  # new already superseded
            u.evidence.supersede(supersession(3, eid(3), eid(1)))
        self.assertEqual(self.count("evidence_supersessions"), 1)

    def test_a_chain_of_supersessions(self) -> None:
        self.append(*(state_submission(n, self.v0, payload={"v": n}) for n in (1, 2, 3)))
        with self.uow() as u:
            u.evidence.supersede(supersession(1, eid(1), eid(2)))
            u.evidence.supersede(supersession(2, eid(2), eid(3)))
            self.assertEqual(u.evidence.supersedes(eid(3)), eid(2))
            self.assertEqual(u.evidence.supersedes(eid(2)), eid(1))
            self.assertEqual(u.evidence.superseded_by(eid(1)), eid(2))
        self.assertIs(self.validity_in(3, self.ctx_v0), V.VALID)

    def test_a_redelivered_supersession_is_a_duplicate(self) -> None:
        self.append(state_submission(1, self.v0), state_submission(2, self.v0, payload={"v": 2}))
        req = supersession(1, eid(1), eid(2))
        with self.uow() as u:
            one = u.evidence.supersede(req)
            two = u.evidence.supersede(req)
        self.assertFalse(one.duplicate)
        self.assertTrue(two.duplicate)
        self.assertEqual(self.count("evidence_supersessions"), 1)
        self.assertEqual(self.count("audit_events"), 1)
        with self.uow() as u, self.assertRaises(EvidenceConflictError):
            u.evidence.supersede(supersession(1, eid(1), eid(2), reason="a different reason"))

    def test_a_failure_in_the_unit_of_work_undoes_the_supersession(self) -> None:
        self.append(state_submission(1, self.v0), state_submission(2, self.v0, payload={"v": 2}))
        with self.assertRaises(Boom), self.uow() as u:
            u.evidence.supersede(supersession(1, eid(1), eid(2)))
            raise Boom
        for table in ("evidence_supersessions", "evidence_validity_transitions", "audit_events"):
            self.assertEqual(self.count(table), 0, table)


class TestDeferredStateForeignKey(EvidenceCase):
    """C-59: evidence about a trusted state commits only together with that state, or after it."""

    def setUp(self) -> None:
        super().setUp()
        self.new_state = baseline(state_id=uid(0x77), lineage_id=uid(0xCC))

    def test_evidence_written_before_its_state_commits_with_it(self) -> None:
        with self.uow() as u:
            u.evidence.append(state_submission(1, self.new_state))
            u.trusted_states.save_baseline(self.new_state)
        self.assertEqual(self.count("evidence_events", "state_id = ?", (uid(0x77),)), 1)
        self.assertEqual(self.count("trusted_states", "state_id = ?", (uid(0x77),)), 1)

    def test_evidence_written_after_its_state_commits_with_it(self) -> None:
        with self.uow() as u:
            u.trusted_states.save_baseline(self.new_state)
            u.evidence.append(state_submission(1, self.new_state))
        self.assertEqual(self.count("evidence_events", "state_id = ?", (uid(0x77),)), 1)

    def test_evidence_about_a_state_that_never_commits_cannot_persist(self) -> None:
        artifacts = self.count("evidence_artifacts")
        with self.assertRaises(PersistenceError) as caught, self.uow() as u:
            u.evidence.append(state_submission(1, self.new_state))
        self.assertIn("commit failed", str(caught.exception))
        self.assertEqual(self.count("evidence_events"), 0)
        self.assertEqual(self.count("evidence_artifacts"), artifacts)

    def test_evidence_and_its_state_are_rolled_back_together(self) -> None:
        with self.assertRaises(Boom), self.uow() as u:
            u.evidence.append(state_submission(1, self.new_state))
            u.trusted_states.save_baseline(self.new_state)
            raise Boom
        self.assertEqual(self.count("evidence_events"), 0)
        self.assertEqual(self.count("trusted_states", "state_id = ?", (uid(0x77),)), 0)

    def test_evidence_for_a_missing_candidate_is_refused_at_once(self) -> None:
        ghost = SimpleNamespace(
            candidate_id=uid(0xABCD),
            parent_state_id=self.v0.state_id,
            state_hash=self.c1.state_hash,
        )
        with self.uow() as u, self.assertRaises(PersistenceError):
            u.evidence.append(candidate_submission(1, ghost))
        self.assertEqual(self.count("evidence_events"), 0)


class TestPortShape(unittest.TestCase):
    def test_the_adapter_repositories_have_no_mutation_shortcut(self) -> None:
        forbidden = {"update", "set", "delete", "remove", "upsert", "save", "replace"}
        for cls in (sqlite_module._Evidence, sqlite_module._Audit):
            names = {n for n in vars(cls) if not n.startswith("_")}
            self.assertEqual(names & forbidden, set(), cls.__name__)

    def test_no_port_method_accepts_a_read_result_as_authority(self) -> None:
        """Nothing takes an EvidenceEvent, ValidityTransition or ProofCheck as an argument."""
        read_results = {"EvidenceEvent", "ValidityTransition", "ProofCheck", "AuditEvent"}
        for port in (repositories.EvidenceRepository, repositories.AuditRepository):
            for name, member in vars(port).items():
                if name.startswith("_") or not callable(member):
                    continue
                annotations = getattr(member, "__annotations__", {})
                for arg, annotation in annotations.items():
                    if arg == "return":
                        continue
                    with self.subTest(port=port.__name__, method=name, arg=arg):
                        self.assertNotIn(str(annotation).split(".")[-1].strip("'\""), read_results)

    def test_the_unit_of_work_exposes_evidence_and_audit(self) -> None:
        for name in ("evidence", "audit"):
            self.assertTrue(hasattr(SqliteUnitOfWork, name))
        unopened = SqliteUnitOfWork(Path("nowhere.db"))
        for name in ("evidence", "audit"):
            with self.assertRaises(PersistenceError):
                getattr(unopened, name)


if __name__ == "__main__":
    unittest.main()
