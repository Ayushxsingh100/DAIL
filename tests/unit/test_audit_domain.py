"""Audit events (Doc 11 §12, §13, §28, §38; Doc 06 §28; C-57).

Expected values come from the specification text quoted in the P2-fix prompt: the Doc 11 §12 event
list, the Doc 06 §28 minimum fields and the §4.6 table of required payload keys.
"""

from __future__ import annotations

import dataclasses
import unittest
from typing import Any

from core.domain.audit import (
    REQUIRED_COLUMNS,
    REQUIRED_PAYLOAD_KEYS,
    ActorType,
    AuditEvent,
    AuditEventType,
    AuditSubmission,
    validity_event_id,
)
from core.domain.errors import DomainValidationError
from core.domain.evidence import ArtifactRef
from tests.domain_builders import at, uid

T = AuditEventType
CORR, OP = uid(11), uid(12)

DOC_11_SECTION_12 = {
    "STATE_CREATED",
    "CANDIDATE_CREATED",
    "LLM_REQUESTED",
    "LLM_COMPLETED",
    "PATCH_VALIDATED",
    "IDENTITY_COMPLETED",
    "DEPENDENCY_COMPLETED",
    "IMPACT_COMPLETED",
    "VERIFICATION_COMPLETED",
    "PROMOTION_REQUESTED",
    "STATE_PROMOTED",
    "CANDIDATE_REJECTED",
    "RETRY_SCHEDULED",
    "ESCALATED",
    "ERROR_OCCURRED",
}
DOC_06_SECTION_28_ADDITIONS = {"INVARIANT_AFFECTED", "PROMOTION_DECIDED", "PROMOTION_FAILED"}

# The P2-fix prompt §4.6 table, written out: (columns, payload keys).
SECTION_4_6: dict[str, tuple[set[str], set[str]]] = {
    "STATE_CREATED": (
        {"state_id"},
        {"lineage_id", "version", "parent_state_id", "state_hash"},
    ),
    "CANDIDATE_CREATED": ({"candidate_id"}, {"parent_state_id", "patch_id", "source"}),
    "INVARIANT_AFFECTED": (
        {"state_id", "candidate_id"},
        {"invariant_id", "invariant_version", "reason"},
    ),
    "VERIFICATION_COMPLETED": (
        set(),
        {"verification_id", "target", "result", "verifier_id", "verifier_version"},
    ),
    "PROMOTION_DECIDED": (
        {"decision_id", "candidate_id"},
        {"parent_state_id", "decision", "policy_version"},
    ),
    "STATE_PROMOTED": ({"state_id", "decision_id"}, {"parent_state_id"}),
    "PROMOTION_FAILED": ({"candidate_id"}, {"parent_state_id", "reason"}),
    "RETRY_SCHEDULED": (set(), {"attempt_id", "parent_state_id", "reason"}),
    "ESCALATED": (set(), {"reason", "unresolved_conditions"}),
    "EVIDENCE_VALIDITY_CHANGED": (
        set(),
        {
            "evidence_id",
            "scope",
            "context_kind",
            "context_id",
            "from_validity",
            "to_validity",
            "reason",
            "impact_ref",
            "superseded_by",
        },
    ),
}

COLUMN_VALUES = {"state_id": uid(100), "candidate_id": uid(200), "decision_id": uid(300)}

# A complete payload for every type that has required keys.
PAYLOADS: dict[str, dict[str, Any]] = {
    "STATE_CREATED": {
        "lineage_id": uid(9),
        "version": 1,
        "parent_state_id": uid(100),
        "state_hash": "ab" * 32,
    },
    "CANDIDATE_CREATED": {"parent_state_id": uid(100), "patch_id": uid(400), "source": "LLM"},
    "INVARIANT_AFFECTED": {
        "invariant_id": "INV-SEC-001",
        "invariant_version": 1,
        "reason": "ssh rule changed",
    },
    "VERIFICATION_COMPLETED": {
        "verification_id": uid(500),
        "target": "candidate",
        "result": "PASS",
        "verifier_id": "ssh-open",
        "verifier_version": "1",
    },
    "PROMOTION_DECIDED": {
        "parent_state_id": uid(100),
        "decision": "PROMOTE",
        "policy_version": "1",
    },
    "STATE_PROMOTED": {"parent_state_id": uid(100)},
    "PROMOTION_FAILED": {"parent_state_id": uid(100), "reason": "stale parent"},
    "RETRY_SCHEDULED": {"attempt_id": uid(600), "parent_state_id": uid(100), "reason": "failed"},
    "ESCALATED": {
        "reason": "no safe patch",
        "unresolved_conditions": ["INV-FUNC-001"],
        "attempt_id": uid(600),
    },
    "EVIDENCE_VALIDITY_CHANGED": {
        "evidence_id": uid(1),
        "scope": "CONTEXT",
        "context_kind": "CANDIDATE",
        "context_id": uid(200),
        "from_validity": "UNCERTAIN",
        "to_validity": "INVALID",
        "reason": "affected",
        "impact_ref": uid(7),
        "superseded_by": None,
    },
}


def submit(event_type: AuditEventType, payload: Any = None, **overrides: Any) -> AuditSubmission:
    """A valid submission of ``event_type``: every required column and key present."""
    columns = {name: COLUMN_VALUES[name] for name in REQUIRED_COLUMNS.get(event_type, ())}
    fields: dict[str, Any] = {
        "event_id": uid(1),
        "event_type": event_type,
        "correlation_id": CORR,
        "operation_id": OP,
        "timestamp": at(5),
        "payload": PAYLOADS.get(event_type.value, {}) if payload is None else payload,
        **columns,
    }
    fields.update(overrides)
    return AuditSubmission.create(**fields)


class TestEnums(unittest.TestCase):
    def test_the_event_types_are_exactly_the_nineteen_of_c_57(self) -> None:
        expected = DOC_11_SECTION_12 | DOC_06_SECTION_28_ADDITIONS | {"EVIDENCE_VALIDITY_CHANGED"}
        self.assertEqual({t.value for t in T}, expected)
        self.assertEqual(len(T), 19)

    def test_the_retired_names_are_gone(self) -> None:
        names = {t.name for t in T}
        for retired in ("RETRY_REQUESTED", "EVIDENCE_INVALIDATED", "EVIDENCE_SUPERSEDED"):
            self.assertNotIn(retired, names)

    def test_actor_types_are_doc_11_section_13(self) -> None:
        self.assertEqual({a.value for a in ActorType}, {"SYSTEM", "USER", "AUTOMATION", "PROVIDER"})


class TestRequiredFields(unittest.TestCase):
    def test_required_payload_keys_match_the_table(self) -> None:
        self.assertEqual(
            {t.value: set(keys) for t, keys in REQUIRED_PAYLOAD_KEYS.items()},
            {name: keys for name, (_cols, keys) in SECTION_4_6.items()},
        )

    def test_required_columns_match_the_table(self) -> None:
        self.assertEqual(
            {t.value: set(cols) for t, cols in REQUIRED_COLUMNS.items()},
            {name: cols for name, (cols, _keys) in SECTION_4_6.items() if cols},
        )

    def test_a_complete_event_of_every_type_is_accepted(self) -> None:
        for event_type in T:
            with self.subTest(type=event_type.value):
                sub = submit(event_type)
                self.assertEqual(sub.event_type, event_type)

    def test_each_missing_payload_key_is_refused(self) -> None:
        for name, (_cols, keys) in SECTION_4_6.items():
            if name == "ESCALATED":
                continue  # the candidate/attempt alternative is tested below
            for key in sorted(keys):
                payload = {k: v for k, v in PAYLOADS[name].items() if k != key}
                with self.subTest(type=name, missing=key), self.assertRaises(DomainValidationError):
                    submit(T(name), payload)

    def test_escalated_missing_keys_are_refused(self) -> None:
        for key in ("reason", "unresolved_conditions"):
            payload = {k: v for k, v in PAYLOADS["ESCALATED"].items() if k != key}
            with self.subTest(missing=key), self.assertRaises(DomainValidationError):
                submit(T.ESCALATED, payload, candidate_id=uid(200))

    def test_each_missing_column_is_refused(self) -> None:
        for name, (cols, _keys) in SECTION_4_6.items():
            for column in sorted(cols):
                with (
                    self.subTest(type=name, missing=column),
                    self.assertRaises(DomainValidationError),
                ):
                    submit(T(name), **{column: None})

    def test_a_null_is_refused_where_none_is_allowed(self) -> None:
        nullable = {
            "STATE_CREATED": {"parent_state_id"},
            "EVIDENCE_VALIDITY_CHANGED": {
                "context_kind",
                "context_id",
                "impact_ref",
                "superseded_by",
            },
        }
        for name, (_cols, keys) in SECTION_4_6.items():
            if name == "ESCALATED":
                continue
            for key in sorted(keys - nullable.get(name, set())):
                payload = {**PAYLOADS[name], key: None}
                with self.subTest(type=name, null=key), self.assertRaises(DomainValidationError):
                    submit(T(name), payload)

    def test_state_created_parent_is_null_only_for_version_zero(self) -> None:
        base = PAYLOADS["STATE_CREATED"]
        submit(T.STATE_CREATED, {**base, "version": 0, "parent_state_id": None})
        with self.assertRaises(DomainValidationError):
            submit(T.STATE_CREATED, {**base, "version": 1, "parent_state_id": None})
        with self.assertRaises(DomainValidationError):
            submit(T.STATE_CREATED, {**base, "version": 0, "parent_state_id": uid(100)})
        with self.assertRaises(DomainValidationError):
            submit(T.STATE_CREATED, {**base, "version": -1})

    def test_escalated_needs_the_candidate_column_or_the_attempt_key(self) -> None:
        base = {k: v for k, v in PAYLOADS["ESCALATED"].items() if k != "attempt_id"}
        submit(T.ESCALATED, base, candidate_id=uid(200))
        submit(T.ESCALATED, {**base, "attempt_id": uid(600)})
        with self.assertRaises(DomainValidationError):
            submit(T.ESCALATED, base)
        with self.assertRaises(DomainValidationError):
            submit(T.ESCALATED, {**base, "attempt_id": None})

    def test_the_other_types_need_only_a_json_object(self) -> None:
        for event_type in T:
            if event_type.value in SECTION_4_6:
                continue
            with self.subTest(type=event_type.value):
                submit(event_type, {})
                submit(event_type, {"anything": [1, {"x": None}]})
                for bad in ([], "text", 7, None):
                    if bad is None:
                        continue  # None means "use the default" in the helper
                    with self.assertRaises(DomainValidationError):
                        submit(event_type, bad)


class TestSubmission(unittest.TestCase):
    def test_the_payload_is_stored_content_addressed_under_audit(self) -> None:
        sub = submit(T.LLM_REQUESTED, {"b": 1, "a": 2})
        self.assertEqual(sub.payload_json, '{"a":2,"b":1}')
        self.assertEqual(sub.payload_ref, ArtifactRef("audit", sub.payload_hash).uri)
        self.assertTrue(sub.payload_ref.startswith("evidence://audit/"))

    def test_the_hash_is_stable_under_key_reordering(self) -> None:
        a = submit(T.LLM_REQUESTED, {"a": 1, "b": 2})
        b = submit(T.LLM_REQUESTED, {"b": 2, "a": 1})
        self.assertEqual(a.payload_hash, b.payload_hash)

    def test_floats_and_secrets_are_refused(self) -> None:
        for payload in ({"x": 1.5}, {"password": "hunter2"}, {"n": {"api_key": "k"}}):
            with self.subTest(payload=payload), self.assertRaises(DomainValidationError):
                submit(T.LLM_REQUESTED, payload)

    def test_a_hand_built_submission_is_checked_too(self) -> None:
        good = submit(T.LLM_REQUESTED, {"a": 1})
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(good, payload_json='{"a":2}')  # does not hash to payload_hash
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(good, payload_ref="evidence://verification/" + good.payload_hash)
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(good, payload_ref="cas:" + good.payload_hash)

    def test_ids_are_canonical_uuids_and_the_version_is_positive(self) -> None:
        for field in ("event_id", "correlation_id", "operation_id"):
            with self.subTest(field=field), self.assertRaises(DomainValidationError):
                submit(T.LLM_REQUESTED, {}, **{field: "evt-0123456789abcdef"})
        with self.assertRaises(DomainValidationError):
            submit(T.LLM_REQUESTED, {}, state_id="state-1")
        with self.assertRaises(DomainValidationError):
            submit(T.LLM_REQUESTED, {}, event_version=0)

    def test_the_timestamp_is_utc(self) -> None:
        from datetime import datetime

        with self.assertRaises(DomainValidationError):
            submit(T.LLM_REQUESTED, {}, timestamp=datetime(2026, 10, 1))


class TestStoredEventAndIdentity(unittest.TestCase):
    def row(self, sub: AuditSubmission, sequence: int = 1) -> dict[str, Any]:
        return {
            "sequence": sequence,
            "event_id": sub.event_id,
            "event_type": sub.event_type.value,
            "event_version": sub.event_version,
            "correlation_id": sub.correlation_id,
            "operation_id": sub.operation_id,
            "actor_type": sub.actor_type.value,
            "actor_id": sub.actor_id,
            "state_id": sub.state_id,
            "candidate_id": sub.candidate_id,
            "decision_id": sub.decision_id,
            "timestamp": sub.timestamp.isoformat(),
            "payload_hash": sub.payload_hash,
            "payload_ref": sub.payload_ref,
        }

    def test_a_stored_event_round_trips(self) -> None:
        sub = submit(T.CANDIDATE_CREATED)
        event = AuditEvent.from_row(self.row(sub, sequence=7))
        self.assertEqual(event.sequence, 7)
        self.assertEqual(event.event_type, T.CANDIDATE_CREATED)
        self.assertEqual(AuditEvent.from_row(event.to_dict()), event)

    def test_a_stored_row_is_revalidated(self) -> None:
        sub = submit(T.LLM_REQUESTED, {})
        for column, bad in (
            ("event_id", "evt-1"),
            ("event_type", "RETRY_REQUESTED"),
            ("actor_type", "ROBOT"),
            ("payload_ref", "cas:" + sub.payload_hash),
            ("sequence", 0),
            ("timestamp", "yesterday"),
        ):
            with self.subTest(column=column), self.assertRaises(DomainValidationError):
                AuditEvent.from_row({**self.row(sub), column: bad})

    def test_same_content_ignores_only_sequence_and_timestamp(self) -> None:
        sub = submit(T.CANDIDATE_CREATED)
        event = AuditEvent.from_row(self.row(sub, sequence=3))
        self.assertTrue(event.same_content_as(submit(T.CANDIDATE_CREATED, timestamp=at(50))))
        for change in (
            {"candidate_id": uid(201)},
            {"correlation_id": uid(13)},
            {"actor_type": ActorType.USER},
            {"event_version": 2},
            {"payload": {**PAYLOADS["CANDIDATE_CREATED"], "source": "FIXED_PATCH"}},
        ):
            with self.subTest(change=list(change)):
                self.assertFalse(event.same_content_as(submit(T.CANDIDATE_CREATED, **change)))


class TestValidityEventId(unittest.TestCase):
    def test_it_is_a_deterministic_canonical_uuid(self) -> None:
        first = validity_event_id(uid(5001))
        self.assertEqual(first, validity_event_id(uid(5001)))
        self.assertNotEqual(first, validity_event_id(uid(5002)))
        self.assertNotEqual(first, uid(5001))
        AuditSubmission.create(
            event_id=first,
            event_type=T.LLM_REQUESTED,
            correlation_id=CORR,
            operation_id=OP,
            timestamp=at(1),
            payload={},
        )

    def test_the_transition_id_must_be_a_uuid(self) -> None:
        with self.assertRaises(DomainValidationError):
            validity_event_id("vt-1")


if __name__ == "__main__":
    unittest.main()
