"""The evidence domain model (Doc 05 §16; Doc 11 §5-§9, §16, §17, §28, §32, §33, §45; C-51 to C-56).

Expected values come from the specification text quoted in the P2-fix prompt, not from the
implementation. The 5x5 transition matrices follow C-52.
"""

from __future__ import annotations

import dataclasses
import hashlib
import unittest
from datetime import UTC, datetime
from typing import Any

from core.domain import hashing
from core.domain.audit import REQUIRED_PAYLOAD_KEYS, AuditEventType
from core.domain.errors import DomainValidationError, HashMismatchError, IllegalTransitionError
from core.domain.evidence import (
    CANDIDATE_BOUND_KINDS,
    PROOF_KINDS,
    ArtifactRef,
    ContextKind,
    EvidenceContext,
    EvidenceEvent,
    EvidenceKind,
    EvidenceSubmission,
    EvidenceValidity,
    IntegrityStatus,
    ProofCheck,
    SupersessionRequest,
    TransitionRequest,
    TransitionScope,
    ValidityTransition,
    check_supersession,
    check_transition,
    effective_validity,
    evaluate_proof,
    primary_validity,
    validity_changed_payload,
)
from core.domain.redaction import Redactor
from tests.domain_builders import at, provenance, uid

V = EvidenceValidity
K = EvidenceKind
CONTEXT, RECORD = TransitionScope.CONTEXT, TransitionScope.RECORD

RUN, CORR, OP, ATT = uid(10), uid(11), uid(12), uid(13)
STATE, OTHER_STATE = uid(100), uid(101)
CAND, OTHER_CAND = uid(200), uid(201)
HASH = "ab" * 32
OTHER_HASH = "cd" * 32


def prov(algorithm_version: str | None = "verifier-1") -> Any:
    return dataclasses.replace(provenance(), algorithm_version=algorithm_version)


def submit(**overrides: Any) -> EvidenceSubmission:
    """A valid VERIFICATION record bound to ``STATE`` unless overridden."""
    fields: dict[str, Any] = {
        "payload": {"result": "PASS"},
        "evidence_id": uid(1),
        "run_id": RUN,
        "attempt_id": None,
        "correlation_id": CORR,
        "operation_id": OP,
        "kind": K.VERIFICATION,
        "event_name": "verification_completed",
        "provenance": prov(),
        "created_at": at(5),
        "state_id": STATE,
        "state_hash": HASH,
    }
    fields.update(overrides)
    return EvidenceSubmission.create(**fields)


def event(**overrides: Any) -> EvidenceEvent:
    return submit(**overrides).event


def candidate_event(**overrides: Any) -> EvidenceEvent:
    """Evidence bound to ``CAND`` (with its attempt and parent, B1)."""
    fields: dict[str, Any] = {
        "state_id": None,
        "state_hash": None,
        "candidate_id": CAND,
        "attempt_id": ATT,
        "parent_state_id": STATE,
    }
    fields.update(overrides)
    return event(**fields)


def transition(
    ev: EvidenceEvent,
    seq: int,
    *,
    scope: TransitionScope = CONTEXT,
    context: EvidenceContext | None = None,
    to: EvidenceValidity = V.INVALID,
    frm: EvidenceValidity = V.VALID,
    reason: str = "because",
    impact_ref: str | None = None,
    superseded_by: str | None = None,
) -> ValidityTransition:
    return ValidityTransition(
        seq=seq,
        transition_id=uid(5000 + seq),
        evidence_id=ev.evidence_id,
        scope=scope,
        context=context,
        from_validity=frm,
        to_validity=to,
        reason=reason,
        impact_ref=impact_ref,
        superseded_by=superseded_by,
        correlation_id=CORR,
        operation_id=OP,
        created_at=at(6),
    )


def request(
    ev: EvidenceEvent,
    to: EvidenceValidity,
    *,
    scope: TransitionScope = CONTEXT,
    context: EvidenceContext | None = None,
    reason: str = "because",
    impact_ref: str | None = None,
) -> TransitionRequest:
    return TransitionRequest(
        transition_id=uid(9000),
        evidence_id=ev.evidence_id,
        scope=scope,
        context=context,
        to_validity=to,
        reason=reason,
        impact_ref=impact_ref,
        correlation_id=CORR,
        operation_id=OP,
        created_at=at(7),
    )


class TestTaxonomy(unittest.TestCase):
    def test_the_kinds_are_exactly_doc_11_section_5(self) -> None:
        self.assertEqual(
            {kind.value for kind in K},
            {
                "STATE",
                "CONFIGURATION",
                "IDENTITY",
                "DEPENDENCY",
                "IMPACT",
                "VERIFICATION",
                "LLM",
                "PROMOTION",
                "ERROR",
                "EXPERIMENT",
            },
        )

    def test_the_old_and_foreign_kinds_are_gone(self) -> None:
        names = {kind.name for kind in K}
        for retired in ("ORACLE", "CANDIDATE", "PATCH", "INPUT", "NORMALIZATION", "DECISION"):
            self.assertNotIn(retired, names)

    def test_proof_kinds_are_the_seven_that_describe_the_system(self) -> None:
        self.assertEqual(
            PROOF_KINDS,
            {
                K.STATE,
                K.CONFIGURATION,
                K.IDENTITY,
                K.DEPENDENCY,
                K.IMPACT,
                K.VERIFICATION,
                K.PROMOTION,
            },
        )
        for never in (K.LLM, K.ERROR, K.EXPERIMENT):
            self.assertNotIn(never, PROOF_KINDS)

    def test_impact_and_promotion_are_the_candidate_bound_kinds(self) -> None:
        self.assertEqual(CANDIDATE_BOUND_KINDS, {K.IMPACT, K.PROMOTION})

    def test_validity_values_are_doc_11_section_7(self) -> None:
        self.assertEqual(
            {v.value for v in V}, {"VALID", "INVALID", "UNCERTAIN", "SUPERSEDED", "REDACTED"}
        )


class TestRecordRules(unittest.TestCase):
    """B1 to B7 (C-51, C-55), each with a positive and a negative case."""

    def test_b1_a_candidate_binding_needs_attempt_and_parent(self) -> None:
        self.assertEqual(candidate_event().candidate_id, CAND)
        with self.assertRaises(DomainValidationError):
            candidate_event(attempt_id=None)
        with self.assertRaises(DomainValidationError):
            candidate_event(parent_state_id=None)

    def test_b1_baseline_evidence_has_no_attempt(self) -> None:
        self.assertIsNone(event().attempt_id)  # C-55: null only when candidate_id is null

    def test_b2_state_only_evidence_records_the_state_hash(self) -> None:
        self.assertEqual(event().state_hash, HASH)
        with self.assertRaises(DomainValidationError):
            event(state_hash=None)

    def test_b2_does_not_apply_when_a_candidate_is_set(self) -> None:
        both = candidate_event(state_id=STATE)  # state and candidate, no hash
        self.assertIsNone(both.state_hash)
        self.assertEqual(len(both.contexts), 2)

    def test_b3_unbound_evidence_has_no_state_hash_and_no_parent(self) -> None:
        unbound = event(state_id=None, state_hash=None)
        self.assertFalse(unbound.is_bound)
        with self.assertRaises(DomainValidationError):
            event(state_id=None, state_hash=HASH)
        with self.assertRaises(DomainValidationError):
            event(state_id=None, state_hash=None, parent_state_id=STATE)

    def test_b4_impact_and_promotion_bind_to_a_candidate(self) -> None:
        for kind in (K.IMPACT, K.PROMOTION):
            with self.subTest(kind=kind):
                self.assertEqual(candidate_event(kind=kind).kind, kind)
                with self.assertRaises(DomainValidationError):
                    event(kind=kind)  # state-bound only
                with self.assertRaises(DomainValidationError):
                    event(kind=kind, state_id=None, state_hash=None)  # unbound

    def test_b4_other_kinds_may_be_state_bound(self) -> None:
        for kind in (K.STATE, K.CONFIGURATION, K.VERIFICATION, K.LLM, K.ERROR, K.EXPERIMENT):
            with self.subTest(kind=kind):
                self.assertEqual(event(kind=kind).kind, kind)

    def test_b5_payload_ref_is_the_kind_and_the_hash(self) -> None:
        ev = event()
        self.assertEqual(ev.payload_ref, f"evidence://verification/{ev.content_hash}")
        for bad in (
            f"evidence://impact/{ev.content_hash}",  # wrong type
            f"evidence://verification/{OTHER_HASH}",  # wrong hash
            f"cas:{ev.content_hash}",  # the retired reference form
            f"ext:{ev.content_hash}",
        ):
            with self.subTest(ref=bad), self.assertRaises(DomainValidationError):
                dataclasses.replace(ev, payload_ref=bad)

    def test_b6_provenance_carries_an_algorithm_version(self) -> None:
        self.assertEqual(event().provenance.algorithm_version, "verifier-1")
        with self.assertRaises(DomainValidationError):
            event(provenance=prov(algorithm_version=None))

    def test_b7_every_id_is_a_canonical_uuid(self) -> None:
        ev = event()
        bad_values = ("evd-0123456789abcdef", str(uid(0xABCDEF)).upper(), "", "not-a-uuid", 7)
        for field in ("evidence_id", "run_id", "correlation_id", "operation_id", "state_id"):
            for bad in bad_values:
                with self.subTest(field=field, value=bad), self.assertRaises(DomainValidationError):
                    dataclasses.replace(ev, **{field: bad})
        cand = candidate_event()
        for field in ("attempt_id", "candidate_id", "parent_state_id"):
            with self.subTest(field=field), self.assertRaises(DomainValidationError):
                dataclasses.replace(cand, **{field: "corr-0123456789abcdef"})

    def test_the_creation_validity_is_valid_or_uncertain(self) -> None:
        self.assertEqual(event(validity=V.UNCERTAIN).validity, V.UNCERTAIN)
        for bad in (V.INVALID, V.SUPERSEDED, V.REDACTED):
            with self.subTest(validity=bad), self.assertRaises(DomainValidationError):
                event(validity=bad)

    def test_the_hash_algorithm_is_sha256(self) -> None:
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(event(), hash_algorithm="md5")

    def test_timestamps_are_utc(self) -> None:
        with self.assertRaises(DomainValidationError):
            event(created_at=datetime(2026, 10, 1, 9, 0))
        self.assertEqual(event(created_at=at(5)).created_at.tzinfo, UTC)

    def test_the_event_name_is_required(self) -> None:
        with self.assertRaises(DomainValidationError):
            event(event_name="")

    def test_contexts_and_the_primary_context(self) -> None:
        self.assertEqual(event().contexts, (EvidenceContext.state(STATE),))
        self.assertEqual(candidate_event().primary_context, EvidenceContext.candidate(CAND))
        both = candidate_event(state_id=STATE)
        self.assertEqual(
            both.contexts, (EvidenceContext.state(STATE), EvidenceContext.candidate(CAND))
        )
        self.assertEqual(both.primary_context, EvidenceContext.candidate(CAND))  # candidate first
        self.assertIsNone(event(state_id=None, state_hash=None).primary_context)

    def test_the_record_round_trips_through_to_dict_and_from_dict(self) -> None:
        for ev in (event(), candidate_event(kind=K.IMPACT), event(validity=V.UNCERTAIN)):
            with self.subTest(kind=ev.kind):
                self.assertEqual(EvidenceEvent.from_dict(ev.to_dict()), ev)

    def test_from_dict_rejects_a_missing_or_an_unexpected_key(self) -> None:
        data = event().to_dict()
        with self.assertRaises(DomainValidationError):
            EvidenceEvent.from_dict({k: v for k, v in data.items() if k != "run_id"})
        with self.assertRaises(DomainValidationError):
            EvidenceEvent.from_dict({**data, "extra": 1})

    def test_from_dict_revalidates_the_rules(self) -> None:
        data = event().to_dict()
        data["payload_ref"] = "cas:" + data["content_hash"]
        with self.assertRaises(DomainValidationError):
            EvidenceEvent.from_dict(data)

    def test_same_content_ignores_only_the_creation_time(self) -> None:
        a = event(created_at=at(5))
        self.assertTrue(a.same_content_as(event(created_at=at(50))))
        self.assertFalse(a.same_content_as(event(state_hash=OTHER_HASH)))
        self.assertFalse(a.same_content_as(event(event_name="other")))


class TestArtifactRef(unittest.TestCase):
    """Doc 11 §17: ``artifact_ref = evidence://<type>/<content_hash>``."""

    def test_round_trip_for_every_kind_and_for_audit(self) -> None:
        for kind in [k.value.lower() for k in K] + ["audit"]:
            ref = ArtifactRef(kind, HASH)
            with self.subTest(type=kind):
                self.assertEqual(ref.uri, f"evidence://{kind}/{HASH}")
                self.assertEqual(ArtifactRef.parse(ref.uri), ref)

    def test_parse_rejects_everything_but_the_exact_form(self) -> None:
        for bad in (
            f"EVIDENCE://verification/{HASH}",  # scheme case
            f"evidence://Verification/{HASH}",  # type case
            f"evidence://verification/{HASH.upper()}",  # hash case
            f" evidence://verification/{HASH}",  # padding
            f"evidence://verification/{HASH} ",
            f"evidence://verification/{HASH}\n",
            f"evidence://verification/{HASH}/extra",  # an extra path segment
            f"evidence://verification/{HASH}/",
            f"evidence://verification//{HASH}",
            f"evidence:///{HASH}",
            f"evidence://verification/{HASH[:-1]}",  # short hash
            f"evidence://verification/{HASH}0",  # long hash
            f"evidence://verification/{'g' * 64}",  # not hex
            f"https://verification/{HASH}",  # another scheme
            f"cas:{HASH}",  # retired
            f"ext:{HASH}",  # retired
            f"evidence://oracle/{HASH}",  # not a kind (ADR-010)
            f"evidence://candidate/{HASH}",
            f"evidence://patch/{HASH}",
            f"evidence://9state/{HASH}",
            "",
            "evidence://",
            None,
            7,
        ):
            with self.subTest(uri=bad), self.assertRaises(DomainValidationError):
                ArtifactRef.parse(bad)

    def test_the_constructor_applies_the_same_rules(self) -> None:
        for kind, digest in (("Verification", HASH), ("oracle", HASH), ("audit", HASH.upper())):
            with self.subTest(type=kind), self.assertRaises(DomainValidationError):
                ArtifactRef(kind, digest)


class TestSubmission(unittest.TestCase):
    def test_floats_are_refused(self) -> None:
        for payload in ({"score": 0.5}, {"a": [1, {"b": 2.0}]}, [1.5]):
            with self.subTest(payload=payload), self.assertRaises(DomainValidationError):
                submit(payload=payload)

    def test_a_secret_is_refused_with_a_reference_to_doc_11_section_28(self) -> None:
        aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"  # built at runtime: no secret-shaped literal
        for payload in (
            {"config": {"password": "hunter2"}},
            {"note": f"key is {aws_key}"},
            {"api_key": "k"},
            {"nested": [{"token": "t"}]},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(DomainValidationError) as caught:
                    submit(payload=payload)
                self.assertIn("§28", str(caught.exception))

    def test_a_redacted_payload_is_accepted(self) -> None:
        redacted = Redactor().redact({"config": {"password": "hunter2"}}).payload
        self.assertEqual(submit(payload=redacted).event.kind, K.VERIFICATION)

    def test_the_hash_is_stable_under_key_reordering(self) -> None:
        a = submit(payload={"a": 1, "b": {"x": [1, 2], "y": "z"}})
        b = submit(payload={"b": {"y": "z", "x": [1, 2]}, "a": 1})
        self.assertEqual(a.event.content_hash, b.event.content_hash)
        self.assertEqual(a.payload_json, b.payload_json)

    def test_the_hash_changes_whenever_the_payload_changes(self) -> None:
        self.assertNotEqual(
            submit(payload={"result": "PASS"}).event.content_hash,
            submit(payload={"result": "FAIL"}).event.content_hash,
        )

    def test_the_hash_is_sha256_of_the_canonical_serialization(self) -> None:
        sub = submit(payload={"b": 1, "a": "é"})
        self.assertEqual(sub.payload_json, '{"a":"\\u00e9","b":1}')
        self.assertEqual(
            sub.event.content_hash, hashlib.sha256(sub.payload_json.encode("utf-8")).hexdigest()
        )
        self.assertEqual(sub.event.hash_algorithm, "sha256")

    def test_the_redacted_payload_hashes_differently_from_the_raw_one(self) -> None:
        raw = {"config": {"password": "hunter2", "engine": "postgres"}}
        redacted = Redactor().redact(raw).payload
        self.assertNotEqual(hashing.content_hash(raw), submit(payload=redacted).event.content_hash)

    def test_a_hand_built_submission_is_checked_too(self) -> None:
        good = submit(payload={"result": "PASS"})
        with self.assertRaises(HashMismatchError):
            EvidenceSubmission(event=good.event, payload_json='{"result":"FAIL"}')
        with self.assertRaises(DomainValidationError):  # valid JSON, not the canonical text
            EvidenceSubmission(event=good.event, payload_json='{"result": "PASS"}')
        with self.assertRaises(DomainValidationError):
            EvidenceSubmission(event=good.event, payload_json="{not json")
        with self.assertRaises(DomainValidationError):
            EvidenceSubmission(event=good.event, payload_json='{"result":1.5}')

    def test_a_hand_built_submission_with_a_secret_is_refused(self) -> None:
        text = hashing.canonical_json({"password": "hunter2"})
        digest = hashing.content_hash({"password": "hunter2"})
        ev = dataclasses.replace(
            event(), content_hash=digest, payload_ref=ArtifactRef("verification", digest).uri
        )
        with self.assertRaises(DomainValidationError) as caught:
            EvidenceSubmission(event=ev, payload_json=text)
        self.assertIn("§28", str(caught.exception))

    def test_the_event_must_be_an_evidence_event(self) -> None:
        with self.assertRaises(DomainValidationError):
            EvidenceSubmission(event=event().to_dict(), payload_json="{}")  # type: ignore[arg-type]

    def test_the_kind_must_be_an_evidence_kind(self) -> None:
        with self.assertRaises(DomainValidationError):
            submit(kind="ORACLE")


class TestEffectiveValidity(unittest.TestCase):
    """C-52 R1 to R4."""

    def setUp(self) -> None:
        self.ev = event()  # produced for STATE, created VALID
        self.state = EvidenceContext.state(STATE)
        self.cand = EvidenceContext.candidate(CAND)

    def invalid_for_candidate(self, seq: int = 1) -> ValidityTransition:
        return transition(self.ev, seq, context=self.cand, to=V.INVALID, impact_ref=uid(77))

    def test_r3_an_own_context_has_the_creation_validity(self) -> None:
        self.assertIs(effective_validity(self.ev, self.state, []), V.VALID)
        self.assertIs(effective_validity(event(validity=V.UNCERTAIN), self.state, []), V.UNCERTAIN)

    def test_r4_a_foreign_context_is_uncertain_never_valid(self) -> None:
        for foreign in (
            EvidenceContext.state(OTHER_STATE),
            self.cand,
            EvidenceContext.candidate(OTHER_CAND),
        ):
            with self.subTest(context=foreign):
                self.assertIs(effective_validity(self.ev, foreign, []), V.UNCERTAIN)

    def test_r4_a_foreign_context_is_not_valid_even_if_the_record_is_valid_for_its_own(
        self,
    ) -> None:
        # The anti-stale-evidence rule (Doc 06 §10): v0's evidence is not proof about a candidate.
        self.assertIs(effective_validity(self.ev, self.state, []), V.VALID)
        self.assertIsNot(effective_validity(self.ev, self.cand, []), V.VALID)

    def test_r2_a_context_transition_applies_to_its_own_context_only(self) -> None:
        trs = [self.invalid_for_candidate()]
        self.assertIs(effective_validity(self.ev, self.cand, trs), V.INVALID)
        self.assertIs(effective_validity(self.ev, self.state, trs), V.VALID)  # D1 at domain level
        self.assertIs(
            effective_validity(self.ev, EvidenceContext.candidate(OTHER_CAND), trs), V.UNCERTAIN
        )

    def test_r2_the_latest_context_transition_wins(self) -> None:
        uncertain = transition(self.ev, 1, context=self.state, to=V.UNCERTAIN)
        back = transition(self.ev, 2, context=self.state, frm=V.UNCERTAIN, to=V.VALID)
        self.assertIs(effective_validity(self.ev, self.state, [uncertain]), V.UNCERTAIN)
        self.assertIs(effective_validity(self.ev, self.state, [uncertain, back]), V.VALID)
        # the order of the list does not matter; the sequence does
        self.assertIs(effective_validity(self.ev, self.state, [back, uncertain]), V.VALID)

    def test_r1_a_record_transition_overrides_every_context(self) -> None:
        record = transition(
            self.ev, 3, scope=RECORD, to=V.INVALID, reason="INTEGRITY: hash differs"
        )
        trs = [transition(self.ev, 1, context=self.state, to=V.UNCERTAIN), record]
        for context in (self.state, self.cand, EvidenceContext.state(OTHER_STATE)):
            with self.subTest(context=context):
                self.assertIs(effective_validity(self.ev, context, trs), V.INVALID)

    def test_a_superseded_record_is_superseded_everywhere(self) -> None:
        record = transition(
            self.ev, 1, scope=RECORD, to=V.SUPERSEDED, superseded_by=uid(2), reason="newer"
        )
        self.assertIs(effective_validity(self.ev, self.state, [record]), V.SUPERSEDED)
        self.assertIs(effective_validity(self.ev, self.cand, [record]), V.SUPERSEDED)

    def test_two_record_transitions_are_a_corrupt_history(self) -> None:
        first = transition(self.ev, 1, scope=RECORD, to=V.INVALID, reason="INTEGRITY: a")
        second = transition(
            self.ev, 2, scope=RECORD, to=V.SUPERSEDED, superseded_by=uid(2), reason="b"
        )
        with self.assertRaises(DomainValidationError):
            effective_validity(self.ev, self.state, [first, second])

    def test_another_records_transition_is_refused(self) -> None:
        other = event(evidence_id=uid(2))
        with self.assertRaises(DomainValidationError):
            effective_validity(self.ev, self.state, [transition(other, 1, context=self.state)])

    def test_primary_validity_follows_the_primary_context(self) -> None:
        both = candidate_event(state_id=STATE)
        trs = [transition(both, 1, context=self.cand, to=V.INVALID, impact_ref=uid(77))]
        self.assertIs(primary_validity(both, trs), V.INVALID)  # candidate is primary
        self.assertIs(primary_validity(both, []), V.VALID)
        unbound = event(state_id=None, state_hash=None, validity=V.UNCERTAIN)
        self.assertIs(primary_validity(unbound, []), V.UNCERTAIN)
        record = transition(unbound, 1, scope=RECORD, to=V.INVALID, reason="INTEGRITY: x")
        self.assertIs(primary_validity(unbound, [record]), V.INVALID)


class TestTransitionMatrix(unittest.TestCase):
    """C-52: all 5x5 (from, to) pairs, for CONTEXT scope in an own and a foreign context of each
    kind, and for RECORD scope."""

    ALL = tuple(V)
    LEGAL_CONTEXT = {
        (V.VALID, V.INVALID),
        (V.VALID, V.UNCERTAIN),
        (V.UNCERTAIN, V.INVALID),
        (V.UNCERTAIN, V.VALID),
    }

    def setUp(self) -> None:
        # One record produced for both a state and a candidate, so each kind has an own context.
        self.ev = candidate_event(state_id=STATE)
        self.own_state = EvidenceContext.state(STATE)
        self.own_cand = EvidenceContext.candidate(CAND)
        self.foreign_state = EvidenceContext.state(OTHER_STATE)
        self.foreign_cand = EvidenceContext.candidate(OTHER_CAND)

    def reach(
        self, ev: EvidenceEvent, context: EvidenceContext, frm: EvidenceValidity
    ) -> list[ValidityTransition] | None:
        """Transitions that leave ``ev`` in validity ``frm`` in ``context``, or None if no
        legal history does."""
        own = context in ev.contexts
        if frm is V.VALID:
            return [] if own else None  # R4: a foreign context is never VALID
        if frm is V.UNCERTAIN:
            if own:
                return [transition(ev, 1, context=context, to=V.UNCERTAIN)]
            return []
        if frm is V.INVALID:
            return [transition(ev, 1, context=context, to=V.INVALID, impact_ref=uid(77))]
        if frm is V.SUPERSEDED:
            return [
                transition(
                    ev, 1, scope=RECORD, to=V.SUPERSEDED, superseded_by=uid(2), reason="newer"
                )
            ]
        return None  # REDACTED: no transition leads into it (C-52)

    def test_context_scope_pairs(self) -> None:
        cases = (
            ("own state", self.own_state),
            ("own candidate", self.own_cand),
            ("foreign state", self.foreign_state),
            ("foreign candidate", self.foreign_cand),
        )
        reached = 0
        for label, context in cases:
            own = context in self.ev.contexts
            for frm in self.ALL:
                history = self.reach(self.ev, context, frm)
                if history is None:
                    continue
                for to in self.ALL:
                    reached += 1
                    req = request(self.ev, to, context=context, impact_ref=uid(77))
                    legal = (frm, to) in self.LEGAL_CONTEXT and (
                        own or (frm, to) != (V.UNCERTAIN, V.VALID)
                    )
                    with self.subTest(context=label, frm=frm.value, to=to.value):
                        if legal:
                            self.assertIs(check_transition(self.ev, req, history), frm)
                        else:
                            with self.assertRaises(IllegalTransitionError):
                                check_transition(self.ev, req, history)
        self.assertGreater(reached, 60)

    def test_nothing_leads_into_redacted_or_superseded_in_context_scope(self) -> None:
        for context in (self.own_state, self.own_cand, self.foreign_state, self.foreign_cand):
            for to in (V.REDACTED, V.SUPERSEDED):
                with (
                    self.subTest(context=str(context), to=to.value),
                    self.assertRaises(IllegalTransitionError),
                ):
                    check_transition(
                        self.ev, request(self.ev, to, context=context, impact_ref=uid(77)), []
                    )

    def test_uncertain_to_valid_is_refused_in_a_foreign_context(self) -> None:
        for context in (self.foreign_state, self.foreign_cand):
            with self.subTest(context=str(context)):
                self.assertIs(effective_validity(self.ev, context, []), V.UNCERTAIN)
                with self.assertRaises(IllegalTransitionError):
                    check_transition(self.ev, request(self.ev, V.VALID, context=context), [])

    def test_invalid_is_terminal_within_its_context_but_not_in_another(self) -> None:
        history = [transition(self.ev, 1, context=self.own_cand, to=V.INVALID, impact_ref=uid(77))]
        for to in (V.VALID, V.UNCERTAIN, V.INVALID):
            with self.subTest(to=to.value), self.assertRaises(IllegalTransitionError):
                check_transition(
                    self.ev,
                    request(self.ev, to, context=self.own_cand, impact_ref=uid(77)),
                    history,
                )
        # the same record is still VALID for its state, so it can still be changed there
        self.assertIs(
            check_transition(
                self.ev, request(self.ev, V.UNCERTAIN, context=self.own_state), history
            ),
            V.VALID,
        )

    def test_invalid_in_a_candidate_context_needs_an_impact_reference(self) -> None:
        for context in (self.own_cand, self.foreign_cand):
            with self.subTest(context=str(context)):
                with self.assertRaises(IllegalTransitionError) as caught:
                    check_transition(self.ev, request(self.ev, V.INVALID, context=context), [])
                self.assertIn("impact_ref", str(caught.exception))
                check_transition(
                    self.ev, request(self.ev, V.INVALID, context=context, impact_ref=uid(77)), []
                )

    def test_invalid_in_a_state_context_needs_no_impact_reference(self) -> None:
        check_transition(self.ev, request(self.ev, V.INVALID, context=self.own_state), [])
        check_transition(self.ev, request(self.ev, V.INVALID, context=self.foreign_state), [])

    def test_record_scope_pairs(self) -> None:
        """RECORD scope leads to INVALID only, with an INTEGRITY: reason (Doc 11 §46)."""
        for frm in self.ALL:
            history = self.reach(
                self.ev, self.own_cand, frm
            )  # the primary context is the candidate
            if history is None:
                continue
            for to in self.ALL:
                good = request(
                    self.ev, to, scope=RECORD, reason="INTEGRITY: the payload hash differs"
                )
                with self.subTest(frm=frm.value, to=to.value):
                    if to is V.INVALID and frm in (V.VALID, V.UNCERTAIN, V.INVALID):
                        self.assertIs(check_transition(self.ev, good, history), frm)
                    else:
                        with self.assertRaises(IllegalTransitionError):
                            check_transition(self.ev, good, history)

    def test_record_scope_invalid_needs_the_integrity_prefix(self) -> None:
        for reason in ("impact analysis", "integrity: lower case", " INTEGRITY: padded"):
            with self.subTest(reason=reason):
                try:
                    req = request(self.ev, V.INVALID, scope=RECORD, reason=reason)
                except DomainValidationError:
                    continue  # a padded reason is refused even earlier
                with self.assertRaises(IllegalTransitionError):
                    check_transition(self.ev, req, [])

    def test_record_scope_supersede_goes_through_supersede_only(self) -> None:
        with self.assertRaises(IllegalTransitionError):
            check_transition(self.ev, request(self.ev, V.SUPERSEDED, scope=RECORD), [])

    def test_the_record_transition_is_terminal_and_unique(self) -> None:
        for kind, record in (
            (
                "invalid",
                transition(self.ev, 1, scope=RECORD, to=V.INVALID, reason="INTEGRITY: x"),
            ),
            (
                "superseded",
                transition(
                    self.ev, 1, scope=RECORD, to=V.SUPERSEDED, superseded_by=uid(2), reason="n"
                ),
            ),
        ):
            for to in self.ALL:
                for scope, context in (
                    (RECORD, None),
                    (CONTEXT, self.own_state),
                    (CONTEXT, self.own_cand),
                    (CONTEXT, self.foreign_state),
                ):
                    with self.subTest(record=kind, to=to.value, scope=scope.value):
                        req = request(
                            self.ev,
                            to,
                            scope=scope,
                            context=context,
                            reason="INTEGRITY: again",
                            impact_ref=uid(77),
                        )
                        with self.assertRaises(IllegalTransitionError):
                            check_transition(self.ev, req, [record])

    def test_an_unbound_record_takes_its_record_transition_from_its_creation_validity(self) -> None:
        unbound = event(state_id=None, state_hash=None, validity=V.UNCERTAIN)
        req = request(unbound, V.INVALID, scope=RECORD, reason="INTEGRITY: x")
        self.assertIs(check_transition(unbound, req, []), V.UNCERTAIN)

    def test_a_request_for_another_record_is_refused(self) -> None:
        other = event(evidence_id=uid(2))
        with self.assertRaises(DomainValidationError):
            check_transition(self.ev, request(other, V.INVALID, context=self.own_state), [])

    def test_a_request_is_shaped_by_its_scope(self) -> None:
        with self.assertRaises(DomainValidationError):
            request(self.ev, V.INVALID, scope=CONTEXT, context=None)
        with self.assertRaises(DomainValidationError):
            request(self.ev, V.INVALID, scope=RECORD, context=self.own_state)
        with self.assertRaises(DomainValidationError):
            request(self.ev, V.INVALID, context=self.own_state, reason="  ")


class TestValidityTransitionRecord(unittest.TestCase):
    def setUp(self) -> None:
        self.ev = event()

    def test_nothing_leads_into_redacted(self) -> None:
        with self.assertRaises(DomainValidationError):
            transition(self.ev, 1, scope=RECORD, to=V.REDACTED, superseded_by=None, reason="x")

    def test_superseded_by_is_set_exactly_for_superseded(self) -> None:
        with self.assertRaises(DomainValidationError):
            transition(self.ev, 1, scope=RECORD, to=V.SUPERSEDED, superseded_by=None, reason="x")
        with self.assertRaises(DomainValidationError):
            transition(
                self.ev, 1, scope=RECORD, to=V.INVALID, superseded_by=uid(2), reason="INTEGRITY: x"
            )

    def test_superseded_has_record_scope(self) -> None:
        with self.assertRaises(DomainValidationError):
            transition(
                self.ev,
                1,
                scope=CONTEXT,
                context=EvidenceContext.state(STATE),
                to=V.SUPERSEDED,
                superseded_by=uid(2),
            )

    def test_the_sequence_is_positive(self) -> None:
        with self.assertRaises(DomainValidationError):
            transition(self.ev, 0)

    def test_ids_are_uuids(self) -> None:
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(
                transition(self.ev, 1, context=EvidenceContext.state(STATE)), transition_id="vt-1"
            )

    def test_the_context_is_a_state_or_a_candidate_with_a_uuid(self) -> None:
        with self.assertRaises(DomainValidationError):
            EvidenceContext(ContextKind.STATE, "state-1")
        with self.assertRaises(DomainValidationError):
            EvidenceContext("STATE", STATE)  # type: ignore[arg-type]


class TestSupersession(unittest.TestCase):
    """C-53 (D2): old and new must describe the same thing."""

    def setUp(self) -> None:
        self.old = event(evidence_id=uid(1))
        self.new = event(evidence_id=uid(2), payload={"result": "PASS", "run": 2})

    def refused(self, old: EvidenceEvent, new: EvidenceEvent, ot: Any = (), nt: Any = ()) -> str:
        with self.assertRaises(IllegalTransitionError) as caught:
            check_supersession(old, new, ot, nt)
        return str(caught.exception)

    def test_a_replacement_for_the_same_thing_is_allowed(self) -> None:
        self.assertIs(check_supersession(self.old, self.new, [], []), V.VALID)

    def test_the_from_validity_is_the_old_records_primary_validity(self) -> None:
        invalid = [
            transition(
                self.old, 1, context=EvidenceContext.state(STATE), to=V.INVALID, impact_ref=None
            )
        ]
        self.assertIs(check_supersession(self.old, self.new, invalid, []), V.INVALID)

    def test_a_record_cannot_supersede_itself(self) -> None:
        self.refused(self.old, self.old)

    def test_the_kinds_must_match(self) -> None:
        self.refused(self.old, event(evidence_id=uid(2), kind=K.LLM))

    def test_evidence_about_a_state_is_not_superseded_by_evidence_about_a_candidate(self) -> None:
        # The 2c9b668 gate test superseded v0's evidence with candidate evidence.
        self.refused(self.old, candidate_event(evidence_id=uid(2)))
        self.refused(candidate_event(evidence_id=uid(2)), self.old)

    def test_llm_evidence_about_vn_is_not_superseded_by_verification_of_another_candidate(
        self,
    ) -> None:
        llm = event(evidence_id=uid(1), kind=K.LLM)
        other = candidate_event(evidence_id=uid(2), kind=K.VERIFICATION, candidate_id=OTHER_CAND)
        self.refused(llm, other)

    def test_the_states_must_match(self) -> None:
        self.refused(self.old, event(evidence_id=uid(2), state_id=OTHER_STATE))

    def test_the_candidates_must_match(self) -> None:
        self.refused(
            candidate_event(evidence_id=uid(1)),
            candidate_event(evidence_id=uid(2), candidate_id=OTHER_CAND),
        )

    def test_unbound_records_are_refused(self) -> None:
        a = event(evidence_id=uid(1), state_id=None, state_hash=None)
        b = event(evidence_id=uid(2), state_id=None, state_hash=None)
        self.refused(a, b)

    def test_a_record_that_has_its_record_transition_is_refused(self) -> None:
        record = transition(self.old, 1, scope=RECORD, to=V.INVALID, reason="INTEGRITY: x")
        self.refused(self.old, self.new, [record], [])
        record_new = transition(self.new, 1, scope=RECORD, to=V.INVALID, reason="INTEGRITY: x")
        self.refused(self.old, self.new, [], [record_new])

    def test_the_new_record_must_be_valid_in_its_primary_context(self) -> None:
        self.refused(self.old, event(evidence_id=uid(2), validity=V.UNCERTAIN))
        invalid_new = [transition(self.new, 1, context=EvidenceContext.state(STATE), to=V.INVALID)]
        self.refused(self.old, self.new, [], invalid_new)

    def test_a_supersession_request_is_shaped(self) -> None:
        SupersessionRequest(
            transition_id=uid(9),
            old_evidence_id=uid(1),
            new_evidence_id=uid(2),
            reason="newer",
            correlation_id=CORR,
            operation_id=OP,
            created_at=at(8),
        )
        with self.assertRaises(DomainValidationError):
            SupersessionRequest(
                transition_id="vt-1",
                old_evidence_id=uid(1),
                new_evidence_id=uid(2),
                reason="newer",
                correlation_id=CORR,
                operation_id=OP,
                created_at=at(8),
            )


class TestProofEvaluation(unittest.TestCase):
    """The conditions P1 to P6 of the proof gate (C-52; Doc 11 §8, §45)."""

    def setUp(self) -> None:
        self.ev = event()
        self.state = EvidenceContext.state(STATE)

    def check(self, **overrides: Any) -> ProofCheck:
        args: dict[str, Any] = {
            "event": self.ev,
            "expected": self.state,
            "transitions": [],
            "integrity": IntegrityStatus.VALID,
            "expected_state_hash": HASH,
        }
        args.update(overrides)
        return evaluate_proof(
            args["event"],
            args["expected"],
            args["transitions"],
            args["integrity"],
            args["expected_state_hash"],
        )

    def only(self, check: ProofCheck, prefix: str) -> None:
        self.assertFalse(check.usable)
        self.assertTrue(all(reason.startswith(prefix) for reason in check.reasons), check.reasons)
        self.assertGreaterEqual(len(check.reasons), 1)

    def test_valid_bound_intact_evidence_is_usable(self) -> None:
        check = self.check()
        self.assertTrue(check.usable)
        self.assertEqual(check.reasons, ())

    def test_p1_missing_evidence(self) -> None:
        self.only(self.check(event=None), "P1")

    def test_p2_only_proof_kinds_count(self) -> None:
        for kind in (K.LLM, K.ERROR, K.EXPERIMENT):
            with self.subTest(kind=kind):
                self.only(self.check(event=event(kind=kind)), "P2")
        for kind in PROOF_KINDS - CANDIDATE_BOUND_KINDS:
            with self.subTest(kind=kind):
                self.assertTrue(self.check(event=event(kind=kind)).usable)

    def test_p3_the_expected_context_must_be_one_the_record_was_produced_for(self) -> None:
        check = self.check(expected=EvidenceContext.candidate(CAND))
        self.assertFalse(check.usable)
        self.assertTrue(any(r.startswith("P3") for r in check.reasons))
        # and a foreign state: bound to vN is not proof about another state (Doc 11 §9)
        self.assertFalse(self.check(expected=EvidenceContext.state(OTHER_STATE)).usable)

    def test_p4_validity_in_the_expected_context_must_be_valid(self) -> None:
        for to in (V.UNCERTAIN, V.INVALID):
            history = [transition(self.ev, 1, context=self.state, to=to)]
            with self.subTest(to=to.value):
                self.only(self.check(transitions=history), "P4")
        self.only(self.check(event=event(validity=V.UNCERTAIN)), "P4")

    def test_p4_invalid_for_a_candidate_leaves_the_state_usable(self) -> None:
        history = [
            transition(
                self.ev, 1, context=EvidenceContext.candidate(CAND), to=V.INVALID, impact_ref=uid(7)
            )
        ]
        self.assertTrue(self.check(transitions=history).usable)

    def test_p4_a_superseded_record_is_not_proof(self) -> None:
        record = transition(
            self.ev, 1, scope=RECORD, to=V.SUPERSEDED, superseded_by=uid(2), reason="newer"
        )
        self.only(self.check(transitions=[record]), "P4")

    def test_p5_the_integrity_must_be_valid(self) -> None:
        for status in (IntegrityStatus.TAMPERED, IntegrityStatus.MISSING_PAYLOAD, None):
            with self.subTest(status=status):
                self.only(self.check(integrity=status), "P5")

    def test_p6_the_state_hash_must_match_the_expected_context(self) -> None:
        self.only(self.check(expected_state_hash=OTHER_HASH), "P6")
        self.only(self.check(expected_state_hash=None), "P6")  # the state is missing or unhashed
        candidate = candidate_event(kind=K.VERIFICATION)  # no state_hash recorded
        self.only(self.check(event=candidate, expected=EvidenceContext.candidate(CAND)), "P6")

    def test_every_failed_condition_is_listed(self) -> None:
        check = self.check(
            event=event(kind=K.LLM, validity=V.UNCERTAIN),
            integrity=IntegrityStatus.TAMPERED,
            expected_state_hash=OTHER_HASH,
        )
        prefixes = {reason[:2] for reason in check.reasons}
        self.assertEqual(prefixes, {"P2", "P4", "P5", "P6"})

    def test_a_proof_check_cannot_contradict_itself(self) -> None:
        with self.assertRaises(DomainValidationError):
            ProofCheck(True, ("P4: nope",))
        with self.assertRaises(DomainValidationError):
            ProofCheck(False, ())


class TestValidityChangedPayload(unittest.TestCase):
    def test_the_payload_has_exactly_the_keys_the_audit_event_requires(self) -> None:
        payload = validity_changed_payload(
            evidence_id=uid(1),
            scope=CONTEXT,
            context=EvidenceContext.candidate(CAND),
            from_validity=V.UNCERTAIN,
            to_validity=V.INVALID,
            reason="affected",
            impact_ref=uid(7),
            superseded_by=None,
        )
        self.assertEqual(
            set(payload), set(REQUIRED_PAYLOAD_KEYS[AuditEventType.EVIDENCE_VALIDITY_CHANGED])
        )
        self.assertEqual(payload["context_kind"], "CANDIDATE")
        self.assertEqual(payload["context_id"], CAND)

    def test_a_record_scope_payload_has_a_null_context(self) -> None:
        payload = validity_changed_payload(
            evidence_id=uid(1),
            scope=RECORD,
            context=None,
            from_validity=V.VALID,
            to_validity=V.SUPERSEDED,
            reason="newer",
            impact_ref=None,
            superseded_by=uid(2),
        )
        self.assertIsNone(payload["context_kind"])
        self.assertIsNone(payload["context_id"])
        self.assertEqual(payload["superseded_by"], uid(2))


if __name__ == "__main__":
    unittest.main()
