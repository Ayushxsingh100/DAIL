"""Evidence service (Doc 11; Doc 05 §16, §26; C-50 to C-58; P2-fix step 4).

The service is the only way the rest of DAIL writes evidence. Every method takes an open
``UnitOfWork`` first, so the caller owns the transaction (Doc 05 §32): evidence, its validity
transitions and the audit events they produce commit or roll back together with whatever else the
caller does in that unit of work. The service holds no state beyond its redactor, never touches
``sqlite3`` and never imports the adapter (rules R4, R11): it works through the ports of
``core.domain.repositories``.

Writing: a payload is redacted *before* it is hashed and persisted (Doc 11 §28), so the content hash
describes exactly what was stored; ``redaction_policy_version`` is recorded if and only if something
was redacted. Reading: ``usable_as_proof`` implements the proof gate P1 to P6 and fails closed;
``verify_integrity`` recomputes the content hash on read (Doc 11 §45); ``record_integrity_failure``
carries out Doc 11 §46.

Nothing here accepts an ``EvidenceEvent``, a ``ValidityTransition`` or a ``ProofCheck`` as
authority.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from core.domain import hashing
from core.domain.audit import (
    ActorType,
    AuditAppendResult,
    AuditEvent,
    AuditEventType,
    AuditSubmission,
)
from core.domain.errors import PersistenceError
from core.domain.evidence import (
    ArtifactRef,
    BrokenReferenceError,
    ContextKind,
    EvidenceContext,
    EvidenceEvent,
    EvidenceKind,
    EvidenceNotFoundError,
    EvidenceSubmission,
    EvidenceValidity,
    IntegrityStatus,
    ProofCheck,
    SupersessionRequest,
    TransitionAppendResult,
    TransitionRequest,
    TransitionScope,
    ValidityTransition,
    effective_validity,
    evaluate_proof,
)
from core.domain.ids import new_uuid
from core.domain.jsonvalue import thaw_json, validate_json
from core.domain.redaction import Redactor
from core.domain.repositories import UnitOfWork
from core.domain.values import Provenance
from evidence.ids import CorrelationContext

_DERIVED_NAMESPACE = uuid.UUID("3c9b6a50-1f4e-4d7a-8b2c-6e0d5a91f7b3")


def _derived_id(key: str) -> str:
    """A deterministic UUID for an effect that must happen once however often it is requested
    (an integrity failure is recorded once per record and status; Doc 11 §38)."""
    return str(uuid.uuid5(_DERIVED_NAMESPACE, key))


def _now(now: datetime | None) -> datetime:
    return datetime.now(UTC) if now is None else now


@dataclass(frozen=True)
class RecordResult:
    """The outcome of ``EvidenceService.record``."""

    record: EvidenceEvent
    duplicate: bool
    redaction_count: int


class EvidenceService:
    def __init__(self, redactor: Redactor | None = None) -> None:
        self._redactor = Redactor() if redactor is None else redactor

    # --- writing -----------------------------------------------------------------------------

    def record(
        self,
        uow: UnitOfWork,
        *,
        kind: EvidenceKind,
        event_name: str,
        payload: Any,
        ctx: CorrelationContext,
        provenance: Provenance,
        state_id: str | None = None,
        candidate_id: str | None = None,
        parent_state_id: str | None = None,
        state_hash: str | None = None,
        validity: EvidenceValidity = EvidenceValidity.VALID,
        schema_version: str = "1",
        evidence_id: str | None = None,
        now: datetime | None = None,
    ) -> RecordResult:
        """Redact, hash and persist one evidence record (idempotent by ``evidence_id``).

        The order is fixed: redact, build the submission (which hashes and re-checks the payload),
        append. ``run_id`` and ``attempt_id`` come from ``ctx``, so a candidate-bound record is
        refused unless the context carries its attempt (C-55)."""
        validate_json(payload, "payload")  # C-33: no floats
        redacted = self._redactor.redact(thaw_json(payload))
        submission = EvidenceSubmission.create(
            payload=redacted.payload,
            evidence_id=new_uuid() if evidence_id is None else evidence_id,
            run_id=ctx.run_id,
            attempt_id=ctx.attempt_id,
            correlation_id=ctx.correlation_id,
            operation_id=ctx.operation_id,
            kind=kind,
            event_name=event_name,
            provenance=provenance,
            created_at=_now(now),
            state_id=state_id,
            candidate_id=candidate_id,
            parent_state_id=parent_state_id,
            state_hash=state_hash,
            validity=validity,
            schema_version=schema_version,
            redaction_policy_version=redacted.policy_version if redacted.redacted else None,
        )
        appended = uow.evidence.append(submission)
        return RecordResult(appended.record, appended.duplicate, redacted.redaction_count)

    def _redact_reason(self, reason: str) -> str:
        redacted = self._redactor.redact(reason).payload
        return redacted if isinstance(redacted, str) else reason

    def change_validity(
        self,
        uow: UnitOfWork,
        evidence_id: str,
        *,
        context: EvidenceContext,
        to: EvidenceValidity,
        reason: str,
        ctx: CorrelationContext,
        impact_ref: str | None = None,
        transition_id: str | None = None,
        now: datetime | None = None,
    ) -> TransitionAppendResult:
        """Change the validity of one record in ONE context (C-52). The record, its payload and its
        validity in every other context stay as they were; a redelivery with the same
        ``transition_id`` adds nothing (Doc 11 §38)."""
        return uow.evidence.append_transition(
            TransitionRequest(
                transition_id=new_uuid() if transition_id is None else transition_id,
                evidence_id=evidence_id,
                scope=TransitionScope.CONTEXT,
                context=context,
                to_validity=to,
                reason=self._redact_reason(reason),
                impact_ref=impact_ref,
                correlation_id=ctx.correlation_id,
                operation_id=ctx.operation_id,
                created_at=_now(now),
            )
        )

    def invalidate(
        self,
        uow: UnitOfWork,
        evidence_id: str,
        *,
        context: EvidenceContext,
        reason: str,
        ctx: CorrelationContext,
        impact_ref: str | None = None,
        transition_id: str | None = None,
        now: datetime | None = None,
    ) -> TransitionAppendResult:
        """Impact analysis invalidates evidence for ``context`` (Doc 11 §32): INVALID there only.
        In a candidate context ``impact_ref`` must name IMPACT evidence bound to that candidate."""
        return self.change_validity(
            uow,
            evidence_id,
            context=context,
            to=EvidenceValidity.INVALID,
            reason=reason,
            ctx=ctx,
            impact_ref=impact_ref,
            transition_id=transition_id,
            now=now,
        )

    def supersede(
        self,
        uow: UnitOfWork,
        old_id: str,
        new_id: str,
        *,
        reason: str,
        ctx: CorrelationContext,
        transition_id: str | None = None,
        now: datetime | None = None,
    ) -> TransitionAppendResult:
        """evidence_v1 --SUPERSEDED_BY--> evidence_v2, deleting nothing (Doc 11 §33). Both must
        describe the same thing (C-53); the repository writes the supersession row, the RECORD-scope
        transition and the audit event atomically."""
        return uow.evidence.supersede(
            SupersessionRequest(
                transition_id=new_uuid() if transition_id is None else transition_id,
                old_evidence_id=old_id,
                new_evidence_id=new_id,
                reason=self._redact_reason(reason),
                correlation_id=ctx.correlation_id,
                operation_id=ctx.operation_id,
                created_at=_now(now),
            )
        )

    def record_integrity_failure(
        self,
        uow: UnitOfWork,
        evidence_id: str,
        *,
        ctx: CorrelationContext,
        now: datetime | None = None,
    ) -> IntegrityStatus:
        """Check a record's integrity and, if it fails, carry out Doc 11 §46: mark the record
        INVALID in every context (a RECORD-scope transition whose reason starts ``INTEGRITY:``),
        emit an ERROR_OCCURRED audit event and keep both. A record with a failed integrity check
        is never eligible as proof (P5), so promotion that needs it is blocked.

        It is idempotent: the RECORD-scope transition is appended once, and the event once per
        record and status, however often this is called."""
        status = self.verify_integrity(uow, evidence_id)
        if status is IntegrityStatus.VALID:
            return status
        event = self._require(uow, evidence_id)
        when = _now(now)
        if not any(
            t.scope is TransitionScope.RECORD for t in uow.evidence.transitions(evidence_id)
        ):
            uow.evidence.append_transition(
                TransitionRequest(
                    transition_id=_derived_id(f"integrity-transition:{evidence_id}:{status.value}"),
                    evidence_id=evidence_id,
                    scope=TransitionScope.RECORD,
                    context=None,
                    to_validity=EvidenceValidity.INVALID,
                    reason=f"INTEGRITY: {status.value}: the stored payload does not match "
                    f"content_hash {event.content_hash}",
                    impact_ref=None,
                    correlation_id=ctx.correlation_id,
                    operation_id=ctx.operation_id,
                    created_at=when,
                )
            )
        event_id = _derived_id(f"integrity-event:{evidence_id}:{status.value}")
        if uow.audit.get(event_id) is None:
            uow.audit.append(
                AuditSubmission.create(
                    event_id=event_id,
                    event_type=AuditEventType.ERROR_OCCURRED,
                    correlation_id=ctx.correlation_id,
                    operation_id=ctx.operation_id,
                    timestamp=when,
                    payload={
                        "error_code": "EVIDENCE_INTEGRITY_FAILURE",
                        "evidence_id": evidence_id,
                        "integrity_status": status.value,
                        "content_hash": event.content_hash,
                        "payload_ref": event.payload_ref,
                    },
                    state_id=event.state_id,
                    candidate_id=event.candidate_id,
                )
            )
        return status

    def append_audit_event(
        self,
        uow: UnitOfWork,
        *,
        event_type: AuditEventType,
        ctx: CorrelationContext,
        payload: Any,
        actor_type: ActorType = ActorType.SYSTEM,
        actor_id: str | None = None,
        state_id: str | None = None,
        candidate_id: str | None = None,
        decision_id: str | None = None,
        event_id: str | None = None,
        event_version: int = 1,
        now: datetime | None = None,
    ) -> AuditAppendResult:
        """Append an audit event: redact the payload, then check the required columns and payload
        keys of the type (§4.6). Supply a stable ``event_id`` (the idempotency key) when the same
        event may be delivered more than once (Doc 11 §38)."""
        validate_json(payload, "payload")  # C-33: no floats
        redacted = self._redactor.redact(thaw_json(payload))
        return uow.audit.append(
            AuditSubmission.create(
                event_id=new_uuid() if event_id is None else event_id,
                event_type=event_type,
                correlation_id=ctx.correlation_id,
                operation_id=ctx.operation_id,
                timestamp=_now(now),
                payload=redacted.payload,
                actor_type=actor_type,
                actor_id=actor_id,
                state_id=state_id,
                candidate_id=candidate_id,
                decision_id=decision_id,
                event_version=event_version,
            )
        )

    # --- reading -----------------------------------------------------------------------------

    @staticmethod
    def _require(uow: UnitOfWork, evidence_id: str) -> EvidenceEvent:
        event = uow.evidence.get(evidence_id)
        if event is None:
            raise EvidenceNotFoundError(f"evidence {evidence_id} does not exist")
        return event

    def validity_in(
        self, uow: UnitOfWork, evidence_id: str, context: EvidenceContext
    ) -> EvidenceValidity:
        """The validity of the record in ``context`` (C-52: R1 to R4). Evidence is never VALID in a
        context it was not produced for."""
        event = self._require(uow, evidence_id)
        return effective_validity(event, context, uow.evidence.transitions(evidence_id))

    def verify_integrity(self, uow: UnitOfWork, evidence_id: str) -> IntegrityStatus:
        """Recompute the content hash of the stored payload (Doc 11 §45): VALID, TAMPERED, or
        MISSING_PAYLOAD when the reference no longer resolves (Doc 11 §44)."""
        event = self._require(uow, evidence_id)
        try:
            payload = uow.evidence.resolve(ArtifactRef.parse(event.payload_ref))
        except BrokenReferenceError:
            return IntegrityStatus.MISSING_PAYLOAD
        except PersistenceError:  # the stored text is no longer valid JSON
            return IntegrityStatus.TAMPERED
        if hashing.content_hash(payload) != event.content_hash:
            return IntegrityStatus.TAMPERED
        return IntegrityStatus.VALID

    def usable_as_proof(
        self, uow: UnitOfWork, evidence_id: str, expected: EvidenceContext
    ) -> ProofCheck:
        """May this evidence support a trust decision about ``expected`` (a trusted state or a
        candidate)? Fails closed (Doc 11 §8, §45): every condition must hold, and any exception
        while checking makes the evidence unusable. The conditions:

        P1 the evidence exists; P2 its kind is a proof kind; P3 ``expected`` is a context it was
        produced for; P4 its effective validity in ``expected`` is VALID; P5 its integrity is VALID;
        P6 its state_hash equals the stored state_hash of the expected state or candidate, which
        must exist. Every failed condition is listed."""
        try:
            if not isinstance(expected, EvidenceContext):
                return ProofCheck(
                    False, ("P3: no expected state or candidate was supplied (Doc 11 §8)",)
                )
            event = uow.evidence.get(evidence_id)
            if event is None:
                return evaluate_proof(None, expected, (), None, None)
            return evaluate_proof(
                event,
                expected,
                uow.evidence.transitions(evidence_id),
                self.verify_integrity(uow, evidence_id),
                self._state_hash_of(uow, expected),
            )
        except Exception as exc:  # fail closed on anything unexpected
            return ProofCheck(False, (f"error while checking the evidence: {type(exc).__name__}",))

    @staticmethod
    def _state_hash_of(uow: UnitOfWork, expected: EvidenceContext) -> str | None:
        if expected.kind is ContextKind.STATE:
            state = uow.trusted_states.get(expected.id)
            return None if state is None else state.state_hash
        candidate = uow.candidates.get(expected.id)
        return None if candidate is None else candidate.state_hash

    def resolve_payload(self, uow: UnitOfWork, evidence_id: str) -> Any:
        """The stored payload the record's ``payload_ref`` names (Doc 11 §17); a broken reference
        raises ``PersistenceError``."""
        event = self._require(uow, evidence_id)
        return uow.evidence.resolve(ArtifactRef.parse(event.payload_ref))

    # --- lineage -----------------------------------------------------------------------------

    def evidence_for_attempt(self, uow: UnitOfWork, attempt_id: str) -> tuple[EvidenceEvent, ...]:
        return uow.evidence.list_for_attempt(attempt_id)

    def evidence_for_run(self, uow: UnitOfWork, run_id: str) -> tuple[EvidenceEvent, ...]:
        return uow.evidence.list_for_run(run_id)

    def evidence_for_state(self, uow: UnitOfWork, state_id: str) -> tuple[EvidenceEvent, ...]:
        return uow.evidence.list_for_state(state_id)

    def evidence_for_candidate(
        self, uow: UnitOfWork, candidate_id: str
    ) -> tuple[EvidenceEvent, ...]:
        return uow.evidence.list_for_candidate(candidate_id)

    def evidence_for_correlation(
        self, uow: UnitOfWork, correlation_id: str
    ) -> tuple[EvidenceEvent, ...]:
        return uow.evidence.list_for_correlation(correlation_id)

    def events_for_correlation(
        self, uow: UnitOfWork, correlation_id: str
    ) -> tuple[AuditEvent, ...]:
        """A whole workflow in sequence order, not timestamp order (Doc 11 §19, §20)."""
        return uow.audit.list_for_correlation(correlation_id)

    def events_for_candidate(self, uow: UnitOfWork, candidate_id: str) -> tuple[AuditEvent, ...]:
        return uow.audit.list_for_candidate(candidate_id)

    def validity_history(
        self, uow: UnitOfWork, evidence_id: str, context: EvidenceContext | None = None
    ) -> tuple[ValidityTransition, ...]:
        """The record's transitions in sequence order; with ``context``, only those that affect it:
        its own CONTEXT transitions and the RECORD-scope one (C-52)."""
        history: Sequence[ValidityTransition] = uow.evidence.transitions(evidence_id)
        if context is None:
            return tuple(history)
        return tuple(
            t for t in history if t.scope is TransitionScope.RECORD or t.context == context
        )

    def supersession_chain(self, uow: UnitOfWork, evidence_id: str) -> tuple[str, ...]:
        """The ids of the supersession chain through ``evidence_id``, oldest to newest."""
        self._require(uow, evidence_id)
        oldest, seen = evidence_id, {evidence_id}
        while (older := uow.evidence.supersedes(oldest)) is not None:
            if older in seen:
                raise PersistenceError(f"supersession cycle at {older}")
            seen.add(older)
            oldest = older
        chain = [oldest]
        while (newer := uow.evidence.superseded_by(chain[-1])) is not None:
            if newer in chain:
                raise PersistenceError(f"supersession cycle at {newer}")
            chain.append(newer)
        return tuple(chain)
