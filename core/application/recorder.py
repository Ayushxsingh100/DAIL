"""The stage recorder: evidence records and audit events of one evaluation (P6c step 2; Doc 11 §5,
§8-§12, §25, §28, §38; Doc 06 §28; C-54, C-55, C-170 (4), C-172).

``StageRecorder`` writes through ``evidence.service.EvidenceService`` and the audit port, always
in a unit of work the caller owns, so a stage's evidence and its event commit together. Every record
carries the run, attempt, correlation and operation ids of the ``PromotionContext`` (C-55); a record
about a candidate is bound to it (candidate id, parent state, the candidate's state hash).

**Idempotent by id.** The ids are derived from the request (``core.application.ids``), so a rerun
writes the same records: the same content under an id is a duplicate and is accepted, another
content raises ``ConflictingDuplicateError``. Nothing is overwritten. A payload that holds a secret
is refused (``DomainValidationError``) and nothing is stored: the service would redact it, but a
secret in a stage payload is a defect to surface, not to hide.

The engines draw a random ``report_id`` or ``graph_id`` on every run and offer no way to inject one;
both sit outside the report's content hash. The recorder leaves them out of the payload, so a rerun
that computes a report again records the same bytes (C-170 (4)); the report is identified by its
content hash, which the payload carries.

Time: ``at`` is the deterministic instant of the evaluation (the candidate's ``created_at``); it is
the only time that enters a hash. ``when`` is the live clock and stamps the audit event, which the
duplicate test ignores (Doc 11 §38).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from core.application import ids as oids
from core.domain.audit import (
    AuditEventType,
    ConflictingDuplicateEventError,
)
from core.domain.enums import ProvenanceSourceKind
from core.domain.errors import DomainValidationError
from core.domain.evidence import EvidenceConflictError, EvidenceKind, EvidenceSubmission
from core.domain.graph import DependencyGraph
from core.domain.identity import IdentityReport
from core.domain.impact import ImpactReport
from core.domain.jsonvalue import thaw_json, utc
from core.domain.patch import Patch
from core.domain.promotion import ConflictingDuplicateError
from core.domain.redaction import Redactor
from core.domain.repositories import UnitOfWork
from core.domain.state import CandidateState
from core.domain.values import Provenance
from core.domain.verification import VerificationReport
from core.promotion.commit import PromotionContext
from core.verification.engine import to_evidence_submission
from evidence.ids import CorrelationContext
from evidence.service import EvidenceService

_COMPONENT = "core.application.orchestrator"
_VERSION = "1"


def _need(value: object, kind: type, name: str) -> None:
    if not isinstance(value, kind):
        raise DomainValidationError(f"StageRecorder: {name} must be a {kind.__name__}")


def _without(data: Mapping[str, Any], key: str) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k != key}


class StageRecorder:
    """Records the stages of one evaluation (or of a baseline) for one ``PromotionContext``."""

    def __init__(
        self,
        context: PromotionContext,
        *,
        service: EvidenceService | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        _need(context, PromotionContext, "context")
        self._context = context
        self._service = EvidenceService() if service is None else service
        self._redactor = Redactor() if redactor is None else redactor
        self._ctx = CorrelationContext(
            context.run_id, context.correlation_id, context.operation_id, context.attempt_id
        )

    @property
    def context(self) -> PromotionContext:
        return self._context

    # --- the one place that writes ------------------------------------------------------------

    def _check_secret(self, payload: Any, what: str) -> None:
        if self._redactor.contains_secret(thaw_json(payload)):
            raise DomainValidationError(
                f"StageRecorder: the {what} payload contains a secret-like value; it is refused, "
                "not stored (Doc 11 §28)"
            )

    def append(self, uow: UnitOfWork, submission: EvidenceSubmission) -> bool:
        """Append a prepared evidence submission. True for a duplicate. A secret is refused; a
        different content under the id raises ``ConflictingDuplicateError``."""
        _need(submission, EvidenceSubmission, "submission")
        self._check_secret(json.loads(submission.payload_json), "evidence")
        try:
            return uow.evidence.append(submission).duplicate
        except EvidenceConflictError as conflict:
            raise ConflictingDuplicateError(
                f"evidence {submission.event.evidence_id} was already stored with different "
                f"content (Doc 11 §38): {conflict}"
            ) from conflict

    def _record(
        self,
        uow: UnitOfWork,
        *,
        kind: EvidenceKind,
        event_name: str,
        payload: Mapping[str, Any],
        evidence_id: str,
        at: datetime,
        source_reference: str,
        candidate: CandidateState | None,
        state_hash: str | None,
    ) -> str:
        self._check_secret(payload, kind.value)
        moment = utc(at, "at")
        try:
            self._service.record(
                uow,
                kind=kind,
                event_name=event_name,
                payload=payload,
                ctx=self._ctx,
                provenance=Provenance(
                    source_kind=ProvenanceSourceKind.DERIVED,
                    source_component=_COMPONENT,
                    source_reference=source_reference,
                    observed_at=moment,
                    tool_name="evaluation-orchestrator",
                    tool_version=_VERSION,
                    algorithm_version=_VERSION,
                ),
                candidate_id=candidate.candidate_id if candidate is not None else None,
                parent_state_id=None if candidate is None else candidate.parent_state_id,
                state_hash=state_hash,
                evidence_id=evidence_id,
                now=moment,
            )
        except EvidenceConflictError as conflict:
            raise ConflictingDuplicateError(
                f"evidence {evidence_id} was already stored with different content "
                f"(Doc 11 §38): {conflict}"
            ) from conflict
        return evidence_id

    def emit(
        self,
        uow: UnitOfWork,
        event_type: AuditEventType,
        *,
        event_id: str,
        payload: Mapping[str, Any],
        when: datetime,
        state_id: str | None = None,
        candidate_id: str | None = None,
        decision_id: str | None = None,
    ) -> None:
        """Append one audit event (idempotent by ``event_id``)."""
        if not isinstance(event_type, AuditEventType):
            raise DomainValidationError("StageRecorder.emit: event_type must be an AuditEventType")
        self._check_secret(payload, event_type.value)
        try:
            self._service.append_audit_event(
                uow,
                event_type=event_type,
                ctx=self._ctx,
                payload=dict(payload),
                actor_id=self._context.actor_id,
                state_id=state_id,
                candidate_id=candidate_id,
                decision_id=decision_id,
                event_id=event_id,
                now=utc(when, "when"),
            )
        except ConflictingDuplicateEventError as conflict:
            raise ConflictingDuplicateError(
                f"audit event {event_id} was already stored with different content "
                f"(Doc 11 §38): {conflict}"
            ) from conflict

    # --- the stages ---------------------------------------------------------------------------

    def record_candidate(
        self,
        uow: UnitOfWork,
        candidate: CandidateState,
        patch: Patch,
        *,
        attempt_number: int,
        at: datetime,
    ) -> str:
        """The STATE record of the built candidate: its hash, its patch and its parent."""
        _need(candidate, CandidateState, "candidate")
        _need(patch, Patch, "patch")
        if candidate.state_hash is None:
            raise DomainValidationError("StageRecorder: the candidate has no state_hash yet")
        if candidate.patch_id != patch.patch_id or candidate.patch_hash != patch.content_hash:
            raise DomainValidationError("StageRecorder: the patch is not the candidate's patch")
        return self._record(
            uow,
            kind=EvidenceKind.STATE,
            event_name="candidate.built",
            payload={
                "candidate_id": candidate.candidate_id,
                "parent_state_id": candidate.parent_state_id,
                "candidate_sequence": candidate.candidate_sequence,
                "attempt_number": attempt_number,
                "state_hash": candidate.state_hash,
                "normalization_version": candidate.normalization_version,
                "resource_count": len(candidate.resources),
                "patch_id": patch.patch_id,
                "patch_hash": patch.content_hash,
                "patch_source": patch.source.value,
            },
            evidence_id=oids.evidence_id_for(candidate.candidate_id, attempt_number, "state"),
            at=at,
            source_reference=candidate.candidate_id,
            candidate=candidate,
            state_hash=candidate.state_hash,
        )

    def _stage(
        self,
        uow: UnitOfWork,
        *,
        stage: str,
        kind: EvidenceKind,
        event_type: AuditEventType,
        payload: Mapping[str, Any],
        report_hash: str,
        candidate: CandidateState,
        attempt_number: int,
        at: datetime,
        when: datetime,
    ) -> str:
        evidence_id = self._record(
            uow,
            kind=kind,
            event_name=f"{stage}.completed",
            payload=payload,
            evidence_id=oids.evidence_id_for(candidate.candidate_id, attempt_number, stage),
            at=at,
            source_reference=candidate.candidate_id,
            candidate=candidate,
            state_hash=candidate.state_hash,
        )
        self.emit(
            uow,
            event_type,
            event_id=oids.event_id_for(candidate.candidate_id, attempt_number, event_type),
            payload={
                "evidence_id": evidence_id,
                "report_hash": report_hash,
                "parent_state_id": candidate.parent_state_id,
            },
            when=when,
            candidate_id=candidate.candidate_id,
        )
        return evidence_id

    def record_identity(
        self,
        uow: UnitOfWork,
        candidate: CandidateState,
        report: IdentityReport,
        *,
        attempt_number: int,
        at: datetime,
        when: datetime,
    ) -> str:
        """The IDENTITY record and IDENTITY_COMPLETED."""
        _need(candidate, CandidateState, "candidate")
        _need(report, IdentityReport, "report")
        self._belongs(report.candidate_id, report.parent_state_id, candidate, "identity report")
        return self._stage(
            uow,
            stage="identity",
            kind=EvidenceKind.IDENTITY,
            event_type=AuditEventType.IDENTITY_COMPLETED,
            payload=_without(report.to_dict(), "report_id"),
            report_hash=report.content_hash,
            candidate=candidate,
            attempt_number=attempt_number,
            at=at,
            when=when,
        )

    def record_dependency(
        self,
        uow: UnitOfWork,
        candidate: CandidateState,
        graph: DependencyGraph,
        *,
        attempt_number: int,
        at: datetime,
        when: datetime,
    ) -> str:
        """The DEPENDENCY record (the candidate's graph) and DEPENDENCY_COMPLETED."""
        _need(candidate, CandidateState, "candidate")
        _need(graph, DependencyGraph, "graph")
        if graph.state_id != candidate.candidate_id:
            raise DomainValidationError("StageRecorder: the graph is of another state")
        return self._stage(
            uow,
            stage="dependency",
            kind=EvidenceKind.DEPENDENCY,
            event_type=AuditEventType.DEPENDENCY_COMPLETED,
            payload=_without(graph.to_dict(), "graph_id"),
            report_hash=graph.graph_hash,
            candidate=candidate,
            attempt_number=attempt_number,
            at=at,
            when=when,
        )

    def record_impact(
        self,
        uow: UnitOfWork,
        candidate: CandidateState,
        report: ImpactReport,
        *,
        attempt_number: int,
        at: datetime,
        when: datetime,
    ) -> str:
        """The IMPACT record (candidate-bound, C-54) and IMPACT_COMPLETED."""
        _need(candidate, CandidateState, "candidate")
        _need(report, ImpactReport, "report")
        self._belongs(report.candidate_id, report.parent_state_id, candidate, "impact report")
        return self._stage(
            uow,
            stage="impact",
            kind=EvidenceKind.IMPACT,
            event_type=AuditEventType.IMPACT_COMPLETED,
            payload=_without(report.to_dict(), "report_id"),
            report_hash=report.content_hash,
            candidate=candidate,
            attempt_number=attempt_number,
            at=at,
            when=when,
        )

    def record_verification(
        self,
        uow: UnitOfWork,
        candidate: CandidateState,
        report: VerificationReport,
        *,
        attempt_number: int,
        when: datetime,
    ) -> dict[str, str]:
        """One VERIFICATION record and one VERIFICATION_COMPLETED per result, in report order.
        Returns ``verification_id -> evidence_id`` (what ``commit_promotion`` is given)."""
        _need(candidate, CandidateState, "candidate")
        _need(report, VerificationReport, "report")
        if report.candidate_id != candidate.candidate_id or (
            report.candidate_hash != candidate.state_hash
        ):
            raise DomainValidationError(
                "StageRecorder: the verification report is of another candidate"
            )
        found: dict[str, str] = {}
        for result in report.results:
            evidence_id = oids.evidence_id_for(
                candidate.candidate_id, attempt_number, "verification", result.target_id
            )
            self.append(
                uow,
                to_evidence_submission(
                    result,
                    evidence_id=evidence_id,
                    run_id=self._context.run_id,
                    attempt_id=self._context.attempt_id,
                    correlation_id=self._context.correlation_id,
                    operation_id=self._context.operation_id,
                    parent_state_id=candidate.parent_state_id,
                ),
            )
            found[result.verification_id] = evidence_id
            self.emit(
                uow,
                AuditEventType.VERIFICATION_COMPLETED,
                event_id=oids.event_id_for(
                    candidate.candidate_id,
                    attempt_number,
                    AuditEventType.VERIFICATION_COMPLETED,
                    result.target_id,
                ),
                payload={
                    "evidence_id": evidence_id,
                    "verification_id": result.verification_id,
                    "target": result.target_id,
                    "result": result.result.value,
                    "verifier_id": result.verifier_id,
                    "verifier_version": result.verifier_version,
                },
                when=when,
                candidate_id=candidate.candidate_id,
            )
        return found

    def record_error(
        self,
        uow: UnitOfWork,
        *,
        stage: str,
        error_type: str,
        detail: Mapping[str, Any],
        attempt_number: int,
        at: datetime,
        when: datetime,
        candidate: CandidateState | None = None,
        evidence_id: str | None = None,
        event_id: str | None = None,
    ) -> str:
        """An ERROR record and ERROR_OCCURRED. Bound to ``candidate`` when one is given; without
        one (a refused baseline) it is unbound, and the caller names the ids."""
        payload = {
            "stage": stage,
            "error_type": error_type,
            "attempt_number": attempt_number,
            "detail": dict(detail),
        }
        # Doc 11 §44: evidence bound to a candidate carries its state hash. A candidate that failed
        # to build has none, so its error record is unbound and names the candidate in the payload.
        hash_of = None if candidate is None else candidate.state_hash
        bound = candidate if hash_of is not None else None
        if candidate is not None:
            payload["candidate_id"] = candidate.candidate_id
            evidence_id = evidence_id or oids.evidence_id_for(
                candidate.candidate_id, attempt_number, "error"
            )
            event_id = event_id or oids.event_id_for(
                candidate.candidate_id, attempt_number, AuditEventType.ERROR_OCCURRED
            )
        elif evidence_id is None or event_id is None:
            raise DomainValidationError(
                "StageRecorder.record_error: an error without a candidate needs its ids"
            )
        stored = self._record(
            uow,
            kind=EvidenceKind.ERROR,
            event_name="error.occurred",
            payload=payload,
            evidence_id=evidence_id,
            at=at,
            source_reference=stage,
            candidate=bound,
            state_hash=hash_of,
        )
        self.emit(
            uow,
            AuditEventType.ERROR_OCCURRED,
            event_id=event_id,
            payload={"evidence_id": stored, "stage": stage, "error_type": error_type},
            when=when,
            candidate_id=candidate.candidate_id if candidate is not None else None,
        )
        return stored

    @staticmethod
    def _belongs(
        candidate_id: str, parent_state_id: str, candidate: CandidateState, what: str
    ) -> None:
        if candidate_id != candidate.candidate_id or parent_state_id != candidate.parent_state_id:
            raise DomainValidationError(f"StageRecorder: the {what} is of another candidate")
