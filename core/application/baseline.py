"""Baseline establishment: the first Trusted State of a lineage (P6c step 3; Doc 06 §24, Doc 13 §13;
Doc 11 §8, §44; C-30, C-32, C-59, C-171, C-176).

Doc 06 §24: before repair begins the system establishes an initial Trusted State and its protected
invariants. ``establish_baseline`` does it for one directory:

    normalize the directory, build its graph, verify **every** invariant of the definitions against
    it, map each result to a status (C-30), build the proofs, create version 0, and write, in one
    unit of work, the definitions, one VERIFICATION record per result, the state and its lineage
    head, and ``STATE_CREATED``.

**Acceptance protocol (C-171, conservative; the specification leaves it to the experiment
protocol).** The baseline is created only if normalization is OK and yields resources, the
STRUCTURAL and CONSISTENCY gates PASS, no result is VERIFIER_ERROR, the request declares the fixture
eligible (Doc 13 §13), and the lineage has no baseline yet. Otherwise ``BaselineRefused`` is
raised, fail closed, and the only things stored are one ERROR record and one ERROR_OCCURRED event.
A VIOLATED or UNCERTAIN invariant is **accepted and recorded as it is**, never as PROTECTED: the
canonical scenario starts from public SSH.

**The evidence carries the state's own hash (C-176).** ``to_evidence_submission`` stamps a result
with the hash of the resource set it verified; evidence about a *state* must carry that state's
``state_hash`` (Doc 11 §8, §44), and P6b's binding check compares exactly that value when a later
candidate carries an invariant forward from version 0 (``evaluate_proof`` condition P6). So the
baseline builds its submissions here, from the same result payload, once the state (and so its hash,
which does not depend on evidence ids) exists.

**Idempotent.** Every id derives from ``baseline_id`` (``core.application.ids``), so a second call
is a duplicate: it rewrites nothing, returns the stored state with ``duplicate=True``, and raises
``ConflictingDuplicateError`` if the same ``baseline_id`` now describes another state. The only
caller of ``save_baseline`` in the repository (C-175).

Time is the request's ``now``; the module reads no clock (R6 of the P6c prompt).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from core.application import ids as oids
from core.application.recorder import StageRecorder
from core.dependency.build import build_graph
from core.dependency.invariants import SemanticBinding
from core.domain.audit import AuditEventType
from core.domain.enums import (
    InvariantStatus,
    ProvenanceSourceKind,
    VerificationResult,
)
from core.domain.errors import DomainValidationError
from core.domain.evidence import EvidenceKind, EvidenceSubmission
from core.domain.hashing import content_hash
from core.domain.ids import require_uuid
from core.domain.impact import ReasonCode, VerificationWorkItem, WorkPriority, WorkTargetType
from core.domain.invariant import Invariant, InvariantProof
from core.domain.jsonvalue import thaw_json, utc
from core.domain.lifecycle import RESULT_TO_STATUS
from core.domain.promotion import ConflictingDuplicateError
from core.domain.repositories import UnitOfWork
from core.domain.state import TrustedState
from core.domain.values import Provenance
from core.domain.verification import (
    ConstructionStatus,
    VerificationReport,
    VerificationResultRecord,
)
from core.promotion.commit import PromotionContext
from core.terraform_model.normalization import normalize_directory
from core.verification.dispatch import DEFAULT_VERIFIERS, VerifierTable
from core.verification.engine import (
    CONSISTENCY_ID,
    EVENT_NAME,
    STRUCTURAL_ID,
    run_work_set,
)
from core.verification.inputs import VerificationInputs

_GATES = (STRUCTURAL_ID, CONSISTENCY_ID)
_MAX_DIAGNOSTICS = 10
_MAX_TEXT = 300


class BaselineRefused(DomainValidationError):
    """The baseline was not established (C-171). ``reasons`` lists every cause found; nothing was
    stored but one ERROR record and one ERROR_OCCURRED event."""

    def __init__(self, reasons: Sequence[str]) -> None:
        self.reasons = tuple(reasons)
        super().__init__("the baseline was refused: " + "; ".join(self.reasons))


@dataclass(frozen=True)
class BaselineRequest:
    """What to establish. ``eligible`` is the caller's declaration that the fixture may serve as a
    baseline (Doc 13 §13); ``now`` is the one instant used for everything that is hashed."""

    baseline_id: str
    lineage_id: str
    baseline_dir: Path
    variables: Mapping[str, object] | None
    definitions: tuple[Invariant, ...]
    bindings: tuple[SemanticBinding, ...]
    context: PromotionContext
    now: datetime
    eligible: bool
    verifiers: VerifierTable = DEFAULT_VERIFIERS
    registry_version: int = 1

    def __post_init__(self) -> None:
        require_uuid(self.baseline_id, "BaselineRequest.baseline_id")
        require_uuid(self.lineage_id, "BaselineRequest.lineage_id")
        if not isinstance(self.baseline_dir, Path):
            raise DomainValidationError("BaselineRequest.baseline_dir must be a Path")
        if not isinstance(self.eligible, bool):
            raise DomainValidationError("BaselineRequest.eligible must be a bool")
        if not isinstance(self.context, PromotionContext):
            raise DomainValidationError("BaselineRequest.context must be a PromotionContext")
        definitions = tuple(self.definitions)
        if not definitions or not all(isinstance(d, Invariant) for d in definitions):
            raise DomainValidationError("BaselineRequest.definitions must hold Invariant objects")
        bindings = tuple(self.bindings)
        if not all(isinstance(b, SemanticBinding) for b in bindings):
            raise DomainValidationError("BaselineRequest.bindings must hold SemanticBinding")
        object.__setattr__(self, "definitions", definitions)
        object.__setattr__(self, "bindings", bindings)
        object.__setattr__(self, "now", utc(self.now, "BaselineRequest.now"))


@dataclass(frozen=True)
class BaselineResult:
    """Version 0, the verification report it rests on, the evidence id of each result (by
    ``verification_id``), the status given to each invariant, and whether it already existed."""

    state: TrustedState
    report: VerificationReport
    evidence_ids: Mapping[str, str]
    statuses: Mapping[str, InvariantStatus]
    duplicate: bool


class _Refuse(Exception):
    def __init__(self, reasons: Sequence[str]) -> None:
        self.reasons = tuple(reasons)
        super().__init__("; ".join(self.reasons))


def _clip(text: str) -> str:
    return text if len(text) <= _MAX_TEXT else text[: _MAX_TEXT - 3] + "..."


def establish_baseline(
    factory: Callable[[], UnitOfWork], request: BaselineRequest
) -> BaselineResult:
    """Establish version 0 of ``request.lineage_id`` (see the module docstring).

    ``factory`` opens a unit of work. Raises ``BaselineRefused`` for a refusal,
    ``ConflictingDuplicateError`` when the baseline id already names another state or record, and
    lets an infrastructure failure propagate after the write has rolled back."""
    if not callable(factory):
        raise DomainValidationError("establish_baseline: factory must open a unit of work")
    if not isinstance(request, BaselineRequest):
        raise DomainValidationError("establish_baseline: request must be a BaselineRequest")
    recorder = StageRecorder(request.context)
    try:
        prepared = _prepare(request)
        with factory() as uow:
            return _write(uow, recorder, request, prepared)
    except _Refuse as refusal:
        _record_refusal(factory, recorder, request, refusal.reasons)
        raise BaselineRefused(refusal.reasons) from None


# --- the verification of the baseline ----------------------------------------------------------


@dataclass(frozen=True)
class _Prepared:
    state_id: str
    resources: Any
    normalization_version: str
    report: VerificationReport
    statuses: Mapping[str, InvariantStatus]
    evidence_ids: Mapping[str, str]
    results: Mapping[str, VerificationResultRecord]


def _prepare(request: BaselineRequest) -> _Prepared:
    """Everything that can be decided before anything is written; raises ``_Refuse``."""
    if not request.eligible:
        raise _Refuse(["the fixture is not declared eligible as a baseline (Doc 13 §13)"])
    state_id = oids.baseline_state_id_for(request.baseline_id)
    outcome = normalize_directory(request.baseline_dir, request.variables, now=request.now)
    if outcome.status.value != "OK" or outcome.resource_set_hash is None:
        shown = [_clip(f"{d.code}: {d.message}") for d in outcome.diagnostics[:_MAX_DIAGNOSTICS]]
        raise _Refuse([f"normalization is not OK (status {outcome.status.value})", *shown])
    if not outcome.resources:
        raise _Refuse(["the baseline has no resource to verify"])
    graph = build_graph(
        outcome.resources, request.definitions, request.bindings, state_id=state_id, now=request.now
    )
    inputs = VerificationInputs(
        candidate_resources=outcome.resources,
        parent_resources=None,
        candidate_state_hash=outcome.resource_set_hash,
        normalization_version=outcome.normalization_version,
        candidate_id=state_id,
        parent_state_id=None,
        identity=None,
        impact=None,
        candidate_graph=graph,
        trusted_graph=None,
        invariants=request.definitions,
        construction=ConstructionStatus.OK,
    )
    scope = tuple(sorted(r.address for r in outcome.resources))
    work = [
        VerificationWorkItem(
            target_id=f"INVARIANT:{d.invariant_id}:{d.version}",
            target_type=WorkTargetType.INVARIANT,
            reason=ReasonCode.CREATED_IN_SCOPE,  # every resource of a baseline is new to it
            scope=scope,
            required_evidence="L1",
            priority=WorkPriority.BLOCKING,
        )
        for d in request.definitions
    ]
    instant = request.now
    report = run_work_set(
        work,
        inputs,
        clock=lambda: instant,
        ids=oids.baseline_verification_ids(request.baseline_id),
        verifiers=request.verifiers,
    )
    results = {r.target_id: r for r in report.results}
    reasons = _acceptance_problems(report, results)
    if reasons:
        raise _Refuse(reasons)
    statuses = {
        d.invariant_id: RESULT_TO_STATUS[results[f"INVARIANT:{d.invariant_id}:{d.version}"].result]
        for d in request.definitions
    }
    evidence_ids = {
        r.verification_id: oids.baseline_evidence_id_for(
            request.baseline_id, "verification", r.target_id
        )
        for r in report.results
    }
    return _Prepared(
        state_id,
        outcome.resources,
        outcome.normalization_version,
        report,
        statuses,
        evidence_ids,
        results,
    )


def _acceptance_problems(
    report: VerificationReport, results: Mapping[str, VerificationResultRecord]
) -> list[str]:
    """Acceptance conditions (b) and (c) of C-171."""
    reasons = []
    for gate in _GATES:
        record = results.get(gate)
        if record is None or record.result is not VerificationResult.PASS:
            shown = "missing" if record is None else record.result.value
            reasons.append(f"the {gate} gate is {shown}, not PASS")
    for record in report.results:
        if record.result is VerificationResult.VERIFIER_ERROR:
            reasons.append(f"{record.target_id}: VERIFIER_ERROR")
    return reasons


# --- the write ---------------------------------------------------------------------------------


def _submission(
    result: VerificationResultRecord,
    evidence_id: str,
    context: PromotionContext,
    state: TrustedState,
) -> EvidenceSubmission:
    """The VERIFICATION record of one result, bound to the baseline state and carrying its hash
    (C-176). Same payload, kind, event name and provenance as ``to_evidence_submission``."""
    return EvidenceSubmission.create(
        payload=thaw_json(result.evidence),
        evidence_id=evidence_id,
        run_id=context.run_id,
        attempt_id=context.attempt_id,
        correlation_id=context.correlation_id,
        operation_id=context.operation_id,
        kind=EvidenceKind.VERIFICATION,
        event_name=EVENT_NAME,
        provenance=Provenance(
            source_kind=ProvenanceSourceKind.DERIVED,
            source_component="core.verification",
            source_reference=result.target_id,
            observed_at=result.completed_at,
            tool_name=result.verifier_id,
            tool_version=result.verifier_version,
            algorithm_version=result.verifier_version,
        ),
        created_at=result.completed_at,
        state_id=state.state_id,
        state_hash=state.state_hash,
    )


def _register(uow: UnitOfWork, definitions: Sequence[Invariant]) -> None:
    for definition in definitions:
        stored = uow.invariants.get_definition(definition.invariant_id, definition.version)
        if stored is None:
            uow.invariants.register_definition(definition)
        elif stored.definition_hash() != definition.definition_hash():
            raise ConflictingDuplicateError(
                f"{definition.invariant_id} v{definition.version} is already registered with "
                "another definition (Doc 06 §4.2)"
            )


def _write(
    uow: UnitOfWork, recorder: StageRecorder, request: BaselineRequest, prepared: _Prepared
) -> BaselineResult:
    head = uow.trusted_states.get_current(request.lineage_id)
    existing = uow.trusted_states.get(prepared.state_id)
    if head is not None and head.state_id != prepared.state_id:
        raise _Refuse([f"lineage {request.lineage_id} already has a baseline (SM-001)"])
    proofs = [
        InvariantProof.for_baseline(
            invariant_id=d.invariant_id,
            invariant_version=d.version,
            status=prepared.statuses[d.invariant_id],
            evidence_ids=(
                prepared.evidence_ids[
                    prepared.results[f"INVARIANT:{d.invariant_id}:{d.version}"].verification_id
                ],
            ),
            verified_at=request.now,
        )
        for d in request.definitions
    ]
    state = TrustedState.establish_baseline(
        lineage_id=request.lineage_id,
        resources=prepared.resources,
        invariant_proofs=proofs,
        evidence_refs=sorted({e for proof in proofs for e in proof.evidence_ids}),
        normalization_version=prepared.normalization_version,
        invariant_registry_version=request.registry_version,
        now=request.now,
        state_id=prepared.state_id,
    )
    if existing is not None and (
        existing.state_hash != state.state_hash or existing.lineage_id != state.lineage_id
    ):
        raise ConflictingDuplicateError(
            f"baseline {request.baseline_id} already names state {existing.state_id} with "
            "another content (Doc 11 §38)"
        )
    _register(uow, request.definitions)
    for record in prepared.report.results:
        recorder.append(
            uow,
            _submission(
                record, prepared.evidence_ids[record.verification_id], request.context, state
            ),
        )
    if existing is None:
        uow.trusted_states.save_baseline(state)
    recorder.emit(
        uow,
        AuditEventType.STATE_CREATED,
        event_id=oids.baseline_event_id_for(request.baseline_id, AuditEventType.STATE_CREATED),
        payload={
            "lineage_id": state.lineage_id,
            "version": 0,
            "parent_state_id": None,
            "state_hash": state.state_hash,
            "baseline_id": request.baseline_id,
        },
        when=request.now,
        state_id=state.state_id,
    )
    return BaselineResult(
        state=existing or state,
        report=prepared.report,
        evidence_ids=prepared.evidence_ids,
        statuses=prepared.statuses,
        duplicate=existing is not None,
    )


def _record_refusal(
    factory: Callable[[], UnitOfWork],
    recorder: StageRecorder,
    request: BaselineRequest,
    reasons: Sequence[str],
) -> None:
    """One ERROR record and one ERROR_OCCURRED event, keyed by the reasons so that the same refusal
    again is a duplicate and another refusal is a record of its own."""
    key = content_hash({"reasons": list(reasons)})[:32]
    with factory() as uow:
        recorder.record_error(
            uow,
            stage="baseline",
            error_type="BaselineRefused",
            detail={"baseline_id": request.baseline_id, "reasons": list(reasons)},
            attempt_number=1,
            at=request.now,
            when=request.now,
            evidence_id=oids.baseline_evidence_id_for(request.baseline_id, "error", key),
            event_id=oids.baseline_event_id_for(
                request.baseline_id, AuditEventType.ERROR_OCCURRED, key
            ),
        )
