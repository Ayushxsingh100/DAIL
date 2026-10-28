"""The verification engine (Doc 09 §3-§18, §37; registry §2.4, §2.8, §2.10; C-144 to C-148).

``run_work_set`` answers every work item the impact report lists, adds the mandatory STRUCTURAL and
CONSISTENCY items, and returns a ``VerificationReport``. ``verify_work_item`` answers one request.
Both are pure: the clock and the id source are injected, nothing reads the wall clock or draws
randomness, and the same inputs with the same injected values give the same report.

**Fail closed.**

* An exception inside a verifier, a verifier that returns something that is not a
  ``PredicateOutcome``, and an outcome the result record refuses (clauses that disagree with the
  result) all become VERIFIER_ERROR for that item, with ``error = {type, message, class}`` and the
  usual metadata. They are never FAIL and never PASS. ``KeyboardInterrupt`` and ``SystemExit`` are
  not caught.
* Malformed inputs (``VerificationInputError``) stop the run before any item runs.
* A construction status that is not OK makes every invariant and baseline item UNSUPPORTED
  ``construction.invalid``; no predicate runs (registry §2.8).
* An invariant the definitions do not have is UNSUPPORTED ``invariant.unknown``; a verifier pair
  the table does not have is UNSUPPORTED ``verifier.not_available`` (the table of P5b has the three
  registry verifiers).

``verifier_invocations`` counts verifier executions: the predicates, the baseline checks and the two
gates, including executions that raised. Items answered without running a verifier are not counted.

``to_evidence_submission`` builds the evidence record of one result (Doc 11 §25, registry §2.10). It
persists nothing; the caller (the evidence service, P6) does.

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from core.domain.enums import ProvenanceSourceKind, VerificationResult
from core.domain.errors import DomainValidationError
from core.domain.evidence import EvidenceKind, EvidenceSubmission, EvidenceValidity
from core.domain.hashing import canonical_json
from core.domain.ids import new_uuid
from core.domain.impact import VerificationWorkItem, WorkTargetType
from core.domain.invariant import Invariant
from core.domain.jsonvalue import iso_utc, thaw_json
from core.domain.values import Provenance
from core.domain.verification import (
    ConstructionStatus,
    VerificationClass,
    VerificationReason,
    VerificationReport,
    VerificationRequest,
    VerificationResultRecord,
    VerificationTargetType,
)
from core.verification.baseline import BASELINE_VERIFIER, baseline_verifier, verify_baseline
from core.verification.dispatch import DEFAULT_VERIFIERS, VerifierTable
from core.verification.errors import VerificationInputError
from core.verification.inputs import VerificationInputs
from core.verification.outcome import PredicateOutcome
from core.verification.structural import consistency_gate, structural_gate

VERIFIER_SET_VERSION: Final = "dail-verify-1"
STRUCTURAL_ID: Final = "STRUCTURAL"
CONSISTENCY_ID: Final = "CONSISTENCY"
STRUCTURAL_VERIFIER: Final = ("dail.verify.structural", "1")
CONSISTENCY_VERIFIER: Final = ("dail.verify.consistency", "1")
UNAVAILABLE_VERIFIER: Final = ("dail.verify.unavailable", "0")  # named by no definition
EVENT_NAME: Final = "verification.result"
MAX_ERROR_MESSAGE: Final = 500

Clock = Callable[[], datetime]
Ids = Callable[[], str]
R = VerificationReason
P, S, E = (
    VerificationResult.PASS,
    VerificationResult.UNSUPPORTED,
    VerificationResult.VERIFIER_ERROR,
)


@dataclass(frozen=True, slots=True)
class _Plan:
    """What an item is, decided before anything runs (and without anything that can raise)."""

    kind: VerificationTargetType
    target_id: str
    invariant_id: str | None
    invariant_version: int | None
    definition: Invariant | None
    verification_class: VerificationClass
    level: str
    verifier: tuple[str, str]


@dataclass(frozen=True, slots=True)
class _Evaluation:
    result: VerificationResult
    reason: VerificationReason | None
    clauses: Any
    observations: dict[str, Any]
    assumptions: tuple[str, ...]
    applicable: bool
    verifier: tuple[str, str]


def _parse_invariant(target_id: str) -> tuple[str, int] | None:
    _, _, rest = target_id.partition(":")
    invariant_id, _, version = rest.rpartition(":")
    if not invariant_id or not version.isdigit():
        return None
    return invariant_id, int(version)


def _plan(request: VerificationRequest, inputs: VerificationInputs) -> _Plan:
    kind = request.target_type
    request_verifier = (request.verifier_id, request.verifier_version)
    if kind is VerificationTargetType.INVARIANT:
        parsed = _parse_invariant(request.target_id)
        if parsed is None:
            raise VerificationInputError(f"{request.target_id!r} is not INVARIANT:<id>:<version>")
        definition = inputs.invariant(*parsed)
        if definition is None:
            return _Plan(
                kind,
                request.target_id,
                parsed[0],
                parsed[1],
                None,
                VerificationClass.STRUCTURAL,
                "L1",
                request_verifier,
            )
        category = (
            VerificationClass.SECURITY
            if definition.category.value == "SECURITY"
            else VerificationClass.FUNCTIONAL
        )
        return _Plan(
            kind,
            request.target_id,
            definition.invariant_id,
            definition.version,
            definition,
            category,
            "L1",
            (definition.verifier_id, definition.verifier_version),
        )
    if kind is VerificationTargetType.RESOURCE:
        return _Plan(
            kind,
            request.target_id,
            None,
            None,
            None,
            VerificationClass.BASELINE,
            "L1",
            request_verifier,
        )
    consistency = request.target_id == CONSISTENCY_ID
    return _Plan(
        kind,
        request.target_id,
        None,
        None,
        None,
        VerificationClass.CONSISTENCY if consistency else VerificationClass.STRUCTURAL,
        "L0",
        CONSISTENCY_VERIFIER if consistency else STRUCTURAL_VERIFIER,
    )


def _check_request(request: object, inputs: object) -> None:
    if not isinstance(request, VerificationRequest):
        raise VerificationInputError("request must be a VerificationRequest")
    if not isinstance(inputs, VerificationInputs):
        raise VerificationInputError("inputs must be VerificationInputs")
    if request.candidate_id != inputs.candidate_id:
        raise VerificationInputError("the request is for another candidate")
    if request.candidate_hash != inputs.candidate_state_hash:
        raise VerificationInputError("the request is for another candidate state hash")
    if request.target_type is VerificationTargetType.INVARIANT:
        plan = _plan(request, inputs)
        if plan.definition is not None and plan.verifier != (
            request.verifier_id,
            request.verifier_version,
        ):
            raise VerificationInputError(
                "the request names a verifier other than the one in the definition"
            )


def _unsupported(
    plan: _Plan, reason: VerificationReason, observations: dict[str, Any]
) -> _Evaluation:
    return _Evaluation(S, reason, None, observations, (), True, plan.verifier)


def _gate_observations(outcome: PredicateOutcome) -> dict[str, Any]:
    return {**outcome.observations, "work_reason": "MANDATORY_GATE", "priority": "BLOCKING"}


def _evaluate(
    plan: _Plan,
    inputs: VerificationInputs,
    verifiers: VerifierTable,
    work: Sequence[VerificationWorkItem],
    results: Sequence[VerificationResultRecord],
    ran: list[bool],
) -> _Evaluation:
    kind = plan.kind
    if (
        kind in (VerificationTargetType.INVARIANT, VerificationTargetType.RESOURCE)
        and inputs.construction is not ConstructionStatus.OK
    ):
        return _unsupported(
            plan,
            R.CONSTRUCTION_INVALID,
            {"construction": inputs.construction.value, "note": inputs.construction_note},
        )
    if kind is VerificationTargetType.INVARIANT:
        definition = plan.definition
        if definition is None:
            return _unsupported(plan, R.INVARIANT_UNKNOWN, {"invariant": plan.target_id})
        verifier = verifiers.get(plan.verifier)
        if verifier is None:
            return _unsupported(
                plan,
                R.VERIFIER_NOT_AVAILABLE,
                {"verifier_id": plan.verifier[0], "verifier_version": plan.verifier[1]},
            )
        ran[0] = True
        outcome = verifier(definition, inputs)
        return _from_outcome(plan, outcome)
    if kind is VerificationTargetType.RESOURCE:
        ran[0] = True
        baseline = verify_baseline(plan.target_id.removeprefix("RESOURCE:"), inputs)
        return _Evaluation(
            baseline.result,
            baseline.reason,
            None,
            baseline.observations,
            baseline.assumptions,
            baseline.applicable,
            (baseline.verifier_id, baseline.verifier_version),
        )
    if kind is VerificationTargetType.STRUCTURAL and plan.target_id == STRUCTURAL_ID:
        ran[0] = True
        gate = structural_gate(inputs, work)
        return _Evaluation(
            gate.result,
            gate.reason,
            None,
            _gate_observations(gate),
            gate.assumptions,
            True,
            plan.verifier,
        )
    if kind is VerificationTargetType.STRUCTURAL and plan.target_id == CONSISTENCY_ID:
        ran[0] = True
        gate = consistency_gate(inputs, results)
        return _Evaluation(
            gate.result,
            gate.reason,
            None,
            _gate_observations(gate),
            gate.assumptions,
            True,
            plan.verifier,
        )
    return _unsupported(plan, R.VERIFIER_NOT_AVAILABLE, {"target": plan.target_id})


def _from_outcome(plan: _Plan, outcome: object) -> _Evaluation:
    if not isinstance(outcome, PredicateOutcome):
        raise TypeError(f"a verifier returned {type(outcome).__name__}, not a PredicateOutcome")
    return _Evaluation(
        outcome.result,
        outcome.reason,
        outcome.clauses,
        dict(outcome.observations),
        tuple(outcome.assumptions),
        True,
        plan.verifier,
    )


def _inputs_description(plan: _Plan, inputs: VerificationInputs) -> list[dict[str, Any]]:
    described: list[dict[str, Any]] = [
        {
            "kind": "candidate_state",
            "hash": inputs.candidate_state_hash,
            "resources": len(inputs.candidate_resources),
        }
    ]
    if inputs.parent_state_id is not None:
        described.append({"kind": "parent_state", "state_id": inputs.parent_state_id})
    if inputs.identity is not None:
        described.append({"kind": "identity_report", "hash": inputs.identity.content_hash})
    if inputs.impact is not None:
        described.append({"kind": "impact_report", "hash": inputs.impact.content_hash})
    if plan.definition is not None:
        described.append(
            {
                "kind": "invariant_definition",
                "id": plan.definition.invariant_id,
                "version": plan.definition.version,
                "hash": plan.definition.definition_hash(),
            }
        )
    return described


def _predicate_text(plan: _Plan) -> str:
    if plan.definition is None:
        return plan.target_id
    predicate = plan.definition.predicate
    parameters = thaw_json(predicate.get("parameters", {}))
    return f"registry-v1.0 {predicate.get('section', '')} {canonical_json(parameters)}"


def _evidence(
    plan: _Plan,
    evaluation: _Evaluation,
    request: VerificationRequest,
    inputs: VerificationInputs,
    verification_id: str,
    started: datetime,
    completed: datetime,
    error: dict[str, str] | None,
) -> dict[str, Any]:
    clauses = (
        None
        if evaluation.clauses is None
        else {name: evaluation.clauses[name].value for name in ("IPV4", "IPV6")}
    )
    return {
        "verification_id": verification_id,
        "invariant_id": plan.invariant_id,
        "invariant_version": plan.invariant_version,
        "candidate_id": request.candidate_id,
        "candidate_hash": request.candidate_hash,
        "target_id": plan.target_id,
        "verifier_id": evaluation.verifier[0],
        "verifier_version": evaluation.verifier[1],
        "evidence_level": plan.level,
        "predicate": _predicate_text(plan),
        "inputs": _inputs_description(plan, inputs),
        "observations": evaluation.observations,
        "result": evaluation.result.value,
        "reason": None if evaluation.reason is None else evaluation.reason.value,
        "applicable": evaluation.applicable,
        "clauses": clauses,
        "assumptions": list(evaluation.assumptions),
        "evidence_refs": [],
        "error": error,
        "started_at": iso_utc(started),
        "completed_at": iso_utc(completed),
    }


def _record(
    plan: _Plan,
    evaluation: _Evaluation,
    request: VerificationRequest,
    inputs: VerificationInputs,
    verification_id: str,
    started: datetime,
    completed: datetime,
    error: dict[str, str] | None,
) -> VerificationResultRecord:
    return VerificationResultRecord(
        verification_id=verification_id,
        request_id=request.request_id,
        target_type=plan.kind,
        target_id=plan.target_id,
        candidate_id=request.candidate_id,
        candidate_hash=request.candidate_hash,
        invariant_id=plan.invariant_id,
        invariant_version=plan.invariant_version,
        verifier_id=evaluation.verifier[0],
        verifier_version=evaluation.verifier[1],
        evidence_level=plan.level,
        verification_class=plan.verification_class,
        result=evaluation.result,
        reason=evaluation.reason,
        applicable=evaluation.applicable,
        clauses=evaluation.clauses,
        observations=evaluation.observations,
        assumptions=evaluation.assumptions,
        evidence=_evidence(
            plan, evaluation, request, inputs, verification_id, started, completed, error
        ),
        error=error,
        started_at=started,
        completed_at=completed,
    )


def _run_item(
    request: object,
    inputs: object,
    *,
    clock: Clock,
    ids: Ids,
    verifiers: VerifierTable,
    work: Sequence[VerificationWorkItem],
    results: Sequence[VerificationResultRecord],
) -> tuple[VerificationResultRecord, bool]:
    _check_request(request, inputs)
    assert isinstance(request, VerificationRequest) and isinstance(inputs, VerificationInputs)
    plan = _plan(request, inputs)
    verification_id = ids()
    ran = [False]
    started = clock()
    evaluation: _Evaluation | None = None
    failure: Exception | None = None
    try:
        evaluation = _evaluate(plan, inputs, verifiers, work, results, ran)
    except Exception as error:  # a verifier fault; KeyboardInterrupt and SystemExit propagate
        failure = error
    completed = clock()
    record: VerificationResultRecord | None = None
    if failure is None and evaluation is not None:
        try:
            record = _record(
                plan, evaluation, request, inputs, verification_id, started, completed, None
            )
        except Exception as error:  # an outcome the record refuses is a verifier fault too
            failure = error
    if record is None:
        message = str(failure)[:MAX_ERROR_MESSAGE] or type(failure).__name__
        details = {
            "type": type(failure).__name__,
            "message": message,
            "class": plan.verification_class.value,
        }
        faulty = _Evaluation(E, R.VERIFIER_ERROR, None, {}, (), True, plan.verifier)
        record = _record(
            plan, faulty, request, inputs, verification_id, started, completed, details
        )
    return record, ran[0]


def verify_work_item(
    request: VerificationRequest,
    inputs: VerificationInputs,
    *,
    clock: Clock,
    ids: Ids = new_uuid,
    verifiers: VerifierTable = DEFAULT_VERIFIERS,
    work: Iterable[VerificationWorkItem] = (),
    results: Iterable[VerificationResultRecord] = (),
) -> VerificationResultRecord:
    """The result for one request. ``work`` and ``results`` are only read by the STRUCTURAL and
    CONSISTENCY items."""
    record, _ = _run_item(
        request,
        inputs,
        clock=clock,
        ids=ids,
        verifiers=verifiers,
        work=tuple(work),
        results=tuple(results),
    )
    return record


def _request_for(
    item: VerificationWorkItem, inputs: VerificationInputs, ids: Ids
) -> VerificationRequest:
    state = inputs.parent_state_id or inputs.candidate_id
    if item.target_type is WorkTargetType.INVARIANT:
        parsed = _parse_invariant(item.target_id)
        definition = None if parsed is None else inputs.invariant(*parsed)
        verifier = (
            UNAVAILABLE_VERIFIER
            if definition is None
            else (definition.verifier_id, definition.verifier_version)
        )
        refs = () if parsed is None else (f"{parsed[0]}:{parsed[1]}",)
        kind = VerificationTargetType.INVARIANT
    else:
        address = item.target_id.removeprefix("RESOURCE:")
        resource = next((r for r in inputs.candidate_resources if r.address == address), None)
        verifier = (
            BASELINE_VERIFIER
            if resource is None
            else baseline_verifier(inputs, resource.resource_type) or BASELINE_VERIFIER
        )
        refs = ()
        kind = VerificationTargetType.RESOURCE
    return VerificationRequest(
        request_id=ids(),
        candidate_id=inputs.candidate_id,
        state_id=state,
        candidate_hash=inputs.candidate_state_hash,
        target_id=item.target_id,
        target_type=kind,
        invariant_refs=refs,
        verification_scope=item.scope,
        verifier_id=verifier[0],
        verifier_version=verifier[1],
    )


def _gate_request(target: str, inputs: VerificationInputs, ids: Ids) -> VerificationRequest:
    verifier = CONSISTENCY_VERIFIER if target == CONSISTENCY_ID else STRUCTURAL_VERIFIER
    return VerificationRequest(
        request_id=ids(),
        candidate_id=inputs.candidate_id,
        state_id=inputs.parent_state_id or inputs.candidate_id,
        candidate_hash=inputs.candidate_state_hash,
        target_id=target,
        target_type=VerificationTargetType.STRUCTURAL,
        invariant_refs=(),
        verification_scope=(),
        verifier_id=verifier[0],
        verifier_version=verifier[1],
    )


def run_work_set(
    work_items: Iterable[VerificationWorkItem],
    inputs: VerificationInputs,
    *,
    clock: Clock,
    ids: Ids,
    verifiers: VerifierTable = DEFAULT_VERIFIERS,
) -> VerificationReport:
    """Answer every work item, add the mandatory gate items, and report (Doc 09 §3, §6)."""
    if not isinstance(inputs, VerificationInputs):
        raise VerificationInputError("inputs must be VerificationInputs")
    if isinstance(work_items, str | bytes) or not isinstance(work_items, Iterable):
        raise VerificationInputError("work_items must be a list of VerificationWorkItem")
    work = tuple(work_items)
    if not all(isinstance(item, VerificationWorkItem) for item in work):
        raise VerificationInputError("work_items must hold only VerificationWorkItem objects")
    targets = [item.target_id for item in work]
    if len(set(targets)) != len(targets):
        raise VerificationInputError("a target is in the work set twice")
    ordered = sorted(work, key=VerificationWorkItem.sort_key)
    results: list[VerificationResultRecord] = []
    invocations = 0

    def answer(
        request: VerificationRequest, *, gate_work: Sequence[VerificationWorkItem] = ()
    ) -> None:
        nonlocal invocations
        record, ran = _run_item(
            request,
            inputs,
            clock=clock,
            ids=ids,
            verifiers=verifiers,
            work=gate_work,
            results=tuple(results),
        )
        results.append(record)
        invocations += ran

    for item in ordered:
        answer(_request_for(item, inputs, ids))
    answer(_gate_request(STRUCTURAL_ID, inputs, ids), gate_work=ordered)
    answer(_gate_request(CONSISTENCY_ID, inputs, ids))
    return VerificationReport.create(
        candidate_id=inputs.candidate_id,
        candidate_hash=inputs.candidate_state_hash,
        results=results,
        verifier_invocations=invocations,
        verifier_set_version=VERIFIER_SET_VERSION,
        report_id=ids(),
    )


def to_evidence_submission(
    result: VerificationResultRecord,
    *,
    evidence_id: str,
    run_id: str,
    attempt_id: str | None,
    correlation_id: str,
    operation_id: str,
    parent_state_id: str | None,
    state_id: str | None = None,
    created_at: datetime | None = None,
    validity: EvidenceValidity = EvidenceValidity.VALID,
) -> EvidenceSubmission:
    """The evidence record of one result (kind VERIFICATION; Doc 11 §8, §9, §25).

    With a ``parent_state_id`` the record is bound to the candidate (it then needs ``attempt_id``,
    Doc 11 §9). Without one, a baseline, it is bound to ``state_id`` and carries the state hash. A
    field that cannot be filled raises ``DomainValidationError``; nothing is invented. The payload
    is the result's own evidence payload, so it is the same text the report was built from."""
    if parent_state_id is None and state_id is None:
        raise DomainValidationError(
            "to_evidence_submission: a result without a parent state needs the state it is "
            "bound to (state_id); neither was given"
        )
    candidate_bound = parent_state_id is not None
    provenance = Provenance(
        source_kind=ProvenanceSourceKind.DERIVED,
        source_component="core.verification",
        source_reference=result.target_id,
        observed_at=result.completed_at,
        tool_name=result.verifier_id,
        tool_version=result.verifier_version,
        algorithm_version=result.verifier_version,
    )
    return EvidenceSubmission.create(
        payload=thaw_json(result.evidence),
        evidence_id=evidence_id,
        run_id=run_id,
        attempt_id=attempt_id,
        correlation_id=correlation_id,
        operation_id=operation_id,
        kind=EvidenceKind.VERIFICATION,
        event_name=EVENT_NAME,
        provenance=provenance,
        created_at=result.completed_at if created_at is None else created_at,
        state_id=None if candidate_bound else state_id,
        candidate_id=result.candidate_id if candidate_bound else None,
        parent_state_id=parent_state_id,
        state_hash=result.candidate_hash,
        validity=validity,
    )
