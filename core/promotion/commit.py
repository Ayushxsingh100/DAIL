"""The promotion commit: the one place where a decision becomes Trusted State (P6b; Doc 09 §26, §27,
§38-§40, Appendix B; Doc 06 §20, §21, §27; Doc 05 §15, §22, §32; Doc 11 §26, §43; C-38, C-163 to
C-168).

``record_decision`` makes every decision durable (Doc 09 §40): it stores the decision, moves the
candidate along the exit of Doc 06 §5 that the decision names and appends the audit events. For a
PROMOTE the candidate becomes PROMOTABLE and nothing else changes: no trusted state is touched.

``commit_promotion`` turns a PROMOTE into the next Trusted State, once, from the current parent
only. In one unit of work (``BEGIN IMMEDIATE``, so the write lock is taken first, C-166):

    1. an existing decision with this id is a duplicate (C-163) or a conflict;
    2. the candidate and the current state are read from the database; a candidate whose parent is
       no longer the current state lost the race (C-38 case 1);
    3. ``decide`` is run again with the same inputs and must give the same decision and the same
       proof plan (C-167, Appendix B ``validate_decision``);
    4. the evidence of the plan is checked to bind to the new state (C-164, ``binding``);
    5. the proofs, the new state, the binding record and the committed decision are built; nothing
       is written yet, so a refusal here leaves no trace;
    6. writes, in this order, each a seam for a fault (``core.persistence.sqlite`` checkpoints):
       the decision (``after_decision_insert``), the binding record, the state and its references
       and the lineage head (``after_trusted_state_insert``, ``after_invariant_refs_insert``,
       ``after_lineage_head_update``), the decision committed to the state
       (``after_decision_commit``), the candidate PROMOTED (``after_candidate_update``), the
       STATE_PROMOTED event, ``before_commit``.

A refusal in 3 to 5 rolls everything back and escalates the candidate in a transaction of its own
(C-38 case 2); a lost race stores a REJECT decision and rejects the candidate in its own
transaction (C-38 case 1, C-166); any other failure rolls back, leaves the candidate PROMOTABLE and
raises ``PromotionCommitError`` after a best-effort PROMOTION_FAILED event (C-38 case 3). The
exception is never swallowed inside the transaction. This module is the only caller of
``TrustedState.promote`` and ``mark_promoted`` (R8). Standard library and ``core.domain`` only
(R18).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from core.domain.audit import ActorType, AuditEventType, AuditSubmission
from core.domain.enums import (
    CandidateStatus,
    DecisionType,
    ProvenanceSourceKind,
)
from core.domain.errors import DomainValidationError, PersistenceError, StaleParentError
from core.domain.evidence import EvidenceKind, EvidenceSubmission
from core.domain.ids import require_uuid
from core.domain.impact import ImpactReport
from core.domain.invariant import Invariant
from core.domain.jsonvalue import optional_text, utc
from core.domain.promotion import (
    BlockingCondition,
    ConflictingDuplicateError,
    DecisionOutcome,
    DecisionReason,
    OracleVerdict,
    PromotionDecision,
    PromotionInputError,
    PromotionPolicy,
    ProofPlanEntry,
    ProofSource,
)
from core.domain.repositories import UnitOfWork
from core.domain.state import (
    CandidateState,
    TrustedState,
    mark_promoted,
    transition_candidate,
)
from core.domain.values import Provenance
from core.domain.verification import VerificationReport
from core.promotion import ids
from core.promotion.binding import BINDING_EVENT_NAME, binding_payload, binding_problems
from core.promotion.decide import decide
from core.promotion.lifecycle import candidate_after
from core.promotion.newstate import promotion_arguments
from core.promotion.proofs import build_proofs, evaluate_from_results

D = DecisionType
R = DecisionReason

_COMPONENT = "core.promotion.commit"
_VERSION = "1"
_REASON_LIMIT = 500


class PromotionCommitError(PersistenceError):
    """The commit failed for a reason that is not a decision (a database error, an I/O error, an
    injected fault). Everything was rolled back; the candidate is still PROMOTABLE and the same
    commit may be retried (C-38 case 3, C-163)."""


@dataclass(frozen=True)
class PromotionContext:
    """Who is committing: the ids that tie the evidence and audit records to one workflow."""

    run_id: str
    correlation_id: str
    operation_id: str
    attempt_id: str
    actor_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("run_id", "correlation_id", "operation_id", "attempt_id"):
            require_uuid(getattr(self, name), f"PromotionContext.{name}")
        optional_text(self.actor_id, "PromotionContext.actor_id")


@dataclass(frozen=True)
class CommitResult:
    """What ``commit_promotion`` returns. ``state`` is the new Trusted State, or ``None`` when the
    commit did not promote. ``duplicate``: the decision had been committed before and nothing was
    written. ``stale``: the parent was no longer current, ``decision`` is the stored REJECT.
    ``escalated``: the decision no longer held, the candidate is ESCALATED."""

    decision: PromotionDecision
    state: TrustedState | None = None
    duplicate: bool = False
    stale: bool = False
    escalated: bool = False


class _Lost(Exception):
    """The candidate's parent is not the current state."""


class _Invalid(Exception):
    """The decision no longer holds, or its evidence does not bind (revalidation failure)."""


# --- audit events ---------------------------------------------------------------------------------


def _event(
    event_id: str,
    event_type: AuditEventType,
    context: PromotionContext,
    when: datetime,
    payload: Mapping[str, Any],
    *,
    state_id: str | None = None,
    candidate_id: str | None = None,
    decision_id: str | None = None,
) -> AuditSubmission:
    return AuditSubmission.create(
        event_id=event_id,
        event_type=event_type,
        correlation_id=context.correlation_id,
        operation_id=context.operation_id,
        timestamp=when,
        payload=dict(payload),
        actor_type=ActorType.SYSTEM,
        actor_id=context.actor_id,
        state_id=state_id,
        candidate_id=candidate_id,
        decision_id=decision_id,
    )


def _append_once(uow: UnitOfWork, submission: AuditSubmission) -> None:
    """Append unless the event is there: a retry must not trip over its own earlier event."""
    if uow.audit.get(submission.event_id) is None:
        uow.audit.append(submission)


def _decided_events(
    uow: UnitOfWork, decision: PromotionDecision, context: PromotionContext
) -> None:
    """PROMOTION_DECIDED, and for a non-PROMOTE the event Doc 11 §12 names."""
    base = {
        "candidate_id": decision.candidate_id,
        "decision_id": decision.decision_id,
    }
    _append_once(
        uow,
        _event(
            ids.decided_event_id_for(decision.decision_id),
            AuditEventType.PROMOTION_DECIDED,
            context,
            decision.created_at,
            {
                "parent_state_id": decision.parent_state_id,
                "decision": decision.decision.value,
                "reason": decision.reason.value,
                "policy_version": decision.policy_version,
                "attempt_number": decision.attempt_number,
            },
            **base,
        ),
    )
    outcome_id = ids.outcome_event_id_for(decision.decision_id)
    conditions = [c.to_dict() for c in decision.blocking_conditions]
    if decision.decision is D.REJECT:
        event = _event(
            outcome_id,
            AuditEventType.CANDIDATE_REJECTED,
            context,
            decision.created_at,
            {
                "parent_state_id": decision.parent_state_id,
                "reason": decision.reason.value,
                "blocking_conditions": conditions,
            },
            **base,
        )
    elif decision.decision is D.RETRY:
        event = _event(
            outcome_id,
            AuditEventType.RETRY_SCHEDULED,
            context,
            decision.created_at,
            {
                "attempt_id": context.attempt_id,
                "parent_state_id": decision.parent_state_id,
                "reason": decision.reason.value,
                "blocking_conditions": conditions,
            },
            **base,
        )
    elif decision.decision is D.ESCALATE:
        event = _event(
            outcome_id,
            AuditEventType.ESCALATED,
            context,
            decision.created_at,
            {"reason": decision.reason.value, "unresolved_conditions": conditions},
            **base,
        )
    else:
        return
    _append_once(uow, event)


# --- record_decision ------------------------------------------------------------------------------


def record_decision(
    uow: UnitOfWork,
    outcome: DecisionOutcome,
    candidate: CandidateState,
    context: PromotionContext,
    *,
    now: datetime,
) -> CandidateState:
    """Store the decision and move the candidate along its exit (Doc 09 §40; C-38).

    Every decision is stored with all its blocking conditions and every one moves the candidate:
    PROMOTE to PROMOTABLE, REJECT to REJECTED, RETRY to RETRY_REQUIRED, ESCALATE to ESCALATED. The
    trusted state is read and never written (SM-001, SM-003, SM-004). Recording the same decision
    again changes nothing; the same id with another content raises ``ConflictingDuplicateError``.
    ``uow`` is open; the caller's ``with`` commits. Returns the candidate as stored afterwards."""
    if not isinstance(outcome, DecisionOutcome):
        raise PromotionInputError("record_decision: outcome must be a DecisionOutcome")
    if not isinstance(candidate, CandidateState):
        raise PromotionInputError("record_decision: candidate must be a CandidateState")
    if not isinstance(context, PromotionContext):
        raise PromotionInputError("record_decision: context must be a PromotionContext")
    utc(now, "record_decision.now")
    decision = outcome.decision
    if decision.committed_state_id is not None:
        raise PromotionInputError("record_decision: a committed decision cannot be recorded again")
    if decision.candidate_id != candidate.candidate_id:
        raise PromotionInputError("record_decision: the decision is about another candidate")
    stored = uow.candidates.get(candidate.candidate_id)
    if stored is None:
        raise PromotionInputError("record_decision: the candidate is not stored")
    existing = uow.decisions.get(decision.decision_id)
    if existing is not None:
        if existing.content_hash != decision.content_hash and (
            existing.committed_state_id is None
            or existing.content_hash != decision.committed(existing.committed_state_id).content_hash
        ):
            raise ConflictingDuplicateError(
                f"decision {decision.decision_id} was already stored with different content "
                "(C-163, Doc 09 §38)"
            )
        return stored
    trusted = uow.trusted_states.get_current(stored.lineage_id)
    if trusted is None:
        raise PromotionInputError("record_decision: the candidate's lineage has no current state")
    moved = candidate_after(decision, stored, trusted)
    uow.decisions.save(decision)
    uow.candidates.save_transition(moved)
    _decided_events(uow, decision, context)
    return moved


# --- commit_promotion -----------------------------------------------------------------------------


def _check_arguments(
    factory: object,
    outcome: object,
    candidate: object,
    impact: object,
    verification: object,
    policy: object,
    evidence_ids: object,
    context: object,
) -> None:
    for value, kind, name in (
        (outcome, DecisionOutcome, "outcome"),
        (candidate, CandidateState, "candidate"),
        (impact, ImpactReport, "impact"),
        (verification, VerificationReport, "verification"),
        (policy, PromotionPolicy, "policy"),
        (context, PromotionContext, "context"),
    ):
        if not isinstance(value, kind):
            raise PromotionInputError(f"commit_promotion: {name} must be a {kind.__name__}")
    if not callable(factory):
        raise PromotionInputError("commit_promotion: factory must open a unit of work")
    if not isinstance(evidence_ids, Mapping):
        raise PromotionInputError("commit_promotion: evidence_ids must be a mapping")
    assert isinstance(outcome, DecisionOutcome) and isinstance(candidate, CandidateState)
    if outcome.decision.decision is not D.PROMOTE:
        raise PromotionInputError(
            f"commit_promotion: only a PROMOTE can be committed, not {outcome.decision.decision}"
        )
    if outcome.decision.committed_state_id is not None:
        raise PromotionInputError("commit_promotion: the outcome's decision is already committed")
    if outcome.decision.candidate_id != candidate.candidate_id:
        raise PromotionInputError("commit_promotion: the decision is about another candidate")


def commit_promotion(
    factory: Callable[[], UnitOfWork],
    outcome: DecisionOutcome,
    candidate: CandidateState,
    impact: ImpactReport,
    verification: VerificationReport,
    policy: PromotionPolicy,
    evidence_ids: Mapping[str, str],
    context: PromotionContext,
    *,
    now: datetime,
    attempt_number: int | None = None,
    oracle_verdicts: Iterable[OracleVerdict] = (),
) -> CommitResult:
    """Commit a PROMOTE decision as the next Trusted State, once (see the module docstring).

    ``factory`` opens a unit of work on the database; it is called once for the commit and once
    more for each outcome that is not a promotion. ``evidence_ids`` maps each ``verification_id``
    of the report to the id of the evidence record that stores that result. ``impact``,
    ``verification`` and ``policy`` are the inputs of the decision: ``decide`` is run on them again
    at the commit. Raises ``PromotionInputError`` for malformed arguments,
    ``ConflictingDuplicateError`` for a decision id or a candidate that is already used
    differently, and ``PromotionCommitError`` for an infrastructure failure."""
    _check_arguments(
        factory, outcome, candidate, impact, verification, policy, evidence_ids, context
    )
    moment = utc(now, "commit_promotion.now")
    attempt = outcome.decision.attempt_number if attempt_number is None else attempt_number
    verdicts = tuple(oracle_verdicts)
    try:
        try:
            with factory() as uow:
                return _attempt(
                    uow,
                    outcome,
                    impact,
                    verification,
                    policy,
                    evidence_ids,
                    context,
                    moment,
                    attempt,
                    verdicts,
                )
        except _Lost as lost:
            return _lose(factory, outcome, context, moment, str(lost))
        except _Invalid as invalid:
            return _escalate(factory, outcome, context, moment, str(invalid))
    except (ConflictingDuplicateError, PromotionInputError):
        raise
    except Exception as failure:
        _record_failure(factory, outcome, context, moment, failure)
        raise PromotionCommitError(
            f"the promotion of decision {outcome.decision.decision_id} could not be committed "
            f"({type(failure).__name__}); everything was rolled back, the candidate is still "
            "PROMOTABLE and the same commit can be retried (C-38, C-163)"
        ) from failure


def _existing(
    stored: PromotionDecision, decision: PromotionDecision, uow: UnitOfWork
) -> CommitResult | None:
    """A decision with this id is stored: a committed twin returns its state (C-163), another
    content is a conflict, an uncommitted twin lets the commit go on."""
    if stored.committed_state_id is None:
        if stored.content_hash != decision.content_hash:
            raise ConflictingDuplicateError(
                f"decision {decision.decision_id} was already stored with different content "
                "(C-163, Doc 09 §38)"
            )
        return None
    if stored.content_hash != decision.committed(stored.committed_state_id).content_hash:
        raise ConflictingDuplicateError(
            f"decision {decision.decision_id} was already committed with different content "
            "(C-163, Doc 09 §38)"
        )
    state = uow.trusted_states.get(stored.committed_state_id)
    if state is None:
        raise PersistenceError(
            f"decision {stored.decision_id} names state {stored.committed_state_id}, which "
            "is not stored"
        )
    return CommitResult(stored, state, duplicate=True)


def _attempt(
    uow: UnitOfWork,
    outcome: DecisionOutcome,
    impact: ImpactReport,
    verification: VerificationReport,
    policy: PromotionPolicy,
    evidence_ids: Mapping[str, str],
    context: PromotionContext,
    now: datetime,
    attempt_number: int,
    oracle_verdicts: tuple[OracleVerdict, ...],
) -> CommitResult:
    decision = outcome.decision
    stored = uow.decisions.get(decision.decision_id)
    if stored is not None:
        found = _existing(stored, decision, uow)
        if found is not None:
            return found
    else:
        rejection = uow.decisions.get(ids.rejection_decision_id_for(decision.decision_id))
        if rejection is not None:
            return CommitResult(rejection, stale=True)
        others = [
            d
            for d in uow.decisions.for_candidate(decision.candidate_id)
            if d.committed_state_id is not None
        ]
        if others:
            raise ConflictingDuplicateError(
                f"candidate {decision.candidate_id} was already promoted by decision "
                f"{others[0].decision_id} (C-163)"
            )
    candidate = uow.candidates.get(decision.candidate_id)
    if candidate is None:
        raise _Invalid("the candidate is not stored")
    current = uow.trusted_states.get_current(candidate.lineage_id)
    if current is None:
        raise _Invalid("the candidate's lineage has no current state")
    if candidate.status is not CandidateStatus.PROMOTABLE:
        raise _Invalid(f"the candidate is {candidate.status.value}, not PROMOTABLE")
    if current.state_id != candidate.parent_state_id:
        raise _Lost(
            f"the candidate's parent {candidate.parent_state_id} is not the current state "
            f"{current.state_id}"
        )
    plan = _revalidate(
        outcome, candidate, current, impact, verification, policy, attempt_number, oracle_verdicts
    )
    definitions = _definitions(uow, plan)
    results = {r.verification_id: r for r in verification.results}
    problems = binding_problems(
        uow.evidence, plan, candidate, current, definitions, results, evidence_ids
    )
    if problems:
        raise _Invalid("the evidence does not bind to the new state: " + "; ".join(problems))
    try:
        built = _build(
            outcome,
            candidate,
            current,
            impact,
            policy,
            plan,
            definitions,
            results,
            evidence_ids,
            context,
            now,
        )
    except DomainValidationError as refusal:
        raise _Invalid(f"the new state cannot be built: {refusal}") from refusal
    state, committed, promoted, binding, marked = built
    if stored is None:
        uow.decisions.save(decision)
        _decided_events(uow, decision, context)
    uow.evidence.append(binding)
    try:
        uow.trusted_states.save_promoted(state)
    except StaleParentError as moved:
        raise _Lost(str(moved)) from moved
    done = uow.decisions.commit(decision.decision_id, state.state_id)
    if done != committed:
        raise PersistenceError(f"decision {decision.decision_id} reads back differently")
    uow.candidates.save_transition(marked)
    _append_once(
        uow,
        _event(
            ids.event_id_for(decision.decision_id),
            AuditEventType.STATE_PROMOTED,
            context,
            now,
            {
                "parent_state_id": current.state_id,
                "new_state_id": state.state_id,
                "version": state.version,
                "state_hash": state.state_hash,
                "binding_evidence_id": binding.event.evidence_id,
                "evidence_sufficiency": promoted.evidence_sufficiency,
            },
            state_id=state.state_id,
            candidate_id=candidate.candidate_id,
            decision_id=decision.decision_id,
        ),
    )
    return CommitResult(done, state)


def _revalidate(
    outcome: DecisionOutcome,
    candidate: CandidateState,
    current: TrustedState,
    impact: ImpactReport,
    verification: VerificationReport,
    policy: PromotionPolicy,
    attempt_number: int,
    oracle_verdicts: tuple[OracleVerdict, ...],
) -> tuple[ProofPlanEntry, ...]:
    """C-167: ``decide`` again, on the candidate and the state as the database holds them."""
    try:
        fresh = decide(
            candidate,
            current,
            impact,
            verification,
            policy,
            decision_id=outcome.decision.decision_id,
            now=outcome.decision.created_at,
            attempt_number=attempt_number,
            oracle_verdicts=oracle_verdicts,
        )
    except DomainValidationError as refusal:
        raise _Invalid(f"decide refuses its inputs now: {refusal}") from refusal
    if (
        fresh.decision.content_hash != outcome.decision.content_hash
        or fresh.proof_plan != outcome.proof_plan
        or fresh.evidence.content_hash != outcome.evidence.content_hash
    ):
        raise _Invalid(
            f"the decision no longer holds: deciding again gives {fresh.decision.decision.value} "
            f"({fresh.decision.reason.value}) instead of the stored PROMOTE"
        )
    return fresh.proof_plan


def _definitions(uow: UnitOfWork, plan: Iterable[ProofPlanEntry]) -> dict[str, Invariant]:
    found: dict[str, Invariant] = {}
    for entry in plan:
        if entry.source is ProofSource.VERIFIED:
            definition = uow.invariants.get_definition(entry.invariant_id, entry.invariant_version)
            if definition is not None:
                found[entry.invariant_id] = definition
    return found


def _build(
    outcome: DecisionOutcome,
    candidate: CandidateState,
    current: TrustedState,
    impact: ImpactReport,
    policy: PromotionPolicy,
    plan: tuple[ProofPlanEntry, ...],
    definitions: Mapping[str, Invariant],
    results: Mapping[str, Any],
    evidence_ids: Mapping[str, str],
    context: PromotionContext,
    now: datetime,
) -> tuple[TrustedState, PromotionDecision, Any, EvidenceSubmission, CandidateState]:
    """Everything the commit will write, built before anything is (so a refusal leaves no trace)."""
    decision = outcome.decision
    binding_id = ids.evidence_id_for(decision.decision_id)
    evaluations = evaluate_from_results(
        plan, candidate, current, definitions, results, evidence_ids, binding_id
    )
    proofs = build_proofs(
        plan, candidate, current, impact, evaluations, binding_evidence_id=binding_id
    )
    arguments = promotion_arguments(
        candidate,
        current,
        decision.decision_id,
        proofs,
        registry_version=policy.invariant_registry_version,
        now=now,
    )
    state = TrustedState.promote(**arguments)
    committed = decision.committed(state.state_id)
    promoted = outcome.evidence.with_new_state(state.state_id)
    binding = EvidenceSubmission.create(
        payload=binding_payload(committed, promoted, plan, state, evidence_ids),
        evidence_id=binding_id,
        run_id=context.run_id,
        attempt_id=context.attempt_id,
        correlation_id=context.correlation_id,
        operation_id=context.operation_id,
        kind=EvidenceKind.STATE,
        event_name=BINDING_EVENT_NAME,
        provenance=Provenance(
            source_kind=ProvenanceSourceKind.DERIVED,
            source_component=_COMPONENT,
            source_reference=decision.decision_id,
            observed_at=now,
            tool_name="promotion-controller",
            tool_version=_VERSION,
            algorithm_version=_VERSION,
        ),
        created_at=now,
        state_id=state.state_id,
        parent_state_id=current.state_id,
        state_hash=state.state_hash,
    )
    return state, committed, promoted, binding, mark_promoted(candidate, state)


# --- the outcomes that are not a promotion --------------------------------------------------------


def _clip(text: str) -> str:
    return text if len(text) <= _REASON_LIMIT else text[: _REASON_LIMIT - 3] + "..."


def _lose(
    factory: Callable[[], UnitOfWork],
    outcome: DecisionOutcome,
    context: PromotionContext,
    now: datetime,
    detail: str,
) -> CommitResult:
    """C-38 case 1, C-166: the commit lost the race. Store a REJECT decision (STALE_PARENT) and
    reject the candidate; no state. The same loser again returns the stored REJECT."""
    decision = outcome.decision
    rejection_id = ids.rejection_decision_id_for(decision.decision_id)
    with factory() as uow:
        existing = uow.decisions.get(rejection_id)
        if existing is not None:
            return CommitResult(existing, stale=True)
        candidate = uow.candidates.get(decision.candidate_id)
        current = (
            None if candidate is None else uow.trusted_states.get_current(candidate.lineage_id)
        )
        if candidate is None or current is None:
            raise PersistenceError("the stale candidate or its lineage is not stored")
        rejection = PromotionDecision.create(
            decision_id=rejection_id,
            candidate_id=decision.candidate_id,
            parent_state_id=decision.parent_state_id,
            decision=D.REJECT,
            reason=R.STALE_PARENT,
            policy_version=decision.policy_version,
            attempt_number=decision.attempt_number,
            required_checks=(),
            blocking_conditions=[BlockingCondition(R.STALE_PARENT, D.REJECT, "STATE", detail)],
            supporting_results=(),
            created_at=now,
        )
        moved = candidate_after(rejection, candidate, current)
        uow.decisions.save(rejection)
        uow.candidates.save_transition(moved)
        _decided_events(uow, rejection, context)
    return CommitResult(rejection, stale=True)


def _escalate(
    factory: Callable[[], UnitOfWork],
    outcome: DecisionOutcome,
    context: PromotionContext,
    now: datetime,
    detail: str,
) -> CommitResult:
    """C-38 case 2: the decision no longer holds. The commit is rolled back; in a transaction of
    its own the candidate is ESCALATED and PROMOTION_FAILED is appended. The PROMOTE stays as the
    uncommitted record of what was decided."""
    decision = outcome.decision
    reason = _clip(f"REVALIDATION: {detail}")
    with factory() as uow:
        candidate = uow.candidates.get(decision.candidate_id)
        if candidate is None:
            raise PersistenceError("the candidate is not stored")
        if uow.decisions.get(decision.decision_id) is None:
            uow.decisions.save(decision)
            _decided_events(uow, decision, context)
        if candidate.status in (CandidateStatus.ANALYZING, CandidateStatus.PROMOTABLE):
            uow.candidates.save_transition(
                transition_candidate(candidate, CandidateStatus.ESCALATED)
            )
        _append_once(
            uow,
            _event(
                ids.failure_event_id_for(decision.decision_id, "REVALIDATION"),
                AuditEventType.PROMOTION_FAILED,
                context,
                now,
                {
                    "parent_state_id": decision.parent_state_id,
                    "reason": reason,
                    "decision_id": decision.decision_id,
                },
                candidate_id=decision.candidate_id,
            ),
        )
        _append_once(
            uow,
            _event(
                ids.outcome_event_id_for(decision.decision_id),
                AuditEventType.ESCALATED,
                context,
                now,
                {"reason": reason, "unresolved_conditions": [reason]},
                candidate_id=decision.candidate_id,
            ),
        )
    return CommitResult(decision, escalated=True)


def _record_failure(
    factory: Callable[[], UnitOfWork],
    outcome: DecisionOutcome,
    context: PromotionContext,
    now: datetime,
    failure: BaseException,
) -> None:
    """C-38 case 3, best effort: a PROMOTION_FAILED event in a separate transaction. If that fails
    too, nothing is recorded and nothing is claimed; the caller still gets the original error."""
    decision = outcome.decision
    try:
        with factory() as uow:
            _append_once(
                uow,
                _event(
                    ids.failure_event_id_for(decision.decision_id, "INFRASTRUCTURE"),
                    AuditEventType.PROMOTION_FAILED,
                    context,
                    now,
                    {
                        "parent_state_id": decision.parent_state_id,
                        "reason": _clip(
                            f"INFRASTRUCTURE: {type(failure).__name__}: the commit was rolled back"
                        ),
                        "decision_id": decision.decision_id,
                    },
                    candidate_id=decision.candidate_id,
                ),
            )
    except Exception:  # best effort by C-38 case 3: the original failure is what the caller gets
        return
