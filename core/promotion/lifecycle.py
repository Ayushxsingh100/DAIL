"""Applying a decision to the candidate (P6a; Doc 06 §4-§5, §20, §22 SM-001 to SM-004 and SM-010,
Doc 09 §21-§25; C-29, C-157).

``candidate_after`` moves a candidate under analysis along the legal exit of Doc 06 §5 that the
decision names, using only the existing lifecycle functions of ``core.domain.state``:

    PROMOTE  -> PROMOTABLE   (never PROMOTED: SM-002, the commit of P6b does that)
    REJECT   -> REJECTED     (a PROMOTABLE candidate only through the stale-parent exit, C-29)
    RETRY    -> RETRY_REQUIRED
    ESCALATE -> ESCALATED

The trusted state is read (its id, its lineage) and never changed: a decision does not advance
Trusted State (SM-001), and a rejection or a retry preserves the current one (SM-003, SM-004).
Nothing here creates or advances a trusted state.

Standard library and ``core.domain`` only (R18).
"""

from __future__ import annotations

from core.domain.enums import CandidateStatus, DecisionType
from core.domain.errors import StaleParentError
from core.domain.promotion import DecisionReason, PromotionDecision, PromotionInputError
from core.domain.state import (
    CandidateState,
    TrustedState,
    reject_stale_candidate,
    transition_candidate,
)

_EXIT = {
    DecisionType.REJECT: CandidateStatus.REJECTED,
    DecisionType.RETRY: CandidateStatus.RETRY_REQUIRED,
    DecisionType.ESCALATE: CandidateStatus.ESCALATED,
}


def candidate_after(
    decision: PromotionDecision, candidate: CandidateState, trusted: TrustedState
) -> CandidateState:
    """The candidate once ``decision`` is applied; ``trusted`` is only read.

    The decision must be about this candidate and its parent (DATA-INT-003). A candidate that is
    not in the status the exit needs, or whose exit the lifecycle forbids, raises the domain's
    ``IllegalTransitionError``; a PROMOTE for a candidate whose parent is no longer the current
    state raises ``StaleParentError`` (SM-010)."""
    if not isinstance(decision, PromotionDecision):
        raise PromotionInputError("candidate_after: decision must be a PromotionDecision")
    if not isinstance(candidate, CandidateState):
        raise PromotionInputError("candidate_after: candidate must be a CandidateState")
    if not isinstance(trusted, TrustedState):
        raise PromotionInputError("candidate_after: trusted must be a TrustedState")
    if decision.candidate_id != candidate.candidate_id:
        raise PromotionInputError("candidate_after: the decision is about another candidate")
    if decision.parent_state_id != candidate.parent_state_id:
        raise PromotionInputError(
            "candidate_after: the decision's parent is not the candidate's parent (DATA-INT-003)"
        )
    if candidate.lineage_id != trusted.lineage_id:
        raise PromotionInputError("candidate_after: the trusted state is in another lineage")
    if decision.decision is DecisionType.PROMOTE:
        if candidate.parent_state_id != trusted.state_id:
            raise StaleParentError(
                candidate.status,
                CandidateStatus.PROMOTABLE,
                f"the candidate's parent {candidate.parent_state_id} is not the current state "
                f"{trusted.state_id}",
            )
        return transition_candidate(candidate, CandidateStatus.PROMOTABLE)
    if (
        decision.decision is DecisionType.REJECT
        and decision.reason is DecisionReason.STALE_PARENT
        and candidate.status is CandidateStatus.PROMOTABLE
    ):
        return reject_stale_candidate(candidate, trusted)
    return transition_candidate(candidate, _EXIT[decision.decision])
