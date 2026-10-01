"""Lifecycle tables and pure transition checks (Doc 06 §5, §8, §9, §12; C-29, C-30; P1a).

The candidate lifecycle is Doc 06 §5 (C-05, C-29). The invariant lifecycle is
Doc 06 §8-§9, with results mapped to statuses as C-30 records:

    PASS -> PROTECTED; FAIL -> VIOLATED;
    UNKNOWN, UNSUPPORTED, VERIFIER_ERROR -> UNCERTAIN.

PROTECTED, VIOLATED and UNCERTAIN are reachable only by applying a verification
result to a VERIFYING or REVERIFYING invariant (``apply_verification_result``).
No plain transition leads to them, so an AFFECTED invariant can never be treated
as PROTECTED, or shortcut to VIOLATED, without verification (Doc 06 §12, SM-006).
"""

from __future__ import annotations

from types import MappingProxyType

from core.domain.enums import CandidateStatus, InvariantStatus, VerificationResult
from core.domain.errors import DomainValidationError, IllegalTransitionError

_C = CandidateStatus
_I = InvariantStatus

CANDIDATE_TRANSITIONS: MappingProxyType[CandidateStatus, frozenset[CandidateStatus]] = (
    MappingProxyType(
        {
            _C.CREATED: frozenset({_C.BUILDING}),
            # Only via finish_building / fail_building.
            _C.BUILDING: frozenset({_C.READY, _C.FAILED}),
            _C.READY: frozenset({_C.ANALYZING}),
            _C.ANALYZING: frozenset({_C.REJECTED, _C.RETRY_REQUIRED, _C.ESCALATED, _C.PROMOTABLE}),
            # PROMOTED only via mark_promoted; REJECTED only via reject_stale_candidate (C-29).
            _C.PROMOTABLE: frozenset({_C.PROMOTED, _C.REJECTED}),
            _C.FAILED: frozenset(),
            _C.REJECTED: frozenset(),
            _C.RETRY_REQUIRED: frozenset(),
            _C.ESCALATED: frozenset(),
            _C.PROMOTED: frozenset(),
        }
    )
)

INVARIANT_PLAIN_TRANSITIONS: MappingProxyType[InvariantStatus, frozenset[InvariantStatus]] = (
    MappingProxyType(
        {
            _I.REGISTERED: frozenset({_I.VERIFYING}),
            _I.PROTECTED: frozenset({_I.AFFECTED}),
            _I.AFFECTED: frozenset({_I.REVERIFYING}),
            _I.VIOLATED: frozenset({_I.REVERIFYING}),
            _I.UNCERTAIN: frozenset({_I.REVERIFYING}),
            # Exit only through a verification result.
            _I.VERIFYING: frozenset(),
            _I.REVERIFYING: frozenset(),
        }
    )
)

RESULT_TO_STATUS: MappingProxyType[VerificationResult, InvariantStatus] = MappingProxyType(
    {
        VerificationResult.PASS: _I.PROTECTED,
        VerificationResult.FAIL: _I.VIOLATED,
        VerificationResult.UNKNOWN: _I.UNCERTAIN,
        VerificationResult.UNSUPPORTED: _I.UNCERTAIN,
        VerificationResult.VERIFIER_ERROR: _I.UNCERTAIN,
    }
)

TRUSTED_REF_STATUSES: frozenset[InvariantStatus] = frozenset(
    {_I.PROTECTED, _I.VIOLATED, _I.UNCERTAIN}
)

_RESULT_ONLY_STATUSES = TRUSTED_REF_STATUSES
_VERIFYING_STATUSES = frozenset({_I.VERIFYING, _I.REVERIFYING})


def check_candidate_transition(current: CandidateStatus, target: CandidateStatus) -> None:
    """Raise ``IllegalTransitionError`` unless ``current -> target`` is in Doc 06 §5 (C-29)."""
    if not isinstance(current, CandidateStatus) or not isinstance(target, CandidateStatus):
        raise DomainValidationError("candidate transition: both statuses must be CandidateStatus")
    if target in CANDIDATE_TRANSITIONS[current]:
        return
    # Promotion has its own rule: a candidate never becomes trusted by a status change alone.
    rule = "SM-002" if target is CandidateStatus.PROMOTED else "Doc 06 §5"
    raise IllegalTransitionError("candidate", current, target, rule)


def check_invariant_transition(current: InvariantStatus, target: InvariantStatus) -> None:
    """Check a plain invariant transition (Doc 06 §9).

    A target of PROTECTED, VIOLATED or UNCERTAIN always raises: those statuses are
    reached only by applying a verification result (Doc 06 §12, SM-006).
    """
    if not isinstance(current, InvariantStatus) or not isinstance(target, InvariantStatus):
        raise DomainValidationError("invariant transition: both statuses must be InvariantStatus")
    if target in _RESULT_ONLY_STATUSES:
        raise IllegalTransitionError(
            "invariant",
            current,
            target,
            "SM-006",
            "Doc 06 §12: reachable only by applying a verification result",
        )
    if target not in INVARIANT_PLAIN_TRANSITIONS[current]:
        raise IllegalTransitionError("invariant", current, target, "Doc 06 §9")


def status_for_result(result: VerificationResult) -> InvariantStatus:
    """The invariant status a verification result leads to (C-30)."""
    if not isinstance(result, VerificationResult):
        raise DomainValidationError("verification result must be a VerificationResult")
    return RESULT_TO_STATUS[result]


def apply_verification_result(
    current: InvariantStatus, result: VerificationResult
) -> InvariantStatus:
    """Apply ``result`` to an invariant that is VERIFYING or REVERIFYING (Doc 06 §8, C-30).

    Any other starting status raises: a result cannot move an AFFECTED or PROTECTED
    invariant (SM-006, Doc 06 §12), nor skip VERIFYING (Doc 06 §8).
    """
    if not isinstance(current, InvariantStatus):
        raise DomainValidationError("invariant transition: status must be InvariantStatus")
    outcome = status_for_result(result)
    if current not in _VERIFYING_STATUSES:
        if current in (_I.PROTECTED, _I.AFFECTED):
            raise IllegalTransitionError(
                "invariant",
                current,
                outcome,
                "SM-006",
                "Doc 06 §12: verification required before any new status",
            )
        raise IllegalTransitionError(
            "invariant", current, outcome, "Doc 06 §8", "a result applies only while verifying"
        )
    return outcome
