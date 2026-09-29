"""Canonical enum types for DAIL's domain model.

Every value here is taken directly from the paper's formal model
(Section IV) rather than invented independently, so the code and the
paper stay in lockstep. Where the paper introduces an "uncertainty"
outcome (UNKNOWN / UNSUPPORTED / UNCERTAIN / ERROR), it is a hard rule
(Eq. 1, Section IV-G) that these are never silently treated as PASS or
as a definite identity/change classification. Do not add a fallback
that defaults an uncertain outcome to a "safe-looking" value anywhere
in this codebase; that would violate the paper's own trust model.
"""

from __future__ import annotations

from enum import Enum


class ChangeAction(str, Enum):
    """Delta(S_t, C_t) element action, per Section IV-F.

    The paper defines the abstract set as {CREATED, MODIFIED, DELETED,
    REPLACED}; UNCHANGED and UNCERTAIN are added here because the
    Identity Engine (Section IV-C) needs to represent "nothing changed"
    and "the Identity Engine could not classify this" as first-class
    outcomes, not as an absence of a ChangeAction value.
    """

    UNCHANGED = "UNCHANGED"
    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    REPLACED = "REPLACED"
    UNCERTAIN = "UNCERTAIN"


class IdentityOutcome(str, Enum):
    """Identity Engine result, per Section IV-C.

    SAME/DIFFERENT/UNCERTAIN — identity is resolved using supported
    Terraform/AWS resource-identity semantics, never by address
    stability alone. UNCERTAIN is the conservative default: evidence
    is never carried forward when identity cannot be established
    reliably (Section IV-C, IV-F).
    """

    SAME = "SAME"
    DIFFERENT = "DIFFERENT"
    UNCERTAIN = "UNCERTAIN"


class VerificationOutcome(str, Enum):
    """Result of V(C_t, i) for some invariant i, per Section IV-F/IV-G.

    PASS is the only outcome that can satisfy a required obligation.
    UNKNOWN, ERROR, UNSUPPORTED, and UNCERTAIN are all treated as
    (!= PASS) per Eq. 1 and must never be coerced to PASS anywhere in
    this codebase, including in error-handling or retry paths.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"
    UNCERTAIN = "UNCERTAIN"

    @property
    def is_pass(self) -> bool:
        """The only correct way to ask "did this pass?" in the codebase.

        Deliberately not just `outcome == VerificationOutcome.PASS`
        spelled out at every call site, so there is exactly one place
        that encodes "PASS is the only passing outcome" and it cannot
        drift from Eq. 1 by an accidental `!= FAIL` check elsewhere,
        which would silently treat UNKNOWN/ERROR/UNSUPPORTED/UNCERTAIN
        as passing.
        """
        return self is VerificationOutcome.PASS


class InvariantLifecycleState(str, Enum):
    """Invariant lifecycle, per Section IV-E:

    REGISTERED -> VERIFYING -> VERIFIED/PROTECTED -> AFFECTED
    -> REVERIFYING -> PASS/FAIL/UNKNOWN

    "Protection requires current evidence for the current trusted
    state; a protected invariant is not merely a historical PASS"
    (Section IV-E) -- so PROTECTED is a distinct state from a bare
    VERIFIED/PASS result, and an AFFECTED invariant loses PROTECTED
    status until it is REVERIFIED against the new candidate/trusted
    state.
    """

    REGISTERED = "REGISTERED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    PROTECTED = "PROTECTED"
    AFFECTED = "AFFECTED"
    REVERIFYING = "REVERIFYING"
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


# Explicit transition table. Per P1 exit criterion ("Forbidden lifecycle
# transitions are rejected") this is the single source of truth for what
# counts as a legal transition -- nothing outside this table is permitted.
_ALLOWED_LIFECYCLE_TRANSITIONS: dict[InvariantLifecycleState, frozenset[InvariantLifecycleState]] = {
    InvariantLifecycleState.REGISTERED: frozenset({InvariantLifecycleState.VERIFYING}),
    InvariantLifecycleState.VERIFYING: frozenset(
        {
            InvariantLifecycleState.VERIFIED,
            InvariantLifecycleState.PASS,
            InvariantLifecycleState.FAIL,
            InvariantLifecycleState.UNKNOWN,
        }
    ),
    InvariantLifecycleState.VERIFIED: frozenset(
        {InvariantLifecycleState.PROTECTED, InvariantLifecycleState.AFFECTED}
    ),
    InvariantLifecycleState.PROTECTED: frozenset({InvariantLifecycleState.AFFECTED}),
    InvariantLifecycleState.AFFECTED: frozenset({InvariantLifecycleState.REVERIFYING}),
    InvariantLifecycleState.REVERIFYING: frozenset(
        {
            InvariantLifecycleState.PASS,
            InvariantLifecycleState.FAIL,
            InvariantLifecycleState.UNKNOWN,
        }
    ),
    # Terminal-looking states can still re-enter the cycle when a *new*
    # transition makes the invariant newly in-scope again (e.g. PASS on a
    # promoted candidate becomes the new trusted state's VERIFIED evidence).
    InvariantLifecycleState.PASS: frozenset({InvariantLifecycleState.VERIFIED}),
    InvariantLifecycleState.FAIL: frozenset({InvariantLifecycleState.VERIFYING}),
    InvariantLifecycleState.UNKNOWN: frozenset(
        {InvariantLifecycleState.VERIFYING, InvariantLifecycleState.REVERIFYING}
    ),
}


def is_allowed_lifecycle_transition(
    current: InvariantLifecycleState, target: InvariantLifecycleState
) -> bool:
    """Whether `current -> target` is a legal invariant lifecycle transition."""
    return target in _ALLOWED_LIFECYCLE_TRANSITIONS.get(current, frozenset())


class ObligationCategory(str, Enum):
    """The four obligation categories, per Section IV-E:

    (A) target remediation obligation
    (B) protected invariant
    (C) affected protected invariant
    (D) baseline obligation (new/in-scope resource)
    """

    TARGET = "TARGET"
    PROTECTED = "PROTECTED"
    AFFECTED_PROTECTED = "AFFECTED_PROTECTED"
    BASELINE = "BASELINE"


class PromotionDecision(str, Enum):
    """Promotion Controller output, per Section IV-G.

    Only PROMOTE mutates trusted state. This is enforced structurally,
    not just documented: see core.domain.state.TrustedState, which has
    no public constructor other than the one the (future, P6) Promotion
    Controller uses on a successful PROMOTE decision.
    """

    PROMOTE = "PROMOTE"
    REJECT = "REJECT"
    RETRY = "RETRY"
    ESCALATE = "ESCALATE"


class InvariantType(str, Enum):
    """Security vs. functional invariant, per the paper's two canonical
    examples (INV-SEC-001, INV-FUNC-001) and Section VI-A's statement
    that the invariant set is drawn from Checkov's CIS-AWS policy
    library and is expected to grow beyond these two.
    """

    SECURITY = "SECURITY"
    FUNCTIONAL = "FUNCTIONAL"
