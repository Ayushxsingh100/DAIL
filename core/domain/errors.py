"""Domain errors (P1a step 4).

Every rejection in ``core.domain`` raises one of these, never a bare
``ValueError`` or ``Exception`` (P1a rule 6). The message names the rule that
fired, e.g. ``SM-010``, ``DATA-INT-002`` or ``Doc 06 §12``, so a rejection is
traceable to the specification (Doc 06 §30: "Reject illegal transitions at the
domain boundary").
"""

from __future__ import annotations


class DomainValidationError(ValueError):
    """A domain object or operation violates a documented rule."""


class IllegalTransitionError(DomainValidationError):
    """A lifecycle transition the specification does not allow (Doc 06 §9, §12, §22)."""

    def __init__(
        self,
        kind: str,
        current: object,
        requested: object,
        rule: str,
        detail: str = "",
    ) -> None:
        self.kind = kind
        self.current = current
        self.requested = requested
        self.rule = rule
        message = f"{rule}: illegal {kind} transition {current} -> {requested}"
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


class StaleParentError(IllegalTransitionError):
    """A candidate whose parent is no longer the current trusted state (SM-010, Doc 06 §20)."""

    def __init__(self, current: object, requested: object, detail: str = "") -> None:
        super().__init__("candidate", current, requested, "SM-010", detail)


class HashMismatchError(DomainValidationError):
    """A stored or supplied hash does not match the canonical content (DATA-INT-010)."""


class UnauthorizedConstructionError(DomainValidationError):
    """A lifecycle-bearing object was built outside its factories or lifecycle functions.

    ``dataclasses.replace`` and direct constructor calls cannot skip a transition
    (Doc 06 §30: "Represent transitions through domain functions").
    """


class PersistenceError(DomainValidationError):
    """A persistence adapter failure that is not a lifecycle violation (Doc 05 §22, §32).

    Raised for an unusable database (wrong schema version, a stored row that fails validation, a
    busy database, a failed write). A lifecycle violation keeps its own error: a stale parent is
    ``StaleParentError`` and an illegal candidate change is ``IllegalTransitionError``.
    """
