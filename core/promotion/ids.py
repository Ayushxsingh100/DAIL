"""Identifiers derived from a decision id (P6b; Doc 09 §38; C-163).

The key of a promotion is its ``decision_id``. The new state id, the promotion-evidence id and the
STATE_PROMOTED audit event id are derived from it with ``uuid5`` under one fixed namespace, so the
same decision always names the same state, record and event, and a duplicate submission is
detected by the database as well as by code. Nothing here draws a random number or reads a clock
(R10); standard library and ``core.domain`` only (R18).

Two further ids are derived the same way for the C-38 outcomes: the REJECT decision that a stale
loser stores (it needs an id of its own, because the PROMOTE decision keeps its) and the
PROMOTION_FAILED audit events.
"""

from __future__ import annotations

import uuid
from typing import Final

from core.domain.errors import DomainValidationError
from core.domain.ids import require_uuid

# A fixed constant: changing it would change every derived id (a golden value is pinned by a test).
PROMOTION_NAMESPACE: Final = uuid.UUID("c3b0e0d2-6f1a-4d8e-9a57-2b7c4e1f8a90")
FAILURE_KINDS: Final = ("REVALIDATION", "INFRASTRUCTURE")


def _derived(decision_id: str, prefix: str) -> str:
    require_uuid(decision_id, "decision_id")
    return str(uuid.uuid5(PROMOTION_NAMESPACE, prefix + decision_id))


def state_id_for(decision_id: str) -> str:
    """The id of the trusted state that the PROMOTE decision ``decision_id`` creates."""
    return _derived(decision_id, "state:")


def evidence_id_for(decision_id: str) -> str:
    """The id of the promotion binding record (C-164) of that decision."""
    return _derived(decision_id, "promotion-evidence:")


def event_id_for(decision_id: str) -> str:
    """The id of the STATE_PROMOTED audit event of that decision."""
    return _derived(decision_id, "state-promoted:")


def rejection_decision_id_for(decision_id: str) -> str:
    """The id of the REJECT decision (STALE_PARENT) stored when a commit of ``decision_id`` loses
    the race (C-166)."""
    return _derived(decision_id, "stale-rejection:")


def failure_event_id_for(decision_id: str, kind: str) -> str:
    """The id of the PROMOTION_FAILED audit event for a failed commit of ``decision_id``
    (C-38 case 2 is REVALIDATION, case 3 is INFRASTRUCTURE)."""
    if kind not in FAILURE_KINDS:
        raise DomainValidationError(f"failure kind must be one of {FAILURE_KINDS}, not {kind!r}")
    return _derived(decision_id, f"promotion-failed:{kind}:")
