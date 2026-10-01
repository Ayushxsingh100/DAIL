"""Identifiers (Doc 05 §3; P1a step 4).

``record_id``, ``state_id``, ``candidate_id``, ``run_id``, ``attempt_id``,
``evidence_id`` and ``decision_id`` are UUIDs. This is the only module in
``core.domain`` that may call ``uuid.uuid4`` (enforced by contract rule R10), so
randomness enters the domain in exactly one place.
"""

from __future__ import annotations

import uuid

from core.domain.errors import DomainValidationError


def new_uuid() -> str:
    """A fresh canonical lowercase UUID string."""
    return str(uuid.uuid4())


def require_uuid(value: object, field: str) -> str:
    """Return ``value`` if it is a canonical lowercase UUID string, else raise."""
    if not isinstance(value, str):
        raise DomainValidationError(f"{field}: must be a UUID string (Doc 05 §3)")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise DomainValidationError(f"{field}: not a UUID (Doc 05 §3)") from None
    if str(parsed) != value:
        raise DomainValidationError(f"{field}: UUID must be canonical lowercase (Doc 05 §3)")
    return value
