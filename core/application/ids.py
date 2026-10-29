"""Identifiers the orchestrator and the baseline flow derive from a request (P6c; Doc 11 §38;
C-170 (4), C-171).

Every id is ``uuid5(ORCHESTRATOR_NAMESPACE, "<kind>:<key parts>")``, so the same request always
names the same decision, evidence records and audit events, and a rerun is a duplicate that the
database and the recorder recognise, never a conflict (Doc 11 §38). Nothing here draws a random
number or reads a clock. The namespace is a pinned constant: changing it, or a key, changes every
derived id (a test pins both).

Verification ids are positional: the engine's id source is a zero-argument callable, so the n-th id
it asks for is ``uuid5(ns, "verification:<candidate>:<attempt>:<n>")``. The call sequence is fixed
by the sorted work set, hence by the candidate (C-170 (4)).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Final

from core.domain.audit import AuditEventType
from core.domain.errors import DomainValidationError
from core.domain.ids import require_uuid

ORCHESTRATOR_NAMESPACE: Final = uuid.UUID("5e1d7a43-92c0-4b6f-8d3a-17f4c9e02b68")
STAGES: Final = ("state", "identity", "dependency", "impact", "verification", "error")


def _derived(key: str) -> str:
    return str(uuid.uuid5(ORCHESTRATOR_NAMESPACE, key))


def _attempt(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise DomainValidationError(f"attempt_number must be an integer >= 1, not {value!r}")
    return value


def _stage(value: object) -> str:
    if value not in STAGES:
        raise DomainValidationError(f"stage must be one of {STAGES}, not {value!r}")
    assert isinstance(value, str)
    return value


def _part(value: object, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise DomainValidationError(f"{name} must be non-empty text, not {value!r}")
    return value


def _suffix(extra: str | None, name: str) -> str:
    return "" if extra is None else ":" + _part(extra, name)


def _event_type(value: object) -> str:
    if not isinstance(value, AuditEventType):
        raise DomainValidationError("event_type must be an AuditEventType")
    return value.value


# --- an evaluation ---------------------------------------------------------------------------


def decision_id_for(candidate_id: str, attempt_number: int) -> str:
    """The id of the decision about ``candidate_id`` at this attempt."""
    require_uuid(candidate_id, "candidate_id")
    return _derived(f"decision:{candidate_id}:{_attempt(attempt_number)}")


def evidence_id_for(
    candidate_id: str, attempt_number: int, stage: str, target_id: str | None = None
) -> str:
    """The id of the evidence record of one stage (and one target, for a verification result)."""
    require_uuid(candidate_id, "candidate_id")
    return _derived(
        f"evidence:{candidate_id}:{_attempt(attempt_number)}:{_stage(stage)}"
        f"{_suffix(target_id, 'target_id')}"
    )


def event_id_for(
    candidate_id: str, attempt_number: int, event_type: AuditEventType, key: str | None = None
) -> str:
    """The id of one audit event of the evaluation (``key`` tells apart the events of one type)."""
    require_uuid(candidate_id, "candidate_id")
    return _derived(
        f"event:{candidate_id}:{_attempt(attempt_number)}:{_event_type(event_type)}"
        f"{_suffix(key, 'key')}"
    )


def verification_ids(candidate_id: str, attempt_number: int) -> Callable[[], str]:
    """A fresh id source for ``run_work_set``: the n-th call returns the n-th derived id."""
    require_uuid(candidate_id, "candidate_id")
    prefix = f"verification:{candidate_id}:{_attempt(attempt_number)}:"
    counter = {"next": 0}

    def next_id() -> str:
        value = _derived(prefix + str(counter["next"]))
        counter["next"] += 1
        return value

    return next_id


# --- a baseline ------------------------------------------------------------------------------


def baseline_state_id_for(baseline_id: str) -> str:
    """The id of the version-0 trusted state that ``baseline_id`` establishes."""
    require_uuid(baseline_id, "baseline_id")
    return _derived(f"baseline-state:{baseline_id}")


def baseline_evidence_id_for(baseline_id: str, stage: str, target_id: str | None = None) -> str:
    require_uuid(baseline_id, "baseline_id")
    return _derived(
        f"baseline-evidence:{baseline_id}:{_stage(stage)}{_suffix(target_id, 'target_id')}"
    )


def baseline_event_id_for(
    baseline_id: str, event_type: AuditEventType, key: str | None = None
) -> str:
    require_uuid(baseline_id, "baseline_id")
    return _derived(f"baseline-event:{baseline_id}:{_event_type(event_type)}{_suffix(key, 'key')}")


def baseline_verification_ids(baseline_id: str) -> Callable[[], str]:
    """A fresh id source for the baseline verification run."""
    require_uuid(baseline_id, "baseline_id")
    prefix = f"baseline-verification:{baseline_id}:"
    counter = {"next": 0}

    def next_id() -> str:
        value = _derived(prefix + str(counter["next"]))
        counter["next"] += 1
        return value

    return next_id
