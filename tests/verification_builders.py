"""Builders for the verification tests (P5a). Not a test module.

Everything is deterministic: ids come from ``tests.domain_builders.uid`` and timestamps from ``at``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from core.domain.enums import VerificationResult
from core.domain.verification import (
    VerificationClass,
    VerificationReason,
    VerificationReport,
    VerificationRequest,
    VerificationResultRecord,
    VerificationTargetType,
)
from tests.domain_builders import at, uid

HASH = "a" * 64
OTHER_HASH = "b" * 64
CANDIDATE = uid(301)
PARENT = uid(302)
SEC1 = "INVARIANT:INV-SEC-001:1"


def evidence_for(
    result: VerificationResult, *, invariant_id: str | None = "INV-SEC-001"
) -> dict[str, Any]:
    """A Doc 11 §25 payload that is complete."""
    return {
        "verification_id": uid(1),
        "invariant_id": invariant_id,
        "invariant_version": 1 if invariant_id else None,
        "candidate_id": CANDIDATE,
        "verifier_id": "dail.verify.public_ingress",
        "verifier_version": "1",
        "predicate": "PIP(22)",
        "inputs": [],
        "observations": [],
        "result": result.value,
        "evidence_refs": [],
        "started_at": at(0).isoformat(),
        "completed_at": at(1).isoformat(),
    }


def record(
    *,
    result: VerificationResult = VerificationResult.PASS,
    target_id: str = SEC1,
    target_type: VerificationTargetType = VerificationTargetType.INVARIANT,
    invariant_id: str | None = "INV-SEC-001",
    invariant_version: int | None = 1,
    verifier_id: str = "dail.verify.public_ingress",
    verifier_version: str = "1",
    candidate_hash: str = HASH,
    candidate_id: str = CANDIDATE,
    verification_class: VerificationClass = VerificationClass.SECURITY,
    evidence_level: str = "L1",
    reason: VerificationReason | None | bool = True,
    clauses: Mapping[str, VerificationResult] | None | bool = True,
    observations: Mapping[str, Any] | None = None,
    assumptions: Iterable[str] = (),
    error: Mapping[str, str] | None | bool = True,
    evidence: Mapping[str, Any] | None = None,
    verification_id: str | None = None,
    request_id: str | None = None,
    started: datetime | None = None,
    completed: datetime | None = None,
    applicable: bool = True,
) -> VerificationResultRecord:
    """A valid result record; ``reason``, ``clauses`` and ``error`` default to what the result
    needs (pass ``None`` or a value to override)."""
    if reason is True:
        reason = (
            None if result is VerificationResult.PASS else VerificationReason.PREDICATE_VIOLATED
        )
        if result in (VerificationResult.UNKNOWN, VerificationResult.UNSUPPORTED):
            reason = VerificationReason.RULE_INDETERMINATE
        if result is VerificationResult.VERIFIER_ERROR:
            reason = VerificationReason.VERIFIER_ERROR
    if clauses is True:
        clauses = (
            {"IPV4": result, "IPV6": result}
            if invariant_id in ("INV-SEC-001", "INV-SEC-002")
            and result is not VerificationResult.VERIFIER_ERROR
            else None
        )
    if error is True:
        error = (
            {"type": "ValueError", "message": "boom", "class": "SecurityPredicate"}
            if result is VerificationResult.VERIFIER_ERROR
            else None
        )
    return VerificationResultRecord(
        verification_id=verification_id or uid(10),
        request_id=request_id or uid(11),
        target_type=target_type,
        target_id=target_id,
        candidate_id=candidate_id,
        candidate_hash=candidate_hash,
        invariant_id=invariant_id,
        invariant_version=invariant_version,
        verifier_id=verifier_id,
        verifier_version=verifier_version,
        evidence_level=evidence_level,
        verification_class=verification_class,
        result=result,
        reason=reason,  # type: ignore[arg-type]
        applicable=applicable,
        clauses=clauses,  # type: ignore[arg-type]
        observations={} if observations is None else observations,
        assumptions=tuple(sorted(set(assumptions))),
        evidence=(
            evidence if evidence is not None else evidence_for(result, invariant_id=invariant_id)
        ),
        error=error,  # type: ignore[arg-type]
        started_at=started or at(0),
        completed_at=completed or at(1),
    )


def request(**overrides: Any) -> VerificationRequest:
    values: dict[str, Any] = {
        "request_id": uid(11),
        "candidate_id": CANDIDATE,
        "state_id": PARENT,
        "candidate_hash": HASH,
        "target_id": SEC1,
        "target_type": VerificationTargetType.INVARIANT,
        "invariant_refs": ("INV-SEC-001:1",),
        "verification_scope": ("aws_security_group.app",),
        "verifier_id": "dail.verify.public_ingress",
        "verifier_version": "1",
    }
    values.update(overrides)
    return VerificationRequest(**values)


def report(
    results: Iterable[VerificationResultRecord] | None = None,
    *,
    report_id: str | None = None,
    candidate_hash: str = HASH,
    invocations: int | None = None,
    verifier_set_version: str = "dail-verify-1",
) -> VerificationReport:
    items = list(results) if results is not None else [record()]
    return VerificationReport.create(
        candidate_id=CANDIDATE,
        candidate_hash=candidate_hash,
        results=items,
        verifier_invocations=len(items) if invocations is None else invocations,
        verifier_set_version=verifier_set_version,
        report_id=report_id,
    )
