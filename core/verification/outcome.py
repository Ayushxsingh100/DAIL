"""What a security predicate concludes, before it becomes a result record (C-146; P5a step 4).

A predicate returns a ``PredicateOutcome``: the result, the reason when it is not a PASS, the
clauses (INV-SEC-001/002 only), the observations of its registry section and the assumptions it
relied on. ``core.verification.engine`` turns it into a ``VerificationResultRecord``. Observations
are plain JSON (lists and dicts, no floats, sorted) and are not to be changed by the caller.

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from core.domain.enums import VerificationResult
from core.domain.verification import VerificationReason

CLAUSE_IPV4 = "IPV4"
CLAUSE_IPV6 = "IPV6"

_RANK = {
    VerificationResult.PASS: 0,
    VerificationResult.UNKNOWN: 1,
    VerificationResult.UNSUPPORTED: 2,
}


def combine(clauses: Mapping[str, VerificationResult]) -> VerificationResult:
    """Registry §3.4: FAIL if either clause FAILs, else the worse of UNSUPPORTED, UNKNOWN, PASS."""
    values = list(clauses.values())
    if VerificationResult.FAIL in values:
        return VerificationResult.FAIL
    return max(values, key=lambda value: _RANK[value])


@dataclass(frozen=True, slots=True)
class PredicateOutcome:
    result: VerificationResult
    reason: VerificationReason | None
    clauses: Mapping[str, VerificationResult] | None
    observations: dict[str, Any]
    assumptions: tuple[str, ...]
