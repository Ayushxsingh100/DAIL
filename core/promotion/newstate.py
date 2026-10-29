"""The arguments of the new trusted state (P6b; Doc 09 §26, §27, Appendix B; C-41, C-163, C-164).

``TrustedState.promote`` is called in exactly one place, ``core.promotion.commit`` (R8; the
contract test pins it). This module checks everything that can be checked before that call and
returns the keyword arguments for it: the derived state id (C-163), the proofs, the evidence
references (the union of the proofs' evidence, which includes the binding record), the policy's
registry version (non-decreasing across promotions, C-41) and the time. Standard library and
``core.domain`` only (R18).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from core.domain.enums import CandidateStatus
from core.domain.errors import DomainValidationError
from core.domain.invariant import InvariantProof
from core.domain.jsonvalue import require_int, utc
from core.domain.state import CandidateState, TrustedState
from core.promotion.ids import state_id_for


def promotion_arguments(
    candidate: CandidateState,
    trusted: TrustedState,
    decision_id: str,
    proofs: Sequence[InvariantProof],
    *,
    registry_version: int,
    now: datetime,
) -> dict[str, Any]:
    """The keyword arguments of ``TrustedState.promote`` for this decision."""
    if candidate.status is not CandidateStatus.PROMOTABLE:
        raise DomainValidationError(
            f"a {candidate.status.value} candidate cannot become a trusted state; only a "
            "PROMOTABLE one can (SM-002)"
        )
    require_int(registry_version, "registry_version", 1)
    if registry_version < trusted.invariant_registry_version:
        raise DomainValidationError(
            f"C-41: the registry version {registry_version} is lower than the current state's "
            f"{trusted.invariant_registry_version}"
        )
    return {
        "candidate": candidate,
        "current": trusted,
        "decision_id": decision_id,
        "invariant_proofs": list(proofs),
        "evidence_refs": sorted({e for proof in proofs for e in proof.evidence_ids}),
        "invariant_registry_version": registry_version,
        "now": utc(now, "now"),
        "state_id": state_id_for(decision_id),
    }
