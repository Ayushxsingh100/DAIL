"""TrustedState and CandidateState.

Field shapes are taken verbatim from the Implementation Roadmap's
"Core Contracts" (Doc 15, Section 8.2):

    TrustedState {
        state_id, version, content_hash, invariant_registry_version,
        created_at, parent_state_id | null
    }
    CandidateState {
        candidate_id, parent_state_id, patch_hash, status
    }

These correspond to S_t and C_t in the paper's formal model (Section
IV-F), with `parent_state_id` implementing the Git-backed trusted-state
ledger described in Section VI-B: "promoted states correspond to
commits (or tags) and rejected candidates correspond to discarded
branches."

Engineering principle enforced here (Doc 14, Section 2): "Trusted State
changes only through the application promotion transaction." P1 cannot
implement the *real* promotion transaction -- that is P6, which depends
on Identity (P3), Dependency (P3), Impact (P4), and Verification (P5),
none of which exist yet. So this module draws a hard structural line:
TrustedState has no public constructor except `genesis()` (the very
first trusted state, which by definition has no candidate to promote
from) and `promoted_from()`, which P6's Promotion Controller will call
-- and only after a real PROMOTE decision. Calling `promoted_from()`
anywhere before P6 exists is a placeholder for wiring tests together,
not a claim that verification happened.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from core.domain.hashing import content_hash


class CandidateStatus(str, Enum):
    """CandidateState.status lifecycle.

    Distinct from the LLM's own self-reported LLMRepairResponse.status
    (PATCH/NO_SOLUTION/UNCERTAIN/INVALID, per Section VI-B / P7) --
    that describes what the *model* claims about its own output before
    DAIL has looked at it at all. CandidateStatus describes where the
    candidate is in DAIL's own pipeline, which the LLM has no authority
    over (Section IV-A: the LLM "may not declare its own output
    verified... or promote a candidate").
    """

    BUILT = "BUILT"  # Candidate State Builder has produced this candidate
    UNDER_VERIFICATION = "UNDER_VERIFICATION"
    PROMOTED = "PROMOTED"
    REJECTED = "REJECTED"


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass(frozen=True)
class TrustedState:
    """S_t: a trusted Terraform state, per Section IV-F.

    Immutable by construction (frozen dataclass) *and* by access path
    (no public __init__ call sites outside this module are expected --
    see module docstring). content_hash is not computed automatically
    from arbitrary payload here, because P1 does not yet have a
    canonical "what does a trusted state's content actually consist
    of" answer -- that depends on the Terraform model (P3). Callers
    must supply an already-computed content_hash today; P3 will replace
    ad-hoc callers with a real hash derived from the parsed Terraform
    state.
    """

    state_id: str
    version: int
    content_hash: str
    invariant_registry_version: int
    parent_state_id: str | None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError(f"TrustedState {self.state_id!r}: version must be >= 1")
        if self.version == 1 and self.parent_state_id is not None:
            raise ValueError(
                f"TrustedState {self.state_id!r}: version 1 must have parent_state_id=None "
                "(it is the genesis state)"
            )
        if self.version > 1 and self.parent_state_id is None:
            raise ValueError(
                f"TrustedState {self.state_id!r}: version {self.version} must have a "
                "parent_state_id (only version 1 is parentless)"
            )
        if not self.content_hash:
            raise ValueError(f"TrustedState {self.state_id!r}: content_hash must be non-empty")

    @classmethod
    def genesis(
        cls, *, content_payload: object, invariant_registry_version: int
    ) -> TrustedState:
        """Construct the very first trusted state (version 1, no parent).

        This is the one legitimate way to create a TrustedState without
        a promotion having occurred, because by definition there is no
        prior trusted state to promote *from* yet.
        """
        return cls(
            state_id=_new_id("state"),
            version=1,
            content_hash=content_hash(content_payload),
            invariant_registry_version=invariant_registry_version,
            parent_state_id=None,
        )

    @classmethod
    def promoted_from(
        cls,
        *,
        candidate: CandidateState,
        parent: TrustedState,
        content_payload: object,
        invariant_registry_version: int,
    ) -> TrustedState:
        """Construct the next trusted state following a promotion.

        P1 PLACEHOLDER: this performs no verification itself. It exists
        so P1's data model can be exercised end-to-end in tests and so
        P6 (Promotion Controller) has an obvious, already-tested target
        to call into once real verification exists. Any call site
        outside tests/fixtures that invokes this before P5/P6 exist is
        wiring, not a promotion decision.
        """
        if candidate.parent_state_id != parent.state_id:
            raise ValueError(
                f"CandidateState {candidate.candidate_id!r} has parent_state_id="
                f"{candidate.parent_state_id!r}, which does not match the trusted "
                f"state being promoted from ({parent.state_id!r})"
            )
        if candidate.status != CandidateStatus.PROMOTED:
            raise ValueError(
                f"CandidateState {candidate.candidate_id!r} has status="
                f"{candidate.status.value}, expected PROMOTED before a TrustedState "
                "can be derived from it"
            )
        return cls(
            state_id=_new_id("state"),
            version=parent.version + 1,
            content_hash=content_hash(content_payload),
            invariant_registry_version=invariant_registry_version,
            parent_state_id=parent.state_id,
        )


@dataclass
class CandidateState:
    """C_t: an untrusted candidate state produced from S_t via an
    LLM-generated patch, per Section IV-F.

    Mutable (unlike TrustedState) because `status` legitimately
    transitions over the candidate's lifetime as it moves through
    DAIL's pipeline (BUILT -> UNDER_VERIFICATION -> PROMOTED/REJECTED).
    Nothing about mutating a CandidateState mutates trusted state --
    that asymmetry is the whole point of the trust boundary (Section
    IV-A).
    """

    candidate_id: str
    parent_state_id: str
    patch_hash: str
    status: CandidateStatus = CandidateStatus.BUILT
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.parent_state_id:
            raise ValueError(
                f"CandidateState {self.candidate_id!r}: parent_state_id must be non-empty "
                "(every candidate is built from some trusted state)"
            )
        if not self.patch_hash:
            raise ValueError(f"CandidateState {self.candidate_id!r}: patch_hash must be non-empty")

    @classmethod
    def build(cls, *, parent: TrustedState, patch_payload: object) -> CandidateState:
        """Construct a new candidate from a trusted state and a patch payload.

        This is the Candidate State Builder's entry point (Section IV,
        Fig. 1's "Candidate State Builder" stage). `patch_payload` is
        deliberately untyped `object` at this phase -- P3's Terraform
        model will give it a real shape once the parser exists.
        """
        return cls(
            candidate_id=_new_id("cand"),
            parent_state_id=parent.state_id,
            patch_hash=content_hash(patch_payload),
        )

    def mark_under_verification(self) -> None:
        if self.status != CandidateStatus.BUILT:
            raise ValueError(
                f"CandidateState {self.candidate_id!r}: cannot move to "
                f"UNDER_VERIFICATION from {self.status.value}"
            )
        self.status = CandidateStatus.UNDER_VERIFICATION

    def mark_promoted(self) -> None:
        if self.status != CandidateStatus.UNDER_VERIFICATION:
            raise ValueError(
                f"CandidateState {self.candidate_id!r}: cannot move to PROMOTED "
                f"from {self.status.value} (must pass through UNDER_VERIFICATION)"
            )
        self.status = CandidateStatus.PROMOTED

    def mark_rejected(self) -> None:
        if self.status != CandidateStatus.UNDER_VERIFICATION:
            raise ValueError(
                f"CandidateState {self.candidate_id!r}: cannot move to REJECTED "
                f"from {self.status.value} (must pass through UNDER_VERIFICATION)"
            )
        self.status = CandidateStatus.REJECTED
