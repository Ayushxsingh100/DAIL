"""Invariant model and registry.

Field list taken verbatim from Section IV-E of the paper: "An invariant
is a machine-checkable security or functional property associated with
an identifier/version, description, type, predicate, scope,
applicability rules, verification policy, lifecycle status, verified-
state identifier, dependency snapshot, evidence reference,
verifier/configuration version, and provenance."

`predicate` and `scope` are intentionally left as opaque, callable-free
placeholders here (a string identifier, not a Python callable) because
their real implementations depend on the Verification Engine (P5) and
Dependency Engine (P3), which do not exist yet. Encoding them as
executable predicates now would mean inventing an interface this early
phase has no way to validate against real Terraform data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.domain.enums import (
    InvariantLifecycleState,
    InvariantType,
    is_allowed_lifecycle_transition,
)
from core.domain.hashing import content_hash


class InvalidLifecycleTransition(Exception):
    """Raised when an invariant's lifecycle state transition is not
    permitted by the transition table in core.domain.enums. This is
    the concrete mechanism behind the P1 exit criterion "Forbidden
    lifecycle transitions are rejected" -- it is a hard exception, not
    a logged warning, because a silently-ignored illegal transition is
    exactly the kind of failure mode the paper's trust model (Section
    IV-A) exists to prevent.
    """


@dataclass
class Invariant:
    """A single protected invariant, per Section IV-E's field list.

    Deliberately mutable (unlike Resource/TrustedState) because an
    invariant's lifecycle_state and verified_state_id are expected to
    change over the invariant's lifetime as it moves through
    REGISTERED -> VERIFYING -> ... -> PASS/FAIL/UNKNOWN. Mutation is
    only ever performed through `transition_to`, which enforces the
    legal-transition table -- direct field assignment to
    `lifecycle_state` elsewhere in the codebase should be treated as a
    bug.
    """

    invariant_id: str
    version: int
    description: str
    invariant_type: InvariantType
    predicate_id: str
    scope_id: str
    applicability_rule: str
    verification_policy_id: str
    verifier_version: str
    lifecycle_state: InvariantLifecycleState = InvariantLifecycleState.REGISTERED
    verified_state_id: str | None = None
    dependency_snapshot_hash: str | None = None
    evidence_reference: str | None = None
    provenance: str = "unspecified"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.invariant_id:
            raise ValueError("Invariant.invariant_id must be non-empty")
        if self.version < 1:
            raise ValueError(f"Invariant {self.invariant_id!r}: version must be >= 1")

    def transition_to(self, target: InvariantLifecycleState) -> None:
        """Move this invariant to `target`, enforcing the legal-transition table.

        Raises:
            InvalidLifecycleTransition: if `current -> target` is not
                a permitted transition per core.domain.enums'
                _ALLOWED_LIFECYCLE_TRANSITIONS table.
        """
        if not is_allowed_lifecycle_transition(self.lifecycle_state, target):
            raise InvalidLifecycleTransition(
                f"Invariant {self.invariant_id!r}: illegal lifecycle transition "
                f"{self.lifecycle_state.value} -> {target.value}"
            )
        self.lifecycle_state = target

    def is_protected(self) -> bool:
        """Whether this invariant currently counts as a protected obligation.

        Per Section IV-E: "Protection requires current evidence for the
        current trusted state; a protected invariant is not merely a
        historical PASS" -- so this checks the lifecycle_state
        specifically, not merely "did this ever pass."
        """
        return self.lifecycle_state is InvariantLifecycleState.PROTECTED

    def canonical_dict(self) -> dict[str, Any]:
        """Deterministic dict representation for hashing / evidence records."""
        return {
            "invariant_id": self.invariant_id,
            "version": self.version,
            "description": self.description,
            "invariant_type": self.invariant_type.value,
            "predicate_id": self.predicate_id,
            "scope_id": self.scope_id,
            "applicability_rule": self.applicability_rule,
            "verification_policy_id": self.verification_policy_id,
            "verifier_version": self.verifier_version,
            "lifecycle_state": self.lifecycle_state.value,
            "verified_state_id": self.verified_state_id,
            "dependency_snapshot_hash": self.dependency_snapshot_hash,
            "evidence_reference": self.evidence_reference,
            "provenance": self.provenance,
        }

    def content_hash(self) -> str:
        return content_hash(self.canonical_dict())


class DuplicateInvariantError(Exception):
    """Raised when registering an invariant_id that is already registered
    at the same version."""


class InvariantNotFoundError(Exception):
    """Raised when looking up an invariant_id that has no registered version."""


class InvariantRegistry:
    """In-memory invariant registry (P1).

    A real persistence-backed registry is P2/P9 work (Evidence
    Foundation, AWS/Terraform integration); this class exists now so
    that P1's domain objects can be constructed and tested end-to-end
    without depending on unimplemented phases. Keyed by
    (invariant_id, version) so multiple versions of the same logical
    invariant can coexist, matching Section IV-E's "verifier/
    configuration version" field -- an invariant's checkable meaning
    can change across verifier versions, and the registry must not
    silently collapse those into one entry.
    """

    def __init__(self) -> None:
        self._invariants: dict[tuple[str, int], Invariant] = {}

    def register(self, invariant: Invariant) -> None:
        key = (invariant.invariant_id, invariant.version)
        if key in self._invariants:
            raise DuplicateInvariantError(
                f"Invariant {invariant.invariant_id!r} version {invariant.version} "
                "is already registered"
            )
        self._invariants[key] = invariant

    def get(self, invariant_id: str, version: int) -> Invariant:
        key = (invariant_id, version)
        if key not in self._invariants:
            raise InvariantNotFoundError(
                f"No invariant {invariant_id!r} at version {version}"
            )
        return self._invariants[key]

    def latest_version(self, invariant_id: str) -> Invariant:
        """Return the highest-version registered entry for `invariant_id`."""
        matches = [inv for (iid, _v), inv in self._invariants.items() if iid == invariant_id]
        if not matches:
            raise InvariantNotFoundError(f"No invariant registered with id {invariant_id!r}")
        return max(matches, key=lambda inv: inv.version)

    def all_protected(self) -> list[Invariant]:
        """All currently-protected invariants across the registry.

        This is the registry-level building block that P4 (Impact
        engine) will use to compute P_t, the protected invariant set
        associated with a trusted state (Section IV-F).
        """
        return [inv for inv in self._invariants.values() if inv.is_protected()]

    def __len__(self) -> int:
        return len(self._invariants)
