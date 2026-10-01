"""Invariants: definitions, registry, proofs, state-scoped references and candidate-scoped
evaluations (Doc 05 §10, §28; Doc 06 §4.2, §8, §9, §13, §14, §29; C-04, C-23, C-30, C-31, C-37).

Doc 05 §10.2: "The definition and the state-specific reference are intentionally
separate." So:

- ``Invariant`` is the immutable, versioned definition. It has no status (C-04).
- ``InvariantRef`` belongs to one ``TrustedState``: PROTECTED, VIOLATED or UNCERTAIN,
  with evidence, immutable (C-31).
- ``InvariantEvaluation`` is candidate-scoped and carries the in-flight statuses
  (AFFECTED, REVERIFYING, ...) and the originating verification result (C-23, C-30).
  The parent state's references are never touched by an evaluation.

``InvariantProof``, ``InvariantRef`` and ``InvariantEvaluation`` are lifecycle-bearing: they can
be created only through the factories and lifecycle methods below, so
``dataclasses.replace`` and direct constructor calls cannot skip a transition
(Doc 06 §30). The guard token is module-private; Python cannot stop deliberate
``object.__setattr__`` misuse (P1a risk R5).
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable, Mapping
from dataclasses import InitVar, dataclass
from datetime import datetime
from typing import Any, Final

from core.domain.enums import (
    InvariantCategory,
    InvariantStatus,
    ProofOrigin,
    VerificationResult,
)
from core.domain.errors import (
    DomainValidationError,
    IllegalTransitionError,
    UnauthorizedConstructionError,
)
from core.domain.hashing import content_hash
from core.domain.ids import require_uuid
from core.domain.jsonvalue import (
    freeze_json,
    iso_utc,
    parse_enum,
    parse_utc,
    require_enum,
    require_int,
    require_keys,
    require_text,
    thaw_json,
    utc,
    validate_json,
)
from core.domain.lifecycle import (
    RESULT_TO_STATUS,
    TRUSTED_REF_STATUSES,
    apply_verification_result,
    check_invariant_transition,
)

_INVARIANT_ID = re.compile(r"INV-[A-Z0-9]+-[0-9]{3}")
_REF_TOKEN: Final = object()
_EVALUATION_TOKEN: Final = object()
_PROOF_TOKEN: Final = object()

# Result-free statuses of an evaluation: no result, no evidence, no verification time yet.
_PENDING_STATUSES = frozenset(
    {
        InvariantStatus.REGISTERED,
        InvariantStatus.VERIFYING,
        InvariantStatus.AFFECTED,
        InvariantStatus.REVERIFYING,
    }
)


def _invariant_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _INVARIANT_ID.fullmatch(value) is None:
        raise DomainValidationError(f"{field}: must look like INV-<AREA>-<NNN> (Doc 05 §3)")
    return value


def _evidence_ids(value: object, field: str, *, required: bool) -> tuple[str, ...]:
    """Evidence ids as a sorted, duplicate-free tuple of UUIDs (derived rule)."""
    if not isinstance(value, list | tuple):
        raise DomainValidationError(f"{field}: must be a list of evidence UUIDs")
    ids = sorted({require_uuid(item, f"{field}[{index}]") for index, item in enumerate(value)})
    if required and not ids:
        raise DomainValidationError(f"{field}: evidence is required (Doc 06 §14, §29)")
    return tuple(ids)


def _text_tuple(value: object, field: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise DomainValidationError(f"{field}: must be a list of text")
    return tuple(sorted({require_text(item, f"{field}[{i}]") for i, item in enumerate(value)}))


@dataclass(frozen=True)
class InvariantScope:
    """Which resources an invariant covers (Doc 06 §13), explicit enough for deterministic impact
    analysis. Lists are stored sorted and duplicate-free."""

    resources: tuple[str, ...]
    resource_types: tuple[str, ...]
    relationships: tuple[str, ...]
    properties: tuple[str, ...]
    dependency_depth: int

    def __post_init__(self) -> None:
        for name in ("resources", "resource_types", "relationships", "properties"):
            object.__setattr__(
                self, name, _text_tuple(getattr(self, name), f"InvariantScope.{name}")
            )
        require_int(self.dependency_depth, "InvariantScope.dependency_depth", 0)
        # Derived rule (Doc 06 §13): a scope names resources or resource types.
        if not self.resources and not self.resource_types:
            raise DomainValidationError(
                "InvariantScope: resources or resource_types must be non-empty (Doc 06 §13)"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resources": list(self.resources),
            "resource_types": list(self.resource_types),
            "relationships": list(self.relationships),
            "properties": list(self.properties),
            "dependency_depth": self.dependency_depth,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InvariantScope:
        fields = require_keys(
            data,
            ("resources", "resource_types", "relationships", "properties", "dependency_depth"),
            "InvariantScope",
        )
        return cls(
            resources=fields["resources"],
            resource_types=fields["resource_types"],
            relationships=fields["relationships"],
            properties=fields["properties"],
            dependency_depth=fields["dependency_depth"],
        )


_CHANGEABLE_FIELDS = frozenset(
    {"name", "category", "description", "predicate", "scope", "verifier_id", "verifier_version"}
)


@dataclass(frozen=True)
class Invariant:
    """An immutable, versioned invariant definition (Doc 05 §10.1). It has no status (C-04)."""

    invariant_id: str
    version: int
    name: str
    category: InvariantCategory
    description: str
    predicate: Mapping[str, Any]
    scope: InvariantScope
    verifier_id: str
    verifier_version: str
    created_at: datetime

    def __post_init__(self) -> None:
        _invariant_id(self.invariant_id, "Invariant.invariant_id")
        require_int(self.version, "Invariant.version", 1)
        for name in ("name", "description", "verifier_id", "verifier_version"):
            require_text(getattr(self, name), f"Invariant.{name}")
        require_enum(self.category, InvariantCategory, "Invariant.category")
        if not isinstance(self.predicate, Mapping) or len(self.predicate) == 0:
            raise DomainValidationError("Invariant.predicate: must be a non-empty JSON object")
        validate_json(self.predicate, "Invariant.predicate")
        object.__setattr__(self, "predicate", freeze_json(self.predicate))
        if not isinstance(self.scope, InvariantScope):
            raise DomainValidationError("Invariant.scope: must be an InvariantScope")
        object.__setattr__(self, "created_at", utc(self.created_at, "Invariant.created_at"))

    def _definition_payload(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "version": self.version,
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "predicate": thaw_json(self.predicate),
            "scope": self.scope.to_dict(),
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
        }

    def definition_hash(self) -> str:
        """SHA-256 over the whole definition except ``created_at`` (stable under key order)."""
        return content_hash(self._definition_payload())

    @classmethod
    def new_version(cls, definition: Invariant, *, now: datetime, **changes: Any) -> Invariant:
        """A new definition with version + 1 (Doc 06 §4.2: changing a definition creates a new
        version). The identity, the version and ``created_at`` cannot be overridden."""
        unknown = set(changes) - _CHANGEABLE_FIELDS
        if unknown:
            raise DomainValidationError(
                f"Invariant.new_version: cannot change {sorted(unknown)} (Doc 06 §4.2)"
            )
        return dataclasses.replace(
            definition, version=definition.version + 1, created_at=now, **changes
        )

    def to_dict(self) -> dict[str, Any]:
        data = self._definition_payload()
        data["created_at"] = iso_utc(self.created_at)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Invariant:
        fields = require_keys(
            data,
            (
                "invariant_id",
                "version",
                "name",
                "category",
                "description",
                "predicate",
                "scope",
                "verifier_id",
                "verifier_version",
                "created_at",
            ),
            "Invariant",
        )
        return cls(
            invariant_id=fields["invariant_id"],
            version=fields["version"],
            name=fields["name"],
            category=parse_enum(fields["category"], InvariantCategory, "Invariant.category"),
            description=fields["description"],
            predicate=fields["predicate"],
            scope=InvariantScope.from_dict(fields["scope"]),
            verifier_id=fields["verifier_id"],
            verifier_version=fields["verifier_version"],
            created_at=parse_utc(fields["created_at"], "Invariant.created_at"),
        )


def new_version(definition: Invariant, *, now: datetime, **changes: Any) -> Invariant:
    """``Invariant.new_version`` as a function: the next version of ``definition`` (Doc 06 §4.2)."""
    return Invariant.new_version(definition, now=now, **changes)


class InvariantRegistry:
    """In-memory registry of definitions (P1b adds ``InvariantRepository``).

    Versions of one invariant are registered as 1, 2, 3, ... with no gaps. The registry has
    no status queries: status belongs to references and evaluations (C-04).
    """

    def __init__(self) -> None:
        self._definitions: dict[tuple[str, int], Invariant] = {}
        self._latest: dict[str, int] = {}

    def register(self, definition: Invariant) -> None:
        if not isinstance(definition, Invariant):
            raise DomainValidationError("InvariantRegistry.register: expected an Invariant")
        key = (definition.invariant_id, definition.version)
        if key in self._definitions:
            raise DomainValidationError(
                f"InvariantRegistry: {definition.invariant_id} v{definition.version} is already "
                "registered (Doc 06 §4.2)"
            )
        expected = self._latest.get(definition.invariant_id, 0) + 1
        if definition.version != expected:
            raise DomainValidationError(
                f"InvariantRegistry: {definition.invariant_id} must be registered as version "
                f"{expected}, not {definition.version} (versions have no gaps)"
            )
        self._definitions[key] = definition
        self._latest[definition.invariant_id] = definition.version

    def get(self, invariant_id: str, version: int) -> Invariant:
        try:
            return self._definitions[(invariant_id, version)]
        except KeyError:
            raise DomainValidationError(
                f"InvariantRegistry: {invariant_id} v{version} is not registered"
            ) from None

    def latest(self, invariant_id: str) -> Invariant:
        if invariant_id not in self._latest:
            raise DomainValidationError(f"InvariantRegistry: {invariant_id} is not registered")
        return self._definitions[(invariant_id, self._latest[invariant_id])]

    def definitions(self) -> list[Invariant]:
        return [self._definitions[key] for key in sorted(self._definitions)]


@dataclass(frozen=True)
class InvariantProof:
    """The verified outcome for one invariant, as input to the trusted-state factories (C-40).

    A proof cannot be built by hand, and ``dataclasses.replace`` cannot change one. It exists only
    through ``for_baseline`` (origin BASELINE), ``InvariantEvaluation.to_proof`` (origin VERIFIED,
    bound to the evaluation's candidate) and ``carry_forward`` (origin CARRIED_FORWARD, bound to the
    candidate and to the state it was copied from). ``TrustedState.promote`` checks the binding
    (Doc 06 §22 SM-006).
    """

    invariant_id: str
    invariant_version: int
    status: InvariantStatus
    evidence_ids: tuple[str, ...]
    verified_at: datetime
    origin: ProofOrigin
    candidate_id: str | None
    source_state_id: str | None
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        if _token is not _PROOF_TOKEN:
            raise UnauthorizedConstructionError(
                "InvariantProof can be created only by InvariantProof.for_baseline, "
                "InvariantEvaluation.to_proof or InvariantProof.carry_forward (C-40, SM-006)"
            )
        _invariant_id(self.invariant_id, "InvariantProof.invariant_id")
        require_int(self.invariant_version, "InvariantProof.invariant_version", 1)
        require_enum(self.status, InvariantStatus, "InvariantProof.status")
        if self.status not in TRUSTED_REF_STATUSES:
            raise DomainValidationError(
                f"InvariantProof.status: {self.status} cannot be recorded on a trusted state"
            )
        object.__setattr__(
            self,
            "evidence_ids",
            _evidence_ids(self.evidence_ids, "InvariantProof.evidence_ids", required=True),
        )
        object.__setattr__(self, "verified_at", utc(self.verified_at, "InvariantProof.verified_at"))
        require_enum(self.origin, ProofOrigin, "InvariantProof.origin")
        # The binding each origin must carry (C-40).
        wants_candidate = self.origin is not ProofOrigin.BASELINE
        wants_source = self.origin is ProofOrigin.CARRIED_FORWARD
        if (self.candidate_id is not None) != wants_candidate:
            raise DomainValidationError(
                f"InvariantProof: a {self.origin} proof "
                f"{'is bound to a candidate' if wants_candidate else 'has no candidate'} (C-40)"
            )
        if (self.source_state_id is not None) != wants_source:
            raise DomainValidationError(
                f"InvariantProof: a {self.origin} proof "
                f"{'names its source state' if wants_source else 'has no source state'} (C-40)"
            )
        if self.candidate_id is not None:
            require_uuid(self.candidate_id, "InvariantProof.candidate_id")
        if self.source_state_id is not None:
            require_uuid(self.source_state_id, "InvariantProof.source_state_id")

    @classmethod
    def for_baseline(
        cls,
        *,
        invariant_id: str,
        invariant_version: int,
        status: InvariantStatus,
        evidence_ids: Iterable[str],
        verified_at: datetime,
    ) -> InvariantProof:
        """The proof the baseline protocol records for version 0 (origin BASELINE, Doc 06 §24)."""
        if isinstance(evidence_ids, str) or not isinstance(evidence_ids, Iterable):
            raise DomainValidationError("InvariantProof.evidence_ids: must be a list of UUIDs")
        return cls(
            invariant_id=invariant_id,
            invariant_version=invariant_version,
            status=status,
            evidence_ids=tuple(evidence_ids),
            verified_at=verified_at,
            origin=ProofOrigin.BASELINE,
            candidate_id=None,
            source_state_id=None,
            _token=_PROOF_TOKEN,
        )

    @classmethod
    def carry_forward(cls, parent_ref: InvariantRef, candidate: object) -> InvariantProof:
        """The proof of an invariant that the candidate leaves as the current state has it
        (origin CARRIED_FORWARD). Status, evidence and verification time are copied unchanged, so a
        VIOLATED or UNCERTAIN reference stays that way. A PROTECTED reference must still satisfy
        proof, i.e. must not be invalidated (C-40). Whether carrying forward is permitted for an
        invariant the candidate affects is P6 policy (C-22)."""
        from core.domain.state import CandidateState

        if not isinstance(parent_ref, InvariantRef):
            raise DomainValidationError("InvariantProof.carry_forward: expected an InvariantRef")
        if not isinstance(candidate, CandidateState):
            raise DomainValidationError(
                "InvariantProof.carry_forward: candidate must be a CandidateState"
            )
        if parent_ref.state_id != candidate.parent_state_id:
            raise DomainValidationError(
                "C-40: the reference belongs to state "
                f"{parent_ref.state_id}, not the candidate's parent {candidate.parent_state_id}"
            )
        if parent_ref.status is InvariantStatus.PROTECTED and not parent_ref.can_satisfy_proof():
            raise DomainValidationError(
                f"C-40: the PROTECTED reference to {parent_ref.invariant_id} was invalidated "
                "and cannot be carried forward"
            )
        return cls(
            invariant_id=parent_ref.invariant_id,
            invariant_version=parent_ref.invariant_version,
            status=parent_ref.status,
            evidence_ids=parent_ref.evidence_ids,
            verified_at=parent_ref.last_verified_at,
            origin=ProofOrigin.CARRIED_FORWARD,
            candidate_id=candidate.candidate_id,
            source_state_id=parent_ref.state_id,
            _token=_PROOF_TOKEN,
        )


@dataclass(frozen=True)
class InvariantRef:
    """A trusted state's reference to one invariant version (C-31, Doc 05 §10.2, Doc 06 §14).

    Immutable. Status is PROTECTED, VIOLATED or UNCERTAIN, with evidence generated for
    ``state_id`` (DATA-INT-009). The invalidation fields are both set or both null; when set,
    the reference can no longer satisfy proof for a later state (C-37 leaves open which event
    sets them).
    """

    invariant_id: str
    invariant_version: int
    state_id: str
    status: InvariantStatus
    evidence_ids: tuple[str, ...]
    last_verified_at: datetime
    invalidated_by_candidate_id: str | None
    invalidation_reason: str | None
    origin: ProofOrigin
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        if _token is not _REF_TOKEN:
            raise UnauthorizedConstructionError(
                "InvariantRef can be created only by TrustedState factories or from_dict "
                "(Doc 06 §30)"
            )
        _invariant_id(self.invariant_id, "InvariantRef.invariant_id")
        require_int(self.invariant_version, "InvariantRef.invariant_version", 1)
        require_uuid(self.state_id, "InvariantRef.state_id")
        require_enum(self.status, InvariantStatus, "InvariantRef.status")
        require_enum(self.origin, ProofOrigin, "InvariantRef.origin")
        if self.status not in TRUSTED_REF_STATUSES:
            raise DomainValidationError(
                f"InvariantRef.status: {self.status} is not PROTECTED, VIOLATED or UNCERTAIN "
                "(C-31)"
            )
        object.__setattr__(
            self,
            "evidence_ids",
            _evidence_ids(self.evidence_ids, "InvariantRef.evidence_ids", required=True),
        )
        object.__setattr__(
            self, "last_verified_at", utc(self.last_verified_at, "InvariantRef.last_verified_at")
        )
        if (self.invalidated_by_candidate_id is None) != (self.invalidation_reason is None):
            raise DomainValidationError(
                "InvariantRef: invalidated_by_candidate_id and invalidation_reason must be "
                "both set or both null (Doc 06 §14)"
            )
        if self.invalidated_by_candidate_id is not None:
            require_uuid(
                self.invalidated_by_candidate_id, "InvariantRef.invalidated_by_candidate_id"
            )
            require_text(self.invalidation_reason, "InvariantRef.invalidation_reason")

    def can_satisfy_proof(self) -> bool:
        """True only for a PROTECTED reference that has not been invalidated (Doc 06 §14)."""
        return self.status is InvariantStatus.PROTECTED and self.invalidated_by_candidate_id is None

    @classmethod
    def _from_proof(cls, proof: InvariantProof, state_id: str) -> InvariantRef:
        """Used by the ``TrustedState`` factories only."""
        if not isinstance(proof, InvariantProof):
            raise DomainValidationError("InvariantRef: expected an InvariantProof")
        return cls(
            invariant_id=proof.invariant_id,
            invariant_version=proof.invariant_version,
            state_id=state_id,
            status=proof.status,
            evidence_ids=proof.evidence_ids,
            last_verified_at=proof.verified_at,
            invalidated_by_candidate_id=None,
            invalidation_reason=None,
            origin=proof.origin,
            _token=_REF_TOKEN,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "invariant_version": self.invariant_version,
            "state_id": self.state_id,
            "status": self.status.value,
            "evidence_ids": list(self.evidence_ids),
            "last_verified_at": iso_utc(self.last_verified_at),
            "invalidated_by_candidate_id": self.invalidated_by_candidate_id,
            "invalidation_reason": self.invalidation_reason,
            "origin": self.origin.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InvariantRef:
        fields = require_keys(
            data,
            (
                "invariant_id",
                "invariant_version",
                "state_id",
                "status",
                "evidence_ids",
                "last_verified_at",
                "invalidated_by_candidate_id",
                "invalidation_reason",
                "origin",
            ),
            "InvariantRef",
        )
        return cls(
            invariant_id=fields["invariant_id"],
            invariant_version=fields["invariant_version"],
            state_id=fields["state_id"],
            status=parse_enum(fields["status"], InvariantStatus, "InvariantRef.status"),
            evidence_ids=fields["evidence_ids"],
            last_verified_at=parse_utc(fields["last_verified_at"], "InvariantRef.last_verified_at"),
            invalidated_by_candidate_id=fields["invalidated_by_candidate_id"],
            invalidation_reason=fields["invalidation_reason"],
            origin=parse_enum(fields["origin"], ProofOrigin, "InvariantRef.origin"),
            _token=_REF_TOKEN,
        )


@dataclass(frozen=True)
class InvariantEvaluation:
    """Candidate-scoped status of one invariant (C-23, C-31).

    Created only by ``affect``, ``reopen`` and ``register``; every method returns a new object
    and the parent state's references are never modified (Doc 06 §15, §16.2). ``last_result``
    keeps the originating verification result, so UNKNOWN, UNSUPPORTED and VERIFIER_ERROR stay
    distinguishable although they share the UNCERTAIN status (C-30, Doc 05 §29).
    """

    candidate_id: str
    parent_state_id: str
    invariant_id: str
    invariant_version: int
    status: InvariantStatus
    last_result: VerificationResult | None
    evidence_ids: tuple[str, ...]
    reason: str
    verified_at: datetime | None
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        if _token is not _EVALUATION_TOKEN:
            raise UnauthorizedConstructionError(
                "InvariantEvaluation can be created only by affect, reopen, register or "
                "from_dict, and changed only by its lifecycle methods (Doc 06 §30)"
            )
        require_uuid(self.candidate_id, "InvariantEvaluation.candidate_id")
        require_uuid(self.parent_state_id, "InvariantEvaluation.parent_state_id")
        _invariant_id(self.invariant_id, "InvariantEvaluation.invariant_id")
        require_int(self.invariant_version, "InvariantEvaluation.invariant_version", 1)
        require_enum(self.status, InvariantStatus, "InvariantEvaluation.status")
        require_text(self.reason, "InvariantEvaluation.reason")  # Doc 06 §29
        if self.last_result is not None:
            require_enum(self.last_result, VerificationResult, "InvariantEvaluation.last_result")
        object.__setattr__(
            self,
            "evidence_ids",
            _evidence_ids(self.evidence_ids, "InvariantEvaluation.evidence_ids", required=False),
        )
        if self.verified_at is not None:
            object.__setattr__(
                self, "verified_at", utc(self.verified_at, "InvariantEvaluation.verified_at")
            )
        if self.status in _PENDING_STATUSES:
            if self.last_result is not None or self.verified_at is not None or self.evidence_ids:
                raise DomainValidationError(
                    f"InvariantEvaluation: {self.status} has no result, evidence or verification "
                    "time yet (Doc 06 §12)"
                )
        else:
            if self.last_result is None or RESULT_TO_STATUS[self.last_result] is not self.status:
                raise DomainValidationError(
                    f"InvariantEvaluation: status {self.status} does not follow from "
                    f"last_result {self.last_result} (C-30)"
                )
            if not self.evidence_ids or self.verified_at is None:
                raise DomainValidationError(
                    "InvariantEvaluation: a verified status needs evidence and a verification "
                    "time (Doc 06 §29, Doc 09 §37)"
                )

    # --- construction ---------------------------------------------------------------

    @classmethod
    def _checked_candidate(cls, parent_ref: InvariantRef, candidate: object) -> Any:
        from core.domain.state import CandidateState

        if not isinstance(parent_ref, InvariantRef):
            raise DomainValidationError("InvariantEvaluation: parent_ref must be an InvariantRef")
        if not isinstance(candidate, CandidateState):
            raise DomainValidationError("InvariantEvaluation: candidate must be a CandidateState")
        if parent_ref.state_id != candidate.parent_state_id:
            raise DomainValidationError(
                "DATA-INT-009: the parent reference belongs to state "
                f"{parent_ref.state_id}, not the candidate's parent {candidate.parent_state_id}"
            )
        return candidate

    @classmethod
    def _create(
        cls,
        candidate: Any,
        invariant_id: str,
        invariant_version: int,
        status: InvariantStatus,
        reason: str,
    ) -> InvariantEvaluation:
        return cls(
            candidate_id=candidate.candidate_id,
            parent_state_id=candidate.parent_state_id,
            invariant_id=invariant_id,
            invariant_version=invariant_version,
            status=status,
            last_result=None,
            evidence_ids=(),
            reason=reason,
            verified_at=None,
            _token=_EVALUATION_TOKEN,
        )

    @classmethod
    def affect(
        cls, parent_ref: InvariantRef, candidate: object, reason: str
    ) -> InvariantEvaluation:
        """PROTECTED -> AFFECTED, caused by a relevant change, not by proof of breakage
        (Doc 06 §8). The parent reference is read, never modified."""
        checked = cls._checked_candidate(parent_ref, candidate)
        check_invariant_transition(parent_ref.status, InvariantStatus.AFFECTED)
        return cls._create(
            checked,
            parent_ref.invariant_id,
            parent_ref.invariant_version,
            InvariantStatus.AFFECTED,
            require_text(reason, "InvariantEvaluation.reason"),
        )

    @classmethod
    def reopen(
        cls, parent_ref: InvariantRef, candidate: object, reason: str
    ) -> InvariantEvaluation:
        """VIOLATED or UNCERTAIN -> REVERIFYING once a new candidate is evaluated (Doc 06 §9)."""
        checked = cls._checked_candidate(parent_ref, candidate)
        check_invariant_transition(parent_ref.status, InvariantStatus.REVERIFYING)
        return cls._create(
            checked,
            parent_ref.invariant_id,
            parent_ref.invariant_version,
            InvariantStatus.REVERIFYING,
            require_text(reason, "InvariantEvaluation.reason"),
        )

    @classmethod
    def register(cls, candidate: object, invariant: Invariant) -> InvariantEvaluation:
        """REGISTERED, for an invariant that has no reference on the parent state."""
        from core.domain.state import CandidateState

        if not isinstance(candidate, CandidateState):
            raise DomainValidationError("InvariantEvaluation: candidate must be a CandidateState")
        if not isinstance(invariant, Invariant):
            raise DomainValidationError("InvariantEvaluation: invariant must be an Invariant")
        return cls._create(
            candidate,
            invariant.invariant_id,
            invariant.version,
            InvariantStatus.REGISTERED,
            "REGISTERED_FOR_CANDIDATE",
        )

    # --- lifecycle ------------------------------------------------------------------

    def _evolve(self, **changes: Any) -> InvariantEvaluation:
        return dataclasses.replace(self, _token=_EVALUATION_TOKEN, **changes)

    def start_verification(self) -> InvariantEvaluation:
        """REGISTERED -> VERIFYING."""
        check_invariant_transition(self.status, InvariantStatus.VERIFYING)
        return self._evolve(status=InvariantStatus.VERIFYING, reason="VERIFICATION_STARTED")

    def start_reverification(self) -> InvariantEvaluation:
        """AFFECTED -> REVERIFYING. Never straight to PROTECTED or VIOLATED (Doc 06 §12)."""
        check_invariant_transition(self.status, InvariantStatus.REVERIFYING)
        if self.status is not InvariantStatus.AFFECTED:
            raise IllegalTransitionError(
                "invariant",
                self.status,
                InvariantStatus.REVERIFYING,
                "Doc 06 §9",
                "start_reverification applies to an AFFECTED evaluation",
            )
        return self._evolve(status=InvariantStatus.REVERIFYING, reason="REVERIFICATION_STARTED")

    def apply_result(
        self,
        result: VerificationResult,
        evidence_ids: Iterable[str],
        verified_at: datetime,
    ) -> InvariantEvaluation:
        """VERIFYING or REVERIFYING -> the status of ``result`` (C-30). Evidence is required
        for every result, including VERIFIER_ERROR (Doc 09 §37)."""
        status = apply_verification_result(self.status, result)
        if isinstance(evidence_ids, str) or not isinstance(evidence_ids, Iterable):
            raise DomainValidationError(
                "InvariantEvaluation.apply_result: evidence_ids must be a list of UUIDs"
            )
        return self._evolve(
            status=status,
            last_result=result,
            evidence_ids=tuple(evidence_ids),
            reason=f"VERIFICATION_RESULT_{result.value}",
            verified_at=verified_at,
        )

    def to_proof(self) -> InvariantProof:
        """The proof for a trusted state, origin VERIFIED and bound to this evaluation's candidate
        (C-40). Only an evaluation that was verified, in this very evaluation, can produce one
        (SM-006): AFFECTED, REVERIFYING and never-verified evaluations cannot."""
        if self.last_result is None:
            raise IllegalTransitionError(
                "invariant",
                self.status,
                "proof",
                "SM-006",
                "the evaluation was never given a verification result",
            )
        if self.status not in TRUSTED_REF_STATUSES:
            raise IllegalTransitionError(
                "invariant",
                self.status,
                "proof",
                "SM-006",
                "only a verified evaluation can become a proof",
            )
        assert self.verified_at is not None  # guaranteed by __post_init__
        return InvariantProof(
            invariant_id=self.invariant_id,
            invariant_version=self.invariant_version,
            status=self.status,
            evidence_ids=self.evidence_ids,
            verified_at=self.verified_at,
            origin=ProofOrigin.VERIFIED,
            candidate_id=self.candidate_id,
            source_state_id=None,
            _token=_PROOF_TOKEN,
        )

    # --- serialization --------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "parent_state_id": self.parent_state_id,
            "invariant_id": self.invariant_id,
            "invariant_version": self.invariant_version,
            "status": self.status.value,
            "last_result": None if self.last_result is None else self.last_result.value,
            "evidence_ids": list(self.evidence_ids),
            "reason": self.reason,
            "verified_at": None if self.verified_at is None else iso_utc(self.verified_at),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InvariantEvaluation:
        fields = require_keys(
            data,
            (
                "candidate_id",
                "parent_state_id",
                "invariant_id",
                "invariant_version",
                "status",
                "last_result",
                "evidence_ids",
                "reason",
                "verified_at",
            ),
            "InvariantEvaluation",
        )
        last_result = fields["last_result"]
        verified_at = fields["verified_at"]
        return cls(
            candidate_id=fields["candidate_id"],
            parent_state_id=fields["parent_state_id"],
            invariant_id=fields["invariant_id"],
            invariant_version=fields["invariant_version"],
            status=parse_enum(fields["status"], InvariantStatus, "InvariantEvaluation.status"),
            last_result=(
                None
                if last_result is None
                else parse_enum(last_result, VerificationResult, "InvariantEvaluation.last_result")
            ),
            evidence_ids=fields["evidence_ids"],
            reason=fields["reason"],
            verified_at=(
                None
                if verified_at is None
                else parse_utc(verified_at, "InvariantEvaluation.verified_at")
            ),
            _token=_EVALUATION_TOKEN,
        )
