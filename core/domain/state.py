"""TrustedState and CandidateState with their lifecycle functions (Doc 05 §7, §8, §22, §23, §28;
Doc 06 §4-§6, §20, §22, §24, §30; C-29, C-31, C-32, C-33; P1a step 12).

A ``CandidateState`` is untrusted: it is built from exactly one ``TrustedState`` and moves
through the Doc 06 §5 lifecycle by the functions below, each of which returns a new object
(Doc 06 §30: "Represent transitions through domain functions"). Only
``TrustedState.promote`` creates the next trusted state, and only the Promotion Controller
(P6) may call it (contract rule R8). "Candidate failure never mutates Trusted State" (Doc 06
§5.1): nothing here modifies a ``TrustedState``.

Both classes carry a module-private construction token as an ``InitVar``. Direct constructor
calls and ``dataclasses.replace`` do not supply it, so they raise
``UnauthorizedConstructionError`` and cannot skip a transition. (Python cannot stop deliberate
``object.__setattr__`` misuse; the database triggers in P1b are the second line, P1a risk R5.)

Hashes (C-33): a candidate's ``state_hash`` is ``resource_set_hash`` over its resources; a
trusted state's ``state_hash`` also covers lineage, version and the invariant statuses
(Doc 05 §30). Both exclude record ids, timestamps and evidence ids (Doc 05 §27).
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable, Mapping
from dataclasses import InitVar, dataclass
from datetime import datetime
from typing import Any, Final

from core.domain.enums import CandidateSource, CandidateStatus, ProofOrigin
from core.domain.errors import (
    DomainValidationError,
    HashMismatchError,
    IllegalTransitionError,
    StaleParentError,
    UnauthorizedConstructionError,
)
from core.domain.hashing import content_hash
from core.domain.ids import new_uuid, require_uuid
from core.domain.invariant import InvariantProof, InvariantRef
from core.domain.jsonvalue import (
    iso_utc,
    parse_enum,
    parse_utc,
    require_enum,
    require_int,
    require_keys,
    require_text,
    utc,
)
from core.domain.lifecycle import check_candidate_transition
from core.domain.patch import Patch
from core.domain.resource import Resource

_CANDIDATE_TOKEN: Final = object()
_TRUSTED_TOKEN: Final = object()
_SHA256 = re.compile(r"[0-9a-f]{64}")

_POST_BUILD_STATUSES = frozenset(CandidateStatus) - {
    CandidateStatus.CREATED,
    CandidateStatus.BUILDING,
    CandidateStatus.FAILED,
}

# Why promote refuses a candidate that is not PROMOTABLE (Doc 06 §22).
_NOT_PROMOTABLE_RULE = {
    CandidateStatus.REJECTED: "SM-003",
    CandidateStatus.RETRY_REQUIRED: "SM-004",
    CandidateStatus.ESCALATED: "SM-005",
}


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DomainValidationError(f"{field}: must be a lowercase SHA-256 hex digest (C-33)")
    return value


def _resources(value: object, field: str) -> tuple[Resource, ...]:
    """Resources sorted by address with unique addresses."""
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise DomainValidationError(f"{field}: must be a list of Resource objects")
    items = tuple(value)
    if not all(isinstance(item, Resource) for item in items):
        raise DomainValidationError(f"{field}: must be a list of Resource objects")
    ordered = tuple(sorted(items, key=lambda r: r.address))
    addresses = [r.address for r in ordered]
    if len(set(addresses)) != len(addresses):
        raise DomainValidationError(f"{field}: duplicate resource address (Doc 05 §28)")
    return ordered


def _require_one_reference_per_invariant(invariant_ids: list[str]) -> None:
    """A trusted state holds at most one reference per invariant_id, at any version (C-40)."""
    seen: set[str] = set()
    for invariant_id in invariant_ids:
        if invariant_id in seen:
            raise DomainValidationError(
                f"C-40: duplicate reference for {invariant_id}; a trusted state holds at most one "
                "reference per invariant_id"
            )
        seen.add(invariant_id)


def _check_baseline_proofs(proofs: list[InvariantProof]) -> None:
    """``establish_baseline`` accepts only BASELINE proofs (C-40)."""
    for proof in proofs:
        if not isinstance(proof, InvariantProof):
            raise DomainValidationError("establish_baseline: expected InvariantProof objects")
        if proof.origin is not ProofOrigin.BASELINE:
            raise DomainValidationError(
                f"C-40, SM-006: the proof for {proof.invariant_id} has origin {proof.origin}; "
                "only a BASELINE proof can found a baseline"
            )


def _check_promotion_proofs(
    proofs: list[InvariantProof], candidate: CandidateState, current: TrustedState
) -> None:
    """``promote`` accepts only VERIFIED proofs bound to this candidate and CARRIED_FORWARD proofs
    from the current state (C-40, Doc 06 §22 SM-006)."""
    for proof in proofs:
        if not isinstance(proof, InvariantProof):
            raise DomainValidationError("TrustedState.promote: expected InvariantProof objects")
        if proof.origin is ProofOrigin.BASELINE:
            raise DomainValidationError(
                f"C-40, SM-006: the BASELINE proof for {proof.invariant_id} cannot promote a "
                "candidate"
            )
        if proof.candidate_id != candidate.candidate_id:
            raise DomainValidationError(
                f"C-40, SM-006: the proof for {proof.invariant_id} is bound to candidate "
                f"{proof.candidate_id}, not to {candidate.candidate_id}"
            )
        if (
            proof.origin is ProofOrigin.CARRIED_FORWARD
            and proof.source_state_id != current.state_id
        ):
            raise DomainValidationError(
                f"C-40, SM-006: the proof for {proof.invariant_id} was carried forward from state "
                f"{proof.source_state_id}, not from the current state {current.state_id}"
            )
    _require_one_reference_per_invariant([proof.invariant_id for proof in proofs])
    # Coverage: no invariant on the current state may be dropped, and none may go back to an
    # older definition (C-40; retiring an invariant is the open C-41).
    proof_versions = {proof.invariant_id: proof.invariant_version for proof in proofs}
    for ref in current.invariant_refs:
        if ref.invariant_id not in proof_versions:
            raise DomainValidationError(
                f"C-40, SM-006: no proof for {ref.invariant_id}; an invariant on the current "
                "state cannot be dropped at promotion (C-41)"
            )
        if proof_versions[ref.invariant_id] < ref.invariant_version:
            raise DomainValidationError(
                f"C-40: the proof for {ref.invariant_id} is version "
                f"{proof_versions[ref.invariant_id]}, lower than the current version "
                f"{ref.invariant_version}"
            )


def _resource_entries(resources: Iterable[Resource]) -> list[dict[str, str]]:
    return [
        {"address": r.address, "resource_type": r.resource_type, "fingerprint": r.fingerprint}
        for r in sorted(resources, key=lambda res: res.address)
    ]


def resource_set_hash(resources: Iterable[Resource], normalization_version: str) -> str:
    """SHA-256 over {normalization_version, resources: [{address, resource_type, fingerprint}]
    sorted by address} (C-33). A candidate's ``state_hash`` is this value."""
    return content_hash(
        {
            "normalization_version": normalization_version,
            "resources": _resource_entries(resources),
        }
    )


def _trusted_state_hash(
    lineage_id: str,
    version: int,
    normalization_version: str,
    resources: Iterable[Resource],
    invariant_refs: Iterable[InvariantRef],
) -> str:
    """SHA-256 over the canonical trusted state (Doc 05 §30, C-33)."""
    return content_hash(
        {
            "lineage_id": lineage_id,
            "version": version,
            "normalization_version": normalization_version,
            "resources": _resource_entries(resources),
            "invariants": [
                {
                    "invariant_id": ref.invariant_id,
                    "invariant_version": ref.invariant_version,
                    "status": ref.status.value,
                }
                for ref in sorted(
                    invariant_refs, key=lambda r: (r.invariant_id, r.invariant_version)
                )
            ],
        }
    )


@dataclass(frozen=True)
class CandidateState:
    """An untrusted candidate state (Doc 05 §8). ``status`` is the single status field;
    ``construction_status`` is derived from it (C-29)."""

    candidate_id: str
    lineage_id: str
    parent_state_id: str
    candidate_sequence: int
    source: CandidateSource
    patch_id: str
    patch_hash: str
    status: CandidateStatus
    resources: tuple[Resource, ...]
    state_hash: str | None
    normalization_version: str
    status_reason: str | None
    created_at: datetime
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        if _token is not _CANDIDATE_TOKEN:
            raise UnauthorizedConstructionError(
                "CandidateState can be created only by CandidateState.create or from_dict and "
                "changed only by the lifecycle functions (Doc 06 §30)"
            )
        require_uuid(self.candidate_id, "CandidateState.candidate_id")
        require_uuid(self.lineage_id, "CandidateState.lineage_id")
        require_uuid(self.parent_state_id, "CandidateState.parent_state_id")
        require_int(self.candidate_sequence, "CandidateState.candidate_sequence", 1)
        require_enum(self.source, CandidateSource, "CandidateState.source")
        require_uuid(self.patch_id, "CandidateState.patch_id")
        _sha256(self.patch_hash, "CandidateState.patch_hash")
        require_enum(self.status, CandidateStatus, "CandidateState.status")
        object.__setattr__(
            self, "resources", _resources(self.resources, "CandidateState.resources")
        )
        require_text(self.normalization_version, "CandidateState.normalization_version")
        if self.status_reason is not None:
            require_text(self.status_reason, "CandidateState.status_reason")
        object.__setattr__(self, "created_at", utc(self.created_at, "CandidateState.created_at"))
        if self.state_hash is not None:
            _sha256(self.state_hash, "CandidateState.state_hash")
        if self.status not in _POST_BUILD_STATUSES:
            if self.resources:
                raise DomainValidationError(
                    f"CandidateState: {self.status} has no resources yet (Doc 06 §5)"
                )
            if self.state_hash is not None:
                raise DomainValidationError(
                    f"CandidateState: {self.status} has no state_hash yet (Doc 05 §8.1)"
                )
            if self.status is CandidateStatus.FAILED and self.status_reason is None:
                raise DomainValidationError("CandidateState: FAILED requires a status_reason")
        else:
            if self.state_hash is None:
                raise DomainValidationError(
                    f"CandidateState: {self.status} requires a state_hash (Doc 05 §8.1)"
                )
            expected = resource_set_hash(self.resources, self.normalization_version)
            if self.state_hash != expected:
                raise HashMismatchError(
                    f"DATA-INT-010: candidate {self.candidate_id} state_hash does not match "
                    "its resources"
                )

    @property
    def construction_status(self) -> CandidateStatus:
        """Doc 05 §8's BUILDING | READY | FAILED, derived from ``status`` (C-29)."""
        if self.status in (CandidateStatus.CREATED, CandidateStatus.BUILDING):
            return CandidateStatus.BUILDING
        if self.status is CandidateStatus.FAILED:
            return CandidateStatus.FAILED
        return CandidateStatus.READY

    def _evolve(self, **changes: Any) -> CandidateState:
        return dataclasses.replace(self, _token=_CANDIDATE_TOKEN, **changes)

    @classmethod
    def create(
        cls,
        *,
        parent: TrustedState,
        patch: Patch,
        candidate_sequence: int,
        now: datetime,
        candidate_id: str | None = None,
    ) -> CandidateState:
        """A CREATED candidate built from exactly one trusted state (Doc 05 §8.1)."""
        if not isinstance(parent, TrustedState):
            raise DomainValidationError(
                "DATA-INT-002: a candidate's parent must be a TrustedState, never a candidate"
            )
        if not isinstance(patch, Patch):
            raise DomainValidationError("CandidateState.create: patch must be a Patch (Doc 05 §9)")
        if patch.parent_state_id != parent.state_id:
            raise DomainValidationError(
                f"DATA-INT-001: patch {patch.patch_id} was written against state "
                f"{patch.parent_state_id}, not the parent {parent.state_id}"
            )
        return cls(
            candidate_id=new_uuid() if candidate_id is None else candidate_id,
            lineage_id=parent.lineage_id,
            parent_state_id=parent.state_id,
            candidate_sequence=candidate_sequence,
            source=patch.source,
            patch_id=patch.patch_id,
            patch_hash=patch.content_hash,
            status=CandidateStatus.CREATED,
            resources=(),
            state_hash=None,
            normalization_version=parent.normalization_version,
            status_reason=None,
            created_at=now,
            _token=_CANDIDATE_TOKEN,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "lineage_id": self.lineage_id,
            "parent_state_id": self.parent_state_id,
            "candidate_sequence": self.candidate_sequence,
            "source": self.source.value,
            "patch_id": self.patch_id,
            "patch_hash": self.patch_hash,
            "status": self.status.value,
            "resources": [r.to_dict() for r in self.resources],
            "state_hash": self.state_hash,
            "normalization_version": self.normalization_version,
            "status_reason": self.status_reason,
            "created_at": iso_utc(self.created_at),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CandidateState:
        fields = require_keys(
            data,
            (
                "candidate_id",
                "lineage_id",
                "parent_state_id",
                "candidate_sequence",
                "source",
                "patch_id",
                "patch_hash",
                "status",
                "resources",
                "state_hash",
                "normalization_version",
                "status_reason",
                "created_at",
            ),
            "CandidateState",
        )
        raw_resources = fields["resources"]
        if not isinstance(raw_resources, list | tuple):
            raise DomainValidationError("CandidateState.resources: must be a list")
        return cls(
            candidate_id=fields["candidate_id"],
            lineage_id=fields["lineage_id"],
            parent_state_id=fields["parent_state_id"],
            candidate_sequence=fields["candidate_sequence"],
            source=parse_enum(fields["source"], CandidateSource, "CandidateState.source"),
            patch_id=fields["patch_id"],
            patch_hash=fields["patch_hash"],
            status=parse_enum(fields["status"], CandidateStatus, "CandidateState.status"),
            resources=tuple(Resource.from_dict(item) for item in raw_resources),
            state_hash=fields["state_hash"],
            normalization_version=fields["normalization_version"],
            status_reason=fields["status_reason"],
            created_at=parse_utc(fields["created_at"], "CandidateState.created_at"),
            _token=_CANDIDATE_TOKEN,
        )


def _candidate(value: object, name: str) -> CandidateState:
    if not isinstance(value, CandidateState):
        raise DomainValidationError(f"{name}: expected a CandidateState")
    return value


def start_building(candidate: CandidateState) -> CandidateState:
    """CREATED -> BUILDING."""
    c = _candidate(candidate, "start_building")
    check_candidate_transition(c.status, CandidateStatus.BUILDING)
    return c._evolve(status=CandidateStatus.BUILDING)


def finish_building(candidate: CandidateState, resources: Iterable[Resource]) -> CandidateState:
    """BUILDING -> READY, fixing the resource set and the candidate ``state_hash`` for good
    (Doc 05 §8.1: calculated before analysis and stable for the candidate version)."""
    c = _candidate(candidate, "finish_building")
    check_candidate_transition(c.status, CandidateStatus.READY)
    ordered = _resources(resources, "finish_building.resources")
    return c._evolve(
        status=CandidateStatus.READY,
        resources=ordered,
        state_hash=resource_set_hash(ordered, c.normalization_version),
    )


def fail_building(candidate: CandidateState, reason: str) -> CandidateState:
    """BUILDING -> FAILED (Doc 06 §27: a malformed candidate fails; Trusted is unchanged)."""
    c = _candidate(candidate, "fail_building")
    check_candidate_transition(c.status, CandidateStatus.FAILED)
    return c._evolve(
        status=CandidateStatus.FAILED, status_reason=require_text(reason, "fail_building.reason")
    )


def transition_candidate(candidate: CandidateState, target: CandidateStatus) -> CandidateState:
    """The remaining Doc 06 §5 transitions. READY, FAILED and PROMOTED are refused here, as is
    PROMOTABLE -> REJECTED: those go through ``finish_building``, ``fail_building``,
    ``mark_promoted`` and ``reject_stale_candidate``."""
    c = _candidate(candidate, "transition_candidate")
    if not isinstance(target, CandidateStatus):
        raise DomainValidationError("transition_candidate: target must be a CandidateStatus")
    if target is CandidateStatus.READY:
        raise IllegalTransitionError(
            "candidate", c.status, target, "Doc 06 §5", "use finish_building"
        )
    if target is CandidateStatus.FAILED:
        raise IllegalTransitionError(
            "candidate", c.status, target, "Doc 06 §5", "use fail_building"
        )
    if target is CandidateStatus.PROMOTED:
        raise IllegalTransitionError(
            "candidate",
            c.status,
            target,
            "SM-002",
            "only the Promotion Controller via mark_promoted",
        )
    if c.status is CandidateStatus.PROMOTABLE and target is CandidateStatus.REJECTED:
        raise IllegalTransitionError(
            "candidate", c.status, target, "C-29", "use reject_stale_candidate (Doc 06 §20)"
        )
    check_candidate_transition(c.status, target)
    return c._evolve(status=target)


def reject_stale_candidate(candidate: CandidateState, current: TrustedState) -> CandidateState:
    """PROMOTABLE -> REJECTED with reason STALE_PARENT, legal only when the candidate's parent
    is no longer the current state of its lineage (Doc 06 §20, §27; C-29)."""
    c = _candidate(candidate, "reject_stale_candidate")
    if not isinstance(current, TrustedState):
        raise DomainValidationError("reject_stale_candidate: current must be a TrustedState")
    if c.status is not CandidateStatus.PROMOTABLE:
        raise IllegalTransitionError(
            "candidate",
            c.status,
            CandidateStatus.REJECTED,
            "C-29",
            "reject_stale_candidate applies to a PROMOTABLE candidate",
        )
    if current.lineage_id != c.lineage_id:
        raise DomainValidationError(
            "reject_stale_candidate: the current state belongs to another lineage (Doc 06 §6)"
        )
    if current.state_id == c.parent_state_id:
        raise IllegalTransitionError(
            "candidate",
            c.status,
            CandidateStatus.REJECTED,
            "Doc 06 §20",
            "the candidate's parent is still the current state, so it is not stale",
        )
    return c._evolve(status=CandidateStatus.REJECTED, status_reason="STALE_PARENT")


def mark_promoted(candidate: CandidateState, new_state: TrustedState) -> CandidateState:
    """PROMOTABLE -> PROMOTED, recording that ``new_state`` is its promotion (DATA-INT-005).
    Only the Promotion Controller (P6) calls this, after ``TrustedState.promote``."""
    c = _candidate(candidate, "mark_promoted")
    check_candidate_transition(c.status, CandidateStatus.PROMOTED)
    if not isinstance(new_state, TrustedState):
        raise DomainValidationError("mark_promoted: new_state must be a TrustedState")
    if new_state.parent_state_id != c.parent_state_id:
        raise DomainValidationError(
            "DATA-INT-005: the promoted state's parent must equal the candidate's parent state"
        )
    if new_state.lineage_id != c.lineage_id:
        raise DomainValidationError("DATA-INT-005: the promoted state is in another lineage")
    if new_state.resource_set_hash() != c.state_hash:
        raise HashMismatchError(
            "DATA-INT-010: the promoted state's resources do not match the candidate's state_hash"
        )
    return c._evolve(status=CandidateStatus.PROMOTED)


@dataclass(frozen=True)
class TrustedState:
    """A trusted state (Doc 05 §7). Immutable, with a deterministic ``state_hash`` over its
    canonical content. Version 0 is the baseline; every later state comes only from
    ``TrustedState.promote`` (C-32)."""

    state_id: str
    lineage_id: str
    version: int
    parent_state_id: str | None
    state_hash: str
    resources: tuple[Resource, ...]
    invariant_refs: tuple[InvariantRef, ...]
    evidence_refs: tuple[str, ...]
    created_at: datetime
    committed_at: datetime
    commit_decision_id: str | None
    normalization_version: str
    invariant_registry_version: int
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        if _token is not _TRUSTED_TOKEN:
            raise UnauthorizedConstructionError(
                "TrustedState can be created only by establish_baseline, promote or from_dict "
                "(Doc 06 §4.1, SM-001, SM-002)"
            )
        require_uuid(self.state_id, "TrustedState.state_id")
        require_uuid(self.lineage_id, "TrustedState.lineage_id")
        require_int(self.version, "TrustedState.version", 0)
        if self.version == 0:
            if self.parent_state_id is not None or self.commit_decision_id is not None:
                raise DomainValidationError(
                    "TrustedState: version 0 (the baseline) has no parent_state_id and no "
                    "commit_decision_id (C-32)"
                )
        else:
            if self.parent_state_id is None:
                raise DomainValidationError(
                    f"TrustedState: version {self.version} needs a parent_state_id (Doc 05 §7.2)"
                )
            if self.commit_decision_id is None:
                raise DomainValidationError(
                    f"TrustedState: version {self.version} needs a commit_decision_id (Doc 06 §4.1)"
                )
            require_uuid(self.parent_state_id, "TrustedState.parent_state_id")
            require_uuid(self.commit_decision_id, "TrustedState.commit_decision_id")
        object.__setattr__(self, "resources", _resources(self.resources, "TrustedState.resources"))
        refs = self.invariant_refs
        if not isinstance(refs, list | tuple) or not all(isinstance(r, InvariantRef) for r in refs):
            raise DomainValidationError("TrustedState.invariant_refs: must be InvariantRef objects")
        for ref in refs:
            if ref.state_id != self.state_id:
                raise DomainValidationError(
                    f"DATA-INT-009: reference to {ref.invariant_id} belongs to state "
                    f"{ref.state_id}, not {self.state_id}"
                )
        _require_one_reference_per_invariant([r.invariant_id for r in refs])
        # origin is not part of state_hash (C-33), so a stored state is checked for it here:
        # a baseline holds BASELINE references only and every later state none (C-40).
        for ref in refs:
            if (ref.origin is ProofOrigin.BASELINE) != (self.version == 0):
                raise DomainValidationError(
                    f"C-40: the reference to {ref.invariant_id} has origin {ref.origin}, which a "
                    f"state of version {self.version} cannot hold"
                )
        ordered_refs = tuple(sorted(refs, key=lambda r: (r.invariant_id, r.invariant_version)))
        object.__setattr__(self, "invariant_refs", ordered_refs)
        evidence = self.evidence_refs
        if isinstance(evidence, str) or not isinstance(evidence, Iterable):
            raise DomainValidationError("TrustedState.evidence_refs: must be a list of UUIDs")
        evidence_list = [
            require_uuid(item, f"TrustedState.evidence_refs[{i}]")
            for i, item in enumerate(evidence)
        ]
        if len(set(evidence_list)) != len(evidence_list):
            raise DomainValidationError("TrustedState.evidence_refs: duplicate evidence id")
        object.__setattr__(self, "evidence_refs", tuple(sorted(evidence_list)))
        for ref in ordered_refs:
            missing = set(ref.evidence_ids) - set(evidence_list)
            if missing:
                raise DomainValidationError(
                    f"TrustedState: evidence of {ref.invariant_id} is not in evidence_refs "
                    "(Doc 05 §7.2)"
                )
        object.__setattr__(self, "created_at", utc(self.created_at, "TrustedState.created_at"))
        object.__setattr__(
            self, "committed_at", utc(self.committed_at, "TrustedState.committed_at")
        )
        if self.committed_at < self.created_at:
            raise DomainValidationError("TrustedState: committed_at precedes created_at")
        require_text(self.normalization_version, "TrustedState.normalization_version")
        require_int(self.invariant_registry_version, "TrustedState.invariant_registry_version", 1)
        _sha256(self.state_hash, "TrustedState.state_hash")
        expected = _trusted_state_hash(
            self.lineage_id,
            self.version,
            self.normalization_version,
            self.resources,
            self.invariant_refs,
        )
        if self.state_hash != expected:
            raise HashMismatchError(
                f"DATA-INT-010: trusted state {self.state_id} state_hash does not match its "
                "canonical content"
            )

    def resource_set_hash(self) -> str:
        """The hash a candidate with exactly these resources would carry as its ``state_hash``."""
        return resource_set_hash(self.resources, self.normalization_version)

    @classmethod
    def _build(
        cls,
        *,
        state_id: str,
        lineage_id: str,
        version: int,
        parent_state_id: str | None,
        resources: Iterable[Resource],
        invariant_proofs: Iterable[InvariantProof],
        evidence_refs: Iterable[str],
        created_at: datetime,
        commit_decision_id: str | None,
        normalization_version: str,
        invariant_registry_version: int,
    ) -> TrustedState:
        require_uuid(state_id, "TrustedState.state_id")
        ordered_resources = _resources(resources, "TrustedState.resources")
        proofs = list(invariant_proofs)
        refs = tuple(InvariantRef._from_proof(proof, state_id) for proof in proofs)
        require_int(version, "TrustedState.version", 0)
        require_text(normalization_version, "TrustedState.normalization_version")
        # Hash check happens in __post_init__; validate the inputs it needs first.
        require_uuid(lineage_id, "TrustedState.lineage_id")
        _require_one_reference_per_invariant([r.invariant_id for r in refs])
        state_hash = _trusted_state_hash(
            lineage_id, version, normalization_version, ordered_resources, refs
        )
        return cls(
            state_id=state_id,
            lineage_id=lineage_id,
            version=version,
            parent_state_id=parent_state_id,
            state_hash=state_hash,
            resources=ordered_resources,
            invariant_refs=refs,
            evidence_refs=tuple(evidence_refs),
            created_at=created_at,
            committed_at=created_at,
            commit_decision_id=commit_decision_id,
            normalization_version=normalization_version,
            invariant_registry_version=invariant_registry_version,
            _token=_TRUSTED_TOKEN,
        )

    @classmethod
    def establish_baseline(
        cls,
        *,
        lineage_id: str,
        resources: Iterable[Resource],
        invariant_proofs: Iterable[InvariantProof],
        evidence_refs: Iterable[str],
        normalization_version: str,
        invariant_registry_version: int,
        now: datetime,
        state_id: str | None = None,
    ) -> TrustedState:
        """The baseline, version 0: no parent and no promotion decision (C-32). It is created only
        when the baseline protocol accepts it, with current invariant evidence (Doc 06 §24)."""
        proofs = list(invariant_proofs)
        if not proofs:
            raise DomainValidationError(
                "establish_baseline: at least one invariant proof is required (Doc 06 §24)"
            )
        _check_baseline_proofs(proofs)
        return cls._build(
            state_id=new_uuid() if state_id is None else state_id,
            lineage_id=lineage_id,
            version=0,
            parent_state_id=None,
            resources=resources,
            invariant_proofs=proofs,
            evidence_refs=evidence_refs,
            created_at=now,
            commit_decision_id=None,
            normalization_version=normalization_version,
            invariant_registry_version=invariant_registry_version,
        )

    @classmethod
    def promote(
        cls,
        *,
        candidate: CandidateState,
        current: TrustedState,
        decision_id: str,
        invariant_proofs: Iterable[InvariantProof],
        evidence_refs: Iterable[str],
        invariant_registry_version: int,
        now: datetime,
        state_id: str | None = None,
    ) -> TrustedState:
        """The next trusted state: the only way a candidate becomes trusted (SM-001, SM-002).

        Checks structure, lineage, staleness and the proofs' origin and binding (C-40): only
        VERIFIED proofs bound to this candidate and CARRIED_FORWARD proofs from ``current`` are
        accepted. Whether carrying an invariant forward is allowed, and the promotion policy,
        belong to P6; only the Promotion Controller may call this (R8). ``current`` is never
        modified.
        """
        if not isinstance(candidate, CandidateState):
            raise DomainValidationError("TrustedState.promote: candidate must be a CandidateState")
        if not isinstance(current, TrustedState):
            raise DomainValidationError("TrustedState.promote: current must be a TrustedState")
        if candidate.status is not CandidateStatus.PROMOTABLE:
            raise IllegalTransitionError(
                "candidate",
                candidate.status,
                CandidateStatus.PROMOTED,
                _NOT_PROMOTABLE_RULE.get(candidate.status, "SM-002"),
                "only a PROMOTABLE candidate can become trusted",
            )
        if candidate.lineage_id != current.lineage_id:
            raise DomainValidationError(
                "TrustedState.promote: candidate and current state are in different lineages "
                "(Doc 06 §6)"
            )
        if candidate.parent_state_id != current.state_id:
            raise StaleParentError(
                candidate.status,
                CandidateStatus.PROMOTED,
                f"the candidate's parent {candidate.parent_state_id} is not the current state "
                f"{current.state_id}",
            )
        require_uuid(decision_id, "TrustedState.promote.decision_id")
        proofs = list(invariant_proofs)
        _check_promotion_proofs(proofs, candidate, current)
        return cls._build(
            state_id=new_uuid() if state_id is None else state_id,
            lineage_id=current.lineage_id,
            version=current.version + 1,
            parent_state_id=current.state_id,
            resources=candidate.resources,
            invariant_proofs=proofs,
            evidence_refs=evidence_refs,
            created_at=now,
            commit_decision_id=decision_id,
            normalization_version=candidate.normalization_version,
            invariant_registry_version=invariant_registry_version,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_id": self.state_id,
            "lineage_id": self.lineage_id,
            "version": self.version,
            "parent_state_id": self.parent_state_id,
            "state_hash": self.state_hash,
            "resources": [r.to_dict() for r in self.resources],
            "invariant_refs": [ref.to_dict() for ref in self.invariant_refs],
            "evidence_refs": list(self.evidence_refs),
            "created_at": iso_utc(self.created_at),
            "committed_at": iso_utc(self.committed_at),
            "commit_decision_id": self.commit_decision_id,
            "normalization_version": self.normalization_version,
            "invariant_registry_version": self.invariant_registry_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TrustedState:
        fields = require_keys(
            data,
            (
                "state_id",
                "lineage_id",
                "version",
                "parent_state_id",
                "state_hash",
                "resources",
                "invariant_refs",
                "evidence_refs",
                "created_at",
                "committed_at",
                "commit_decision_id",
                "normalization_version",
                "invariant_registry_version",
            ),
            "TrustedState",
        )
        raw_resources = fields["resources"]
        raw_refs = fields["invariant_refs"]
        if not isinstance(raw_resources, list | tuple) or not isinstance(raw_refs, list | tuple):
            raise DomainValidationError("TrustedState: resources and invariant_refs must be lists")
        return cls(
            state_id=fields["state_id"],
            lineage_id=fields["lineage_id"],
            version=fields["version"],
            parent_state_id=fields["parent_state_id"],
            state_hash=fields["state_hash"],
            resources=tuple(Resource.from_dict(item) for item in raw_resources),
            invariant_refs=tuple(InvariantRef.from_dict(item) for item in raw_refs),
            evidence_refs=fields["evidence_refs"],
            created_at=parse_utc(fields["created_at"], "TrustedState.created_at"),
            committed_at=parse_utc(fields["committed_at"], "TrustedState.committed_at"),
            commit_decision_id=fields["commit_decision_id"],
            normalization_version=fields["normalization_version"],
            invariant_registry_version=fields["invariant_registry_version"],
            _token=_TRUSTED_TOKEN,
        )
