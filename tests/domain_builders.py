"""Shared builders for the domain tests (P1a). Not a test module.

Everything is deterministic: ids come from ``uid(n)`` and timestamps from ``at(n)``,
so no test depends on a clock or on randomness.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from core.domain.enums import (
    CandidateSource,
    CandidateStatus,
    InvariantCategory,
    InvariantStatus,
    ProvenanceSourceKind,
    ReferenceResolution,
    ResourceSupport,
    VerificationResult,
)
from core.domain.invariant import (
    Invariant,
    InvariantEvaluation,
    InvariantProof,
    InvariantRef,
    InvariantScope,
)
from core.domain.patch import Patch
from core.domain.resource import Resource
from core.domain.state import (
    CandidateState,
    TrustedState,
    finish_building,
    start_building,
    transition_candidate,
)
from core.domain.values import Provenance, Reference

NORMALIZATION = "norm-1"
LINEAGE = "00000000-0000-4000-8000-0000000000aa"

SEC = "INV-SEC-001"
FUNC = "INV-FUNC-001"


def uid(n: int) -> str:
    """A deterministic canonical UUID string."""
    return str(uuid.UUID(int=n))


def at(minutes: int = 0) -> datetime:
    return datetime(2026, 10, 1, 9, 0, tzinfo=UTC) + timedelta(minutes=minutes)


def provenance() -> Provenance:
    return Provenance(
        source_kind=ProvenanceSourceKind.TERRAFORM_CONFIG,
        source_component="fixture",
        source_reference="main.tf",
        observed_at=at(0),
    )


def resource(
    address: str = "aws_instance.app",
    resource_type: str = "aws_instance",
    *,
    attributes: dict[str, Any] | None = None,
    security_attributes: dict[str, Any] | None = None,
    references: Iterable[Reference] = (),
    support_status: ResourceSupport = ResourceSupport.SUPPORTED,
    record_id: str | None = None,
) -> Resource:
    return Resource.create(
        address=address,
        resource_type=resource_type,
        logical_identity={"name": address.split(".")[-1]},
        attributes=attributes if attributes is not None else {"size": "small"},
        security_attributes=security_attributes if security_attributes is not None else {},
        semantic_attributes={},
        references=references,
        provenance=provenance(),
        support_status=support_status,
        record_id=record_id,
    )


def reference(source: str, target: str, attribute: str = "security_groups") -> Reference:
    return Reference(
        source_address=source,
        source_attribute=attribute,
        target_address=target,
        reference_type="reference",
        resolution_status=ReferenceResolution.SUPPORTED,
    )


def canonical_resources(*, ssh_open: bool, db_path: bool) -> list[Resource]:
    """The paper's scenario: public SSH and an EC2 -> RDS TCP/5432 path, each switchable."""
    web_sg = resource(
        "aws_security_group.web",
        "aws_security_group",
        security_attributes={"ssh_cidrs": ["0.0.0.0/0"] if ssh_open else ["10.0.0.0/8"]},
    )
    rule = resource(
        "aws_security_group_rule.ec2_to_rds",
        "aws_security_group_rule",
        attributes={"port": 5432, "source": "aws_security_group.web" if db_path else "none"},
        references=(
            [reference("aws_security_group_rule.ec2_to_rds", "aws_security_group.web")]
            if db_path
            else []
        ),
    )
    return [
        web_sg,
        rule,
        resource("aws_instance.app"),
        resource("aws_db_instance.db", "aws_db_instance"),
    ]


def invariant(
    invariant_id: str = SEC, category: InvariantCategory = InvariantCategory.SECURITY
) -> Invariant:
    return Invariant(
        invariant_id=invariant_id,
        version=1,
        name=f"{invariant_id} name",
        category=category,
        description=f"{invariant_id} description",
        predicate={"op": "fixture"},
        scope=InvariantScope(
            resources=(),
            resource_types=("aws_security_group",),
            relationships=(),
            properties=(),
            dependency_depth=1,
        ),
        verifier_id="fixture-verifier",
        verifier_version="1",
        created_at=at(0),
    )


def proof(
    invariant_id: str = SEC,
    status: InvariantStatus = InvariantStatus.PROTECTED,
    evidence: int = 1,
    minutes: int = 0,
) -> InvariantProof:
    """A BASELINE proof (``InvariantProof.for_baseline``, C-40)."""
    return InvariantProof.for_baseline(
        invariant_id=invariant_id,
        invariant_version=1,
        status=status,
        evidence_ids=(uid(1000 + evidence),),
        verified_at=at(minutes),
    )


_RESULT_FOR_STATUS = {
    InvariantStatus.PROTECTED: VerificationResult.PASS,
    InvariantStatus.VIOLATED: VerificationResult.FAIL,
    InvariantStatus.UNCERTAIN: VerificationResult.UNKNOWN,
}


def parent_ref(parent: TrustedState, invariant_id: str) -> InvariantRef:
    return next(ref for ref in parent.invariant_refs if ref.invariant_id == invariant_id)


def evaluation_for(
    parent: TrustedState, candidate: CandidateState, invariant_id: str
) -> InvariantEvaluation:
    """An evaluation of ``invariant_id`` for ``candidate``, ready for ``apply_result``: the
    lifecycle path the parent's reference allows (Doc 06 §8, §9, §12)."""
    ref = next((r for r in parent.invariant_refs if r.invariant_id == invariant_id), None)
    if ref is None:
        return InvariantEvaluation.register(candidate, invariant(invariant_id)).start_verification()
    if ref.status is InvariantStatus.PROTECTED:
        return InvariantEvaluation.affect(ref, candidate, "fixture").start_reverification()
    return InvariantEvaluation.reopen(ref, candidate, "fixture")


def verified_proof(
    parent: TrustedState,
    candidate: CandidateState,
    invariant_id: str = SEC,
    status: InvariantStatus = InvariantStatus.PROTECTED,
    evidence: int = 1,
    minutes: int = 10,
) -> InvariantProof:
    """A VERIFIED proof, obtained the only way C-40 allows: evaluation -> result -> ``to_proof``."""
    evaluation = evaluation_for(parent, candidate, invariant_id)
    done = evaluation.apply_result(_RESULT_FOR_STATUS[status], [uid(1000 + evidence)], at(minutes))
    return done.to_proof()


def carried_proof(
    parent: TrustedState, candidate: CandidateState, invariant_id: str = SEC
) -> InvariantProof:
    """A CARRIED_FORWARD proof copied from the parent's reference (C-40)."""
    return InvariantProof.carry_forward(parent_ref(parent, invariant_id), candidate)


def baseline(
    *,
    resources: Iterable[Resource] | None = None,
    proofs: Iterable[InvariantProof] | None = None,
    evidence_refs: Iterable[str] | None = None,
    state_id: str | None = None,
    lineage_id: str = LINEAGE,
) -> TrustedState:
    chosen = (
        list(proofs) if proofs is not None else [proof(SEC, evidence=1), proof(FUNC, evidence=2)]
    )
    evidence = (
        list(evidence_refs)
        if evidence_refs is not None
        else sorted({e for p in chosen for e in p.evidence_ids})
    )
    return TrustedState.establish_baseline(
        lineage_id=lineage_id,
        resources=(
            list(resources)
            if resources is not None
            else canonical_resources(ssh_open=True, db_path=True)
        ),
        invariant_proofs=chosen,
        evidence_refs=evidence,
        normalization_version=NORMALIZATION,
        invariant_registry_version=1,
        now=at(1),
        state_id=state_id or uid(1),
    )


def patch_for(parent: TrustedState, *, n: int = 1, content: str | None = None) -> Patch:
    return Patch.create(
        source=CandidateSource.FIXED_PATCH,
        content=content or f'resource "x" "p{n}" {{}}\n',
        parent_state_id=parent.state_id,
        now=at(2),
        patch_id=uid(2000 + n),
    )


def new_candidate(parent: TrustedState, *, sequence: int = 1, n: int = 1) -> CandidateState:
    return CandidateState.create(
        parent=parent,
        patch=patch_for(parent, n=n),
        candidate_sequence=sequence,
        now=at(3),
        candidate_id=uid(3000 + n),
    )


def ready_candidate(
    parent: TrustedState,
    resources: Iterable[Resource],
    *,
    sequence: int = 1,
    n: int = 1,
) -> CandidateState:
    candidate = start_building(new_candidate(parent, sequence=sequence, n=n))
    return finish_building(candidate, list(resources))


def analyzing_candidate(
    parent: TrustedState, resources: Iterable[Resource], *, sequence: int = 1, n: int = 1
) -> CandidateState:
    return transition_candidate(
        ready_candidate(parent, resources, sequence=sequence, n=n), CandidateStatus.ANALYZING
    )


def promotable_candidate(
    parent: TrustedState, resources: Iterable[Resource], *, sequence: int = 1, n: int = 1
) -> CandidateState:
    return transition_candidate(
        analyzing_candidate(parent, resources, sequence=sequence, n=n), CandidateStatus.PROMOTABLE
    )


_DEFAULT_EVIDENCE = {SEC: 11, FUNC: 12}


def default_verified_proofs(
    candidate: CandidateState, current: TrustedState
) -> list[InvariantProof]:
    """A PROTECTED, VERIFIED proof for every invariant on ``current`` (C-40 coverage).

    A candidate whose parent is not ``current`` is stale: no honest proof can exist for it, and
    ``promote`` refuses it (SM-010) before it reads any proof, so the list is empty then."""
    if candidate.parent_state_id != current.state_id:
        return []
    return [
        verified_proof(
            current,
            candidate,
            ref.invariant_id,
            InvariantStatus.PROTECTED,
            evidence=_DEFAULT_EVIDENCE.get(ref.invariant_id, 20 + index),
        )
        for index, ref in enumerate(current.invariant_refs)
    ]


def promote(
    candidate: CandidateState,
    current: TrustedState,
    *,
    proofs: Iterable[InvariantProof] | None = None,
    state_id: str | None = None,
    decision: int = 1,
    minutes: int = 10,
) -> TrustedState:
    chosen = list(proofs) if proofs is not None else default_verified_proofs(candidate, current)
    return TrustedState.promote(
        candidate=candidate,
        current=current,
        decision_id=uid(4000 + decision),
        invariant_proofs=chosen,
        evidence_refs=sorted({e for p in chosen for e in p.evidence_ids}),
        invariant_registry_version=1,
        now=at(minutes),
        state_id=state_id or uid(10 + decision),
    )
