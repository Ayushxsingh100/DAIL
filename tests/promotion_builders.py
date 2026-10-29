"""Builders for the promotion tests (P6a). Not a test module.

Tests may import every package; ``core.promotion`` may import only ``core.domain`` (R18).
Everything is deterministic: ids come from ``tests.domain_builders.uid`` and times from ``at``.

``make_world`` builds the canonical scenario at the domain level: a trusted state ``v0`` in which
INV-SEC-001 is VIOLATED (public SSH is open) and the other three registry-v1.0 invariants are
PROTECTED; a candidate that fixes SSH; an impact report in which INV-SEC-001 and INV-FUNC-001 are
affected and INV-SEC-002 and INV-SEC-003 are eligible to carry forward; and a verification report
with a fresh L1 PASS for every required item. Each test then changes one thing.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from core.domain.enums import (
    CandidateStatus,
    ChangeType,
    InvariantCategory,
    InvariantStatus,
    VerificationResult,
)
from core.domain.impact import ImpactReport
from core.domain.invariant import Invariant, InvariantProof, InvariantRef
from core.domain.promotion import DecisionOutcome, OracleVerdict, PromotionPolicy
from core.domain.registry_v1 import registry_v1_invariants
from core.domain.state import CandidateState, TrustedState
from core.domain.verification import (
    VerificationClass,
    VerificationReason,
    VerificationReport,
    VerificationResultRecord,
    VerificationTargetType,
)
from core.promotion.decide import decide
from core.promotion.policy import dail_policy
from tests.domain_builders import (
    LINEAGE,
    NORMALIZATION,
    analyzing_candidate,
    at,
    canonical_resources,
    transition_candidate,
    uid,
)

SEC1, SEC2, SEC3, FUNC1 = "INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"
ALL = (SEC1, SEC2, SEC3, FUNC1)
GATES = ("STRUCTURAL", "CONSISTENCY")
BASELINE_ITEM = "RESOURCE:aws_internet_gateway.new"
PASS, FAIL = VerificationResult.PASS, VerificationResult.FAIL
UNKNOWN = VerificationResult.UNKNOWN
UNSUPPORTED = VerificationResult.UNSUPPORTED
ERROR = VerificationResult.VERIFIER_ERROR
DECISION_ID = uid(9100)
NOW = at(20)

_REASONS = {
    FAIL: VerificationReason.PREDICATE_VIOLATED,
    UNKNOWN: VerificationReason.RULE_INDETERMINATE,
    UNSUPPORTED: VerificationReason.TYPE_RELEVANT_UNSUPPORTED,
    ERROR: VerificationReason.VERIFIER_ERROR,
}


def _ref(parent: TrustedState, invariant_id: str) -> InvariantRef:
    return next(r for r in parent.invariant_refs if r.invariant_id == invariant_id)


def impact_for(
    parent: TrustedState,
    candidate: CandidateState,
    *,
    carry: Iterable[str] = (),
    affected: Iterable[str] = (),
    uncertain: Iterable[str] = (),
    ineligible: Iterable[str] = (),
    versions: dict[str, int] | None = None,
    with_baseline_work: bool = True,
) -> ImpactReport:
    """An impact report of ``candidate`` against ``parent``.

    ``carry`` are unaffected invariants whose prior evidence is eligible (the parent reference's
    own evidence); ``ineligible`` are unaffected but not eligible; ``affected`` and ``uncertain``
    are the impacted ones, which owe a work item. ``versions`` overrides the invariant version the
    report names (default: the version of the parent's reference). With ``with_baseline_work`` the
    report also owes the baseline item of the created resource ``BASELINE_ITEM``."""
    from tests import impact_builders as ib

    def version(invariant_id: str) -> int:
        if versions and invariant_id in versions:
            return versions[invariant_id]
        return _ref(parent, invariant_id).invariant_version

    impacted = [ib.affected_invariant(i, version(i)) for i in affected] + [
        ib.uncertain_invariant(i, version(i)) for i in uncertain
    ]
    kept = [
        ib.unaffected(i, version(i), eligible=True, evidence=_ref(parent, i).evidence_ids)
        for i in carry
    ] + [ib.unaffected(i, version(i)) for i in ineligible]
    work = [ib.work_for(item) for item in impacted]
    if with_baseline_work:
        work.append(ib.baseline_work("aws_internet_gateway.new"))
    changed = [ib.changed("aws_security_group.app")]
    if with_baseline_work:
        changed.append(ib.changed("aws_internet_gateway.new", ChangeType.CREATED))
    return ib.report(
        changed_resources=changed,
        affected=impacted,
        work=work,
        unaffected_invariants=kept,
        parent_state_id=parent.state_id,
        candidate_id=candidate.candidate_id,
    )


# --- verification results -------------------------------------------------------------------------


def record(
    candidate: CandidateState,
    target_id: str,
    result: VerificationResult = PASS,
    *,
    definition: Invariant | None = None,
    level: str | None = None,
    verifier: tuple[str, str] | None = None,
    candidate_hash: str | None = None,
    error_type: str = "RuntimeError",
    reason: VerificationReason | None = None,
    n: int = 0,
) -> VerificationResultRecord:
    """One result for ``target_id`` (an invariant, a gate item or a resource), by default a fresh
    result of the verifier the definition names: L1, as the verification engine gives for an
    invariant and a baseline item, and L0 for the two gate items, as it does."""
    assert candidate.state_hash is not None
    if target_id.startswith("INVARIANT:"):
        assert definition is not None
        target_type = VerificationTargetType.INVARIANT
        klass = (
            VerificationClass.SECURITY
            if definition.category is InvariantCategory.SECURITY
            else VerificationClass.FUNCTIONAL
        )
        invariant_id: str | None = definition.invariant_id
        version: int | None = definition.version
        chosen = verifier or (definition.verifier_id, definition.verifier_version)
    elif target_id in GATES:
        target_type = VerificationTargetType.STRUCTURAL
        klass = getattr(VerificationClass, target_id)
        invariant_id, version = None, None
        chosen = verifier or (f"dail.verify.{target_id.lower()}", "1")
    else:
        target_type = VerificationTargetType.RESOURCE
        klass = VerificationClass.BASELINE
        invariant_id, version = None, None
        chosen = verifier or ("dail.verify.baseline", "1")
    chosen_reason = None if result is PASS else (reason or _REASONS[result])
    error = (
        {"type": error_type, "message": "boom", "class": "Exception"} if result is ERROR else None
    )
    return VerificationResultRecord(
        verification_id=uid(7000 + n),
        request_id=uid(8000 + n),
        target_type=target_type,
        target_id=target_id,
        candidate_id=candidate.candidate_id,
        candidate_hash=candidate_hash or candidate.state_hash,
        invariant_id=invariant_id,
        invariant_version=version,
        verifier_id=chosen[0],
        verifier_version=chosen[1],
        evidence_level=level or ("L0" if target_id in GATES else "L1"),
        verification_class=klass,
        result=result,
        reason=chosen_reason,
        applicable=True,
        clauses=None,
        observations={},
        assumptions=(),
        evidence={"predicate": "p", "inputs": {}, "observations": {}, "result": result.value},
        error=error,
        started_at=at(10),
        completed_at=at(11),
    )


def report_of(
    candidate: CandidateState, records: Iterable[VerificationResultRecord]
) -> VerificationReport:
    items = list(records)
    return VerificationReport.create(
        candidate_id=candidate.candidate_id,
        candidate_hash=candidate.state_hash or "0" * 64,
        results=items,
        verifier_invocations=len(items),
        verifier_set_version="dail-verify-1",
        report_id=uid(6000),
    )


# --- the world ------------------------------------------------------------------------------------


def invariant_definitions() -> dict[str, Invariant]:
    return {
        d.invariant_id: d
        for d in registry_v1_invariants(
            at(0), source="aws_instance.app", destination="aws_db_instance.database"
        )
    }


def trusted_state(
    statuses: Mapping[str, InvariantStatus] | None = None,
    *,
    registry_version: int = 1,
    state_id: str | None = None,
    versions: Mapping[str, int] | None = None,
    ids: Iterable[str] = ALL,
) -> TrustedState:
    """A baseline (version 0): INV-SEC-001 VIOLATED, the rest PROTECTED unless ``statuses`` says
    otherwise."""
    wanted = {SEC1: InvariantStatus.VIOLATED}
    wanted.update(statuses or {})
    proofs = [
        InvariantProof.for_baseline(
            invariant_id=i,
            invariant_version=(versions or {}).get(i, 1),
            status=wanted.get(i, InvariantStatus.PROTECTED),
            evidence_ids=(uid(1100 + n),),
            verified_at=at(1),
        )
        for n, i in enumerate(sorted(ids))
    ]
    return TrustedState.establish_baseline(
        lineage_id=LINEAGE,
        resources=canonical_resources(ssh_open=True, db_path=True),
        invariant_proofs=proofs,
        evidence_refs=sorted({e for p in proofs for e in p.evidence_ids}),
        normalization_version=NORMALIZATION,
        invariant_registry_version=registry_version,
        now=at(1),
        state_id=state_id or uid(1),
    )


@dataclass(frozen=True)
class World:
    trusted: TrustedState
    candidate: CandidateState
    impact: ImpactReport
    verification: VerificationReport
    policy: PromotionPolicy
    records: Mapping[str, VerificationResultRecord] = field(default_factory=dict)
    definitions: Mapping[str, Invariant] = field(default_factory=dict)

    def with_report(self, records: Iterable[VerificationResultRecord]) -> World:
        items = list(records)
        return dataclasses.replace(
            self,
            records={r.target_id: r for r in items},
            verification=report_of(self.candidate, items),
        )

    def with_policy(self, **changes: Any) -> World:
        return dataclasses.replace(self, policy=dataclasses.replace(self.policy, **changes))


def target(invariant_id: str, version: int = 1) -> str:
    return f"INVARIANT:{invariant_id}:{version}"


def make_world(
    *,
    results: Mapping[str, VerificationResult | None | VerificationResultRecord] | None = None,
    affected: Iterable[str] = (SEC1, FUNC1),
    uncertain: Iterable[str] = (),
    carry: Iterable[str] | None = None,
    ineligible: Iterable[str] = (),
    statuses: Mapping[str, InvariantStatus] | None = None,
    registry_version: int = 1,
    candidate_status: CandidateStatus = CandidateStatus.ANALYZING,
    with_baseline_work: bool = True,
    policy: PromotionPolicy | None = None,
    automatic_enabled: bool = True,
) -> World:
    """The canonical world, with ``results`` overriding single targets: a result value replaces the
    PASS, ``None`` removes the item, a record is used as it is."""
    definitions = invariant_definitions()
    trusted = trusted_state(statuses, registry_version=registry_version)
    candidate = analyzing_candidate(trusted, canonical_resources(ssh_open=False, db_path=True))
    if candidate_status is CandidateStatus.PROMOTABLE:
        candidate = transition_candidate(candidate, CandidateStatus.PROMOTABLE)
    impacted = tuple(affected)
    unsure = tuple(uncertain)
    kept = (
        tuple(i for i in ALL if i not in impacted and i not in unsure)
        if carry is None
        else tuple(carry)
    )
    unmatched = tuple(ineligible)
    impact = impact_for(
        trusted,
        candidate,
        carry=kept,
        affected=impacted,
        uncertain=unsure,
        ineligible=unmatched,
        with_baseline_work=with_baseline_work,
    )
    wanted: dict[str, Any] = {g: PASS for g in GATES}
    for i in (*impacted, *unsure):
        wanted[target(i)] = PASS
    if with_baseline_work:
        wanted[BASELINE_ITEM] = PASS
    wanted.update(results or {})
    items = []
    for n, (tid, value) in enumerate(sorted(wanted.items())):
        if value is None:
            continue
        if isinstance(value, VerificationResultRecord):
            items.append(value)
            continue
        definition = None
        if tid.startswith("INVARIANT:"):
            definition = definitions[tid.split(":")[1]]
        items.append(record(candidate, tid, value, definition=definition, n=n))
    chosen = policy or dail_policy(
        policy_version="policy-1",
        invariants=definitions.values(),
        automatic_enabled=automatic_enabled,
        invariant_registry_version=registry_version,
    )
    return World(
        trusted=trusted,
        candidate=candidate,
        impact=impact,
        verification=report_of(candidate, items),
        policy=chosen,
        records={r.target_id: r for r in items},
        definitions=definitions,
    )


def run(
    world: World,
    *,
    attempt_number: int = 1,
    oracle: Iterable[OracleVerdict] = (),
    decision_id: str = DECISION_ID,
) -> DecisionOutcome:
    return decide(
        world.candidate,
        world.trusted,
        world.impact,
        world.verification,
        world.policy,
        decision_id=decision_id,
        now=NOW,
        attempt_number=attempt_number,
        oracle_verdicts=tuple(oracle),
    )
