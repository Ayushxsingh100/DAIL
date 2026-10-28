"""``compute_impact``: which protected invariants must be checked again (Doc 08, all; C-137,
C-140, C-141; P4 steps 5 and 6).

Impact decides what must be checked, never what is true (Doc 08 §3):

    AFFECTED != VIOLATED     AFFECTED != UNKNOWN
    NO EDGE != NO DEPENDENCY NO PRIOR EVIDENCE != PASS

The algorithm is resource-level and follows the registry footprint (C-140):

1. The changed set: every identity match that is not UNCHANGED, plus UNCHANGED resources with
   unresolved content (C-117), see ``changes``.
2. For each invariant, its footprint in the trusted graph and in the candidate graph (``walk``).
3. A change is in the invariant when its trusted or candidate ref is a member in either graph;
   DIRECT when it is a seed (a scope element), DEPENDENCY when only the walk reaches it. MODIFIED,
   CREATED, DELETED and REPLACED make the invariant AFFECTED; an UNCERTAIN identity or unresolved
   content makes it UNCERTAIN, and nothing is ever preserved because one reading looks safe.
4. A footprint that is not fully known makes the invariant UNCERTAIN when a resource of a walkable
   type changed; an absent endpoint or a missing binding does so unconditionally.
5. One record per invariant merges its reasons, paths and changed resources (Doc 08 §31). An
   impacted invariant owes verification work, every created resource owes baseline work, and an
   unaffected invariant says whether its prior proof may be carried (Doc 08 §21-§22).

The result is data only: the engine keeps historical evidence and decides nothing about promotion.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Final

from core.domain.enums import ChangeType, ImpactStatus
from core.domain.evidence import EvidenceValidity
from core.domain.graph import DependencyGraph
from core.domain.identity import IdentityReport
from core.domain.impact import (
    AFFECTED_CODES,
    UNCERTAIN_CODES,
    ChangedResource,
    ImpactedInvariant,
    ImpactPath,
    ImpactReason,
    ImpactReport,
    ImpactStep,
    ImpactType,
    ReasonCode,
    StepDirection,
    UnaffectedInvariant,
    UncertaintyRecord,
    VerificationWorkItem,
    WorkPriority,
    WorkTargetType,
)
from core.domain.invariant import Invariant
from core.domain.resource import Resource
from core.impact.changes import ChangeSource, Origin, change_sources
from core.impact.inputs import CheckedInputs, PriorProof, check_inputs
from core.impact.walk import (
    Footprint,
    IncompleteCode,
    Member,
    footprint,
    walkable_types,
)

_STRONGEST: Final = (
    ReasonCode.DELETED_IN_SCOPE,
    ReasonCode.REPLACED_IN_SCOPE,
    ReasonCode.CREATED_IN_SCOPE,
    ReasonCode.SCOPE_RESOURCE_CHANGED,
    ReasonCode.SCOPE_TYPE_CHANGED,
    ReasonCode.FOOTPRINT_MEMBER_CHANGED,
    ReasonCode.IDENTITY_UNCERTAIN,
    ReasonCode.ENDPOINT_ABSENT,
    ReasonCode.UNRESOLVED_CONTENT,
    ReasonCode.WALK_INCOMPLETE,
)
_UNCONDITIONAL: Final = frozenset({IncompleteCode.ABSENT_SEED, IncompleteCode.MISSING_BINDING})
_FLIP: Final = {
    StepDirection.FORWARD: StepDirection.REVERSE,
    StepDirection.REVERSE: StepDirection.FORWARD,
}


# --- one change against one footprint -------------------------------------------------------------


def _pick(hits: list[tuple[str, Member]]) -> tuple[str, Member]:
    """The canonical member among the matches of one change: a seed first, then the shortest
    path, then the smallest edge-key sequence, then the trusted graph, then the address."""
    return min(
        hits,
        key=lambda hit: (
            not hit[1].seed,
            len(hit[1].path),
            tuple(step.edge_key for step in hit[1].path),
            hit[0] != "trusted",
            hit[1].address,
        ),
    )


def _path(changed_ref: str, member: Member) -> ImpactPath:
    """The path from the changed resource to the scope seed: the walk path, reversed."""
    steps = tuple(
        ImpactStep(
            edge_key=step.edge_key,
            from_node=step.to_node,
            to_node=step.from_node,
            relationship=step.relationship,
            direction=_FLIP[step.direction],
            status=step.status,
        )
        for step in reversed(member.path)
    )
    return ImpactPath(changed_ref, steps)


def _code(source: ChangeSource, member: Member) -> ReasonCode:
    if source.origin is Origin.UNRESOLVED:
        return ReasonCode.UNRESOLVED_CONTENT
    change = source.changed.change_type
    if change is ChangeType.UNCERTAIN:
        return ReasonCode.IDENTITY_UNCERTAIN
    if change is ChangeType.CREATED:
        return ReasonCode.CREATED_IN_SCOPE
    if change is ChangeType.DELETED:
        return ReasonCode.DELETED_IN_SCOPE
    if change is ChangeType.REPLACED:
        return ReasonCode.REPLACED_IN_SCOPE
    if not member.seed:
        return ReasonCode.FOOTPRINT_MEMBER_CHANGED
    explicit = any(e.startswith(("resources:", "binding:")) for e in member.scope_elements)
    return ReasonCode.SCOPE_RESOURCE_CHANGED if explicit else ReasonCode.SCOPE_TYPE_CHANGED


class _Record:
    """Everything one invariant collects while the changes are checked against its footprints."""

    def __init__(self) -> None:
        self.reasons: dict[tuple[str, str, str, str], ImpactReason] = {}
        self.refs: set[str] = set()
        self.paths: dict[tuple[str, int, tuple[str, ...]], ImpactPath] = {}
        self.types: set[ImpactType] = set()
        self.uncertainty: dict[tuple[str, str], UncertaintyRecord] = {}
        self.hit_unresolved: list[ChangedResource] = []

    def add(self, reason: ImpactReason) -> None:
        self.reasons[reason.sort_key()] = reason
        if reason.changed_ref is not None:
            self.refs.add(reason.changed_ref)

    def add_path(self, path: ImpactPath) -> None:
        self.paths[path.sort_key()] = path


def _check_changes(
    invariant: Invariant,
    sources: Sequence[ChangeSource],
    trusted: Footprint,
    candidate: Footprint,
    record: _Record,
) -> None:
    for source in sources:
        changed = source.changed
        hits: list[tuple[str, Member]] = []
        for ref in changed.refs():
            hits.extend(("trusted", m) for m in trusted.find(ref))
            hits.extend(("candidate", m) for m in candidate.find(ref))
        if not hits:
            continue
        _, member = _pick(hits)
        code = _code(source, member)
        element = ", ".join(member.scope_elements) if member.seed else member.scope_elements[0]
        place = "a scope element" if member.seed else "in the walk"
        record.add(
            ImpactReason(
                code,
                changed.address,
                element,
                f"{changed.change_type.value} {changed.address} is {place} of "
                f"{invariant.invariant_id}",
            )
        )
        record.add_path(_path(changed.address, member))
        record.types.add(ImpactType.DIRECT if member.seed else ImpactType.DEPENDENCY)
        if source.origin is Origin.UNRESOLVED:
            record.hit_unresolved.append(changed)
        if code in UNCERTAIN_CODES:
            detail = (
                f"{changed.address} has unresolved content (registry 2.9)"
                if code is ReasonCode.UNRESOLVED_CONTENT
                else f"{changed.address} has an uncertain identity"
            )
            record.uncertainty[(code.value, detail)] = UncertaintyRecord(
                invariant.invariant_id, invariant.version, code, detail
            )


def _check_footprints(
    invariant: Invariant,
    sources: Sequence[ChangeSource],
    trusted: Footprint,
    candidate: Footprint,
    record: _Record,
) -> None:
    tagged = (("trusted", trusted), ("candidate", candidate))
    # an absent endpoint or a missing binding is uncertainty whatever changed (R6)
    for tag, found in tagged:
        for item in found.incomplete:
            if item.code in _UNCONDITIONAL:
                detail = f"{tag}: {item.detail}"
                record.add(
                    ImpactReason(
                        ReasonCode.ENDPOINT_ABSENT,
                        None,
                        (
                            f"resources:{item.subject}"
                            if item.code is IncompleteCode.ABSENT_SEED
                            else "binding"
                        ),
                        detail,
                    )
                )
                record.uncertainty[(ReasonCode.ENDPOINT_ABSENT.value, detail)] = UncertaintyRecord(
                    invariant.invariant_id, invariant.version, ReasonCode.ENDPOINT_ABSENT, detail
                )
    # any other incompleteness matters when a resource of a walkable type changed
    other = [
        (tag, item)
        for tag, found in tagged
        for item in found.incomplete
        if item.code not in _UNCONDITIONAL
    ]
    if not other:
        return
    walkable = walkable_types(invariant, [trusted, candidate])
    for source in sources:
        if source.origin is not Origin.IDENTITY:
            continue
        changed = source.changed
        if walkable is not None and changed.resource_type not in walkable:
            continue
        codes = ", ".join(sorted({item.code.value for _, item in other}))
        record.add(
            ImpactReason(
                ReasonCode.WALK_INCOMPLETE,
                changed.address,
                "walk",
                f"the footprint of {invariant.invariant_id} is incomplete ({codes}) and "
                f"{changed.address} is of a walkable type",
            )
        )
    if any(r.code is ReasonCode.WALK_INCOMPLETE for r in record.reasons.values()):
        for tag, item in other:
            detail = f"{tag}: {item.detail}"
            record.uncertainty[(ReasonCode.WALK_INCOMPLETE.value, detail)] = UncertaintyRecord(
                invariant.invariant_id, invariant.version, ReasonCode.WALK_INCOMPLETE, detail
            )


def _impacted(invariant: Invariant, record: _Record, proof: PriorProof | None) -> ImpactedInvariant:
    reasons = tuple(sorted(record.reasons.values(), key=ImpactReason.sort_key))
    codes = {r.code for r in reasons}
    types = set(record.types)
    if ReasonCode.IDENTITY_UNCERTAIN in codes:
        types.add(ImpactType.IDENTITY)
    if codes & {
        ReasonCode.UNRESOLVED_CONTENT,
        ReasonCode.WALK_INCOMPLETE,
        ReasonCode.ENDPOINT_ABSENT,
    }:
        types.add(ImpactType.UNCERTAINTY)
    if ReasonCode.CREATED_IN_SCOPE in codes:
        types.add(ImpactType.BASELINE)
    affected = bool(codes & AFFECTED_CODES)
    return ImpactedInvariant(
        invariant_id=invariant.invariant_id,
        invariant_version=invariant.version,
        status=ImpactStatus.AFFECTED if affected else ImpactStatus.UNCERTAIN,
        impact_types=tuple(sorted(types)),
        changed_resource_refs=tuple(sorted(record.refs)),
        dependency_paths=tuple(sorted(record.paths.values(), key=ImpactPath.sort_key)),
        reasons=reasons,
        prior_evidence_ids=proof.evidence_ids if proof is not None else (),
        evidence_validity=EvidenceValidity.INVALID if affected else EvidenceValidity.UNCERTAIN,
    )


def _work_item(invariant: Invariant, impacted: ImpactedInvariant) -> VerificationWorkItem:
    codes = {r.code for r in impacted.reasons}
    strongest = next(code for code in _STRONGEST if code in codes)
    scope = sorted({*impacted.changed_resource_refs, *invariant.scope.resources})
    return VerificationWorkItem(
        target_id=f"INVARIANT:{invariant.invariant_id}:{invariant.version}",
        target_type=WorkTargetType.INVARIANT,
        reason=strongest,
        scope=tuple(scope or sorted(invariant.scope.resource_types)),
        required_evidence=(
            f"L1 {invariant.verifier_id} {invariant.verifier_version} (registry-v1.0)"
        ),
        priority=WorkPriority.BLOCKING,
    )


def _unaffected(invariant: Invariant, inputs: CheckedInputs) -> UnaffectedInvariant:
    """Doc 08 §22: prior evidence is eligible for the same version made by the same verifier."""
    proof = inputs.proofs.get((invariant.invariant_id, invariant.version))
    if proof is None:
        reason = (
            ReasonCode.INVARIANT_VERSION_CHANGED
            if invariant.invariant_id in inputs.proof_ids
            else ReasonCode.NO_PRIOR_EVIDENCE
        )
        return UnaffectedInvariant(invariant.invariant_id, invariant.version, (), False, reason)
    if (proof.verifier_id, proof.verifier_version) != (
        invariant.verifier_id,
        invariant.verifier_version,
    ):
        return UnaffectedInvariant(
            invariant.invariant_id,
            invariant.version,
            proof.evidence_ids,
            False,
            ReasonCode.VERIFIER_CHANGED,
        )
    return UnaffectedInvariant(
        invariant.invariant_id,
        invariant.version,
        proof.evidence_ids,
        True,
        ReasonCode.NO_CHANGE_IN_FOOTPRINT,
    )


# --- the entry point ------------------------------------------------------------------------------


def compute_impact(
    trusted: Sequence[Resource],
    candidate: Sequence[Resource],
    identity: IdentityReport,
    trusted_graph: DependencyGraph,
    candidate_graph: DependencyGraph,
    invariants: Sequence[Invariant],
    prior: Sequence[PriorProof] = (),
    *,
    parent_state_id: str,
    candidate_id: str,
    now: datetime,
) -> ImpactReport:
    """Which of ``invariants`` must be checked again for ``candidate``, and why (Doc 08 §23)."""
    inputs = check_inputs(
        trusted,
        candidate,
        identity,
        trusted_graph,
        candidate_graph,
        invariants,
        prior,
        parent_state_id=parent_state_id,
        candidate_id=candidate_id,
    )
    sources = change_sources(identity, inputs.trusted, inputs.candidate)

    impacted: list[ImpactedInvariant] = []
    unaffected: list[UnaffectedInvariant] = []
    work: list[VerificationWorkItem] = []
    uncertainty: list[UncertaintyRecord] = []
    unresolved_hits: dict[str, ChangedResource] = {}
    for invariant in inputs.invariants:
        found_trusted = footprint(trusted_graph, invariant)
        found_candidate = footprint(candidate_graph, invariant)
        record = _Record()
        _check_changes(invariant, sources, found_trusted, found_candidate, record)
        _check_footprints(invariant, sources, found_trusted, found_candidate, record)
        for changed in record.hit_unresolved:
            unresolved_hits[changed.address] = changed
        if not record.reasons:
            unaffected.append(_unaffected(invariant, inputs))
            continue
        item = _impacted(
            invariant, record, inputs.proofs.get((invariant.invariant_id, invariant.version))
        )
        impacted.append(item)
        work.append(_work_item(invariant, item))
        uncertainty.extend(record.uncertainty.values())

    changed_resources = [s.changed for s in sources if s.origin is Origin.IDENTITY]
    changed_resources.extend(unresolved_hits.values())
    for changed in changed_resources:
        if changed.change_type is ChangeType.CREATED:
            work.append(
                VerificationWorkItem(
                    target_id=f"RESOURCE:{changed.address}",
                    target_type=WorkTargetType.RESOURCE,
                    reason=ReasonCode.CREATED_BASELINE,
                    scope=(changed.address,),
                    required_evidence="BASELINE (registry-v1.0 baseline predicates, Doc 09 §5)",
                    priority=WorkPriority.BLOCKING,
                )
            )
    return ImpactReport.create(
        parent_state_id=parent_state_id,
        candidate_id=candidate_id,
        changed_resources=changed_resources,
        affected_invariants=impacted,
        verification_work=work,
        uncertainty=uncertainty,
        unaffected=unaffected,
        graph_version=inputs.graph_version,
        trusted_graph_hash=trusted_graph.graph_hash,
        candidate_graph_hash=candidate_graph.graph_hash,
        identity_report_hash=identity.content_hash,
        now=now,
    )
