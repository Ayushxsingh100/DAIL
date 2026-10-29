"""The whole pipeline, from a fixture directory to a promotion decision (P6a step 6). Not a test
module.

Normalise the parent and the candidate directory, identity, graphs, impact with the prior proofs
of the trusted state, the verification scope policy, the verification engine, then ``decide``.
Tests may import every package; the pipeline modules are P3 to P5, ``decide`` is P6a.

The trusted state is built from the parent directory: its invariant statuses are those of the
parent's own ``expected.json`` (PASS is PROTECTED, FAIL is VIOLATED, anything else UNCERTAIN), which
is hand-written data (C-89). Nothing here computes an expected decision.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from core.application.scope_policy import DailScopePolicy
from core.dependency.build import build_graph
from core.dependency.invariants import SemanticBinding
from core.domain.enums import CandidateStatus, InvariantStatus
from core.domain.impact import ImpactReport, WorkTargetType
from core.domain.invariant import Invariant, InvariantProof
from core.domain.promotion import DecisionOutcome, PromotionPolicy
from core.domain.state import (
    CandidateState,
    TrustedState,
    finish_building,
    start_building,
    transition_candidate,
)
from core.domain.verification import ConstructionStatus, VerificationReport
from core.identity.engine import compare
from core.impact.engine import compute_impact
from core.impact.inputs import PriorProof
from core.promotion.decide import decide
from core.promotion.policy import dail_policy, stateful_full_policy
from core.terraform_model.normalization import normalize_directory
from core.terraform_model.normalize import NORMALIZATION_VERSION
from core.verification.dispatch import DEFAULT_VERIFIERS, REACHABILITY_CFG, VerifierTable
from core.verification.engine import run_work_set
from core.verification.inputs import VerificationInputs
from tests import fixture_catalog as fc
from tests.domain_builders import LINEAGE, patch_for, uid
from tests.identity_builders import NOW
from tests.impact_builders import registry
from tests.pipeline_builders import (
    CANDIDATE_STATE,
    PARENT_STATE,
    counting_ids,
    fixed_clock,
    invariant_item,
)

ROOT = fc.REPO_ROOT
INVARIANTS = ("INV-FUNC-001", "INV-SEC-001", "INV-SEC-002", "INV-SEC-003")
_STATUS = {"PASS": InvariantStatus.PROTECTED, "FAIL": InvariantStatus.VIOLATED}


@dataclass(frozen=True)
class PipelineRun:
    fixture_id: str
    trusted: TrustedState
    candidate: CandidateState
    inputs: VerificationInputs
    impact: ImpactReport
    verification: VerificationReport
    definitions: tuple[Invariant, ...]
    work: tuple[str, ...]
    parent: str

    def policy(
        self, *, stateful_full: bool = False, automatic_enabled: bool = True, **options: Any
    ) -> PromotionPolicy:
        make = stateful_full_policy if stateful_full else dail_policy
        return make(
            policy_version="policy-p6a",
            invariants=self.definitions,
            automatic_enabled=automatic_enabled,
            **options,
        )

    def newer_trusted(self) -> TrustedState:
        """Another state of the same lineage with the same content, as if it had been promoted
        after this candidate was made (Doc 09 §25): this candidate is then stale."""
        return trusted_from(
            self.parent, self.trusted.resources, list(self.definitions), state_id=uid(403)
        )

    def decide(
        self,
        policy: PromotionPolicy | None = None,
        *,
        trusted: TrustedState | None = None,
        attempt_number: int = 1,
    ) -> DecisionOutcome:
        return decide(
            self.candidate,
            trusted or self.trusted,
            self.impact,
            self.verification,
            policy or self.policy(),
            decision_id=uid(9300),
            now=NOW,
            attempt_number=attempt_number,
        )


def parent_statuses(parent: str) -> dict[str, InvariantStatus]:
    """The invariant statuses of the parent directory's own ``expected.json``."""
    data = json.loads((ROOT / parent / "expected.json").read_text(encoding="utf-8"))
    results: Mapping[str, Mapping[str, Any]] = data["results"]
    return {i: _STATUS.get(results[i]["result"], InvariantStatus.UNCERTAIN) for i in results}


def trusted_from(
    parent: str, resources: Any, definitions: list[Invariant], *, state_id: str = PARENT_STATE
) -> TrustedState:
    statuses = parent_statuses(parent)
    proofs = [
        InvariantProof.for_baseline(
            invariant_id=d.invariant_id,
            invariant_version=d.version,
            status=statuses[d.invariant_id],
            evidence_ids=(uid(2100 + n),),
            verified_at=NOW,
        )
        for n, d in enumerate(definitions)
    ]
    return TrustedState.establish_baseline(
        lineage_id=LINEAGE,
        resources=resources,
        invariant_proofs=proofs,
        evidence_refs=sorted({e for p in proofs for e in p.evidence_ids}),
        normalization_version=NORMALIZATION_VERSION,
        invariant_registry_version=1,
        now=NOW,
        state_id=state_id,
    )


def pipeline(
    fixture: fc.Fixture,
    *,
    stateful_full: bool = False,
    verifiers: VerifierTable = DEFAULT_VERIFIERS,
) -> PipelineRun:
    """Everything up to the verification report for one fixture that has a parent."""
    data = fixture.data
    parent = data["parent"]
    assert parent is not None, data["fixture_id"]
    binding = data["bindings"]["INV-FUNC-001"]
    source, destination = binding["S"], binding["D"]
    after = normalize_directory(ROOT / data["config"], None, now=NOW)
    before = normalize_directory(ROOT / parent, None, now=NOW)
    assert after.resource_set_hash is not None
    definitions = list(registry(source, destination).values())
    semantic = [SemanticBinding("INV-FUNC-001", source, destination, "TCP", 5432)]
    trusted = trusted_from(parent, before.resources, definitions)
    identity = compare(
        before.resources,
        after.resources,
        list(after.moves),
        parent_state_id=PARENT_STATE,
        candidate_id=CANDIDATE_STATE,
        now=NOW,
    )
    trusted_graph = build_graph(
        before.resources, definitions, semantic, state_id=PARENT_STATE, now=NOW
    )
    candidate_graph = build_graph(
        after.resources, definitions, semantic, state_id=CANDIDATE_STATE, now=NOW
    )
    priors = [
        PriorProof(
            ref.invariant_id,
            ref.invariant_version,
            ref.evidence_ids,
            next(d for d in definitions if d.invariant_id == ref.invariant_id).verifier_id,
            next(d for d in definitions if d.invariant_id == ref.invariant_id).verifier_version,
        )
        for ref in trusted.invariant_refs
    ]
    impact = compute_impact(
        before.resources,
        after.resources,
        identity,
        trusted_graph,
        candidate_graph,
        definitions,
        priors,
        parent_state_id=PARENT_STATE,
        candidate_id=CANDIDATE_STATE,
        now=NOW,
    )
    inputs = VerificationInputs(
        candidate_resources=after.resources,
        parent_resources=before.resources,
        candidate_state_hash=after.resource_set_hash,
        normalization_version=NORMALIZATION_VERSION,
        candidate_id=CANDIDATE_STATE,
        parent_state_id=PARENT_STATE,
        identity=identity,
        impact=impact,
        candidate_graph=candidate_graph,
        trusted_graph=trusted_graph,
        invariants=tuple(definitions),
        construction=ConstructionStatus.OK,
    )
    candidate = CandidateState.create(
        parent=trusted,
        patch=patch_for(trusted, n=7),
        candidate_sequence=1,
        now=NOW,
        candidate_id=CANDIDATE_STATE,
    )
    candidate = finish_building(start_building(candidate), after.resources)
    candidate = transition_candidate(candidate, CandidateStatus.ANALYZING)
    assert candidate.state_hash == after.resource_set_hash
    if stateful_full:  # Doc 13: every invariant is verified again, plus the created resources
        work = [invariant_item(i) for i in INVARIANTS] + [
            w for w in impact.verification_work if w.target_type is WorkTargetType.RESOURCE
        ]
    else:
        work = list(DailScopePolicy().select(impact, definitions))
    report = run_work_set(
        work, inputs, clock=fixed_clock(), ids=counting_ids(), verifiers=verifiers
    )
    return PipelineRun(
        data["fixture_id"],
        trusted,
        candidate,
        inputs,
        impact,
        report,
        tuple(definitions),
        tuple(sorted(w.target_id for w in work)),
        parent,
    )


def failing_reachability(_definition: Invariant, _inputs: VerificationInputs) -> Any:
    raise RuntimeError("the reachability verifier crashed")


def with_failing_reachability() -> VerifierTable:
    """The default verifier table with a reachability verifier that raises (Doc 12 §19)."""
    return {**DEFAULT_VERIFIERS, REACHABILITY_CFG: failing_reachability}


def fixtures_with_a_parent() -> dict[str, fc.Fixture]:
    found = {fx.data["fixture_id"]: fx for fx in fc.load_all().values()}
    return {k: v for k, v in sorted(found.items()) if v.data["parent"] is not None}


__all__ = [
    "PipelineRun",
    "failing_reachability",
    "fixtures_with_a_parent",
    "parent_statuses",
    "pipeline",
    "trusted_from",
    "with_failing_reachability",
]
