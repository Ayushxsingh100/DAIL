"""What each condition gives DAIL (P8a; C-196 to C-198, C-203, C-205, C-206).

All four conditions use the same verifiers, the same ``EvaluationOrchestrator`` and the same
Promotion Controller (RV-001); they differ only in the scope policy, the policy constructor, the
identity strategy and, for A, the invariants its lineage tracks:

=====  ================  =========================  =======================  ======================
cond.  identity          scope policy               policy constructor       lineage tracks
=====  ================  =========================  =======================  ======================
A      EvidenceIdentity  StatelessScopePolicy(t)    stateless_policy(t)      t only (C-205, C-206)
B      EvidenceIdentity  StatefulFullScopePolicy    stateful_full_policy     the four invariants
C      EvidenceIdentity  DailScopePolicy            dail_policy              the four invariants
C'     AddressOnly       DailScopePolicy            dail_policy              the four invariants
=====  ================  =========================  =======================  ======================

``t`` is the repair target of a ``repair`` scenario, or nothing for a ``change_request`` (C-197).

Registry (C-203): every condition uses registry v1.1 (``registry_v1_1_invariants``, INV-SEC-001/002
version 2), stored as ``invariant_registry_version`` 2 (C-180). TerraPreserve names the protected
invariants by their registry-v1.0 ids at version "1.0"; each maps to the v1.1 definition of the same
id. A store registers an invariant's earlier versions first (``history``): Doc 06 §4.2 allows no
gaps in an invariant's versions, so version 2 of INV-SEC-001 needs version 1 registered before it.

Open targets (C-196): on a scenario with more than one step after S0, the repair target is open on
every step but the last.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from core.application.scope_policy import (
    DailScopePolicy,
    StatefulFullScopePolicy,
    StatelessScopePolicy,
    VerificationScopePolicy,
)
from core.dependency.invariants import SemanticBinding
from core.domain.invariant import Invariant
from core.domain.promotion import PromotionPolicy
from core.domain.registry_v1 import registry_v1_invariants
from core.domain.registry_v1_1 import (
    REGISTRY_TAG_V1_1,
    REGISTRY_VERSION_V1_1,
    registry_v1_1_invariants,
)
from core.identity.strategy import AddressOnlyIdentity, EvidenceIdentity, IdentityStrategy
from core.promotion.policy import (
    STATELESS_RULES_VERSION,
    dail_policy,
    stateful_full_policy,
    stateless_policy,
)
from experiments.definition import Condition
from experiments.loader import ScenarioInput

REPAIR: Final = "repair"
CHANGE_REQUEST: Final = "change_request"
TERRAPRESERVE_VERSION: Final = "1.0"  # the registry version TerraPreserve v1.0 names
FUNC_BINDING: Final = ("INV-FUNC-001", "TCP", 5432)
REGISTRY_RECORD: Final = {
    "stored_invariant_registry_version": REGISTRY_VERSION_V1_1,
    "means": REGISTRY_TAG_V1_1,
}
POLICY_RULES: Final = {
    Condition.A: STATELESS_RULES_VERSION,
    Condition.B: "stateful-full",
    Condition.C: "dail",
    Condition.C_PRIME: "dail",
}


class ConditionError(Exception):
    """A scenario that a condition cannot be built for (a harness failure)."""


@dataclass(frozen=True)
class ConditionSetup:
    """Everything a trial of ``condition`` on one scenario passes to DAIL."""

    condition: Condition
    policy_version: str
    scope_policy: VerificationScopePolicy
    policy_factory: Callable[..., PromotionPolicy]
    identity_strategy: IdentityStrategy
    definitions: tuple[Invariant, ...]  # evaluation: graph, impact, verification
    bindings: tuple[SemanticBinding, ...]
    baseline_definitions: tuple[Invariant, ...]  # what the lineage tracks
    baseline_bindings: tuple[SemanticBinding, ...]
    allow_no_invariants: bool
    history: tuple[Invariant, ...]  # earlier versions registered first (Doc 06 §4.2)
    required: tuple[str, ...] | None  # A's explicit required set, None for B, C, C'
    protected_mapping: dict[str, dict[str, Any]]

    def open_targets(self, scenario: ScenarioInput, step: int) -> tuple[str, ...]:
        """C-196: the repair target is open on steps 1..n-1 of a scenario with n > 1 steps."""
        if (
            scenario.target_kind == REPAIR
            and scenario.target_invariant_id is not None
            and scenario.transitions > 1
            and step < scenario.transitions
        ):
            return (scenario.target_invariant_id,)
        return ()

    def versions(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "policy_rules": POLICY_RULES[self.condition],
            "scope_policy": getattr(self.scope_policy, "version", type(self.scope_policy).__name__),
            "identity": self.identity_strategy.algorithm_version,
        }


def _target(scenario: ScenarioInput) -> tuple[str, ...]:
    if scenario.target_kind == REPAIR:
        if scenario.target_invariant_id is None:
            raise ConditionError(f"{scenario.scenario_id}: a repair scenario names no target")
        return (scenario.target_invariant_id,)
    if scenario.target_kind == CHANGE_REQUEST:
        return ()
    raise ConditionError(f"{scenario.scenario_id}: unknown target kind {scenario.target_kind!r}")


def _mapping(
    scenario: ScenarioInput, definitions: tuple[Invariant, ...]
) -> dict[str, dict[str, Any]]:
    """C-203: TerraPreserve's protected invariants (v1.0 ids) to the v1.1 definitions."""
    by_id = {d.invariant_id: d for d in definitions}
    found: dict[str, dict[str, Any]] = {}
    for invariant_id, version in scenario.protected_invariants:
        definition = by_id.get(invariant_id)
        if definition is None or version != TERRAPRESERVE_VERSION:
            raise ConditionError(
                f"{scenario.scenario_id}: protected invariant {invariant_id} {version} has no "
                "registry-v1.1 definition"
            )
        found[invariant_id] = {
            "terrapreserve_version": version,
            "dail_version": definition.version,
            "registry": REGISTRY_TAG_V1_1,
        }
    return found


def setup_for(condition: Condition, scenario: ScenarioInput, now: datetime) -> ConditionSetup:
    """The setup of ``condition`` for ``scenario`` (see the module docstring)."""
    source, destination = scenario.source_endpoint, scenario.destination_endpoint
    definitions = registry_v1_1_invariants(now, source=source, destination=destination)
    func, protocol, port = FUNC_BINDING
    bindings = (SemanticBinding(func, source, destination, protocol, port),)
    mapping = _mapping(scenario, definitions)
    targets = _target(scenario)
    if condition is Condition.A:
        tracked = tuple(d for d in definitions if d.invariant_id in targets)
        scope: VerificationScopePolicy = StatelessScopePolicy(targets)
        factory: Callable[..., PromotionPolicy] = functools.partial(
            stateless_policy, required=targets, invariant_registry_version=REGISTRY_VERSION_V1_1
        )
        required: tuple[str, ...] | None = targets
    else:
        tracked = definitions
        full = condition is Condition.B
        scope = StatefulFullScopePolicy() if full else DailScopePolicy()
        factory = functools.partial(
            stateful_full_policy if full else dail_policy,
            invariant_registry_version=REGISTRY_VERSION_V1_1,
        )
        required = None
    identity: IdentityStrategy = (
        AddressOnlyIdentity() if condition is Condition.C_PRIME else EvidenceIdentity()
    )
    tracked_ids = {d.invariant_id for d in tracked}
    earlier = registry_v1_invariants(now, source=source, destination=destination)
    history = tuple(
        d
        for d in earlier
        if d.invariant_id in tracked_ids
        and d.version < next(t.version for t in tracked if t.invariant_id == d.invariant_id)
    )
    return ConditionSetup(
        condition=condition,
        policy_version=f"p8a-{condition.value}-{POLICY_RULES[condition]}",
        scope_policy=scope,
        policy_factory=factory,
        identity_strategy=identity,
        definitions=definitions,
        bindings=bindings,
        baseline_definitions=tracked,
        baseline_bindings=tuple(b for b in bindings if b.invariant_id in tracked_ids),
        allow_no_invariants=not tracked,
        history=history,
        required=required,
        protected_mapping=mapping,
    )
