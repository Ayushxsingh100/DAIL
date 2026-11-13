"""Verification scope policies (Doc 03 §24; Doc 08 §26; C-142; P4 step 8; P8a: C-198; P8a-2:
C-210, C-211).

A scope policy decides which verification work a candidate owes, given the impact report. It is an
experiment-level choice (the conditions of Doc 13), so it lives in the application layer and never
in the domain: ``core.domain`` and ``core.impact`` do not import it (rule R2).

``DailScopePolicy`` is the DAIL condition (C and C'): the impact work set (the impacted invariants
and the baseline checks of the created resources, all BLOCKING, Doc 08 §26), plus, since P8a-2
(C-210), one invariant item for every invariant whose reference in the parent is not PROTECTED
(VIOLATED or UNCERTAIN) and that impact did not already list: the U_t of the paper's required set
R(C_t) = G_gate ∪ U_t ∪ I_t ∪ B. C-159 already required a fresh result for each of them (a VIOLATED
or UNCERTAIN reference is never carried forward); the work set did not schedule one. With every
parent reference PROTECTED the work set is impact's, unchanged.

The two comparison policies of the experiment harness (P8a, C-198):

* ``StatefulFullScopePolicy`` (condition B): every protected invariant is checked again, together
  with every RESOURCE baseline item of the impact work set.
* ``StatelessScopePolicy`` (condition A): the repair target's invariant item only, or nothing for a
  change request (C-197). No baseline item.

The two gate items (STRUCTURAL, CONSISTENCY) are not selected by any policy: the verification engine
adds them to every work set (C-147).

**The parent's statuses.** ``select`` takes them as ``parent_refs`` (keyword, default none): the
parent state's invariant references, which the orchestrator already holds. It is the narrowest input
that carries the statuses (C-210); the impact report does not, and the scope policy must not read
the database. Without it ``DailScopePolicy`` returns impact's work set as before.

An item a policy adds for an invariant impact did not list has the fields impact gives an invariant
item (target, BLOCKING, L1) and the definition's scope (resources, else resource types; the
verifiers do not read the scope). Its reason (C-211) is ``CONDITION_SCOPE`` when the condition's
policy requires it (B, A) and ``NOT_PROTECTED_IN_PARENT`` for the U_t items.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import ClassVar, Protocol, runtime_checkable

from core.domain.enums import InvariantStatus
from core.domain.errors import DomainValidationError
from core.domain.impact import (
    ImpactReport,
    ReasonCode,
    VerificationWorkItem,
    WorkPriority,
    WorkTargetType,
)
from core.domain.invariant import Invariant, InvariantRef


@runtime_checkable
class VerificationScopePolicy(Protocol):
    """Which verification work a candidate owes."""

    def select(
        self,
        report: ImpactReport,
        protected: Sequence[Invariant],
        *,
        parent_refs: Sequence[InvariantRef] = (),
    ) -> tuple[VerificationWorkItem, ...]:
        """The work items to run for ``report``, given the protected invariants and the parent
        state's invariant references."""
        ...


def _target(definition: Invariant) -> str:
    return f"INVARIANT:{definition.invariant_id}:{definition.version}"


def policy_item(definition: Invariant, reason: ReasonCode) -> VerificationWorkItem:
    """A work item for ``definition`` that impact did not list (see the module docstring)."""
    scope = definition.scope.resources or definition.scope.resource_types
    return VerificationWorkItem(
        target_id=_target(definition),
        target_type=WorkTargetType.INVARIANT,
        reason=reason,
        scope=scope,
        required_evidence="L1",
        priority=WorkPriority.BLOCKING,
    )


def _ordered(items: Iterable[VerificationWorkItem]) -> tuple[VerificationWorkItem, ...]:
    return tuple(sorted(items, key=VerificationWorkItem.sort_key))


class DailScopePolicy:
    """The DAIL condition: the impact work set and the U_t items (C-210)."""

    version: ClassVar[str] = "dail-scope-2"

    def select(
        self,
        report: ImpactReport,
        protected: Sequence[Invariant],
        *,
        parent_refs: Sequence[InvariantRef] = (),
    ) -> tuple[VerificationWorkItem, ...]:
        by_id = {d.invariant_id: d for d in protected}
        listed = {item.target_id for item in report.verification_work}
        added = {}
        for ref in parent_refs:
            definition = by_id.get(ref.invariant_id)
            if ref.status is InvariantStatus.PROTECTED or definition is None:
                continue  # an undefined one is the decision's policy condition (C-41)
            if _target(definition) not in listed:
                added[_target(definition)] = policy_item(
                    definition, ReasonCode.NOT_PROTECTED_IN_PARENT
                )
        if not added:
            return report.verification_work
        return _ordered([*report.verification_work, *added.values()])


class StatefulFullScopePolicy:
    """Condition B, Stateful Full (C-198): every protected invariant and every RESOURCE baseline
    item of the impact work set. Impact's own item is kept where it listed one."""

    version: ClassVar[str] = "stateful-full-scope-2"

    def select(
        self,
        report: ImpactReport,
        protected: Sequence[Invariant],
        *,
        parent_refs: Sequence[InvariantRef] = (),
    ) -> tuple[VerificationWorkItem, ...]:
        del parent_refs  # every protected invariant is checked anyway
        listed = {item.target_id: item for item in report.verification_work}
        chosen = [
            item for item in report.verification_work if item.target_type is WorkTargetType.RESOURCE
        ]
        chosen += [
            listed.get(_target(d)) or policy_item(d, ReasonCode.CONDITION_SCOPE) for d in protected
        ]
        return _ordered(chosen)


class StatelessScopePolicy:
    """Condition A, Stateless (C-198): the invariant items of ``targets`` only (the repair target,
    or none for a change request). Impact's own item is kept where it listed one."""

    version: ClassVar[str] = "stateless-scope-2"

    def __init__(self, targets: Iterable[str]) -> None:
        if isinstance(targets, str):
            raise DomainValidationError("StatelessScopePolicy: targets is a list of invariant ids")
        self.targets = tuple(sorted(set(targets)))

    def select(
        self,
        report: ImpactReport,
        protected: Sequence[Invariant],
        *,
        parent_refs: Sequence[InvariantRef] = (),
    ) -> tuple[VerificationWorkItem, ...]:
        del parent_refs  # A uses no ledger (C-198): its lineage holds only its targets anyway
        by_id = {d.invariant_id: d for d in protected}
        missing = [t for t in self.targets if t not in by_id]
        if missing:
            raise DomainValidationError(
                f"StatelessScopePolicy: no definition for {', '.join(missing)}"
            )
        listed = {item.target_id: item for item in report.verification_work}
        return _ordered(
            listed.get(_target(by_id[t])) or policy_item(by_id[t], ReasonCode.CONDITION_SCOPE)
            for t in self.targets
        )
