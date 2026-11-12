"""Verification scope policies (Doc 03 §24; Doc 08 §26; C-142; P4 step 8; P8a: C-198).

A scope policy decides which verification work a candidate owes, given the impact report. It is an
experiment-level choice (the conditions of Doc 13), so it lives in the application layer and never
in the domain: ``core.domain`` and ``core.impact`` do not import it (rule R2).

``DailScopePolicy`` is the DAIL condition (C and C'): the verification work is exactly what impact
derived, the work set of the impacted invariants plus the baseline checks of the created resources,
all BLOCKING (Doc 08 §26). The two comparison policies of the experiment harness (P8a, C-198):

* ``StatefulFullScopePolicy`` (condition B): every protected invariant is checked again, together
  with every RESOURCE baseline item of the impact work set.
* ``StatelessScopePolicy`` (condition A): the repair target's invariant item only, or nothing for a
  change request (C-197). No baseline item.

The two gate items (STRUCTURAL, CONSISTENCY) are not selected by any policy: the verification engine
adds them to every work set (C-147).

An invariant that impact did not list gets a work item made here. Its fields are those impact gives
an invariant item (target, BLOCKING, L1), its scope is the definition's scope (resources, or else
resource types; the verifiers do not read the scope), and its reason is ``CONDITION_ITEM_REASON``:
C-138's vocabulary is closed and has no code for "the condition re-verifies it", so a valid code of
an affected item stands in. Nothing reads a work item's reason after this point (the verification
request does not carry it); the experiment records mark such items ``origin = condition`` (C-207).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import ClassVar, Final, Protocol, runtime_checkable

from core.domain.errors import DomainValidationError
from core.domain.impact import (
    ImpactReport,
    ReasonCode,
    VerificationWorkItem,
    WorkPriority,
    WorkTargetType,
)
from core.domain.invariant import Invariant

# See the module docstring: a stand-in from C-138's closed vocabulary (C-207).
CONDITION_ITEM_REASON: Final = ReasonCode.SCOPE_TYPE_CHANGED


@runtime_checkable
class VerificationScopePolicy(Protocol):
    """Which verification work a candidate owes."""

    def select(
        self, report: ImpactReport, protected: Sequence[Invariant]
    ) -> tuple[VerificationWorkItem, ...]:
        """The work items to run for ``report``, given the protected invariants."""
        ...


def _target(definition: Invariant) -> str:
    return f"INVARIANT:{definition.invariant_id}:{definition.version}"


def condition_item(definition: Invariant) -> VerificationWorkItem:
    """A work item for ``definition`` that impact did not list (see the module docstring)."""
    scope = definition.scope.resources or definition.scope.resource_types
    return VerificationWorkItem(
        target_id=_target(definition),
        target_type=WorkTargetType.INVARIANT,
        reason=CONDITION_ITEM_REASON,
        scope=scope,
        required_evidence="L1",
        priority=WorkPriority.BLOCKING,
    )


def _ordered(items: Iterable[VerificationWorkItem]) -> tuple[VerificationWorkItem, ...]:
    return tuple(sorted(items, key=VerificationWorkItem.sort_key))


class DailScopePolicy:
    """The DAIL condition: the impact work set, unchanged."""

    version: ClassVar[str] = "dail-scope-1"

    def select(
        self, report: ImpactReport, protected: Sequence[Invariant]
    ) -> tuple[VerificationWorkItem, ...]:
        del protected  # impact already derived its work from the protected invariants
        return report.verification_work


class StatefulFullScopePolicy:
    """Condition B, Stateful Full (C-198): every protected invariant and every RESOURCE baseline
    item of the impact work set. Impact's own item is kept where it listed one."""

    version: ClassVar[str] = "stateful-full-scope-1"

    def select(
        self, report: ImpactReport, protected: Sequence[Invariant]
    ) -> tuple[VerificationWorkItem, ...]:
        listed = {item.target_id: item for item in report.verification_work}
        chosen = [
            item for item in report.verification_work if item.target_type is WorkTargetType.RESOURCE
        ]
        chosen += [listed.get(_target(d)) or condition_item(d) for d in protected]
        return _ordered(chosen)


class StatelessScopePolicy:
    """Condition A, Stateless (C-198): the invariant items of ``targets`` only (the repair target,
    or none for a change request). Impact's own item is kept where it listed one."""

    version: ClassVar[str] = "stateless-scope-1"

    def __init__(self, targets: Iterable[str]) -> None:
        if isinstance(targets, str):
            raise DomainValidationError("StatelessScopePolicy: targets is a list of invariant ids")
        self.targets = tuple(sorted(set(targets)))

    def select(
        self, report: ImpactReport, protected: Sequence[Invariant]
    ) -> tuple[VerificationWorkItem, ...]:
        by_id = {d.invariant_id: d for d in protected}
        missing = [t for t in self.targets if t not in by_id]
        if missing:
            raise DomainValidationError(
                f"StatelessScopePolicy: no definition for {', '.join(missing)}"
            )
        listed = {item.target_id: item for item in report.verification_work}
        return _ordered(
            listed.get(_target(by_id[t])) or condition_item(by_id[t]) for t in self.targets
        )
