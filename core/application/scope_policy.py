"""Verification scope policies (Doc 03 §24; Doc 08 §26; C-142; P4 step 8).

A scope policy decides which verification work a candidate owes, given the impact report. It is an
experiment-level choice (the conditions of Doc 13), so it lives in the application layer and never
in the domain: ``core.domain`` and ``core.impact`` do not import it (rule R2).

``DailScopePolicy`` is the DAIL condition: the verification work is exactly what impact derived,
the work set of the impacted invariants plus the baseline checks of the created resources, all
BLOCKING (Doc 08 §26). The two comparison policies belong to the experiment harness and are built in
P8, not here: *Stateful Full* (every protected invariant is checked again) and *Stateless* (checked
again with no parent state).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from core.domain.impact import ImpactReport, VerificationWorkItem
from core.domain.invariant import Invariant


@runtime_checkable
class VerificationScopePolicy(Protocol):
    """Which verification work a candidate owes."""

    def select(
        self, report: ImpactReport, protected: Sequence[Invariant]
    ) -> tuple[VerificationWorkItem, ...]:
        """The work items to run for ``report``, given the protected invariants."""
        ...


class DailScopePolicy:
    """The DAIL condition: the impact work set, unchanged."""

    def select(
        self, report: ImpactReport, protected: Sequence[Invariant]
    ) -> tuple[VerificationWorkItem, ...]:
        del protected  # impact already derived its work from the protected invariants
        return report.verification_work
