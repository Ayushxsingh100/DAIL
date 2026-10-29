"""Builders for the promotion tests (P6a). Not a test module.

Tests may import every package; ``core.promotion`` may import only ``core.domain`` (R18).
Everything is deterministic: ids come from ``tests.domain_builders.uid`` and times from ``at``.
"""

from __future__ import annotations

from collections.abc import Iterable

from core.domain.impact import ImpactReport
from core.domain.invariant import InvariantRef
from core.domain.state import CandidateState, TrustedState


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
) -> ImpactReport:
    """An impact report of ``candidate`` against ``parent``.

    ``carry`` are unaffected invariants whose prior evidence is eligible (the parent reference's
    own evidence); ``ineligible`` are unaffected but not eligible; ``affected`` and ``uncertain``
    are the impacted ones, which owe a work item. ``versions`` overrides the invariant version the
    report names (default: the version of the parent's reference)."""
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
    return ib.report(
        affected=impacted,
        unaffected_invariants=kept,
        parent_state_id=parent.state_id,
        candidate_id=candidate.candidate_id,
    )
