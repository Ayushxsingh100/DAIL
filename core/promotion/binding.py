"""The evidence binding of a promotion (P6b; Doc 11 §8, §9, §44; Doc 09 §27; C-52, C-60, C-68,
C-164).

C-60 only checks that the evidence a trusted state links to exists. Whether it may serve as proof
for that state is decided here, at the commit, with ``evaluate_proof`` (conditions P1 to P6):

* a VERIFIED reference rests on VERIFICATION evidence produced for the candidate: bound to it, with
  its state hash, whose subject (the invariant, its version, the verifier and the result) is the one
  the proof plan names;
* a CARRIED_FORWARD reference rests on the parent state: for a baseline, its evidence is bound to
  the baseline; for a promoted parent, the promotion binding record of that parent (a STATE-kind
  record bound to it, event name ``promotion.committed``) is, and it names the invariant.

So the chain never needs evidence to be valid in a context it was not produced for: the commit
writes one new binding record bound to the new state (``binding_payload``), and the next promotion
carries from that record. Every check fails closed: a missing record, a record that does not
resolve, a tampered payload, a wrong hash or a wrong subject is a problem, and a problem stops the
commit. Standard library and ``core.domain`` only (R18).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from core.domain.enums import VerificationResult
from core.domain.errors import DomainValidationError
from core.domain.evidence import (
    ArtifactRef,
    BrokenReferenceError,
    EvidenceContext,
    EvidenceEvent,
    EvidenceKind,
    IntegrityStatus,
    evaluate_proof,
)
from core.domain.invariant import Invariant, InvariantRef
from core.domain.promotion import PromotionDecision, PromotionEvidence, ProofPlanEntry, ProofSource
from core.domain.repositories import EvidenceRepository
from core.domain.state import CandidateState, TrustedState
from core.domain.verification import VerificationResultRecord
from core.promotion import ids

BINDING_EVENT_NAME: Final = "promotion.committed"


def integrity_of(evidence: EvidenceRepository, event: EvidenceEvent) -> IntegrityStatus:
    """Doc 11 §45: does the payload the record names resolve, and is it the text that was hashed?"""
    try:
        evidence.resolve(ArtifactRef.parse(event.payload_ref))
    except BrokenReferenceError:
        return IntegrityStatus.MISSING_PAYLOAD
    except DomainValidationError:
        return IntegrityStatus.TAMPERED
    return IntegrityStatus.VALID


def _fetch(
    evidence: EvidenceRepository, evidence_id: str, label: str
) -> tuple[EvidenceEvent | None, list[str]]:
    """The record, or why it cannot be read: a record whose stored columns disagree with its
    content (DATA-INT-010) is a binding problem, not an infrastructure failure."""
    try:
        return evidence.get(evidence_id), []
    except DomainValidationError as unreadable:
        return None, [f"{label}: the evidence record cannot be read ({unreadable})"]


def _payload(evidence: EvidenceRepository, event: EvidenceEvent) -> Mapping[str, Any] | None:
    try:
        value = evidence.resolve(ArtifactRef.parse(event.payload_ref))
    except DomainValidationError:
        return None
    return value if isinstance(value, Mapping) else None


def _proof_problems(
    evidence: EvidenceRepository,
    event: EvidenceEvent | None,
    context: EvidenceContext,
    state_hash: str,
    label: str,
) -> list[str]:
    """The reasons ``event`` may not serve as proof in ``context`` (none if it may)."""
    if event is None:
        return [f"{label}: the evidence record does not exist"]
    check = evaluate_proof(
        event,
        context,
        evidence.transitions(event.evidence_id),
        integrity_of(evidence, event),
        state_hash,
    )
    return [] if check.usable else [f"{label}: {reason}" for reason in check.reasons]


def verified_problems(
    evidence: EvidenceRepository,
    entry: ProofPlanEntry,
    candidate: CandidateState,
    definition: Invariant | None,
    result: VerificationResultRecord | None,
    evidence_id: str | None,
) -> list[str]:
    """Why the evidence of a VERIFIED entry is not proof for this candidate (C-164, C-68)."""
    label = f"{entry.target_id} (VERIFIED)"
    if candidate.state_hash is None:
        return [f"{label}: the candidate has no state_hash"]
    if result is None or evidence_id is None:
        return [f"{label}: no verification result or no evidence record for it"]
    if definition is None or definition.version != entry.invariant_version:
        return [f"{label}: no definition of that version to check the verifier against"]
    problems: list[str] = []
    if (
        result.result is not VerificationResult.PASS
        or result.candidate_hash != candidate.state_hash
    ):
        problems.append(f"{label}: the result is not a PASS of this candidate's hash")
    event, problems_read = _fetch(evidence, evidence_id, label)
    problems += problems_read
    if event is None:
        return problems or [f"{label}: the evidence record does not exist"]
    problems += _proof_problems(
        evidence,
        event,
        EvidenceContext.candidate(candidate.candidate_id),
        candidate.state_hash,
        label,
    )
    if event.kind is not EvidenceKind.VERIFICATION or event.candidate_id != candidate.candidate_id:
        problems.append(f"{label}: the record is not VERIFICATION evidence bound to the candidate")
    payload = _payload(evidence, event)
    if payload is not None:
        subject = {
            "verification_id": entry.verification_id,
            "invariant_id": entry.invariant_id,
            "invariant_version": entry.invariant_version,
            "verifier_id": definition.verifier_id,
            "verifier_version": definition.verifier_version,
            "candidate_id": candidate.candidate_id,
            "candidate_hash": candidate.state_hash,
            "result": VerificationResult.PASS.value,
        }
        for key, expected in subject.items():
            if payload.get(key) != expected:
                problems.append(f"{label}: the record's {key} is not {expected!r} (C-68)")
    return problems


def carried_problems(
    evidence: EvidenceRepository,
    entry: ProofPlanEntry,
    parent: TrustedState,
    reference: InvariantRef | None,
) -> list[str]:
    """Why the parent's evidence is not proof for a CARRIED_FORWARD entry (C-164)."""
    label = f"{entry.target_id} (CARRIED_FORWARD)"
    if reference is None:
        return [f"{label}: the parent state has no reference to it"]
    if set(entry.evidence_ids) != set(reference.evidence_ids) or not reference.evidence_ids:
        return [f"{label}: the plan's evidence is not the parent reference's evidence"]
    context = EvidenceContext.state(parent.state_id)
    if parent.version == 0:
        problems: list[str] = []
        for evidence_id in reference.evidence_ids:
            found, unread = _fetch(evidence, evidence_id, label)
            problems += unread or _proof_problems(
                evidence, found, context, parent.state_hash, label
            )
        return problems
    assert parent.commit_decision_id is not None  # a promoted state names its decision
    binding_id = ids.evidence_id_for(parent.commit_decision_id)
    if binding_id not in reference.evidence_ids:
        return [f"{label}: the parent reference does not carry the parent's binding record"]
    event, problems = _fetch(evidence, binding_id, label)
    if event is None:
        return problems or [f"{label}: the parent's binding record does not exist"]
    problems += _proof_problems(evidence, event, context, parent.state_hash, label)
    if event.kind is not EvidenceKind.STATE or event.event_name != BINDING_EVENT_NAME:
        problems.append(
            f"{label}: the parent's binding record is not a {BINDING_EVENT_NAME} record"
        )
    payload = _payload(evidence, event)
    if payload is not None:
        problems += _binding_payload_problems(payload, entry, parent, label)
    return problems


def _binding_payload_problems(
    payload: Mapping[str, Any], entry: ProofPlanEntry, parent: TrustedState, label: str
) -> list[str]:
    decision = payload.get("decision")
    promoted = payload.get("promotion_evidence")
    named = payload.get("invariants")
    problems: list[str] = []
    if (
        not isinstance(decision, Mapping)
        or decision.get("decision_id") != parent.commit_decision_id
    ):
        problems.append(f"{label}: the binding record names another decision")
    if not isinstance(promoted, Mapping) or promoted.get("new_state_id") != parent.state_id:
        problems.append(f"{label}: the binding record names another state")
    found = isinstance(named, list) and any(
        isinstance(item, Mapping)
        and item.get("invariant_id") == entry.invariant_id
        and item.get("invariant_version") == entry.invariant_version
        for item in named
    )
    if not found:
        problems.append(f"{label}: the binding record does not name this invariant")
    return problems


def binding_problems(
    evidence: EvidenceRepository,
    plan: Sequence[ProofPlanEntry],
    candidate: CandidateState,
    parent: TrustedState,
    definitions: Mapping[str, Invariant],
    results: Mapping[str, VerificationResultRecord],
    evidence_ids: Mapping[str, str],
) -> list[str]:
    """Every reason the evidence of ``plan`` does not bind to the new state (empty: it does)."""
    references = {r.invariant_id: r for r in parent.invariant_refs}
    problems: list[str] = []
    for entry in plan:
        if entry.source is ProofSource.VERIFIED:
            key = entry.verification_id or ""
            problems += verified_problems(
                evidence,
                entry,
                candidate,
                definitions.get(entry.invariant_id),
                results.get(key),
                evidence_ids.get(key),
            )
        else:
            problems += carried_problems(
                evidence, entry, parent, references.get(entry.invariant_id)
            )
    return problems


def binding_payload(
    decision: PromotionDecision,
    promotion_evidence: PromotionEvidence,
    plan: Sequence[ProofPlanEntry],
    new_state: TrustedState,
    evidence_ids: Mapping[str, str],
) -> dict[str, Any]:
    """The payload of the binding record: the committed decision, its evidence naming the new
    state, the state, and for every invariant its source (C-164)."""
    invariants: list[dict[str, Any]] = []
    for entry in sorted(plan, key=lambda e: e.invariant_id):
        verified = entry.source is ProofSource.VERIFIED
        invariants.append(
            {
                "invariant_id": entry.invariant_id,
                "invariant_version": entry.invariant_version,
                "source": entry.source.value,
                "source_evidence_ids": (
                    [evidence_ids[entry.verification_id or ""]]
                    if verified
                    else sorted(entry.evidence_ids)
                ),
                "source_state_id": entry.source_state_id,
            }
        )
    return {
        "decision": decision.to_dict(),
        "promotion_evidence": promotion_evidence.to_dict(),
        "state": {
            "state_id": new_state.state_id,
            "version": new_state.version,
            "parent_state_id": new_state.parent_state_id,
            "state_hash": new_state.state_hash,
        },
        "invariants": invariants,
    }
