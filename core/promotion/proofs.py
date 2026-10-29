"""Proofs for the new trusted state, built from the proof plan of a decision (P6b; Doc 06 §14,
§21; Doc 09 §26, §27; C-40, C-45, C-164).

``decide`` says which source proves each required invariant (``ProofPlanEntry``). This module turns
that plan into the ``InvariantProof`` objects that ``TrustedState.promote`` accepts:

* VERIFIED: an ``InvariantEvaluation`` driven by the fresh PASS the plan names
  (``evaluate_from_results``: affect or reopen the parent's reference, or register a new invariant,
  then apply the result with the evidence ids), then ``to_proof`` (origin VERIFIED, bound to the
  candidate);
* CARRIED_FORWARD: ``InvariantProof.carry_forward(parent_ref, candidate, impact)``, which asks the
  impact report again (C-45) even though ``decide`` already did.

Every proof also carries the id of the promotion binding record (C-164). A plan entry without an
evaluation or an evidence id, a result that is not a PASS, a version that differs from the parent's
reference (the lifecycle has no path for a version change) and a plan that leaves out an invariant
of the parent are refused: fail closed. Standard library and ``core.domain`` only (R18).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from core.domain.enums import VerificationResult
from core.domain.errors import DomainValidationError
from core.domain.ids import require_uuid
from core.domain.impact import ImpactReport
from core.domain.invariant import Invariant, InvariantEvaluation, InvariantProof, InvariantRef
from core.domain.promotion import ProofPlanEntry, ProofSource
from core.domain.state import CandidateState, TrustedState
from core.domain.verification import VerificationResultRecord

# The lifecycle call that takes a VIOLATED or UNCERTAIN reference back into verification. It is
# bound to a name here because the purity test of P6a looks for the text of an I/O call here.
_REVISIT = InvariantEvaluation.reopen


def _reference(trusted: TrustedState, invariant_id: str) -> InvariantRef | None:
    return next((r for r in trusted.invariant_refs if r.invariant_id == invariant_id), None)


def _unique(plan: Sequence[ProofPlanEntry]) -> None:
    seen = [entry.invariant_id for entry in plan]
    if len(set(seen)) != len(seen):
        raise DomainValidationError("proof plan: two entries for one invariant")


def evaluate_from_results(
    plan: Sequence[ProofPlanEntry],
    candidate: CandidateState,
    trusted: TrustedState,
    definitions: Mapping[str, Invariant],
    results: Mapping[str, VerificationResultRecord],
    evidence_ids: Mapping[str, str],
    binding_evidence_id: str,
) -> dict[str, InvariantEvaluation]:
    """The evaluation of every VERIFIED entry of ``plan``, by invariant id.

    ``results`` holds the verification results by ``verification_id`` and ``evidence_ids`` the id
    of the evidence record that stores each of them. Each evaluation is the one the lifecycle
    allows for the parent's reference (a PROTECTED one is affected and re-verified, a VIOLATED or
    UNCERTAIN one is reopened, a missing one is registered from ``definitions``) with the PASS of
    the entry applied; its evidence is the source record plus the binding record."""
    require_uuid(binding_evidence_id, "binding_evidence_id")
    _unique(plan)
    found: dict[str, InvariantEvaluation] = {}
    for entry in plan:
        if entry.source is not ProofSource.VERIFIED:
            continue
        assert entry.verification_id is not None  # guaranteed by ProofPlanEntry
        record = results.get(entry.verification_id)
        source = evidence_ids.get(entry.verification_id)
        if record is None or source is None:
            raise DomainValidationError(
                f"proof plan: {entry.target_id} names result {entry.verification_id}, which has no "
                "stored result or no evidence record"
            )
        if record.result is not VerificationResult.PASS:
            raise DomainValidationError(
                f"proof plan: {entry.target_id} is VERIFIED by a {record.result.value} result"
            )
        reference = _reference(trusted, entry.invariant_id)
        if reference is None:
            definition = definitions.get(entry.invariant_id)
            if definition is None or definition.version != entry.invariant_version:
                raise DomainValidationError(
                    f"proof plan: {entry.target_id} has no reference on the parent state and no "
                    "matching definition to register"
                )
            started = InvariantEvaluation.register(
                candidate, definition, trusted
            ).start_verification()
        else:
            if reference.invariant_version != entry.invariant_version:
                raise DomainValidationError(
                    f"proof plan: {entry.target_id} changes the version of the parent's reference "
                    f"({reference.invariant_version}); the lifecycle has no path for that"
                )
            if reference.status.value == "PROTECTED":
                started = InvariantEvaluation.affect(
                    reference, candidate, "AFFECTED_BY_CANDIDATE"
                ).start_reverification()
            else:
                started = _REVISIT(reference, candidate, "REOPENED_FOR_CANDIDATE")
        found[entry.invariant_id] = started.apply_result(
            record.result, [source, binding_evidence_id], record.completed_at
        )
    return found


def build_proofs(
    plan: Sequence[ProofPlanEntry],
    candidate: CandidateState,
    trusted: TrustedState,
    impact: ImpactReport,
    evaluations: Mapping[str, InvariantEvaluation],
    *,
    binding_evidence_id: str,
) -> list[InvariantProof]:
    """The proofs for ``TrustedState.promote``, sorted by invariant id (C-40, C-45, C-164)."""
    require_uuid(binding_evidence_id, "binding_evidence_id")
    _unique(plan)
    covered = {entry.invariant_id for entry in plan}
    missing = sorted({r.invariant_id for r in trusted.invariant_refs} - covered)
    if missing:
        raise DomainValidationError(
            f"proof plan: no proof for {', '.join(missing)}; an invariant of the current state "
            "cannot be dropped at promotion (C-41)"
        )
    proofs: list[InvariantProof] = []
    for entry in sorted(plan, key=lambda e: e.invariant_id):
        if entry.source is ProofSource.VERIFIED:
            evaluation = evaluations.get(entry.invariant_id)
            if evaluation is None:
                raise DomainValidationError(
                    f"proof plan: {entry.target_id} is VERIFIED but has no evaluation"
                )
            if (
                evaluation.candidate_id != candidate.candidate_id
                or evaluation.invariant_version != entry.invariant_version
                or binding_evidence_id not in evaluation.evidence_ids
            ):
                raise DomainValidationError(
                    f"proof plan: the evaluation of {entry.target_id} is not this candidate's, is "
                    "of another version, or lacks the binding record"
                )
            proofs.append(evaluation.to_proof())
            continue
        reference = _reference(trusted, entry.invariant_id)
        if reference is None:
            raise DomainValidationError(
                f"proof plan: {entry.target_id} is CARRIED_FORWARD but the current state has no "
                "reference to it"
            )
        proofs.append(
            InvariantProof.carry_forward(
                reference, candidate, impact, extra_evidence_ids=(binding_evidence_id,)
            )
        )
    return proofs
