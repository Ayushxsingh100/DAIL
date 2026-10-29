"""``decide``: the decision half of the Promotion Controller (P6a; Doc 09 §17-§29, Appendix A,
Doc 06 §16-§21, Doc 11 §26, §43; C-45, C-157 to C-161, C-37, C-41).

A pure function of its arguments: no clock, no randomness, no I/O, no mutation. It consumes the
reports it is given and never runs, repeats or repairs verification (Doc 02 §15). Anything it finds
is a decision (REJECT, RETRY or ESCALATE, with every blocking reason); only a malformed argument
raises (``PromotionInputError``). Uncertainty never promotes: an UNKNOWN, UNSUPPORTED or
VERIFIER_ERROR result, a missing, stale or insufficient one, an oracle conflict and an incomplete
decision all stop short of PROMOTE.

The order of Doc 09 Appendix A is kept (stale parent, structure, required items, sufficiency), but
the early return of its loop is not: every required item is examined and the conditions are folded
by severity (C-158), so a later FAIL cannot hide behind an earlier UNKNOWN and the decision does not
depend on the order of anything.

Standard library and ``core.domain`` only (R18).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

from core.domain.enums import (
    CandidateStatus,
    DecisionType,
    InvariantStatus,
    VerificationResult,
)
from core.domain.errors import DomainValidationError
from core.domain.ids import require_uuid
from core.domain.impact import ImpactReport, WorkTargetType
from core.domain.invariant import Invariant, InvariantRef
from core.domain.jsonvalue import utc
from core.domain.promotion import (
    GATE_CONSISTENCY,
    GATE_STRUCTURAL,
    BlockingCondition,
    DecisionOutcome,
    DecisionReason,
    OracleVerdict,
    PromotionDecision,
    PromotionEvidence,
    PromotionInputError,
    PromotionPolicy,
    ProofPlanEntry,
    ProofSource,
    RequiredCheck,
)
from core.domain.state import CandidateState, TrustedState
from core.domain.verification import (
    EVIDENCE_LEVELS,
    VerificationReport,
    VerificationResultRecord,
    fresh,
    sufficient,
)

D = DecisionType
R = DecisionReason

_SEVERITY: Final = {D.REJECT: 3, D.ESCALATE: 2, D.RETRY: 1}
# Among the conditions of the winning class the reason is the first of this list (C-158).
_PRIORITY: Final = (
    R.STALE_PARENT,
    R.STRUCTURAL_FAILURE,
    R.INCONSISTENT_REPORTS,
    R.REQUIRED_CHECK_FAILED,
    R.REQUIRED_UNSUPPORTED,
    R.INSUFFICIENT_EVIDENCE,
    R.EVIDENCE_NOT_SUFFICIENT,
    R.EVIDENCE_STALE,
    R.POLICY_REGISTRY_REGRESSION,
    R.VERIFIER_ERROR,
    R.EVIDENCE_CONFLICT,
    R.RETRY_BUDGET_EXHAUSTED,
    R.REQUIRED_UNKNOWN,
    R.DECISION_INCOMPLETE,
    R.AUTOMATIC_PROMOTION_DISABLED,
)
_NON_SUCCESS_CODE: Final = {
    VerificationResult.UNKNOWN: R.REQUIRED_UNKNOWN,
    VerificationResult.UNSUPPORTED: R.REQUIRED_UNSUPPORTED,
    VerificationResult.VERIFIER_ERROR: R.VERIFIER_ERROR,
}
_DECIDABLE: Final = (CandidateStatus.ANALYZING, CandidateStatus.PROMOTABLE)


def fold(conditions: Sequence[BlockingCondition]) -> tuple[DecisionType, DecisionReason]:
    """The decision and the reason of a non-empty set of blocking conditions (C-158): the most
    severe class wins (REJECT above ESCALATE above RETRY), and within it the reason is the first of
    a fixed list. It does not depend on the order of ``conditions``."""
    if not conditions:
        raise DomainValidationError("fold: there is no blocking condition to decide on")
    top = max(_SEVERITY[c.decision] for c in conditions)
    winners = [c for c in conditions if _SEVERITY[c.decision] == top]
    decision = next(d for d, severity in _SEVERITY.items() if severity == top)
    return decision, min((c.code for c in winners), key=_PRIORITY.index)


# --- arguments ------------------------------------------------------------------------------------


def _check_arguments(
    candidate: object,
    trusted: object,
    impact: object,
    verification: object,
    policy: object,
    decision_id: object,
    now: object,
    attempt_number: object,
    oracle_verdicts: object,
) -> tuple[datetime, tuple[OracleVerdict, ...]]:
    for value, kind, name in (
        (candidate, CandidateState, "candidate"),
        (trusted, TrustedState, "trusted"),
        (impact, ImpactReport, "impact"),
        (verification, VerificationReport, "verification"),
        (policy, PromotionPolicy, "policy"),
    ):
        if not isinstance(value, kind):
            raise PromotionInputError(f"decide: {name} must be a {kind.__name__}")
    assert isinstance(candidate, CandidateState) and isinstance(trusted, TrustedState)
    try:
        require_uuid(decision_id, "decide.decision_id")
        moment = utc(now, "decide.now")
    except DomainValidationError as error:
        raise PromotionInputError(str(error)) from None
    if (
        not isinstance(attempt_number, int)
        or isinstance(attempt_number, bool)
        or attempt_number < 1
    ):
        raise PromotionInputError("decide.attempt_number: must be an integer >= 1")
    if candidate.lineage_id != trusted.lineage_id:
        raise PromotionInputError(
            "decide: the candidate and the trusted state are in different lineages"
        )
    if candidate.status not in _DECIDABLE or candidate.state_hash is None:
        raise PromotionInputError(
            f"decide: a {candidate.status.value} candidate is not under analysis "
            "(ANALYZING or PROMOTABLE)"
        )
    if isinstance(oracle_verdicts, str) or not isinstance(oracle_verdicts, Iterable):
        raise PromotionInputError("decide.oracle_verdicts: must be a list of OracleVerdict")
    verdicts = tuple(oracle_verdicts)
    if not all(isinstance(v, OracleVerdict) for v in verdicts):
        raise PromotionInputError("decide.oracle_verdicts: must hold OracleVerdict objects")
    keys = [(v.invariant_id, v.invariant_version) for v in verdicts]
    if len(set(keys)) != len(keys):
        raise PromotionInputError("decide.oracle_verdicts: two verdicts for one invariant version")
    return moment, verdicts


# --- the pieces of the decision -------------------------------------------------------------------


@dataclass(frozen=True)
class _Item:
    """One required target, and what a result for it must be."""

    target_id: str
    kind: str  # GATE, INVARIANT or BASELINE
    invariant: Invariant | None  # the definition at the policy's registry version
    reference: InvariantRef | None  # the current state's reference to it, if any
    verifier: tuple[str, str] | None  # id and version a result must carry; None: its own


@dataclass
class _Verdict:
    check: RequiredCheck
    conditions: list[BlockingCondition] = field(default_factory=list)
    entry: ProofPlanEntry | None = None
    result_id: str | None = None


def _condition(
    code: DecisionReason, decision: DecisionType, target: str, detail: str
) -> BlockingCondition:
    return BlockingCondition(code, decision, target, detail)


def _described(record: VerificationResultRecord) -> str:
    reason = "" if record.reason is None else f" {record.reason.value}"
    return f"result {record.verification_id}: {record.result.value}{reason}"


def _failure_code(item: _Item) -> DecisionReason:
    if item.target_id == GATE_STRUCTURAL:
        return R.STRUCTURAL_FAILURE
    if item.target_id == GATE_CONSISTENCY:
        return R.INCONSISTENT_REPORTS
    return R.REQUIRED_CHECK_FAILED


def _level_ok(record: VerificationResultRecord, policy: PromotionPolicy) -> bool:
    return EVIDENCE_LEVELS.index(record.evidence_level) >= EVIDENCE_LEVELS.index(
        policy.min_evidence_level
    )


def _required_items(
    trusted: TrustedState, impact: ImpactReport, policy: PromotionPolicy
) -> tuple[list[_Item], list[BlockingCondition]]:
    """Every required target (C-159), and the policy conditions found on the way (C-41)."""
    problems: list[BlockingCondition] = []
    if policy.invariant_registry_version < trusted.invariant_registry_version:
        problems.append(
            _condition(
                R.POLICY_REGISTRY_REGRESSION,
                D.ESCALATE,
                "POLICY",
                f"registry version {policy.invariant_registry_version} is lower than the "
                f"current state's {trusted.invariant_registry_version}",
            )
        )
    references = {ref.invariant_id: ref for ref in trusted.invariant_refs}
    items = [
        _Item(target, "GATE", None, None, policy.gate_verifier(target))
        for target in (GATE_CONSISTENCY, GATE_STRUCTURAL)
    ]
    for invariant_id in sorted({*references, *policy.extra_required}):
        reference = references.get(invariant_id)
        definition = policy.definition(invariant_id)
        if definition is None or (
            reference is not None and definition.version < reference.invariant_version
        ):
            version = 1 if reference is None else reference.invariant_version
            problems.append(
                _condition(
                    R.POLICY_REGISTRY_REGRESSION,
                    D.ESCALATE,
                    f"INVARIANT:{invariant_id}:{version}",
                    "the policy has no definition of it at or above the current version",
                )
            )
            items.append(
                _Item(f"INVARIANT:{invariant_id}:{version}", "UNDEFINED", None, reference, None)
            )
            continue
        items.append(
            _Item(
                f"INVARIANT:{invariant_id}:{definition.version}",
                "INVARIANT",
                definition,
                reference,
                (definition.verifier_id, definition.verifier_version),
            )
        )
    items.extend(
        _Item(work.target_id, "BASELINE", None, None, None)
        for work in impact.verification_work
        if work.target_type is WorkTargetType.RESOURCE
    )
    return sorted(items, key=lambda item: item.target_id), problems


def _binding_conditions(
    candidate: CandidateState, impact: ImpactReport, verification: VerificationReport
) -> list[BlockingCondition]:
    """The reports must be those of this candidate and this parent (Doc 09 §19, §31)."""
    found = []
    if impact.candidate_id != candidate.candidate_id:
        found.append(("impact report", "is for another candidate"))
    if impact.parent_state_id != candidate.parent_state_id:
        found.append(("impact report", "is for another parent state"))
    if verification.candidate_id != candidate.candidate_id:
        found.append(("verification report", "is for another candidate"))
    return [
        _condition(R.INCONSISTENT_REPORTS, D.REJECT, name.replace(" ", "-"), f"the {name} {what}")
        for name, what in found
    ]


def _carry_forward_refusals(
    item: _Item,
    candidate: CandidateState,
    trusted: TrustedState,
    impact: ImpactReport,
    policy: PromotionPolicy,
) -> list[str]:
    """Why ``item`` cannot be proven by carrying its reference forward (C-159); empty if it can."""
    assert item.invariant is not None
    definition, reference = item.invariant, item.reference
    refusals = []
    if not policy.carry_forward_enabled:
        refusals.append("the policy does not permit carry-forward")
    if reference is None:
        refusals.append("the current state has no reference to it")
    else:
        if reference.invariant_version != definition.version:
            refusals.append(
                f"its version changed from {reference.invariant_version} to {definition.version}"
            )
        if reference.status is not InvariantStatus.PROTECTED:
            refusals.append(f"its reference is {reference.status.value}, not PROTECTED")
        elif not reference.can_satisfy_proof():
            refusals.append("its reference was invalidated")
    key = (definition.invariant_id, definition.version)
    if impact.affected_for(*key) is not None:
        refusals.append("the candidate affects it")
    if any((r.invariant_id, r.invariant_version) == key for r in impact.uncertainty):
        refusals.append("its impact is uncertain")
    if not impact.carry_forward_ok(
        *key, candidate_id=candidate.candidate_id, parent_state_id=candidate.parent_state_id
    ):
        refusals.append("the impact report does not offer its evidence")
    if reference is not None and reference.state_id != trusted.state_id:
        refusals.append("its reference is not the current state's")
    return refusals


def _assess(
    item: _Item,
    records: Mapping[str, VerificationResultRecord],
    candidate: CandidateState,
    trusted: TrustedState,
    impact: ImpactReport,
    policy: PromotionPolicy,
) -> _Verdict:
    """Is ``item`` proven, and if not, why not (C-158, C-159)?"""
    candidate_hash = candidate.state_hash
    assert candidate_hash is not None
    verdict = _Verdict(RequiredCheck(item.target_id, _kind(item), None, None))
    if item.kind == "UNDEFINED":
        return verdict  # the policy condition already says what is wrong
    record = records.get(item.target_id)
    invariant = item.invariant
    verifier_id, verifier_version = item.verifier or (
        (record.verifier_id, record.verifier_version) if record is not None else ("", "")
    )
    is_fresh = record is not None and fresh(
        record,
        candidate_hash=candidate_hash,
        invariant_version=None if invariant is None else invariant.version,
        verifier_version=verifier_version,
    )
    if record is not None and is_fresh:
        _assess_result(verdict, item, record, verifier_id, verifier_version, candidate_hash, policy)
        return verdict
    if invariant is not None:
        refusals = _carry_forward_refusals(item, candidate, trusted, impact, policy)
        if not refusals:
            assert item.reference is not None
            verdict.check = RequiredCheck(
                item.target_id, "INVARIANT", ProofSource.CARRIED_FORWARD, None
            )
            verdict.entry = ProofPlanEntry(
                invariant.invariant_id,
                invariant.version,
                ProofSource.CARRIED_FORWARD,
                None,
                trusted.state_id,
                item.reference.evidence_ids,
            )
            return verdict
        why = f"no fresh result; carry-forward refused: {'; '.join(refusals)}"
    else:
        why = "no fresh result"
    if record is None:
        verdict.conditions.append(
            _condition(R.INSUFFICIENT_EVIDENCE, D.REJECT, item.target_id, f"no result; {why}")
        )
    else:
        verdict.conditions.append(
            _condition(
                R.EVIDENCE_STALE,
                D.REJECT,
                item.target_id,
                f"{_described(record)} is stale for this candidate and these versions; {why}",
            )
        )
    return verdict


def _kind(item: _Item) -> str:
    return "INVARIANT" if item.kind == "UNDEFINED" else item.kind


def _assess_result(
    verdict: _Verdict,
    item: _Item,
    record: VerificationResultRecord,
    verifier_id: str,
    verifier_version: str,
    candidate_hash: str,
    policy: PromotionPolicy,
) -> None:
    """A fresh result decides: FAIL rejects, a non-success follows the table, a sufficient PASS
    proves (Doc 09 §11, §18)."""
    target, described = item.target_id, _described(record)
    if record.result is VerificationResult.FAIL:
        verdict.conditions.append(_condition(_failure_code(item), D.REJECT, target, described))
        return
    if record.result is VerificationResult.PASS:
        invariant = item.invariant
        if sufficient(
            record,
            target_id=target,
            candidate_hash=candidate_hash,
            invariant_id=None if invariant is None else invariant.invariant_id,
            invariant_version=None if invariant is None else invariant.version,
            verifier_id=verifier_id,
            verifier_version=verifier_version,
        ) and (item.kind == "GATE" or _level_ok(record, policy)):
            verdict.check = RequiredCheck(
                target, _kind(item), ProofSource.VERIFIED, record.verification_id
            )
            verdict.result_id = record.verification_id
            if invariant is not None:
                verdict.entry = ProofPlanEntry(
                    invariant.invariant_id,
                    invariant.version,
                    ProofSource.VERIFIED,
                    record.verification_id,
                    None,
                    (),
                )
            return
        verdict.conditions.append(
            _condition(
                R.EVIDENCE_NOT_SUFFICIENT,
                D.REJECT,
                target,
                f"{described} is not sufficient proof: it must be from {verifier_id} "
                f"{verifier_version}"
                + (
                    "" if item.kind == "GATE" else f" at level {policy.min_evidence_level} or above"
                ),
            )
        )
        return
    error_type = None if record.error is None else record.error["type"]
    verdict.conditions.append(
        _condition(
            _NON_SUCCESS_CODE[record.result],
            policy.non_success_decision(record.result, error_type),
            target,
            described,
        )
    )


def _oracle_conflicts(
    verdicts: Iterable[OracleVerdict],
    results: dict[str, _Verdict],
    policy: PromotionPolicy,
) -> list[BlockingCondition]:
    """Primary PASS (or a carried proof) and oracle FAIL: a conflict, and the check is not proven
    (C-160). Every other pairing leaves the primary result as it is."""
    found = []
    for oracle in sorted(verdicts, key=lambda v: (v.invariant_id, v.invariant_version)):
        if oracle.result is not VerificationResult.FAIL:
            continue
        target = f"INVARIANT:{oracle.invariant_id}:{oracle.invariant_version}"
        verdict = results.get(target)
        if verdict is None or verdict.check.source is None:
            continue
        found.append(
            _condition(
                R.EVIDENCE_CONFLICT,
                policy.conflict_decision,
                target,
                f"the primary verifier proves it but oracle {oracle.oracle_version} reports FAIL",
            )
        )
        verdict.check = RequiredCheck(target, "INVARIANT", None, None)
        verdict.entry = None
        verdict.result_id = None
    return found


def completeness_problems(
    candidate: CandidateState,
    parent_state_id: str,
    supporting: Iterable[str],
    impact: ImpactReport,
    verification: VerificationReport,
    policy: PromotionPolicy,
) -> list[str]:
    """What is missing for the decision to be complete (Doc 11 §43, C-161): candidate and parent
    binding, every supporting result present, the report hashes, the policy version."""
    problems = []
    if parent_state_id != candidate.parent_state_id:
        problems.append("the decision's parent is not the candidate's parent state")
    if verification.candidate_id != candidate.candidate_id:
        problems.append("the verification report is for another candidate")
    if impact.candidate_id != candidate.candidate_id:
        problems.append("the impact report is for another candidate")
    held = {r.verification_id for r in verification.results}
    for missing in sorted(set(supporting) - held):
        problems.append(f"supporting result {missing} is not in the verification report")
    if verification.candidate_hash != candidate.state_hash:
        problems.append(
            "the verification report's candidate_hash is not the candidate's state_hash"
        )
    if verification.content_hash != verification.compute_hash():
        problems.append("the verification report's content hash does not recompute")
    if impact.content_hash != impact.compute_hash():
        problems.append("the impact report's content hash does not recompute")
    if not policy.policy_version:
        problems.append("the policy version is not recorded")
    return problems


# --- decide ---------------------------------------------------------------------------------------


def decide(
    candidate: CandidateState,
    trusted: TrustedState,
    impact: ImpactReport,
    verification: VerificationReport,
    policy: PromotionPolicy,
    *,
    decision_id: str,
    now: datetime,
    attempt_number: int = 1,
    oracle_verdicts: Iterable[OracleVerdict] = (),
) -> DecisionOutcome:
    """PROMOTE, REJECT, RETRY or ESCALATE for ``candidate`` against the current state ``trusted``.

    ``attempt_number`` counts the attempts at this candidate's problem (1 for the first); it feeds
    only the retry budget of the policy. PROMOTE needs every required item proven, nothing
    conflicting, a complete decision and the emergency switch on (Doc 09 §19)."""
    moment, verdicts = _check_arguments(
        candidate,
        trusted,
        impact,
        verification,
        policy,
        decision_id,
        now,
        attempt_number,
        oracle_verdicts,
    )
    if candidate.parent_state_id != trusted.state_id:
        stale = _condition(
            R.STALE_PARENT,
            D.REJECT,
            "STATE",
            f"the candidate's parent {candidate.parent_state_id} is not the current state "
            f"{trusted.state_id}",
        )
        return _build(candidate, policy, decision_id, moment, attempt_number, [], [stale], (), ())
    items, conditions = _required_items(trusted, impact, policy)
    conditions += _binding_conditions(candidate, impact, verification)
    records = {r.target_id: r for r in verification.results}
    assessed = {
        item.target_id: _assess(item, records, candidate, trusted, impact, policy) for item in items
    }
    for verdict in assessed.values():
        conditions += verdict.conditions
    conditions += _oracle_conflicts(verdicts, assessed, policy)
    ordered = [assessed[item.target_id] for item in items]
    checks = [v.check for v in ordered]
    plan = sorted((v.entry for v in ordered if v.entry is not None), key=lambda e: e.invariant_id)
    supporting = sorted({v.result_id for v in ordered if v.result_id is not None})
    problems = completeness_problems(
        candidate, candidate.parent_state_id, supporting, impact, verification, policy
    )
    if not conditions:
        if problems:
            conditions.append(
                _condition(R.DECISION_INCOMPLETE, D.ESCALATE, "DECISION", "; ".join(problems))
            )
        if not policy.automatic_enabled:
            conditions.append(
                _condition(
                    R.AUTOMATIC_PROMOTION_DISABLED,
                    D.ESCALATE,
                    "POLICY",
                    "automatic promotion is disabled; the decision would have been PROMOTE",
                )
            )
    else:
        decision, _ = fold(conditions)
        if decision is D.RETRY and attempt_number >= policy.max_attempts:
            conditions.append(
                _condition(
                    R.RETRY_BUDGET_EXHAUSTED,
                    D.ESCALATE,
                    "POLICY",
                    f"attempt {attempt_number} of {policy.max_attempts}: repeated UNKNOWN is "
                    "not an eventual PASS",
                )
            )
            decision, _ = fold(conditions)
        if problems:  # recorded; the decision it keeps is the one found above
            conditions.append(
                _condition(R.DECISION_INCOMPLETE, decision, "DECISION", "; ".join(problems))
            )
    return _build(
        candidate, policy, decision_id, moment, attempt_number, checks, conditions, plan, supporting
    )


def _build(
    candidate: CandidateState,
    policy: PromotionPolicy,
    decision_id: str,
    moment: datetime,
    attempt_number: int,
    checks: Sequence[RequiredCheck],
    conditions: Sequence[BlockingCondition],
    plan: Sequence[ProofPlanEntry],
    supporting: Sequence[str],
) -> DecisionOutcome:
    unique = sorted({c.sort_key(): c for c in conditions}.values(), key=BlockingCondition.sort_key)
    if unique:
        decision, reason = fold(unique)
    else:
        decision, reason = D.PROMOTE, R.ALL_REQUIRED_PROVEN
    ordered_checks = sorted(checks, key=lambda c: c.target_id)
    made = PromotionDecision.create(
        decision_id=decision_id,
        candidate_id=candidate.candidate_id,
        parent_state_id=candidate.parent_state_id,
        decision=decision,
        reason=reason,
        policy_version=policy.policy_version,
        attempt_number=attempt_number,
        required_checks=ordered_checks,
        blocking_conditions=unique,
        supporting_results=sorted(supporting),
        created_at=moment,
    )
    proven = bool(ordered_checks) and all(c.source is not None for c in ordered_checks)
    evidence = PromotionEvidence.create(
        decision_id=decision_id,
        candidate_id=candidate.candidate_id,
        parent_state_id=candidate.parent_state_id,
        required_checks=ordered_checks,
        verification_refs=sorted(supporting),
        evidence_sufficiency="SUFFICIENT" if proven else "INSUFFICIENT",
        policy_version=policy.policy_version,
        decision=decision,
        reason=reason,
    )
    return DecisionOutcome(made, tuple(plan), evidence)
