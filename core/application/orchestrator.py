"""The evaluation orchestrator: one call from a stored baseline and a candidate configuration to a
decision and, for a PROMOTE, the next Trusted State (P6c step 4; Doc 03 §15; Doc 06 §20, §27; Doc 09
§25, §26, §40; Doc 11 §12, §43; C-170, C-172, C-173, C-174, C-175).

    load parent -> build candidate -> normalize -> identity -> graph -> impact -> scope policy
    -> verify -> decide -> record evidence -> record decision -> commit if PROMOTE

**It coordinates only.** It owns no policy and no decision logic: every rule it uses lives in a
package that has passed its gate (the engines, ``decide``, ``record_decision``,
``commit_promotion``). It routes on the *type* of what a stage returned (a normalization that
produced no resource set, a decision kind, a stored row) and never on a verification result, an
invariant id or a policy value; a test reads this file with ``ast`` to keep it so. The emergency
switch needs no branch here: the policy built from ``promotion.automatic_enabled`` turns a
would-be PROMOTE into an ESCALATE (C-161). It imports neither ``sqlite3`` nor ``core.persistence``
(it works through a factory that opens a unit of work, C-167), reads no clock and draws no
randomness (the clock is injected, every id is derived from the request, C-170 (4)).

**Stages are separate units of work**, so a crash after stage k leaves records 1..k, all valid, and
a rerun with the same request completes: every record and event is idempotent by derived id, the
candidate resumes from its stored status, and a decision that is already stored is the decision.

**The stages always run against the candidate's recorded parent** (``Patch.parent_state_id``), read
back from the database, and ``decide`` is given the **current** state: when the two differ the
candidate is stale and ``decide``'s own stale-first rule rejects it (Doc 09 §25) with real reports
behind the decision (C-173). The stale REJECT has the id ``rejection_decision_id_for(decision_id)``,
the one P6b gives the loser of a race.

**Reruns.** A candidate that already has its decision (PROMOTED, REJECTED, RETRY_REQUIRED,
ESCALATED, FAILED) is not decided again: its stages are recomputed and re-recorded, so that another
directory under the same ids raises ``ConflictingDuplicateError``, and the stored decision comes
back with ``duplicate=True``.

``checkpoint`` is a test-only hook, called with the name of a stage after its records committed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from core.application import ids as oids
from core.application.recorder import StageRecorder
from core.application.scope_policy import VerificationScopePolicy
from core.dependency.build import build_graph
from core.dependency.invariants import SemanticBinding
from core.domain.audit import AuditEventType
from core.domain.enums import CandidateSource, CandidateStatus, DecisionType
from core.domain.errors import DomainValidationError, StaleParentError
from core.domain.hashing import content_hash
from core.domain.ids import require_uuid
from core.domain.impact import ImpactReport
from core.domain.invariant import Invariant
from core.domain.patch import Patch
from core.domain.promotion import (
    ConflictingDuplicateError,
    DecisionOutcome,
    OracleVerdict,
    PromotionDecision,
    PromotionInputError,
    PromotionPolicy,
)
from core.domain.repositories import UnitOfWork
from core.domain.state import (
    CandidateState,
    TrustedState,
    fail_building,
    finish_building,
    start_building,
    transition_candidate,
)
from core.domain.verification import ConstructionStatus, VerificationReport
from core.identity.engine import compare
from core.impact.engine import compute_impact
from core.impact.inputs import PriorProof
from core.promotion import ids as pids
from core.promotion.commit import (
    CommitResult,
    PromotionCommitError,
    PromotionContext,
    commit_promotion,
    record_decision,
)
from core.promotion.decide import decide
from core.promotion.policy import dail_policy
from core.terraform_model.normalization import normalize_directory
from core.verification.dispatch import DEFAULT_VERIFIERS, VerifierTable
from core.verification.engine import run_work_set
from core.verification.inputs import VerificationInputs

D = DecisionType
S = CandidateStatus
_FLAG = "promotion.automatic_enabled"
_TERMINAL = frozenset(
    {S.PROMOTED, S.REJECTED, S.RETRY_REQUIRED, S.ESCALATED, S.FAILED}
)  # the candidate already has its outcome


class EvaluationInputError(DomainValidationError):
    """The request cannot be evaluated (malformed, or it names state the database does not hold)."""


class ResultKind(StrEnum):
    """How an evaluation ended. DUPLICATE: the promotion had been committed already."""

    PROMOTED = "PROMOTED"
    REJECTED = "REJECTED"
    RETRY_REQUIRED = "RETRY_REQUIRED"
    ESCALATED = "ESCALATED"
    STALE = "STALE"
    CONSTRUCTION_FAILED = "CONSTRUCTION_FAILED"
    DUPLICATE = "DUPLICATE"


_KIND_OF_DECISION: Mapping[DecisionType, ResultKind] = {
    D.REJECT: ResultKind.REJECTED,
    D.RETRY: ResultKind.RETRY_REQUIRED,
    D.ESCALATE: ResultKind.ESCALATED,
    D.PROMOTE: ResultKind.PROMOTED,
}


@dataclass(frozen=True)
class EvaluationRequest:
    """One candidate to evaluate (C-170 (2)). ``patch`` is a record bound to the parent it was
    written against; ``candidate_dir`` is the candidate configuration, and the patch text is not
    applied to it (C-174). ``candidate_sequence`` is the candidate's place in its lineage."""

    lineage_id: str
    candidate_id: str
    candidate_sequence: int
    attempt_number: int
    patch: Patch
    candidate_dir: Path
    variables: Mapping[str, object] | None
    definitions: tuple[Invariant, ...]
    bindings: tuple[SemanticBinding, ...]
    context: PromotionContext
    oracle_verdicts: tuple[OracleVerdict, ...] = ()

    def __post_init__(self) -> None:
        for name in ("lineage_id", "candidate_id"):
            require_uuid(getattr(self, name), f"EvaluationRequest.{name}")
        for name in ("candidate_sequence", "attempt_number"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise EvaluationInputError(f"EvaluationRequest.{name} must be an integer >= 1")
        if (
            not isinstance(self.patch, Patch)
            or self.patch.source is not CandidateSource.FIXED_PATCH
        ):
            raise EvaluationInputError("EvaluationRequest.patch must be a FIXED_PATCH Patch")
        if not isinstance(self.candidate_dir, Path):
            raise EvaluationInputError("EvaluationRequest.candidate_dir must be a Path")
        if not isinstance(self.context, PromotionContext):
            raise EvaluationInputError("EvaluationRequest.context must be a PromotionContext")
        definitions = tuple(self.definitions)
        if not definitions or not all(isinstance(d, Invariant) for d in definitions):
            raise EvaluationInputError("EvaluationRequest.definitions must hold Invariant objects")
        bindings = tuple(self.bindings)
        if not all(isinstance(b, SemanticBinding) for b in bindings):
            raise EvaluationInputError("EvaluationRequest.bindings must hold SemanticBinding")
        verdicts = tuple(self.oracle_verdicts)
        if not all(isinstance(v, OracleVerdict) for v in verdicts):
            raise EvaluationInputError("EvaluationRequest.oracle_verdicts must hold OracleVerdict")
        object.__setattr__(self, "definitions", definitions)
        object.__setattr__(self, "bindings", bindings)
        object.__setattr__(self, "oracle_verdicts", verdicts)


@dataclass(frozen=True)
class EvaluationResult:
    """What ``evaluate`` returns. ``decision`` is the stored decision (``None`` for a construction
    failure), ``outcome`` the ``DecisionOutcome`` made in this call (``None`` on a rerun that had
    its decision already), ``commit`` the result of ``commit_promotion`` when one ran, ``state`` the
    new Trusted State of a promotion, ``candidate`` the candidate as stored afterwards. ``impact``,
    ``verification`` and ``evidence_ids`` are the reports and the evidence-id map computed in this
    call (reports are not persisted, C-167); ``duplicate`` is true when nothing new was decided."""

    kind: ResultKind
    candidate: CandidateState
    decision: PromotionDecision | None = None
    outcome: DecisionOutcome | None = None
    commit: CommitResult | None = None
    state: TrustedState | None = None
    impact: ImpactReport | None = None
    verification: VerificationReport | None = None
    evidence_ids: Mapping[str, str] | None = None
    duplicate: bool = False


class EvaluationOrchestrator:
    """Evaluates candidates against a database (see the module docstring)."""

    def __init__(
        self,
        factory: Callable[[], UnitOfWork],
        *,
        config: Any,
        scope_policy: VerificationScopePolicy,
        clock: Callable[[], datetime],
        policy_version: str,
        verifiers: VerifierTable = DEFAULT_VERIFIERS,
        policy_factory: Callable[..., PromotionPolicy] = dail_policy,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        if not callable(factory):
            raise EvaluationInputError("EvaluationOrchestrator: factory must open a unit of work")
        if not isinstance(scope_policy, VerificationScopePolicy):
            raise EvaluationInputError("EvaluationOrchestrator: scope_policy must have select()")
        if not callable(clock):
            raise EvaluationInputError("EvaluationOrchestrator: clock must be callable")
        if not isinstance(policy_version, str) or not policy_version:
            raise EvaluationInputError("EvaluationOrchestrator: policy_version must be text")
        if checkpoint is not None and not callable(checkpoint):
            raise EvaluationInputError("EvaluationOrchestrator: checkpoint must be callable")
        try:
            flag = config.get(_FLAG)
        except (KeyError, AttributeError) as missing:
            raise EvaluationInputError(f"the configuration has no {_FLAG}") from missing
        if not isinstance(flag, bool):
            raise EvaluationInputError(f"{_FLAG} must be a bool, not {flag!r}: refusing to start")
        self._factory = factory
        self._scope_policy = scope_policy
        self._clock = clock
        self._policy_version = policy_version
        self._verifiers = verifiers
        self._policy_factory = policy_factory
        self._checkpoint = checkpoint
        self._automatic = flag

    def evaluate(self, request: EvaluationRequest) -> EvaluationResult:
        """Evaluate ``request`` (see the module docstring). Raises ``EvaluationInputError`` for a
        request the database cannot satisfy, ``ConflictingDuplicateError`` when the ids are in use
        with another content, ``PromotionCommitError`` as P6b defines it; any other exception
        propagates after a best-effort ERROR_OCCURRED."""
        if not isinstance(request, EvaluationRequest):
            raise EvaluationInputError("evaluate: request must be an EvaluationRequest")
        run = _Run(self, request)
        try:
            return run.execute()
        except (
            ConflictingDuplicateError,
            PromotionInputError,
            EvaluationInputError,
            PromotionCommitError,
        ):
            raise
        except Exception as failure:
            run.record_failure(failure)
            raise


class _Run:
    """One call of ``evaluate``: the request, the candidate so far, and the stage reached."""

    def __init__(self, orchestrator: EvaluationOrchestrator, request: EvaluationRequest) -> None:
        self.o = orchestrator
        self.r = request
        self.recorder = StageRecorder(request.context)
        self.stage = "load"
        self.candidate: CandidateState | None = None
        self.failed_now = False  # this call is the one that moved the candidate to FAILED

    # --- small helpers -------------------------------------------------------------------------

    def _passed(self, name: str) -> None:
        if self.o._checkpoint is not None:
            self.o._checkpoint(name)

    def _when(self) -> datetime:
        return self.o._clock()

    @property
    def _cid(self) -> str:
        return self.r.candidate_id

    def _stored(self) -> CandidateState:
        with self.o._factory() as uow:
            stored = uow.candidates.get(self._cid)
        if stored is None:
            raise EvaluationInputError(f"candidate {self._cid} is not stored")
        self.candidate = stored
        return stored

    # --- the whole evaluation ------------------------------------------------------------------

    def execute(self) -> EvaluationResult:
        r, o = self.r, self.o
        with o._factory() as uow:
            current = uow.trusted_states.get_current(r.lineage_id)
            parent = uow.trusted_states.get(r.patch.parent_state_id)
        if current is None:
            raise EvaluationInputError(
                f"lineage {r.lineage_id} has no baseline to evaluate against"
            )
        if parent is None or parent.lineage_id != r.lineage_id:
            raise EvaluationInputError(
                f"the patch was written against state {r.patch.parent_state_id}, which is not a "
                f"state of lineage {r.lineage_id}"
            )
        self.stage = "candidate"
        candidate = self._create(parent)
        at = candidate.created_at
        self._passed("after_candidate")
        self.stage = "build"
        outcome = normalize_directory(r.candidate_dir, r.variables, now=at)
        candidate = self._build(candidate, outcome)
        self._passed("after_build")
        if candidate.state_hash is None:
            return self._construction_failed()
        assert outcome.resource_set_hash is not None
        self.stage = "identity"
        identity = compare(
            parent.resources,
            outcome.resources,
            list(outcome.moves),
            parent_state_id=parent.state_id,
            candidate_id=self._cid,
            now=at,
        )
        self._record(
            lambda u: self.recorder.record_identity(
                u, candidate, identity, attempt_number=r.attempt_number, at=at, when=self._when()
            )
        )
        self._passed("after_identity")
        self.stage = "dependency"
        trusted_graph = build_graph(
            parent.resources, r.definitions, r.bindings, state_id=parent.state_id, now=at
        )
        candidate_graph = build_graph(
            outcome.resources, r.definitions, r.bindings, state_id=self._cid, now=at
        )
        self._record(
            lambda u: self.recorder.record_dependency(
                u,
                candidate,
                candidate_graph,
                attempt_number=r.attempt_number,
                at=at,
                when=self._when(),
            )
        )
        self._passed("after_dependency")
        self.stage = "impact"
        impact = compute_impact(
            parent.resources,
            outcome.resources,
            identity,
            trusted_graph,
            candidate_graph,
            r.definitions,
            self._priors(parent),
            parent_state_id=parent.state_id,
            candidate_id=self._cid,
            now=at,
        )
        self._record(
            lambda u: self.recorder.record_impact(
                u, candidate, impact, attempt_number=r.attempt_number, at=at, when=self._when()
            )
        )
        self._passed("after_impact")
        self.stage = "verification"
        work = o._scope_policy.select(impact, r.definitions)
        inputs = VerificationInputs(
            candidate_resources=outcome.resources,
            parent_resources=parent.resources,
            candidate_state_hash=outcome.resource_set_hash,
            normalization_version=outcome.normalization_version,
            candidate_id=self._cid,
            parent_state_id=parent.state_id,
            identity=identity,
            impact=impact,
            candidate_graph=candidate_graph,
            trusted_graph=trusted_graph,
            invariants=r.definitions,
            construction=ConstructionStatus.OK,
        )
        report = run_work_set(
            work,
            inputs,
            clock=lambda: at,
            ids=oids.verification_ids(self._cid, r.attempt_number),
            verifiers=o._verifiers,
        )
        evidence_ids = self._record(
            lambda u: self.recorder.record_verification(
                u, candidate, report, attempt_number=r.attempt_number, when=self._when()
            )
        )
        self._passed("after_verification")
        self.stage = "decision"
        return self._decide(impact, report, evidence_ids, at)

    # --- the candidate -------------------------------------------------------------------------

    def _record(self, write: Callable[[UnitOfWork], Any]) -> Any:
        with self.o._factory() as uow:
            return write(uow)

    def _create(self, parent: TrustedState) -> CandidateState:
        """The stored candidate, or a new one: patch, CREATED then BUILDING, CANDIDATE_CREATED."""
        r = self.r
        with self.o._factory() as uow:
            stored = uow.candidates.get(self._cid)
            patch = uow.patches.get(r.patch.patch_id)
            if patch is not None and patch != r.patch:
                raise ConflictingDuplicateError(
                    f"patch {r.patch.patch_id} is already stored with different content"
                )
            if stored is not None:
                if (
                    stored.patch_id != r.patch.patch_id
                    or stored.patch_hash != r.patch.content_hash
                    or stored.parent_state_id != parent.state_id
                    or stored.candidate_sequence != r.candidate_sequence
                    or stored.lineage_id != r.lineage_id
                ):
                    raise ConflictingDuplicateError(
                        f"candidate {self._cid} already exists for another patch, parent or "
                        "sequence"
                    )
                self.candidate = stored
                return stored
            if patch is None:
                uow.patches.save(r.patch)
            created = CandidateState.create(
                parent=parent,
                patch=r.patch,
                candidate_sequence=r.candidate_sequence,
                now=self._when(),
                candidate_id=self._cid,
            )
            building = start_building(created)
            uow.candidates.create(created)
            uow.candidates.save_transition(building)
            self.recorder.emit(
                uow,
                AuditEventType.CANDIDATE_CREATED,
                event_id=oids.event_id_for(
                    self._cid, r.attempt_number, AuditEventType.CANDIDATE_CREATED
                ),
                payload={
                    "parent_state_id": parent.state_id,
                    "patch_id": r.patch.patch_id,
                    "source": r.patch.source.value,
                    "patch_hash": r.patch.content_hash,
                    "candidate_sequence": r.candidate_sequence,
                    "attempt_number": r.attempt_number,
                },
                when=self._when(),
                candidate_id=self._cid,
            )
        self.candidate = building
        return building

    def _build(self, candidate: CandidateState, outcome: Any) -> CandidateState:
        """BUILDING to READY to ANALYZING, or to FAILED (Doc 06 §27); a rerun finds its own stored
        status and checks that the directory is the one that was built."""
        r = self.r
        usable = outcome.resource_set_hash is not None
        if candidate.state_hash is not None or candidate.status is S.FAILED:
            built = candidate.state_hash
            if usable != (built is not None) or (usable and built != outcome.resource_set_hash):
                raise ConflictingDuplicateError(
                    f"candidate {self._cid} was built from another configuration "
                    "(its state hash differs, Doc 11 §38)"
                )
        if not usable:
            if candidate.status is S.FAILED:
                return candidate
            return self._fail(candidate, outcome)
        if candidate.status is S.BUILDING or candidate.status is S.CREATED:
            if candidate.status is S.CREATED:
                candidate = start_building(candidate)
            try:
                ready = finish_building(candidate, outcome.resources)
            except DomainValidationError as refusal:
                return self._fail(candidate, outcome, str(refusal))
            if ready.state_hash != outcome.resource_set_hash:
                return self._fail(
                    candidate, outcome, "the candidate's state hash is not the normalizer's"
                )
            analyzing = transition_candidate(ready, S.ANALYZING)
            with self.o._factory() as uow:
                uow.candidates.save_transition(ready)
                self.recorder.record_candidate(
                    uow, ready, r.patch, attempt_number=r.attempt_number, at=ready.created_at
                )
                uow.candidates.save_transition(analyzing)
            self.candidate = analyzing
            return analyzing
        if candidate.status is S.READY:
            analyzing = transition_candidate(candidate, S.ANALYZING)
            with self.o._factory() as uow:
                self.recorder.record_candidate(
                    uow,
                    candidate,
                    r.patch,
                    attempt_number=r.attempt_number,
                    at=candidate.created_at,
                )
                uow.candidates.save_transition(analyzing)
            self.candidate = analyzing
            return analyzing
        with self.o._factory() as uow:  # a rerun: the same record again
            self.recorder.record_candidate(
                uow, candidate, r.patch, attempt_number=r.attempt_number, at=candidate.created_at
            )
        return candidate

    def _fail(
        self, candidate: CandidateState, outcome: Any, note: str | None = None
    ) -> CandidateState:
        """BUILDING to FAILED with the ERROR record and ERROR_OCCURRED (C-170 (3))."""
        r = self.r
        shown = [f"{d.code}: {d.message}" for d in outcome.diagnostics[:10]]
        reason = note or f"normalization is not OK (status {outcome.status.value})"
        failed = fail_building(candidate, reason[:300])
        self.failed_now = True
        with self.o._factory() as uow:
            uow.candidates.save_transition(failed)
            self.recorder.record_error(
                uow,
                stage="build",
                error_type="ConstructionFailed",
                detail={"reason": reason[:300], "diagnostics": [t[:300] for t in shown]},
                attempt_number=r.attempt_number,
                at=candidate.created_at,
                when=self._when(),
                candidate=failed,
            )
        self.candidate = failed
        return failed

    def _construction_failed(self) -> EvaluationResult:
        """The candidate is FAILED: no decision exists to return, only the candidate and, if it was
        already FAILED before this call, the mark that nothing new was written."""
        return EvaluationResult(
            kind=ResultKind.CONSTRUCTION_FAILED,
            candidate=self._stored(),
            duplicate=not self.failed_now,
        )

    def _priors(self, parent: TrustedState) -> list[PriorProof]:
        by_id = {d.invariant_id: d for d in self.r.definitions}
        priors = []
        for ref in parent.invariant_refs:
            definition = by_id.get(ref.invariant_id)
            if definition is None:
                raise EvaluationInputError(
                    f"the parent state refers to {ref.invariant_id}, which the request does not "
                    "define"
                )
            priors.append(
                PriorProof(
                    ref.invariant_id,
                    ref.invariant_version,
                    ref.evidence_ids,
                    definition.verifier_id,
                    definition.verifier_version,
                )
            )
        return priors

    # --- decide, record, commit ----------------------------------------------------------------

    def _current(self) -> TrustedState:
        with self.o._factory() as uow:
            current = uow.trusted_states.get_current(self.r.lineage_id)
        if current is None:
            raise EvaluationInputError(f"lineage {self.r.lineage_id} has no current state")
        return current

    def _decision(
        self,
        candidate: CandidateState,
        impact: ImpactReport,
        report: VerificationReport,
        policy: PromotionPolicy,
        at: datetime,
    ) -> tuple[DecisionOutcome, bool]:
        """``decide`` against the current state as it is now. When the candidate's parent is not
        that state it is stale and ``decide`` says so (Doc 09 §25) under the derived id of the
        stale rejection, the one P6b gives the loser of a race (C-166)."""
        r = self.r
        current = self._current()
        stale = current.state_id != candidate.parent_state_id
        base_id = oids.decision_id_for(self._cid, r.attempt_number)
        outcome = decide(
            candidate,
            current,
            impact,
            report,
            policy,
            decision_id=pids.rejection_decision_id_for(base_id) if stale else base_id,
            now=at,
            attempt_number=r.attempt_number,
            oracle_verdicts=r.oracle_verdicts,
        )
        return outcome, stale

    def _decide(
        self,
        impact: ImpactReport,
        report: VerificationReport,
        evidence_ids: Mapping[str, str],
        at: datetime,
    ) -> EvaluationResult:
        r, o = self.r, self.o
        candidate = self._stored()
        if candidate.status in _TERMINAL:
            return self._stored_result(candidate, impact, report, evidence_ids)
        policy = o._policy_factory(
            policy_version=o._policy_version,
            invariants=r.definitions,
            automatic_enabled=o._automatic,
        )
        outcome, stale = self._decision(candidate, impact, report, policy, at)
        try:
            with o._factory() as uow:
                moved = record_decision(uow, outcome, candidate, r.context, now=at)
        except StaleParentError:
            # Another promotion landed between decide and record_decision: the head only moves
            # forward, so deciding again can only give the stale rejection (Doc 06 §27).
            outcome, stale = self._decision(candidate, impact, report, policy, at)
            with o._factory() as uow:
                moved = record_decision(uow, outcome, candidate, r.context, now=at)
        self.candidate = moved
        self._passed("after_decision")
        kind = _KIND_OF_DECISION[outcome.decision.decision]
        if outcome.decision.decision is not D.PROMOTE:
            return EvaluationResult(
                kind=ResultKind.STALE if stale else kind,
                candidate=self._stored(),
                decision=outcome.decision,
                outcome=outcome,
                impact=impact,
                verification=report,
                evidence_ids=evidence_ids,
            )
        self.stage = "commit"
        with o._factory() as uow:
            self.recorder.emit(
                uow,
                AuditEventType.PROMOTION_REQUESTED,
                event_id=oids.event_id_for(
                    self._cid, r.attempt_number, AuditEventType.PROMOTION_REQUESTED
                ),
                payload={
                    "decision_id": outcome.decision.decision_id,
                    "parent_state_id": outcome.decision.parent_state_id,
                },
                when=self._when(),
                candidate_id=self._cid,
                decision_id=outcome.decision.decision_id,
            )
        self._passed("after_request")
        committed = commit_promotion(
            o._factory,
            outcome,
            moved,
            impact,
            report,
            policy,
            evidence_ids,
            r.context,
            now=at,
            attempt_number=r.attempt_number,
            oracle_verdicts=r.oracle_verdicts,
        )
        return self._after_commit(outcome, committed, impact, report, evidence_ids)

    def _after_commit(
        self,
        outcome: DecisionOutcome,
        committed: CommitResult,
        impact: ImpactReport,
        report: VerificationReport,
        evidence_ids: Mapping[str, str],
    ) -> EvaluationResult:
        if committed.stale:
            kind = ResultKind.STALE
        elif committed.escalated:
            kind = ResultKind.ESCALATED
        elif committed.duplicate:
            kind = ResultKind.DUPLICATE
        else:
            kind = ResultKind.PROMOTED
        return EvaluationResult(
            kind=kind,
            candidate=self._stored(),
            decision=committed.decision,
            outcome=outcome,
            commit=committed,
            state=committed.state,
            impact=impact,
            verification=report,
            evidence_ids=evidence_ids,
            duplicate=committed.duplicate,
        )

    def _stored_result(
        self,
        candidate: CandidateState,
        impact: ImpactReport,
        report: VerificationReport,
        evidence_ids: Mapping[str, str],
    ) -> EvaluationResult:
        """A rerun of a candidate that has its outcome: the stored decision, nothing written."""
        base_id = oids.decision_id_for(self._cid, self.r.attempt_number)
        with self.o._factory() as uow:
            decisions = uow.decisions.for_candidate(self._cid)
            committed = next((d for d in decisions if d.committed_state_id is not None), None)
            state = (
                None
                if committed is None or committed.committed_state_id is None
                else uow.trusted_states.get(committed.committed_state_id)
            )
        decision = committed or (decisions[-1] if decisions else None)
        if decision is None:
            kind = ResultKind.CONSTRUCTION_FAILED
        elif state is not None:
            kind = ResultKind.DUPLICATE
        elif decision.decision_id == pids.rejection_decision_id_for(base_id):
            kind = ResultKind.STALE
        else:
            kind = _KIND_OF_DECISION[decision.decision]
        return EvaluationResult(
            kind=kind,
            candidate=candidate,
            decision=decision,
            state=state,
            impact=impact,
            verification=report,
            evidence_ids=evidence_ids,
            duplicate=True,
        )

    # --- failures that are not decisions -------------------------------------------------------

    def record_failure(self, failure: Exception) -> None:
        """Best effort: an ERROR_OCCURRED event (and its record) for the stage that failed. If it
        cannot be written nothing is claimed and the caller still gets the original exception."""
        candidate = self.candidate
        if candidate is None:
            return
        key = content_hash(
            {"stage": self.stage, "type": type(failure).__name__, "message": str(failure)[:200]}
        )[:16]
        try:
            with self.o._factory() as uow:
                self.recorder.record_error(
                    uow,
                    stage=self.stage,
                    error_type=type(failure).__name__,
                    detail={"message": str(failure)[:300]},
                    attempt_number=self.r.attempt_number,
                    at=candidate.created_at,
                    when=self._when(),
                    candidate=candidate,
                    evidence_id=oids.evidence_id_for(
                        self._cid, self.r.attempt_number, "error", key
                    ),
                    event_id=oids.event_id_for(
                        self._cid, self.r.attempt_number, AuditEventType.ERROR_OCCURRED, key
                    ),
                )
        except Exception:  # best effort: the stage's own exception is what the caller gets
            return
