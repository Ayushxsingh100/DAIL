"""The evidence chain of a candidate, and the checker that defines "complete" (P6c step 2; Doc 11
§12, §43, §44, §51.3; Doc 06 §28; Doc 09 §26; C-172).

``describe_chain`` reads back, in one open unit of work, everything the orchestrator wrote about one
candidate: its audit events in ``sequence`` order, its candidate-bound evidence in append order, its
decisions, the state a committed decision created and that state's binding record. It writes
nothing and never raises for a damaged record: what cannot be read becomes a problem.

``EvidenceChain.problems()`` returns every violation of the rules of C-172, each as
``"<RULE>: <what>"``:

    ORDER           the events are not those of the candidate's status, in the order of C-172
    EVIDENCE-ORDER  the candidate-bound records are not STATE, IDENTITY, DEPENDENCY, IMPACT and then
                    VERIFICATION records
    NAMED-EVIDENCE  an evidence id an event names does not exist, or a record no event names
    INTEGRITY       a record does not recompute its hash, or its payload is gone (Doc 11 §45)
    BINDING         a record is not bound to this candidate, its parent and its state hash
    DECISION        a decision row is incomplete, or missing for the candidate's status (§43)
    ENDING          the chain does not end as its status says: STATE_PROMOTED for a promotion, the
                    outcome event of the decision for a rejection, a retry or an escalation,
                    ERROR_OCCURRED for a FAILED candidate, and no STATE_PROMOTED otherwise
    PROMOTED-STATE  a promotion without its new state or its binding record bound to that state
    STALE           a STALE_PARENT decision that is not a rejection of a candidate whose parent
                    the lineage has left
    UNREADABLE      something could not be read

``problems(finished=False)`` accepts a chain that stops early (a crash window): the rules that
describe the ending are not applied and the events and records may be a prefix of the full chain;
everything that was written must still be valid.

The checker is production code so that P8's reports can call it. Standard library, ``core.domain``,
``core.promotion.ids`` and ``evidence`` only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from core.domain.audit import AuditEvent, AuditEventType
from core.domain.enums import CandidateStatus, DecisionType
from core.domain.errors import DomainValidationError
from core.domain.evidence import ArtifactRef, EvidenceEvent, EvidenceKind, IntegrityStatus
from core.domain.promotion import DecisionReason, PromotionDecision
from core.domain.repositories import UnitOfWork
from core.domain.state import CandidateState, TrustedState
from core.promotion import ids as pids
from evidence.service import EvidenceService

T = AuditEventType
K = EvidenceKind
S = CandidateStatus

_VC = "VERIFICATION_COMPLETED"
_IGNORED = frozenset({T.PROMOTION_FAILED, T.EVIDENCE_VALIDITY_CHANGED})
_HEAD = (T.CANDIDATE_CREATED, T.IDENTITY_COMPLETED, T.DEPENDENCY_COMPLETED, T.IMPACT_COMPLETED)
# After the verification events, by the candidate's status. PROMOTION_DECIDED comes from the
# decision, PROMOTION_REQUESTED from the orchestrator before a commit; a lost race stores a second
# decision (the stale REJECT, C-166); an escalation by revalidation follows a request (C-38).
_TAILS: Mapping[CandidateStatus, tuple[tuple[AuditEventType, ...], ...]] = {
    S.ANALYZING: ((),),
    S.PROMOTABLE: ((T.PROMOTION_DECIDED,), (T.PROMOTION_DECIDED, T.PROMOTION_REQUESTED)),
    S.PROMOTED: ((T.PROMOTION_DECIDED, T.PROMOTION_REQUESTED, T.STATE_PROMOTED),),
    S.REJECTED: (
        (T.PROMOTION_DECIDED, T.CANDIDATE_REJECTED),
        (T.PROMOTION_DECIDED, T.PROMOTION_REQUESTED, T.PROMOTION_DECIDED, T.CANDIDATE_REJECTED),
    ),
    S.RETRY_REQUIRED: ((T.PROMOTION_DECIDED, T.RETRY_SCHEDULED),),
    S.ESCALATED: (
        (T.PROMOTION_DECIDED, T.ESCALATED),
        (T.PROMOTION_DECIDED, T.PROMOTION_REQUESTED, T.ESCALATED),
    ),
}
_OUTCOME: Mapping[DecisionType, AuditEventType] = {
    DecisionType.REJECT: T.CANDIDATE_REJECTED,
    DecisionType.RETRY: T.RETRY_SCHEDULED,
    DecisionType.ESCALATE: T.ESCALATED,
}
_STATUS_OF_OUTCOME: Mapping[CandidateStatus, DecisionType] = {
    S.REJECTED: DecisionType.REJECT,
    S.RETRY_REQUIRED: DecisionType.RETRY,
    S.ESCALATED: DecisionType.ESCALATE,
}
_EVIDENCE_HEAD = (K.STATE, K.IDENTITY, K.DEPENDENCY, K.IMPACT)
_STAGE_EVENT = {
    T.IDENTITY_COMPLETED: K.IDENTITY,
    T.DEPENDENCY_COMPLETED: K.DEPENDENCY,
    T.IMPACT_COMPLETED: K.IMPACT,
}


_BROKEN: Any = object()  # a read that failed; the failure is in ``unreadable``


@dataclass(frozen=True)
class ChainEvent:
    """An audit event and the payload it points to."""

    event: AuditEvent
    payload: Mapping[str, Any]

    @property
    def event_type(self) -> AuditEventType:
        return self.event.event_type


@dataclass(frozen=True)
class EvidenceChain:
    """Everything recorded about one candidate (see the module docstring)."""

    candidate_id: str
    candidate: CandidateState | None
    events: tuple[ChainEvent, ...]
    evidence: tuple[EvidenceEvent, ...]
    payloads: Mapping[str, Any]
    named: Mapping[str, EvidenceEvent | None]
    integrity: Mapping[str, str]
    decisions: tuple[PromotionDecision, ...]
    state: TrustedState | None
    binding: EvidenceEvent | None
    binding_integrity: str | None
    head_state_id: str | None
    unreadable: tuple[str, ...]
    evidence_read: bool = True

    # --- what was recorded --------------------------------------------------------------------

    def event_types(self) -> list[str]:
        return [e.event_type.value for e in self.events]

    def evidence_kinds(self) -> list[str]:
        return [e.kind.value for e in self.evidence]

    # --- the rules ----------------------------------------------------------------------------

    def problems(self, *, finished: bool = True) -> list[str]:
        found = [f"UNREADABLE: {what}" for what in self.unreadable]
        if self.candidate is None:
            return found or [f"UNREADABLE: candidate {self.candidate_id} is not stored"]
        found += self._order(finished)
        if self.evidence_read:  # otherwise the failure above is the finding
            found += self._evidence_order(finished)
            found += self._named()
        found += self._integrity()
        found += self._binding()
        found += self._decisions()
        found += self._promoted_state()
        found += self._stale(finished)
        found += self._ending(finished)
        return found

    def _types(self) -> list[AuditEventType]:
        return [e.event_type for e in self.events]

    def _expected_sequences(self, candidate: CandidateState) -> list[list[str]]:
        if candidate.status is S.FAILED:
            return [[T.CANDIDATE_CREATED.value, T.ERROR_OCCURRED.value]]
        sequences = []
        for tail in _TAILS.get(candidate.status, ()):
            sequences.append([e.value for e in _HEAD] + [_VC + "+"] + [e.value for e in tail])
        return sequences

    @staticmethod
    def _compress(types: list[str]) -> list[str]:
        out: list[str] = []
        for item in types:
            if item == _VC and out and out[-1] == _VC + "+":
                continue
            out.append(_VC + "+" if item == _VC else item)
        return out

    def _order(self, finished: bool) -> list[str]:
        candidate = self.candidate
        assert candidate is not None
        found: list[str] = []
        types = self._types()
        decided = False
        for kind in types:
            if kind is T.PROMOTION_DECIDED:
                decided = True
            if kind is T.PROMOTION_FAILED and not decided:
                found.append("ORDER: PROMOTION_FAILED comes before any decision")
        # A stage that failed and was rerun leaves its ERROR_OCCURRED in the history (an error is
        # not erased by a recovery); only a FAILED candidate's chain is built around it.
        skipped = _IGNORED if candidate.status is S.FAILED else _IGNORED | {T.ERROR_OCCURRED}
        kept = self._compress([t.value for t in types if t not in skipped])
        if candidate.status not in _TAILS and candidate.status is not S.FAILED:
            if finished or kept[: len(_HEAD)] != [e.value for e in _HEAD][: len(kept)]:
                found.append(
                    f"ORDER: no event order is defined for a {candidate.status.value} candidate"
                )
            return found
        allowed = self._expected_sequences(candidate)
        if finished:
            if kept not in allowed:
                found.append(
                    f"ORDER: events are {kept}, expected one of {allowed} for a "
                    f"{candidate.status.value} candidate"
                )
            return found
        # an unfinished chain: any prefix of an ending
        every = [*allowed, *self._all_prefix_targets()]
        if not any(kept == seq[: len(kept)] for seq in every):
            found.append(f"ORDER: events are {kept}, which is not a prefix of {every}")
        return found

    def _all_prefix_targets(self) -> list[list[str]]:
        full = [e.value for e in _HEAD] + [_VC + "+"]
        return [full + [e.value for e in tail] for tails in _TAILS.values() for tail in tails]

    def _evidence_order(self, finished: bool) -> list[str]:
        candidate = self.candidate
        assert candidate is not None
        kinds = self._compress_kinds(
            [e.kind for e in self.evidence if e.kind is not K.ERROR or candidate.status is S.FAILED]
        )
        if candidate.status is S.FAILED:
            return [] if not kinds else [f"EVIDENCE-ORDER: a FAILED candidate is bound to {kinds}"]
        expected = [k.value for k in _EVIDENCE_HEAD] + ["VERIFICATION+"]
        if (finished and kinds != expected) or kinds != expected[: len(kinds)]:
            return [f"EVIDENCE-ORDER: records are {kinds}, expected {expected}"]
        return []

    @staticmethod
    def _compress_kinds(kinds: list[EvidenceKind]) -> list[str]:
        out: list[str] = []
        for kind in kinds:
            if kind is K.VERIFICATION and out and out[-1] == "VERIFICATION+":
                continue
            out.append("VERIFICATION+" if kind is K.VERIFICATION else kind.value)
        return out

    def _named(self) -> list[str]:
        found = []
        for evidence_id, record in self.named.items():
            if record is None:
                found.append(f"NAMED-EVIDENCE: an event names evidence {evidence_id}, not stored")
        by_event: dict[AuditEventType, set[str]] = {}
        for item in self.events:
            name = item.payload.get("evidence_id")
            if isinstance(name, str):
                by_event.setdefault(item.event_type, set()).add(name)
        for event_type, kind in _STAGE_EVENT.items():
            for row in self.evidence:
                if row.kind is kind and row.evidence_id not in by_event.get(event_type, set()):
                    found.append(
                        f"NAMED-EVIDENCE: {kind.value} record {row.evidence_id} is named by no "
                        f"{event_type.value} event"
                    )
        verification = by_event.get(T.VERIFICATION_COMPLETED, set())
        for row in self.evidence:
            if row.kind is K.VERIFICATION and row.evidence_id not in verification:
                found.append(
                    f"NAMED-EVIDENCE: VERIFICATION record {row.evidence_id} is named by no "
                    "VERIFICATION_COMPLETED event"
                )
        return found

    def _integrity(self) -> list[str]:
        return [
            f"INTEGRITY: evidence {evidence_id} is {status}"
            for evidence_id, status in self.integrity.items()
            if status != IntegrityStatus.VALID.value
        ]

    def _binding(self) -> list[str]:
        candidate = self.candidate
        assert candidate is not None
        found = []
        for row in self.evidence:
            problems = []
            if row.candidate_id != candidate.candidate_id:
                problems.append("another candidate")
            if row.parent_state_id != candidate.parent_state_id:
                problems.append("another parent state")
            if candidate.state_hash is not None and row.state_hash != candidate.state_hash:
                problems.append("another state hash")
            if row.attempt_id is None:
                problems.append("no attempt id")
            if problems:
                found.append(f"BINDING: {row.kind.value} record {row.evidence_id}: {problems}")
        return found

    def _decisions(self) -> list[str]:
        candidate = self.candidate
        assert candidate is not None
        found = []
        verification_ids = {
            body["verification_id"]
            for row in self.evidence
            if row.kind is K.VERIFICATION
            and isinstance(body := self.payloads.get(row.evidence_id), dict)
            and "verification_id" in body
        }
        for d in self.decisions:
            label = f"decision {d.decision_id}"
            if d.candidate_id != candidate.candidate_id:
                found.append(f"DECISION: {label} is about another candidate")
            if d.parent_state_id != candidate.parent_state_id:
                found.append(f"DECISION: {label} names another parent state")
            if not d.policy_version:
                found.append(f"DECISION: {label} records no policy version")
            for stray in sorted(set(d.supporting_results) - verification_ids):
                if not self.evidence_read:
                    break
                found.append(f"DECISION: {label} is supported by {stray}, a result with no record")
            for check in d.required_checks:
                if check.verification_id is not None and (
                    check.verification_id not in d.supporting_results
                ):
                    found.append(
                        f"DECISION: {label}: required check {check.target_id} cites "
                        f"{check.verification_id}, which is not a supporting result"
                    )
            if d.reason is not DecisionReason.STALE_PARENT and not d.required_checks:
                found.append(f"DECISION: {label} lists no required check")
            if d.committed_state_id is not None and (
                self.state is None or self.state.state_id != d.committed_state_id
            ):
                found.append(f"DECISION: {label} is committed to a state that cannot be read")
        found += self._status_decision(candidate)
        return found

    def _status_decision(self, candidate: CandidateState) -> list[str]:
        status = candidate.status
        kinds = {d.decision for d in self.decisions}
        committed = [d for d in self.decisions if d.committed_state_id is not None]
        if status is S.PROMOTED:
            ok = len(committed) == 1 and committed[0].decision is DecisionType.PROMOTE
            return (
                [] if ok else ["DECISION: a PROMOTED candidate has no committed PROMOTE decision"]
            )
        if committed:
            return [f"DECISION: a {status.value} candidate has a committed decision"]
        if status in _STATUS_OF_OUTCOME:
            wanted = _STATUS_OF_OUTCOME[status]
            # an escalation by revalidation keeps the PROMOTE it could not commit (C-38 case 2)
            revalidated = status is S.ESCALATED and DecisionType.PROMOTE in kinds
            if wanted not in kinds and not revalidated:
                return [f"DECISION: a {status.value} candidate has no {wanted.value} decision"]
        if status is S.PROMOTABLE and DecisionType.PROMOTE not in kinds:
            return ["DECISION: a PROMOTABLE candidate has no PROMOTE decision"]
        if status is S.FAILED and self.decisions:
            return ["DECISION: a FAILED candidate has a decision (it has no state hash to bind)"]
        return []

    def _promoted_state(self) -> list[str]:
        committed = [d for d in self.decisions if d.committed_state_id is not None]
        if not committed:
            return []
        decision = committed[0]
        state, binding = self.state, self.binding
        if state is None:
            return [f"PROMOTED-STATE: decision {decision.decision_id} names a state not stored"]
        found = []
        if state.commit_decision_id != decision.decision_id:
            found.append("PROMOTED-STATE: the new state names another decision")
        if binding is None:
            return [*found, f"PROMOTED-STATE: no binding record for state {state.state_id}"]
        if binding.kind is not K.STATE or binding.state_id != state.state_id:
            found.append("PROMOTED-STATE: the binding record is not bound to the new state")
        if binding.state_hash != state.state_hash:
            found.append("PROMOTED-STATE: the binding record carries another state hash")
        if binding.parent_state_id != decision.parent_state_id:
            found.append("PROMOTED-STATE: the binding record names another parent")
        if self.binding_integrity not in (None, IntegrityStatus.VALID.value):
            found.append(f"PROMOTED-STATE: the binding record is {self.binding_integrity}")
        return found

    def _stale(self, finished: bool) -> list[str]:
        candidate = self.candidate
        assert candidate is not None
        found = []
        for d in self.decisions:
            if d.reason is not DecisionReason.STALE_PARENT:
                continue
            if d.decision is not DecisionType.REJECT:
                found.append(f"STALE: decision {d.decision_id} is STALE_PARENT but not a REJECT")
            if candidate.status is not S.REJECTED:
                found.append(
                    f"STALE: a STALE_PARENT decision, but the candidate is {candidate.status.value}"
                )
            if self.head_state_id == candidate.parent_state_id:
                found.append(
                    "STALE: a STALE_PARENT decision, but the candidate's parent is still the "
                    "lineage's current state"
                )
            if finished:
                last = self.events[-1] if self.events else None
                if (
                    last is None
                    or last.event_type is not T.CANDIDATE_REJECTED
                    or last.payload.get("reason") != DecisionReason.STALE_PARENT.value
                ):
                    found.append("STALE: the chain does not end with REJECT STALE_PARENT")
        return found

    def _ending(self, finished: bool) -> list[str]:
        candidate = self.candidate
        assert candidate is not None
        found = []
        types = self._types()
        # a recorded error (even one after the ending, when the call failed once the work was done)
        # does not move the ending; only a FAILED candidate's chain is built around it
        skipped = _IGNORED if candidate.status is S.FAILED else _IGNORED | {T.ERROR_OCCURRED}
        types_for_ending = [t for t in types if t not in skipped]
        if T.STATE_PROMOTED in types and candidate.status is not S.PROMOTED:
            found.append(f"ENDING: STATE_PROMOTED on a {candidate.status.value} candidate")
        if not finished:
            return found
        last = types_for_ending[-1] if types_for_ending else None
        status = candidate.status
        if status is S.PROMOTED:
            if last is not T.STATE_PROMOTED:
                found.append(
                    "ENDING: a promoted candidate's chain does not end with STATE_PROMOTED"
                )
        elif status is S.FAILED:
            if last is not T.ERROR_OCCURRED:
                found.append("ENDING: a FAILED candidate's chain does not end with ERROR_OCCURRED")
        elif status in _STATUS_OF_OUTCOME:
            wanted = _OUTCOME[_STATUS_OF_OUTCOME[status]]
            if last is not wanted:
                found.append(
                    f"ENDING: a {status.value} candidate's chain ends with "
                    f"{None if last is None else last.value}, not {wanted.value}"
                )
        else:
            found.append(f"ENDING: the chain of a {status.value} candidate is not finished")
        return found


# --- reading -----------------------------------------------------------------------------------


def _try(unreadable: list[str], what: str, read: Any, default: Any = None) -> Any:
    try:
        return read()
    except (DomainValidationError, KeyError, ValueError) as failure:
        unreadable.append(f"{what}: {type(failure).__name__}: {failure}")
        return default


def describe_chain(uow: UnitOfWork, candidate_id: str) -> EvidenceChain:
    """Read the chain of ``candidate_id`` (read-only; see the module docstring)."""
    unreadable: list[str] = []
    service = EvidenceService()
    candidate = _try(unreadable, "candidate", lambda: uow.candidates.get(candidate_id))
    audit = _try(unreadable, "audit events", lambda: uow.audit.list_for_candidate(candidate_id), ())
    events = tuple(
        ChainEvent(
            e,
            _try(
                unreadable,
                f"audit payload {e.event_id}",
                lambda e=e: uow.evidence.resolve(ArtifactRef.parse(e.payload_ref)),
                {},
            ),
        )
        for e in audit
    )
    listed = _try(
        unreadable, "evidence", lambda: uow.evidence.list_for_candidate(candidate_id), _BROKEN
    )
    evidence_read = listed is not _BROKEN
    evidence: tuple[EvidenceEvent, ...] = () if listed is _BROKEN else tuple(listed)
    payloads: dict[str, Any] = {}
    integrity: dict[str, str] = {}
    named: dict[str, EvidenceEvent | None] = {}
    wanted = [row.evidence_id for row in evidence]
    for item in events:
        for key in ("evidence_id", "binding_evidence_id"):
            value = item.payload.get(key) if isinstance(item.payload, dict) else None
            if isinstance(value, str):
                found = _try(
                    unreadable, f"evidence {value}", lambda v=value: uow.evidence.get(v), _BROKEN
                )
                if found is not _BROKEN:
                    named[value] = found
                wanted.append(value)
    for evidence_id in dict.fromkeys(wanted):
        if evidence_id in named and named[evidence_id] is None:
            continue
        status = _try(
            unreadable,
            f"integrity of {evidence_id}",
            lambda v=evidence_id: service.verify_integrity(uow, v),
        )
        if status is not None:
            integrity[evidence_id] = status.value
        record = named.get(evidence_id) or _try(
            unreadable, f"evidence {evidence_id}", lambda v=evidence_id: uow.evidence.get(v)
        )
        if record is not None and status is IntegrityStatus.VALID:
            payloads[evidence_id] = _try(
                unreadable,
                f"payload of {evidence_id}",
                lambda r=record: uow.evidence.resolve(ArtifactRef.parse(r.payload_ref)),
            )
    decisions = tuple(
        _try(unreadable, "decisions", lambda: uow.decisions.for_candidate(candidate_id), ())
    )
    committed = next((d for d in decisions if d.committed_state_id is not None), None)
    state = binding = binding_integrity = None
    if committed is not None and committed.committed_state_id is not None:
        state = _try(
            unreadable,
            "the new state",
            lambda: uow.trusted_states.get(committed.committed_state_id),
        )
        binding_id = pids.evidence_id_for(committed.decision_id)
        binding = _try(unreadable, "the binding record", lambda: uow.evidence.get(binding_id))
        if binding is not None:
            status = _try(
                unreadable,
                "integrity of the binding record",
                lambda: service.verify_integrity(uow, binding_id),
            )
            binding_integrity = None if status is None else status.value
    head = None
    if candidate is not None:
        current = _try(
            unreadable,
            "the lineage head",
            lambda: uow.trusted_states.get_current(candidate.lineage_id),
        )
        head = None if current is None else current.state_id
    return EvidenceChain(
        candidate_id=candidate_id,
        candidate=candidate,
        events=events,
        evidence=evidence,
        payloads=payloads,
        named=named,
        integrity=integrity,
        decisions=decisions,
        state=state,
        binding=binding,
        binding_integrity=binding_integrity,
        head_state_id=head,
        unreadable=tuple(unreadable),
        evidence_read=evidence_read,
    )
