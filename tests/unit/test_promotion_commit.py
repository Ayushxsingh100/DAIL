"""The commit of a promotion (P6b step 5; Doc 09 §26, §27, §38-§40, Appendix B; Doc 06 §20,
§21, §27; Doc 05 §32; DATA-INT-003, 004, 009; C-38, C-163 to C-168).

HAND EXPECTATIONS, written before the code. The canonical world (``tests/promotion_builders.py``):
v0 has INV-SEC-001 VIOLATED and the other three PROTECTED; the candidate fixes SSH; the decision
is a PROMOTE with INV-SEC-001 and INV-FUNC-001 VERIFIED and INV-SEC-002 and INV-SEC-003
CARRIED_FORWARD.

* ``record_decision`` stores every decision, keeps all its blocking conditions, moves the candidate
  to the status of Doc 06 §5 that the decision names (PROMOTABLE, REJECTED, RETRY_REQUIRED or
  ESCALATED), appends PROMOTION_DECIDED and, for a non-PROMOTE, the event Doc 11 §12 names, and
  never touches ``trusted_states`` or ``lineage_heads`` (Doc 09 §40, SM-003, SM-004). Recording
  the same decision twice changes nothing.
* A commit makes version 1: parent v0, the candidate's resources, the state id and the binding
  record id derived from the decision id, ``commit_decision_id`` = the decision id; the reference of
  INV-SEC-001 and INV-FUNC-001 are VERIFIED and PROTECTED, those of INV-SEC-002 and INV-SEC-003 are
  CARRIED_FORWARD from v0 (status and time of the parent); every reference and the state carry the
  binding record id (C-164); the binding record is STATE-kind evidence bound to vN+1 with its state
  hash, parent v0 and event name ``promotion.committed``, and its payload names every source.
* The lineage head is v1, the candidate is PROMOTED, the decision is committed to v1, and one
  STATE_PROMOTED event with the derived id names v1 and the decision (Doc 09 §26).
* The same decision committed again returns the same state with ``duplicate=True`` and writes
  nothing (C-163); another content under the same decision id raises ``ConflictingDuplicateError``.
* A commit whose parent is no longer current loses (C-38 case 1, C-166): ``stale=True``, a REJECT
  decision STALE_PARENT with no state, the candidate REJECTED, the head unchanged.
* A commit whose decision no longer holds (C-167) or whose evidence does not bind (C-164) rolls back
  and escalates the candidate (C-38 case 2): ``escalated=True``, a PROMOTION_FAILED event, no state,
  no binding record, the PROMOTE decision still uncommitted.
* v1 to v2: a reference carried forward from v1 needs the binding record of v1; with that record
  tampered, absent from the reference, or bound to another state, the commit escalates.
"""

from __future__ import annotations

import dataclasses
import unittest
from typing import Any

from core.domain.audit import AuditEventType as AE
from core.domain.enums import CandidateStatus as CS
from core.domain.enums import DecisionType, InvariantStatus, ProofOrigin
from core.domain.errors import DomainValidationError
from core.domain.evidence import ArtifactRef, EvidenceKind
from core.domain.promotion import ConflictingDuplicateError, DecisionReason, ProofSource
from core.domain.state import TrustedState
from core.persistence.sqlite import SqliteUnitOfWork
from core.promotion import ids
from core.promotion.commit import (
    PromotionCommitError,
    PromotionContext,
    commit_promotion,
    record_decision,
)
from tests.domain_builders import uid
from tests.promotion_builders import (
    ERROR,
    FAIL,
    FUNC1,
    SEC1,
    SEC2,
    SEC3,
    UNKNOWN,
    make_world,
    run,
    target,
)
from tests.promotion_commit_builders import CONTEXT, NOW, CommitCase

D, R = DecisionType, DecisionReason
DECISION = uid(9100)


class TestRecordDecision(CommitCase):
    stored_status = CS.ANALYZING

    def record(self, outcome: Any) -> Any:
        with self.uow() as u:
            return record_decision(u, outcome, self.world.candidate, CONTEXT, now=NOW)

    def counts(self) -> tuple[int, int, int]:
        return (
            self.count("trusted_states"),
            self.count("lineage_heads"),
            self.count("invariant_refs"),
        )

    def test_a_promote_is_stored_uncommitted_and_the_candidate_becomes_promotable(self) -> None:
        outcome = run(self.world)
        moved = self.record(outcome)
        self.assertIs(moved.status, CS.PROMOTABLE)
        self.assertEqual(self.candidate_status(), "PROMOTABLE")
        with self.uow() as u:
            stored = u.decisions.get(outcome.decision.decision_id)
        self.assertEqual(stored, outcome.decision)
        self.assertIsNone(stored.committed_state_id)  # type: ignore[union-attr]
        self.assertEqual(self.audit_types(), ["PROMOTION_DECIDED"])

    def test_every_non_promote_keeps_all_its_blocking_conditions_and_moves_the_candidate(
        self,
    ) -> None:
        cases = (
            ({target(SEC1): FAIL, target(FUNC1): FAIL}, D.REJECT, "REJECTED", "CANDIDATE_REJECTED"),
            ({target(FUNC1): UNKNOWN}, D.RETRY, "RETRY_REQUIRED", "RETRY_SCHEDULED"),
            ({target(FUNC1): ERROR}, D.ESCALATE, "ESCALATED", "ESCALATED"),
        )
        for index, (results, kind, status, event) in enumerate(cases):
            with self.subTest(decision=kind):
                self.tearDown()
                self.setUp()
                outcome = run(make_world(results=results))  # same ids as the stored candidate
                self.assertIs(outcome.decision.decision, kind)
                self.assertGreaterEqual(len(outcome.decision.blocking_conditions), 1)
                moved = self.record(outcome)
                self.assertEqual(moved.status.value, status)
                with self.uow() as u:
                    stored = u.decisions.get(outcome.decision.decision_id)
                self.assertEqual(stored, outcome.decision)  # every condition, from the database
                self.assertEqual(self.audit_types(), ["PROMOTION_DECIDED", event])
                self.assertEqual(self.counts(), (1, 1, 4))
                self.assertGreaterEqual(index, 0)

    def test_the_trusted_state_is_never_touched(self) -> None:
        before = (self.counts(), self.current().state_hash)
        self.record(run(self.world))
        self.assertEqual((self.counts(), self.current().state_hash), before)

    def test_recording_the_same_decision_twice_changes_nothing(self) -> None:
        outcome = run(self.world)
        self.record(outcome)
        rows = (self.count("promotion_decisions"), self.count("audit_events"))
        self.record(outcome)
        self.assertEqual((self.count("promotion_decisions"), self.count("audit_events")), rows)
        self.assertEqual(self.candidate_status(), "PROMOTABLE")

    def test_the_decision_event_carries_the_decision_and_the_policy(self) -> None:
        outcome = run(self.world)
        self.record(outcome)
        with self.uow() as u:
            (event,) = u.audit.list_for_candidate(self.world.candidate.candidate_id)
            payload = u.evidence.resolve(ArtifactRef.parse(event.payload_ref))
        self.assertIs(event.event_type, AE.PROMOTION_DECIDED)
        self.assertEqual(event.decision_id, outcome.decision.decision_id)
        self.assertEqual(payload["parent_state_id"], self.world.trusted.state_id)
        self.assertEqual(payload["decision"], "PROMOTE")
        self.assertEqual(payload["policy_version"], "policy-1")


class TestCommitPromotion(CommitCase):
    def setUp(self) -> None:
        super().setUp()
        self.outcome = run(self.world)
        self.assertIs(self.outcome.decision.decision, D.PROMOTE)

    def test_the_result_names_the_new_state_and_the_committed_decision(self) -> None:
        result = self.commit(outcome=self.outcome)
        self.assertFalse(result.duplicate or result.stale or result.escalated)
        assert result.state is not None
        self.assertEqual(result.state, self.current())
        self.assertEqual(result.decision, self.outcome.decision.committed(result.state.state_id))

    def test_the_new_state_has_the_right_parent_version_resources_and_ids(self) -> None:
        state = self.commit(outcome=self.outcome).state
        assert state is not None
        self.assertEqual(state.version, 1)
        self.assertEqual(state.parent_state_id, self.world.trusted.state_id)
        self.assertEqual(state.resources, self.world.candidate.resources)
        self.assertEqual(state.state_id, ids.state_id_for(DECISION))
        self.assertEqual(state.commit_decision_id, DECISION)
        self.assertEqual(state.lineage_id, self.world.trusted.lineage_id)

    def test_the_references_are_verified_or_carried_with_the_right_status(self) -> None:
        state = self.commit(outcome=self.outcome).state
        assert state is not None
        origins = {r.invariant_id: r.origin for r in state.invariant_refs}
        self.assertEqual(
            origins,
            {
                FUNC1: ProofOrigin.VERIFIED,
                SEC1: ProofOrigin.VERIFIED,
                SEC2: ProofOrigin.CARRIED_FORWARD,
                SEC3: ProofOrigin.CARRIED_FORWARD,
            },
        )
        for ref in state.invariant_refs:
            self.assertIs(ref.status, InvariantStatus.PROTECTED, ref.invariant_id)
        parent = {r.invariant_id: r for r in self.world.trusted.invariant_refs}
        for carried in (SEC2, SEC3):
            ref = next(r for r in state.invariant_refs if r.invariant_id == carried)
            self.assertEqual(ref.last_verified_at, parent[carried].last_verified_at)
            self.assertTrue(set(parent[carried].evidence_ids) <= set(ref.evidence_ids))

    def test_every_reference_and_the_state_carry_the_binding_record(self) -> None:
        state = self.commit(outcome=self.outcome).state
        assert state is not None
        binding = ids.evidence_id_for(DECISION)
        for ref in state.invariant_refs:
            self.assertIn(binding, ref.evidence_ids, ref.invariant_id)
        self.assertIn(binding, state.evidence_refs)
        union = {e for ref in state.invariant_refs for e in ref.evidence_ids}
        self.assertEqual(set(state.evidence_refs), union)

    def test_the_binding_record_is_state_evidence_bound_to_the_new_state(self) -> None:
        state = self.commit(outcome=self.outcome).state
        assert state is not None
        with self.uow() as u:
            event = u.evidence.get(ids.evidence_id_for(DECISION))
            assert event is not None
            payload = u.evidence.resolve(ArtifactRef.parse(event.payload_ref))
        self.assertIs(event.kind, EvidenceKind.STATE)
        self.assertEqual(event.event_name, "promotion.committed")
        self.assertEqual(event.state_id, state.state_id)
        self.assertEqual(event.state_hash, state.state_hash)
        self.assertEqual(event.parent_state_id, self.world.trusted.state_id)
        self.assertIsNone(event.candidate_id)
        self.assertEqual(event.validity.value, "VALID")
        self.assertEqual(payload["decision"]["decision_id"], DECISION)
        self.assertEqual(payload["decision"]["candidate_id"], self.world.candidate.candidate_id)
        sources = {s["invariant_id"]: s for s in payload["invariants"]}
        self.assertEqual(set(sources), {FUNC1, SEC1, SEC2, SEC3})
        for verified in (FUNC1, SEC1):
            self.assertEqual(sources[verified]["source"], ProofSource.VERIFIED.value)
            self.assertIsNone(sources[verified]["source_state_id"])
            self.assertEqual(len(sources[verified]["source_evidence_ids"]), 1)
        for carried in (SEC2, SEC3):
            self.assertEqual(sources[carried]["source"], ProofSource.CARRIED_FORWARD.value)
            self.assertEqual(sources[carried]["source_state_id"], self.world.trusted.state_id)

    def test_the_head_the_candidate_and_the_decision_move_together(self) -> None:
        state = self.commit(outcome=self.outcome).state
        assert state is not None
        self.assertEqual(self.current().state_id, state.state_id)
        self.assertEqual(self.candidate_status(), "PROMOTED")
        with self.uow() as u:
            stored = u.decisions.get(DECISION)
        assert stored is not None
        self.assertEqual(stored.committed_state_id, state.state_id)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(self.count("promotion_decisions"), 1)

    def test_one_state_promoted_event_with_the_derived_id(self) -> None:
        state = self.commit(outcome=self.outcome).state
        assert state is not None
        with self.uow() as u:
            event = u.audit.get(ids.event_id_for(DECISION))
            assert event is not None
            payload = u.evidence.resolve(ArtifactRef.parse(event.payload_ref))
        self.assertIs(event.event_type, AE.STATE_PROMOTED)
        self.assertEqual((event.state_id, event.decision_id), (state.state_id, DECISION))
        self.assertEqual(payload["parent_state_id"], self.world.trusted.state_id)
        self.assertEqual(payload["new_state_id"], state.state_id)
        self.assertEqual(self.count("audit_events", "event_type = 'STATE_PROMOTED'"), 1)

    def test_the_decision_is_stored_even_when_it_was_not_recorded_before(self) -> None:
        self.assertEqual(self.count("promotion_decisions"), 0)
        self.commit(outcome=self.outcome)
        self.assertEqual(self.count("promotion_decisions"), 1)

    def test_a_recorded_decision_is_committed_in_place(self) -> None:
        with self.uow() as u:
            u.decisions.save(self.outcome.decision)
        self.commit(outcome=self.outcome)
        self.assertEqual(self.count("promotion_decisions"), 1)

    def test_only_a_promote_can_be_committed(self) -> None:
        reject = run(make_world(results={target(FUNC1): FAIL}))
        with self.assertRaises(Exception) as caught:
            self.commit(outcome=reject)
        self.assertNotIsInstance(caught.exception, PromotionCommitError)
        self.assertEqual(self.count("trusted_states"), 1)


class TestIdempotency(CommitCase):
    def setUp(self) -> None:
        super().setUp()
        self.outcome = run(self.world)
        self.first = self.commit(outcome=self.outcome)

    def rows(self) -> dict[str, int]:
        return {
            t: self.count(t)
            for t in (
                "trusted_states",
                "invariant_refs",
                "promotion_decisions",
                "audit_events",
                "evidence_events",
                "state_resources",
            )
        }

    def test_the_same_decision_again_returns_the_same_state_and_writes_nothing(self) -> None:
        before = self.rows()
        again = self.commit(outcome=self.outcome)
        self.assertTrue(again.duplicate)
        self.assertEqual(again.state, self.first.state)
        self.assertEqual(again.decision, self.first.decision)
        self.assertEqual(self.rows(), before)

    def test_the_same_id_with_other_content_is_a_conflicting_duplicate(self) -> None:
        other = run(make_world(results={target(FUNC1): FAIL}))
        forged = dataclasses.replace(
            self.outcome, decision=self.outcome.decision, evidence=self.outcome.evidence
        )
        policy = dataclasses.replace(self.world.policy, policy_version="policy-2")
        other_content = run(dataclasses.replace(self.world, policy=policy))
        self.assertEqual(other_content.decision.decision_id, self.outcome.decision.decision_id)
        self.assertNotEqual(other_content.decision.content_hash, self.outcome.decision.content_hash)
        before = self.rows()
        with self.assertRaises(ConflictingDuplicateError):
            self.commit(outcome=other_content)
        self.assertEqual(self.rows(), before)
        self.assertIsNotNone(other)
        self.assertIsNotNone(forged)

    def test_a_second_promote_for_a_promoted_candidate_is_refused(self) -> None:
        second = run(self.world, decision_id=uid(9101))
        before = self.rows()
        with self.assertRaises(ConflictingDuplicateError):
            self.commit(outcome=second)
        self.assertEqual(self.rows(), before)


class TestStaleParent(CommitCase):
    def test_a_commit_whose_parent_is_no_longer_current_loses(self) -> None:
        # candidate A promotes; candidate B, built from the same parent, then tries
        winner = self.commit(outcome=run(self.world))
        assert winner.state is not None
        other, evidence = self.rival()
        result = self.commit(
            other, outcome=run(other, decision_id=uid(9200)), evidence_ids=evidence
        )
        self.assertTrue(result.stale)
        self.assertIsNone(result.state)
        self.assertIs(result.decision.decision, D.REJECT)
        self.assertIs(result.decision.reason, R.STALE_PARENT)
        self.assertIsNone(result.decision.committed_state_id)
        self.assertEqual(self.candidate_status(other.candidate.candidate_id), "REJECTED")
        self.assertEqual(self.current().state_id, winner.state.state_id)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(self.count("promotion_decisions", "committed_state_id IS NOT NULL"), 1)

    def test_a_loser_is_not_committed_twice(self) -> None:
        self.commit(outcome=run(self.world))
        other, evidence = self.rival()
        outcome = run(other, decision_id=uid(9200))
        first = self.commit(other, outcome=outcome, evidence_ids=evidence)
        again = self.commit(other, outcome=outcome, evidence_ids=evidence)
        self.assertTrue(first.stale and again.stale)
        self.assertEqual(self.count("promotion_decisions", "decision = 'REJECT'"), 1)
        self.assertEqual(self.candidate_status(other.candidate.candidate_id), "REJECTED")


class TestRevalidation(CommitCase):
    """C-167 and C-164: a decision that no longer holds, or evidence that does not bind, rolls the
    commit back and escalates the candidate (C-38 case 2)."""

    def setUp(self) -> None:
        super().setUp()
        self.outcome = run(self.world)

    def assert_escalated(self, result: Any) -> None:
        self.assertTrue(result.escalated)
        self.assertIsNone(result.state)
        self.assertEqual(self.candidate_status(), "ESCALATED")
        self.assertEqual(self.current().state_id, self.world.trusted.state_id)
        self.assertEqual(self.count("trusted_states"), 1)
        self.assertEqual(self.count("evidence_events", "event_name = 'promotion.committed'"), 0)
        self.assertEqual(self.count("audit_events", "event_type = 'STATE_PROMOTED'"), 0)
        self.assertEqual(self.count("promotion_decisions", "committed_state_id IS NOT NULL"), 0)
        self.assertEqual(self.count("audit_events", "event_type = 'PROMOTION_FAILED'"), 1)
        with self.uow() as u:
            (failed,) = (
                e
                for e in u.audit.list_for_candidate(self.world.candidate.candidate_id)
                if e.event_type is AE.PROMOTION_FAILED
            )
            payload = u.evidence.resolve(ArtifactRef.parse(failed.payload_ref))
        self.assertTrue(payload["reason"].startswith("REVALIDATION"))

    def test_a_verification_report_that_changed_since_the_decision(self) -> None:
        changed = make_world(candidate_status=CS.PROMOTABLE, results={target(FUNC1): FAIL})
        result = self.commit(
            dataclasses.replace(self.world, verification=changed.verification),
            outcome=self.outcome,
        )
        self.assert_escalated(result)

    def test_a_policy_that_changed_since_the_decision(self) -> None:
        stricter = self.world.with_policy(carry_forward_enabled=False)
        self.assert_escalated(self.commit(stricter, outcome=self.outcome))

    def test_an_impact_report_of_another_candidate(self) -> None:
        from tests.domain_builders import analyzing_candidate, canonical_resources
        from tests.promotion_builders import impact_for

        elsewhere = analyzing_candidate(
            self.world.trusted, canonical_resources(ssh_open=False, db_path=True), n=3
        )
        impact = impact_for(
            self.world.trusted, elsewhere, affected=(SEC1, FUNC1), carry=(SEC2, SEC3)
        )
        self.assert_escalated(
            self.commit(dataclasses.replace(self.world, impact=impact), outcome=self.outcome)
        )

    def test_a_source_evidence_record_with_a_tampered_payload(self) -> None:
        verified = next(e for e in self.outcome.proof_plan if e.source is ProofSource.VERIFIED)
        evidence_id = self.evidence_ids[verified.verification_id or ""]
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json = '{\"tampered\":true}' WHERE content_hash "
            "= (SELECT content_hash FROM evidence_events WHERE evidence_id = ?)",
            (evidence_id,),
        )
        self.assert_escalated(self.commit(outcome=self.outcome))

    def test_a_source_evidence_record_with_another_state_hash(self) -> None:
        verified = next(e for e in self.outcome.proof_plan if e.source is ProofSource.VERIFIED)
        evidence_id = self.evidence_ids[verified.verification_id or ""]
        self.tamper(
            "UPDATE evidence_events SET state_hash = ? WHERE evidence_id = ?",
            ("1" * 64, evidence_id),
        )
        self.assert_escalated(self.commit(outcome=self.outcome))

    def test_a_source_evidence_record_that_is_missing_from_the_map(self) -> None:
        verified = next(e for e in self.outcome.proof_plan if e.source is ProofSource.VERIFIED)
        partial = {k: v for k, v in self.evidence_ids.items() if k != verified.verification_id}
        self.assert_escalated(self.commit(outcome=self.outcome, evidence_ids=partial))

    def test_a_source_evidence_record_of_another_invariant(self) -> None:
        sec = next(e for e in self.outcome.proof_plan if e.invariant_id == SEC1)
        func = next(e for e in self.outcome.proof_plan if e.invariant_id == FUNC1)
        swapped = dict(self.evidence_ids)
        swapped[sec.verification_id or ""] = self.evidence_ids[func.verification_id or ""]
        self.assert_escalated(self.commit(outcome=self.outcome, evidence_ids=swapped))

    def test_a_carried_reference_whose_parent_evidence_is_not_bound_to_the_parent(self) -> None:
        carried = next(
            e for e in self.outcome.proof_plan if e.source is ProofSource.CARRIED_FORWARD
        )
        evidence_id = carried.evidence_ids[0]
        self.tamper(
            "UPDATE evidence_events SET state_hash = ? WHERE evidence_id = ?",
            ("2" * 64, evidence_id),
        )
        self.assert_escalated(self.commit(outcome=self.outcome))

    def test_a_carried_reference_whose_evidence_is_not_the_one_decided_on(self) -> None:
        # The decision was made against a copy of v0 whose INV-SEC-002 reference named other
        # evidence (the state hash does not depend on evidence ids, C-33). The database's v0 names
        # the stored seed evidence, so deciding again gives the same decision on a different proof
        # plan: what was decided is not what would be committed (C-167).
        data = self.world.trusted.to_dict()
        for ref in data["invariant_refs"]:
            if ref["invariant_id"] == SEC2:
                ref["evidence_ids"] = [uid(4300)]
        data["evidence_refs"] = sorted({*data["evidence_refs"], uid(4300)})
        decided_on = TrustedState.from_dict(data)
        outcome = run(dataclasses.replace(self.world, trusted=decided_on))
        self.assertIs(outcome.decision.decision, D.PROMOTE)
        again = run(self.world, decision_id=outcome.decision.decision_id)
        self.assertEqual(outcome.decision.content_hash, again.decision.content_hash)
        self.assertNotEqual(outcome.proof_plan, again.proof_plan)
        self.assert_escalated(self.commit(outcome=outcome))

    def test_the_candidate_must_still_be_promotable(self) -> None:
        self.tamper(
            "UPDATE candidates SET status = 'ANALYZING' WHERE candidate_id = ?",
            (self.world.candidate.candidate_id,),
        )
        result = self.commit(outcome=self.outcome)
        self.assertTrue(result.escalated)
        self.assertEqual(self.count("trusted_states"), 1)


class TestInfrastructureFailure(CommitCase):
    def test_a_fault_leaves_the_previous_state_and_the_candidate_promotable(self) -> None:
        def hook(name: str) -> None:
            if name == "after_lineage_head_update":
                raise RuntimeError(name)

        with self.assertRaises(PromotionCommitError) as caught:
            self.commit(outcome=run(self.world), checkpoint=hook)
        self.assertIsInstance(caught.exception.__cause__, RuntimeError)
        self.assertEqual(self.current().state_id, self.world.trusted.state_id)
        self.assertEqual(self.candidate_status(), "PROMOTABLE")
        self.assertEqual(self.count("trusted_states"), 1)
        self.assertEqual(self.count("evidence_events", "event_name = 'promotion.committed'"), 0)
        self.assertEqual(self.count("audit_events", "event_type = 'STATE_PROMOTED'"), 0)

    def test_the_same_commit_then_succeeds_exactly_once(self) -> None:
        outcome = run(self.world)

        def hook(name: str) -> None:
            if name == "after_decision_commit":
                raise RuntimeError(name)

        with self.assertRaises(PromotionCommitError):
            self.commit(outcome=outcome, checkpoint=hook)
        again = self.commit(outcome=outcome)
        self.assertFalse(again.duplicate)
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(self.current().state_id, ids.state_id_for(DECISION))

    def test_a_failure_event_is_recorded_when_the_database_allows(self) -> None:
        def hook(name: str) -> None:
            if name == "after_trusted_state_insert":
                raise RuntimeError(name)

        with self.assertRaises(PromotionCommitError):
            self.commit(outcome=run(self.world), checkpoint=hook)
        with self.uow() as u:
            failed = [
                e
                for e in u.audit.list_for_candidate(self.world.candidate.candidate_id)
                if e.event_type is AE.PROMOTION_FAILED
            ]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].event_id, ids.failure_event_id_for(DECISION, "INFRASTRUCTURE"))


class _Spy:
    """A repository that logs each write call before it makes it."""

    WRITES = frozenset({"save", "append", "save_promoted", "save_transition", "commit"})

    def __init__(self, name: str, real: Any, log: list[str]) -> None:
        self._name = name
        self._real = real
        self._log = log

    def __getattr__(self, attr: str) -> Any:
        member = getattr(self._real, attr)
        if attr not in self.WRITES:
            return member

        def logged(*args: Any, **kwargs: Any) -> Any:
            detail = ""
            if self._name == "audit":
                detail = ":" + args[0].event_type.value
            elif self._name == "evidence":
                detail = ":" + args[0].event.event_name
            self._log.append(f"{self._name}.{attr}{detail}")
            return member(*args, **kwargs)

        return logged


class TestOrderOfWrites(CommitCase):
    """Appendix B, in the order of the commit: the decision, then its event, the binding record,
    the state with the lineage head, the decision committed to the state, the candidate PROMOTED,
    and last the STATE_PROMOTED event (nothing says the state is promoted before it is)."""

    def test_the_writes_are_made_in_the_order_of_the_commit(self) -> None:
        log: list[str] = []
        path = self.path

        class Watching(SqliteUnitOfWork):
            @property
            def trusted_states(self) -> Any:
                return _Spy("trusted_states", super().trusted_states, log)

            @property
            def candidates(self) -> Any:
                return _Spy("candidates", super().candidates, log)

            @property
            def decisions(self) -> Any:
                return _Spy("decisions", super().decisions, log)

            @property
            def evidence(self) -> Any:
                return _Spy("evidence", super().evidence, log)

            @property
            def audit(self) -> Any:
                return _Spy("audit", super().audit, log)

        self.commit(outcome=run(self.world), opener=lambda: Watching(path))
        self.assertEqual(
            log,
            [
                "decisions.save",
                "audit.append:PROMOTION_DECIDED",
                "evidence.append:promotion.committed",
                "trusted_states.save_promoted",
                "decisions.commit",
                "candidates.save_transition",
                "audit.append:STATE_PROMOTED",
            ],
        )


class TestChainOfCarryForward(CommitCase):
    """v1 to v2 (C-164): a reference carried from v1 is proved by v1's binding record."""

    def setUp(self) -> None:
        super().setUp()
        first = self.commit(outcome=run(self.world))
        assert first.state is not None
        self.v1 = first.state
        self.world2 = self.next_world(self.v1)
        self.store_candidate(self.world2, n=2, sequence=2)
        self.evidence_ids.update(self.store_results(self.world2, first=60))
        self.outcome2 = run(self.world2, decision_id=uid(9300))
        with self.uow() as u:
            record_decision(u, self.outcome2, self.world2.candidate, CONTEXT, now=NOW)

    def test_the_second_promotion_carries_from_the_first(self) -> None:
        self.assertIs(self.outcome2.decision.decision, D.PROMOTE)
        sources = {e.invariant_id: e.source for e in self.outcome2.proof_plan}
        self.assertEqual(sources[SEC1], ProofSource.CARRIED_FORWARD)
        result = self.commit(self.world2, outcome=self.outcome2)
        v2 = result.state
        assert v2 is not None
        self.assertEqual(v2.version, 2)
        self.assertEqual(v2.parent_state_id, self.v1.state_id)
        binding1 = ids.evidence_id_for(DECISION)
        binding2 = ids.evidence_id_for(uid(9300))
        for ref in v2.invariant_refs:
            self.assertIn(binding2, ref.evidence_ids)
        carried = next(r for r in v2.invariant_refs if r.invariant_id == SEC1)
        self.assertIn(binding1, carried.evidence_ids)  # the record that proved it at v1
        self.assertIs(carried.origin, ProofOrigin.CARRIED_FORWARD)

    def test_with_the_first_binding_record_bound_to_another_state_it_escalates(self) -> None:
        self.tamper(
            "UPDATE evidence_events SET state_id = ? WHERE evidence_id = ?",
            (self.world.trusted.state_id, ids.evidence_id_for(DECISION)),
        )
        result = self.commit(self.world2, outcome=self.outcome2)
        self.assertTrue(result.escalated)
        self.assertEqual(self.current().state_id, self.v1.state_id)

    def test_with_the_first_binding_record_tampered_it_escalates(self) -> None:
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json = '{\"x\":1}' WHERE content_hash = "
            "(SELECT content_hash FROM evidence_events WHERE evidence_id = ?)",
            (ids.evidence_id_for(DECISION),),
        )
        self.assertTrue(self.commit(self.world2, outcome=self.outcome2).escalated)

    def test_with_the_first_binding_record_with_another_state_hash_it_escalates(self) -> None:
        self.tamper(
            "UPDATE evidence_events SET state_hash = ? WHERE evidence_id = ?",
            ("3" * 64, ids.evidence_id_for(DECISION)),
        )
        self.assertTrue(self.commit(self.world2, outcome=self.outcome2).escalated)


class TestRecordDecisionContext(unittest.TestCase):
    def test_the_context_checks_its_ids(self) -> None:
        for field in ("run_id", "correlation_id", "operation_id", "attempt_id"):
            with self.subTest(field=field), self.assertRaises(DomainValidationError):
                PromotionContext(**{**dataclasses.asdict(CONTEXT), field: "not-a-uuid"})
        PromotionContext(**dataclasses.asdict(CONTEXT))
        self.assertTrue(callable(commit_promotion))


if __name__ == "__main__":
    unittest.main()
