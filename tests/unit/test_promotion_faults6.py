"""Faults in the middle of a promotion (P6b step 6; Doc 12 §19; Doc 09 §26, §41 "DB commit failure";
Doc 06 §27; C-38 cases 2 and 3, C-163, C-165).

HAND EXPECTATIONS, written before the run. A promotion that fails anywhere before the commit point
leaves the previous state current and nothing of the attempt behind (Doc 06 §27: "no new current
Trusted State"; Doc 09 §26: one transaction):

* injected at each of the seven checkpoints of the unit of work, at the STATE_PROMOTED audit append
  and at the binding-record append: ``PromotionCommitError`` (case 3), caused by the injected fault;
  read from a new connection, the head is still v0, no state, reference, resource, binding record,
  STATE_PROMOTED event or committed decision of the attempt exists, the candidate is PROMOTABLE, the
  only new row is the best-effort PROMOTION_FAILED event, and the same commit then succeeds once
  with exactly one new state;
* when the decision had been recorded before, its row (uncommitted) is still there; when it had
  not, its row is gone with the rolled-back transaction;
* when even the failure event cannot be written, nothing is recorded and the caller still gets
  ``PromotionCommitError``;
* evidence that does not bind (a tampered payload, a wrong ``state_hash``, a record produced for
  another candidate) and a report whose hash no longer recomputes are revalidation failures (case
  2): the candidate is ESCALATED, PROMOTION_FAILED and ESCALATED are appended, nothing of the new
  state exists, and a second attempt changes nothing.
"""

from __future__ import annotations

import dataclasses
import unittest
from typing import Any

from core.domain.audit import AuditEventType as AE
from core.domain.enums import CandidateStatus
from core.domain.promotion import ProofSource
from core.persistence.sqlite import ALL_CHECKPOINTS, SqliteUnitOfWork
from core.promotion import ids
from core.promotion.commit import PromotionCommitError, record_decision
from tests.domain_builders import uid
from tests.promotion_builders import SEC1, run
from tests.promotion_commit_builders import (
    CONTEXT,
    NOW,
    CommitCase,
    InjectedFault,
    check_database,
)

DECISION = uid(9100)
AUDIT_APPEND = "audit_append"
BINDING_APPEND = "binding_append"
POINTS = (*ALL_CHECKPOINTS, AUDIT_APPEND, BINDING_APPEND)
TABLES = (
    "trusted_states",
    "lineage_heads",
    "invariant_refs",
    "state_resources",
    "resources",
    "promotion_decisions",
    "candidates",
    "evidence_events",
    "evidence_artifacts",
)


class _Breaking:
    """A repository whose ``append`` raises for the submissions ``match`` selects."""

    def __init__(self, real: Any, match: Any) -> None:
        self._real = real
        self._match = match

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def append(self, submission: Any) -> Any:
        if self._match(submission):
            raise InjectedFault("append")
        return self._real.append(submission)


class BreakingUnitOfWork(SqliteUnitOfWork):
    """A unit of work whose audit append of STATE_PROMOTED, or whose append of the binding record,
    fails."""

    def __init__(self, path: Any, *, audit: bool = False, binding: bool = False) -> None:
        super().__init__(path)
        self._break_audit = audit
        self._break_binding = binding

    @property
    def audit(self) -> Any:
        real = super().audit
        if not self._break_audit:
            return real
        return _Breaking(real, lambda s: s.event_type is AE.STATE_PROMOTED)

    @property
    def evidence(self) -> Any:
        real = super().evidence
        if not self._break_binding:
            return real
        return _Breaking(real, lambda s: s.event.event_name == "promotion.committed")


class FaultBase(CommitCase):
    recorded = False

    def setUp(self) -> None:
        super().setUp()
        self.outcome = run(self.world)
        if self.recorded:
            with self.uow() as u:
                record_decision(u, self.outcome, self.world.candidate, CONTEXT, now=NOW)

    def rows(self) -> dict[str, int]:
        return {table: self.count(table) for table in TABLES}

    def audit_ids(self) -> set[str]:
        with self.uow() as u:
            return {
                e.event_id for e in u.audit.list_for_candidate(self.world.candidate.candidate_id)
            }

    def attempt(self, point: str) -> BaseException:
        """Commit with a fault injected at ``point``; return the error the caller gets."""
        if point in (AUDIT_APPEND, BINDING_APPEND):
            path = self.path
            opened: list[int] = []

            def opener() -> Any:
                opened.append(1)  # the first unit of work is the commit; later ones are honest
                return BreakingUnitOfWork(
                    path,
                    audit=point == AUDIT_APPEND and len(opened) == 1,
                    binding=point == BINDING_APPEND and len(opened) == 1,
                )

            with self.assertRaises(PromotionCommitError) as caught:
                self.commit(outcome=self.outcome, opener=opener)
        else:

            fired: list[str] = []

            def hook(name: str) -> None:
                if name == point and not fired:
                    fired.append(name)
                    raise InjectedFault(name)

            with self.assertRaises(PromotionCommitError) as caught:
                self.commit(outcome=self.outcome, checkpoint=hook)
            self.assertEqual(fired, [point], f"{point} was never reached")
        return caught.exception

    def inject(self, point: str) -> dict[str, Any]:
        """Inject a fault at ``point``, check what is left and retry; return the row of the report's
        table."""
        before = self.rows()
        events_before = self.audit_ids()
        error = self.attempt(point)
        self.assertIsInstance(error.__cause__, InjectedFault)
        after = self.rows()
        left = {
            "head": "v0" if self.current().state_id == self.world.trusted.state_id else "MOVED",
            "candidate": self.candidate_status(),
            "rows_changed": {t: (before[t], after[t]) for t in TABLES if before[t] != after[t]},
            "new_events": sorted(self.audit_ids() - events_before),
            "committed_decisions": self.count(
                "promotion_decisions", "committed_state_id IS NOT NULL"
            ),
            "binding_records": self.count("evidence_events", "event_name = 'promotion.committed'"),
            "state_promoted_events": self.count("audit_events", "event_type = 'STATE_PROMOTED'"),
        }
        retry = self.commit(outcome=self.outcome)
        left["retry"] = (
            "one new state" if retry.state is not None and not retry.duplicate else "FAILED"
        )
        left["states_after_retry"] = self.count("trusted_states")
        return left

    def check(self, point: str) -> None:
        before = self.rows()
        left = self.inject(point)
        self.assertEqual(left["head"], "v0")
        self.assertEqual(left["candidate"], "PROMOTABLE")
        self.assertEqual(left["committed_decisions"], 0)
        self.assertEqual(left["binding_records"], 0)
        self.assertEqual(left["state_promoted_events"], 0)
        self.assertEqual(left["new_events"], [ids.failure_event_id_for(DECISION, "INFRASTRUCTURE")])
        # the only new row is the payload of the PROMOTION_FAILED event (audit payloads are stored
        # as content-addressed artifacts); the event itself is in audit_events, checked above
        changed = left["rows_changed"]
        self.assertEqual(set(changed), {"evidence_artifacts"}, "the attempt left rows behind")
        self.assertEqual(changed["evidence_artifacts"][1], changed["evidence_artifacts"][0] + 1)
        self.assertEqual(before["promotion_decisions"], 1 if self.recorded else 0)
        self.assertEqual(left["retry"], "one new state")
        self.assertEqual(left["states_after_retry"], 2)
        self.assertEqual(self.count("audit_events", "event_type = 'STATE_PROMOTED'"), 1)
        self.assertEqual(check_database(self.path), [])


class TestFaultsBeforeTheDecisionWasRecorded(FaultBase):
    def test_every_point_leaves_nothing_and_the_retry_works(self) -> None:
        for index, point in enumerate(POINTS):
            with self.subTest(point=point):
                if index:
                    self.tearDown()
                    self.setUp()
                self.check(point)


class TestFaultsAfterTheDecisionWasRecorded(FaultBase):
    recorded = True
    stored_status = CandidateStatus.ANALYZING

    def test_every_point_the_commit_reaches_leaves_nothing_and_the_retry_works(self) -> None:
        for index, point in enumerate(p for p in POINTS if p != "after_decision_insert"):
            with self.subTest(point=point):
                if index:
                    self.tearDown()
                    self.setUp()
                self.check(point)

    def test_the_recorded_decision_row_survives_a_failed_commit(self) -> None:
        self.attempt("after_lineage_head_update")
        self.assertEqual(self.count("promotion_decisions"), 1)
        self.assertEqual(self.count("promotion_decisions", "committed_state_id IS NOT NULL"), 0)
        self.assertEqual(self.candidate_status(), "PROMOTABLE")


class TestEvenTheFailureEventFails(CommitCase):
    def test_nothing_is_recorded_and_the_caller_still_gets_the_error(self) -> None:
        outcome = run(self.world)
        before = {
            t: self.count(t) for t in ("audit_events", "trusted_states", "promotion_decisions")
        }

        def hook(name: str) -> None:
            raise InjectedFault(name)

        with self.assertRaises(PromotionCommitError) as caught:
            self.commit(outcome=outcome, checkpoint=hook)
        self.assertIsInstance(caught.exception.__cause__, InjectedFault)
        after = {t: self.count(t) for t in before}
        self.assertEqual(after, before)
        self.assertEqual(self.candidate_status(), "PROMOTABLE")
        self.assertFalse(self.commit(outcome=outcome).duplicate)


class TestRevalidationFailures(CommitCase):
    """C-38 case 2: the candidate is ESCALATED and nothing of the new state exists."""

    def setUp(self) -> None:
        super().setUp()
        self.outcome = run(self.world)
        self.before = {
            t: self.count(t)
            for t in ("trusted_states", "invariant_refs", "state_resources", "lineage_heads")
        }

    def sources(self, source: ProofSource) -> list[Any]:
        return [e for e in self.outcome.proof_plan if e.source is source]

    def assert_escalated(self, result: Any) -> None:
        self.assertTrue(result.escalated)
        self.assertIsNone(result.state)
        self.assertEqual(self.candidate_status(), "ESCALATED")
        self.assertEqual({t: self.count(t) for t in self.before}, self.before)
        self.assertEqual(self.count("evidence_events", "event_name = 'promotion.committed'"), 0)
        self.assertEqual(self.count("audit_events", "event_type = 'STATE_PROMOTED'"), 0)
        self.assertEqual(self.count("promotion_decisions", "committed_state_id IS NOT NULL"), 0)
        self.assertEqual(self.count("audit_events", "event_type = 'PROMOTION_FAILED'"), 1)
        self.assertEqual(self.count("audit_events", "event_type = 'ESCALATED'"), 1)
        # trying again changes nothing: the candidate is ESCALATED and stays so
        rows = (self.count("audit_events"), self.count("promotion_decisions"))
        again = self.commit(outcome=self.outcome)
        self.assertTrue(again.escalated)
        self.assertEqual((self.count("audit_events"), self.count("promotion_decisions")), rows)
        self.assertEqual(self.candidate_status(), "ESCALATED")
        self.assertEqual(check_database(self.path), [])

    def test_a_tampered_evidence_payload(self) -> None:
        evidence_id = self.evidence_ids[self.sources(ProofSource.VERIFIED)[0].verification_id or ""]
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json = '{\"x\":1}' WHERE content_hash = "
            "(SELECT content_hash FROM evidence_events WHERE evidence_id = ?)",
            (evidence_id,),
        )
        self.assert_escalated(self.commit(outcome=self.outcome))

    def test_a_wrong_state_hash_on_a_source_record(self) -> None:
        evidence_id = self.evidence_ids[self.sources(ProofSource.VERIFIED)[0].verification_id or ""]
        self.tamper(
            "UPDATE evidence_events SET state_hash = ? WHERE evidence_id = ?",
            ("5" * 64, evidence_id),
        )
        self.assert_escalated(self.commit(outcome=self.outcome))

    def test_a_source_record_produced_for_another_candidate(self) -> None:
        other, other_ids = self.rival()
        entry = next(e for e in self.sources(ProofSource.VERIFIED) if e.invariant_id == SEC1)
        theirs = next(
            r.verification_id
            for r in other.verification.results
            if r.target_id == f"INVARIANT:{SEC1}:1"
        )
        mapped = {**self.evidence_ids, entry.verification_id or "": other_ids[theirs]}
        self.assert_escalated(self.commit(outcome=self.outcome, evidence_ids=mapped))

    def test_a_verification_report_whose_hash_no_longer_recomputes(self) -> None:
        forged = dataclasses.replace(self.world.verification)
        object.__setattr__(forged, "content_hash", "0" * 64)
        self.assertNotEqual(forged.content_hash, forged.compute_hash())
        self.assert_escalated(
            self.commit(dataclasses.replace(self.world, verification=forged), outcome=self.outcome)
        )

    def test_an_impact_report_whose_hash_no_longer_recomputes(self) -> None:
        forged = dataclasses.replace(self.world.impact)
        object.__setattr__(forged, "content_hash", "0" * 64)
        self.assertNotEqual(forged.content_hash, forged.compute_hash())
        self.assert_escalated(
            self.commit(dataclasses.replace(self.world, impact=forged), outcome=self.outcome)
        )


if __name__ == "__main__":
    unittest.main()
