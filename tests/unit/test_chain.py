"""The evidence chain and the checker that defines "complete" (P6c step 2; Doc 11 §12, §43, §44,
§51.3; Doc 06 §28; C-172).

HAND EXPECTATIONS (the order of C-172 and Doc 11 §51.3, not the code's output):

* a safe promotion: CANDIDATE_CREATED, IDENTITY_COMPLETED, DEPENDENCY_COMPLETED, IMPACT_COMPLETED,
  one VERIFICATION_COMPLETED per result, PROMOTION_DECIDED, PROMOTION_REQUESTED, STATE_PROMOTED;
  its candidate-bound evidence is STATE, IDENTITY, DEPENDENCY, IMPACT, then one VERIFICATION per
  result; a binding record is bound to the new state;
* a rejected candidate: the same up to PROMOTION_DECIDED, then CANDIDATE_REJECTED, and no
  STATE_PROMOTED;
* ``problems()`` is empty for both, and fires, with the name of the rule, for each rule of C-172
  that a hand-broken database violates: the order, a named record that is missing, an integrity
  failure, a record bound to the wrong candidate or hash, an incomplete decision, a promotion
  without STATE_PROMOTED or its binding record, a rejection with STATE_PROMOTED or without its
  outcome event, a stale decision whose parent is still current, a FAILED candidate without
  ERROR_OCCURRED.
"""

from __future__ import annotations

import unittest
from typing import Any

from core.application import ids as oids
from core.application.chain import describe_chain
from core.domain.audit import AuditEventType
from core.domain.enums import CandidateStatus, DecisionType
from core.domain.evidence import EvidenceKind
from core.domain.promotion import DecisionReason
from core.domain.state import CandidateState, fail_building, start_building
from core.promotion import ids as pids
from tests.domain_builders import patch_for, uid
from tests.identity_builders import NOW as PIPELINE_NOW
from tests.promotion_commit_builders import NOW
from tests.promotion_e2e_builders import SAFE, ChainCase, run_for

T = AuditEventType
K = EvidenceKind
PREFIX = [T.CANDIDATE_CREATED, T.IDENTITY_COMPLETED, T.DEPENDENCY_COMPLETED, T.IMPACT_COMPLETED]


def codes(problems: list[str]) -> set[str]:
    return {p.split(":", 1)[0] for p in problems}


class ChainReader(ChainCase):
    def chain(self, candidate_id: str) -> Any:
        with self.uow() as u:
            return describe_chain(u, candidate_id)

    def failed(self, *, with_error: bool) -> CandidateState:
        run = run_for(SAFE)
        self.install(run)
        trusted = run.trusted
        created = CandidateState.create(
            parent=trusted,
            patch=patch_for(trusted, n=21),
            candidate_sequence=5,
            now=PIPELINE_NOW,
            candidate_id=uid(3500),
        )
        building = start_building(created)
        failed = fail_building(building, "the configuration does not parse")
        with self.uow() as u:
            u.patches.save(patch_for(trusted, n=21))
            u.candidates.create(created)
            u.candidates.save_transition(building)
            u.candidates.save_transition(failed)
            self.recorder.emit(
                u,
                T.CANDIDATE_CREATED,
                event_id=oids.event_id_for(failed.candidate_id, 1, T.CANDIDATE_CREATED),
                payload={
                    "parent_state_id": trusted.state_id,
                    "patch_id": failed.patch_id,
                    "source": failed.source.value,
                },
                when=NOW,
                candidate_id=failed.candidate_id,
            )
            if with_error:
                self.recorder.record_error(
                    u,
                    stage="normalize",
                    error_type="ConstructionFailed",
                    detail={"status": "INVALID"},
                    attempt_number=1,
                    at=PIPELINE_NOW,
                    when=NOW,
                    candidate=failed,
                )
        return failed


class TestAGoodChain(ChainReader):
    def test_a_safe_promotion_is_complete_and_in_the_order_of_c_172(self) -> None:
        run = self.promoted_chain()
        chain = self.chain(run.candidate.candidate_id)
        n = len(run.verification.results)
        self.assertEqual(
            chain.event_types(),
            [e.value for e in PREFIX]
            + ["VERIFICATION_COMPLETED"] * n
            + ["PROMOTION_DECIDED", "PROMOTION_REQUESTED", "STATE_PROMOTED"],
        )
        self.assertEqual(
            chain.evidence_kinds(),
            ["STATE", "IDENTITY", "DEPENDENCY", "IMPACT"] + ["VERIFICATION"] * n,
        )
        self.assertEqual(chain.problems(), [])
        self.assertIsNotNone(chain.binding)
        assert chain.state is not None and chain.binding is not None
        self.assertEqual(chain.binding.state_id, chain.state.state_id)
        self.assertEqual(chain.binding.state_hash, chain.state.state_hash)
        self.assertIs(chain.candidate.status, CandidateStatus.PROMOTED)

    def test_a_rejected_candidate_is_complete_and_has_no_state_promoted(self) -> None:
        run = self.rejected_chain()
        chain = self.chain(run.candidate.candidate_id)
        n = len(run.verification.results)
        self.assertEqual(
            chain.event_types(),
            [e.value for e in PREFIX]
            + ["VERIFICATION_COMPLETED"] * n
            + ["PROMOTION_DECIDED", "CANDIDATE_REJECTED"],
        )
        self.assertEqual(chain.problems(), [])
        self.assertIsNone(chain.state)
        self.assertIs(chain.candidate.status, CandidateStatus.REJECTED)

    def test_an_unfinished_chain_has_no_problem_as_long_as_it_is_a_prefix(self) -> None:
        run = self.promoted_chain(fixture_id=SAFE)
        del run
        run2 = run_for(SAFE, candidate_id=uid(3998), sequence=2, patch_n=8)
        self.patch_numbers[run2.candidate.candidate_id] = 8
        self.store(run2, sequence=2, patch_n=8)
        self.emit_created(run2)
        for stage in ("state", "identity", "dependency"):
            self.record_stage(run2, stage)
        chain = self.chain(run2.candidate.candidate_id)
        self.assertIs(chain.candidate.status, CandidateStatus.ANALYZING)
        self.assertEqual(chain.problems(finished=False), [])
        self.assertTrue(chain.problems(finished=True))

    def test_an_unknown_candidate_is_a_problem(self) -> None:
        chain = self.chain(uid(123456))
        self.assertIn("UNREADABLE", codes(chain.problems()))


class TestARecordedError(ChainReader):
    """An error that was recorded and then recovered from is history, not a broken chain."""

    def error_after_the_end(self, run: Any) -> None:
        with self.uow() as u:
            self.recorder.record_error(
                u,
                stage="commit",
                error_type="InjectedFault",
                detail={"message": "a read after the promotion failed"},
                attempt_number=1,
                at=PIPELINE_NOW,
                when=NOW,
                candidate=run.candidate,
                evidence_id=oids.evidence_id_for(run.candidate.candidate_id, 1, "error", "k"),
                event_id=oids.event_id_for(run.candidate.candidate_id, 1, T.ERROR_OCCURRED, "k"),
            )

    def test_an_error_after_a_promotion_is_not_a_problem(self) -> None:
        run = self.promoted_chain()
        self.error_after_the_end(run)
        chain = self.chain(run.candidate.candidate_id)
        self.assertEqual(chain.event_types()[-2:], ["STATE_PROMOTED", "ERROR_OCCURRED"])
        self.assertEqual(chain.problems(), [])

    def test_an_error_after_a_rejection_is_not_a_problem(self) -> None:
        run = self.rejected_chain()
        self.error_after_the_end(run)
        self.assertEqual(self.chain(run.candidate.candidate_id).problems(), [])

    def test_a_failed_candidate_is_still_built_around_its_error(self) -> None:
        """The leniency stops at a FAILED candidate: without ERROR_OCCURRED it is a problem."""
        failed = self.failed(with_error=False)
        self.assertIn("ENDING", codes(self.chain(failed.candidate_id).problems()))


class TestTheOrder(ChainReader):
    def test_stages_recorded_out_of_order_are_found(self) -> None:
        run = run_for(SAFE)
        self.install(run)
        self.store(run)
        self.write_chain(run, order=("state", "impact", "identity", "dependency", "verification"))
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertIn("ORDER", codes(problems))

    def test_a_missing_stage_is_found(self) -> None:
        run = run_for(SAFE)
        self.install(run)
        self.store(run)
        self.write_chain(run, stages=("state", "identity", "impact", "verification"))
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertIn("ORDER", codes(problems))

    def test_a_missing_verification_is_found(self) -> None:
        run = run_for(SAFE)
        self.install(run)
        self.store(run)
        self.write_chain(run, stages=("state", "identity", "dependency", "impact"))
        self.assertIn("ORDER", codes(self.chain(run.candidate.candidate_id).problems()))

    def test_the_evidence_kinds_must_follow_the_stages(self) -> None:
        run = run_for(SAFE)
        self.install(run)
        self.store(run)
        self.write_chain(run, order=("identity", "state", "dependency", "impact", "verification"))
        self.assertIn("EVIDENCE-ORDER", codes(self.chain(run.candidate.candidate_id).problems()))


class TestNamedEvidence(ChainReader):
    def test_an_event_naming_a_record_that_does_not_exist_is_found(self) -> None:
        run = self.promoted_chain()
        identity = oids.evidence_id_for(run.candidate.candidate_id, 1, "identity")
        self.tamper("DELETE FROM evidence_events WHERE evidence_id = ?", (identity,))
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertIn("NAMED-EVIDENCE", codes(problems))

    def test_a_verification_record_no_event_names_is_found(self) -> None:
        run = self.promoted_chain()
        self.tamper(
            "DELETE FROM audit_events WHERE event_type = 'VERIFICATION_COMPLETED' "
            "AND rowid = (SELECT MIN(rowid) FROM audit_events "
            "WHERE event_type = 'VERIFICATION_COMPLETED')"
        )
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertTrue({"NAMED-EVIDENCE", "ORDER"} & codes(problems), problems)


class TestIntegrity(ChainReader):
    def test_a_tampered_payload_is_found(self) -> None:
        run = self.promoted_chain()
        impact = oids.evidence_id_for(run.candidate.candidate_id, 1, "impact")
        with self.uow() as u:
            row = u.evidence.get(impact)
        assert row is not None
        digest = row.content_hash
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json = ? WHERE content_hash = ?",
            ('{"tampered":true}', digest),
        )
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertIn("INTEGRITY", codes(problems))

    def test_a_missing_payload_is_found(self) -> None:
        run = self.promoted_chain()
        impact = oids.evidence_id_for(run.candidate.candidate_id, 1, "impact")
        with self.uow() as u:
            row = u.evidence.get(impact)
        assert row is not None
        self.tamper("DELETE FROM evidence_artifacts WHERE content_hash = ?", (row.content_hash,))
        self.assertIn("INTEGRITY", codes(self.chain(run.candidate.candidate_id).problems()))


class TestBinding(ChainReader):
    def test_a_record_with_another_state_hash_is_found(self) -> None:
        run = self.promoted_chain()
        identity = oids.evidence_id_for(run.candidate.candidate_id, 1, "identity")
        # the repository refuses a column that disagrees with the stored record (DATA-INT-010), so
        # the column and the record are changed together, as an attacker with file access would
        self.tamper(
            "UPDATE evidence_events SET state_hash = ?, "
            "content_json = json_set(content_json, '$.state_hash', ?) WHERE evidence_id = ?",
            ("c" * 64, "c" * 64, identity),
        )
        self.assertIn("BINDING", codes(self.chain(run.candidate.candidate_id).problems()))

    def test_a_record_with_another_parent_is_found(self) -> None:
        run = self.promoted_chain()
        dependency = oids.evidence_id_for(run.candidate.candidate_id, 1, "dependency")
        self.tamper(
            "UPDATE evidence_events SET parent_state_id = ?, "
            "content_json = json_set(content_json, '$.parent_state_id', ?) WHERE evidence_id = ?",
            (run.candidate.candidate_id, run.candidate.candidate_id, dependency),
        )
        self.assertIn("BINDING", codes(self.chain(run.candidate.candidate_id).problems()))


class TestTheDecisionRow(ChainReader):
    def test_a_terminal_candidate_without_a_decision_is_found(self) -> None:
        run = self.rejected_chain()
        self.tamper("DELETE FROM promotion_decisions")
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertIn("DECISION", codes(problems))

    def test_a_decision_supported_by_a_result_that_is_not_in_the_chain_is_found(self) -> None:
        run = self.rejected_chain()
        did = oids.decision_id_for(run.candidate.candidate_id, 1)
        with self.uow() as u:
            row = u.decisions.get(did)
        assert row is not None
        # a result id that no VERIFICATION record of the candidate carries
        stray = uid(7777777)
        self.tamper(
            "UPDATE promotion_decisions SET supporting_results_json = ?, content_hash = ? "
            "WHERE decision_id = ?",
            self.with_supporting(row, [stray]),
        )
        self.assertIn("DECISION", codes(self.chain(run.candidate.candidate_id).problems()))

    def with_supporting(self, row: Any, supporting: list[str]) -> tuple[Any, ...]:
        """The SQL parameters that give ``row`` another list of supporting results, with the hash
        the domain computes for that content (so the row still reads back)."""
        import json

        from core.domain.promotion import PromotionDecision

        changed = PromotionDecision.create(
            decision_id=row.decision_id,
            candidate_id=row.candidate_id,
            parent_state_id=row.parent_state_id,
            decision=row.decision,
            reason=row.reason,
            policy_version=row.policy_version,
            attempt_number=row.attempt_number,
            required_checks=row.required_checks,
            blocking_conditions=row.blocking_conditions,
            supporting_results=supporting,
            created_at=row.created_at,
        )
        return (json.dumps(list(supporting)), changed.content_hash, row.decision_id)

    def test_a_decision_with_a_required_check_outside_its_supporting_results_is_found(
        self,
    ) -> None:
        run = self.rejected_chain()
        did = oids.decision_id_for(run.candidate.candidate_id, 1)
        with self.uow() as u:
            row = u.decisions.get(did)
        assert row is not None
        # keep the rows consistent with their hash, but drop the supporting results
        self.tamper(
            "UPDATE promotion_decisions SET supporting_results_json = ?, content_hash = ? "
            "WHERE decision_id = ?",
            self.with_supporting(row, []),
        )
        self.assertIn("DECISION", codes(self.chain(run.candidate.candidate_id).problems()))


class TestTheEnding(ChainReader):
    def test_a_promotion_without_state_promoted_is_found(self) -> None:
        run = self.promoted_chain()
        self.tamper("DELETE FROM audit_events WHERE event_type = 'STATE_PROMOTED'")
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertIn("ENDING", codes(problems))

    def test_a_promotion_without_its_binding_record_is_found(self) -> None:
        run = self.promoted_chain()
        with self.uow() as u:
            did = u.decisions.for_candidate(run.candidate.candidate_id)[0].decision_id
        self.tamper(
            "DELETE FROM evidence_events WHERE evidence_id = ?", (pids.evidence_id_for(did),)
        )
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertIn("PROMOTED-STATE", codes(problems))

    def test_a_binding_record_for_another_state_hash_is_found(self) -> None:
        run = self.promoted_chain()
        with self.uow() as u:
            did = u.decisions.for_candidate(run.candidate.candidate_id)[0].decision_id
        self.tamper(
            "UPDATE evidence_events SET state_hash = ? WHERE evidence_id = ?",
            ("d" * 64, pids.evidence_id_for(did)),
        )
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertIn("PROMOTED-STATE", codes(problems))

    def test_a_rejection_without_its_outcome_event_is_found(self) -> None:
        run = self.rejected_chain()
        self.tamper("DELETE FROM audit_events WHERE event_type = 'CANDIDATE_REJECTED'")
        self.assertIn("ENDING", codes(self.chain(run.candidate.candidate_id).problems()))

    def test_a_rejection_with_a_state_promoted_event_is_found(self) -> None:
        run = self.rejected_chain()
        with self.uow() as u:
            decision = u.decisions.for_candidate(run.candidate.candidate_id)[0]
            self.recorder.emit(
                u,
                T.STATE_PROMOTED,
                event_id=uid(8881),
                payload={"parent_state_id": run.trusted.state_id},
                when=NOW,
                state_id=run.trusted.state_id,
                candidate_id=run.candidate.candidate_id,
                decision_id=decision.decision_id,
            )
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertTrue({"ENDING", "ORDER"} & codes(problems), problems)

    def test_a_candidate_marked_promoted_without_a_committed_decision_is_found(self) -> None:
        run = self.promoted_chain()
        self.tamper("UPDATE promotion_decisions SET committed_state_id = NULL")
        problems = self.chain(run.candidate.candidate_id).problems()
        self.assertIn("DECISION", codes(problems) | codes(self.chain_problems_unfinished(run)))

    def chain_problems_unfinished(self, run: Any) -> list[str]:
        return self.chain(run.candidate.candidate_id).problems(finished=False)


class TestAStaleChain(ChainReader):
    def stale(self) -> Any:
        first = self.promoted_chain()
        second = self.second_candidate()
        self.write_chain(second)
        return first, second

    def test_a_stale_candidate_ends_with_a_stale_parent_rejection(self) -> None:
        _, second = self.stale()
        chain = self.chain(second.candidate.candidate_id)
        self.assertEqual(chain.problems(), [])
        self.assertIs(chain.candidate.status, CandidateStatus.REJECTED)
        [decision] = [d for d in chain.decisions if d.reason is DecisionReason.STALE_PARENT]
        self.assertIs(decision.decision, DecisionType.REJECT)
        self.assertEqual(chain.event_types()[-2:], ["PROMOTION_DECIDED", "CANDIDATE_REJECTED"])

    def test_a_stale_rejection_whose_parent_is_still_current_is_found(self) -> None:
        """REJECT/STALE_PARENT is stored for a candidate of the current state: not stale."""
        run = run_for(SAFE)
        self.install(run)
        self.store(run)
        self.emit_created(run)
        for stage in ("state", "identity", "dependency", "impact", "verification"):
            self.record_stage(run, stage)
        from core.promotion.commit import record_decision
        from core.promotion.decide import decide
        from tests.promotion_commit_builders import CONTEXT

        outcome = decide(
            run.candidate,
            run.newer_trusted(),  # another state of the lineage: the candidate is stale for decide
            run.impact,
            run.verification,
            run.policy(),
            decision_id=oids.decision_id_for(run.candidate.candidate_id, 1),
            now=PIPELINE_NOW,
        )
        self.assertIs(outcome.decision.reason, DecisionReason.STALE_PARENT)
        with self.uow() as u:
            record_decision(u, outcome, run.candidate, CONTEXT, now=NOW)
        # nothing was promoted: the candidate's parent is still the lineage head
        self.assertIn("STALE", codes(self.chain(run.candidate.candidate_id).problems()))


class TestAFailedCandidate(ChainReader):
    def test_a_failed_candidate_with_its_error_record_is_complete(self) -> None:
        failed = self.failed(with_error=True)
        chain = self.chain(failed.candidate_id)
        self.assertEqual(chain.event_types(), ["CANDIDATE_CREATED", "ERROR_OCCURRED"])
        self.assertEqual(chain.problems(), [])
        self.assertEqual(chain.decisions, ())
        self.assertIsNone(chain.state)

    def test_a_failed_candidate_without_error_occurred_is_found(self) -> None:
        failed = self.failed(with_error=False)
        problems = self.chain(failed.candidate_id).problems()
        self.assertIn("ENDING", codes(problems))


class TestTheChainReadsOnlyThisCandidate(ChainReader):
    def test_another_candidates_records_are_not_in_the_chain(self) -> None:
        first = self.promoted_chain()
        second = self.second_candidate()
        self.write_chain(second)
        one = self.chain(first.candidate.candidate_id)
        two = self.chain(second.candidate.candidate_id)
        self.assertTrue(all(e.candidate_id == first.candidate.candidate_id for e in one.evidence))
        self.assertTrue(all(e.candidate_id == second.candidate.candidate_id for e in two.evidence))
        self.assertTrue(
            {K.STATE, K.IDENTITY, K.DEPENDENCY, K.IMPACT, K.VERIFICATION}
            >= {e.kind for e in one.evidence}
        )


if __name__ == "__main__":
    unittest.main()
