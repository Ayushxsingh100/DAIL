"""The canonical transitions through the database (P6b step 6; Doc 06 §25, §26; Doc 09 §33, §34;
Doc 12 §5-§7, §19; C-22, C-45, C-52, C-164).

The real P6a pipeline (normalisation, identity, graphs, impact, scope policy, verification engine,
``decide``) runs on the canonical fixtures; the run is stored in SQLite and committed by
``commit_promotion``. Nothing here edits a fixture or computes an expected decision.

HAND EXPECTATIONS (CLAUDE.md, the three canonical fixtures, the P6b prompt):

* ``canonical_safe_repair_promote_v1``: v0 has public SSH open (INV-SEC-001 VIOLATED); the repair
  closes it and keeps EC2 -> RDS 5432. It is promoted into version 1, parent v0, with INV-SEC-001
  VERIFIED (a VIOLATED reference cannot be carried), INV-SEC-003 CARRIED_FORWARD from v0, and every
  reference PROTECTED. Every reference of v1 carries the binding record, and the binding record is
  proof for v1 (``usable_as_proof``) while the evidence of the sources is not: a candidate's
  evidence is valid for the candidate, and v0's evidence for v0 (C-52, C-164).
* ``canonical_security_repair_breaks_function_reject_v1``: fixes SSH and breaks the database path.
  The decision is REJECT, stored with its blocking condition; the candidate is REJECTED; v0 is still
  current and no state exists. A second candidate from v0 (the safe repair) then promotes (Doc 06
  §25-§26). A REJECT cannot be committed.
* ``ec2_rds_5432_pass_v1`` from v1 (its parent directory is the safe repair): promoted into
  version 2; what the impact report leaves unaffected is carried forward from v1 through v1's
  binding record, so those references carry both binding records.
* With the Stateful-Full policy every invariant is verified again: nothing is carried forward.
"""

from __future__ import annotations

import unittest
from functools import cache
from typing import Any

from core.domain.enums import CandidateStatus, DecisionType, InvariantStatus, ProofOrigin
from core.domain.evidence import EvidenceContext
from core.domain.promotion import PromotionInputError, ProofSource
from core.promotion import ids
from core.promotion.commit import commit_promotion
from evidence.service import EvidenceService
from tests.domain_builders import uid
from tests.promotion_commit_builders import CONTEXT, NOW, check_database
from tests.promotion_pipeline import PipelineRun, fixtures_with_a_parent, pipeline
from tests.promotion_pipeline_commit import PipelineCommitCase

SAFE = "canonical_safe_repair_promote_v1"
REGRESSION = "canonical_security_repair_breaks_function_reject_v1"
NEXT = "ec2_rds_5432_pass_v1"
SEC1, SEC3, FUNC = "INV-SEC-001", "INV-SEC-003", "INV-FUNC-001"
D1, D2, D3 = uid(9301), uid(9302), uid(9303)
SECOND_CANDIDATE = uid(3998)


@cache
def run_of(fixture_id: str, *, stateful_full: bool = False) -> PipelineRun:
    return pipeline(fixtures_with_a_parent()[fixture_id], stateful_full=stateful_full)


class TestSafeRepair(PipelineCommitCase):
    def setUp(self) -> None:
        super().setUp()
        self.run = run_of(SAFE)
        self.install(self.run)
        self.evidence_ids = self.prepare(self.run)
        self.outcome, self.result = self.promote(self.run, self.evidence_ids, decision_id=D1)
        assert self.result is not None and self.result.state is not None
        self.v1 = self.result.state

    def usable(self, evidence_id: str, context: EvidenceContext) -> bool:
        with self.uow() as u:
            return EvidenceService().usable_as_proof(u, evidence_id, context).usable

    def test_the_safe_repair_becomes_version_one(self) -> None:
        self.assertIs(self.outcome.decision.decision, DecisionType.PROMOTE)
        self.assertEqual(self.v1.version, 1)
        self.assertEqual(self.v1.parent_state_id, self.run.trusted.state_id)
        self.assertEqual(self.v1.commit_decision_id, D1)
        self.assertEqual(self.v1.state_id, ids.state_id_for(D1))
        self.assertEqual(self.current(self.run), self.v1)
        self.assertEqual(self.status(self.run.candidate.candidate_id), "PROMOTED")
        self.assertEqual(self.v1.resources, self.run.candidate.resources)

    def test_ssh_is_verified_the_untouched_invariants_are_carried_and_all_are_protected(
        self,
    ) -> None:
        refs = {r.invariant_id: r for r in self.v1.invariant_refs}
        self.assertEqual(refs[SEC1].origin, ProofOrigin.VERIFIED)
        self.assertEqual(refs[SEC3].origin, ProofOrigin.CARRIED_FORWARD)
        for ref in refs.values():
            self.assertIs(ref.status, InvariantStatus.PROTECTED, ref.invariant_id)
        planned = {e.invariant_id: e.source for e in self.outcome.proof_plan}
        for invariant, ref in refs.items():
            expected = (
                ProofOrigin.VERIFIED
                if planned[invariant] is ProofSource.VERIFIED
                else ProofOrigin.CARRIED_FORWARD
            )
            self.assertIs(ref.origin, expected, invariant)

    def test_every_reference_carries_the_binding_record_and_it_is_proof_for_v1(self) -> None:
        binding = ids.evidence_id_for(D1)
        self.assertIn(binding, self.v1.evidence_refs)
        context = EvidenceContext.state(self.v1.state_id)
        for ref in self.v1.invariant_refs:
            self.assertIn(binding, ref.evidence_ids, ref.invariant_id)
        self.assertTrue(self.usable(binding, context))

    def test_the_evidence_of_the_sources_is_proof_only_where_it_was_produced(self) -> None:
        v1_context = EvidenceContext.state(self.v1.state_id)
        v0_context = EvidenceContext.state(self.run.trusted.state_id)
        candidate_context = EvidenceContext.candidate(self.run.candidate.candidate_id)
        for entry in self.outcome.proof_plan:
            if entry.source is ProofSource.VERIFIED:
                source = self.evidence_ids[entry.verification_id or ""]
                with self.subTest(invariant=entry.invariant_id, source="VERIFIED"):
                    self.assertTrue(self.usable(source, candidate_context))
                    self.assertFalse(self.usable(source, v1_context))
            else:
                for source in entry.evidence_ids:
                    with self.subTest(invariant=entry.invariant_id, source="CARRIED_FORWARD"):
                        self.assertTrue(self.usable(source, v0_context))
                        self.assertFalse(self.usable(source, v1_context))

    def test_the_database_holds_nothing_that_breaks_the_rules_of_promoted_history(self) -> None:
        self.assertEqual(check_database(self.path), [])
        self.assertEqual(self.count("audit_events", "event_type = 'STATE_PROMOTED'"), 1)

    def test_the_same_decision_again_is_the_same_state(self) -> None:
        again = commit_promotion(
            lambda: self.uow(),
            self.outcome,
            self.run.candidate,
            self.run.impact,
            self.run.verification,
            self.run.policy(),
            self.evidence_ids,
            CONTEXT,
            now=NOW,
        )
        self.assertTrue(again.duplicate)
        self.assertEqual(again.state, self.v1)

    def test_carrying_forward_from_v1_goes_through_the_binding_record(self) -> None:
        second = pipeline(
            fixtures_with_a_parent()[NEXT],
            parent_trusted=self.v1,
            candidate_id=SECOND_CANDIDATE,
            sequence=2,
            patch_n=8,
        )
        evidence = self.prepare(second, sequence=2, patch_n=8, first=40)
        outcome, result = self.promote(second, evidence, decision_id=D2)
        self.assertIs(outcome.decision.decision, DecisionType.PROMOTE)
        assert result is not None and result.state is not None
        v2 = result.state
        self.assertEqual((v2.version, v2.parent_state_id), (2, self.v1.state_id))
        carried = [e for e in outcome.proof_plan if e.source is ProofSource.CARRIED_FORWARD]
        self.assertTrue(carried, "the fixture should leave something unaffected")
        first_binding, second_binding = ids.evidence_id_for(D1), ids.evidence_id_for(D2)
        refs = {r.invariant_id: r for r in v2.invariant_refs}
        for ref in v2.invariant_refs:
            self.assertIn(second_binding, ref.evidence_ids, ref.invariant_id)
        for entry in carried:
            ref = refs[entry.invariant_id]
            with self.subTest(carried=entry.invariant_id):
                self.assertEqual(entry.source_state_id, self.v1.state_id)
                self.assertIn(first_binding, ref.evidence_ids)
                self.assertIs(ref.origin, ProofOrigin.CARRIED_FORWARD)
        self.assertTrue(self.usable(first_binding, EvidenceContext.state(self.v1.state_id)))
        self.assertTrue(self.usable(second_binding, EvidenceContext.state(v2.state_id)))
        self.assertEqual(self.current(second), v2)
        self.assertEqual(check_database(self.path), [])


class TestRegressionThenSafe(PipelineCommitCase):
    def test_the_regression_is_rejected_and_a_second_candidate_then_promotes(self) -> None:
        bad = run_of(REGRESSION)
        self.install(bad)
        evidence = self.prepare(bad)
        outcome, result = self.promote(bad, evidence, decision_id=D1)
        self.assertIs(outcome.decision.decision, DecisionType.REJECT)
        self.assertIsNone(result)
        self.assertEqual(self.status(bad.candidate.candidate_id), "REJECTED")
        self.assertEqual(self.current(bad), bad.trusted)  # v0 is still current
        self.assertEqual(self.count("trusted_states"), 1)
        with self.uow() as u:
            stored = u.decisions.get(D1)
        assert stored is not None
        self.assertEqual(stored, outcome.decision)
        self.assertEqual([c.target for c in stored.blocking_conditions], [f"INVARIANT:{FUNC}:1"])
        # a REJECT cannot be committed
        with self.assertRaises(PromotionInputError):
            commit_promotion(
                lambda: self.uow(),
                outcome,
                bad.candidate,
                bad.impact,
                bad.verification,
                bad.policy(),
                evidence,
                CONTEXT,
                now=NOW,
            )
        self.assertEqual(self.count("trusted_states"), 1)

        good = pipeline(
            fixtures_with_a_parent()[SAFE], candidate_id=SECOND_CANDIDATE, sequence=2, patch_n=8
        )
        # the same v0: same id and hash (the resource records are renormalised, with new record ids)
        self.assertEqual(
            (good.trusted.state_id, good.trusted.state_hash),
            (bad.trusted.state_id, bad.trusted.state_hash),
        )
        second = self.prepare(good, sequence=2, patch_n=8, first=40)
        outcome2, result2 = self.promote(good, second, decision_id=D2)
        self.assertIs(outcome2.decision.decision, DecisionType.PROMOTE)
        assert result2 is not None and result2.state is not None
        self.assertEqual(result2.state.version, 1)
        self.assertEqual(result2.state.parent_state_id, bad.trusted.state_id)
        self.assertEqual(self.status(bad.candidate.candidate_id), "REJECTED")
        self.assertEqual(self.status(SECOND_CANDIDATE), "PROMOTED")
        self.assertEqual(self.count("trusted_states"), 2)
        self.assertEqual(check_database(self.path), [])


class TestStatefulFull(PipelineCommitCase):
    def test_nothing_is_carried_forward_and_every_reference_is_verified(self) -> None:
        run = run_of(SAFE, stateful_full=True)
        self.install(run)
        evidence = self.prepare(run)
        outcome, result = self.promote(run, evidence, decision_id=D3, stateful_full=True)
        self.assertIs(outcome.decision.decision, DecisionType.PROMOTE)
        assert result is not None and result.state is not None
        origins = {r.origin for r in result.state.invariant_refs}
        self.assertEqual(origins, {ProofOrigin.VERIFIED})
        self.assertEqual(len(result.state.invariant_refs), 4)
        binding = ids.evidence_id_for(D3)
        for ref in result.state.invariant_refs:
            self.assertEqual(
                len(ref.evidence_ids), 2, ref.invariant_id
            )  # the source and the record
            self.assertIn(binding, ref.evidence_ids)
        self.assertEqual(check_database(self.path), [])


class TestTheRunsAreStillTheRunsOfP6a(unittest.TestCase):
    """The helper change of this package leaves the P6a behaviour alone."""

    def test_the_default_candidate_is_the_one_of_p6a(self) -> None:
        from tests.pipeline_builders import CANDIDATE_STATE, PARENT_STATE

        run = run_of(SAFE)
        self.assertEqual(run.candidate.candidate_id, CANDIDATE_STATE)
        self.assertEqual(run.trusted.state_id, PARENT_STATE)
        self.assertIs(run.candidate.status, CandidateStatus.ANALYZING)
        self.assertEqual(run.decide().decision.decision_id, uid(9300))

    def test_arguments_are_not_shared_between_runs(self) -> None:
        other: Any = pipeline(
            fixtures_with_a_parent()[SAFE], candidate_id=SECOND_CANDIDATE, sequence=2, patch_n=8
        )
        self.assertNotEqual(other.candidate.candidate_id, run_of(SAFE).candidate.candidate_id)


if __name__ == "__main__":
    unittest.main()
