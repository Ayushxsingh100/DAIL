"""``decide()``: Doc 09 Appendix A, the decision matrix of §20 and §41, and C-157 to C-161 (P6a
step 4).

HAND DERIVATION, written before ``decide`` existed. The canonical world (see
``tests/promotion_builders.py``): the trusted state ``v0`` has INV-SEC-001 VIOLATED (public SSH is
open) and INV-SEC-002, INV-SEC-003 and INV-FUNC-001 PROTECTED. The candidate fixes SSH. The impact
report has INV-SEC-001 and INV-FUNC-001 affected and INV-SEC-002 and INV-SEC-003 unaffected with
eligible evidence; it also owes the baseline item of one created resource. Required (C-159): the
gate items STRUCTURAL and CONSISTENCY, the four invariants and the baseline item. A fresh L1 PASS
exists for every item that owes verification: the two gates, the two affected invariants and the
baseline item (five results). So:

    INV-SEC-001  VERIFIED (affected; its reference is VIOLATED, so it could not be carried anyway)
    INV-FUNC-001 VERIFIED (affected)
    INV-SEC-002  CARRIED_FORWARD (unaffected, PROTECTED, eligible, same version, policy allows it)
    INV-SEC-003  CARRIED_FORWARD (the same)
    decision PROMOTE, reason ALL_REQUIRED_PROVEN, supporting results = the five verification ids.

Each test below changes one thing and states what Appendix A, §20 or C-158 to C-161 then give. The
doc 09 §20 matrix: all PASS and parent current gives PROMOTE; any required FAIL gives REJECT; a
required UNKNOWN that a retry could resolve gives RETRY; UNSUPPORTED when mandatory gives REJECT
(§29); a verifier error that cannot be retried automatically gives ESCALATE; a stale parent gives
REJECT and never PROMOTE; a construction failure gives REJECT; an unresolved evidence conflict gives
ESCALATE or REJECT per policy, never PROMOTE.
"""

from __future__ import annotations

import ast
import dataclasses
import itertools
import random
import unittest
from pathlib import Path

from core.domain.enums import (
    CandidateStatus,
    DecisionType,
    InvariantStatus,
    VerificationResult,
)
from core.domain.errors import DomainValidationError
from core.domain.invariant import Invariant
from core.domain.promotion import (
    BlockingCondition,
    DecisionOutcome,
    DecisionReason,
    OracleVerdict,
    PromotionInputError,
    ProofSource,
)
from core.domain.state import TrustedState
from core.domain.verification import VerificationReason, VerificationReport
from core.promotion.decide import completeness_problems, fold
from core.promotion.policy import dail_policy, stateful_full_policy
from tests.domain_builders import analyzing_candidate, baseline, canonical_resources, uid
from tests.promotion_builders import (
    ALL,
    BASELINE_ITEM,
    ERROR,
    FAIL,
    FUNC1,
    PASS,
    SEC1,
    SEC2,
    SEC3,
    UNKNOWN,
    UNSUPPORTED,
    World,
    impact_for,
    make_world,
    record,
    report_of,
    run,
    target,
    trusted_state,
)

D, R = DecisionType, DecisionReason
ROOT = Path(__file__).resolve().parents[2]


def codes(outcome: DecisionOutcome) -> list[DecisionReason]:
    return [c.code for c in outcome.decision.blocking_conditions]


def sources(outcome: DecisionOutcome) -> dict[str, ProofSource]:
    return {e.invariant_id: e.source for e in outcome.proof_plan}


def decided(outcome: DecisionOutcome) -> tuple[DecisionType, DecisionReason]:
    return outcome.decision.decision, outcome.decision.reason


def definitions_with(world: World, **bumped: int) -> list[Invariant]:
    """The registry of the world with some invariants at a higher version."""
    out = []
    for invariant_id, definition in world.definitions.items():
        if invariant_id in bumped:
            for _ in range(bumped[invariant_id] - definition.version):
                definition = Invariant.new_version(definition, now=world.trusted.created_at)
        out.append(definition)
    return out


class TestAllRequiredProven(unittest.TestCase):
    def setUp(self) -> None:
        self.world = make_world()
        self.outcome = run(self.world)

    def test_the_canonical_safe_repair_is_promoted(self) -> None:
        self.assertEqual(decided(self.outcome), (D.PROMOTE, R.ALL_REQUIRED_PROVEN))
        self.assertEqual(self.outcome.decision.blocking_conditions, ())
        self.assertEqual(self.outcome.decision.attempt_number, 1)

    def test_the_decision_is_bound_to_the_candidate_the_parent_and_the_policy(self) -> None:
        decision = self.outcome.decision
        self.assertEqual(decision.candidate_id, self.world.candidate.candidate_id)
        self.assertEqual(decision.parent_state_id, self.world.candidate.parent_state_id)
        self.assertEqual(decision.parent_state_id, self.world.trusted.state_id)
        self.assertEqual(decision.policy_version, "policy-1")
        self.assertIsNone(decision.committed_state_id)

    def test_the_proof_plan_says_which_source_proves_each_invariant(self) -> None:
        self.assertEqual(
            sources(self.outcome),
            {
                SEC1: ProofSource.VERIFIED,
                FUNC1: ProofSource.VERIFIED,
                SEC2: ProofSource.CARRIED_FORWARD,
                SEC3: ProofSource.CARRIED_FORWARD,
            },
        )
        by_id = {e.invariant_id: e for e in self.outcome.proof_plan}
        self.assertEqual(
            by_id[SEC1].verification_id, self.world.records[target(SEC1)].verification_id
        )
        carried = by_id[SEC2]
        reference = next(r for r in self.world.trusted.invariant_refs if r.invariant_id == SEC2)
        self.assertIsNone(carried.verification_id)
        self.assertEqual(carried.source_state_id, self.world.trusted.state_id)
        self.assertEqual(carried.evidence_ids, reference.evidence_ids)
        self.assertEqual(
            [e.invariant_id for e in self.outcome.proof_plan], sorted(sources(self.outcome))
        )

    def test_a_promote_lists_every_verification_result_it_used(self) -> None:
        used = sorted(
            self.world.records[t].verification_id
            for t in (
                "STRUCTURAL",
                "CONSISTENCY",
                target(SEC1),
                target(FUNC1),
                BASELINE_ITEM,
            )
        )
        self.assertEqual(list(self.outcome.decision.supporting_results), used)
        self.assertEqual(list(self.outcome.evidence.verification_refs), used)
        # a carried-forward invariant has no result of this candidate to reference
        for carried in (SEC2, SEC3):
            self.assertNotIn(target(carried), self.world.records)

    def test_the_required_checks_name_every_gate_invariant_and_baseline_item(self) -> None:
        wanted = {
            "CONSISTENCY": ("GATE", ProofSource.VERIFIED),
            "STRUCTURAL": ("GATE", ProofSource.VERIFIED),
            target(FUNC1): ("INVARIANT", ProofSource.VERIFIED),
            target(SEC1): ("INVARIANT", ProofSource.VERIFIED),
            target(SEC2): ("INVARIANT", ProofSource.CARRIED_FORWARD),
            target(SEC3): ("INVARIANT", ProofSource.CARRIED_FORWARD),
            BASELINE_ITEM: ("BASELINE", ProofSource.VERIFIED),
        }
        got = {c.target_id: (c.kind, c.source) for c in self.outcome.decision.required_checks}
        self.assertEqual(got, wanted)
        self.assertEqual(
            [c.target_id for c in self.outcome.decision.required_checks], sorted(wanted)
        )

    def test_the_evidence_record_follows_doc_11_section_26(self) -> None:
        evidence = self.outcome.evidence
        self.assertEqual(evidence.decision_id, self.outcome.decision.decision_id)
        self.assertEqual(evidence.evidence_sufficiency, "SUFFICIENT")
        self.assertEqual((evidence.decision, evidence.reason), (D.PROMOTE, R.ALL_REQUIRED_PROVEN))
        self.assertEqual(evidence.required_checks, self.outcome.decision.required_checks)
        self.assertEqual(evidence.policy_version, "policy-1")
        self.assertIsNone(evidence.new_state_id)

    def test_a_promotable_candidate_may_be_decided_again(self) -> None:
        # P6b decides again at commit time, when the candidate is already PROMOTABLE
        world = make_world(candidate_status=CandidateStatus.PROMOTABLE)
        self.assertEqual(decided(run(world)), (D.PROMOTE, R.ALL_REQUIRED_PROVEN))


class TestStatefulFull(unittest.TestCase):
    """C-22: the same controller with carry-forward disabled."""

    def stateful(self, world: World) -> World:
        policy = stateful_full_policy(
            policy_version="policy-1",
            invariants=world.definitions.values(),
            automatic_enabled=True,
        )
        return dataclasses.replace(world, policy=policy)

    def test_nothing_is_carried_forward_and_unverified_invariants_have_no_proof(self) -> None:
        out = run(self.stateful(make_world()))
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))
        self.assertEqual(
            sorted(c.target for c in out.decision.blocking_conditions),
            [target(SEC2), target(SEC3)],
        )
        self.assertNotIn(ProofSource.CARRIED_FORWARD, sources(out).values())

    def test_when_everything_is_verified_again_it_promotes_with_no_carried_proof(self) -> None:
        world = make_world(affected=ALL, carry=())
        out = run(self.stateful(world))
        self.assertEqual(decided(out), (D.PROMOTE, R.ALL_REQUIRED_PROVEN))
        self.assertEqual(set(sources(out).values()), {ProofSource.VERIFIED})
        self.assertEqual(len(out.proof_plan), 4)


class TestAppendixAAndTheDecisionMatrix(unittest.TestCase):
    """Doc 09 §20 and §41, one row each."""

    def test_security_pass_and_functional_fail_is_rejected(self) -> None:
        out = run(make_world(results={target(FUNC1): FAIL}))
        self.assertEqual(decided(out), (D.REJECT, R.REQUIRED_CHECK_FAILED))
        self.assertEqual([c.target for c in out.decision.blocking_conditions], [target(FUNC1)])
        self.assertNotIn(FUNC1, sources(out))
        self.assertEqual(out.evidence.evidence_sufficiency, "INSUFFICIENT")

    def test_security_fail_and_functional_pass_is_rejected(self) -> None:
        out = run(make_world(results={target(SEC1): FAIL}))
        self.assertEqual(decided(out), (D.REJECT, R.REQUIRED_CHECK_FAILED))
        self.assertEqual([c.target for c in out.decision.blocking_conditions], [target(SEC1)])

    def test_both_failing_preserves_both_reasons(self) -> None:
        out = run(make_world(results={target(SEC1): FAIL, target(FUNC1): FAIL}))
        self.assertEqual(decided(out), (D.REJECT, R.REQUIRED_CHECK_FAILED))
        self.assertEqual(
            sorted(c.target for c in out.decision.blocking_conditions),
            [target(FUNC1), target(SEC1)],
        )

    def test_a_required_unknown_is_a_retry_and_never_a_promotion(self) -> None:
        out = run(make_world(results={target(FUNC1): UNKNOWN}))
        self.assertEqual(decided(out), (D.RETRY, R.REQUIRED_UNKNOWN))
        self.assertNotIn(FUNC1, sources(out))

    def test_a_mandatory_unsupported_is_rejected(self) -> None:
        out = run(make_world(results={target(FUNC1): UNSUPPORTED}))
        self.assertEqual(decided(out), (D.REJECT, R.REQUIRED_UNSUPPORTED))

    def test_a_verifier_error_that_cannot_be_retried_is_escalated(self) -> None:
        out = run(make_world(results={target(FUNC1): ERROR}))
        self.assertEqual(decided(out), (D.ESCALATE, R.VERIFIER_ERROR))

    def test_a_transient_verifier_error_is_retried(self) -> None:
        world = make_world(results={})
        error = record(
            world.candidate,
            target(FUNC1),
            ERROR,
            definition=world.definitions[FUNC1],
            error_type="TimeoutError",
            n=40,
        )
        base = make_world(results={target(FUNC1): error})
        out = run(base.with_policy(transient_errors=("TimeoutError",)))
        self.assertEqual(decided(out), (D.RETRY, R.VERIFIER_ERROR))
        other = run(base.with_policy(transient_errors=("ValueError",)))
        self.assertEqual(decided(other), (D.ESCALATE, R.VERIFIER_ERROR))

    def test_a_missing_result_is_insufficient_evidence(self) -> None:
        out = run(make_world(results={target(FUNC1): None}))
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))
        self.assertEqual([c.target for c in out.decision.blocking_conditions], [target(FUNC1)])

    def test_a_missing_gate_item_is_insufficient_evidence(self) -> None:
        for gate in ("STRUCTURAL", "CONSISTENCY"):
            with self.subTest(gate=gate):
                out = run(make_world(results={gate: None}))
                self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))
                self.assertEqual([c.target for c in out.decision.blocking_conditions], [gate])

    def test_a_missing_baseline_item_is_insufficient_evidence(self) -> None:
        out = run(make_world(results={BASELINE_ITEM: None}))
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))

    def test_a_failed_baseline_item_is_a_failed_required_check(self) -> None:
        out = run(make_world(results={BASELINE_ITEM: FAIL}))
        self.assertEqual(decided(out), (D.REJECT, R.REQUIRED_CHECK_FAILED))

    def test_a_construction_failure_is_rejected(self) -> None:
        world = make_world()
        bad = record(
            world.candidate,
            "STRUCTURAL",
            FAIL,
            reason=VerificationReason.CONSTRUCTION_INVALID,
            n=41,
        )
        out = run(make_world(results={"STRUCTURAL": bad}))
        self.assertEqual(decided(out), (D.REJECT, R.STRUCTURAL_FAILURE))

    def test_a_structural_finding_is_rejected(self) -> None:
        out = run(make_world(results={"STRUCTURAL": FAIL}))
        self.assertEqual(decided(out), (D.REJECT, R.STRUCTURAL_FAILURE))

    def test_inconsistent_reports_are_rejected(self) -> None:
        out = run(make_world(results={"CONSISTENCY": FAIL}))
        self.assertEqual(decided(out), (D.REJECT, R.INCONSISTENT_REPORTS))

    def test_a_non_success_gate_follows_the_table(self) -> None:
        self.assertEqual(
            decided(run(make_world(results={"STRUCTURAL": UNKNOWN}))),
            (D.RETRY, R.REQUIRED_UNKNOWN),
        )
        self.assertEqual(
            decided(run(make_world(results={"CONSISTENCY": ERROR}))), (D.ESCALATE, R.VERIFIER_ERROR)
        )


class TestStaleParent(unittest.TestCase):
    def stale(self, world: World) -> World:
        return dataclasses.replace(world, trusted=trusted_state(state_id=uid(2)))

    def test_a_candidate_of_an_old_parent_is_rejected(self) -> None:
        out = run(self.stale(make_world()))
        self.assertEqual(decided(out), (D.REJECT, R.STALE_PARENT))
        self.assertEqual(codes(out), [R.STALE_PARENT])
        self.assertEqual(out.decision.parent_state_id, out.decision.parent_state_id)
        self.assertEqual(out.proof_plan, ())

    def test_staleness_wins_over_a_fail_an_unknown_and_an_error(self) -> None:
        for results in (
            {target(SEC1): FAIL},
            {target(FUNC1): UNKNOWN},
            {target(FUNC1): ERROR},
            {"STRUCTURAL": FAIL},
        ):
            with self.subTest(results=results):
                out = run(self.stale(make_world(results=results)))
                self.assertEqual(decided(out), (D.REJECT, R.STALE_PARENT))
                self.assertEqual(codes(out), [R.STALE_PARENT])

    def test_the_decision_names_the_parent_of_the_candidate(self) -> None:
        world = self.stale(make_world())
        out = run(world)
        self.assertEqual(out.decision.parent_state_id, world.candidate.parent_state_id)
        self.assertNotEqual(out.decision.parent_state_id, world.trusted.state_id)


class TestEvidenceSufficiencyAndFreshness(unittest.TestCase):
    def with_record(self, **options: object) -> DecisionOutcome:
        world = make_world()
        changed = record(
            world.candidate,
            target(FUNC1),
            PASS,
            definition=world.definitions[FUNC1],
            n=42,
            **options,  # type: ignore[arg-type]
        )
        return run(make_world(results={target(FUNC1): changed}))

    def test_a_result_below_the_minimum_evidence_level_is_not_proof(self) -> None:
        out = self.with_record(level="L0")
        self.assertEqual(decided(out), (D.REJECT, R.EVIDENCE_NOT_SUFFICIENT))

    def test_the_gate_items_are_l0_evidence_and_still_proof(self) -> None:
        # the verification engine gives the structural and consistency items level L0
        world = make_world()
        self.assertEqual(world.records["STRUCTURAL"].evidence_level, "L0")
        self.assertEqual(world.records["CONSISTENCY"].evidence_level, "L0")
        self.assertEqual(decided(run(world)), (D.PROMOTE, R.ALL_REQUIRED_PROVEN))

    def test_a_baseline_item_below_the_minimum_level_is_not_proof(self) -> None:
        world = make_world()
        low = record(world.candidate, BASELINE_ITEM, PASS, level="L0", n=44)
        out = run(make_world(results={BASELINE_ITEM: low}))
        self.assertEqual(decided(out), (D.REJECT, R.EVIDENCE_NOT_SUFFICIENT))
        self.assertEqual([c.target for c in out.decision.blocking_conditions], [BASELINE_ITEM])

    def test_the_minimum_level_is_the_policys(self) -> None:
        world = make_world()
        low = record(
            world.candidate,
            target(FUNC1),
            PASS,
            definition=world.definitions[FUNC1],
            level="L0",
            n=43,
        )
        relaxed = make_world(results={target(FUNC1): low}).with_policy(min_evidence_level="L0")
        self.assertEqual(decided(run(relaxed)), (D.PROMOTE, R.ALL_REQUIRED_PROVEN))

    def test_a_pass_of_another_verifier_is_not_proof(self) -> None:
        # same version, other id: fresh but not sufficient (Doc 09 §11)
        out = self.with_record(verifier=("other.verifier", "1"))
        self.assertEqual(decided(out), (D.REJECT, R.EVIDENCE_NOT_SUFFICIENT))

    def test_a_result_of_an_older_verifier_version_is_stale(self) -> None:
        out = self.with_record(verifier=("dail.verify.reachability_cfg", "0"))
        self.assertEqual(decided(out), (D.REJECT, R.EVIDENCE_STALE))

    def test_a_report_of_another_candidate_hash_makes_every_result_stale(self) -> None:
        world = make_world()
        other_hash = "1" * 64
        records = [
            dataclasses.replace(r, candidate_hash=other_hash) for r in world.records.values()
        ]
        stale = VerificationReport.create(
            candidate_id=world.candidate.candidate_id,
            candidate_hash=other_hash,
            results=records,
            verifier_invocations=len(records),
            verifier_set_version="dail-verify-1",
        )
        out = run(dataclasses.replace(world, verification=stale))
        self.assertEqual(out.decision.decision, D.REJECT)
        self.assertIn(R.EVIDENCE_STALE, codes(out))
        self.assertIn(R.DECISION_INCOMPLETE, codes(out))  # the report hash is not the candidate's
        # only the carried-forward invariants have a proof: they do not rest on the report
        self.assertEqual(sorted(sources(out)), [SEC2, SEC3])

    def test_a_stale_result_is_not_used_instead_of_the_fresh_one_it_replaced(self) -> None:
        # a FAIL of an older verifier version does not count as a FAIL (aggregate ignores it) and
        # the invariant has no proof either
        out = self.with_record(verifier=("dail.verify.reachability_cfg", "0"))
        self.assertNotIn(R.REQUIRED_CHECK_FAILED, codes(out))


class TestSeverityFold(unittest.TestCase):
    """C-158: REJECT above ESCALATE above RETRY, over every pair of conditions."""

    CASES = {
        "REJECT": {target(SEC1): FAIL},
        "ESCALATE": {target(FUNC1): ERROR},
        "RETRY": {BASELINE_ITEM: UNKNOWN},
    }
    WANT = {
        frozenset({"REJECT"}): D.REJECT,
        frozenset({"ESCALATE"}): D.ESCALATE,
        frozenset({"RETRY"}): D.RETRY,
        frozenset({"REJECT", "ESCALATE"}): D.REJECT,
        frozenset({"REJECT", "RETRY"}): D.REJECT,
        frozenset({"ESCALATE", "RETRY"}): D.ESCALATE,
        frozenset({"REJECT", "ESCALATE", "RETRY"}): D.REJECT,
    }

    def test_every_combination_gives_the_most_severe_class(self) -> None:
        for names, want in self.WANT.items():
            results: dict[str, VerificationResult] = {}
            for name in names:
                results.update(self.CASES[name])
            with self.subTest(conditions=sorted(names)):
                out = run(make_world(results=results))  # type: ignore[arg-type]
                self.assertEqual(out.decision.decision, want)
                self.assertEqual(len(out.decision.blocking_conditions), len(names))

    def test_a_later_fail_is_not_hidden_behind_an_earlier_unknown(self) -> None:
        # Appendix A returns at the first non-PASS item; INV-FUNC-001 is checked before INV-SEC-001
        out = run(make_world(results={target(FUNC1): UNKNOWN, target(SEC1): FAIL}))
        self.assertEqual(decided(out), (D.REJECT, R.REQUIRED_CHECK_FAILED))
        self.assertEqual(sorted(codes(out)), [R.REQUIRED_CHECK_FAILED, R.REQUIRED_UNKNOWN])

    def test_a_baseline_fail_is_not_hidden_behind_an_unknown_invariant(self) -> None:
        out = run(make_world(results={target(SEC1): UNKNOWN, BASELINE_ITEM: FAIL}))
        self.assertEqual(decided(out), (D.REJECT, R.REQUIRED_CHECK_FAILED))

    def test_a_gate_fail_wins_over_an_error_and_an_unknown(self) -> None:
        out = run(
            make_world(results={"STRUCTURAL": FAIL, target(FUNC1): ERROR, target(SEC1): UNKNOWN})
        )
        self.assertEqual(decided(out), (D.REJECT, R.STRUCTURAL_FAILURE))

    def test_the_reason_is_the_highest_priority_of_the_winning_class(self) -> None:
        out = run(make_world(results={"STRUCTURAL": FAIL, target(FUNC1): FAIL}))
        self.assertEqual(out.decision.reason, R.STRUCTURAL_FAILURE)
        out = run(make_world(results={target(FUNC1): FAIL, target(SEC1): UNSUPPORTED}))
        self.assertEqual(out.decision.reason, R.REQUIRED_CHECK_FAILED)

    def test_the_fold_does_not_depend_on_the_order_of_the_conditions(self) -> None:
        conditions = [
            BlockingCondition(R.REQUIRED_CHECK_FAILED, D.REJECT, "A", "x"),
            BlockingCondition(R.VERIFIER_ERROR, D.ESCALATE, "B", "x"),
            BlockingCondition(R.REQUIRED_UNKNOWN, D.RETRY, "C", "x"),
            BlockingCondition(R.EVIDENCE_STALE, D.REJECT, "D", "x"),
        ]
        rng = random.Random(20261029)
        expected = fold(conditions)
        self.assertEqual(expected, (D.REJECT, R.REQUIRED_CHECK_FAILED))
        for _ in range(50):
            shuffled = conditions[:]
            rng.shuffle(shuffled)
            self.assertEqual(fold(shuffled), expected)
        for size in (1, 2, 3):
            for subset in itertools.combinations(conditions, size):
                for ordering in itertools.permutations(subset):
                    self.assertEqual(fold(list(ordering)), fold(list(subset)))

    def test_nothing_to_fold_is_not_a_decision(self) -> None:
        with self.assertRaises(DomainValidationError):
            fold([])


class TestRetryBudget(unittest.TestCase):
    def unknown(
        self, attempt: int, *, max_attempts: int = 3, extra: dict | None = None
    ) -> DecisionOutcome:
        results = {target(FUNC1): UNKNOWN}
        results.update(extra or {})
        world = make_world(results=results).with_policy(max_attempts=max_attempts)
        return run(world, attempt_number=attempt)

    def test_a_retry_below_the_budget_stays_a_retry(self) -> None:
        for attempt in (1, 2):
            with self.subTest(attempt=attempt):
                out = self.unknown(attempt)
                self.assertEqual(decided(out), (D.RETRY, R.REQUIRED_UNKNOWN))
                self.assertEqual(out.decision.attempt_number, attempt)

    def test_the_last_attempt_escalates_and_never_rejects_or_passes(self) -> None:
        out = self.unknown(3)
        self.assertEqual(decided(out), (D.ESCALATE, R.RETRY_BUDGET_EXHAUSTED))
        self.assertEqual(sorted(codes(out)), [R.REQUIRED_UNKNOWN, R.RETRY_BUDGET_EXHAUSTED])
        self.assertEqual(decided(self.unknown(7)), (D.ESCALATE, R.RETRY_BUDGET_EXHAUSTED))

    def test_a_budget_of_one_escalates_the_first_unknown(self) -> None:
        out = self.unknown(1, max_attempts=1)
        self.assertEqual(decided(out), (D.ESCALATE, R.RETRY_BUDGET_EXHAUSTED))

    def test_the_budget_changes_only_a_retry(self) -> None:
        out = self.unknown(9, extra={target(SEC1): FAIL})
        self.assertEqual(decided(out), (D.REJECT, R.REQUIRED_CHECK_FAILED))
        world = make_world(results={target(FUNC1): ERROR}).with_policy(
            transient_errors=("RuntimeError",)
        )
        self.assertEqual(decided(run(world, attempt_number=1)), (D.RETRY, R.VERIFIER_ERROR))
        self.assertEqual(
            decided(run(world, attempt_number=3)), (D.ESCALATE, R.RETRY_BUDGET_EXHAUSTED)
        )


class TestEmergencySwitch(unittest.TestCase):
    def test_a_would_be_promote_is_escalated(self) -> None:
        out = run(make_world(automatic_enabled=False))
        self.assertEqual(decided(out), (D.ESCALATE, R.AUTOMATIC_PROMOTION_DISABLED))
        condition = out.decision.blocking_conditions[0]
        self.assertIn("PROMOTE", condition.detail)  # the audit keeps what it would have been
        self.assertEqual(out.evidence.evidence_sufficiency, "SUFFICIENT")
        self.assertEqual(len(out.proof_plan), 4)

    def test_other_decisions_are_unchanged(self) -> None:
        cases = (
            ({target(SEC1): FAIL}, (D.REJECT, R.REQUIRED_CHECK_FAILED)),
            ({target(FUNC1): UNKNOWN}, (D.RETRY, R.REQUIRED_UNKNOWN)),
            ({target(FUNC1): ERROR}, (D.ESCALATE, R.VERIFIER_ERROR)),
        )
        for results, want in cases:
            with self.subTest(results=results):
                out = run(make_world(results=results, automatic_enabled=False))  # type: ignore[arg-type]
                self.assertEqual(decided(out), want)
                self.assertNotIn(R.AUTOMATIC_PROMOTION_DISABLED, codes(out))


class TestRegistryRegression(unittest.TestCase):
    """C-41: the registry version is non-decreasing and nothing is retired."""

    def test_a_policy_with_a_lower_registry_version_is_escalated(self) -> None:
        world = make_world(registry_version=2).with_policy(invariant_registry_version=1)
        out = run(world)
        self.assertEqual(decided(out), (D.ESCALATE, R.POLICY_REGISTRY_REGRESSION))

    def test_a_higher_or_equal_registry_version_is_fine(self) -> None:
        self.assertEqual(
            decided(run(make_world(registry_version=1).with_policy(invariant_registry_version=3))),
            (D.PROMOTE, R.ALL_REQUIRED_PROVEN),
        )

    def test_an_invariant_of_the_current_state_missing_from_the_policy_is_escalated(self) -> None:
        world = make_world()
        smaller = dail_policy(
            policy_version="policy-1",
            invariants=[d for i, d in world.definitions.items() if i != SEC3],
            automatic_enabled=True,
        )
        out = run(dataclasses.replace(world, policy=smaller))
        self.assertEqual(decided(out), (D.ESCALATE, R.POLICY_REGISTRY_REGRESSION))
        self.assertIn(target(SEC3), [c.target for c in out.decision.blocking_conditions])

    def test_a_policy_definition_older_than_the_reference_is_escalated(self) -> None:
        trusted = trusted_state(versions={SEC2: 2})
        world = make_world()
        candidate = analyzing_candidate(trusted, canonical_resources(ssh_open=False, db_path=True))
        impact = impact_for(trusted, candidate, carry=(SEC2, SEC3), affected=(SEC1, FUNC1))
        records = [
            record(candidate, "STRUCTURAL", n=1),
            record(candidate, "CONSISTENCY", n=2),
            record(candidate, target(SEC1), definition=world.definitions[SEC1], n=3),
            record(candidate, target(FUNC1), definition=world.definitions[FUNC1], n=4),
            record(candidate, BASELINE_ITEM, n=5),
        ]
        again = dataclasses.replace(
            world,
            trusted=trusted,
            candidate=candidate,
            impact=impact,
            verification=report_of(candidate, records),
        )
        out = run(again)
        self.assertEqual(decided(out), (D.ESCALATE, R.POLICY_REGISTRY_REGRESSION))

    def test_a_new_invariant_is_required_and_needs_a_fresh_verified_pass(self) -> None:
        # the state has three invariants; the registry has four and the policy requires the new one
        trusted = trusted_state(ids=(SEC1, SEC2, SEC3))
        world = make_world()
        candidate = analyzing_candidate(trusted, canonical_resources(ssh_open=False, db_path=True))
        impact = impact_for(trusted, candidate, carry=(SEC2, SEC3), affected=(SEC1,))
        policy = dail_policy(
            policy_version="policy-1",
            invariants=world.definitions.values(),
            automatic_enabled=True,
            extra_required=(FUNC1,),
        )
        base = [
            record(candidate, "STRUCTURAL", n=1),
            record(candidate, "CONSISTENCY", n=2),
            record(candidate, target(SEC1), definition=world.definitions[SEC1], n=3),
            record(candidate, BASELINE_ITEM, n=5),
        ]
        without = dataclasses.replace(
            world,
            trusted=trusted,
            candidate=candidate,
            impact=impact,
            policy=policy,
            verification=report_of(candidate, base),
        )
        out = run(without)
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))
        self.assertEqual([c.target for c in out.decision.blocking_conditions], [target(FUNC1)])
        func = record(candidate, target(FUNC1), definition=world.definitions[FUNC1], n=4)
        with_proof = dataclasses.replace(without, verification=report_of(candidate, [*base, func]))
        out = run(with_proof)
        self.assertEqual(decided(out), (D.PROMOTE, R.ALL_REQUIRED_PROVEN))
        self.assertEqual(sources(out)[FUNC1], ProofSource.VERIFIED)

    def test_an_invariant_whose_version_rose_cannot_be_carried_forward(self) -> None:
        world = make_world()
        policy = dail_policy(
            policy_version="policy-1",
            invariants=definitions_with(world, **{SEC2: 2}),
            automatic_enabled=True,
        )
        bumped = dataclasses.replace(world, policy=policy)
        out = run(bumped)
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))
        self.assertEqual([c.target for c in out.decision.blocking_conditions], [target(SEC2, 2)])
        # a fresh VERIFIED PASS at the new version proves it
        second = next(d for d in definitions_with(world, **{SEC2: 2}) if d.invariant_id == SEC2)
        fresh_v2 = record(world.candidate, target(SEC2, 2), definition=second, n=50)
        done = bumped.with_report([*bumped.records.values(), fresh_v2])
        out = run(done)
        self.assertEqual(decided(out), (D.PROMOTE, R.ALL_REQUIRED_PROVEN))
        self.assertEqual(sources(out)[SEC2], ProofSource.VERIFIED)


class TestCarryForwardRules(unittest.TestCase):
    """C-159: every precondition of a carry-forward removed in turn, and the never-cases."""

    def only(self, out: DecisionOutcome) -> list[str]:
        return [c.target for c in out.decision.blocking_conditions]

    def test_an_affected_invariant_is_never_carried_forward(self) -> None:
        # SEC-001 is affected; with its result missing nothing may stand in for it (C-45)
        out = run(make_world(results={target(SEC1): None}))
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))
        self.assertEqual(self.only(out), [target(SEC1)])
        self.assertNotIn(SEC1, sources(out))

    def test_an_affected_protected_invariant_is_never_carried_forward(self) -> None:
        world = make_world(affected=(SEC1, SEC2, FUNC1), results={target(SEC2): None})
        out = run(world)
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))
        self.assertEqual(self.only(out), [target(SEC2)])

    def test_an_uncertain_invariant_is_never_carried_forward(self) -> None:
        world = make_world(
            affected=(SEC1,), uncertain=(SEC2,), carry=(SEC3, FUNC1), results={target(SEC2): None}
        )
        out = run(world)
        self.assertEqual(self.only(out), [target(SEC2)])

    def test_carry_forward_needs_the_policy_to_permit_it(self) -> None:
        world = make_world().with_policy(carry_forward_enabled=False)
        out = run(world)
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))
        self.assertEqual(self.only(out), [target(SEC2), target(SEC3)])

    def test_carry_forward_needs_eligible_evidence_in_the_impact_report(self) -> None:
        base = make_world()
        impact = impact_for(
            base.trusted,
            base.candidate,
            carry=(SEC3,),
            ineligible=(SEC2,),
            affected=(SEC1, FUNC1),
        )
        out = run(dataclasses.replace(base, impact=impact))
        self.assertEqual(self.only(out), [target(SEC2)])

    def test_carry_forward_needs_the_impact_report_to_recompute_its_hash(self) -> None:
        world = make_world()
        object.__setattr__(world.impact, "graph_version", "tampered")
        out = run(world)
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))
        unproven = [
            c.target for c in out.decision.blocking_conditions if c.code is R.INSUFFICIENT_EVIDENCE
        ]
        self.assertEqual(unproven, [target(SEC2), target(SEC3)])
        self.assertIn(R.DECISION_INCOMPLETE, codes(out))

    def test_a_violated_reference_is_never_carried_forward(self) -> None:
        # R1 of the prompt: an unrelated edit cannot promote from a violated baseline invariant
        world = make_world(statuses={SEC2: InvariantStatus.VIOLATED})
        out = run(world)
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))
        self.assertEqual(self.only(out), [target(SEC2)])

    def test_an_uncertain_reference_is_never_carried_forward(self) -> None:
        world = make_world(statuses={SEC2: InvariantStatus.UNCERTAIN})
        out = run(world)
        self.assertEqual(self.only(out), [target(SEC2)])

    def test_an_invalidated_reference_is_never_carried_forward(self) -> None:
        world = make_world()
        data = world.trusted.to_dict()
        for ref in data["invariant_refs"]:
            if ref["invariant_id"] == SEC2:
                ref["invalidated_by_candidate_id"] = world.candidate.candidate_id
                ref["invalidation_reason"] = "affected by the candidate"
        invalidated = TrustedState.from_dict(data)
        out = run(dataclasses.replace(world, trusted=invalidated))
        self.assertEqual(self.only(out), [target(SEC2)])

    def test_a_version_change_is_never_carried_forward(self) -> None:
        world = make_world()
        policy = dail_policy(
            policy_version="policy-1",
            invariants=definitions_with(world, **{SEC3: 2}),
            automatic_enabled=True,
        )
        out = run(dataclasses.replace(world, policy=policy))
        self.assertEqual(self.only(out), [target(SEC3, 2)])

    def test_a_fresh_result_decides_even_for_an_unaffected_invariant(self) -> None:
        out = run(make_world(results={target(SEC2): FAIL}))
        self.assertEqual(decided(out), (D.REJECT, R.REQUIRED_CHECK_FAILED))
        self.assertEqual(self.only(out), [target(SEC2)])

    def test_a_fresh_pass_is_preferred_to_carrying_forward(self) -> None:
        out = run(make_world(results={target(SEC2): PASS}))
        self.assertEqual(decided(out), (D.PROMOTE, R.ALL_REQUIRED_PROVEN))
        self.assertEqual(sources(out)[SEC2], ProofSource.VERIFIED)
        self.assertEqual(sources(out)[SEC3], ProofSource.CARRIED_FORWARD)

    def test_no_condition_hides_the_others(self) -> None:
        out = run(make_world().with_policy(carry_forward_enabled=False))
        self.assertEqual(len(out.decision.blocking_conditions), 2)

    def test_the_refusal_says_why(self) -> None:
        out = run(make_world().with_policy(carry_forward_enabled=False))
        self.assertTrue(all("carry" in c.detail for c in out.decision.blocking_conditions))

    def test_promotion_code_never_sets_the_invalidation_fields(self) -> None:
        # C-37: no P6 event sets them
        for path in sorted((ROOT / "core" / "promotion").glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for name in ("invalidated_by_candidate_id", "invalidation_reason"):
                with self.subTest(file=path.name, name=name):
                    self.assertNotIn(name, text)


class TestOracleEvidence(unittest.TestCase):
    """C-160, Doc 09 §16 and §17."""

    def oracle(self, invariant: str, result: VerificationResult) -> OracleVerdict:
        return OracleVerdict(invariant, 1, result, "oracle-1")

    def test_agreement_changes_nothing(self) -> None:
        verdicts = [self.oracle(i, PASS) for i in ALL]
        self.assertEqual(
            decided(run(make_world(), oracle=verdicts)), (D.PROMOTE, R.ALL_REQUIRED_PROVEN)
        )

    def test_primary_pass_and_oracle_fail_is_a_conflict_and_never_a_promotion(self) -> None:
        out = run(make_world(), oracle=[self.oracle(FUNC1, FAIL)])
        self.assertEqual(decided(out), (D.ESCALATE, R.EVIDENCE_CONFLICT))
        self.assertEqual([c.target for c in out.decision.blocking_conditions], [target(FUNC1)])
        self.assertNotIn(FUNC1, sources(out))  # not treated as proven
        self.assertEqual(out.evidence.evidence_sufficiency, "INSUFFICIENT")

    def test_the_policy_may_make_a_conflict_a_rejection(self) -> None:
        world = make_world().with_policy(conflict_decision=D.REJECT)
        out = run(world, oracle=[self.oracle(FUNC1, FAIL)])
        self.assertEqual(decided(out), (D.REJECT, R.EVIDENCE_CONFLICT))

    def test_an_oracle_fail_on_a_carried_forward_invariant_is_a_conflict(self) -> None:
        out = run(make_world(), oracle=[self.oracle(SEC2, FAIL)])
        self.assertEqual(decided(out), (D.ESCALATE, R.EVIDENCE_CONFLICT))
        self.assertNotIn(SEC2, sources(out))

    def test_primary_fail_and_oracle_pass_stays_a_rejection(self) -> None:
        out = run(make_world(results={target(FUNC1): FAIL}), oracle=[self.oracle(FUNC1, PASS)])
        self.assertEqual(decided(out), (D.REJECT, R.REQUIRED_CHECK_FAILED))
        self.assertNotIn(R.EVIDENCE_CONFLICT, codes(out))

    def test_primary_unknown_and_oracle_pass_stays_unknown(self) -> None:
        out = run(make_world(results={target(FUNC1): UNKNOWN}), oracle=[self.oracle(FUNC1, PASS)])
        self.assertEqual(decided(out), (D.RETRY, R.REQUIRED_UNKNOWN))

    def test_an_oracle_pass_never_proves_a_missing_result(self) -> None:
        out = run(make_world(results={target(FUNC1): None}), oracle=[self.oracle(FUNC1, PASS)])
        self.assertEqual(decided(out), (D.REJECT, R.INSUFFICIENT_EVIDENCE))

    def test_a_verdict_for_another_version_or_an_unrequired_invariant_is_ignored(self) -> None:
        verdicts = [OracleVerdict(FUNC1, 2, FAIL, "oracle-1"), self.oracle("INV-OTHER-001", FAIL)]
        self.assertEqual(
            decided(run(make_world(), oracle=verdicts)), (D.PROMOTE, R.ALL_REQUIRED_PROVEN)
        )

    def test_a_stale_parent_still_wins_over_a_conflict(self) -> None:
        world = dataclasses.replace(make_world(), trusted=trusted_state(state_id=uid(2)))
        self.assertEqual(
            decided(run(world, oracle=[self.oracle(FUNC1, FAIL)])), (D.REJECT, R.STALE_PARENT)
        )

    def test_the_policy_cannot_accept_the_oracle(self) -> None:
        with self.assertRaises(DomainValidationError):
            make_world().with_policy(accept_oracle_for_unknown=True)


class TestDecisionCompleteness(unittest.TestCase):
    """C-161, Doc 11 §43."""

    def test_a_tampered_verification_report_downgrades_a_promote(self) -> None:
        world = make_world()
        object.__setattr__(world.verification, "content_hash", "0" * 64)
        out = run(world)
        self.assertEqual(decided(out), (D.ESCALATE, R.DECISION_INCOMPLETE))
        self.assertIn("verification", out.decision.blocking_conditions[0].detail)

    def test_a_tampered_impact_report_downgrades_a_promote(self) -> None:
        # every invariant verified, so carry_forward_ok is not what is tested here
        world = make_world(affected=ALL, carry=())
        object.__setattr__(world.impact, "graph_version", "tampered")
        out = run(world)
        self.assertEqual(decided(out), (D.ESCALATE, R.DECISION_INCOMPLETE))

    def test_a_non_promote_keeps_its_decision_and_records_the_incompleteness(self) -> None:
        world = make_world(results={target(FUNC1): UNKNOWN})
        object.__setattr__(world.verification, "content_hash", "0" * 64)
        out = run(world)
        self.assertEqual(decided(out), (D.RETRY, R.REQUIRED_UNKNOWN))
        self.assertIn(R.DECISION_INCOMPLETE, codes(out))

    def test_a_complete_decision_has_no_problem(self) -> None:
        world = make_world()
        out = run(world)
        self.assertEqual(
            completeness_problems(
                world.candidate,
                out.decision.parent_state_id,
                out.decision.supporting_results,
                world.impact,
                world.verification,
                world.policy,
            ),
            [],
        )

    def test_each_clause_is_checked(self) -> None:
        world = make_world()
        out = run(world)
        supporting = list(out.decision.supporting_results)
        parent = out.decision.parent_state_id

        def problems(**changes: object) -> list[str]:
            args: dict[str, object] = {
                "candidate": world.candidate,
                "parent_state_id": parent,
                "supporting": supporting,
                "impact": world.impact,
                "verification": world.verification,
                "policy": world.policy,
            }
            args.update(changes)
            return completeness_problems(  # type: ignore[arg-type]
                args["candidate"],
                args["parent_state_id"],
                args["supporting"],
                args["impact"],
                args["verification"],
                args["policy"],
            )

        self.assertTrue(problems(parent_state_id=uid(2)))  # parent binding
        self.assertTrue(
            problems(supporting=[*supporting, uid(31337)])
        )  # a result that is not there
        other = make_world(results={target(FUNC1): FAIL})
        self.assertEqual(problems(verification=other.verification), [])  # hashes recompute
        broken_report = make_world()
        object.__setattr__(broken_report.verification, "content_hash", "0" * 64)
        self.assertTrue(problems(verification=broken_report.verification))
        broken_impact = make_world()
        object.__setattr__(broken_impact.impact, "graph_version", "tampered")
        self.assertTrue(problems(impact=broken_impact.impact))

    def test_the_candidate_hash_of_the_report_must_be_the_candidates(self) -> None:
        world = make_world()
        other_hash = "1" * 64
        records = [
            dataclasses.replace(r, candidate_hash=other_hash) for r in world.records.values()
        ]
        report = VerificationReport.create(
            candidate_id=world.candidate.candidate_id,
            candidate_hash=other_hash,
            results=records,
            verifier_invocations=len(records),
            verifier_set_version="dail-verify-1",
        )
        found = completeness_problems(
            world.candidate, world.trusted.state_id, [], world.impact, report, world.policy
        )
        self.assertEqual(len(found), 1)
        self.assertIn("candidate_hash", found[0])


class TestReportBindings(unittest.TestCase):
    """The impact and verification reports must be those of this candidate and parent."""

    def test_an_impact_report_of_another_candidate_is_rejected(self) -> None:
        world = make_world()
        elsewhere = analyzing_candidate(
            world.trusted, canonical_resources(ssh_open=False, db_path=True), n=2
        )
        self.assertNotEqual(elsewhere.candidate_id, world.candidate.candidate_id)
        other = dataclasses.replace(
            world,
            impact=impact_for(world.trusted, elsewhere, carry=(SEC2, SEC3), affected=(SEC1, FUNC1)),
        )
        out = run(other)
        self.assertEqual(decided(out), (D.REJECT, R.INCONSISTENT_REPORTS))
        self.assertNotIn(SEC2, sources(out))

    def test_an_impact_report_of_another_parent_is_rejected(self) -> None:
        world = make_world()
        elsewhere = trusted_state(state_id=uid(2))
        report = impact_for(elsewhere, world.candidate, carry=(SEC2, SEC3), affected=(SEC1, FUNC1))
        out = run(dataclasses.replace(world, impact=report))
        self.assertEqual(decided(out), (D.REJECT, R.INCONSISTENT_REPORTS))

    def test_a_verification_report_of_another_candidate_is_rejected(self) -> None:
        world = make_world()
        report = VerificationReport.create(
            candidate_id=uid(99),
            candidate_hash=world.candidate.state_hash or "",
            results=[dataclasses.replace(r, candidate_id=uid(99)) for r in world.records.values()],
            verifier_invocations=5,
            verifier_set_version="dail-verify-1",
        )
        out = run(dataclasses.replace(world, verification=report))
        self.assertEqual(decided(out), (D.REJECT, R.INCONSISTENT_REPORTS))


class TestMalformedArguments(unittest.TestCase):
    def test_wrong_types_raise_an_input_error(self) -> None:
        w = make_world()
        calls = {
            "candidate": lambda: self.call(w, candidate=w.trusted),
            "trusted": lambda: self.call(w, trusted=w.candidate),
            "impact": lambda: self.call(w, impact=w.verification),
            "verification": lambda: self.call(w, verification=w.impact),
            "policy": lambda: self.call(w, policy="policy"),
        }
        for name, call in calls.items():
            with self.subTest(argument=name), self.assertRaises(PromotionInputError):
                call()

    def call(self, world: World, **replace: object) -> DecisionOutcome:
        from core.promotion.decide import decide

        args: dict[str, object] = {
            "candidate": world.candidate,
            "trusted": world.trusted,
            "impact": world.impact,
            "verification": world.verification,
            "policy": world.policy,
        }
        args.update(replace)
        return decide(
            args["candidate"],  # type: ignore[arg-type]
            args["trusted"],  # type: ignore[arg-type]
            args["impact"],  # type: ignore[arg-type]
            args["verification"],  # type: ignore[arg-type]
            args["policy"],  # type: ignore[arg-type]
            decision_id=uid(9100),
            now=world.trusted.created_at,
        )

    def test_the_other_arguments_are_checked_too(self) -> None:
        from datetime import datetime

        from core.promotion.decide import decide

        w = make_world()

        def call(**kw: object) -> DecisionOutcome:
            args: dict[str, object] = {
                "decision_id": uid(9100),
                "now": w.trusted.created_at,
                "attempt_number": 1,
                "oracle_verdicts": (),
            }
            args.update(kw)
            return decide(w.candidate, w.trusted, w.impact, w.verification, w.policy, **args)  # type: ignore[arg-type]

        for name, value in (
            ("decision_id", "not-a-uuid"),
            ("now", datetime(2026, 10, 1)),  # naive
            ("now", "2026-10-01"),
            ("attempt_number", 0),
            ("attempt_number", True),
            ("attempt_number", "1"),
            ("oracle_verdicts", ("PASS",)),
            ("oracle_verdicts", "oracle"),
        ):
            with self.subTest(argument=name, value=value), self.assertRaises(PromotionInputError):
                call(**{name: value})
        duplicate = OracleVerdict(FUNC1, 1, PASS, "o")
        with self.assertRaises(PromotionInputError):
            call(oracle_verdicts=(duplicate, OracleVerdict(FUNC1, 1, FAIL, "o")))

    def test_another_lineage_is_an_input_error_not_a_decision(self) -> None:
        w = make_world()
        other_lineage = baseline(lineage_id=uid(77))
        with self.assertRaises(PromotionInputError):
            self.call(w, trusted=other_lineage)

    def test_a_candidate_that_is_not_under_analysis_is_an_input_error(self) -> None:
        w = make_world()
        for status in (CandidateStatus.REJECTED, CandidateStatus.RETRY_REQUIRED):
            from core.domain.state import transition_candidate

            moved = transition_candidate(w.candidate, status)
            with self.subTest(status=status), self.assertRaises(PromotionInputError):
                self.call(w, candidate=moved)


class TestPurity(unittest.TestCase):
    def test_the_same_inputs_give_the_same_outcome(self) -> None:
        world = make_world()
        self.assertEqual(run(world), run(world))
        self.assertEqual(run(world).decision.content_hash, run(world).decision.content_hash)

    def test_the_id_changes_the_id_and_nothing_else(self) -> None:
        world = make_world()
        a, b = run(world), run(world, decision_id=uid(9200))
        self.assertNotEqual(a.decision.decision_id, b.decision.decision_id)
        self.assertEqual(a.decision.content_hash, b.decision.content_hash)
        self.assertEqual(a.proof_plan, b.proof_plan)

    def test_no_argument_is_changed(self) -> None:
        for world in (
            make_world(),
            make_world(results={target(FUNC1): FAIL}),
            make_world(results={target(FUNC1): UNKNOWN}),
            dataclasses.replace(make_world(), trusted=trusted_state(state_id=uid(2))),
        ):
            before = (
                world.candidate.to_dict(),
                world.trusted.to_dict(),
                world.impact.to_dict(),
                world.verification.to_dict(),
                world.policy,
            )
            run(world, oracle=[OracleVerdict(FUNC1, 1, FAIL, "o")])
            after = (
                world.candidate.to_dict(),
                world.trusted.to_dict(),
                world.impact.to_dict(),
                world.verification.to_dict(),
                world.policy,
            )
            self.assertEqual(before, after)

    def test_the_decision_code_has_no_clock_randomness_or_io(self) -> None:
        for path in sorted((ROOT / "core" / "promotion").glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for forbidden in (
                "datetime.now",
                "utcnow",
                "time.time",
                "import random",
                "uuid4",
                "open(",
                "print(",
                "import os",
                "import logging",
            ):
                with self.subTest(file=path.name, forbidden=forbidden):
                    self.assertNotIn(forbidden, text)

    def test_the_decision_never_runs_or_repairs_verification(self) -> None:
        for path in sorted((ROOT / "core" / "promotion").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or "").startswith("core.verification"), path.name)
                if isinstance(node, ast.Name):
                    self.assertNotEqual(node.id, "run_work_set", path.name)


if __name__ == "__main__":
    unittest.main()
