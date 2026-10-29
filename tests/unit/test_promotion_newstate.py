"""Derived ids, proof building and the arguments of the new trusted state (P6b step 3; Doc 09 §26,
§27; Doc 06 §14, §21; C-40, C-41, C-45, C-163, C-164).

HAND EXPECTATIONS, written before the code (canonical world of ``tests/promotion_builders.py``:
INV-SEC-001 and INV-FUNC-001 verified, INV-SEC-002 and INV-SEC-003 carried forward):

* C-163: the new state id, the promotion-evidence id and the STATE_PROMOTED event id are
  ``uuid5(NAMESPACE, "state:" + decision_id)``, ``... "promotion-evidence:" ...`` and
  ``... "state-promoted:" ...``; the namespace is the constant written below.
* C-164: every reference of the new state carries the id of the binding record. A VERIFIED
  reference has its source evidence plus the binding id (PROTECTED, origin VERIFIED, bound to the
  candidate); a CARRIED_FORWARD one has the parent reference's evidence plus the binding id
  (status and time copied, origin CARRIED_FORWARD, source state the parent).
* The proof set covers every invariant of the parent and nothing is built from a plan entry that
  has no evaluation, no evidence id, a result that is not PASS, or a changed version (a version
  change has no lifecycle path: fail closed).
* ``TrustedState.promote`` with those arguments gives version parent + 1, the candidate's resources,
  ``commit_decision_id`` = the decision id, the derived state id, and a registry version that is not
  lower than the parent's (C-41).
"""

from __future__ import annotations

import dataclasses
import unittest
import uuid

from core.domain.enums import CandidateStatus, InvariantStatus, ProofOrigin, VerificationResult
from core.domain.errors import DomainValidationError
from core.domain.promotion import DecisionOutcome, ProofPlanEntry
from core.domain.state import TrustedState
from core.domain.verification import VerificationReason
from core.promotion import ids
from core.promotion.newstate import promotion_arguments
from core.promotion.proofs import build_proofs, evaluate_from_results
from tests.domain_builders import uid
from tests.promotion_builders import (
    FUNC1,
    SEC1,
    SEC2,
    SEC3,
    World,
    impact_for,
    make_world,
    run,
    target,
)

NAMESPACE = uuid.UUID("c3b0e0d2-6f1a-4d8e-9a57-2b7c4e1f8a90")
DECISION = uid(9100)
BINDING = ids.evidence_id_for(DECISION)


class TestDerivedIds(unittest.TestCase):
    def test_the_namespace_is_the_fixed_constant(self) -> None:
        self.assertEqual(ids.PROMOTION_NAMESPACE, NAMESPACE)

    def test_the_three_ids_follow_the_formulas_of_c_163(self) -> None:
        self.assertEqual(
            ids.state_id_for(DECISION), str(uuid.uuid5(NAMESPACE, "state:" + DECISION))
        )
        self.assertEqual(
            ids.evidence_id_for(DECISION),
            str(uuid.uuid5(NAMESPACE, "promotion-evidence:" + DECISION)),
        )
        self.assertEqual(
            ids.event_id_for(DECISION), str(uuid.uuid5(NAMESPACE, "state-promoted:" + DECISION))
        )

    def test_the_ids_are_distinct_and_stable(self) -> None:
        found = {
            ids.state_id_for(DECISION),
            ids.evidence_id_for(DECISION),
            ids.event_id_for(DECISION),
            ids.rejection_decision_id_for(DECISION),
            ids.failure_event_id_for(DECISION, "REVALIDATION"),
            ids.failure_event_id_for(DECISION, "INFRASTRUCTURE"),
        }
        self.assertEqual(len(found), 6)
        self.assertEqual(ids.state_id_for(DECISION), ids.state_id_for(DECISION))
        self.assertNotEqual(ids.state_id_for(DECISION), ids.state_id_for(uid(9101)))

    def test_a_decision_id_must_be_a_uuid(self) -> None:
        for bad in ("", "x", None, 5):
            with self.subTest(bad=bad), self.assertRaises(DomainValidationError):
                ids.state_id_for(bad)  # type: ignore[arg-type]

    def test_the_failure_kind_is_a_known_word(self) -> None:
        with self.assertRaises(DomainValidationError):
            ids.failure_event_id_for(DECISION, "OTHER")


def sources_for(world: World) -> tuple[dict[str, object], dict[str, str]]:
    """The verification records by id and a made-up evidence id for each (n-th result)."""
    by_id = {r.verification_id: r for r in world.verification.results}
    evidence = {vid: uid(8800 + n) for n, vid in enumerate(sorted(by_id))}
    return by_id, evidence


def evaluations_of(world: World, outcome: DecisionOutcome) -> dict[str, object]:
    by_id, evidence = sources_for(world)
    return evaluate_from_results(
        outcome.proof_plan,
        world.candidate,
        world.trusted,
        world.definitions,
        by_id,  # type: ignore[arg-type]
        evidence,
        BINDING,
    )


class TestBuildProofs(unittest.TestCase):
    def setUp(self) -> None:
        self.world = make_world()
        self.outcome = run(self.world)
        self.by_id, self.evidence = sources_for(self.world)
        self.evaluations = evaluations_of(self.world, self.outcome)
        self.proofs = build_proofs(
            self.outcome.proof_plan,
            self.world.candidate,
            self.world.trusted,
            self.world.impact,
            self.evaluations,  # type: ignore[arg-type]
            binding_evidence_id=BINDING,
        )

    def by_invariant(self) -> dict[str, object]:
        return {p.invariant_id: p for p in self.proofs}

    def test_one_proof_per_invariant_of_the_parent_sorted_by_id(self) -> None:
        self.assertEqual([p.invariant_id for p in self.proofs], [FUNC1, SEC1, SEC2, SEC3])

    def test_a_verified_proof_has_its_source_evidence_and_the_binding_record(self) -> None:
        for invariant_id in (SEC1, FUNC1):
            proof = self.by_invariant()[invariant_id]
            source = self.evidence[self.world.records[target(invariant_id)].verification_id]
            with self.subTest(invariant=invariant_id):
                self.assertIs(proof.origin, ProofOrigin.VERIFIED)  # type: ignore[attr-defined]
                self.assertIs(proof.status, InvariantStatus.PROTECTED)  # type: ignore[attr-defined]
                self.assertEqual(proof.evidence_ids, tuple(sorted({source, BINDING})))  # type: ignore[attr-defined]
                self.assertEqual(proof.candidate_id, self.world.candidate.candidate_id)  # type: ignore[attr-defined]

    def test_a_carried_proof_has_the_parents_evidence_and_the_binding_record(self) -> None:
        for invariant_id in (SEC2, SEC3):
            parent = next(
                r for r in self.world.trusted.invariant_refs if r.invariant_id == invariant_id
            )
            proof = self.by_invariant()[invariant_id]
            with self.subTest(invariant=invariant_id):
                self.assertIs(proof.origin, ProofOrigin.CARRIED_FORWARD)  # type: ignore[attr-defined]
                self.assertEqual(proof.status, parent.status)  # type: ignore[attr-defined]
                self.assertEqual(proof.verified_at, parent.last_verified_at)  # type: ignore[attr-defined]
                self.assertEqual(proof.source_state_id, self.world.trusted.state_id)  # type: ignore[attr-defined]
                self.assertEqual(
                    proof.evidence_ids,  # type: ignore[attr-defined]
                    tuple(sorted({*parent.evidence_ids, BINDING})),
                )

    def test_a_plan_entry_without_an_evaluation_is_refused(self) -> None:
        partial = {k: v for k, v in self.evaluations.items() if k != SEC1}
        with self.assertRaises(DomainValidationError):
            build_proofs(
                self.outcome.proof_plan,
                self.world.candidate,
                self.world.trusted,
                self.world.impact,
                partial,  # type: ignore[arg-type]
                binding_evidence_id=BINDING,
            )

    def test_a_plan_that_leaves_out_an_invariant_of_the_parent_is_refused(self) -> None:
        short = tuple(e for e in self.outcome.proof_plan if e.invariant_id != SEC3)
        with self.assertRaises(DomainValidationError):
            build_proofs(
                short,
                self.world.candidate,
                self.world.trusted,
                self.world.impact,
                self.evaluations,  # type: ignore[arg-type]
                binding_evidence_id=BINDING,
            )

    def test_two_entries_for_one_invariant_are_refused(self) -> None:
        twice = (*self.outcome.proof_plan, self.outcome.proof_plan[0])
        with self.assertRaises(DomainValidationError):
            build_proofs(
                twice,
                self.world.candidate,
                self.world.trusted,
                self.world.impact,
                self.evaluations,  # type: ignore[arg-type]
                binding_evidence_id=BINDING,
            )

    def test_an_affected_invariant_cannot_be_carried_forward_here_either(self) -> None:
        # C-45 at the point where proofs are built: the report says SEC-002 is affected
        report = impact_for(
            self.world.trusted,
            self.world.candidate,
            affected=(SEC1, FUNC1, SEC2),
            carry=(SEC3,),
        )
        with self.assertRaises(DomainValidationError) as caught:
            build_proofs(
                self.outcome.proof_plan,
                self.world.candidate,
                self.world.trusted,
                report,
                self.evaluations,  # type: ignore[arg-type]
                binding_evidence_id=BINDING,
            )
        self.assertIn("C-45", str(caught.exception))

    def test_the_binding_id_must_be_a_uuid(self) -> None:
        with self.assertRaises(DomainValidationError):
            build_proofs(
                self.outcome.proof_plan,
                self.world.candidate,
                self.world.trusted,
                self.world.impact,
                self.evaluations,  # type: ignore[arg-type]
                binding_evidence_id="binding",
            )


class TestEvaluateFromResults(unittest.TestCase):
    def setUp(self) -> None:
        self.world = make_world()
        self.outcome = run(self.world)
        self.by_id, self.evidence = sources_for(self.world)

    def call(
        self,
        *,
        plan: tuple[ProofPlanEntry, ...] | None = None,
        by_id: dict[str, object] | None = None,
        evidence: dict[str, str] | None = None,
    ) -> dict[str, object]:
        return evaluate_from_results(
            self.outcome.proof_plan if plan is None else plan,
            self.world.candidate,
            self.world.trusted,
            self.world.definitions,
            self.by_id if by_id is None else by_id,  # type: ignore[arg-type]
            self.evidence if evidence is None else evidence,
            BINDING,
        )

    def test_a_violated_reference_is_reopened_and_a_protected_one_is_affected(self) -> None:
        got = self.call()
        self.assertEqual(sorted(got), [FUNC1, SEC1])  # only the VERIFIED entries
        for evaluation in got.values():
            self.assertIs(evaluation.status, InvariantStatus.PROTECTED)  # type: ignore[attr-defined]

    def test_a_missing_result_or_evidence_id_is_refused(self) -> None:
        some = next(iter(self.by_id))
        with self.assertRaises(DomainValidationError):
            self.call(by_id={k: v for k, v in self.by_id.items() if k != some})
        with self.assertRaises(DomainValidationError):
            self.call(evidence={k: v for k, v in self.evidence.items() if k != some})

    def test_a_result_that_is_not_a_pass_is_refused(self) -> None:
        failing = {
            k: dataclasses.replace(
                v,  # type: ignore[type-var]
                result=VerificationResult.FAIL,
                reason=VerificationReason.PREDICATE_VIOLATED,
                evidence={**v.evidence, "result": "FAIL"},  # type: ignore[attr-defined]
            )
            for k, v in self.by_id.items()
        }
        with self.assertRaises(DomainValidationError):
            self.call(by_id=failing)

    def test_a_version_change_has_no_lifecycle_path(self) -> None:
        entry = next(e for e in self.outcome.proof_plan if e.invariant_id == SEC1)
        bumped = dataclasses.replace(entry, invariant_version=2)
        plan = tuple(bumped if e is entry else e for e in self.outcome.proof_plan)
        with self.assertRaises(DomainValidationError):
            self.call(plan=plan)


class TestThePromotionArguments(unittest.TestCase):
    def setUp(self) -> None:
        self.world = make_world(candidate_status=CandidateStatus.PROMOTABLE)
        self.outcome = run(self.world)
        self.proofs = build_proofs(
            self.outcome.proof_plan,
            self.world.candidate,
            self.world.trusted,
            self.world.impact,
            evaluations_of(self.world, self.outcome),  # type: ignore[arg-type]
            binding_evidence_id=BINDING,
        )

    def args(self, **changes: object) -> dict[str, object]:
        base: dict[str, object] = {
            "registry_version": self.world.trusted.invariant_registry_version,
            "now": self.world.trusted.created_at,
        }
        base.update(changes)
        return promotion_arguments(
            self.world.candidate,
            self.world.trusted,
            DECISION,
            self.proofs,
            registry_version=base["registry_version"],  # type: ignore[arg-type]
            now=base["now"],  # type: ignore[arg-type]
        )

    def test_the_arguments_make_the_next_state(self) -> None:
        # in a test the controller's own call is repeated; production code calls it in commit
        state = TrustedState.promote(**self.args())  # type: ignore[arg-type]
        self.assertEqual(state.version, self.world.trusted.version + 1)
        self.assertEqual(state.parent_state_id, self.world.trusted.state_id)
        self.assertEqual(state.state_id, ids.state_id_for(DECISION))
        self.assertEqual(state.commit_decision_id, DECISION)
        self.assertEqual(state.resources, self.world.candidate.resources)
        self.assertEqual({r.invariant_id for r in state.invariant_refs}, {FUNC1, SEC1, SEC2, SEC3})
        for ref in state.invariant_refs:
            with self.subTest(invariant=ref.invariant_id):
                self.assertIs(ref.status, InvariantStatus.PROTECTED)
                self.assertIn(BINDING, ref.evidence_ids)
        self.assertIn(BINDING, state.evidence_refs)
        union = {e for p in self.proofs for e in p.evidence_ids}
        self.assertEqual(set(state.evidence_refs), union)

    def test_the_ssh_reference_is_verified_not_carried(self) -> None:
        state = TrustedState.promote(**self.args())  # type: ignore[arg-type]
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

    def test_a_lower_registry_version_is_refused(self) -> None:
        # C-41: the registry version is non-decreasing across promotions
        world = make_world(registry_version=2)
        with self.assertRaises(DomainValidationError):
            promotion_arguments(
                world.candidate,
                world.trusted,
                DECISION,
                self.proofs,
                registry_version=1,
                now=world.trusted.created_at,
            )

    def test_a_higher_registry_version_is_accepted(self) -> None:
        state = TrustedState.promote(**self.args(registry_version=3))  # type: ignore[arg-type]
        self.assertEqual(state.invariant_registry_version, 3)

    def test_the_candidate_must_be_promotable(self) -> None:
        # an ANALYZING candidate is refused here, before promote is called
        analyzing = make_world()
        self.assertIs(analyzing.candidate.status, CandidateStatus.ANALYZING)
        with self.assertRaises(DomainValidationError):
            promotion_arguments(
                analyzing.candidate,
                analyzing.trusted,
                DECISION,
                self.proofs,
                registry_version=1,
                now=self.world.trusted.created_at,
            )


if __name__ == "__main__":
    unittest.main()
