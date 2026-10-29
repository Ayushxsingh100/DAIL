"""InvariantProof: origin, construction guard and the three constructors (C-40; Doc 06 §14, §22
SM-006, §30; review F10).

Expected values come from the C-40 text: a proof is created only by ``for_baseline`` (BASELINE),
``InvariantEvaluation.to_proof`` (VERIFIED, bound to the evaluation's candidate) and
``carry_forward`` (CARRIED_FORWARD, status and evidence copied unchanged).
"""

from __future__ import annotations

import dataclasses
import unittest

from core.domain.enums import InvariantStatus as S
from core.domain.enums import ProofOrigin, VerificationResult
from core.domain.errors import (
    DomainValidationError,
    IllegalTransitionError,
    UnauthorizedConstructionError,
)
from core.domain.impact import ImpactReport
from core.domain.invariant import InvariantEvaluation, InvariantProof, InvariantRef
from tests.domain_builders import (
    FUNC,
    SEC,
    at,
    baseline,
    new_candidate,
    proof,
    uid,
    verified_proof,
)
from tests.promotion_builders import impact_for

EVIDENCE = uid(1500)


def forged_fields(**overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "invariant_id": FUNC,
        "invariant_version": 1,
        "status": S.PROTECTED,
        "evidence_ids": (EVIDENCE,),
        "verified_at": at(5),
        "origin": ProofOrigin.VERIFIED,
        "candidate_id": uid(3001),
        "source_state_id": None,
    }
    fields.update(overrides)
    return fields


class TestProofOriginEnum(unittest.TestCase):
    def test_values_are_the_three_named_in_c40(self) -> None:
        self.assertEqual(
            {member.value for member in ProofOrigin}, {"BASELINE", "VERIFIED", "CARRIED_FORWARD"}
        )
        self.assertEqual({member.name for member in ProofOrigin}, {m.value for m in ProofOrigin})


class TestConstructionGuard(unittest.TestCase):
    """C-40: a proof cannot be built by hand, so a VIOLATED invariant cannot be relabelled."""

    def setUp(self) -> None:
        self.v0 = baseline(proofs=[proof(SEC, S.PROTECTED, evidence=1), proof(FUNC, S.VIOLATED, 2)])
        self.candidate = new_candidate(self.v0)
        self.baseline_proof = proof(FUNC, S.VIOLATED, evidence=2)
        self.carried = InvariantProof.carry_forward(
            next(r for r in self.v0.invariant_refs if r.invariant_id == FUNC),
            self.candidate,
            impact_for(self.v0, self.candidate, carry=(FUNC,)),
        )

    def test_direct_construction_is_refused_for_every_origin(self) -> None:
        for origin, candidate_id, source in (
            (ProofOrigin.BASELINE, None, None),
            (ProofOrigin.VERIFIED, self.candidate.candidate_id, None),
            (ProofOrigin.CARRIED_FORWARD, self.candidate.candidate_id, self.v0.state_id),
        ):
            with self.subTest(origin=origin), self.assertRaises(UnauthorizedConstructionError):
                InvariantProof(  # type: ignore[call-arg]
                    **forged_fields(  # type: ignore[arg-type]
                        origin=origin, candidate_id=candidate_id, source_state_id=source
                    )
                )

    def test_a_guessed_token_is_refused(self) -> None:
        with self.assertRaises(UnauthorizedConstructionError):
            InvariantProof(**forged_fields(), _token=object())  # type: ignore[arg-type]

    def test_replace_cannot_change_a_proof(self) -> None:
        # The forgery of the review: a VIOLATED invariant relabelled PROTECTED.
        for proof_ in (self.baseline_proof, self.carried):
            with (
                self.subTest(origin=proof_.origin),
                self.assertRaises(UnauthorizedConstructionError),
            ):
                dataclasses.replace(proof_, status=S.PROTECTED)
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(self.baseline_proof, origin=ProofOrigin.VERIFIED)
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(self.carried, candidate_id=uid(3999))

    def test_a_proof_is_frozen(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.baseline_proof.status = S.PROTECTED  # type: ignore[misc]


class TestForBaseline(unittest.TestCase):
    def test_a_baseline_proof_has_origin_baseline_and_no_bindings(self) -> None:
        for status in (S.PROTECTED, S.VIOLATED, S.UNCERTAIN):
            p = InvariantProof.for_baseline(
                invariant_id=SEC,
                invariant_version=1,
                status=status,
                evidence_ids=[EVIDENCE],
                verified_at=at(0),
            )
            with self.subTest(status=status):
                self.assertIs(p.origin, ProofOrigin.BASELINE)
                self.assertEqual(p.status, status)
                self.assertIsNone(p.candidate_id)
                self.assertIsNone(p.source_state_id)

    def test_it_validates_like_any_proof(self) -> None:
        good = dict(
            invariant_id=SEC,
            invariant_version=1,
            status=S.PROTECTED,
            evidence_ids=[EVIDENCE],
            verified_at=at(0),
        )
        for field, bad in (
            ("invariant_id", "bad"),
            ("invariant_version", 0),
            ("status", S.AFFECTED),
            ("evidence_ids", []),
            ("verified_at", None),
        ):
            with self.subTest(field=field), self.assertRaises(DomainValidationError):
                InvariantProof.for_baseline(**{**good, field: bad})  # type: ignore[arg-type]


class TestVerifiedProof(unittest.TestCase):
    def test_to_proof_is_verified_and_bound_to_the_evaluations_candidate(self) -> None:
        v0 = baseline()
        candidate = new_candidate(v0)
        p = verified_proof(v0, candidate, SEC, S.PROTECTED, evidence=7)
        self.assertIs(p.origin, ProofOrigin.VERIFIED)
        self.assertEqual(p.candidate_id, candidate.candidate_id)
        self.assertIsNone(p.source_state_id)

    def test_a_violated_invariant_becomes_protected_only_through_a_passing_evaluation(self) -> None:
        v0 = baseline(proofs=[proof(SEC, evidence=1), proof(FUNC, S.VIOLATED, evidence=2)])
        candidate = new_candidate(v0)
        ref = next(r for r in v0.invariant_refs if r.invariant_id == FUNC)
        evaluation = InvariantEvaluation.reopen(ref, candidate, "candidate under review")
        self.assertEqual(evaluation.status, S.REVERIFYING)
        with self.assertRaises(IllegalTransitionError) as ctx:
            evaluation.to_proof()  # no result yet: nothing to prove
        self.assertEqual(ctx.exception.rule, "SM-006")
        verified = evaluation.apply_result(VerificationResult.PASS, [EVIDENCE], at(6))
        p = verified.to_proof()
        self.assertEqual((p.status, p.origin), (S.PROTECTED, ProofOrigin.VERIFIED))
        # A failing re-verification keeps it VIOLATED; it cannot be promoted to PROTECTED.
        failed = evaluation.apply_result(VerificationResult.FAIL, [EVIDENCE], at(6)).to_proof()
        self.assertEqual(failed.status, S.VIOLATED)


class TestCarryForward(unittest.TestCase):
    def setUp(self) -> None:
        self.v0 = baseline(
            proofs=[
                proof(SEC, S.PROTECTED, evidence=1, minutes=3),
                proof(FUNC, S.VIOLATED, evidence=2, minutes=4),
                proof("INV-SEC-002", S.UNCERTAIN, evidence=3, minutes=5),
            ]
        )
        self.candidate = new_candidate(self.v0)

    def ref(self, invariant_id: str) -> InvariantRef:
        return next(r for r in self.v0.invariant_refs if r.invariant_id == invariant_id)

    def impact(self, invariant_id: str) -> ImpactReport:
        """An impact report that leaves ``invariant_id`` alone and offers its evidence (C-45)."""
        return impact_for(self.v0, self.candidate, carry=(invariant_id,))

    def test_status_evidence_and_time_are_copied_unchanged(self) -> None:
        for invariant_id in (SEC, FUNC, "INV-SEC-002"):
            ref = self.ref(invariant_id)
            p = InvariantProof.carry_forward(ref, self.candidate, self.impact(invariant_id))
            with self.subTest(invariant=invariant_id):
                self.assertIs(p.origin, ProofOrigin.CARRIED_FORWARD)
                self.assertEqual(p.status, ref.status)  # VIOLATED and UNCERTAIN stay as they are
                self.assertEqual(p.evidence_ids, ref.evidence_ids)
                self.assertEqual(p.verified_at, ref.last_verified_at)
                self.assertEqual(p.invariant_id, ref.invariant_id)
                self.assertEqual(p.invariant_version, ref.invariant_version)

    def test_it_is_bound_to_the_candidate_and_to_the_state_it_came_from(self) -> None:
        p = InvariantProof.carry_forward(self.ref(SEC), self.candidate, self.impact(SEC))
        self.assertEqual(p.candidate_id, self.candidate.candidate_id)
        self.assertEqual(p.source_state_id, self.v0.state_id)

    def test_a_reference_from_another_state_is_refused(self) -> None:
        other = baseline(state_id=uid(88))
        foreign = next(r for r in other.invariant_refs if r.invariant_id == SEC)
        with self.assertRaises(DomainValidationError) as ctx:
            InvariantProof.carry_forward(foreign, self.candidate, self.impact(SEC))
        self.assertIn("C-40", str(ctx.exception))

    def test_an_invalidated_protected_reference_is_refused(self) -> None:
        data = self.ref(SEC).to_dict()
        data["invalidated_by_candidate_id"] = self.candidate.candidate_id
        data["invalidation_reason"] = "affected by the candidate"
        invalidated = InvariantRef.from_dict(data)
        self.assertFalse(invalidated.can_satisfy_proof())
        with self.assertRaises(DomainValidationError) as ctx:
            InvariantProof.carry_forward(invalidated, self.candidate, self.impact(SEC))
        self.assertIn("C-40", str(ctx.exception))

    def test_a_protected_status_is_never_manufactured_from_a_weaker_reference(self) -> None:
        for invariant_id in (FUNC, "INV-SEC-002"):
            with self.subTest(invariant=invariant_id):
                p = InvariantProof.carry_forward(
                    self.ref(invariant_id), self.candidate, self.impact(invariant_id)
                )
                self.assertNotEqual(p.status, S.PROTECTED)

    def test_arguments_are_type_checked(self) -> None:
        with self.assertRaises(DomainValidationError):
            InvariantProof.carry_forward(
                {"invariant_id": SEC},  # type: ignore[arg-type]
                self.candidate,
                self.impact(SEC),
            )
        with self.assertRaises(DomainValidationError):
            InvariantProof.carry_forward(
                self.ref(SEC),
                self.v0,  # type: ignore[arg-type]
                self.impact(SEC),
            )


class TestCarryForwardNeedsTheImpactReport(unittest.TestCase):
    """C-45, the canonical DAIL failure: a candidate that affects an invariant and then violates
    it must not hide behind the parent's old evidence. ``carry_forward`` therefore asks the impact
    report of exactly this candidate and parent (``carry_forward_ok``, C-141): anything but an
    eligible, unaffected invariant is refused."""

    def setUp(self) -> None:
        self.v0 = baseline(
            proofs=[
                proof(SEC, S.PROTECTED, evidence=1, minutes=3),
                proof(FUNC, S.PROTECTED, evidence=2, minutes=4),
            ]
        )
        self.candidate = new_candidate(self.v0)

    def ref(self, invariant_id: str) -> InvariantRef:
        return next(r for r in self.v0.invariant_refs if r.invariant_id == invariant_id)

    def carry(self, impact: object, invariant_id: str = SEC) -> InvariantProof:
        return InvariantProof.carry_forward(
            self.ref(invariant_id),
            self.candidate,
            impact,  # type: ignore[arg-type]
        )

    def refused(self, impact: object, invariant_id: str = SEC) -> None:
        with self.assertRaises(DomainValidationError) as ctx:
            self.carry(impact, invariant_id)
        self.assertIn("C-45", str(ctx.exception))

    def test_an_unaffected_invariant_with_eligible_evidence_may_be_carried(self) -> None:
        carried = self.carry(impact_for(self.v0, self.candidate, carry=(SEC, FUNC)))
        self.assertIs(carried.origin, ProofOrigin.CARRIED_FORWARD)
        self.assertEqual(carried.evidence_ids, self.ref(SEC).evidence_ids)

    def test_an_affected_invariant_is_refused(self) -> None:
        self.refused(impact_for(self.v0, self.candidate, affected=(SEC,), carry=(FUNC,)))

    def test_an_uncertain_invariant_is_refused(self) -> None:
        self.refused(impact_for(self.v0, self.candidate, uncertain=(SEC,), carry=(FUNC,)))

    def test_an_invariant_the_report_does_not_mention_is_refused(self) -> None:
        self.refused(impact_for(self.v0, self.candidate, carry=(FUNC,)), SEC)

    def test_an_unaffected_invariant_without_eligible_evidence_is_refused(self) -> None:
        self.refused(impact_for(self.v0, self.candidate, ineligible=(SEC,), carry=(FUNC,)))

    def test_a_report_for_another_candidate_is_refused(self) -> None:
        other = new_candidate(self.v0, sequence=2, n=2)
        self.refused(impact_for(self.v0, other, carry=(SEC,)))

    def test_a_report_for_another_parent_is_refused(self) -> None:
        other_parent = baseline(state_id=uid(88))
        report = impact_for(other_parent, self.candidate, carry=(SEC,))
        self.assertNotEqual(report.parent_state_id, self.candidate.parent_state_id)
        self.refused(report)

    def test_a_report_whose_hash_no_longer_recomputes_is_refused(self) -> None:
        report = impact_for(self.v0, self.candidate, carry=(SEC,))
        object.__setattr__(report, "graph_version", "tampered")
        self.assertNotEqual(report.content_hash, report.compute_hash())
        self.refused(report)

    def test_a_report_that_names_the_invariant_at_another_version_is_refused(self) -> None:
        self.refused(impact_for(self.v0, self.candidate, carry=(SEC,), versions={SEC: 2}))

    def test_the_version_asked_is_the_version_of_the_reference(self) -> None:
        # a reference to version 2: a report that only knows version 1 does not allow it, and
        # one that names version 2 does
        newer = InvariantProof.for_baseline(
            invariant_id=SEC,
            invariant_version=2,
            status=S.PROTECTED,
            evidence_ids=(uid(1001),),
            verified_at=at(3),
        )
        self.v0 = baseline(proofs=[newer, proof(FUNC, S.PROTECTED, evidence=2)])
        self.candidate = new_candidate(self.v0)
        self.assertEqual(self.ref(SEC).invariant_version, 2)
        self.refused(impact_for(self.v0, self.candidate, carry=(SEC,), versions={SEC: 1}))
        carried = self.carry(impact_for(self.v0, self.candidate, carry=(SEC,)))
        self.assertEqual(carried.invariant_version, 2)

    def test_the_report_is_required_and_must_be_one(self) -> None:
        with self.assertRaises(TypeError):
            InvariantProof.carry_forward(self.ref(SEC), self.candidate)  # type: ignore[call-arg]
        for bad in (None, {"carry_forward_candidates": [SEC]}, "ImpactReport"):
            with self.subTest(bad=bad), self.assertRaises(DomainValidationError):
                self.carry(bad)

    def test_a_refusal_changes_nothing(self) -> None:
        before = self.v0.state_hash
        self.refused(impact_for(self.v0, self.candidate, affected=(SEC,)))
        self.assertEqual(self.v0.state_hash, before)


if __name__ == "__main__":
    unittest.main()
