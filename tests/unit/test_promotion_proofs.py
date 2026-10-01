"""Which proofs the trusted-state factories accept (C-40; Doc 06 §22 SM-006, §24; review F10).

``establish_baseline`` accepts only BASELINE proofs. ``promote`` accepts only VERIFIED proofs bound
to this candidate and CARRIED_FORWARD proofs from the current state; a BASELINE proof, a proof
bound to another candidate and a proof carried from another state are refused. Expected values
come from the C-40 text, not from the implementation.
"""

from __future__ import annotations

import unittest

from core.domain.enums import InvariantStatus as S
from core.domain.enums import ProofOrigin
from core.domain.errors import DomainValidationError
from core.domain.invariant import InvariantProof
from core.domain.state import CandidateState, TrustedState
from tests.domain_builders import (
    FUNC,
    SEC,
    baseline,
    canonical_resources,
    carried_proof,
    promotable_candidate,
    promote,
    proof,
    uid,
    verified_proof,
)

SAFE = canonical_resources(ssh_open=False, db_path=True)


def origins(state: TrustedState) -> dict[str, ProofOrigin]:
    return {ref.invariant_id: ref.origin for ref in state.invariant_refs}


class TestBaselineAcceptsOnlyBaselineProofs(unittest.TestCase):
    def setUp(self) -> None:
        self.donor = baseline(state_id=uid(77))
        self.donor_candidate = promotable_candidate(self.donor, SAFE, n=7)

    def test_baseline_proofs_are_accepted_and_recorded_as_baseline(self) -> None:
        v0 = baseline()
        self.assertEqual(origins(v0), {SEC: ProofOrigin.BASELINE, FUNC: ProofOrigin.BASELINE})

    def test_a_verified_proof_cannot_found_a_baseline(self) -> None:
        verified = verified_proof(self.donor, self.donor_candidate, SEC)
        self.assertIs(verified.origin, ProofOrigin.VERIFIED)
        with self.assertRaises(DomainValidationError) as ctx:
            baseline(proofs=[verified, proof(FUNC, evidence=2)])
        self.assertIn("C-40", str(ctx.exception))
        self.assertIn("only a BASELINE proof can found a baseline", str(ctx.exception))

    def test_a_carried_forward_proof_cannot_found_a_baseline(self) -> None:
        carried = carried_proof(self.donor, self.donor_candidate, SEC)
        with self.assertRaises(DomainValidationError) as ctx:
            baseline(proofs=[carried, proof(FUNC, evidence=2)])
        self.assertIn("C-40", str(ctx.exception))
        self.assertIn("only a BASELINE proof can found a baseline", str(ctx.exception))


class TestPromoteChecksProofOrigin(unittest.TestCase):
    def setUp(self) -> None:
        self.v0 = baseline()
        self.candidate = promotable_candidate(self.v0, SAFE, n=1)
        self.other = promotable_candidate(self.v0, SAFE, n=2, sequence=2)

    def verified(
        self,
        candidate: CandidateState | None = None,
        invariant_id: str = SEC,
        evidence: int = 11,
    ) -> InvariantProof:
        return verified_proof(
            self.v0, candidate or self.candidate, invariant_id, S.PROTECTED, evidence
        )

    def test_verified_proofs_bound_to_this_candidate_are_accepted(self) -> None:
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[self.verified(invariant_id=SEC), self.verified(invariant_id=FUNC, evidence=12)],
        )
        self.assertEqual(origins(v1), {SEC: ProofOrigin.VERIFIED, FUNC: ProofOrigin.VERIFIED})

    def test_carried_forward_proofs_from_the_current_state_are_accepted(self) -> None:
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[
                carried_proof(self.v0, self.candidate, SEC),
                self.verified(invariant_id=FUNC, evidence=12),
            ],
        )
        self.assertEqual(
            origins(v1), {SEC: ProofOrigin.CARRIED_FORWARD, FUNC: ProofOrigin.VERIFIED}
        )

    def test_a_baseline_proof_cannot_promote(self) -> None:
        for proofs in (
            [proof(SEC, evidence=21), proof(FUNC, evidence=22)],
            [proof(SEC, evidence=21), self.verified(invariant_id=FUNC, evidence=12)],
        ):
            with self.subTest(n=len(proofs)), self.assertRaises(DomainValidationError) as ctx:
                promote(self.candidate, self.v0, proofs=proofs)
            self.assertIn("C-40", str(ctx.exception))
            self.assertIn("BASELINE", str(ctx.exception))

    def test_a_verified_proof_from_another_candidate_cannot_promote(self) -> None:
        for proofs in (
            [
                self.verified(self.other, SEC),
                self.verified(self.other, FUNC, evidence=12),
            ],
            [self.verified(self.candidate, SEC), self.verified(self.other, FUNC, evidence=12)],
        ):
            with (
                self.subTest(first=proofs[0].candidate_id),
                self.assertRaises(DomainValidationError) as ctx,
            ):
                promote(self.candidate, self.v0, proofs=proofs)
            self.assertIn("C-40", str(ctx.exception))
            self.assertIn(self.other.candidate_id, str(ctx.exception))

    def test_a_carried_forward_proof_bound_to_another_candidate_cannot_promote(self) -> None:
        with self.assertRaises(DomainValidationError) as ctx:
            promote(
                self.candidate,
                self.v0,
                proofs=[
                    carried_proof(self.v0, self.other, SEC),
                    self.verified(invariant_id=FUNC, evidence=12),
                ],
            )
        self.assertIn("C-40", str(ctx.exception))

    def test_a_carried_forward_proof_from_a_non_current_state_cannot_promote(self) -> None:
        """Defence in depth. ``carry_forward`` already ties the proof to the candidate's parent, so
        a proof naming another state exists only if someone rewrites it with ``object.__setattr__``
        (the guard cannot stop that, P1a risk R5); ``promote`` must still refuse it."""
        carried = carried_proof(self.v0, self.candidate, SEC)
        object.__setattr__(carried, "source_state_id", uid(99))
        with self.assertRaises(DomainValidationError) as ctx:
            promote(
                self.candidate,
                self.v0,
                proofs=[carried, self.verified(invariant_id=FUNC, evidence=12)],
            )
        self.assertIn("C-40", str(ctx.exception))
        self.assertIn(uid(99), str(ctx.exception))

    def test_a_refused_promotion_leaves_the_current_state_unchanged(self) -> None:
        before = self.v0.to_dict()
        with self.assertRaises(DomainValidationError):
            promote(self.candidate, self.v0, proofs=[proof(SEC), proof(FUNC)])
        self.assertEqual(self.v0.to_dict(), before)


class TestStoredOriginsAreConsistent(unittest.TestCase):
    """The state_hash does not cover ``origin`` (C-33), so loading must check it: a baseline holds
    BASELINE references only, every later state none (C-40)."""

    def test_a_baseline_with_a_non_baseline_reference_is_refused(self) -> None:
        data = baseline().to_dict()
        data["invariant_refs"][0]["origin"] = "VERIFIED"
        with self.assertRaises(DomainValidationError) as ctx:
            TrustedState.from_dict(data)
        self.assertIn("C-40", str(ctx.exception))

    def test_a_promoted_state_with_a_baseline_reference_is_refused(self) -> None:
        v0 = baseline()
        v1 = promote(promotable_candidate(v0, SAFE), v0)
        data = v1.to_dict()
        data["invariant_refs"][0]["origin"] = "BASELINE"
        with self.assertRaises(DomainValidationError) as ctx:
            TrustedState.from_dict(data)
        self.assertIn("C-40", str(ctx.exception))

    def test_the_honest_states_load(self) -> None:
        v0 = baseline()
        v1 = promote(promotable_candidate(v0, SAFE), v0)
        for state in (v0, v1):
            self.assertEqual(TrustedState.from_dict(state.to_dict()), state)


if __name__ == "__main__":
    unittest.main()
