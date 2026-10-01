"""Coverage and version of the proofs ``promote`` accepts (C-40, C-41; Doc 06 §22 SM-006; F10).

C-40: "Every invariant_id on the current state must have a proof, with an invariant_version not
lower than its current one." An invariant cannot be dropped at promotion (C-41 leaves retirement
open). A new invariant may be added. Expected values come from that text.
"""

from __future__ import annotations

import unittest

from core.domain.enums import InvariantStatus as S
from core.domain.enums import VerificationResult
from core.domain.errors import DomainValidationError
from core.domain.invariant import Invariant, InvariantEvaluation, InvariantProof, new_version
from core.domain.state import CandidateState
from tests.domain_builders import (
    FUNC,
    SEC,
    at,
    baseline,
    canonical_resources,
    carried_proof,
    evaluation_for,
    invariant,
    promotable_candidate,
    promote,
    proof,
    uid,
    verified_proof,
)

SAFE = canonical_resources(ssh_open=False, db_path=True)
NEW = "INV-SEC-002"


def registered_proof(
    candidate: CandidateState, definition: Invariant, evidence: int = 31
) -> InvariantProof:
    done = (
        InvariantEvaluation.register(candidate, definition)
        .start_verification()
        .apply_result(VerificationResult.PASS, [uid(1000 + evidence)], at(10))
    )
    return done.to_proof()


class TestEveryCurrentInvariantNeedsAProof(unittest.TestCase):
    def setUp(self) -> None:
        self.v0 = baseline(proofs=[proof(SEC, S.PROTECTED, 1), proof(FUNC, S.VIOLATED, 2)])
        self.candidate = promotable_candidate(self.v0, SAFE)

    def test_a_proof_for_every_current_invariant_is_accepted(self) -> None:
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[
                carried_proof(self.v0, self.candidate, SEC),
                verified_proof(self.v0, self.candidate, FUNC, S.VIOLATED, 12),
            ],
        )
        self.assertEqual({r.invariant_id for r in v1.invariant_refs}, {SEC, FUNC})

    def test_dropping_an_invariant_is_refused(self) -> None:
        """The review's second forgery: with another proof list, INV-FUNC-001 disappeared."""
        with self.assertRaises(DomainValidationError) as ctx:
            promote(self.candidate, self.v0, proofs=[carried_proof(self.v0, self.candidate, SEC)])
        message = str(ctx.exception)
        self.assertIn("C-40", message)
        self.assertIn(FUNC, message)

    def test_an_empty_proof_list_is_refused(self) -> None:
        with self.assertRaises(DomainValidationError) as ctx:
            promote(self.candidate, self.v0, proofs=[])
        self.assertIn("C-40", str(ctx.exception))

    def test_a_proof_for_a_new_invariant_does_not_make_up_for_a_dropped_one(self) -> None:
        with self.assertRaises(DomainValidationError) as ctx:
            promote(
                self.candidate,
                self.v0,
                proofs=[
                    carried_proof(self.v0, self.candidate, SEC),
                    registered_proof(self.candidate, invariant(NEW)),
                ],
            )
        self.assertIn(FUNC, str(ctx.exception))

    def test_a_new_invariant_may_be_added(self) -> None:
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[
                carried_proof(self.v0, self.candidate, SEC),
                carried_proof(self.v0, self.candidate, FUNC),
                registered_proof(self.candidate, invariant(NEW)),
            ],
        )
        self.assertEqual({r.invariant_id for r in v1.invariant_refs}, {SEC, FUNC, NEW})

    def test_a_refused_promotion_does_not_change_the_current_state(self) -> None:
        before = self.v0.to_dict()
        with self.assertRaises(DomainValidationError):
            promote(self.candidate, self.v0, proofs=[carried_proof(self.v0, self.candidate, SEC)])
        self.assertEqual(self.v0.to_dict(), before)


class TestProofVersionMayNotGoDown(unittest.TestCase):
    def setUp(self) -> None:
        self.sec_v1 = invariant(SEC)
        self.sec_v2 = new_version(self.sec_v1, now=at(5))
        self.v0 = baseline(
            proofs=[
                InvariantProof.for_baseline(
                    invariant_id=SEC,
                    invariant_version=2,
                    status=S.PROTECTED,
                    evidence_ids=[uid(1001)],
                    verified_at=at(0),
                ),
                proof(FUNC, S.PROTECTED, 2),
            ]
        )
        self.candidate = promotable_candidate(self.v0, SAFE)
        self.func = carried_proof(self.v0, self.candidate, FUNC)

    def test_a_lower_version_is_refused(self) -> None:
        lower = registered_proof(self.candidate, self.sec_v1)
        self.assertEqual(lower.invariant_version, 1)
        with self.assertRaises(DomainValidationError) as ctx:
            promote(self.candidate, self.v0, proofs=[lower, self.func])
        message = str(ctx.exception)
        self.assertIn("C-40", message)
        self.assertIn(SEC, message)

    def test_the_same_version_is_accepted(self) -> None:
        v1 = promote(
            self.candidate,
            self.v0,
            proofs=[carried_proof(self.v0, self.candidate, SEC), self.func],
        )
        self.assertEqual(
            {r.invariant_id: r.invariant_version for r in v1.invariant_refs}, {SEC: 2, FUNC: 1}
        )

    def test_a_higher_version_is_accepted(self) -> None:
        v0 = baseline(proofs=[proof(SEC, S.PROTECTED, 1), proof(FUNC, S.PROTECTED, 2)])
        candidate = promotable_candidate(v0, SAFE)
        higher = registered_proof(candidate, self.sec_v2)
        self.assertEqual(higher.invariant_version, 2)
        v1 = promote(candidate, v0, proofs=[higher, carried_proof(v0, candidate, FUNC)])
        self.assertEqual(
            {r.invariant_id: r.invariant_version for r in v1.invariant_refs}, {SEC: 2, FUNC: 1}
        )


class TestHelpersAreHonest(unittest.TestCase):
    """The builders reach the proofs only through evaluations, so these tests mean something."""

    def test_the_default_promotion_covers_every_current_invariant(self) -> None:
        v0 = baseline(proofs=[proof(SEC, S.PROTECTED, 1), proof(FUNC, S.VIOLATED, 2)])
        candidate = promotable_candidate(v0, SAFE)
        v1 = promote(candidate, v0)
        self.assertEqual({r.invariant_id for r in v1.invariant_refs}, {SEC, FUNC})
        self.assertEqual(evaluation_for(v0, candidate, FUNC).status, S.REVERIFYING)


if __name__ == "__main__":
    unittest.main()
