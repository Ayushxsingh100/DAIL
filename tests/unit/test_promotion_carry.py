"""``InvariantProof.carry_forward`` with extra evidence (P6b step 3; C-164, C-45).

HAND EXPECTATIONS, written before the code. A reference of vN+1 that is carried forward from vN
must also carry the id of the promotion binding record (C-164), because the next carry-forward
(vN+1 to vN+2) looks for that record in the reference's evidence. So ``carry_forward`` takes an
optional keyword ``extra_evidence_ids``: the proof's evidence is the parent reference's evidence
plus those ids, as a sorted set of UUIDs (the rule of ``_evidence_ids``), and nothing else about
the proof changes (status, time, origin, source state). The C-45 check does not move: an affected,
uncertain, unmentioned or ineligible invariant is refused whatever extra evidence is offered.
"""

from __future__ import annotations

import unittest

from core.domain.enums import ProofOrigin
from core.domain.errors import DomainValidationError
from core.domain.invariant import InvariantProof
from tests.domain_builders import FUNC, SEC, baseline, new_candidate, parent_ref, uid
from tests.promotion_builders import impact_for

EXTRA = uid(9901)
OTHER = uid(9902)


class TestExtraEvidence(unittest.TestCase):
    def setUp(self) -> None:
        self.v0 = baseline()
        self.candidate = new_candidate(self.v0)
        self.impact = impact_for(self.v0, self.candidate, carry=(SEC, FUNC))
        self.ref = parent_ref(self.v0, SEC)

    def carry(self, **options: object) -> InvariantProof:
        return InvariantProof.carry_forward(
            self.ref,
            self.candidate,
            self.impact,
            **options,  # type: ignore[arg-type]
        )

    def test_the_default_is_the_parents_evidence_unchanged(self) -> None:
        self.assertEqual(self.carry().evidence_ids, self.ref.evidence_ids)

    def test_the_extra_evidence_is_added_as_a_sorted_set(self) -> None:
        proof = self.carry(extra_evidence_ids=(OTHER, EXTRA))
        self.assertEqual(proof.evidence_ids, tuple(sorted({*self.ref.evidence_ids, EXTRA, OTHER})))

    def test_duplicates_collapse(self) -> None:
        both = self.carry(extra_evidence_ids=(EXTRA, EXTRA, *self.ref.evidence_ids))
        self.assertEqual(both.evidence_ids, tuple(sorted({*self.ref.evidence_ids, EXTRA})))

    def test_nothing_else_about_the_proof_changes(self) -> None:
        plain, extra = self.carry(), self.carry(extra_evidence_ids=(EXTRA,))
        for field in ("invariant_id", "invariant_version", "status", "verified_at", "origin"):
            self.assertEqual(getattr(plain, field), getattr(extra, field), field)
        self.assertIs(extra.origin, ProofOrigin.CARRIED_FORWARD)
        self.assertEqual(extra.source_state_id, self.v0.state_id)
        self.assertEqual(extra.candidate_id, self.candidate.candidate_id)

    def test_the_extra_evidence_must_be_a_list_of_uuids(self) -> None:
        for bad in ("not-a-uuid", EXTRA, ("x",), [""], None, 5):
            with self.subTest(bad=bad), self.assertRaises(DomainValidationError):
                self.carry(extra_evidence_ids=bad)

    def test_the_impact_check_does_not_move(self) -> None:
        for kind in ("affected", "uncertain", "ineligible"):
            report = impact_for(self.v0, self.candidate, carry=(FUNC,), **{kind: (SEC,)})
            with self.subTest(kind=kind), self.assertRaises(DomainValidationError) as caught:
                InvariantProof.carry_forward(
                    self.ref, self.candidate, report, extra_evidence_ids=(EXTRA,)
                )
            self.assertIn("C-45", str(caught.exception))

    def test_a_report_that_does_not_mention_the_invariant_is_still_refused(self) -> None:
        report = impact_for(self.v0, self.candidate, carry=(FUNC,))
        with self.assertRaises(DomainValidationError):
            InvariantProof.carry_forward(
                self.ref, self.candidate, report, extra_evidence_ids=(EXTRA,)
            )


if __name__ == "__main__":
    unittest.main()
