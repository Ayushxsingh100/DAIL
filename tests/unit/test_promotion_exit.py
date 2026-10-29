"""The PROMOTABLE -> ESCALATED exit of C-38 (P6b step 4; Doc 06 §5, Doc 09 §24; C-38).

HAND EXPECTATIONS, written before the code: the candidate lifecycle gains exactly one edge,
PROMOTABLE -> ESCALATED. REJECTED, ESCALATED, RETRY_REQUIRED, PROMOTED and FAILED stay terminal;
PROMOTABLE -> PROMOTED stays reserved to ``mark_promoted`` (SM-002) and PROMOTABLE -> REJECTED to
``reject_stale_candidate`` (C-29); PROMOTABLE -> RETRY_REQUIRED and every backward edge stay
forbidden. The edge is also legal in the database (schema 6).
"""

from __future__ import annotations

import unittest

from core.domain.enums import CandidateStatus as C
from core.domain.errors import IllegalTransitionError
from core.domain.lifecycle import CANDIDATE_TRANSITIONS, check_candidate_transition
from core.domain.state import transition_candidate
from tests.domain_builders import analyzing_candidate, baseline, canonical_resources


class TestThePromotableToEscalatedExit(unittest.TestCase):
    def setUp(self) -> None:
        self.v0 = baseline()
        analyzing = analyzing_candidate(self.v0, canonical_resources(ssh_open=False, db_path=True))
        self.promotable = transition_candidate(analyzing, C.PROMOTABLE)

    def test_the_table_gains_exactly_one_edge(self) -> None:
        self.assertEqual(
            CANDIDATE_TRANSITIONS[C.PROMOTABLE], frozenset({C.PROMOTED, C.REJECTED, C.ESCALATED})
        )
        check_candidate_transition(C.PROMOTABLE, C.ESCALATED)

    def test_a_promotable_candidate_can_be_escalated(self) -> None:
        escalated = transition_candidate(self.promotable, C.ESCALATED)
        self.assertEqual(escalated.status, C.ESCALATED)
        self.assertEqual(escalated.candidate_id, self.promotable.candidate_id)
        self.assertEqual(escalated.state_hash, self.promotable.state_hash)
        self.assertEqual(self.promotable.status, C.PROMOTABLE)

    def test_the_neighbouring_edges_stay_forbidden(self) -> None:
        for target in (C.RETRY_REQUIRED, C.ANALYZING, C.READY, C.BUILDING, C.CREATED, C.FAILED):
            with self.subTest(target=target), self.assertRaises(IllegalTransitionError):
                transition_candidate(self.promotable, target)
        # reserved exits: mark_promoted (SM-002) and reject_stale_candidate (C-29)
        with self.assertRaises(IllegalTransitionError) as promoted:
            transition_candidate(self.promotable, C.PROMOTED)
        self.assertEqual(promoted.exception.rule, "SM-002")
        with self.assertRaises(IllegalTransitionError) as rejected:
            transition_candidate(self.promotable, C.REJECTED)
        self.assertEqual(rejected.exception.rule, "C-29")

    def test_every_terminal_status_stays_terminal(self) -> None:
        for status in (C.FAILED, C.REJECTED, C.RETRY_REQUIRED, C.ESCALATED, C.PROMOTED):
            self.assertEqual(CANDIDATE_TRANSITIONS[status], frozenset(), status)
        escalated = transition_candidate(self.promotable, C.ESCALATED)
        for target in C:
            with self.subTest(target=target), self.assertRaises(IllegalTransitionError):
                transition_candidate(escalated, target)

    def test_no_other_status_gained_an_edge(self) -> None:
        was = {
            C.CREATED: {C.BUILDING},
            C.BUILDING: {C.READY, C.FAILED},
            C.READY: {C.ANALYZING},
            C.ANALYZING: {C.REJECTED, C.RETRY_REQUIRED, C.ESCALATED, C.PROMOTABLE},
        }
        for status, targets in was.items():
            self.assertEqual(CANDIDATE_TRANSITIONS[status], frozenset(targets), status)


if __name__ == "__main__":
    unittest.main()
