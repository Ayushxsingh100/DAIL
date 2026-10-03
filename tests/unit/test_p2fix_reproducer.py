"""P2-fix step 1: reproducer for D1 / gap G1 (Doc 11 §7; Doc 06 §15; C-52).

Doc 06 §15 (end): "Trusted vN remains active and E1/E2 remain valid for vN. A rejected candidate
does not consume or rewrite the evidence attached to the active Trusted State."

Impact analysis of candidate C invalidates E1 *for C* (Doc 11 §7: INVALID means "no longer valid for
the referenced new-state context"). E1 describes vN, so it must stay usable as proof for vN.
"""

import tempfile
import unittest
from pathlib import Path

from evidence.ids import CorrelationContext
from evidence.models import EvidenceType, EvidenceValidity
from evidence.store import EvidenceStore

STATE_VN = "state-vN"
CANDIDATE_C = "cand-C"


class TestInvalidatingForACandidateLeavesTheStateUsable(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = EvidenceStore(Path(self._tmp.name) / "e.db")
        self.store.initialize_schema()
        self.ctx = CorrelationContext.new()
        self.e1 = self.store.put_evidence(
            evidence_type=EvidenceType.VERIFICATION,
            payload={"invariant": "INV-FUNC-001", "result": "PASS"},
            ctx=self.ctx,
            source_component="verification",
            source_type="fixture",
            algorithm_or_verifier_version="test-1",
            state_id=STATE_VN,
        ).record
        self.store.invalidate(
            self.e1.evidence_id,
            reason="INV-FUNC-001 affected by the candidate",
            ctx=self.ctx,
            candidate_id=CANDIDATE_C,
            impact_report_ref="impact-1",
        )

    def test_e1_is_still_proof_for_its_own_state(self) -> None:
        check = self.store.usable_as_proof(self.e1.evidence_id, state_id=STATE_VN)
        self.assertTrue(check.usable, check.reasons)

    def test_e1_is_invalid_for_the_candidate_it_was_invalidated_for(self) -> None:
        self.assertIs(
            self.store.validity_in(self.e1.evidence_id, candidate_id=CANDIDATE_C),
            EvidenceValidity.INVALID,
        )
        self.assertIs(
            self.store.validity_in(self.e1.evidence_id, state_id=STATE_VN), EvidenceValidity.VALID
        )

    def test_a_third_candidate_never_sees_e1_as_valid(self) -> None:
        """C-52 R4: evidence is not implicitly valid outside the context it was produced for."""
        self.assertIs(
            self.store.validity_in(self.e1.evidence_id, candidate_id="cand-other"),
            EvidenceValidity.UNCERTAIN,
        )

    def test_validity_in_needs_exactly_one_context(self) -> None:
        with self.assertRaises(ValueError):
            self.store.validity_in(self.e1.evidence_id)
        with self.assertRaises(ValueError):
            self.store.validity_in(self.e1.evidence_id, state_id=STATE_VN, candidate_id="c")

    def test_the_original_payload_still_resolves(self) -> None:
        record = self.store.get_evidence(self.e1.evidence_id)
        self.assertEqual(
            self.store.resolve_payload(record), {"invariant": "INV-FUNC-001", "result": "PASS"}
        )
