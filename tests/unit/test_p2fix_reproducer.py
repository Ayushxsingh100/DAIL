"""P2-fix reproducer for D1 / gap G1 (Doc 11 §7; Doc 06 §15; C-52), migrated to the service.

Step 1 wrote this against the interim store and watched it fail on the ``2c9b668`` behaviour
(``validity is INVALID, not VALID``). Step 4 moved the same scenario and the same assertions onto
``EvidenceService`` and UUID ids; the interim store is gone.

Doc 06 §15 (end): "Trusted vN remains active and E1/E2 remain valid for vN. A rejected candidate
does not consume or rewrite the evidence attached to the active Trusted State."

Impact analysis of candidate C invalidates E1 *for C* (Doc 11 §7: INVALID means "no longer valid for
the referenced new-state context"). E1 describes vN, so it must stay usable as proof for vN.
"""

from __future__ import annotations

from core.domain.evidence import EvidenceValidity
from tests.service_builders import ServiceCase


class TestInvalidatingForACandidateLeavesTheStateUsable(ServiceCase):
    def setUp(self) -> None:
        super().setUp()
        # E1 is VERIFICATION evidence bound to vN (here v0); the impact report is for candidate C.
        self.e1 = self.put({"invariant": "INV-FUNC-001", "result": "PASS"})
        self.impact = self.impact_for(self.c1)
        with self.uow() as u:
            self.svc.invalidate(
                u,
                self.e1.evidence_id,
                context=self.c1_ctx,
                reason="INV-FUNC-001 affected by the candidate",
                ctx=self.ctx,
                impact_ref=self.impact.evidence_id,
            )

    def test_e1_is_still_proof_for_its_own_state(self) -> None:
        with self.uow() as u:
            check = self.svc.usable_as_proof(u, self.e1.evidence_id, self.v0_ctx)
        self.assertTrue(check.usable, check.reasons)

    def test_e1_is_invalid_for_the_candidate_it_was_invalidated_for(self) -> None:
        with self.uow() as u:
            self.assertIs(
                self.svc.validity_in(u, self.e1.evidence_id, self.c1_ctx), EvidenceValidity.INVALID
            )
            self.assertIs(
                self.svc.validity_in(u, self.e1.evidence_id, self.v0_ctx), EvidenceValidity.VALID
            )

    def test_a_third_candidate_never_sees_e1_as_valid(self) -> None:
        """C-52 R4: evidence is not implicitly valid outside the context it was produced for."""
        with self.uow() as u:
            self.assertIs(
                self.svc.validity_in(u, self.e1.evidence_id, self.c2_ctx),
                EvidenceValidity.UNCERTAIN,
            )

    def test_the_original_payload_still_resolves(self) -> None:
        with self.uow() as u:
            self.assertEqual(
                self.svc.resolve_payload(u, self.e1.evidence_id),
                {"invariant": "INV-FUNC-001", "result": "PASS"},
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
