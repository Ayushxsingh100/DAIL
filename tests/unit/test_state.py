import unittest

from core.domain.state import CandidateState, CandidateStatus, TrustedState


class TestTrustedStateGenesis(unittest.TestCase):
    def test_genesis_has_version_1_and_no_parent(self) -> None:
        s0 = TrustedState.genesis(content_payload={"resources": []}, invariant_registry_version=1)
        self.assertEqual(s0.version, 1)
        self.assertIsNone(s0.parent_state_id)
        self.assertTrue(s0.state_id.startswith("state-"))

    def test_version_1_with_parent_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            TrustedState(
                state_id="state-bad",
                version=1,
                content_hash="deadbeef",
                invariant_registry_version=1,
                parent_state_id="state-should-not-exist",
            )

    def test_version_above_1_without_parent_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            TrustedState(
                state_id="state-bad",
                version=2,
                content_hash="deadbeef",
                invariant_registry_version=1,
                parent_state_id=None,
            )

    def test_trusted_state_is_frozen(self) -> None:
        s0 = TrustedState.genesis(content_payload={}, invariant_registry_version=1)
        with self.assertRaises(Exception):  # noqa: B017
            s0.version = 99  # type: ignore[misc]


class TestStateLineage(unittest.TestCase):
    """P1 exit criterion: 'State lineage tests pass.'"""

    def test_promotion_chain_preserves_lineage(self) -> None:
        s0 = TrustedState.genesis(
            content_payload={"resources": ["web-node-v1"]}, invariant_registry_version=1
        )
        candidate = CandidateState.build(parent=s0, patch_payload={"patch": "remove-ssh-rule"})
        self.assertEqual(candidate.parent_state_id, s0.state_id)
        self.assertEqual(candidate.status, CandidateStatus.BUILT)

        candidate.mark_under_verification()
        candidate.mark_promoted()

        s1 = TrustedState.promoted_from(
            candidate=candidate,
            parent=s0,
            content_payload={"resources": ["web-node-v2"]},
            invariant_registry_version=1,
        )
        self.assertEqual(s1.version, 2)
        self.assertEqual(s1.parent_state_id, s0.state_id)

    def test_multi_step_lineage_chain(self) -> None:
        """s0 -> s1 -> s2: version increments and parent pointers form
        an unbroken chain, mirroring the Git-commit-lineage design
        described in the paper (Section VI-B)."""
        s0 = TrustedState.genesis(content_payload={"v": 0}, invariant_registry_version=1)

        c1 = CandidateState.build(parent=s0, patch_payload={"p": 1})
        c1.mark_under_verification()
        c1.mark_promoted()
        s1 = TrustedState.promoted_from(
            candidate=c1, parent=s0, content_payload={"v": 1}, invariant_registry_version=1
        )

        c2 = CandidateState.build(parent=s1, patch_payload={"p": 2})
        c2.mark_under_verification()
        c2.mark_promoted()
        s2 = TrustedState.promoted_from(
            candidate=c2, parent=s1, content_payload={"v": 2}, invariant_registry_version=1
        )

        self.assertEqual([s0.version, s1.version, s2.version], [1, 2, 3])
        self.assertEqual(s1.parent_state_id, s0.state_id)
        self.assertEqual(s2.parent_state_id, s1.state_id)

    def test_cannot_promote_candidate_built_from_a_different_parent(self) -> None:
        s0 = TrustedState.genesis(content_payload={"v": 0}, invariant_registry_version=1)
        other_branch = TrustedState.genesis(
            content_payload={"v": "other"}, invariant_registry_version=1
        )

        candidate = CandidateState.build(parent=other_branch, patch_payload={"p": 1})
        candidate.mark_under_verification()
        candidate.mark_promoted()

        with self.assertRaises(ValueError):
            TrustedState.promoted_from(
                candidate=candidate,  # built from other_branch, not s0
                parent=s0,
                content_payload={"v": 1},
                invariant_registry_version=1,
            )

    def test_cannot_promote_a_candidate_that_was_not_marked_promoted(self) -> None:
        s0 = TrustedState.genesis(content_payload={"v": 0}, invariant_registry_version=1)
        candidate = CandidateState.build(parent=s0, patch_payload={"p": 1})
        # status is still BUILT, never went through verification
        with self.assertRaises(ValueError):
            TrustedState.promoted_from(
                candidate=candidate,
                parent=s0,
                content_payload={"v": 1},
                invariant_registry_version=1,
            )


class TestCandidateStatusTransitions(unittest.TestCase):
    def test_happy_path(self) -> None:
        s0 = TrustedState.genesis(content_payload={}, invariant_registry_version=1)
        c = CandidateState.build(parent=s0, patch_payload={"p": 1})
        self.assertEqual(c.status, CandidateStatus.BUILT)
        c.mark_under_verification()
        self.assertEqual(c.status, CandidateStatus.UNDER_VERIFICATION)
        c.mark_promoted()
        self.assertEqual(c.status, CandidateStatus.PROMOTED)

    def test_rejection_path(self) -> None:
        s0 = TrustedState.genesis(content_payload={}, invariant_registry_version=1)
        c = CandidateState.build(parent=s0, patch_payload={"p": 1})
        c.mark_under_verification()
        c.mark_rejected()
        self.assertEqual(c.status, CandidateStatus.REJECTED)

    def test_cannot_promote_without_verification_step(self) -> None:
        s0 = TrustedState.genesis(content_payload={}, invariant_registry_version=1)
        c = CandidateState.build(parent=s0, patch_payload={"p": 1})
        with self.assertRaises(ValueError):
            c.mark_promoted()  # skipped mark_under_verification()

    def test_cannot_double_promote(self) -> None:
        s0 = TrustedState.genesis(content_payload={}, invariant_registry_version=1)
        c = CandidateState.build(parent=s0, patch_payload={"p": 1})
        c.mark_under_verification()
        c.mark_promoted()
        with self.assertRaises(ValueError):
            c.mark_promoted()

    def test_rejected_candidate_never_becomes_a_trusted_state(self) -> None:
        """Direct check of the paper's own invariant (Section IV-A):
        'a rejected candidate never becomes the base for the next
        iteration.' Attempting to promote a rejected candidate must
        fail, not silently succeed."""
        s0 = TrustedState.genesis(content_payload={}, invariant_registry_version=1)
        c = CandidateState.build(parent=s0, patch_payload={"p": 1})
        c.mark_under_verification()
        c.mark_rejected()
        with self.assertRaises(ValueError):
            TrustedState.promoted_from(
                candidate=c, parent=s0, content_payload={"v": 1}, invariant_registry_version=1
            )


if __name__ == "__main__":
    unittest.main()
