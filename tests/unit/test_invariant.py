import unittest

from core.domain.enums import InvariantLifecycleState, InvariantType
from core.domain.invariant import (
    DuplicateInvariantError,
    InvalidLifecycleTransition,
    Invariant,
    InvariantNotFoundError,
    InvariantRegistry,
)


def _make_invariant(invariant_id: str = "INV-SEC-001", version: int = 1) -> Invariant:
    return Invariant(
        invariant_id=invariant_id,
        version=version,
        description="No security group allows ingress from 0.0.0.0/0 to port 22",
        invariant_type=InvariantType.SECURITY,
        predicate_id="ckv_aws_24",
        scope_id="aws_security_group",
        applicability_rule="resource_type == 'aws_security_group'",
        verification_policy_id="checkov-default",
        verifier_version="checkov==3.2.526",
    )


class TestInvariantLifecycleTransitions(unittest.TestCase):
    """P1 exit criterion: 'Forbidden lifecycle transitions are rejected.'"""

    def test_starts_registered(self) -> None:
        inv = _make_invariant()
        self.assertEqual(inv.lifecycle_state, InvariantLifecycleState.REGISTERED)

    def test_legal_happy_path_transition_sequence(self) -> None:
        inv = _make_invariant()
        inv.transition_to(InvariantLifecycleState.VERIFYING)
        inv.transition_to(InvariantLifecycleState.VERIFIED)
        inv.transition_to(InvariantLifecycleState.PROTECTED)
        self.assertTrue(inv.is_protected())

    def test_cannot_skip_verifying(self) -> None:
        """REGISTERED -> PROTECTED directly is not a legal transition;
        every invariant must pass through VERIFYING first."""
        inv = _make_invariant()
        with self.assertRaises(InvalidLifecycleTransition):
            inv.transition_to(InvariantLifecycleState.PROTECTED)

    def test_cannot_go_backwards_from_protected_to_registered(self) -> None:
        inv = _make_invariant()
        inv.transition_to(InvariantLifecycleState.VERIFYING)
        inv.transition_to(InvariantLifecycleState.VERIFIED)
        inv.transition_to(InvariantLifecycleState.PROTECTED)
        with self.assertRaises(InvalidLifecycleTransition):
            inv.transition_to(InvariantLifecycleState.REGISTERED)

    def test_protected_invariant_becomes_affected_then_reverifies(self) -> None:
        """This is the exact cycle Section IV-E describes: a protected
        invariant whose evidence is invalidated moves to AFFECTED, then
        must go through REVERIFYING before it can be PROTECTED again."""
        inv = _make_invariant()
        inv.transition_to(InvariantLifecycleState.VERIFYING)
        inv.transition_to(InvariantLifecycleState.VERIFIED)
        inv.transition_to(InvariantLifecycleState.PROTECTED)
        self.assertTrue(inv.is_protected())

        inv.transition_to(InvariantLifecycleState.AFFECTED)
        self.assertFalse(inv.is_protected(), "AFFECTED must not count as protected")

        inv.transition_to(InvariantLifecycleState.REVERIFYING)
        inv.transition_to(InvariantLifecycleState.PASS)
        # PASS is not, by itself, PROTECTED -- Section IV-E: "a protected
        # invariant is not merely a historical PASS."
        self.assertFalse(inv.is_protected())
        inv.transition_to(InvariantLifecycleState.VERIFIED)
        inv.transition_to(InvariantLifecycleState.PROTECTED)
        self.assertTrue(inv.is_protected())

    def test_affected_cannot_jump_straight_to_protected(self) -> None:
        inv = _make_invariant()
        inv.transition_to(InvariantLifecycleState.VERIFYING)
        inv.transition_to(InvariantLifecycleState.VERIFIED)
        inv.transition_to(InvariantLifecycleState.PROTECTED)
        inv.transition_to(InvariantLifecycleState.AFFECTED)
        with self.assertRaises(InvalidLifecycleTransition):
            inv.transition_to(InvariantLifecycleState.PROTECTED)


class TestInvariantValidation(unittest.TestCase):
    def test_empty_invariant_id_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Invariant(
                invariant_id="",
                version=1,
                description="x",
                invariant_type=InvariantType.SECURITY,
                predicate_id="p",
                scope_id="s",
                applicability_rule="r",
                verification_policy_id="v",
                verifier_version="1.0",
            )

    def test_version_below_one_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _make_invariant(version=0)


class TestInvariantRegistry(unittest.TestCase):
    def test_register_and_get(self) -> None:
        registry = InvariantRegistry()
        inv = _make_invariant()
        registry.register(inv)
        self.assertEqual(registry.get("INV-SEC-001", 1), inv)

    def test_duplicate_registration_rejected(self) -> None:
        registry = InvariantRegistry()
        registry.register(_make_invariant())
        with self.assertRaises(DuplicateInvariantError):
            registry.register(_make_invariant())

    def test_get_unknown_invariant_raises(self) -> None:
        registry = InvariantRegistry()
        with self.assertRaises(InvariantNotFoundError):
            registry.get("INV-DOES-NOT-EXIST", 1)

    def test_multiple_versions_coexist(self) -> None:
        registry = InvariantRegistry()
        registry.register(_make_invariant(version=1))
        registry.register(_make_invariant(version=2))
        self.assertEqual(len(registry), 2)
        self.assertEqual(registry.latest_version("INV-SEC-001").version, 2)

    def test_all_protected_only_returns_protected_invariants(self) -> None:
        registry = InvariantRegistry()
        protected = _make_invariant("INV-SEC-001", 1)
        protected.transition_to(InvariantLifecycleState.VERIFYING)
        protected.transition_to(InvariantLifecycleState.VERIFIED)
        protected.transition_to(InvariantLifecycleState.PROTECTED)

        unprotected = _make_invariant("INV-FUNC-001", 1)  # still REGISTERED

        registry.register(protected)
        registry.register(unprotected)

        result = registry.all_protected()
        self.assertEqual(result, [protected])


if __name__ == "__main__":
    unittest.main()
