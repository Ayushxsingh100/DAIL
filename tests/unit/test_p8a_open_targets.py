"""Open repair targets in ``decide`` (P8a; C-196). Expected values come from the decided text:

"For an open target, a FAIL result on the candidate does not block promotion, and the invariant
stays VIOLATED in the new trusted state with the fresh FAIL evidence. Every other required invariant
is decided exactly as before. An open target must be VIOLATED in the parent (the request is refused
otherwise), so the rule can never hide a regression of a PROTECTED invariant. It still needs a fresh
verification result: UNKNOWN, UNSUPPORTED or VERIFIER_ERROR on it blocks as before, and a missing
result blocks. ... The default is no open target, so every existing behaviour, including Doc 15
§13.2 'SEC FAIL + FUNC PASS -> REJECT', is unchanged. The open targets of each transition are
recorded in its decision evidence."

The world is the canonical one of ``tests.promotion_builders``: INV-SEC-001 is VIOLATED in the
parent, the other three invariants are PROTECTED.
"""

from __future__ import annotations

import unittest
from typing import Any

from core.domain.enums import DecisionType, VerificationResult
from core.domain.promotion import (
    DecisionReason,
    OracleVerdict,
    PromotionEvidence,
    PromotionInputError,
    ProofSource,
)
from core.promotion.decide import check_open_targets, decide
from tests.promotion_builders import (
    DECISION_ID,
    ERROR,
    FAIL,
    FUNC1,
    NOW,
    PASS,
    SEC1,
    SEC2,
    UNKNOWN,
    UNSUPPORTED,
    World,
    make_world,
    record,
    run,
    target,
)

D = DecisionType
R = DecisionReason


def decide_open(world: World, open_targets: Any, **options: Any):  # type: ignore[no-untyped-def]
    return decide(
        world.candidate,
        world.trusted,
        world.impact,
        world.verification,
        world.policy,
        decision_id=options.pop("decision_id", DECISION_ID),
        now=NOW,
        open_targets=open_targets,
        **options,
    )


class TestFailOnAnOpenTarget(unittest.TestCase):
    def test_a_fail_on_an_open_target_promotes(self) -> None:
        world = make_world(results={target(SEC1): FAIL})
        outcome = decide_open(world, (SEC1,))
        self.assertIs(outcome.decision.decision, D.PROMOTE)
        self.assertIs(outcome.decision.reason, R.ALL_REQUIRED_PROVEN)

    def test_without_the_open_target_the_same_fail_rejects(self) -> None:
        # Doc 15 §13.2 "SEC FAIL + FUNC PASS -> REJECT" is unchanged by default
        world = make_world(results={target(SEC1): FAIL})
        for outcome in (run(world), decide_open(world, ())):
            with self.subTest(outcome=outcome.decision.decision_id):
                self.assertIs(outcome.decision.decision, D.REJECT)
                self.assertIs(outcome.decision.reason, R.REQUIRED_CHECK_FAILED)

    def test_the_fail_is_the_fresh_evidence_of_the_open_target(self) -> None:
        world = make_world(results={target(SEC1): FAIL})
        failed = world.records[target(SEC1)]
        outcome = decide_open(world, (SEC1,))
        check = next(c for c in outcome.decision.required_checks if c.target_id == target(SEC1))
        self.assertIs(check.source, ProofSource.VERIFIED)
        self.assertEqual(check.verification_id, failed.verification_id)
        self.assertIn(failed.verification_id, outcome.decision.supporting_results)
        entry = next(e for e in outcome.proof_plan if e.invariant_id == SEC1)
        self.assertIs(entry.source, ProofSource.VERIFIED)
        self.assertEqual(entry.verification_id, failed.verification_id)

    def test_a_pass_on_an_open_target_still_promotes(self) -> None:
        world = make_world()
        outcome = decide_open(world, (SEC1,))
        self.assertIs(outcome.decision.decision, D.PROMOTE)

    def test_the_open_targets_are_recorded_in_the_decision_evidence(self) -> None:
        world = make_world(results={target(SEC1): FAIL})
        outcome = decide_open(world, (SEC1,))
        self.assertEqual(outcome.evidence.open_targets, (SEC1,))
        self.assertEqual(outcome.evidence.to_dict()["open_targets"], [SEC1])
        again = PromotionEvidence.from_dict(outcome.evidence.to_dict())
        self.assertEqual(again, outcome.evidence)

    def test_no_open_target_leaves_the_evidence_record_as_it_was(self) -> None:
        # the field is absent from the record (and from its hash) when there is no open target
        outcome = run(make_world())
        self.assertEqual(outcome.evidence.open_targets, ())
        self.assertNotIn("open_targets", outcome.evidence.to_dict())
        self.assertEqual(PromotionEvidence.from_dict(outcome.evidence.to_dict()), outcome.evidence)

    def test_an_insufficient_fail_on_an_open_target_does_not_promote(self) -> None:
        # the FAIL must come from the definition's verifier, like a PASS
        world = make_world()
        definition = world.definitions[SEC1]
        wrong = record(
            world.candidate, target(SEC1), FAIL, definition=definition, verifier=("x", "9"), n=50
        )
        world = make_world(results={target(SEC1): wrong})
        outcome = decide_open(world, (SEC1,))
        self.assertIsNot(outcome.decision.decision, D.PROMOTE)

    def test_a_fresh_but_insufficient_fail_does_not_promote(self) -> None:
        # fresh (same candidate, invariant and verifier version) but another verifier id, or a
        # level below L1: not sufficient evidence (mutation M5 survived the stale case above)
        world = make_world()
        definition = world.definitions[SEC1]
        for n, options in enumerate(
            ({"verifier": ("other.verifier", definition.verifier_version)}, {"level": "L0"})
        ):
            with self.subTest(options=options):
                weak = record(
                    world.candidate, target(SEC1), FAIL, definition=definition, n=60 + n, **options
                )
                outcome = decide_open(make_world(results={target(SEC1): weak}), (SEC1,))
                self.assertIs(outcome.decision.decision, D.REJECT)
                self.assertIs(outcome.decision.reason, R.EVIDENCE_NOT_SUFFICIENT)

    def test_an_oracle_fail_on_an_open_target_is_not_a_conflict(self) -> None:
        world = make_world(results={target(SEC1): FAIL})
        verdict = OracleVerdict(SEC1, 1, VerificationResult.FAIL, "oracle-1.0")
        outcome = decide_open(world, (SEC1,), oracle_verdicts=(verdict,))
        self.assertIs(outcome.decision.decision, D.PROMOTE)


class TestOpenTargetsStillBlock(unittest.TestCase):
    def test_a_non_success_on_an_open_target_blocks_as_before(self) -> None:
        for result, decision, reason in (
            (UNKNOWN, D.RETRY, R.REQUIRED_UNKNOWN),
            (UNSUPPORTED, D.REJECT, R.REQUIRED_UNSUPPORTED),
            (ERROR, D.ESCALATE, R.VERIFIER_ERROR),
        ):
            with self.subTest(result=result.value):
                world = make_world(results={target(SEC1): result})
                outcome = decide_open(world, (SEC1,))
                self.assertIs(outcome.decision.decision, decision)
                self.assertIs(outcome.decision.reason, reason)
                self.assertEqual(outcome.decision.decision, run(world).decision.decision)

    def test_a_missing_result_on_an_open_target_blocks(self) -> None:
        world = make_world(results={target(SEC1): None})
        outcome = decide_open(world, (SEC1,))
        self.assertIs(outcome.decision.decision, D.REJECT)
        self.assertIs(outcome.decision.reason, R.INSUFFICIENT_EVIDENCE)

    def test_a_protected_invariant_that_fails_still_rejects(self) -> None:
        world = make_world(results={target(SEC1): FAIL, target(FUNC1): FAIL})
        outcome = decide_open(world, (SEC1,))
        self.assertIs(outcome.decision.decision, D.REJECT)
        self.assertIs(outcome.decision.reason, R.REQUIRED_CHECK_FAILED)
        self.assertIn(target(FUNC1), {c.target for c in outcome.decision.blocking_conditions})
        self.assertNotIn(target(SEC1), {c.target for c in outcome.decision.blocking_conditions})

    def test_the_gates_still_block(self) -> None:
        world = make_world(results={target(SEC1): FAIL, "STRUCTURAL": FAIL})
        outcome = decide_open(world, (SEC1,))
        self.assertIs(outcome.decision.decision, D.REJECT)
        self.assertIs(outcome.decision.reason, R.STRUCTURAL_FAILURE)


class TestRefusedOpenTargets(unittest.TestCase):
    def test_a_target_that_is_not_violated_in_the_parent_is_refused(self) -> None:
        world = make_world(results={target(FUNC1): FAIL})
        for name in (FUNC1, SEC2):  # PROTECTED in the parent
            with self.subTest(target=name), self.assertRaises(PromotionInputError):
                decide_open(world, (name,))
            with self.subTest(target=name, check="direct"), self.assertRaises(PromotionInputError):
                check_open_targets(world.trusted, world.policy, (name,))

    def test_a_target_that_is_not_on_the_parent_is_refused(self) -> None:
        world = make_world()
        for bad in (("INV-NEW-001",), ("",), (SEC1, SEC1), "INV-SEC-001"):
            with self.subTest(open_targets=bad), self.assertRaises(PromotionInputError):
                decide_open(world, bad)

    def test_a_violated_target_is_accepted(self) -> None:
        world = make_world()
        self.assertEqual(check_open_targets(world.trusted, world.policy, (SEC1,)), (SEC1,))
        self.assertEqual(check_open_targets(world.trusted, world.policy, ()), ())


class TestDefaultUnchanged(unittest.TestCase):
    def test_empty_open_targets_reproduce_every_decision(self) -> None:
        worlds = [
            make_world(),
            make_world(results={target(SEC1): FAIL}),
            make_world(results={target(FUNC1): FAIL}),
            make_world(results={target(SEC1): UNKNOWN}),
            make_world(results={target(SEC1): None}),
            make_world(results={"CONSISTENCY": FAIL}),
            make_world(automatic_enabled=False),
            make_world(carry=()),
        ]
        for n, world in enumerate(worlds):
            with self.subTest(world=n):
                before = run(world)
                after = decide_open(world, ())
                self.assertEqual(after.decision.content_hash, before.decision.content_hash)
                self.assertEqual(after.evidence.content_hash, before.evidence.content_hash)
                self.assertEqual(after.proof_plan, before.proof_plan)

    def test_pass_and_default_give_the_same_record(self) -> None:
        world = make_world(results={target(SEC1): PASS})
        self.assertEqual(run(world).decision.to_dict(), decide_open(world, ()).decision.to_dict())


if __name__ == "__main__":
    unittest.main()
