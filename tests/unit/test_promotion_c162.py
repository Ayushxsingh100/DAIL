"""C-162, the blocking condition of the P6a verdict: a target id has at most one result, whatever
its type (P6b step 1; Doc 09 §18, §30, Doc 12 §17).

HAND EXPECTATIONS, written before the fix and before any run of ``decide`` on these reports:

(1) ``VerificationReport`` refuses two results with the same ``target_id`` even when their target
    types differ.
(2) ``decide`` looks each required item up by the type its kind requires (INVARIANT for an
    invariant, RESOURCE for a baseline item, STRUCTURAL for a gate) and examines every result whose
    target id equals a required id.
(3) A report that holds a second result for a required target id, or a result of the wrong type for
    it, is an INCONSISTENT_REPORTS REJECT condition, and a FAIL among those results stays blocking.

So in the canonical world (``tests/promotion_builders.py``): an INVARIANT-typed FAIL for
INV-SEC-001,
INV-FUNC-001 or a ``RESOURCE:`` baseline item, beside a STRUCTURAL-typed PASS with the same target
id, is REJECT with INCONSISTENT_REPORTS *and* REQUIRED_CHECK_FAILED among the blocking conditions
(never PROMOTE). A genuine PASS beside a decoy FAIL is REJECT too. A wrong-type result alone is not
proof: the item has no proof (INSUFFICIENT_EVIDENCE) and the report is inconsistent.

Such a report cannot be built through the domain once (1) holds, so the tests inject the extra
result into a valid report and recompute its hash (which is what a corrupted store could give).
"""

from __future__ import annotations

import dataclasses
import random
import unittest
from collections.abc import Iterable

from core.domain.enums import DecisionType, VerificationResult
from core.domain.errors import DomainValidationError
from core.domain.promotion import DecisionReason
from core.domain.verification import (
    VerificationReport,
    VerificationResultRecord,
    VerificationTargetType,
    _summary,
)
from tests.domain_builders import uid
from tests.promotion_builders import (
    ALL,
    BASELINE_ITEM,
    ERROR,
    FAIL,
    FUNC1,
    GATES,
    PASS,
    SEC1,
    UNKNOWN,
    UNSUPPORTED,
    World,
    make_world,
    record,
    report_of,
    run,
    target,
)

D, R, T = DecisionType, DecisionReason, VerificationTargetType


def with_extra(
    world: World,
    extras: Iterable[VerificationResultRecord] = (),
    drop: Iterable[tuple[VerificationTargetType, str]] = (),
) -> World:
    """The world with ``extras`` added to the report and the ``drop`` pairs removed, without going
    through the domain checks (the hash is recomputed so that it is not what stops the decision)."""
    gone = set(drop)
    kept = [r for r in world.verification.results if (r.target_type, r.target_id) not in gone]
    report = report_of(world.candidate, kept)
    ordered = tuple(sorted([*kept, *extras], key=VerificationResultRecord.sort_key))
    object.__setattr__(report, "results", ordered)
    object.__setattr__(report, "content_hash", report.compute_hash())
    return dataclasses.replace(world, verification=report)


def decoy(
    world: World,
    target_id: str,
    result: VerificationResult = PASS,
    as_type: VerificationTargetType = T.STRUCTURAL,
    n: int = 0,
) -> VerificationResultRecord:
    """A result for ``target_id`` under another target type (a STRUCTURAL-typed PASS by default)."""
    base = world.records[target_id]
    return dataclasses.replace(
        base,
        target_type=as_type,
        verification_id=uid(7500 + n),
        result=result,
        reason=None if result is PASS else record(world.candidate, "STRUCTURAL", FAIL).reason,
        evidence={**base.evidence, "result": result.value},
    )


def codes(world: World) -> list[DecisionReason]:
    return [c.code for c in run(world).decision.blocking_conditions]


class TestTheDomainRefusesTwoResultsForOneTargetId(unittest.TestCase):
    """C-162 (1)."""

    def test_two_results_for_one_target_id_under_two_types_are_refused(self) -> None:
        world = make_world()
        good = world.records[target(FUNC1)]
        other = decoy(world, target(FUNC1))
        self.assertNotEqual(good.target_type, other.target_type)
        self.assertEqual(good.target_id, other.target_id)
        results = [*world.records.values(), other]
        with self.assertRaises(DomainValidationError) as caught:
            VerificationReport.create(
                candidate_id=world.candidate.candidate_id,
                candidate_hash=world.candidate.state_hash or "",
                results=results,
                verifier_invocations=len(results),
                verifier_set_version="dail-verify-1",
            )
        self.assertIn("target", str(caught.exception))

    def test_the_gate_and_the_baseline_item_are_protected_too(self) -> None:
        world = make_world()
        for tid in ("STRUCTURAL", BASELINE_ITEM):
            other = decoy(world, tid, as_type=T.SECURITY_PREDICATE)
            results = [*world.records.values(), other]
            with self.subTest(target=tid), self.assertRaises(DomainValidationError):
                VerificationReport.create(
                    candidate_id=world.candidate.candidate_id,
                    candidate_hash=world.candidate.state_hash or "",
                    results=results,
                    verifier_invocations=len(results),
                    verifier_set_version="dail-verify-1",
                )

    def test_a_stored_report_with_two_results_for_one_target_id_is_refused_on_reading(self) -> None:
        world = with_extra(make_world(), [decoy(make_world(), target(FUNC1))])
        report = world.verification
        data = report.to_dict()
        # a store that was corrupted consistently: the summary and the hash match the results
        data["summary"] = _summary(report.results, report.verifier_invocations)
        self.assertEqual(data["content_hash"], report.compute_hash())
        with self.assertRaises(DomainValidationError) as caught:
            VerificationReport.from_dict(data)
        self.assertIn("target", str(caught.exception))

    def test_distinct_target_ids_are_still_accepted(self) -> None:
        world = make_world()
        self.assertEqual(len(world.verification.results), len(world.records))


class TestTheReviewersReproductions(unittest.TestCase):
    """C-162 (2) and (3): the decoy STRUCTURAL-typed PASS beside an INVARIANT FAIL (or a RESOURCE
    FAIL) hid the FAIL and gave PROMOTE."""

    def check(self, tid: str) -> None:
        world = make_world(results={tid: FAIL})
        world = with_extra(world, [decoy(world, tid, PASS)])
        found = codes(world)
        out = run(world)
        self.assertEqual(out.decision.decision, D.REJECT)
        self.assertIn(R.INCONSISTENT_REPORTS, found)
        self.assertIn(R.REQUIRED_CHECK_FAILED, found)  # the FAIL stays blocking
        self.assertEqual(out.decision.reason, R.INCONSISTENT_REPORTS)

    def test_inv_sec_001(self) -> None:
        self.check(target(SEC1))

    def test_inv_func_001(self) -> None:
        self.check(target(FUNC1))

    def test_a_resource_baseline_item(self) -> None:
        self.check(BASELINE_ITEM)


class TestEveryMatchingResultIsExamined(unittest.TestCase):
    def test_a_decoy_fail_beside_a_genuine_pass_is_blocking(self) -> None:
        world = make_world()
        world = with_extra(world, [decoy(world, target(FUNC1), FAIL)])
        out = run(world)
        self.assertEqual(out.decision.decision, D.REJECT)
        self.assertIn(R.INCONSISTENT_REPORTS, [c.code for c in out.decision.blocking_conditions])
        self.assertIn(R.REQUIRED_CHECK_FAILED, [c.code for c in out.decision.blocking_conditions])

    def test_a_duplicate_pass_alone_is_still_an_inconsistent_report(self) -> None:
        world = make_world()
        world = with_extra(world, [decoy(world, target(SEC1), PASS)])
        out = run(world)
        self.assertEqual(
            (out.decision.decision, out.decision.reason), (D.REJECT, R.INCONSISTENT_REPORTS)
        )
        # the item that has two results is not proven by either
        self.assertNotIn(SEC1, {e.invariant_id for e in out.proof_plan})

    def test_a_duplicate_gate_result_is_inconsistent_and_its_fail_is_blocking(self) -> None:
        world = make_world()
        world = with_extra(world, [decoy(world, "STRUCTURAL", FAIL, as_type=T.SECURITY_PREDICATE)])
        found = codes(world)
        self.assertIn(R.INCONSISTENT_REPORTS, found)
        self.assertIn(R.STRUCTURAL_FAILURE, found)
        self.assertEqual(run(world).decision.decision, D.REJECT)

    def test_a_result_of_the_wrong_type_alone_is_not_proof(self) -> None:
        world = make_world()
        world = with_extra(
            world,
            [decoy(world, target(FUNC1), PASS)],
            drop=[(T.INVARIANT, target(FUNC1))],
        )
        out = run(world)
        found = [c.code for c in out.decision.blocking_conditions]
        self.assertEqual(out.decision.decision, D.REJECT)
        self.assertIn(R.INCONSISTENT_REPORTS, found)
        self.assertIn(R.INSUFFICIENT_EVIDENCE, found)
        self.assertNotIn(FUNC1, {e.invariant_id for e in out.proof_plan})

    def test_a_decoy_for_an_id_nobody_requires_is_ignored(self) -> None:
        world = make_world()
        stray = dataclasses.replace(
            world.records["STRUCTURAL"],
            target_type=T.SECURITY_PREDICATE,
            target_id="SOMETHING-ELSE",
            verification_id=uid(7600),
        )
        out = run(with_extra(world, [stray]))
        self.assertEqual(out.decision.decision, D.PROMOTE)

    def test_a_clean_report_is_unchanged(self) -> None:
        self.assertEqual(run(make_world()).decision.decision, D.PROMOTE)


class TestAFailNeverPromotesWhateverTheDecoys(unittest.TestCase):
    """The property: for any report, a FAIL on a required target never gives PROMOTE, even with
    decoy results of other types, and the order of the results does not matter."""

    SEEDS = (20261029, 1, 7, 424242, 99991)
    REQUIRED = (*GATES, *(target(i) for i in ALL), BASELINE_ITEM)
    TYPES = (T.STRUCTURAL, T.SECURITY_PREDICATE, T.RESOURCE, T.INVARIANT)
    VALUES = (PASS, FAIL, UNKNOWN, UNSUPPORTED, ERROR)

    def generated(self, rng: random.Random) -> tuple[World, bool]:
        failing = rng.sample(self.REQUIRED, rng.randint(0, 2))
        world = make_world(results={t: FAIL for t in failing if t in self.owed()})
        genuine_fail = any(t in self.owed() for t in failing)
        extras = []
        for k in range(rng.randint(0, 4)):
            tid = rng.choice([t for t in self.REQUIRED if t in world.records])
            as_type = rng.choice([t for t in self.TYPES if t != world.records[tid].target_type])
            value = rng.choice(self.VALUES)
            try:
                extras.append(decoy(world, tid, value, as_type=as_type, n=k))
            except DomainValidationError:
                continue
        return with_extra(world, extras), genuine_fail or any(
            e.result is FAIL and e.target_id in self.REQUIRED for e in extras
        )

    def owed(self) -> set[str]:
        return {*GATES, target(SEC1), target(FUNC1), BASELINE_ITEM}

    def test_a_fail_on_a_required_target_never_promotes(self) -> None:
        promoted_clean = 0
        for seed in self.SEEDS:
            rng = random.Random(seed)
            for n in range(40):
                world, has_fail = self.generated(rng)
                out = run(world)
                if has_fail:
                    self.assertIs(out.decision.decision, D.REJECT, f"seed {seed} world {n}")
                promoted_clean += out.decision.decision is D.PROMOTE
        # decoys of any type spoil a report: the clean ones still promote, and not every world does
        self.assertGreater(promoted_clean, 0)

    def test_the_decision_does_not_depend_on_the_order_of_the_results(self) -> None:
        rng = random.Random(self.SEEDS[0])
        for _ in range(60):
            world, _ = self.generated(rng)
            want = run(world)
            shuffled = list(world.verification.results)
            rng.shuffle(shuffled)
            report = world.verification
            object.__setattr__(report, "results", tuple(shuffled))
            object.__setattr__(report, "content_hash", report.compute_hash())
            self.assertEqual(run(world).decision.content_hash, want.decision.content_hash)


if __name__ == "__main__":
    unittest.main()
