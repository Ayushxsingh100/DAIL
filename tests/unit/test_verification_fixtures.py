"""The 20 canonical fixtures through the whole pipeline (P5a step 7; Doc 12 §5-§7; Doc 15 §12.2).

For every fixture the real pipeline runs: normalise the configuration (and its parent), identity,
graphs, impact, then verification of the full work set (all four invariants plus the baseline items
P4 lists). The expected values are the hand-written ``expected.json`` results (D2, derived by the
external reviewer from registry-v1.0, not computed): the result of INV-SEC-001, INV-SEC-002 and
INV-SEC-003, and the IPv4 and IPv6 clauses of the first two.

INV-FUNC-001 (P5b) is compared with ``expected.json`` in the same way. The aggregate over all four
invariants (Doc 09 §18) is FAIL if any expected result is FAIL, PASS if all four are PASS, and
INSUFFICIENT_PROOF otherwise (an expected UNKNOWN or UNSUPPORTED). It is computed from the engine's
own records, never taken from a constant.
"""

from __future__ import annotations

import unittest
from functools import cache
from typing import Any

from core.domain.enums import VerificationResult
from core.domain.verification import (
    AggregateResult,
    VerificationReason,
    VerificationReport,
    aggregate,
)
from core.verification.engine import run_work_set
from core.verification.inputs import VerificationInputs
from tests import fixture_catalog as fc
from tests.pipeline_builders import (
    counting_ids,
    fixed_clock,
    inputs_for_directories,
    invariant_item,
    required_for,
)

SEC = ("INV-SEC-001", "INV-SEC-002", "INV-SEC-003")
FUNC = "INV-FUNC-001"
ROOT = fc.REPO_ROOT


def fixtures() -> dict[str, fc.Fixture]:
    found = {fx.data["fixture_id"]: fx for fx in fc.load_all().values()}
    return dict(sorted(found.items()))


@cache
def world(fixture_id: str) -> tuple[VerificationInputs, VerificationReport]:
    fx = fixtures()[fixture_id]
    binding = fx.data["bindings"][FUNC]
    inputs = inputs_for_directories(
        fx.data["config"],
        fx.data.get("parent"),
        source=binding["S"],
        destination=binding["D"],
        root=ROOT,
    )
    work = [invariant_item(name) for name in (*SEC, FUNC)]
    if inputs.impact is not None:
        work += [w for w in inputs.impact.verification_work if w.target_id.startswith("RESOURCE:")]
    report = run_work_set(work, inputs, clock=fixed_clock(), ids=counting_ids())
    return inputs, report


def expected(fx: fc.Fixture, invariant: str) -> dict[str, Any]:
    return dict(fx.data["results"][invariant])


class TestFixtures(unittest.TestCase):
    def test_there_are_twenty_fixtures(self) -> None:
        self.assertEqual(len(fixtures()), fc.EXPECTED_FIXTURE_COUNT)

    def test_security_results_and_clauses_equal_expected_json(self) -> None:
        for fixture_id, fx in fixtures().items():
            _, report = world(fixture_id)
            found = {item.target_id: item for item in report.results}
            for name in SEC:
                with self.subTest(fixture=fixture_id, invariant=name):
                    item = found[f"INVARIANT:{name}:1"]
                    want = expected(fx, name)
                    self.assertEqual(item.result.value, want["result"])
                    if "clauses" in want and want["clauses"] is not None:
                        got = {
                            key.lower(): value.value for key, value in (item.clauses or {}).items()
                        }
                        self.assertEqual(got, dict(want["clauses"]))
                    else:
                        self.assertIsNone(item.clauses)

    def test_the_functional_result_equals_expected_json(self) -> None:
        for fixture_id, fx in fixtures().items():
            with self.subTest(fixture=fixture_id):
                _, report = world(fixture_id)
                func = next(i for i in report.results if i.target_id == f"INVARIANT:{FUNC}:1")
                self.assertEqual(func.result.value, expected(fx, FUNC)["result"])
                self.assertIsNone(func.clauses)
                self.assertNotEqual(func.reason, VerificationReason.VERIFIER_NOT_AVAILABLE)
                self.assertIsNone(func.error)

    def test_the_functional_invariant_is_never_a_pass_unless_expected_json_says_so(self) -> None:
        for fixture_id, fx in fixtures().items():
            if expected(fx, FUNC)["result"] == "PASS":
                continue
            with self.subTest(fixture=fixture_id):
                _, report = world(fixture_id)
                func = next(i for i in report.results if i.target_id == f"INVARIANT:{FUNC}:1")
                self.assertIsNot(func.result, VerificationResult.PASS)

    def test_the_mandatory_gate_passes_on_every_sound_candidate(self) -> None:
        for fixture_id in fixtures():
            with self.subTest(fixture=fixture_id):
                _, report = world(fixture_id)
                found = {item.target_id: item for item in report.results}
                for gate in ("STRUCTURAL", "CONSISTENCY"):
                    self.assertEqual(
                        (found[gate].result, list(found[gate].observations["findings"])),
                        (VerificationResult.PASS, []),
                        gate,
                    )

    def test_every_report_is_sound_and_binds_to_the_candidate_hash(self) -> None:
        for fixture_id in fixtures():
            with self.subTest(fixture=fixture_id):
                inputs, report = world(fixture_id)
                self.assertEqual(report.candidate_hash, inputs.candidate_state_hash)
                self.assertEqual(VerificationReport.from_dict(report.to_dict()), report)
                for item in report.results:
                    self.assertEqual(item.candidate_hash, inputs.candidate_state_hash)
                    self.assertNotEqual(item.result, VerificationResult.VERIFIER_ERROR)

    def test_baseline_items_for_created_resources_are_answered(self) -> None:
        answered = 0
        for fixture_id in fixtures():
            inputs, report = world(fixture_id)
            if inputs.impact is None:
                continue
            created = {
                w.target_id
                for w in inputs.impact.verification_work
                if w.target_id.startswith("RESOURCE:")
            }
            found = {i.target_id for i in report.results if i.target_id.startswith("RESOURCE:")}
            with self.subTest(fixture=fixture_id):
                self.assertEqual(found, created)
            answered += len(created)
        self.assertGreater(answered, 0)


class TestAggregationOnFixtures(unittest.TestCase):
    """Doc 09 §18 over the security items, then with the functional invariant required."""

    def verdict(self, fixture_id: str, names: tuple[str, ...]) -> AggregateResult:
        inputs, report = world(fixture_id)
        needs = required_for(inputs, [invariant_item(name) for name in names])
        return aggregate(report.results, needs, candidate_hash=report.candidate_hash)

    def test_security_aggregate_follows_expected_json(self) -> None:
        for fixture_id, fx in fixtures().items():
            wanted = [expected(fx, name)["result"] for name in SEC]
            hand = AggregateResult.FAIL if "FAIL" in wanted else AggregateResult.PASS
            with self.subTest(fixture=fixture_id):
                self.assertIs(self.verdict(fixture_id, SEC), hand)

    def test_the_aggregate_over_all_four_invariants_follows_expected_json(self) -> None:
        for fixture_id, fx in fixtures().items():
            wanted = [expected(fx, name)["result"] for name in (*SEC, FUNC)]
            if "FAIL" in wanted:
                hand = AggregateResult.FAIL
            elif set(wanted) == {"PASS"}:
                hand = AggregateResult.PASS
            else:
                hand = AggregateResult.INSUFFICIENT_PROOF
            with self.subTest(fixture=fixture_id):
                self.assertIs(self.verdict(fixture_id, (*SEC, FUNC)), hand)


class TestCanonicalTransitions(unittest.TestCase):
    """The canonical scenario (CLAUDE.md): a candidate that fixes SSH and keeps the path is
    promotable, one that fixes SSH and breaks EC2 -> RDS must be rejected. Doc 09 §18, from the
    engine's own records."""

    SAFE = "canonical_safe_repair_promote_v1"
    BREAKS = "canonical_security_repair_breaks_function_reject_v1"

    def verdict(self, fixture_id: str, *, without_functional: bool = False) -> AggregateResult:
        inputs, report = world(fixture_id)
        needs = required_for(inputs, [invariant_item(name) for name in (*SEC, FUNC)])
        results = [
            r
            for r in report.results
            if not (without_functional and r.target_id == f"INVARIANT:{FUNC}:1")
        ]
        return aggregate(results, needs, candidate_hash=report.candidate_hash)

    def test_the_safe_repair_aggregates_to_pass(self) -> None:
        self.assertIs(self.verdict(self.SAFE), AggregateResult.PASS)

    def test_the_repair_that_breaks_the_database_path_aggregates_to_fail(self) -> None:
        self.assertIs(self.verdict(self.BREAKS), AggregateResult.FAIL)
        inputs, report = world(self.BREAKS)
        by_id = {r.target_id: r for r in report.results}
        # the security invariants hold; it is the functional one that fails (row 9: no ingress rule)
        for name in SEC:
            self.assertIs(by_id[f"INVARIANT:{name}:1"].result, VerificationResult.PASS)
        func = by_id[f"INVARIANT:{FUNC}:1"]
        self.assertEqual((func.result, func.observations["row"]), (VerificationResult.FAIL, 9))

    def test_without_the_functional_result_nothing_passes(self) -> None:
        # a missing required result is INSUFFICIENT_PROOF, never PASS (Doc 09 §18)
        self.assertIs(
            self.verdict(self.SAFE, without_functional=True), AggregateResult.INSUFFICIENT_PROOF
        )


if __name__ == "__main__":
    unittest.main()
