"""The 20 canonical fixtures through the whole pipeline (P5a step 7; Doc 12 §5-§7; Doc 15 §12.2).

For every fixture the real pipeline runs: normalise the configuration (and its parent), identity,
graphs, impact, then verification of the full work set (all four invariants plus the baseline items
P4 lists). The expected values are the hand-written ``expected.json`` results (D2, derived by the
external reviewer from registry-v1.0, not computed): the result of INV-SEC-001, INV-SEC-002 and
INV-SEC-003, and the IPv4 and IPv6 clauses of the first two.

INV-FUNC-001 is not implemented in P5a. The interim assertion is that it is UNSUPPORTED
``verifier.not_available`` and never PASS; P5b replaces it. For the same reason the aggregate with
INV-FUNC-001 required is INSUFFICIENT_PROOF, never PASS, unless a security result already FAILs.
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

    def test_the_functional_invariant_is_unsupported_and_never_pass_for_now(self) -> None:
        for fixture_id in fixtures():
            with self.subTest(fixture=fixture_id):
                _, report = world(fixture_id)
                func = next(i for i in report.results if i.target_id == f"INVARIANT:{FUNC}:1")
                self.assertEqual(
                    (func.result, func.reason),
                    (VerificationResult.UNSUPPORTED, VerificationReason.VERIFIER_NOT_AVAILABLE),
                )

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

    def test_with_the_functional_invariant_required_nothing_passes_for_now(self) -> None:
        # the interim: INV-FUNC-001 is UNSUPPORTED, so the aggregate is never PASS; a security
        # FAIL still makes it FAIL
        for fixture_id, fx in fixtures().items():
            wanted = [expected(fx, name)["result"] for name in SEC]
            hand = AggregateResult.FAIL if "FAIL" in wanted else AggregateResult.INSUFFICIENT_PROOF
            with self.subTest(fixture=fixture_id):
                self.assertIs(self.verdict(fixture_id, (*SEC, FUNC)), hand)


if __name__ == "__main__":
    unittest.main()
