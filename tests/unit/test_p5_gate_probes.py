"""The four P5 gate probes (P5b step 6; Doc 15 §12.2; C-120(c), Doc 09 §11, §18, §30, §37).

The reviewer repeats these. Each is the executable form of one sentence:

(a) the ``unresolved`` direction form (C-120(c)) is UNSUPPORTED for every invariant that reads that
    direction, never "no rules": the ingress of any group for INV-SEC-001 and INV-SEC-002, the
    egress of ``SG(S)`` and the ingress of ``SG(D)`` for INV-FUNC-001;
(b) every verifier fault becomes VERIFIER_ERROR, never FAIL and never PASS, for each of the three
    verifiers, whether it raises or reads a stored view that is not the shape P3a writes;
(c) a stale or mismatched candidate hash, invariant version or verifier version is never
    sufficient, whatever the result says;
(d) the full pipeline on the canonical scenario: the SSH fix that keeps the path aggregates to
    PASS, the SSH fix that breaks EC2 -> RDS to FAIL.
"""

from __future__ import annotations

import dataclasses
import unittest
from typing import Any

from core.domain.enums import VerificationResult
from core.domain.jsonvalue import thaw_json
from core.domain.verification import (
    AggregateResult,
    VerificationReason,
    VerificationResultRecord,
    aggregate,
    sufficient,
)
from core.verification.dispatch import (
    DEFAULT_VERIFIERS,
    PUBLIC_INGRESS,
    RDS_PUBLIC_FLAG,
    REACHABILITY_CFG,
)
from core.verification.engine import run_work_set
from tests.func_builders import (
    APP_EGRESS,
    APP_GROUP,
    APP_TO_DB,
    DB_GROUP,
    canonical,
    edit,
    edits,
    with_attributes,
)
from tests.pipeline_builders import (
    counting_ids,
    fixed_clock,
    inputs_for,
    invariant_item,
    required_for,
)
from tests.security_builders import with_security
from tests.unit.test_verification_fixtures import world

P, F, S, E = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNSUPPORTED,
    VerificationResult.VERIFIER_ERROR,
)
R = VerificationReason
NAMES = ("INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001")
VAR = 'variable "u" {}\n'


def run(text: str, **overrides: Any) -> dict[str, VerificationResultRecord]:
    given = overrides.pop("given", None) or inputs_for(text)
    report = run_work_set(
        [invariant_item(name) for name in NAMES],
        given,
        clock=fixed_clock(),
        ids=counting_ids(),
        **overrides,
    )
    return {item.target_id: item for item in report.results}


def item(found: dict[str, VerificationResultRecord], name: str) -> VerificationResultRecord:
    return found[f"INVARIANT:{name}:1"]


class TestProbeA(unittest.TestCase):
    """The unresolved direction form is UNSUPPORTED, never "no rules"."""

    def test_the_ingress_of_the_database_group(self) -> None:
        # nothing targets the group by a rule resource, so it is not MIXED; its ingress is unknown
        text = VAR + edits(
            canonical(),
            (DB_GROUP, DB_GROUP.replace("  egress      = []", "  ingress     = var.u")),
            (APP_TO_DB, ""),
        )
        found = run(text)
        for name in ("INV-SEC-001", "INV-SEC-002", "INV-FUNC-001"):
            with self.subTest(invariant=name):
                self.assertEqual(
                    (item(found, name).result, item(found, name).reason), (S, R.FORMS_UNRESOLVED)
                )
        # INV-SEC-003 reads no security group: unaffected
        self.assertIs(item(found, "INV-SEC-003").result, P)

    def test_the_egress_of_the_application_group_matters_to_the_functional_invariant_only(
        self,
    ) -> None:
        text = VAR + edits(
            canonical(),
            (APP_GROUP, APP_GROUP.replace("  ingress     = []", "  egress      = var.u")),
            (APP_EGRESS, ""),
        )
        found = run(text)
        self.assertEqual(
            (item(found, "INV-FUNC-001").result, item(found, "INV-FUNC-001").reason),
            (S, R.FORMS_UNRESOLVED),
        )
        # the security predicates read ingress: the egress of a group is not read
        self.assertIs(item(found, "INV-SEC-001").result, P)

    def test_an_unresolved_direction_is_never_read_as_no_rules(self) -> None:
        # with no rules at all the database group would make the functional invariant FAIL
        # (row 9); an unresolved ingress must not be taken for "no rules"
        text = VAR + edits(
            canonical(),
            (DB_GROUP, DB_GROUP.replace("  egress      = []", "  ingress     = var.u")),
            (APP_TO_DB, ""),
        )
        func = item(run(text), "INV-FUNC-001")
        self.assertIsNot(func.result, F)
        self.assertIsNot(func.result, P)


class TestProbeB(unittest.TestCase):
    """Every verifier fault is VERIFIER_ERROR, never FAIL and never PASS."""

    KEYS = {"INV-SEC-001": PUBLIC_INGRESS, "INV-SEC-002": PUBLIC_INGRESS,
            "INV-SEC-003": RDS_PUBLIC_FLAG, "INV-FUNC-001": REACHABILITY_CFG}  # fmt: skip

    def test_a_verifier_that_raises(self) -> None:
        for name, key in self.KEYS.items():

            def boom(_definition: object, _inputs: object) -> object:
                raise RuntimeError("boom")

            table = {**DEFAULT_VERIFIERS, key: boom}
            found = run(canonical(), verifiers=table)
            with self.subTest(invariant=name):
                self.assertEqual(
                    (item(found, name).result, item(found, name).reason), (E, R.VERIFIER_ERROR)
                )
                self.assertEqual(dict(item(found, name).error or {})["type"], "RuntimeError")

    def test_a_stored_view_that_is_not_the_shape_p3a_writes(self) -> None:
        given = inputs_for(canonical())
        by_address = {r.address: r for r in given.candidate_resources}

        def swapped(address: str, damaged: Any) -> Any:
            rest = [r for r in given.candidate_resources if r.address != address]
            return dataclasses.replace(given, candidate_resources=(*rest, damaged))

        cases = {
            "the instance attributes (INV-FUNC-001 only)": (
                swapped(
                    "aws_instance.app",
                    with_attributes(
                        by_address["aws_instance.app"], {"subnet_id": {"form": "ATTRIBUTE"}}
                    ),
                ),
                {"INV-FUNC-001"},
            ),
            "the database security view (INV-SEC-003 only)": (
                swapped(
                    "aws_db_instance.database",
                    with_security(by_address["aws_db_instance.database"], {"surprise": 1}),
                ),
                {"INV-SEC-003"},
            ),
            "a group security view (the group readers: SEC-001, SEC-002, FUNC-001)": (
                swapped(
                    "aws_security_group.db", with_security(by_address["aws_security_group.db"], {})
                ),
                {"INV-SEC-001", "INV-SEC-002", "INV-FUNC-001"},
            ),
        }
        for label, (damaged, hit) in cases.items():
            found = run("", given=damaged)
            for name in NAMES:
                with self.subTest(case=label, invariant=name):
                    if name in hit:
                        self.assertEqual(
                            (item(found, name).result, item(found, name).reason),
                            (E, R.VERIFIER_ERROR),
                        )
                        self.assertEqual(dict(item(found, name).error or {})["type"], "ViewError")
                    else:
                        self.assertIsNot(item(found, name).result, E)

    def test_an_error_is_not_evidence_of_a_property(self) -> None:
        def boom(_definition: object, _inputs: object) -> object:
            raise RuntimeError("boom")

        found = run(canonical(), verifiers={**DEFAULT_VERIFIERS, REACHABILITY_CFG: boom})
        given = inputs_for(canonical())
        report_results = list(found.values())
        verdict = aggregate(
            report_results,
            required_for(given, [invariant_item(n) for n in NAMES]),
            candidate_hash=given.candidate_state_hash,
        )
        self.assertIs(verdict, AggregateResult.INSUFFICIENT_PROOF)


class TestProbeC(unittest.TestCase):
    """A stale or mismatched hash or version is never sufficient."""

    def setUp(self) -> None:
        self.given = inputs_for(canonical())
        self.found = run(canonical(), given=self.given)

    def args(self, name: str) -> dict[str, Any]:
        definition = self.given.invariant(name, 1)
        assert definition is not None
        return {
            "target_id": f"INVARIANT:{name}:1",
            "candidate_hash": self.given.candidate_state_hash,
            "invariant_id": name,
            "invariant_version": 1,
            "verifier_id": definition.verifier_id,
            "verifier_version": definition.verifier_version,
        }

    def test_a_sound_pass_is_sufficient_for_its_own_requirement_only(self) -> None:
        for name in NAMES:
            with self.subTest(invariant=name):
                self.assertIs(item(self.found, name).result, P)
                self.assertTrue(sufficient(item(self.found, name), **self.args(name)))

    def test_each_mismatch_makes_it_insufficient(self) -> None:
        for name in NAMES:
            record = item(self.found, name)
            for field, other in (
                ("candidate_hash", "b" * 64),
                ("invariant_version", 2),
                ("verifier_version", "2"),
                ("verifier_id", "someone.else"),
                ("target_id", "INVARIANT:INV-OTHER-001:1"),
            ):
                with self.subTest(invariant=name, field=field):
                    self.assertFalse(sufficient(record, **{**self.args(name), field: other}))

    def test_a_stale_set_of_results_never_aggregates_to_pass(self) -> None:
        needs = required_for(self.given, [invariant_item(n) for n in NAMES])
        results = list(self.found.values())
        self.assertIs(
            aggregate(results, needs, candidate_hash=self.given.candidate_state_hash),
            AggregateResult.PASS,
        )
        self.assertIs(
            aggregate(results, needs, candidate_hash="b" * 64), AggregateResult.INSUFFICIENT_PROOF
        )
        for name in NAMES:
            stale = [
                (
                    dataclasses.replace(r, candidate_hash="b" * 64)
                    if r.target_id.endswith(f"{name}:1")
                    else r
                )
                for r in results
            ]
            with self.subTest(stale=name):
                self.assertIs(
                    aggregate(stale, needs, candidate_hash=self.given.candidate_state_hash),
                    AggregateResult.INSUFFICIENT_PROOF,
                )

    def test_a_stale_fail_does_not_count_as_a_fail_either(self) -> None:
        # Doc 09 §30: a result for another candidate is never reused, whatever it says
        text = edit(canonical(), APP_TO_DB, "")
        given = inputs_for(text)
        found = run(text, given=given)
        self.assertIs(item(found, "INV-FUNC-001").result, F)
        needs = required_for(given, [invariant_item("INV-FUNC-001")])
        self.assertIs(
            aggregate(list(found.values()), needs, candidate_hash=given.candidate_state_hash),
            AggregateResult.FAIL,
        )
        self.assertIs(
            aggregate(list(found.values()), needs, candidate_hash="c" * 64),
            AggregateResult.INSUFFICIENT_PROOF,
        )


class TestProbeD(unittest.TestCase):
    """The canonical scenario through the whole pipeline (the real fixtures)."""

    def verdict(self, fixture_id: str) -> AggregateResult:
        given, report = world(fixture_id)
        needs = required_for(given, [invariant_item(n) for n in NAMES])
        return aggregate(report.results, needs, candidate_hash=report.candidate_hash)

    def test_the_trusted_state_has_public_ssh_open(self) -> None:
        _, report = world("canonical_baseline_eligible_v1")
        sec1 = next(r for r in report.results if r.target_id == "INVARIANT:INV-SEC-001:1")
        func = next(r for r in report.results if r.target_id == "INVARIANT:INV-FUNC-001:1")
        self.assertIs(sec1.result, F)  # SSH is open to the internet
        self.assertIs(func.result, P)  # and the path to the database works

    def test_the_ssh_fix_that_keeps_the_path_aggregates_to_pass(self) -> None:
        self.assertIs(self.verdict("canonical_safe_repair_promote_v1"), AggregateResult.PASS)

    def test_the_ssh_fix_that_breaks_the_path_aggregates_to_fail(self) -> None:
        self.assertIs(
            self.verdict("canonical_security_repair_breaks_function_reject_v1"),
            AggregateResult.FAIL,
        )
        _, report = world("canonical_security_repair_breaks_function_reject_v1")
        sec1 = next(r for r in report.results if r.target_id == "INVARIANT:INV-SEC-001:1")
        self.assertIs(sec1.result, P)  # the SSH hole is fixed; the database path is what failed

    def test_every_record_of_the_scenario_round_trips_and_states_its_own_result(self) -> None:
        _, report = world("canonical_safe_repair_promote_v1")
        for record in report.results:
            self.assertEqual(VerificationResultRecord.from_dict(record.to_dict()), record)
            self.assertEqual(thaw_json(record.evidence)["result"], record.result.value)


if __name__ == "__main__":
    unittest.main()
