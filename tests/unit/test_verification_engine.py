"""The verification engine: dispatch, mandatory gate, errors, report, evidence (P5a step 6).

Doc 09 §3-§18, §30, §37, §41; registry §2.4, §2.8, §2.10; C-144 to C-148. Expected values are
derived by hand: a clean group passes the three security invariants, a public SSH group fails
INV-SEC-001 only, INV-FUNC-001 is UNSUPPORTED ``verifier.not_available`` until P5b, and the two
gate items run on every candidate.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import random
import subprocess
import sys
import textwrap
import unittest
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from core.domain.enums import ProvenanceSourceKind, VerificationResult
from core.domain.errors import DomainValidationError
from core.domain.evidence import EvidenceKind, EvidenceValidity, check_payload_json
from core.domain.hashing import canonical_json
from core.domain.impact import VerificationWorkItem
from core.domain.invariant import Invariant
from core.domain.jsonvalue import thaw_json
from core.domain.verification import (
    AggregateResult,
    ConstructionStatus,
    VerificationReason,
    VerificationReport,
    VerificationRequest,
    VerificationResultRecord,
    VerificationTargetType,
    aggregate,
)
from core.verification.engine import (
    DEFAULT_VERIFIERS,
    VERIFIER_SET_VERSION,
    run_work_set,
    to_evidence_submission,
    verify_work_item,
)
from core.verification.errors import VerificationInputError
from core.verification.inputs import VerificationInputs
from core.verification.outcome import PredicateOutcome
from core.verification.views import ViewError
from tests.domain_builders import uid
from tests.impact_builders import baseline_work
from tests.pipeline_builders import (
    CANDIDATE_STATE,
    PARENT_STATE,
    counting_ids,
    fixed_clock,
    inputs_for,
    invariant_item,
    required_for,
)
from tests.security_builders import inline, sg

REPO_ROOT = Path(__file__).resolve().parents[2]
P, F, U, S, E = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
    VerificationResult.VERIFIER_ERROR,
)
R = VerificationReason
SEC1, SEC2, SEC3, FUNC = "INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"
FOUR = (SEC1, SEC2, SEC3, FUNC)
CLEAN = sg(body=inline("ingress", "tcp", 443, 443, ["10.0.0.0/8"]))
OPEN = sg(body=inline("ingress", "tcp", 22, 22, ["0.0.0.0/0"]))
KEY_PUBLIC_INGRESS = ("dail.verify.public_ingress", "1")


def items(*invariants: str) -> list[VerificationWorkItem]:
    return [invariant_item(name) for name in invariants]


def run(
    text: str,
    work: list[VerificationWorkItem] | None = None,
    parent: str | None = None,
    **overrides: Any,
) -> VerificationReport:
    inputs = overrides.pop("inputs", None) or inputs_for(text, parent)
    return run_work_set(
        items(*FOUR) if work is None else work,
        inputs,
        clock=overrides.pop("clock", None) or fixed_clock(),
        ids=overrides.pop("ids", None) or counting_ids(),
        **overrides,
    )


def by_target(report: VerificationReport) -> dict[str, VerificationResultRecord]:
    return {item.target_id: item for item in report.results}


def request_for(
    inputs: VerificationInputs, target: str, kind: VerificationTargetType
) -> VerificationRequest:
    definition = (
        inputs.invariant(*_split(target)) if kind is VerificationTargetType.INVARIANT else None
    )
    return VerificationRequest(
        request_id=uid(11),
        candidate_id=inputs.candidate_id,
        state_id=inputs.parent_state_id or inputs.candidate_id,
        candidate_hash=inputs.candidate_state_hash,
        target_id=target,
        target_type=kind,
        invariant_refs=(target.removeprefix("INVARIANT:"),) if definition else (),
        verification_scope=("aws_security_group.app",),
        verifier_id=definition.verifier_id if definition else "dail.verify.baseline",
        verifier_version=definition.verifier_version if definition else "1",
    )


def _split(target: str) -> tuple[str, int]:
    _, _, rest = target.partition(":")
    invariant_id, _, version = rest.rpartition(":")
    return invariant_id, int(version)


class TestReport(unittest.TestCase):
    def test_a_clean_candidate(self) -> None:
        report = run(CLEAN)
        found = by_target(report)
        self.assertEqual(
            sorted(found),
            [
                "CONSISTENCY",
                "INVARIANT:INV-FUNC-001:1",
                "INVARIANT:INV-SEC-001:1",
                "INVARIANT:INV-SEC-002:1",
                "INVARIANT:INV-SEC-003:1",
                "STRUCTURAL",
            ],
        )
        for name in (SEC1, SEC2, SEC3):
            self.assertIs(found[f"INVARIANT:{name}:1"].result, P, name)
        self.assertIs(found["STRUCTURAL"].result, P)
        self.assertIs(found["CONSISTENCY"].result, P)

    def test_results_are_sorted_by_target_type_then_id(self) -> None:
        report = run(CLEAN)
        keys = [(item.target_type.value, item.target_id) for item in report.results]
        self.assertEqual(keys, sorted(keys))

    def test_a_public_ssh_group_fails_only_inv_sec_001(self) -> None:
        found = by_target(run(OPEN))
        sec1 = found["INVARIANT:INV-SEC-001:1"]
        self.assertEqual((sec1.result, sec1.reason), (F, R.PREDICATE_VIOLATED))
        self.assertEqual(dict(sec1.clauses or {}), {"IPV4": F, "IPV6": P})
        self.assertIs(found["INVARIANT:INV-SEC-002:1"].result, P)
        self.assertIs(found["INVARIANT:INV-SEC-003:1"].result, P)

    def test_the_functional_invariant_is_unsupported_never_pass_until_p5b(self) -> None:
        for text in (CLEAN, OPEN):
            func = by_target(run(text))["INVARIANT:INV-FUNC-001:1"]
            self.assertEqual((func.result, func.reason), (S, R.VERIFIER_NOT_AVAILABLE))
            self.assertIsNone(func.clauses)
            self.assertIsNone(func.error)

    def test_every_result_carries_its_metadata(self) -> None:
        report = run(CLEAN)
        found = by_target(report)
        sec1 = found["INVARIANT:INV-SEC-001:1"]
        self.assertEqual((sec1.verifier_id, sec1.verifier_version), KEY_PUBLIC_INGRESS)
        self.assertEqual((sec1.evidence_level, sec1.verification_class.value), ("L1", "SECURITY"))
        self.assertEqual((sec1.invariant_id, sec1.invariant_version), (SEC1, 1))
        self.assertIn("scope: every group, attached or not (C-64)", sec1.assumptions)
        sec3 = found["INVARIANT:INV-SEC-003:1"]
        self.assertEqual(sec3.verifier_id, "dail.verify.rds_public_flag")
        for gate in ("STRUCTURAL", "CONSISTENCY"):
            self.assertEqual(found[gate].evidence_level, "L0")
            self.assertEqual(found[gate].observations["work_reason"], "MANDATORY_GATE")
            self.assertEqual(found[gate].observations["priority"], "BLOCKING")
        for item in report.results:
            self.assertEqual(item.candidate_hash, report.candidate_hash)
            self.assertTrue(item.evidence)
            self.assertEqual(item.evidence["result"], item.result.value)

    def test_the_summary_and_the_cost_metric(self) -> None:
        report = run(CLEAN)
        self.assertEqual(report.verifier_set_version, VERIFIER_SET_VERSION)
        self.assertEqual(report.summary["results"], 6)
        self.assertEqual(
            thaw_json(report.summary["by_class"]),
            {
                "CONSISTENCY": {"PASS": 1},
                "FUNCTIONAL": {"UNSUPPORTED": 1},
                "SECURITY": {"PASS": 3},
                "STRUCTURAL": {"PASS": 1},
            },
        )
        # three security verifiers and the two gates ran; the functional item was answered
        # without running a verifier
        self.assertEqual(report.verifier_invocations, 5)

    def test_the_mandatory_gate_runs_even_when_the_impact_report_is_empty(self) -> None:
        report = run(CLEAN, work=[])
        self.assertEqual(sorted(by_target(report)), ["CONSISTENCY", "STRUCTURAL"])
        self.assertEqual(report.verifier_invocations, 2)
        self.assertEqual([item.result for item in report.results], [P, P])

    def test_p4_work_items_are_all_answered(self) -> None:
        old = sg() + sg("db")
        new = sg(body=inline("ingress", "tcp", 22, 22, ["0.0.0.0/0"])) + sg("db") + sg("created")
        inputs = inputs_for(new, old)
        work = list(inputs.impact.verification_work)  # type: ignore[union-attr]
        self.assertTrue(any(w.target_id.startswith("RESOURCE:") for w in work))
        report = run(new, work=work, inputs=inputs)
        self.assertEqual(
            set(by_target(report)), {w.target_id for w in work} | {"STRUCTURAL", "CONSISTENCY"}
        )
        created = by_target(report)["RESOURCE:aws_security_group.created"]
        self.assertEqual(created.verification_class.value, "BASELINE")
        self.assertIs(created.result, P)


class TestConstructionAndUnknownInvariants(unittest.TestCase):
    def test_a_construction_failure_makes_every_item_unsupported_and_runs_no_predicate(
        self,
    ) -> None:
        for status in (ConstructionStatus.INVALID, ConstructionStatus.UNSUPPORTED):
            with self.subTest(status=status):
                inputs = dataclasses.replace(
                    inputs_for(OPEN + sg("created")), construction=status, construction_note="hcl"
                )
                work = [*items(*FOUR), baseline_work("aws_security_group.created")]
                report = run_work_set(work, inputs, clock=fixed_clock(), ids=counting_ids())
                found = by_target(report)
                for name in FOUR:
                    item = found[f"INVARIANT:{name}:1"]
                    self.assertEqual((item.result, item.reason), (S, R.CONSTRUCTION_INVALID), name)
                created = found["RESOURCE:aws_security_group.created"]
                self.assertEqual((created.result, created.reason), (S, R.CONSTRUCTION_INVALID))
                structural = found["STRUCTURAL"]
                self.assertEqual(
                    (structural.result, structural.reason), (F, R.CONSTRUCTION_INVALID)
                )
                self.assertEqual(report.verifier_invocations, 2)  # only the two gates ran

    def test_an_unknown_invariant_is_unsupported_not_an_error_and_the_gate_fails(self) -> None:
        inputs = inputs_for(CLEAN)
        work = [invariant_item("INV-NOPE-001")]
        report = run(CLEAN, work=work, inputs=inputs)
        found = by_target(report)
        unknown = found["INVARIANT:INV-NOPE-001:1"]
        self.assertEqual((unknown.result, unknown.reason), (S, R.INVARIANT_UNKNOWN))
        self.assertIsNone(unknown.error)
        structural = found["STRUCTURAL"]
        self.assertEqual((structural.result, structural.reason), (F, R.STRUCTURAL_FINDING))
        self.assertEqual(
            [f["code"] for f in structural.observations["findings"]], ["work.invariant_unknown"]
        )

    def test_a_missing_definition_of_a_known_id_at_another_version(self) -> None:
        report = run(CLEAN, work=[invariant_item(SEC1, 9)])
        item = by_target(report)["INVARIANT:INV-SEC-001:9"]
        self.assertEqual((item.result, item.reason), (S, R.INVARIANT_UNKNOWN))


class TestErrors(unittest.TestCase):
    @staticmethod
    def with_verifier(function: Any) -> Mapping[tuple[str, str], Any]:
        return {**DEFAULT_VERIFIERS, KEY_PUBLIC_INGRESS: function}

    def test_an_exception_inside_a_verifier_is_a_verifier_error_with_metadata(self) -> None:
        def boom(_definition: Invariant, _inputs: VerificationInputs) -> PredicateOutcome:
            raise RuntimeError("boom")

        report = run(CLEAN, verifiers=self.with_verifier(boom))
        found = by_target(report)
        for name in (SEC1, SEC2):
            item = found[f"INVARIANT:{name}:1"]
            self.assertEqual((item.result, item.reason), (E, R.VERIFIER_ERROR))
            self.assertEqual(
                dict(item.error or {}),
                {"type": "RuntimeError", "message": "boom", "class": "SECURITY"},
            )
            self.assertEqual((item.verifier_id, item.verifier_version), KEY_PUBLIC_INGRESS)
            self.assertEqual(
                (item.evidence_level, item.candidate_hash), ("L1", report.candidate_hash)
            )
            self.assertEqual(item.evidence["result"], "VERIFIER_ERROR")
            self.assertIsNone(item.clauses)
        # the other verifiers are not affected, and the failed runs are still invocations
        self.assertIs(found["INVARIANT:INV-SEC-003:1"].result, P)
        self.assertEqual(report.verifier_invocations, 5)

    def test_a_verifier_error_is_never_a_fail_or_a_pass(self) -> None:
        def boom(_definition: Invariant, _inputs: VerificationInputs) -> PredicateOutcome:
            raise ValueError("no")

        report = run(OPEN, verifiers=self.with_verifier(boom))
        self.assertIs(by_target(report)["INVARIANT:INV-SEC-001:1"].result, E)

    def test_a_malformed_stored_view_is_a_verifier_error(self) -> None:
        def bad_view(_definition: Invariant, _inputs: VerificationInputs) -> PredicateOutcome:
            raise ViewError("not the shape P3a writes")

        item = by_target(run(CLEAN, verifiers=self.with_verifier(bad_view)))[
            "INVARIANT:INV-SEC-001:1"
        ]
        self.assertEqual((item.result, item.error["type"]), (E, "ViewError"))  # type: ignore[index]

    def test_an_inconsistent_outcome_is_a_verifier_error(self) -> None:
        def inconsistent(_definition: Invariant, _inputs: VerificationInputs) -> PredicateOutcome:
            return PredicateOutcome(P, None, {"IPV4": F, "IPV6": P}, {}, ())

        item = by_target(run(CLEAN, verifiers=self.with_verifier(inconsistent)))[
            "INVARIANT:INV-SEC-001:1"
        ]
        self.assertEqual((item.result, item.error["type"]), (E, "DomainValidationError"))  # type: ignore[index]

    def test_something_that_is_not_an_outcome_is_a_verifier_error(self) -> None:
        item = by_target(run(CLEAN, verifiers=self.with_verifier(lambda _d, _i: None)))[
            "INVARIANT:INV-SEC-001:1"
        ]
        self.assertIs(item.result, E)

    def test_something_that_only_looks_like_an_outcome_is_a_verifier_error(self) -> None:
        # the same fields, but not a PredicateOutcome: never trusted on its looks
        lookalike = SimpleNamespace(
            result=P, reason=None, clauses=None, observations={}, assumptions=()
        )
        verifiers = self.with_verifier(lambda _d, _i: lookalike)
        item = by_target(run(CLEAN, verifiers=verifiers))["INVARIANT:INV-SEC-001:1"]
        self.assertEqual((item.result, item.error["type"]), (E, "TypeError"))  # type: ignore[index]

    def test_a_keyboard_interrupt_is_not_swallowed(self) -> None:
        def interrupted(_definition: Invariant, _inputs: VerificationInputs) -> PredicateOutcome:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            run(CLEAN, verifiers=self.with_verifier(interrupted))

    def test_a_registered_functional_verifier_is_dispatched_by_the_definition(self) -> None:
        def fake(definition: Invariant, _inputs: VerificationInputs) -> PredicateOutcome:
            return PredicateOutcome(P, None, None, {"seen": definition.invariant_id}, ())

        table = {**DEFAULT_VERIFIERS, ("dail.verify.reachability_cfg", "1"): fake}
        item = by_target(run(CLEAN, verifiers=table))["INVARIANT:INV-FUNC-001:1"]
        self.assertEqual((item.result, item.observations["seen"]), (P, FUNC))
        self.assertEqual(item.verification_class.value, "FUNCTIONAL")


class TestInputErrors(unittest.TestCase):
    def test_malformed_work_is_refused_before_anything_runs(self) -> None:
        inputs = inputs_for(CLEAN)
        for work in ("INV-SEC-001", [1], [invariant_item(SEC1), invariant_item(SEC1)]):
            with self.subTest(work=work), self.assertRaises(VerificationInputError):
                run_work_set(work, inputs, clock=fixed_clock(), ids=counting_ids())  # type: ignore[arg-type]

    def test_inputs_that_are_not_inputs_are_refused(self) -> None:
        with self.assertRaises(VerificationInputError):
            run_work_set([], "inputs", clock=fixed_clock(), ids=counting_ids())  # type: ignore[arg-type]

    def test_a_request_for_another_candidate_or_hash_is_refused(self) -> None:
        inputs = inputs_for(CLEAN)
        good = request_for(inputs, f"INVARIANT:{SEC1}:1", VerificationTargetType.INVARIANT)
        verify_work_item(good, inputs, clock=fixed_clock())  # the sound request works
        for bad in (
            dataclasses.replace(good, candidate_hash="b" * 64),
            dataclasses.replace(good, candidate_id=uid(77)),
            dataclasses.replace(good, verifier_version="2"),
            dataclasses.replace(good, verifier_id="someone.else"),
        ):
            with self.subTest(bad=bad), self.assertRaises(VerificationInputError):
                verify_work_item(bad, inputs, clock=fixed_clock())


class TestSingleItem(unittest.TestCase):
    def test_one_item_with_the_injected_clock(self) -> None:
        inputs = inputs_for(OPEN)
        request = request_for(inputs, f"INVARIANT:{SEC1}:1", VerificationTargetType.INVARIANT)
        record = verify_work_item(request, inputs, clock=fixed_clock(10, 7), ids=counting_ids(9000))
        self.assertEqual((record.result, record.request_id), (F, request.request_id))
        self.assertEqual(record.verification_id, uid(9000))
        self.assertEqual((record.completed_at - record.started_at).total_seconds(), 7)

    def test_a_resource_item(self) -> None:
        text = CLEAN + sg("created")
        inputs = inputs_for(text, CLEAN)
        request = request_for(
            inputs, "RESOURCE:aws_security_group.created", VerificationTargetType.RESOURCE
        )
        record = verify_work_item(request, inputs, clock=fixed_clock())
        self.assertEqual((record.result, record.applicable), (P, True))
        self.assertEqual(record.verification_class.value, "BASELINE")
        self.assertIsNone(record.invariant_id)


class TestAggregationOfReports(unittest.TestCase):
    """Doc 09 §41 rows that P5a can reach, through the P6-facing ``aggregate``."""

    def verdict(
        self, text: str, names: tuple[str, ...] = (SEC1, SEC2, SEC3), **kw: Any
    ) -> AggregateResult:
        inputs = inputs_for(text)
        work = items(*names)
        report = run(text, work=work, inputs=inputs, **kw)
        return aggregate(
            report.results, required_for(inputs, work), candidate_hash=report.candidate_hash
        )

    def test_security_pass(self) -> None:
        self.assertIs(self.verdict(CLEAN), AggregateResult.PASS)

    def test_security_fail(self) -> None:
        self.assertIs(self.verdict(OPEN), AggregateResult.FAIL)

    def test_security_unknown(self) -> None:
        text = 'variable "ssh_cidr" {}\n' + sg(
            body=inline("ingress", "tcp", 22, 22, "[var.ssh_cidr]")
        )
        self.assertIs(self.verdict(text), AggregateResult.INSUFFICIENT_PROOF)

    def test_unsupported_verifier_with_the_functional_invariant_is_never_a_pass(self) -> None:
        # the interim: with INV-FUNC-001 required, a clean candidate is INSUFFICIENT_PROOF
        self.assertIs(self.verdict(CLEAN, FOUR), AggregateResult.INSUFFICIENT_PROOF)

    def test_a_verifier_exception_is_insufficient_proof(self) -> None:
        def boom(_definition: Invariant, _inputs: VerificationInputs) -> PredicateOutcome:
            raise RuntimeError("x")

        verdict = self.verdict(CLEAN, verifiers={**DEFAULT_VERIFIERS, KEY_PUBLIC_INGRESS: boom})
        self.assertIs(verdict, AggregateResult.INSUFFICIENT_PROOF)

    def test_a_result_for_another_candidate_hash_is_stale(self) -> None:
        inputs = inputs_for(CLEAN)
        work = items(SEC1, SEC2, SEC3)
        report = run(CLEAN, work=work, inputs=inputs)
        verdict = aggregate(report.results, required_for(inputs, work), candidate_hash="b" * 64)
        self.assertIs(verdict, AggregateResult.INSUFFICIENT_PROOF)

    def test_evidence_from_another_verifier_version_is_insufficient(self) -> None:
        inputs = inputs_for(CLEAN)
        work = items(SEC1, SEC2, SEC3)
        report = run(CLEAN, work=work, inputs=inputs)
        needs = [
            dataclasses.replace(need, verifier_version="2") for need in required_for(inputs, work)
        ]
        self.assertIs(
            aggregate(report.results, needs, candidate_hash=report.candidate_hash),
            AggregateResult.INSUFFICIENT_PROOF,
        )

    def test_a_missing_required_result(self) -> None:
        inputs = inputs_for(CLEAN)
        report = run(CLEAN, work=items(SEC1), inputs=inputs)
        needs = required_for(inputs, items(SEC1, SEC2))
        self.assertIs(
            aggregate(report.results, needs, candidate_hash=report.candidate_hash),
            AggregateResult.INSUFFICIENT_PROOF,
        )


class TestEvidenceSubmission(unittest.TestCase):
    def record(self) -> VerificationResultRecord:
        report = run(OPEN)
        return by_target(report)["INVARIANT:INV-SEC-001:1"]

    def submit(self, record: VerificationResultRecord, **overrides: Any) -> Any:
        fields: dict[str, Any] = {
            "evidence_id": uid(1),
            "run_id": uid(2),
            "attempt_id": uid(3),
            "correlation_id": uid(4),
            "operation_id": uid(5),
            "parent_state_id": PARENT_STATE,
        }
        fields.update(overrides)
        return to_evidence_submission(record, **fields)

    def test_a_candidate_bound_verification_record(self) -> None:
        record = self.record()
        submission = self.submit(record)
        event = submission.event
        self.assertEqual(event.kind, EvidenceKind.VERIFICATION)
        self.assertEqual(event.event_name, "verification.result")
        self.assertEqual(
            (event.candidate_id, event.parent_state_id, event.attempt_id),
            (record.candidate_id, PARENT_STATE, uid(3)),
        )
        self.assertEqual(event.state_hash, record.candidate_hash)
        self.assertEqual(event.validity, EvidenceValidity.VALID)
        self.assertEqual(event.created_at, record.completed_at)
        self.assertEqual(event.provenance.source_kind, ProvenanceSourceKind.DERIVED)
        self.assertEqual(event.provenance.tool_name, record.verifier_id)
        self.assertEqual(event.provenance.algorithm_version, record.verifier_version)
        payload = check_payload_json(submission.payload_json, event.content_hash)
        self.assertEqual(payload, thaw_json(record.evidence))

    def test_the_payload_has_the_doc_11_and_registry_fields(self) -> None:
        payload = json.loads(self.submit(self.record()).payload_json)
        required = (
            "verification_id invariant_id invariant_version candidate_id candidate_hash "
            "verifier_id verifier_version evidence_level predicate inputs observations result "
            "reason applicable clauses assumptions evidence_refs started_at completed_at error"
        ).split()
        for key in required:
            self.assertIn(key, payload)
        self.assertEqual(payload["evidence_level"], "L1")
        self.assertEqual(payload["clauses"], {"IPV4": "FAIL", "IPV6": "PASS"})
        self.assertEqual(payload["invariant_version"], 1)

    def test_a_baseline_without_a_parent_is_state_bound_when_a_state_is_given(self) -> None:
        record = self.record()
        submission = self.submit(record, parent_state_id=None, state_id=uid(8))
        self.assertEqual(
            (submission.event.state_id, submission.event.candidate_id, submission.event.state_hash),
            (uid(8), None, record.candidate_hash),
        )

    def test_a_field_that_cannot_be_filled_fails_loudly(self) -> None:
        with self.assertRaisesRegex(DomainValidationError, "needs the state it is bound to"):
            self.submit(self.record(), parent_state_id=None)  # no parent and no state
        with self.assertRaises(DomainValidationError):
            self.submit(self.record(), attempt_id=None)  # a candidate-bound record needs it

    def test_the_payload_of_an_error_result_is_complete_too(self) -> None:
        def boom(_definition: Invariant, _inputs: VerificationInputs) -> PredicateOutcome:
            raise RuntimeError("boom")

        record = by_target(run(CLEAN, verifiers={**DEFAULT_VERIFIERS, KEY_PUBLIC_INGRESS: boom}))[
            "INVARIANT:INV-SEC-001:1"
        ]
        payload = json.loads(self.submit(record).payload_json)
        self.assertEqual(payload["result"], "VERIFIER_ERROR")
        self.assertEqual(payload["error"]["message"], "boom")


class TestDeterminism(unittest.TestCase):
    def test_the_order_of_work_items_and_resources_does_not_change_the_report_hash(self) -> None:
        inputs = inputs_for(OPEN + sg("b", inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"])))
        base = run_work_set(items(*FOUR), inputs, clock=fixed_clock(), ids=counting_ids())
        rng = random.Random(20261028)
        for _ in range(8):
            work = items(*FOUR)
            resources = list(inputs.candidate_resources)
            rng.shuffle(work)
            rng.shuffle(resources)
            shuffled = dataclasses.replace(inputs, candidate_resources=tuple(resources))
            again = run_work_set(work, shuffled, clock=fixed_clock(), ids=counting_ids())
            self.assertEqual(again.content_hash, base.content_hash)

    def test_other_clock_and_id_values_do_not_change_the_hash_but_equal_ones_give_equal_reports(
        self,
    ) -> None:
        inputs = inputs_for(OPEN)
        one = run_work_set(items(*FOUR), inputs, clock=fixed_clock(0), ids=counting_ids(100))
        same = run_work_set(items(*FOUR), inputs, clock=fixed_clock(0), ids=counting_ids(100))
        other = run_work_set(
            items(*FOUR), inputs, clock=fixed_clock(900, 13), ids=counting_ids(777)
        )
        self.assertEqual(one, same)
        self.assertNotEqual(one.report_id, other.report_id)
        self.assertEqual(one.content_hash, other.content_hash)

    def test_the_candidate_changing_changes_the_hash(self) -> None:
        a = run(OPEN).content_hash
        b = run(CLEAN).content_hash
        self.assertNotEqual(a, b)

    SCRIPT = textwrap.dedent("""
        import sys
        sys.path.insert(0, ".")
        import hashlib
        from core.domain.hashing import canonical_json
        from core.verification.engine import run_work_set
        from tests.pipeline_builders import counting_ids, fixed_clock, inputs_for, invariant_item
        from tests.security_builders import inline, sg

        text = sg(body=inline("ingress", "tcp", 22, 22, ["0.0.0.0/0"])) + sg("b")
        inputs = inputs_for(text)
        names = ("INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001")
        report = run_work_set(
            [invariant_item(n) for n in names], inputs, clock=fixed_clock(), ids=counting_ids()
        )
        print(report.content_hash)
        print(hashlib.sha256(canonical_json(report.to_dict()).encode()).hexdigest())
        """)

    def output_under(self, *flags: str, seed: str | None = None) -> list[str]:
        env = {key: value for key, value in os.environ.items() if key != "PYTHONHASHSEED"}
        if seed is not None:
            env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = str(REPO_ROOT)
        result = subprocess.run(
            [sys.executable, *flags, "-c", self.SCRIPT],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.split()

    def test_the_report_does_not_depend_on_the_hash_seed(self) -> None:
        reference = self.output_under(seed="0")
        self.assertEqual(len(reference), 2)
        for seed in ("1", "4242", "99991"):
            with self.subTest(PYTHONHASHSEED=seed):
                self.assertEqual(self.output_under(seed=seed), reference)
        for attempt in range(2):
            with self.subTest(isolated=attempt):
                self.assertEqual(self.output_under("-I"), reference)

    def test_the_subprocess_report_equals_the_in_process_report(self) -> None:
        inputs = inputs_for(OPEN + sg("b"))
        report = run_work_set(items(*FOUR), inputs, clock=fixed_clock(), ids=counting_ids())
        digest = hashlib.sha256(canonical_json(report.to_dict()).encode()).hexdigest()
        self.assertEqual(self.output_under(seed="7"), [report.content_hash, digest])


class TestIdentityOfIds(unittest.TestCase):
    def test_every_id_comes_from_the_injected_source(self) -> None:
        ids_seen: list[str] = []
        source = counting_ids(300)

        def spy() -> str:
            value = source()
            ids_seen.append(value)
            return value

        report = run_work_set(items(SEC1), inputs_for(CLEAN), clock=fixed_clock(), ids=spy)
        used = {
            report.report_id,
            *(r.verification_id for r in report.results),
            *(r.request_id for r in report.results),
        }
        self.assertEqual(used, set(ids_seen))
        self.assertEqual(len(ids_seen), len(set(ids_seen)))
        self.assertEqual(report.candidate_id, CANDIDATE_STATE)


if __name__ == "__main__":
    unittest.main()
