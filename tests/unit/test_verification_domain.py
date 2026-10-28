"""The verification domain types (P5a step 2; Doc 05 §14; Doc 09 §4, §11, §18, §30, §37; C-145).

Expectations come from the specification text: the five results and what each means, the guards of
C-145, the sufficiency and freshness conditions of Doc 09 §11 and §30, and the aggregation table of
Doc 09 §18. Nothing here calls the code under test to compute an expected value.
"""

from __future__ import annotations

import dataclasses
import itertools
import unittest
from datetime import timedelta

from core.domain.enums import VerificationResult
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.verification import (
    AggregateResult,
    ConstructionStatus,
    RequiredTarget,
    VerificationClass,
    VerificationReason,
    VerificationReport,
    VerificationTargetType,
    aggregate,
    fresh,
    sufficient,
)
from tests.domain_builders import at, uid
from tests.verification_builders import (
    HASH,
    OTHER_HASH,
    SEC1,
    evidence_for,
    record,
    report,
    request,
)

P, F, U, S, E = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
    VerificationResult.VERIFIER_ERROR,
)
ALL_RESULTS = (P, F, U, S, E)


class TestVocabularies(unittest.TestCase):
    def test_the_five_results_of_doc_09_s4(self) -> None:
        self.assertEqual(
            {r.value for r in VerificationResult},
            {"PASS", "FAIL", "UNKNOWN", "UNSUPPORTED", "VERIFIER_ERROR"},
        )

    def test_the_classes_of_doc_09_s5(self) -> None:
        self.assertEqual(
            {c.value for c in VerificationClass},
            {"STRUCTURAL", "SECURITY", "FUNCTIONAL", "BASELINE", "CONSISTENCY"},
        )

    def test_the_target_types_are_doc_05_s14_plus_resource(self) -> None:
        self.assertEqual(
            {t.value for t in VerificationTargetType},
            {"INVARIANT", "SECURITY_PREDICATE", "STRUCTURAL", "RESOURCE"},
        )

    def test_the_aggregate_results_of_doc_09_s18(self) -> None:
        self.assertEqual({a.value for a in AggregateResult}, {"PASS", "FAIL", "INSUFFICIENT_PROOF"})

    def test_the_construction_statuses(self) -> None:
        self.assertEqual({c.value for c in ConstructionStatus}, {"OK", "INVALID", "UNSUPPORTED"})

    def test_the_functional_predicate_reason_codes_of_c_151(self) -> None:
        # C-151: the closed codes the reachability verifier reports, besides the P5a ones
        wanted = {
            "parameters.invalid",
            "endpoint.absent",
            "port.mismatch",
            "vpc.mismatch",
            "path.missing",
            "coverage.partial",
            "route.unsupported",
            "interface.unsupported",
            "value.unsupported",
            "model.unsupported",
        }
        self.assertTrue(wanted <= {c.value for c in VerificationReason})

    def test_reason_codes_are_dotted_lower_case_text(self) -> None:
        for code in VerificationReason:
            self.assertRegex(code.value, r"^[a-z_]+(\.[a-z_]+)+$")
        self.assertIn("verifier.not_available", {c.value for c in VerificationReason})
        self.assertIn("construction.invalid", {c.value for c in VerificationReason})


class TestRequest(unittest.TestCase):
    def test_a_valid_request_round_trips(self) -> None:
        built = request()
        self.assertEqual(type(built).from_dict(built.to_dict()), built)

    def test_scope_and_refs_are_stored_sorted_and_unique(self) -> None:
        built = request(
            verification_scope=("b.x", "a.x"), invariant_refs=("INV-SEC-002:1", "INV-SEC-001:1")
        )
        self.assertEqual(built.verification_scope, ("a.x", "b.x"))
        self.assertEqual(built.invariant_refs, ("INV-SEC-001:1", "INV-SEC-002:1"))

    def test_guards(self) -> None:
        for overrides in (
            {"request_id": "x"},
            {"candidate_id": "x"},
            {"state_id": "x"},
            {"candidate_hash": "short"},
            {"verifier_id": ""},
            {"verifier_version": ""},
            {"target_id": ""},
            {"target_type": "INVARIANT"},
            {"invariant_refs": ("",)},
            {"verification_scope": ("a.x", "a.x")},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(DomainValidationError):
                request(**overrides)


class TestRecordGuards(unittest.TestCase):
    def test_every_result_has_a_valid_record(self) -> None:
        for result in ALL_RESULTS:
            with self.subTest(result=result):
                self.assertIs(record(result=result).result, result)

    def test_a_pass_needs_its_metadata(self) -> None:
        for field, empty in (
            ("verifier_id", ""),
            ("verifier_version", ""),
            ("evidence_level", ""),
            ("evidence", {}),
        ):
            with self.subTest(field=field), self.assertRaises(DomainValidationError):
                record(**{field: empty})
        with self.assertRaises(DomainValidationError):
            record(candidate_hash="")

    def test_a_pass_needs_a_complete_evidence_payload(self) -> None:
        # Doc 11 §25: predicate, inputs, observations and result must be there
        for missing in ("predicate", "inputs", "observations", "result"):
            payload = evidence_for(P)
            del payload[missing]
            with self.subTest(missing=missing), self.assertRaises(DomainValidationError):
                record(evidence=payload)

    def test_the_evidence_must_state_the_same_result(self) -> None:
        with self.assertRaises(DomainValidationError):
            record(result=P, evidence=evidence_for(F))

    def test_error_is_present_exactly_when_the_result_is_verifier_error(self) -> None:
        self.assertIsNotNone(record(result=E).error)
        for result in (P, F, U, S):
            with self.subTest(result=result), self.assertRaises(DomainValidationError):
                record(result=result, error={"type": "X", "message": "m", "class": "C"})
        with self.assertRaises(DomainValidationError):
            record(result=E, error=None)

    def test_the_error_has_type_message_and_class(self) -> None:
        for bad in (
            {"type": "X"},
            {"type": "X", "message": "m"},
            {},
            {"type": "", "message": "m", "class": "C"},
        ):
            with self.subTest(error=bad), self.assertRaises(DomainValidationError):
                record(result=E, error=bad)

    def test_a_result_that_is_not_a_pass_has_a_reason(self) -> None:
        for result in (F, U, S, E):
            with self.subTest(result=result), self.assertRaises(DomainValidationError):
                record(result=result, reason=None)

    def test_a_pass_has_no_reason(self) -> None:
        with self.assertRaises(DomainValidationError):
            record(result=P, reason=VerificationReason.GROUP_MIXED)

    def test_clauses_only_on_the_two_public_ingress_invariants(self) -> None:
        with self.assertRaises(DomainValidationError):
            record(
                invariant_id="INV-SEC-003",
                target_id="INVARIANT:INV-SEC-003:1",
                clauses={"IPV4": P, "IPV6": P},
            )
        with self.assertRaises(DomainValidationError):
            record(
                target_type=VerificationTargetType.STRUCTURAL,
                invariant_id=None,
                invariant_version=None,
                target_id="STRUCTURAL",
                clauses={"IPV4": P, "IPV6": P},
            )

    def test_the_clauses_must_agree_with_the_result(self) -> None:
        # registry 3.4: FAIL exactly when a clause FAILs, otherwise the worst clause
        good = {
            (P, P): P,
            (P, F): F,
            (F, P): F,
            (F, F): F,
            (P, U): U,
            (U, P): U,
            (U, U): U,
            (P, S): S,
            (S, P): S,
            (U, S): S,
            (S, U): S,
            (S, S): S,
            (F, U): F,
            (F, S): F,
            (S, F): F,
            (U, F): F,
        }
        for (v4, v6), expected in good.items():
            with self.subTest(v4=v4, v6=v6):
                built = record(result=expected, clauses={"IPV4": v4, "IPV6": v6})
                self.assertIs(built.result, expected)
        for (v4, v6), expected in good.items():
            wrong = P if expected is not P else F
            with self.subTest(wrong=wrong, v4=v4, v6=v6), self.assertRaises(DomainValidationError):
                record(result=wrong, clauses={"IPV4": v4, "IPV6": v6})

    def test_the_clauses_have_exactly_the_two_keys_and_no_verifier_error(self) -> None:
        for bad in ({"IPV4": P}, {"IPV4": P, "IPV6": P, "IPV8": P}, {"IPV4": P, "IPV6": E}):
            with self.subTest(clauses=bad), self.assertRaises(DomainValidationError):
                record(clauses=bad)

    def test_a_verifier_error_carries_no_clauses(self) -> None:
        self.assertIsNone(record(result=E).clauses)

    def test_completed_is_not_before_started(self) -> None:
        with self.assertRaises(DomainValidationError):
            record(started=at(5), completed=at(1))
        built = record(started=at(5), completed=at(5))
        self.assertEqual(built.started_at, built.completed_at)

    def test_timestamps_must_be_aware_utc(self) -> None:
        with self.assertRaises(DomainValidationError):
            record(started=at(0).replace(tzinfo=None))

    def test_ids_hashes_and_text_are_validated(self) -> None:
        for overrides in (
            {"verification_id": "x"},
            {"request_id": "x"},
            {"candidate_id": "x"},
            {"candidate_hash": "G" * 64},
            {"invariant_version": 0},
            {"invariant_version": 1.0},
            {"target_id": ""},
            {"evidence_level": "L9"},
            {"assumptions": ("",)},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(DomainValidationError):
                record(**overrides)

    def test_a_structural_item_has_no_invariant(self) -> None:
        built = record(
            target_type=VerificationTargetType.STRUCTURAL,
            target_id="STRUCTURAL",
            invariant_id=None,
            invariant_version=None,
            verification_class=VerificationClass.STRUCTURAL,
            evidence_level="L0",
            verifier_id="dail.verify.structural",
            evidence=evidence_for(P, invariant_id=None),
        )
        self.assertIsNone(built.invariant_id)
        with self.assertRaises(DomainValidationError):
            record(invariant_id="INV-SEC-001", invariant_version=None)

    def test_floats_are_refused_in_observations_and_evidence(self) -> None:
        with self.assertRaises(DomainValidationError):
            record(observations={"ratio": 0.5})
        payload = evidence_for(P)
        payload["inputs"] = [1.5]
        with self.assertRaises(DomainValidationError):
            record(evidence=payload)

    def test_assumptions_are_sorted_and_unique(self) -> None:
        built = record(assumptions=("b", "a", "a"))
        self.assertEqual(built.assumptions, ("a", "b"))
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, assumptions=("b", "a"))

    def test_a_not_applicable_pass_says_so(self) -> None:
        built = record(
            applicable=False,
            assumptions=("registry-v1.0 declares no baseline predicate for aws_vpc",),
        )
        self.assertFalse(built.applicable)
        with self.assertRaises(DomainValidationError):
            record(applicable=False, result=F)  # only a PASS can be "not applicable"

    def test_round_trip(self) -> None:
        for result in ALL_RESULTS:
            built = record(result=result, observations={"groups_evaluated": 3}, assumptions=("a",))
            with self.subTest(result=result):
                self.assertEqual(type(built).from_dict(built.to_dict()), built)

    def test_from_dict_refuses_extra_and_missing_keys(self) -> None:
        data = record().to_dict()
        with self.assertRaises(DomainValidationError):
            type(record()).from_dict({**data, "extra": 1})
        del data["verifier_id"]
        with self.assertRaises(DomainValidationError):
            type(record()).from_dict(data)


class TestSufficient(unittest.TestCase):
    ARGS = {
        "target_id": SEC1,
        "candidate_hash": HASH,
        "invariant_id": "INV-SEC-001",
        "invariant_version": 1,
        "verifier_id": "dail.verify.public_ingress",
        "verifier_version": "1",
    }

    def test_a_complete_matching_pass_is_sufficient(self) -> None:
        self.assertTrue(sufficient(record(), **self.ARGS))

    def test_every_mismatch_is_not_sufficient(self) -> None:
        for field, other in (
            ("target_id", "INVARIANT:INV-SEC-002:1"),
            ("candidate_hash", OTHER_HASH),
            ("invariant_id", "INV-SEC-002"),
            ("invariant_version", 2),
            ("verifier_id", "other.verifier"),
            ("verifier_version", "2"),
        ):
            with self.subTest(field=field):
                self.assertFalse(sufficient(record(), **{**self.ARGS, field: other}))

    def test_only_a_pass_is_sufficient(self) -> None:
        for result in (F, U, S, E):
            with self.subTest(result=result):
                self.assertFalse(sufficient(record(result=result), **self.ARGS))

    def test_a_result_missing_a_field_is_not_sufficient_and_not_an_error(self) -> None:
        for field, empty in (
            ("verifier_id", ""),
            ("verifier_version", ""),
            ("evidence_level", ""),
            ("evidence", {}),
            ("candidate_hash", ""),
        ):
            damaged = record()
            object.__setattr__(damaged, field, empty)  # bypass the constructor on purpose
            with self.subTest(field=field):
                self.assertFalse(sufficient(damaged, **self.ARGS))

    def test_a_result_without_an_invariant_matches_a_none_target(self) -> None:
        built = record(
            target_type=VerificationTargetType.STRUCTURAL,
            target_id="STRUCTURAL",
            invariant_id=None,
            invariant_version=None,
            verification_class=VerificationClass.STRUCTURAL,
            evidence_level="L0",
            evidence=evidence_for(P, invariant_id=None),
        )
        args = {
            **self.ARGS,
            "target_id": "STRUCTURAL",
            "invariant_id": None,
            "invariant_version": None,
        }
        self.assertTrue(sufficient(built, **args))
        self.assertFalse(sufficient(built, **{**args, "invariant_id": "INV-SEC-001"}))


class TestFresh(unittest.TestCase):
    ARGS = {"candidate_hash": HASH, "invariant_version": 1, "verifier_version": "1"}

    def test_a_matching_result_is_fresh(self) -> None:
        self.assertTrue(fresh(record(), **self.ARGS))

    def test_each_mismatch_makes_it_stale(self) -> None:
        for field, other in (
            ("candidate_hash", OTHER_HASH),
            ("invariant_version", 2),
            ("verifier_version", "2"),
        ):
            with self.subTest(field=field):
                self.assertFalse(fresh(record(), **{**self.ARGS, field: other}))

    def test_invalidated_evidence_is_stale(self) -> None:
        self.assertFalse(fresh(record(), **self.ARGS, evidence_valid=False))

    def test_freshness_does_not_depend_on_the_result(self) -> None:
        for result in ALL_RESULTS:
            self.assertTrue(fresh(record(result=result), **self.ARGS))


def required(target: str = SEC1) -> RequiredTarget:
    return RequiredTarget(
        target_id=target,
        invariant_id="INV-SEC-001" if target == SEC1 else "INV-SEC-002",
        invariant_version=1,
        verifier_id="dail.verify.public_ingress",
        verifier_version="1",
    )


SEC2 = "INVARIANT:INV-SEC-002:1"


def result_for(target: str, result: VerificationResult, **kwargs):  # type: ignore[no-untyped-def]
    invariant = "INV-SEC-001" if target == SEC1 else "INV-SEC-002"
    kwargs.setdefault("verification_id", uid(21 if target == SEC1 else 22))
    return record(result=result, target_id=target, invariant_id=invariant, **kwargs)


class TestAggregate(unittest.TestCase):
    """Doc 09 §18, written as a table from the specification text."""

    def run_one(self, result: VerificationResult) -> AggregateResult:
        return aggregate([result_for(SEC1, result)], [required()], candidate_hash=HASH)

    def test_one_required_result_in_each_of_the_five_values(self) -> None:
        self.assertIs(self.run_one(P), AggregateResult.PASS)
        self.assertIs(self.run_one(F), AggregateResult.FAIL)
        for result in (U, S, E):
            with self.subTest(result=result):
                self.assertIs(self.run_one(result), AggregateResult.INSUFFICIENT_PROOF)

    def test_two_required_results_in_every_combination(self) -> None:
        for first, second in itertools.product(ALL_RESULTS, repeat=2):
            combo = {first, second}
            if F in combo:  # "If any required result is FAIL -> FAIL"
                expected = AggregateResult.FAIL
            elif combo == {P}:  # "If all required results are PASS -> PASS"
                expected = AggregateResult.PASS
            else:  # UNKNOWN, UNSUPPORTED or VERIFIER_ERROR -> INSUFFICIENT_PROOF
                expected = AggregateResult.INSUFFICIENT_PROOF
            with self.subTest(first=first, second=second):
                got = aggregate(
                    [result_for(SEC1, first), result_for(SEC2, second)],
                    [required(SEC1), required(SEC2)],
                    candidate_hash=HASH,
                )
                self.assertIs(got, expected)

    def test_three_required_results_in_every_combination(self) -> None:
        targets = (SEC1, SEC2, "INVARIANT:INV-SEC-003:1")
        needs = [
            RequiredTarget(t, t.split(":")[1], 1, "dail.verify.public_ingress", "1")
            for t in targets
        ]
        for combo in itertools.product(ALL_RESULTS, repeat=3):
            if F in combo:
                expected = AggregateResult.FAIL
            elif set(combo) == {P}:
                expected = AggregateResult.PASS
            else:
                expected = AggregateResult.INSUFFICIENT_PROOF
            results = [
                record(result=r, target_id=t, invariant_id=t.split(":")[1], clauses=None)
                for t, r in zip(targets, combo, strict=True)
            ]
            with self.subTest(combo=combo):
                self.assertIs(aggregate(results, needs, candidate_hash=HASH), expected)

    def test_a_missing_required_result_is_insufficient_never_pass(self) -> None:
        got = aggregate(
            [result_for(SEC1, P)], [required(SEC1), required(SEC2)], candidate_hash=HASH
        )
        self.assertIs(got, AggregateResult.INSUFFICIENT_PROOF)

    def test_a_missing_result_does_not_hide_a_fail(self) -> None:
        got = aggregate(
            [result_for(SEC1, F)], [required(SEC1), required(SEC2)], candidate_hash=HASH
        )
        self.assertIs(got, AggregateResult.FAIL)

    def test_a_pass_that_is_not_sufficient_is_insufficient(self) -> None:
        for kwargs in ({"verifier_version": "2"}, {"verifier_id": "other.verifier"}):
            with self.subTest(kwargs=kwargs):
                got = aggregate([result_for(SEC1, P, **kwargs)], [required()], candidate_hash=HASH)
                self.assertIs(got, AggregateResult.INSUFFICIENT_PROOF)

    def test_a_result_for_another_candidate_is_stale_whatever_it_says(self) -> None:
        # Doc 09 §30: a result for another candidate is never reused; neither pass nor fail counts
        for result in (P, F):
            with self.subTest(result=result):
                got = aggregate(
                    [result_for(SEC1, result, candidate_hash=OTHER_HASH)],
                    [required()],
                    candidate_hash=HASH,
                )
                self.assertIs(got, AggregateResult.INSUFFICIENT_PROOF)

    def test_a_fail_beats_a_pass_for_the_same_target(self) -> None:
        got = aggregate(
            [result_for(SEC1, P), result_for(SEC1, F, verification_id=uid(77))],
            [required()],
            candidate_hash=HASH,
        )
        self.assertIs(got, AggregateResult.FAIL)

    def test_an_empty_required_set_is_not_a_pass_unless_marked_empty(self) -> None:
        self.assertIs(aggregate([], [], candidate_hash=HASH), AggregateResult.INSUFFICIENT_PROOF)
        self.assertIs(
            aggregate([], [], candidate_hash=HASH, explicitly_empty=True), AggregateResult.PASS
        )

    def test_explicitly_empty_with_requirements_is_refused(self) -> None:
        with self.assertRaises(DomainValidationError):
            aggregate([], [required()], candidate_hash=HASH, explicitly_empty=True)

    def test_extra_results_that_nobody_requires_are_ignored(self) -> None:
        got = aggregate(
            [result_for(SEC1, P), result_for(SEC2, F)], [required(SEC1)], candidate_hash=HASH
        )
        self.assertIs(got, AggregateResult.PASS)

    def test_the_order_of_the_results_does_not_matter(self) -> None:
        results = [result_for(SEC1, P), result_for(SEC2, U)]
        needs = [required(SEC1), required(SEC2)]
        self.assertIs(
            aggregate(results, needs, candidate_hash=HASH),
            aggregate(list(reversed(results)), list(reversed(needs)), candidate_hash=HASH),
        )


class TestReport(unittest.TestCase):
    def two(self):  # type: ignore[no-untyped-def]
        return [
            result_for(SEC1, P, verification_id=uid(21), request_id=uid(31)),
            result_for(SEC2, F, verification_id=uid(22), request_id=uid(32)),
        ]

    def test_results_are_sorted_by_target_type_then_target_id(self) -> None:
        built = report(reversed(self.two()))
        self.assertEqual([r.target_id for r in built.results], [SEC1, SEC2])
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, results=tuple(reversed(built.results)))

    def test_the_summary_counts_per_class_and_result(self) -> None:
        built = report(
            self.two()
            + [
                record(
                    result=U,
                    target_id="INVARIANT:INV-SEC-003:1",
                    invariant_id="INV-SEC-003",
                    clauses=None,
                )
            ]
        )
        self.assertEqual(built.summary["results"], 3)
        self.assertEqual(
            built.summary["by_class"], {"SECURITY": {"FAIL": 1, "PASS": 1, "UNKNOWN": 1}}
        )
        self.assertEqual(built.summary["verifier_invocations"], 3)

    def test_a_summary_that_does_not_match_is_refused(self) -> None:
        built = report(self.two())
        bad = {**dict(built.summary), "results": 99}
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, summary=bad)

    def test_invocations_cannot_exceed_the_results(self) -> None:
        with self.assertRaises(DomainValidationError):
            report(self.two(), invocations=5)
        with self.assertRaises(DomainValidationError):
            report(self.two(), invocations=-1)

    def test_the_hash_ignores_ids_and_timestamps(self) -> None:
        one = report(self.two(), report_id=uid(90))
        moved = [
            dataclasses.replace(
                r,
                verification_id=uid(100 + i),
                request_id=uid(200 + i),
                started_at=r.started_at + timedelta(days=3),
                completed_at=r.completed_at + timedelta(days=3),
                evidence={
                    **dict(r.evidence),
                    "verification_id": uid(300 + i),
                    "started_at": "2030-01-01T00:00:00+00:00",
                    "completed_at": "2030-01-01T00:00:01+00:00",
                },
            )
            for i, r in enumerate(self.two())
        ]
        two = report(moved, report_id=uid(91))
        self.assertNotEqual(one.report_id, two.report_id)
        self.assertEqual(one.content_hash, two.content_hash)

    def test_the_hash_depends_on_the_content(self) -> None:
        base = report(self.two()).content_hash
        variants = {
            "result": report([result_for(SEC1, P), result_for(SEC2, U)]),
            "candidate hash": report(
                [
                    result_for(SEC1, P, candidate_hash=OTHER_HASH),
                    result_for(SEC2, F, candidate_hash=OTHER_HASH),
                ],
                candidate_hash=OTHER_HASH,
            ),
            "verifier set": report(self.two(), verifier_set_version="dail-verify-2"),
            "invocations": report(self.two(), invocations=1),
            "observations": report(
                [result_for(SEC1, P, observations={"groups_evaluated": 4}), result_for(SEC2, F)]
            ),
            "assumptions": report([result_for(SEC1, P, assumptions=("a",)), result_for(SEC2, F)]),
        }
        for name, variant in variants.items():
            with self.subTest(change=name):
                self.assertNotEqual(variant.content_hash, base)

    def test_a_tampered_hash_is_detected(self) -> None:
        built = report(self.two())
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(built, content_hash="0" * 64)

    def test_the_order_of_the_input_does_not_change_the_hash(self) -> None:
        self.assertEqual(
            report(self.two()).content_hash, report(list(reversed(self.two()))).content_hash
        )

    def test_every_result_must_belong_to_the_report_candidate(self) -> None:
        with self.assertRaises(DomainValidationError):
            report([result_for(SEC1, P, candidate_id=uid(999))])
        with self.assertRaises(DomainValidationError):
            report([result_for(SEC1, P, candidate_hash=OTHER_HASH)])

    def test_duplicate_verification_ids_are_refused(self) -> None:
        a = result_for(SEC1, P, verification_id=uid(5))
        b = result_for(SEC2, P, verification_id=uid(5))
        with self.assertRaises(DomainValidationError):
            report([a, b])

    def test_round_trip_keeps_the_hash(self) -> None:
        built = report(self.two())
        again = VerificationReport.from_dict(built.to_dict())
        self.assertEqual(again, built)
        self.assertEqual(again.content_hash, built.content_hash)

    def test_from_dict_checks_keys_and_hash(self) -> None:
        data = report(self.two()).to_dict()
        with self.assertRaises(DomainValidationError):
            VerificationReport.from_dict({**data, "extra": 1})
        data["content_hash"] = "f" * 64
        with self.assertRaises(HashMismatchError):
            VerificationReport.from_dict(data)

    def test_ids_and_hashes_are_validated(self) -> None:
        built = report(self.two())
        for overrides in (
            {"report_id": "x"},
            {"candidate_id": "x"},
            {"candidate_hash": "short"},
            {"verifier_set_version": ""},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(DomainValidationError):
                dataclasses.replace(built, **overrides)

    def test_a_report_may_be_empty(self) -> None:
        built = report([])
        self.assertEqual(built.results, ())
        self.assertEqual(built.summary["results"], 0)


if __name__ == "__main__":
    unittest.main()
