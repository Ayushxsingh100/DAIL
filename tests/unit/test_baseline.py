"""The baseline establishment flow (P6c step 3; Doc 06 §24, Doc 13 §13; Doc 11 §8, §44; C-30, C-59,
C-171, C-176).

HAND EXPECTATIONS (the fixture's own ``expected.json``, hand-written data, C-89, and the prompt):

* the D2 ``canonical_regression/baseline`` directory gives version 0 with INV-SEC-001 VIOLATED
  (public SSH is open) and INV-SEC-002, INV-SEC-003 and INV-FUNC-001 PROTECTED;
* the evidence of the four invariants is VERIFICATION evidence bound to version 0 and carrying its
  state hash, so that it is proof for version 0 (``usable_as_proof``) and a later candidate can
  carry an unaffected invariant forward from it; the evidence is written before the state, in the
  same transaction, and ``STATE_CREATED`` is appended once;
* a second call with the same request is a duplicate and writes nothing; another configuration
  under the same ``baseline_id`` raises ``ConflictingDuplicateError``;
* the baseline is refused (``BaselineRefused``), fail closed, when the fixture is not declared
  eligible, normalization is not OK, a gate does not PASS, or a result is VERIFIER_ERROR; the only
  things stored are one ERROR record and one ERROR_OCCURRED event, and a repeat stores nothing new;
* a failure at each checkpoint of the write leaves no state, no lineage head, no evidence.
"""

from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from core.application import ids as oids
from core.application.baseline import (
    BaselineRefused,
    BaselineRequest,
    BaselineResult,
    establish_baseline,
)
from core.dependency.invariants import SemanticBinding
from core.domain.audit import AuditEventType
from core.domain.enums import InvariantStatus, VerificationResult
from core.domain.errors import DomainValidationError, PersistenceError
from core.domain.evidence import EvidenceContext, EvidenceKind
from core.domain.promotion import ConflictingDuplicateError
from core.domain.verification import VerificationReason
from core.terraform_model.normalization import normalize_directory
from core.verification.dispatch import DEFAULT_VERIFIERS, REACHABILITY_CFG, VerifierTable
from core.verification.outcome import PredicateOutcome
from evidence.service import EvidenceService
from tests.domain_builders import LINEAGE, uid
from tests.identity_builders import NOW
from tests.impact_builders import registry
from tests.persistence_builders import RepoCase
from tests.promotion_commit_builders import CONTEXT, Gate, InjectedFault, dump
from tests.promotion_pipeline import ROOT, parent_statuses

BASELINE_DIR = ROOT / "fixtures" / "canonical_regression" / "baseline"
SAFE_DIR = ROOT / "fixtures" / "canonical_regression" / "patch_safe"
SOURCE, DESTINATION = "aws_instance.app", "aws_db_instance.database"
BASELINE_ID = uid(3100)
SEC1, SEC2, SEC3, FUNC = "INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"
# hand-derived from the fixture's expected.json: SEC-001 FAIL, the rest PASS
EXPECTED = {
    SEC1: InvariantStatus.VIOLATED,
    SEC2: InvariantStatus.PROTECTED,
    SEC3: InvariantStatus.PROTECTED,
    FUNC: InvariantStatus.PROTECTED,
}


def request_for(directory: Path = BASELINE_DIR, **changes: Any) -> BaselineRequest:
    definitions = tuple(registry(SOURCE, DESTINATION).values())
    base = BaselineRequest(
        baseline_id=BASELINE_ID,
        lineage_id=LINEAGE,
        baseline_dir=directory,
        variables=None,
        definitions=definitions,
        bindings=(SemanticBinding(FUNC, SOURCE, DESTINATION, "TCP", 5432),),
        context=CONTEXT,
        now=NOW,
        eligible=True,
    )
    return dataclasses.replace(base, **changes)


def raising(_definition: Any, _inputs: Any) -> Any:
    raise RuntimeError("the reachability verifier crashed")


def unknown(_definition: Any, _inputs: Any) -> Any:
    return PredicateOutcome(
        VerificationResult.UNKNOWN, VerificationReason.RULE_INDETERMINATE, None, {}, ()
    )


def with_reachability(verifier: Any) -> VerifierTable:
    return {**DEFAULT_VERIFIERS, REACHABILITY_CFG: verifier}


class BaselineCase(RepoCase):
    def factory(self, checkpoint: Any = None) -> Any:
        return lambda: self.uow(checkpoint=checkpoint)

    def establish(self, request: BaselineRequest | None = None, **options: Any) -> BaselineResult:
        return establish_baseline(
            self.factory(options.pop("checkpoint", None)), request or request_for()
        )

    def tables(self) -> dict[str, int]:
        return {
            t: self.count(t)
            for t in (
                "trusted_states",
                "lineage_heads",
                "invariants",
                "invariant_refs",
                "evidence_events",
                "audit_events",
            )
        }


class TestTheCanonicalBaseline(BaselineCase):
    def setUp(self) -> None:
        super().setUp()
        self.result = self.establish()

    def test_it_is_version_zero_of_the_requested_lineage(self) -> None:
        state = self.result.state
        self.assertEqual(state.version, 0)
        self.assertIsNone(state.parent_state_id)
        self.assertEqual(state.lineage_id, LINEAGE)
        self.assertEqual(state.state_id, oids.baseline_state_id_for(BASELINE_ID))
        self.assertFalse(self.result.duplicate)
        with self.uow() as u:
            self.assertEqual(u.trusted_states.get_current(LINEAGE), state)

    def test_its_resources_are_those_of_the_directory(self) -> None:
        outcome = normalize_directory(BASELINE_DIR, None, now=NOW)
        self.assertEqual(self.result.state.resource_set_hash(), outcome.resource_set_hash)

    def test_the_statuses_are_those_of_the_fixture(self) -> None:
        got = {r.invariant_id: r.status for r in self.result.state.invariant_refs}
        self.assertEqual(got, EXPECTED)
        self.assertEqual(got, parent_statuses("fixtures/canonical_regression/baseline"))
        self.assertEqual(dict(self.result.statuses), EXPECTED)
        self.assertEqual({r.invariant_version for r in self.result.state.invariant_refs}, {1})

    def test_a_violated_invariant_is_recorded_as_violated_never_as_protected(self) -> None:
        by = {r.invariant_id: r for r in self.result.state.invariant_refs}
        self.assertIs(by[SEC1].status, InvariantStatus.VIOLATED)

    def test_the_definitions_are_registered(self) -> None:
        with self.uow() as u:
            for definition in registry(SOURCE, DESTINATION).values():
                self.assertEqual(
                    u.invariants.get_definition(definition.invariant_id, 1), definition
                )

    def test_there_is_one_state_bound_verification_record_per_result(self) -> None:
        results = self.result.report.results
        with self.uow() as u:
            rows = [u.evidence.get(self.result.evidence_ids[r.verification_id]) for r in results]
        self.assertEqual(len(rows), len(results))
        self.assertEqual(len(results), 6)  # four invariants and the two gates
        for row, result in zip(rows, results, strict=True):
            assert row is not None
            with self.subTest(target=result.target_id):
                self.assertIs(row.kind, EvidenceKind.VERIFICATION)
                self.assertEqual(row.state_id, self.result.state.state_id)
                self.assertIsNone(row.candidate_id)
                self.assertIsNone(row.parent_state_id)
                self.assertEqual(row.state_hash, self.result.state.state_hash)
                self.assertEqual(row.run_id, CONTEXT.run_id)
                self.assertEqual(row.correlation_id, CONTEXT.correlation_id)
                self.assertEqual(
                    row.evidence_id,
                    oids.baseline_evidence_id_for(BASELINE_ID, "verification", result.target_id),
                )

    def test_each_invariant_reference_carries_its_own_evidence(self) -> None:
        by_target = {r.target_id: r for r in self.result.report.results}
        for ref in self.result.state.invariant_refs:
            record = by_target[f"INVARIANT:{ref.invariant_id}:{ref.invariant_version}"]
            self.assertEqual(ref.evidence_ids, (self.result.evidence_ids[record.verification_id],))
        self.assertEqual(
            list(self.result.state.evidence_refs),
            sorted({e for ref in self.result.state.invariant_refs for e in ref.evidence_ids}),
        )

    def test_the_evidence_is_proof_for_version_zero(self) -> None:
        """What carry-forward needs (C-164): P6 compares the record's hash with the state's."""
        service = EvidenceService()
        context = EvidenceContext.state(self.result.state.state_id)
        with self.uow() as u:
            for ref in self.result.state.invariant_refs:
                for evidence_id in ref.evidence_ids:
                    check = service.usable_as_proof(u, evidence_id, context)
                    self.assertTrue(check.usable, (ref.invariant_id, check.reasons))

    def test_state_created_is_appended_once(self) -> None:
        with self.uow() as u:
            events = [
                e
                for e in u.audit.list_for_correlation(CONTEXT.correlation_id)
                if e.event_type is AuditEventType.STATE_CREATED
            ]
        [event] = events
        self.assertEqual(event.state_id, self.result.state.state_id)
        self.assertEqual(
            event.event_id,
            oids.baseline_event_id_for(BASELINE_ID, AuditEventType.STATE_CREATED),
        )

    def test_the_gates_passed(self) -> None:
        by = {r.target_id: r.result for r in self.result.report.results}
        self.assertIs(by["STRUCTURAL"], VerificationResult.PASS)
        self.assertIs(by["CONSISTENCY"], VerificationResult.PASS)


class TestTheWriteOrder(BaselineCase):
    def test_the_evidence_is_written_before_the_state_in_one_unit_of_work(self) -> None:
        log: list[str] = []
        opened: list[int] = []

        class Repo:
            def __init__(self, inner: Any, name: str) -> None:
                self._inner, self._name = inner, name

            def __getattr__(self, method: str) -> Any:
                target = getattr(self._inner, method)
                if not callable(target):
                    return target

                def call(*args: Any, **kwargs: Any) -> Any:
                    log.append(f"{self._name}.{method}")
                    return target(*args, **kwargs)

                return call

        class Spy:
            def __init__(self, inner: Any) -> None:
                self._inner = inner

            def __enter__(self) -> Spy:
                self._inner.__enter__()
                opened.append(1)
                return self

            def __exit__(self, *exc: Any) -> Any:
                return self._inner.__exit__(*exc)

            def __getattr__(self, name: str) -> Any:
                return Repo(getattr(self._inner, name), name)

        establish_baseline(lambda: Spy(self.uow()), request_for())
        evidence = [i for i, entry in enumerate(log) if entry == "evidence.append"]
        state = log.index("trusted_states.save_baseline")
        self.assertTrue(evidence)
        self.assertTrue(all(i < state for i in evidence), log)
        self.assertEqual(len(opened), 1)  # one unit of work, so one transaction


class TestIdempotency(BaselineCase):
    def test_a_second_call_is_a_duplicate_and_writes_nothing(self) -> None:
        first = self.establish()
        before = dump(self.path)
        second = self.establish()
        self.assertTrue(second.duplicate)
        self.assertEqual(second.state, first.state)
        self.assertEqual(dict(second.evidence_ids), dict(first.evidence_ids))
        self.assertEqual(dump(self.path), before)

    def test_another_configuration_under_the_same_baseline_id_conflicts(self) -> None:
        self.establish()
        before = dump(self.path)
        with self.assertRaises(ConflictingDuplicateError):
            self.establish(request_for(SAFE_DIR))
        self.assertEqual(dump(self.path), before)

    def test_a_second_baseline_for_the_same_lineage_is_refused(self) -> None:
        self.establish()
        with self.assertRaises(BaselineRefused) as refused:
            self.establish(request_for(baseline_id=uid(3101)))
        self.assertTrue(any("already" in r for r in refused.exception.reasons))
        self.assertEqual(self.count("trusted_states"), 1)


class TestRefusals(BaselineCase):
    """Each refusal stores one ERROR record and one ERROR_OCCURRED event and nothing else."""

    def assert_refused(self, request: BaselineRequest, needle: str, **options: Any) -> None:
        with self.assertRaises(BaselineRefused) as refused:
            self.establish(request, **options)
        self.assertTrue(
            any(needle in reason for reason in refused.exception.reasons),
            (needle, refused.exception.reasons),
        )
        self.assertEqual(
            self.tables(),
            {
                "trusted_states": 0,
                "lineage_heads": 0,
                "invariants": 0,
                "invariant_refs": 0,
                "evidence_events": 1,
                "audit_events": 1,
            },
        )
        with self.uow() as u:
            [error] = u.evidence.list_for_correlation(CONTEXT.correlation_id)
            [event] = u.audit.list_for_correlation(CONTEXT.correlation_id)
        self.assertIs(error.kind, EvidenceKind.ERROR)
        self.assertIsNone(error.state_id)
        self.assertIs(event.event_type, AuditEventType.ERROR_OCCURRED)

    def test_a_fixture_not_declared_eligible(self) -> None:
        self.assert_refused(request_for(eligible=False), "eligible")

    def test_a_verifier_error(self) -> None:
        self.assert_refused(request_for(verifiers=with_reachability(raising)), "VERIFIER_ERROR")

    def test_a_failing_structural_gate(self) -> None:
        real = __import__("core.verification.engine", fromlist=["run_work_set"]).run_work_set

        def broken(work: Any, inputs: Any, **kwargs: Any) -> Any:
            return real(work, dataclasses.replace(inputs, candidate_state_hash="0" * 64), **kwargs)

        with mock.patch("core.application.baseline.run_work_set", broken):
            self.assert_refused(request_for(), "STRUCTURAL")

    def test_an_unparseable_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "main.tf").write_text('resource "aws_instance" {{{\n', encoding="utf-8")
            self.assert_refused(request_for(Path(tmp)), "normalization")

    def test_an_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_refused(request_for(Path(tmp)), "no configuration files")

    def test_a_repeat_after_a_refusal_stores_nothing_new(self) -> None:
        request = request_for(eligible=False)
        with self.assertRaises(BaselineRefused):
            self.establish(request)
        before = dump(self.path)
        with self.assertRaises(BaselineRefused):
            self.establish(request)
        self.assertEqual(dump(self.path), before)

    def test_a_refusal_for_another_reason_is_not_a_conflict(self) -> None:
        with self.assertRaises(BaselineRefused):
            self.establish(request_for(eligible=False))
        with self.assertRaises(BaselineRefused):
            self.establish(request_for(verifiers=with_reachability(raising)))
        self.assertEqual(self.count("evidence_events"), 2)

    def test_a_refused_baseline_can_be_established_once_the_cause_is_gone(self) -> None:
        with self.assertRaises(BaselineRefused):
            self.establish(request_for(eligible=False))
        result = self.establish(request_for())
        self.assertEqual(result.state.version, 0)


class TestUncertaintyIsRecordedAsUncertain(BaselineCase):
    def test_an_unknown_result_gives_an_uncertain_reference_never_protected(self) -> None:
        result = self.establish(request_for(verifiers=with_reachability(unknown)))
        by = {r.invariant_id: r.status for r in result.state.invariant_refs}
        self.assertIs(by[FUNC], InvariantStatus.UNCERTAIN)
        self.assertIs(by[SEC1], InvariantStatus.VIOLATED)
        self.assertIs(by[SEC2], InvariantStatus.PROTECTED)


class TestTheWriteIsAtomic(BaselineCase):
    POINTS = (
        "after_trusted_state_insert",
        "after_invariant_refs_insert",
        "after_lineage_head_update",
        "before_commit",
    )

    def test_a_failure_at_each_checkpoint_leaves_nothing(self) -> None:
        for point in self.POINTS:
            with self.subTest(point=point):
                gate = Gate(point, fail=True)
                gate.release.set()
                with self.assertRaises(Exception) as caught:
                    self.establish(checkpoint=gate)
                self.assertTrue(gate.fired)
                self.assertTrue(
                    isinstance(caught.exception, InjectedFault)
                    or isinstance(caught.exception.__cause__, InjectedFault)
                    or "InjectedFault" in repr(caught.exception),
                    repr(caught.exception),
                )
                self.assertEqual(
                    self.tables(),
                    {
                        "trusted_states": 0,
                        "lineage_heads": 0,
                        "invariants": 0,
                        "invariant_refs": 0,
                        "evidence_events": 0,
                        "audit_events": 0,
                    },
                )

    def test_after_a_failure_the_same_request_succeeds(self) -> None:
        gate = Gate("after_lineage_head_update", fail=True)
        gate.release.set()
        with self.assertRaises((InjectedFault, PersistenceError)):
            self.establish(checkpoint=gate)
        result = self.establish()
        self.assertEqual(result.state.version, 0)
        self.assertEqual(self.count("lineage_heads"), 1)


class TestArguments(BaselineCase):
    def test_wrong_types_are_refused(self) -> None:
        with self.assertRaises(DomainValidationError):
            establish_baseline(self.factory(), {"baseline_id": BASELINE_ID})  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            establish_baseline("not a factory", request_for())  # type: ignore[arg-type]
        for bad in (
            {"baseline_id": "x"},
            {"lineage_id": "x"},
            {"eligible": "yes"},
            {"definitions": ()},
            {"baseline_dir": "fixtures"},
        ):
            with self.subTest(bad=bad), self.assertRaises(DomainValidationError):
                self.establish(request_for(**bad))


if __name__ == "__main__":
    unittest.main()
