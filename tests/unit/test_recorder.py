"""The orchestrator's derived ids and the stage recorder (P6c step 2; Doc 11 §5, §8-§12, §25, §28,
§38; Doc 06 §28; C-54, C-55, C-170 (4), C-172).

HAND EXPECTATIONS (written from the P6c prompt and the specs, not from the code):

* every id is ``uuid5(ORCHESTRATOR_NAMESPACE, "<kind>:<candidate_id>:<attempt>[:<stage>...]")``;
  the namespace is the constant below, so a change of it (or of a key) is a visible test failure;
* a stage record is bound to the candidate: ``candidate_id``, ``parent_state_id``, the candidate's
  ``state_hash`` and the attempt, run and correlation ids of the context (C-55); its kind is STATE,
  IDENTITY, DEPENDENCY, IMPACT or VERIFICATION (one per result); IMPACT is candidate-bound (C-54);
* the audit events are IDENTITY_COMPLETED, DEPENDENCY_COMPLETED, IMPACT_COMPLETED and one
  VERIFICATION_COMPLETED per result, each naming the evidence record it belongs to;
* recording the same thing again changes nothing (a duplicate is accepted); another content under
  the same id raises ``ConflictingDuplicateError``; a payload with a secret is refused and nothing
  is stored.
"""

from __future__ import annotations

import unittest
import uuid
from functools import cache
from typing import Any

from core.application import ids as oids
from core.application.recorder import StageRecorder
from core.domain.audit import AuditEventType
from core.domain.errors import DomainValidationError
from core.domain.evidence import ArtifactRef, EvidenceKind
from core.domain.promotion import ConflictingDuplicateError
from tests.domain_builders import patch_for, uid
from tests.identity_builders import NOW as PIPELINE_NOW
from tests.promotion_commit_builders import CONTEXT, NOW, dump
from tests.promotion_pipeline import PipelineRun, fixtures_with_a_parent, pipeline
from tests.promotion_pipeline_commit import PipelineCommitCase

SAFE = "canonical_safe_repair_promote_v1"
REGRESSION = "canonical_security_repair_breaks_function_reject_v1"
NAMESPACE = uuid.UUID("5e1d7a43-92c0-4b6f-8d3a-17f4c9e02b68")
CID = uid(3001)
AT = PIPELINE_NOW


def without(data: dict[str, Any], key: str) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k != key}


def expected(key: str) -> str:
    return str(uuid.uuid5(NAMESPACE, key))


@cache
def run_of(fixture_id: str) -> PipelineRun:
    return pipeline(fixtures_with_a_parent()[fixture_id])


class TestDerivedIds(unittest.TestCase):
    def test_the_namespace_is_a_pinned_constant(self) -> None:
        self.assertEqual(oids.ORCHESTRATOR_NAMESPACE, NAMESPACE)

    def test_it_is_not_the_namespace_of_the_promotion_package(self) -> None:
        from core.promotion.ids import PROMOTION_NAMESPACE

        self.assertNotEqual(oids.ORCHESTRATOR_NAMESPACE, PROMOTION_NAMESPACE)

    def test_the_decision_id(self) -> None:
        self.assertEqual(oids.decision_id_for(CID, 1), expected(f"decision:{CID}:1"))
        self.assertNotEqual(oids.decision_id_for(CID, 1), oids.decision_id_for(CID, 2))
        self.assertNotEqual(oids.decision_id_for(CID, 1), oids.decision_id_for(uid(3002), 1))

    def test_the_evidence_id(self) -> None:
        self.assertEqual(oids.evidence_id_for(CID, 1, "state"), expected(f"evidence:{CID}:1:state"))
        self.assertEqual(
            oids.evidence_id_for(CID, 2, "verification", "STRUCTURAL"),
            expected(f"evidence:{CID}:2:verification:STRUCTURAL"),
        )
        ids = {
            oids.evidence_id_for(CID, 1, stage)
            for stage in ("state", "identity", "dependency", "impact", "error")
        }
        self.assertEqual(len(ids), 5)

    def test_the_event_id(self) -> None:
        self.assertEqual(
            oids.event_id_for(CID, 1, AuditEventType.IMPACT_COMPLETED),
            expected(f"event:{CID}:1:IMPACT_COMPLETED"),
        )
        self.assertEqual(
            oids.event_id_for(CID, 1, AuditEventType.VERIFICATION_COMPLETED, "RESOURCE:a.b"),
            expected(f"event:{CID}:1:VERIFICATION_COMPLETED:RESOURCE:a.b"),
        )

    def test_the_verification_id_source_counts_from_zero_and_repeats(self) -> None:
        first = oids.verification_ids(CID, 1)
        second = oids.verification_ids(CID, 1)
        got = [first() for _ in range(3)]
        self.assertEqual(got, [expected(f"verification:{CID}:1:{n}") for n in range(3)])
        self.assertEqual([second() for _ in range(3)], got)
        other = oids.verification_ids(CID, 2)
        self.assertNotEqual(other(), got[0])

    def test_the_baseline_ids(self) -> None:
        base = uid(3100)
        self.assertEqual(oids.baseline_state_id_for(base), expected(f"baseline-state:{base}"))
        self.assertEqual(
            oids.baseline_evidence_id_for(base, "verification", "INVARIANT:INV-SEC-001:1"),
            expected(f"baseline-evidence:{base}:verification:INVARIANT:INV-SEC-001:1"),
        )
        self.assertEqual(
            oids.baseline_event_id_for(base, AuditEventType.STATE_CREATED),
            expected(f"baseline-event:{base}:STATE_CREATED"),
        )
        source = oids.baseline_verification_ids(base)
        self.assertEqual(source(), expected(f"baseline-verification:{base}:0"))
        self.assertEqual(source(), expected(f"baseline-verification:{base}:1"))

    def test_bad_arguments_are_refused(self) -> None:
        for call in (
            lambda: oids.decision_id_for("not-a-uuid", 1),
            lambda: oids.decision_id_for(CID, 0),
            lambda: oids.decision_id_for(CID, True),
            lambda: oids.decision_id_for(CID, "1"),
            lambda: oids.evidence_id_for(CID, 1, "nonsense"),
            lambda: oids.evidence_id_for(CID, 1, "state", ""),
            lambda: oids.event_id_for(CID, 1, "IMPACT_COMPLETED"),
            lambda: oids.verification_ids("x", 1),
            lambda: oids.baseline_state_id_for("x"),
        ):
            with self.assertRaises(DomainValidationError):
                call()


class RecorderCase(PipelineCommitCase):
    def setUp(self) -> None:
        super().setUp()
        self.run = run_of(SAFE)
        self.install(self.run)
        self.candidate = self.store(self.run)
        self.recorder = StageRecorder(CONTEXT)

    def evidence_rows(self) -> list[Any]:
        with self.uow() as u:
            return list(u.evidence.list_for_candidate(self.candidate.candidate_id))

    def events(self) -> list[Any]:
        with self.uow() as u:
            return list(u.audit.list_for_candidate(self.candidate.candidate_id))

    def payload(self, evidence_id: str) -> Any:
        with self.uow() as u:
            event = u.evidence.get(evidence_id)
            assert event is not None
            return u.evidence.resolve(ArtifactRef.parse(event.payload_ref))

    def event_payload(self, event: Any) -> Any:
        with self.uow() as u:
            return u.evidence.resolve(ArtifactRef.parse(event.payload_ref))

    def record_all(self) -> dict[str, str]:
        patch = patch_for(self.run.trusted, n=7)
        cid = self.candidate.candidate_id
        with self.uow() as u:
            self.recorder.record_candidate(u, self.candidate, patch, attempt_number=1, at=AT)
        with self.uow() as u:
            self.recorder.record_identity(
                u, self.candidate, self.run.inputs.identity, attempt_number=1, at=AT, when=NOW
            )
        with self.uow() as u:
            self.recorder.record_dependency(
                u,
                self.candidate,
                self.run.inputs.candidate_graph,
                attempt_number=1,
                at=AT,
                when=NOW,
            )
        with self.uow() as u:
            self.recorder.record_impact(
                u, self.candidate, self.run.impact, attempt_number=1, at=AT, when=NOW
            )
        with self.uow() as u:
            found = self.recorder.record_verification(
                u, self.candidate, self.run.verification, attempt_number=1, when=NOW
            )
        assert cid == self.candidate.candidate_id
        return found


class TestStageRecords(RecorderCase):
    def test_the_state_record_is_bound_to_the_candidate(self) -> None:
        patch = patch_for(self.run.trusted, n=7)
        with self.uow() as u:
            evidence_id = self.recorder.record_candidate(
                u, self.candidate, patch, attempt_number=1, at=AT
            )
        self.assertEqual(evidence_id, oids.evidence_id_for(self.candidate.candidate_id, 1, "state"))
        [row] = self.evidence_rows()
        self.assertEqual(row.evidence_id, evidence_id)
        self.assertIs(row.kind, EvidenceKind.STATE)
        self.assertEqual(row.candidate_id, self.candidate.candidate_id)
        self.assertEqual(row.parent_state_id, self.run.trusted.state_id)
        self.assertEqual(row.state_hash, self.candidate.state_hash)
        self.assertIsNone(row.state_id)
        self.assertEqual(
            (row.run_id, row.attempt_id, row.correlation_id, row.operation_id),
            (CONTEXT.run_id, CONTEXT.attempt_id, CONTEXT.correlation_id, CONTEXT.operation_id),
        )
        body = self.payload(evidence_id)
        self.assertEqual(body["patch_id"], patch.patch_id)
        self.assertEqual(body["patch_hash"], patch.content_hash)
        self.assertEqual(body["state_hash"], self.candidate.state_hash)
        self.assertEqual(body["parent_state_id"], self.run.trusted.state_id)

    def test_identity_dependency_and_impact_records_and_events(self) -> None:
        self.record_all()
        kinds = {row.kind: row for row in self.evidence_rows()}
        cid = self.candidate.candidate_id
        for kind, stage in (
            (EvidenceKind.IDENTITY, "identity"),
            (EvidenceKind.DEPENDENCY, "dependency"),
            (EvidenceKind.IMPACT, "impact"),
        ):
            with self.subTest(kind=kind):
                row = kinds[kind]
                self.assertEqual(row.evidence_id, oids.evidence_id_for(cid, 1, stage))
                self.assertEqual(row.candidate_id, cid)
                self.assertEqual(row.parent_state_id, self.run.trusted.state_id)
                self.assertEqual(row.state_hash, self.candidate.state_hash)
                self.assertEqual(row.attempt_id, CONTEXT.attempt_id)
        # the report as the domain writes it, without the random id the engine drew for it
        self.assertEqual(
            self.payload(kinds[EvidenceKind.IMPACT].evidence_id),
            without(self.run.impact.to_dict(), "report_id"),
        )
        self.assertEqual(
            self.payload(kinds[EvidenceKind.IDENTITY].evidence_id),
            without(self.run.inputs.identity.to_dict(), "report_id"),
        )
        self.assertEqual(
            self.payload(kinds[EvidenceKind.DEPENDENCY].evidence_id),
            without(self.run.inputs.candidate_graph.to_dict(), "graph_id"),
        )
        wanted = {
            AuditEventType.IDENTITY_COMPLETED: EvidenceKind.IDENTITY,
            AuditEventType.DEPENDENCY_COMPLETED: EvidenceKind.DEPENDENCY,
            AuditEventType.IMPACT_COMPLETED: EvidenceKind.IMPACT,
        }
        got = {e.event_type: e for e in self.events() if e.event_type in wanted}
        self.assertEqual(set(got), set(wanted))
        for event_type, kind in wanted.items():
            self.assertEqual(
                self.event_payload(got[event_type])["evidence_id"], kinds[kind].evidence_id
            )
            self.assertEqual(got[event_type].candidate_id, cid)

    def test_one_verification_record_and_event_per_result(self) -> None:
        found = self.record_all()
        results = self.run.verification.results
        cid = self.candidate.candidate_id
        self.assertEqual(set(found), {r.verification_id for r in results})
        rows = {
            r.evidence_id: r for r in self.evidence_rows() if r.kind is EvidenceKind.VERIFICATION
        }
        self.assertEqual(len(rows), len(results))
        for result in results:
            with self.subTest(target=result.target_id):
                evidence_id = found[result.verification_id]
                self.assertEqual(
                    evidence_id, oids.evidence_id_for(cid, 1, "verification", result.target_id)
                )
                row = rows[evidence_id]
                self.assertEqual(row.candidate_id, cid)
                self.assertEqual(row.parent_state_id, self.run.trusted.state_id)
                self.assertEqual(row.state_hash, self.candidate.state_hash)
                self.assertEqual(row.attempt_id, CONTEXT.attempt_id)
                self.assertEqual(
                    self.payload(evidence_id)["verification_id"], result.verification_id
                )
        done = [
            self.event_payload(e)
            for e in self.events()
            if e.event_type is AuditEventType.VERIFICATION_COMPLETED
        ]
        self.assertEqual(
            sorted((p["verification_id"], p["target"], p["result"]) for p in done),
            sorted((r.verification_id, r.target_id, r.result.value) for r in results),
        )
        for body in done:
            self.assertIn(body["evidence_id"], found.values())

    def test_events_follow_the_stages_in_sequence_order(self) -> None:
        self.record_all()
        types = [e.event_type for e in self.events()]
        n = len(self.run.verification.results)
        self.assertEqual(
            types,
            [
                AuditEventType.IDENTITY_COMPLETED,
                AuditEventType.DEPENDENCY_COMPLETED,
                AuditEventType.IMPACT_COMPLETED,
                *[AuditEventType.VERIFICATION_COMPLETED] * n,
            ],
        )


class TestIdempotency(RecorderCase):
    def test_recording_everything_again_writes_nothing(self) -> None:
        first = self.record_all()
        before = dump(self.path)
        second = self.record_all()
        self.assertEqual(first, second)
        self.assertEqual(dump(self.path), before)

    def test_a_rerun_of_the_pipeline_records_the_same_payloads(self) -> None:
        """R1 of the P6c prompt: the identity, dependency and impact engines draw a new random
        ``report_id`` or ``graph_id`` on every run (there is no injection point). Those two ids are
        outside the content hash; the recorder leaves them out of the payload, so a rerun that
        computes the reports again records duplicates, not conflicts."""
        self.record_all()
        before = dump(self.path)
        again = pipeline(fixtures_with_a_parent()[SAFE])
        self.assertNotEqual(again.impact.report_id, self.run.impact.report_id)
        self.assertNotEqual(again.inputs.identity.report_id, self.run.inputs.identity.report_id)
        self.assertNotEqual(
            again.inputs.candidate_graph.graph_id, self.run.inputs.candidate_graph.graph_id
        )
        self.run = again
        self.record_all()
        self.assertEqual(dump(self.path), before)

    def test_another_report_under_the_same_ids_raises_and_stores_nothing(self) -> None:
        self.record_all()
        before = dump(self.path)
        other = run_of(REGRESSION)
        for call in (
            lambda u: self.recorder.record_identity(
                u, self.candidate, other.inputs.identity, attempt_number=1, at=AT, when=NOW
            ),
            lambda u: self.recorder.record_dependency(
                u, self.candidate, other.inputs.candidate_graph, attempt_number=1, at=AT, when=NOW
            ),
            lambda u: self.recorder.record_impact(
                u, self.candidate, other.impact, attempt_number=1, at=AT, when=NOW
            ),
        ):
            with self.assertRaises(ConflictingDuplicateError), self.uow() as u:
                call(u)
        self.assertEqual(dump(self.path), before)

    def test_another_candidate_under_the_same_state_record_raises(self) -> None:
        """The same candidate id and attempt, built from another configuration (another state
        hash): the STATE record of the first is not overwritten."""
        self.record_all()
        other = run_of(REGRESSION)
        self.assertEqual(other.candidate.candidate_id, self.candidate.candidate_id)
        self.assertNotEqual(other.candidate.state_hash, self.candidate.state_hash)
        patch = patch_for(other.trusted, n=7)
        before = dump(self.path)
        with self.assertRaises(ConflictingDuplicateError), self.uow() as u:
            self.recorder.record_candidate(u, other.candidate, patch, attempt_number=1, at=AT)
        self.assertEqual(dump(self.path), before)

    def test_the_same_candidate_in_another_attempt_is_a_different_record(self) -> None:
        self.record_all()
        with self.uow() as u:
            self.recorder.record_impact(
                u, self.candidate, self.run.impact, attempt_number=2, at=AT, when=NOW
            )
        impact = [r for r in self.evidence_rows() if r.kind is EvidenceKind.IMPACT]
        self.assertEqual(len(impact), 2)


class TestEmit(RecorderCase):
    def event_args(self) -> dict[str, Any]:
        return {
            "event_id": oids.event_id_for(
                self.candidate.candidate_id, 1, AuditEventType.CANDIDATE_CREATED
            ),
            "payload": {
                "parent_state_id": self.run.trusted.state_id,
                "patch_id": uid(77),
                "source": "FIXED_PATCH",
            },
            "when": NOW,
            "candidate_id": self.candidate.candidate_id,
        }

    def test_emit_appends_once(self) -> None:
        with self.uow() as u:
            self.recorder.emit(u, AuditEventType.CANDIDATE_CREATED, **self.event_args())
        before = dump(self.path)
        with self.uow() as u:
            self.recorder.emit(u, AuditEventType.CANDIDATE_CREATED, **self.event_args())
        self.assertEqual(dump(self.path), before)
        [event] = self.events()
        self.assertIs(event.event_type, AuditEventType.CANDIDATE_CREATED)
        self.assertEqual(event.correlation_id, CONTEXT.correlation_id)
        self.assertEqual(event.operation_id, CONTEXT.operation_id)

    def test_another_payload_under_the_same_event_id_raises(self) -> None:
        with self.uow() as u:
            self.recorder.emit(u, AuditEventType.CANDIDATE_CREATED, **self.event_args())
        changed = self.event_args()
        changed["payload"] = {**changed["payload"], "patch_id": uid(78)}
        before = dump(self.path)
        with self.assertRaises(ConflictingDuplicateError), self.uow() as u:
            self.recorder.emit(u, AuditEventType.CANDIDATE_CREATED, **changed)
        self.assertEqual(dump(self.path), before)

    def test_a_missing_required_payload_key_is_refused(self) -> None:
        args = self.event_args()
        args["payload"] = {"parent_state_id": self.run.trusted.state_id}
        with self.assertRaises(DomainValidationError), self.uow() as u:
            self.recorder.emit(u, AuditEventType.CANDIDATE_CREATED, **args)
        self.assertEqual(self.events(), [])

    def test_a_payload_with_a_secret_is_refused_not_stored(self) -> None:
        args = self.event_args()
        args["payload"] = {**args["payload"], "note": "AKIA" + "IOSFODNN7" + "EXAMPLE"}
        before = dump(self.path)
        with self.assertRaises(DomainValidationError), self.uow() as u:
            self.recorder.emit(u, AuditEventType.CANDIDATE_CREATED, **args)
        self.assertEqual(dump(self.path), before)


class TestErrorRecords(RecorderCase):
    def test_a_candidate_bound_error_record_and_its_event(self) -> None:
        with self.uow() as u:
            evidence_id = self.recorder.record_error(
                u,
                stage="normalize",
                error_type="ConstructionFailed",
                detail={"status": "INVALID", "diagnostics": ["x.tf: bad block"]},
                attempt_number=1,
                at=AT,
                when=NOW,
                candidate=self.candidate,
            )
        self.assertEqual(evidence_id, oids.evidence_id_for(self.candidate.candidate_id, 1, "error"))
        [row] = self.evidence_rows()
        self.assertIs(row.kind, EvidenceKind.ERROR)
        self.assertEqual(row.candidate_id, self.candidate.candidate_id)
        self.assertEqual(row.parent_state_id, self.run.trusted.state_id)
        self.assertEqual(row.attempt_id, CONTEXT.attempt_id)
        [event] = self.events()
        self.assertIs(event.event_type, AuditEventType.ERROR_OCCURRED)
        body = self.event_payload(event)
        self.assertEqual(body["evidence_id"], evidence_id)
        self.assertEqual(body["stage"], "normalize")
        self.assertEqual(body["error_type"], "ConstructionFailed")

    def test_the_error_record_of_a_failed_candidate_is_unbound_and_names_the_candidate(
        self,
    ) -> None:
        """A candidate that never got a state hash cannot bind evidence (Doc 11 §44): the ERROR
        record is unbound, its payload and its audit event name the candidate."""
        from core.domain.state import CandidateState, fail_building, start_building
        from tests.domain_builders import patch_for as make_patch

        trusted = self.run.trusted
        created = CandidateState.create(
            parent=trusted,
            patch=make_patch(trusted, n=21),
            candidate_sequence=5,
            now=AT,
            candidate_id=uid(3500),
        )
        failed = fail_building(start_building(created), "the configuration does not parse")
        self.assertIsNone(failed.state_hash)
        with self.uow() as u:
            u.patches.save(make_patch(trusted, n=21))
            u.candidates.create(created)
            u.candidates.save_transition(start_building(created))
            u.candidates.save_transition(failed)
            evidence_id = self.recorder.record_error(
                u,
                stage="normalize",
                error_type="ConstructionFailed",
                detail={"status": "INVALID"},
                attempt_number=1,
                at=AT,
                when=NOW,
                candidate=failed,
            )
            row = u.evidence.get(evidence_id)
            events = u.audit.list_for_candidate(failed.candidate_id)
            body = u.evidence.resolve(ArtifactRef.parse(row.payload_ref)) if row else None
        assert row is not None
        self.assertIs(row.kind, EvidenceKind.ERROR)
        self.assertEqual(
            (row.candidate_id, row.state_id, row.parent_state_id, row.state_hash),
            (None, None, None, None),
        )
        self.assertEqual(body["candidate_id"], failed.candidate_id)
        self.assertEqual([e.event_type for e in events], [AuditEventType.ERROR_OCCURRED])

    def test_an_unbound_error_record_has_no_state_and_no_candidate(self) -> None:
        base = uid(3100)
        with self.uow() as u:
            evidence_id = self.recorder.record_error(
                u,
                stage="baseline",
                error_type="BaselineRefused",
                detail={"reasons": ["not eligible"]},
                attempt_number=1,
                at=AT,
                when=NOW,
                evidence_id=oids.baseline_evidence_id_for(base, "error"),
                event_id=oids.baseline_event_id_for(base, AuditEventType.ERROR_OCCURRED),
            )
            row = u.evidence.get(evidence_id)
        assert row is not None
        self.assertEqual(
            (row.candidate_id, row.state_id, row.parent_state_id, row.state_hash),
            (None, None, None, None),
        )

    def test_an_error_detail_with_a_secret_is_refused(self) -> None:
        before = dump(self.path)
        with self.assertRaises(DomainValidationError), self.uow() as u:
            self.recorder.record_error(
                u,
                stage="normalize",
                error_type="X",
                detail={"message": "key " + "AKIA" + "IOSFODNN7" + "EXAMPLE"},
                attempt_number=1,
                at=AT,
                when=NOW,
                candidate=self.candidate,
            )
        self.assertEqual(dump(self.path), before)


class TestArguments(RecorderCase):
    def test_wrong_types_are_refused(self) -> None:
        with self.assertRaises(DomainValidationError):
            StageRecorder("context")  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError), self.uow() as u:
            self.recorder.record_impact(
                u, self.candidate, {"x": 1}, attempt_number=1, at=AT, when=NOW  # type: ignore[arg-type]
            )
        with self.assertRaises(DomainValidationError), self.uow() as u:
            self.recorder.record_impact(
                u, "candidate", self.run.impact, attempt_number=1, at=AT, when=NOW  # type: ignore[arg-type]
            )

    def test_a_report_for_another_candidate_is_refused(self) -> None:
        other = run_of(REGRESSION)
        self.assertNotEqual(other.impact.candidate_id, "")
        different = pipeline(
            fixtures_with_a_parent()[SAFE], candidate_id=uid(3999), sequence=2, patch_n=9
        )
        with self.assertRaises(DomainValidationError), self.uow() as u:
            self.recorder.record_impact(
                u, self.candidate, different.impact, attempt_number=1, at=AT, when=NOW
            )
        with self.assertRaises(DomainValidationError), self.uow() as u:
            self.recorder.record_verification(
                u, self.candidate, different.verification, attempt_number=1, when=NOW
            )


if __name__ == "__main__":
    unittest.main()
