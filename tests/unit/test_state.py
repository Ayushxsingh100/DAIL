"""CandidateState and TrustedState (Doc 05 §7, §8, §22, §23, §28; Doc 06 §4, §5, §6, §20, §24, §30;
C-29, C-31, C-32, C-33; P1a step 12)."""

from __future__ import annotations

import dataclasses
import json
import unittest
from datetime import datetime
from typing import Any

from core.domain.enums import CandidateSource, CandidateStatus, InvariantStatus
from core.domain.errors import (
    DomainValidationError,
    HashMismatchError,
    IllegalTransitionError,
    UnauthorizedConstructionError,
)
from core.domain.state import (
    CandidateState,
    TrustedState,
    fail_building,
    finish_building,
    mark_promoted,
    resource_set_hash,
    start_building,
    transition_candidate,
)
from tests.domain_builders import (
    FUNC,
    LINEAGE,
    NORMALIZATION,
    SEC,
    at,
    baseline,
    canonical_resources,
    new_candidate,
    patch_for,
    promotable_candidate,
    promote,
    proof,
    ready_candidate,
    resource,
    uid,
)

CS = CandidateStatus


class TestCandidateCreate(unittest.TestCase):
    def setUp(self) -> None:
        self.parent = baseline()
        self.patch = patch_for(self.parent)
        self.candidate = CandidateState.create(
            parent=self.parent,
            patch=self.patch,
            candidate_sequence=1,
            now=at(3),
            candidate_id=uid(3001),
        )

    def test_a_new_candidate_copies_its_parent_and_patch(self) -> None:
        c = self.candidate
        self.assertEqual(c.parent_state_id, self.parent.state_id)
        self.assertEqual(c.lineage_id, self.parent.lineage_id)
        self.assertEqual(c.normalization_version, self.parent.normalization_version)
        self.assertEqual(c.source, CandidateSource.FIXED_PATCH)
        self.assertEqual(c.patch_id, self.patch.patch_id)
        self.assertEqual(c.patch_hash, self.patch.content_hash)
        self.assertEqual(c.candidate_sequence, 1)
        self.assertEqual(c.created_at, at(3))

    def test_a_new_candidate_is_created_and_empty(self) -> None:
        c = self.candidate
        self.assertEqual(c.status, CS.CREATED)
        self.assertEqual(c.resources, ())
        self.assertIsNone(c.state_hash)
        self.assertIsNone(c.status_reason)
        self.assertEqual(c.construction_status, CS.BUILDING)

    def test_candidate_id_is_generated_when_omitted(self) -> None:
        a = CandidateState.create(
            parent=self.parent, patch=self.patch, candidate_sequence=1, now=at(3)
        )
        b = CandidateState.create(
            parent=self.parent, patch=self.patch, candidate_sequence=1, now=at(3)
        )
        self.assertNotEqual(a.candidate_id, b.candidate_id)

    def test_the_parent_must_be_a_trusted_state(self) -> None:
        """DATA-INT-002: a candidate cannot reference another candidate as its trusted parent."""
        for bad in (self.candidate, None, self.parent.to_dict(), "state"):
            with (
                self.subTest(parent=type(bad).__name__),
                self.assertRaises(DomainValidationError) as ctx,
            ):
                CandidateState.create(
                    parent=bad,  # type: ignore[arg-type]
                    patch=self.patch,
                    candidate_sequence=1,
                    now=at(3),
                )
            self.assertIn("DATA-INT-002", str(ctx.exception))

    def test_the_patch_must_belong_to_the_parent(self) -> None:
        other = baseline(state_id=uid(77))
        with self.assertRaises(DomainValidationError) as ctx:
            CandidateState.create(parent=other, patch=self.patch, candidate_sequence=1, now=at(3))
        self.assertIn("DATA-INT-001", str(ctx.exception))
        with self.assertRaises(DomainValidationError):
            CandidateState.create(
                parent=self.parent,
                patch=self.patch.to_dict(),  # type: ignore[arg-type]
                candidate_sequence=1,
                now=at(3),
            )

    def test_sequence_ids_and_time_are_validated(self) -> None:
        for bad in (0, -1, 1.5, "1", None, True):
            with self.subTest(sequence=bad), self.assertRaises(DomainValidationError):
                CandidateState.create(
                    parent=self.parent,
                    patch=self.patch,
                    candidate_sequence=bad,  # type: ignore[arg-type]
                    now=at(3),
                )
        with self.assertRaises(DomainValidationError):
            CandidateState.create(
                parent=self.parent,
                patch=self.patch,
                candidate_sequence=1,
                now=at(3),
                candidate_id="c-1",
            )
        with self.assertRaises(DomainValidationError):
            CandidateState.create(
                parent=self.parent,
                patch=self.patch,
                candidate_sequence=1,
                now=datetime(2026, 10, 1),
            )


class TestConstructionStatus(unittest.TestCase):
    """C-29: ``construction_status`` is derived from the single ``status`` field."""

    def test_mapping_for_every_status(self) -> None:
        parent = baseline()
        resources = canonical_resources(ssh_open=False, db_path=True)
        created = new_candidate(parent)
        building = start_building(created)
        failed = fail_building(building, "parse error")
        ready = finish_building(building, resources)
        analyzing = transition_candidate(ready, CS.ANALYZING)
        promotable = transition_candidate(analyzing, CS.PROMOTABLE)
        rejected = transition_candidate(analyzing, CS.REJECTED)
        retry = transition_candidate(analyzing, CS.RETRY_REQUIRED)
        escalated = transition_candidate(analyzing, CS.ESCALATED)
        promoted = mark_promoted(promotable, promote(promotable, parent))
        expected = [
            (created, CS.BUILDING),
            (building, CS.BUILDING),
            (failed, CS.FAILED),
            (ready, CS.READY),
            (analyzing, CS.READY),
            (promotable, CS.READY),
            (rejected, CS.READY),
            (retry, CS.READY),
            (escalated, CS.READY),
            (promoted, CS.READY),
        ]
        self.assertEqual({c.status for c, _ in expected}, set(CandidateStatus))
        for candidate, construction in expected:
            with self.subTest(status=candidate.status.value):
                self.assertEqual(candidate.construction_status, construction)


class TestBuildFunctions(unittest.TestCase):
    def setUp(self) -> None:
        self.parent = baseline()
        self.created = new_candidate(self.parent)
        self.resources = canonical_resources(ssh_open=False, db_path=True)

    def test_start_building(self) -> None:
        building = start_building(self.created)
        self.assertEqual(building.status, CS.BUILDING)
        self.assertEqual(self.created.status, CS.CREATED)  # the input is unchanged
        with self.assertRaises(IllegalTransitionError):
            start_building(building)

    def test_finish_building_sets_sorted_resources_and_the_state_hash(self) -> None:
        building = start_building(self.created)
        ready = finish_building(building, list(reversed(self.resources)))
        self.assertEqual(ready.status, CS.READY)
        self.assertEqual(
            [r.address for r in ready.resources], sorted(r.address for r in self.resources)
        )
        self.assertEqual(ready.state_hash, resource_set_hash(self.resources, NORMALIZATION))
        self.assertEqual(building.resources, ())
        self.assertIsNone(building.state_hash)

    def test_finish_building_only_from_building(self) -> None:
        for candidate in (self.created, ready_candidate(self.parent, self.resources)):
            with (
                self.subTest(status=candidate.status.value),
                self.assertRaises(IllegalTransitionError),
            ):
                finish_building(candidate, self.resources)

    def test_finish_building_rejects_duplicate_addresses_and_non_resources(self) -> None:
        building = start_building(self.created)
        with self.assertRaises(DomainValidationError):
            finish_building(
                building, [resource("a.x"), resource("a.x", attributes={"size": "big"})]
            )
        with self.assertRaises(DomainValidationError):
            finish_building(building, [resource("a.x"), {"address": "b.x"}])  # type: ignore[list-item]
        with self.assertRaises(DomainValidationError):
            finish_building(building, "aws_instance.app")  # type: ignore[arg-type]

    def test_an_empty_resource_set_is_a_valid_ready_candidate(self) -> None:
        ready = finish_building(start_building(self.created), [])
        self.assertEqual(ready.resources, ())
        self.assertEqual(ready.state_hash, resource_set_hash([], NORMALIZATION))

    def test_fail_building(self) -> None:
        failed = fail_building(start_building(self.created), "syntax error in main.tf")
        self.assertEqual(failed.status, CS.FAILED)
        self.assertEqual(failed.status_reason, "syntax error in main.tf")
        self.assertEqual(failed.resources, ())
        self.assertIsNone(failed.state_hash)
        self.assertEqual(failed.construction_status, CS.FAILED)

    def test_fail_building_requires_a_reason_and_the_building_status(self) -> None:
        building = start_building(self.created)
        for bad in ("", "  ", None):
            with self.subTest(reason=bad), self.assertRaises(DomainValidationError):
                fail_building(building, bad)  # type: ignore[arg-type]
        with self.assertRaises(IllegalTransitionError):
            fail_building(self.created, "reason")
        with self.assertRaises(IllegalTransitionError):
            fail_building(ready_candidate(self.parent, self.resources), "reason")

    def test_functions_reject_non_candidates(self) -> None:
        for func in (start_building,):
            with self.assertRaises(DomainValidationError):
                func({"status": "CREATED"})  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            finish_building("c", [])  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            fail_building(None, "r")  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            transition_candidate(None, CS.ANALYZING)  # type: ignore[arg-type]


class TestTransitionCandidate(unittest.TestCase):
    def setUp(self) -> None:
        self.parent = baseline()
        self.resources = canonical_resources(ssh_open=False, db_path=True)
        self.ready = ready_candidate(self.parent, self.resources)
        self.analyzing = transition_candidate(self.ready, CS.ANALYZING)

    def test_legal_transitions_after_ready(self) -> None:
        self.assertEqual(self.analyzing.status, CS.ANALYZING)
        for target in (CS.REJECTED, CS.RETRY_REQUIRED, CS.ESCALATED, CS.PROMOTABLE):
            with self.subTest(target=target.value):
                self.assertEqual(transition_candidate(self.analyzing, target).status, target)

    def test_the_resource_set_and_hash_never_change_after_ready(self) -> None:
        later = transition_candidate(self.analyzing, CS.PROMOTABLE)
        self.assertEqual(later.state_hash, self.ready.state_hash)
        self.assertEqual(later.resources, self.ready.resources)

    def test_ready_failed_and_promoted_cannot_be_reached_this_way(self) -> None:
        building = start_building(new_candidate(self.parent, n=2))
        for current, target in (
            (building, CS.READY),
            (building, CS.FAILED),
            (transition_candidate(self.analyzing, CS.PROMOTABLE), CS.PROMOTED),
        ):
            with self.subTest(target=target.value), self.assertRaises(IllegalTransitionError):
                transition_candidate(current, target)

    def test_promotable_cannot_be_rejected_by_a_plain_transition(self) -> None:
        promotable = transition_candidate(self.analyzing, CS.PROMOTABLE)
        with self.assertRaises(IllegalTransitionError) as ctx:
            transition_candidate(promotable, CS.REJECTED)
        self.assertIn("C-29", str(ctx.exception))

    def test_illegal_pairs_are_refused(self) -> None:
        for current, target in (
            (self.ready, CS.PROMOTABLE),
            (self.analyzing, CS.READY),
            (self.ready, CS.REJECTED),
        ):
            with (
                self.subTest(current=current.status.value, target=target.value),
                self.assertRaises(IllegalTransitionError),
            ):
                transition_candidate(current, target)

    def test_terminal_candidates_do_not_move(self) -> None:
        for terminal in (CS.REJECTED, CS.RETRY_REQUIRED, CS.ESCALATED):
            done = transition_candidate(self.analyzing, terminal)
            for target in CandidateStatus:
                with (
                    self.subTest(terminal=terminal.value, target=target.value),
                    self.assertRaises(IllegalTransitionError),
                ):
                    transition_candidate(done, target)

    def test_input_is_never_mutated(self) -> None:
        before = self.analyzing.to_dict()
        transition_candidate(self.analyzing, CS.PROMOTABLE)
        self.assertEqual(self.analyzing.to_dict(), before)

    def test_target_must_be_a_candidate_status(self) -> None:
        with self.assertRaises(DomainValidationError):
            transition_candidate(self.ready, "ANALYZING")  # type: ignore[arg-type]


class TestCandidateValidation(unittest.TestCase):
    """Rules enforced when a candidate is rebuilt from data."""

    def setUp(self) -> None:
        self.parent = baseline()
        self.resources = canonical_resources(ssh_open=False, db_path=True)
        self.ready = ready_candidate(self.parent, self.resources)

    def rejected(
        self, data: dict[str, Any], fragment: str, error: type[Exception] = DomainValidationError
    ) -> None:
        with self.assertRaises(error) as ctx:
            CandidateState.from_dict(data)
        self.assertIn(fragment, str(ctx.exception))

    def test_created_building_and_failed_have_no_resources_or_hash(self) -> None:
        resources = self.ready.to_dict()["resources"]
        for candidate in (
            new_candidate(self.parent),
            start_building(new_candidate(self.parent, n=2)),
        ):
            data = candidate.to_dict()
            self.rejected({**data, "resources": resources}, "no resources")
            self.rejected({**data, "state_hash": self.ready.state_hash}, "state_hash")
        failed = fail_building(start_building(new_candidate(self.parent, n=3)), "bad").to_dict()
        self.rejected({**failed, "resources": resources}, "no resources")
        self.rejected({**failed, "state_hash": self.ready.state_hash}, "state_hash")

    def test_ready_and_later_need_the_matching_state_hash(self) -> None:
        data = self.ready.to_dict()
        self.rejected({**data, "state_hash": None}, "state_hash")
        self.rejected({**data, "state_hash": "0" * 64}, "DATA-INT-010", HashMismatchError)
        # A different resource set with the old hash is a mismatch too.
        other = ready_candidate(self.parent, [resource("aws_instance.other")], n=2).to_dict()
        self.rejected({**data, "resources": other["resources"]}, "DATA-INT-010", HashMismatchError)

    def test_failed_needs_a_reason(self) -> None:
        data = fail_building(start_building(new_candidate(self.parent)), "bad").to_dict()
        self.rejected({**data, "status_reason": None}, "status_reason")
        self.rejected({**data, "status_reason": ""}, "status_reason")

    def test_field_validation(self) -> None:
        data = self.ready.to_dict()
        for key, bad in (
            ("candidate_id", "c-1"),
            ("lineage_id", "l-1"),
            ("parent_state_id", "p-1"),
            ("patch_id", "x"),
            ("candidate_sequence", 0),
            ("source", "HUMAN"),
            ("status", "DONE"),
            ("patch_hash", "xyz"),
            ("patch_hash", "A" * 64),
            ("normalization_version", ""),
            ("created_at", "2026-10-01T09:00:00"),
            ("state_hash", "short"),
        ):
            with self.subTest(key=key, value=bad), self.assertRaises(DomainValidationError):
                CandidateState.from_dict({**data, key: bad})

    def test_resources_must_be_unique_and_are_sorted(self) -> None:
        data = self.ready.to_dict()
        dup = {**data, "resources": data["resources"] + data["resources"][:1]}
        self.rejected(dup, "duplicate")
        shuffled = {**data, "resources": list(reversed(data["resources"]))}
        self.assertEqual(CandidateState.from_dict(shuffled), self.ready)

    def test_from_dict_checks_keys(self) -> None:
        data = self.ready.to_dict()
        self.rejected({k: v for k, v in data.items() if k != "patch_hash"}, "keys")
        self.rejected({**data, "construction_status": "READY"}, "keys")


class TestCandidateSerialization(unittest.TestCase):
    def test_round_trip_in_every_phase(self) -> None:
        parent = baseline()
        resources = canonical_resources(ssh_open=False, db_path=True)
        created = new_candidate(parent)
        building = start_building(created)
        failed = fail_building(building, "bad hcl")
        ready = finish_building(building, resources)
        promotable = promotable_candidate(parent, resources, n=2)
        for candidate in (created, building, failed, ready, promotable):
            with self.subTest(status=candidate.status.value):
                data = candidate.to_dict()
                json.dumps(data)
                self.assertEqual(data["status"], candidate.status.value)
                self.assertEqual(CandidateState.from_dict(data), candidate)

    def test_to_dict_has_no_construction_status_or_token(self) -> None:
        data = new_candidate(baseline()).to_dict()
        self.assertNotIn("construction_status", data)
        self.assertNotIn("_token", data)


class TestTrustedBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self.base = baseline()

    def test_baseline_fields(self) -> None:
        b = self.base
        self.assertEqual(b.version, 0)
        self.assertIsNone(b.parent_state_id)
        self.assertIsNone(b.commit_decision_id)
        self.assertEqual(b.lineage_id, LINEAGE)
        self.assertEqual(b.normalization_version, NORMALIZATION)
        self.assertEqual(b.invariant_registry_version, 1)
        self.assertEqual(b.created_at, at(1))
        self.assertEqual(b.committed_at, at(1))

    def test_references_are_built_for_this_state(self) -> None:
        self.assertEqual([r.invariant_id for r in self.base.invariant_refs], [FUNC, SEC])
        for ref in self.base.invariant_refs:
            self.assertEqual(ref.state_id, self.base.state_id)
            self.assertEqual(ref.status, InvariantStatus.PROTECTED)
            self.assertTrue(ref.can_satisfy_proof())

    def test_state_id_is_generated_when_omitted(self) -> None:
        a = TrustedState.establish_baseline(
            lineage_id=LINEAGE,
            resources=[],
            invariant_proofs=[proof()],
            evidence_refs=[proof().evidence_ids[0]],
            normalization_version=NORMALIZATION,
            invariant_registry_version=1,
            now=at(1),
        )
        self.assertNotEqual(a.state_id, self.base.state_id)

    def test_at_least_one_proof_is_required(self) -> None:
        with self.assertRaises(DomainValidationError) as ctx:
            baseline(proofs=[], evidence_refs=[])
        self.assertIn("Doc 06 §24", str(ctx.exception))

    def test_collections_are_sorted(self) -> None:
        resources = canonical_resources(ssh_open=True, db_path=True)
        b = baseline(resources=list(reversed(resources)))
        self.assertEqual([r.address for r in b.resources], sorted(r.address for r in resources))
        self.assertEqual(list(b.evidence_refs), sorted(b.evidence_refs))

    def test_duplicate_resource_addresses_and_references_are_rejected(self) -> None:
        with self.assertRaises(DomainValidationError):
            baseline(resources=[resource("a.x"), resource("a.x", attributes={"size": "big"})])
        with self.assertRaises(DomainValidationError):
            baseline(proofs=[proof(SEC, evidence=1), proof(SEC, evidence=2)])

    def test_evidence_refs_must_cover_the_proofs(self) -> None:
        with self.assertRaises(DomainValidationError) as ctx:
            baseline(evidence_refs=[uid(5000)])
        self.assertIn("evidence", str(ctx.exception))

    def test_wrong_argument_types_are_rejected(self) -> None:
        with self.assertRaises(DomainValidationError):
            baseline(resources=[{"address": "a.x"}])  # type: ignore[list-item]
        with self.assertRaises(DomainValidationError):
            baseline(proofs=[{"invariant_id": SEC}], evidence_refs=[])  # type: ignore[list-item]
        with self.assertRaises(DomainValidationError):
            baseline(lineage_id="lineage")
        with self.assertRaises(DomainValidationError):
            TrustedState.establish_baseline(
                lineage_id=LINEAGE,
                resources=[],
                invariant_proofs=[proof()],
                evidence_refs=[proof().evidence_ids[0]],
                normalization_version="",
                invariant_registry_version=1,
                now=at(1),
            )
        for bad in (0, -1, "1", None, True):
            with self.subTest(registry_version=bad), self.assertRaises(DomainValidationError):
                TrustedState.establish_baseline(
                    lineage_id=LINEAGE,
                    resources=[],
                    invariant_proofs=[proof()],
                    evidence_refs=[proof().evidence_ids[0]],
                    normalization_version=NORMALIZATION,
                    invariant_registry_version=bad,  # type: ignore[arg-type]
                    now=at(1),
                )

    def test_resource_set_hash_method_matches_the_function(self) -> None:
        self.assertEqual(
            self.base.resource_set_hash(), resource_set_hash(self.base.resources, NORMALIZATION)
        )


class TestTrustedValidation(unittest.TestCase):
    """Rules enforced when a trusted state is rebuilt from data (Doc 05 §7, §28)."""

    def setUp(self) -> None:
        self.base = baseline()
        self.candidate = promotable_candidate(
            self.base, canonical_resources(ssh_open=False, db_path=True)
        )
        self.v1 = promote(self.candidate, self.base)

    def rejected(
        self, data: dict[str, Any], fragment: str, error: type[Exception] = DomainValidationError
    ) -> None:
        with self.assertRaises(error) as ctx:
            TrustedState.from_dict(data)
        self.assertIn(fragment, str(ctx.exception))

    def test_round_trip(self) -> None:
        for state in (self.base, self.v1):
            data = state.to_dict()
            json.dumps(data)
            self.assertEqual(TrustedState.from_dict(data), state)

    def test_version_zero_is_the_only_parentless_state_without_a_decision(self) -> None:
        self.rejected({**self.base.to_dict(), "parent_state_id": uid(9)}, "version 0")
        self.rejected({**self.base.to_dict(), "commit_decision_id": uid(9)}, "version 0")
        self.rejected({**self.v1.to_dict(), "parent_state_id": None}, "parent_state_id")
        self.rejected({**self.v1.to_dict(), "commit_decision_id": None}, "commit_decision_id")

    def test_version_must_be_a_non_negative_int(self) -> None:
        for bad in (-1, 1.5, "1", None, True):
            with self.subTest(version=bad), self.assertRaises(DomainValidationError):
                TrustedState.from_dict({**self.base.to_dict(), "version": bad})

    def test_every_reference_must_belong_to_this_state(self) -> None:
        """DATA-INT-009."""
        data = self.base.to_dict()
        refs = [dict(r) for r in data["invariant_refs"]]
        refs[0]["state_id"] = uid(99)
        self.rejected({**data, "invariant_refs": refs}, "DATA-INT-009")

    def test_reference_evidence_must_be_in_the_state_evidence(self) -> None:
        data = self.base.to_dict()
        self.rejected({**data, "evidence_refs": data["evidence_refs"][:1]}, "evidence")

    def test_duplicate_references_and_evidence_are_rejected(self) -> None:
        data = self.base.to_dict()
        self.rejected(
            {**data, "invariant_refs": data["invariant_refs"] + data["invariant_refs"][:1]},
            "duplicate",
        )
        self.rejected(
            {**data, "evidence_refs": data["evidence_refs"] + data["evidence_refs"][:1]},
            "duplicate",
        )

    def test_commit_cannot_precede_creation(self) -> None:
        data = self.base.to_dict()
        self.rejected({**data, "committed_at": "2026-10-01T08:00:00+00:00"}, "committed_at")

    def test_state_hash_must_match_the_canonical_content(self) -> None:
        data = self.v1.to_dict()
        self.rejected({**data, "state_hash": "0" * 64}, "DATA-INT-010", HashMismatchError)
        # Changing any hashed field without recomputing the hash is caught.
        self.rejected({**data, "version": 5}, "DATA-INT-010", HashMismatchError)
        self.rejected(
            {**data, "normalization_version": "norm-2"}, "DATA-INT-010", HashMismatchError
        )
        self.rejected({**data, "lineage_id": uid(0xBB)}, "DATA-INT-010", HashMismatchError)
        refs = [dict(r) for r in data["invariant_refs"]]
        refs[0]["status"] = "VIOLATED"
        self.rejected({**data, "invariant_refs": refs}, "DATA-INT-010", HashMismatchError)
        resources = data["resources"][1:]
        self.rejected({**data, "resources": resources}, "DATA-INT-010", HashMismatchError)

    def test_field_validation(self) -> None:
        data = self.v1.to_dict()
        for key, bad in (
            ("state_id", "s-1"),
            ("lineage_id", "l-1"),
            ("state_hash", "nope"),
            ("normalization_version", ""),
            ("invariant_registry_version", 0),
            ("created_at", "2026-10-01T09:00:00"),
            ("committed_at", None),
        ):
            with self.subTest(key=key, value=bad), self.assertRaises(DomainValidationError):
                TrustedState.from_dict({**data, key: bad})

    def test_from_dict_checks_keys(self) -> None:
        data = self.base.to_dict()
        self.rejected({k: v for k, v in data.items() if k != "state_hash"}, "keys")
        self.rejected({**data, "content_hash": "x"}, "keys")


class TestTrustedStateHashing(unittest.TestCase):
    def test_state_hash_changes_with_each_hashed_field(self) -> None:
        base = baseline()
        variants = {
            "lineage": baseline(lineage_id=uid(0xCC)),
            "resources": baseline(resources=canonical_resources(ssh_open=False, db_path=True)),
            "status": baseline(
                proofs=[
                    proof(SEC, evidence=1),
                    proof(FUNC, status=InvariantStatus.UNCERTAIN, evidence=2),
                ]
            ),
            "invariants": baseline(proofs=[proof(SEC, evidence=1)]),
        }
        for name, other in variants.items():
            with self.subTest(field=name):
                self.assertNotEqual(other.state_hash, base.state_hash)

    def test_state_hash_ignores_ids_timestamps_and_evidence(self) -> None:
        a = baseline(state_id=uid(1))
        b = TrustedState.establish_baseline(
            lineage_id=LINEAGE,
            resources=canonical_resources(ssh_open=True, db_path=True),
            invariant_proofs=[
                proof(SEC, evidence=7, minutes=30),
                proof(FUNC, evidence=8, minutes=31),
            ],
            evidence_refs=sorted(
                {
                    proof(SEC, evidence=7).evidence_ids[0],
                    proof(FUNC, evidence=8).evidence_ids[0],
                    uid(6000),
                }
            ),
            normalization_version=NORMALIZATION,
            invariant_registry_version=1,
            now=at(500),
            state_id=uid(2),
        )
        self.assertEqual(a.state_hash, b.state_hash)

    def test_resource_set_hash_ignores_resource_order_and_record_ids(self) -> None:
        resources = canonical_resources(ssh_open=True, db_path=True)
        again = [
            resource(
                r.address,
                r.resource_type,
                attributes=dict(r.attributes),
                security_attributes=dict(r.security_attributes),
                references=r.references,
                record_id=uid(8000 + i),
            )
            for i, r in enumerate(reversed(resources))
        ]
        self.assertEqual(resource_set_hash(resources, "n"), resource_set_hash(again, "n"))
        self.assertNotEqual(resource_set_hash(resources, "n"), resource_set_hash(resources, "n2"))


class TestConstructionGuard(unittest.TestCase):
    """Doc 06 §30: lifecycle-bearing objects cannot be built or copied outside their functions."""

    def test_direct_candidate_construction_is_refused(self) -> None:
        c = new_candidate(baseline())
        kwargs = {f.name: getattr(c, f.name) for f in dataclasses.fields(c)}
        with self.assertRaises(UnauthorizedConstructionError):
            CandidateState(**kwargs)

    def test_replace_cannot_change_a_candidate_status(self) -> None:
        parent = baseline()
        ready = ready_candidate(parent, canonical_resources(ssh_open=False, db_path=True))
        for target in (CS.PROMOTABLE, CS.PROMOTED, CS.READY, CS.ANALYZING):
            with (
                self.subTest(target=target.value),
                self.assertRaises(UnauthorizedConstructionError),
            ):
                dataclasses.replace(ready, status=target)

    def test_direct_trusted_state_construction_and_replace_are_refused(self) -> None:
        base = baseline()
        kwargs = {f.name: getattr(base, f.name) for f in dataclasses.fields(base)}
        with self.assertRaises(UnauthorizedConstructionError):
            TrustedState(**kwargs)
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(base, version=3)

    def test_the_token_is_not_an_attribute_value(self) -> None:
        base = baseline()
        names = {f.name for f in dataclasses.fields(base)}
        self.assertNotIn("_token", names)


class TestImmutability(unittest.TestCase):
    def test_entities_are_frozen(self) -> None:
        base = baseline()
        candidate = new_candidate(base)
        for obj, fields in (
            (base, ("state_hash", "version", "resources", "invariant_refs", "state_id")),
            (candidate, ("status", "state_hash", "resources", "parent_state_id", "patch_hash")),
            (base.invariant_refs[0], ("status", "evidence_ids")),
        ):
            for field in fields:
                with (
                    self.subTest(type=type(obj).__name__, field=field),
                    self.assertRaises(dataclasses.FrozenInstanceError),
                ):
                    setattr(obj, field, None)

    def test_collections_are_tuples(self) -> None:
        base = baseline()
        for value in (base.resources, base.invariant_refs, base.evidence_refs):
            self.assertIsInstance(value, tuple)


if __name__ == "__main__":
    unittest.main()
