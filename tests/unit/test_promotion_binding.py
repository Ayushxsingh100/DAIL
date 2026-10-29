"""The evidence binding of a promotion, one condition at a time (P6b step 5; Doc 11 §8, §9, §44,
§45; C-52, C-60, C-68, C-164).

HAND EXPECTATIONS, written before the code (the canonical world of ``tests/promotion_builders.py``):

* ``integrity_of`` answers VALID, TAMPERED or MISSING_PAYLOAD exactly as
  ``EvidenceService.verify_integrity`` does for the same stored record (the two are written apart
  because ``core.promotion`` never imports ``evidence/``).
* ``binding_problems`` of a sound plan is empty. A VERIFIED entry is a problem when its result or
  its evidence record is missing, when the record is not VERIFICATION evidence produced for this
  candidate with its hash, when its subject (invariant, version, verifier, result) is another one
  (C-68), or when the definition it is checked against is missing. A CARRIED_FORWARD entry is a
  problem when the plan's evidence is not the parent reference's, when the parent has no such
  reference, when a baseline's evidence is not bound to the baseline, or when a promoted parent's
  binding record is not carried, not a ``promotion.committed`` STATE record, not usable as proof for
  that parent, or does not name the decision, the state and the invariant.
* A record that cannot be read at all (its stored columns disagree with its content, DATA-INT-010)
  is a problem, not an exception.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from core.domain.evidence import ArtifactRef, EvidenceKind, EvidenceSubmission, IntegrityStatus
from core.domain.hashing import canonical_json
from core.domain.promotion import ProofSource
from core.domain.state import TrustedState
from core.promotion import ids
from core.promotion.binding import (
    BINDING_EVENT_NAME,
    binding_payload,
    binding_problems,
    integrity_of,
)
from evidence.service import EvidenceService
from tests.domain_builders import uid
from tests.promotion_builders import FAIL, FUNC1, SEC1, SEC2, SEC3, record, run, target
from tests.promotion_commit_builders import CommitCase

DECISION = uid(9100)


class BindingCase(CommitCase):
    def setUp(self) -> None:
        super().setUp()
        self.outcome = run(self.world)
        self.plan = self.outcome.proof_plan
        self.results = {r.verification_id: r for r in self.world.verification.results}

    def problems(self, **changes: Any) -> list[str]:
        arguments: dict[str, Any] = {
            "plan": self.plan,
            "candidate": self.world.candidate,
            "parent": self.world.trusted,
            "definitions": self.world.definitions,
            "results": self.results,
            "evidence_ids": self.evidence_ids,
        }
        arguments.update(changes)
        with self.uow() as u:
            return binding_problems(
                u.evidence,
                arguments["plan"],
                arguments["candidate"],
                arguments["parent"],
                arguments["definitions"],
                arguments["results"],
                arguments["evidence_ids"],
            )

    def entry(self, invariant_id: str) -> Any:
        return next(e for e in self.plan if e.invariant_id == invariant_id)

    def evidence_of(self, invariant_id: str) -> str:
        return self.evidence_ids[self.entry(invariant_id).verification_id or ""]

    def store_variant(self, which: str, **payload_changes: Any) -> str:
        """A second VERIFICATION record for the same result, with some payload keys changed."""
        return self.forged_copy(
            self.evidence_of(which), uid(8950 + len(payload_changes)), **payload_changes
        )

    def forged_copy(
        self,
        original: str,
        new_id: str,
        *,
        state_hash: str | None = None,
        **payload_changes: Any,
    ) -> str:
        """A readable copy of a stored record under a new id, with some payload keys and perhaps
        its ``state_hash`` changed. It is built whole (the columns agree with the content), so the
        adapter reads it; the triggers that would refuse it are dropped first, the way an attacker
        with file access would."""
        self.tamper("SELECT 1")
        with self.uow() as u:
            event = u.evidence.get(original)
            assert event is not None
            payload = dict(u.evidence.resolve(ArtifactRef.parse(event.payload_ref)))
            variant = EvidenceSubmission.create(
                payload={**payload, **payload_changes},
                evidence_id=new_id,
                run_id=event.run_id,
                attempt_id=event.attempt_id,
                correlation_id=event.correlation_id,
                operation_id=event.operation_id,
                kind=event.kind,
                event_name=event.event_name,
                provenance=event.provenance,
                created_at=event.created_at,
                state_id=event.state_id,
                candidate_id=event.candidate_id,
                parent_state_id=event.parent_state_id,
                state_hash=state_hash or event.state_hash,
            )
            u.evidence.append(variant)
        return variant.event.evidence_id

    def with_variant(self, which: str, **payload_changes: Any) -> list[str]:
        mapped = {
            **self.evidence_ids,
            self.entry(which).verification_id or "": self.store_variant(which, **payload_changes),
        }
        return self.problems(evidence_ids=mapped)


class TestIntegrityAgrees(CommitCase):
    """``integrity_of`` and ``EvidenceService.verify_integrity`` on the same stored record."""

    def both(self, evidence_id: str) -> tuple[IntegrityStatus, IntegrityStatus]:
        with self.uow() as u:
            event = u.evidence.get(evidence_id)
            assert event is not None
            mine = integrity_of(u.evidence, event)
            return mine, EvidenceService().verify_integrity(u, evidence_id)

    def a_record(self) -> tuple[str, str]:
        evidence_id = next(iter(self.evidence_ids.values()))
        with self.uow() as u:
            event = u.evidence.get(evidence_id)
            assert event is not None
        return evidence_id, event.content_hash

    def test_a_sound_record_is_valid_for_both(self) -> None:
        evidence_id, _ = self.a_record()
        self.assertEqual(self.both(evidence_id), (IntegrityStatus.VALID, IntegrityStatus.VALID))

    def test_an_edited_payload_is_tampered_for_both(self) -> None:
        evidence_id, digest = self.a_record()
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json = ? WHERE content_hash = ?",
            ('{"result":"PASS"}', digest),
        )
        self.assertEqual(
            self.both(evidence_id), (IntegrityStatus.TAMPERED, IntegrityStatus.TAMPERED)
        )

    def test_an_edit_that_keeps_the_value_is_tampered_for_both(self) -> None:
        evidence_id, digest = self.a_record()
        with self.uow() as u:
            event = u.evidence.get(evidence_id)
            assert event is not None
            text = u.evidence.resolve(ArtifactRef.parse(event.payload_ref))
        import json

        spaced = json.dumps(text, indent=2, sort_keys=True)
        self.tamper(
            "UPDATE evidence_artifacts SET payload_json = ? WHERE content_hash = ?",
            (spaced, digest),
        )
        self.assertEqual(
            self.both(evidence_id), (IntegrityStatus.TAMPERED, IntegrityStatus.TAMPERED)
        )

    def test_a_deleted_payload_is_missing_for_both(self) -> None:
        evidence_id, digest = self.a_record()
        self.tamper("DELETE FROM evidence_artifacts WHERE content_hash = ?", (digest,))
        self.assertEqual(
            self.both(evidence_id),
            (IntegrityStatus.MISSING_PAYLOAD, IntegrityStatus.MISSING_PAYLOAD),
        )


class TestSoundPlan(BindingCase):
    def test_a_sound_plan_has_no_problem(self) -> None:
        self.assertEqual(self.problems(), [])

    def test_the_plan_has_both_kinds_of_source(self) -> None:
        sources = {e.invariant_id: e.source for e in self.plan}
        self.assertEqual(sources[SEC1], ProofSource.VERIFIED)
        self.assertEqual(sources[SEC2], ProofSource.CARRIED_FORWARD)


class TestVerifiedSources(BindingCase):
    def test_a_result_that_is_not_in_the_report(self) -> None:
        found = self.problems(results={})
        self.assertTrue(any("no verification result" in p for p in found), found)

    def test_an_evidence_record_that_is_not_in_the_map(self) -> None:
        found = self.problems(evidence_ids={})
        self.assertTrue(any("no verification result or no evidence" in p for p in found), found)

    def test_an_evidence_id_that_names_nothing(self) -> None:
        mapped = {**self.evidence_ids, self.entry(SEC1).verification_id or "": uid(4242)}
        found = self.problems(evidence_ids=mapped)
        self.assertTrue(any("does not exist" in p for p in found), found)

    def test_a_record_produced_for_the_baseline_and_not_for_the_candidate(self) -> None:
        baseline_evidence = self.world.trusted.invariant_refs[0].evidence_ids[0]
        mapped = {**self.evidence_ids, self.entry(SEC1).verification_id or "": baseline_evidence}
        found = self.problems(evidence_ids=mapped)
        self.assertTrue(any("P3" in p for p in found), found)
        self.assertTrue(any("not VERIFICATION evidence bound to the candidate" in p for p in found))

    def test_a_record_of_another_invariant(self) -> None:
        found = self.with_variant(SEC1, invariant_id=SEC2)
        self.assertTrue(any("invariant_id" in p and "(C-68)" in p for p in found), found)

    def test_a_record_of_another_invariant_version(self) -> None:
        found = self.with_variant(SEC1, invariant_version=2)
        self.assertTrue(any("invariant_version" in p for p in found), found)

    def test_a_record_of_another_verifier_version(self) -> None:
        found = self.with_variant(SEC1, verifier_version="99")
        self.assertTrue(any("verifier_version" in p for p in found), found)

    def test_a_record_whose_payload_says_fail(self) -> None:
        found = self.with_variant(FUNC1, result="FAIL")
        self.assertTrue(any("'result'" in p or "result is not" in p for p in found), found)

    def test_a_readable_record_with_another_state_hash_is_not_proof(self) -> None:
        # P6 of evaluate_proof: the record is whole and readable; only its hash is not the
        # candidate's
        original = self.evidence_of(SEC1)
        forged = self.forged_copy(original, uid(8960), state_hash="7" * 64)
        mapped = {**self.evidence_ids, self.entry(SEC1).verification_id or "": forged}
        found = self.problems(evidence_ids=mapped)
        self.assertTrue(any("P6" in p for p in found), found)

    def test_a_record_of_another_candidate_hash(self) -> None:
        found = self.with_variant(SEC1, candidate_hash="0" * 64)
        self.assertTrue(any("candidate_hash" in p for p in found), found)

    def test_a_result_that_is_not_a_pass(self) -> None:
        failing = record(
            self.world.candidate,
            target(SEC1),
            FAIL,
            definition=self.world.definitions[SEC1],
            n=3,
        )
        failing = dataclasses.replace(
            failing, verification_id=self.entry(SEC1).verification_id or ""
        )
        found = self.problems(results={**self.results, failing.verification_id: failing})
        self.assertTrue(any("not a PASS" in p for p in found), found)

    def test_a_definition_that_is_missing(self) -> None:
        found = self.problems(definitions={})
        self.assertTrue(any("no definition" in p for p in found), found)

    def test_a_definition_of_another_version(self) -> None:
        other = dataclasses.replace(self.world.definitions[SEC1], version=2)
        found = self.problems(definitions={**self.world.definitions, SEC1: other})
        self.assertTrue(any("no definition" in p for p in found), found)

    def test_an_unreadable_record_is_a_problem_and_not_an_exception(self) -> None:
        evidence_id = self.evidence_of(SEC1)
        self.tamper(
            "UPDATE evidence_events SET state_hash = ? WHERE evidence_id = ?",
            ("1" * 64, evidence_id),
        )
        found = self.problems()
        self.assertTrue(any("cannot be read" in p for p in found), found)


class TestCarriedSources(BindingCase):
    def test_a_plan_whose_evidence_is_not_the_parents(self) -> None:
        carried = self.entry(SEC2)
        forged = dataclasses.replace(carried, evidence_ids=(uid(4243),))
        plan = tuple(forged if e is carried else e for e in self.plan)
        found = self.problems(plan=plan)
        self.assertTrue(any("not the parent reference's evidence" in p for p in found), found)

    def test_an_invariant_the_parent_does_not_hold(self) -> None:
        carried = self.entry(SEC2)
        stranger = dataclasses.replace(carried, invariant_id="INV-SEC-099")
        plan = tuple(stranger if e is carried else e for e in self.plan)
        found = self.problems(plan=plan)
        self.assertTrue(any("no reference to it" in p for p in found), found)

    def test_a_baseline_record_that_is_not_bound_to_the_baseline(self) -> None:
        evidence_id = self.entry(SEC2).evidence_ids[0]
        self.tamper(
            "UPDATE evidence_events SET state_id = NULL, state_hash = NULL, parent_state_id = NULL "
            "WHERE evidence_id = ?",
            (evidence_id,),
        )
        found = self.problems()
        self.assertGreaterEqual(len(found), 1)

    def test_a_readable_baseline_record_with_another_state_hash_is_not_proof(self) -> None:
        carried = self.entry(SEC2)
        forged = self.forged_copy(carried.evidence_ids[0], uid(8961), state_hash="7" * 64)
        data = self.world.trusted.to_dict()
        for ref in data["invariant_refs"]:
            if ref["invariant_id"] == SEC2:
                ref["evidence_ids"] = [forged]
        data["evidence_refs"] = sorted({*data["evidence_refs"], forged})
        parent = TrustedState.from_dict(data)
        swapped = dataclasses.replace(carried, evidence_ids=(forged,))
        plan = tuple(swapped if e is carried else e for e in self.plan)
        found = self.problems(plan=plan, parent=parent)
        self.assertTrue(any("P6" in p for p in found), found)

    def test_a_baseline_record_with_another_state_hash(self) -> None:
        evidence_id = self.entry(SEC3).evidence_ids[0]
        self.tamper(
            "UPDATE evidence_events SET state_hash = ? WHERE evidence_id = ?",
            ("4" * 64, evidence_id),
        )
        found = self.problems()
        self.assertTrue(any("cannot be read" in p or "P6" in p for p in found), found)


class TestPromotedParent(BindingCase):
    """The parent is v1, promoted by DECISION; its carried references rest on its binding record."""

    def setUp(self) -> None:
        super().setUp()
        first = self.commit(outcome=self.outcome)
        assert first.state is not None
        self.v1 = first.state
        self.world2 = self.next_world(self.v1)
        self.outcome2 = run(self.world2, decision_id=uid(9300))
        self.plan2 = self.outcome2.proof_plan
        self.results2 = {r.verification_id: r for r in self.world2.verification.results}
        self.store_candidate(self.world2, n=2, sequence=2)
        self.evidence_ids2 = self.store_results(self.world2, first=60)

    def problems2(self, **changes: Any) -> list[str]:
        arguments: dict[str, Any] = {
            "plan": self.plan2,
            "candidate": self.world2.candidate,
            "parent": self.v1,
            "definitions": self.world2.definitions,
            "results": self.results2,
            "evidence_ids": self.evidence_ids2,
        }
        arguments.update(changes)
        with self.uow() as u:
            return binding_problems(u.evidence, **arguments)

    def test_the_chain_is_sound(self) -> None:
        self.assertEqual(self.problems2(), [])
        self.assertIn(
            ProofSource.CARRIED_FORWARD, {e.source for e in self.plan2 if e.invariant_id == SEC1}
        )

    def test_a_reference_that_does_not_carry_the_parents_binding_record(self) -> None:
        binding_id = ids.evidence_id_for(DECISION)
        carried = next(e for e in self.plan2 if e.invariant_id == SEC1)
        thinned = dataclasses.replace(
            carried, evidence_ids=tuple(e for e in carried.evidence_ids if e != binding_id)
        )
        data = self.v1.to_dict()
        for ref in data["invariant_refs"]:
            if ref["invariant_id"] == SEC1:
                ref["evidence_ids"] = list(thinned.evidence_ids)
        parent = TrustedState.from_dict(data)
        plan = tuple(thinned if e is carried else e for e in self.plan2)
        found = self.problems2(parent=parent, plan=plan)
        wanted = "does not carry the parent's binding record"
        self.assertTrue(any(wanted in p for p in found), found)

    def test_the_binding_record_is_a_state_record_named_promotion_committed(self) -> None:
        with self.uow() as u:
            event = u.evidence.get(ids.evidence_id_for(DECISION))
        assert event is not None
        self.assertIs(event.kind, EvidenceKind.STATE)
        self.assertEqual(event.event_name, BINDING_EVENT_NAME)
        self.assertEqual(BINDING_EVENT_NAME, "promotion.committed")

    def test_a_binding_record_that_does_not_name_the_invariant(self) -> None:
        with self.uow() as u:
            event = u.evidence.get(ids.evidence_id_for(DECISION))
            assert event is not None
            payload = u.evidence.resolve(ArtifactRef.parse(event.payload_ref))
        trimmed = {
            **payload,
            "invariants": [i for i in payload["invariants"] if i["invariant_id"] != SEC1],
        }
        self.replace_binding(trimmed)
        found = self.problems2()
        self.assertTrue(any("does not name this invariant" in p for p in found), found)

    def test_a_binding_record_of_another_decision(self) -> None:
        with self.uow() as u:
            event = u.evidence.get(ids.evidence_id_for(DECISION))
            assert event is not None
            payload = u.evidence.resolve(ArtifactRef.parse(event.payload_ref))
        other = {**payload, "decision": {**payload["decision"], "decision_id": uid(1)}}
        self.replace_binding(other)
        found = self.problems2()
        self.assertTrue(any("another decision" in p for p in found), found)

    def test_a_binding_record_of_another_state(self) -> None:
        with self.uow() as u:
            event = u.evidence.get(ids.evidence_id_for(DECISION))
            assert event is not None
            payload = u.evidence.resolve(ArtifactRef.parse(event.payload_ref))
        other = {
            **payload,
            "promotion_evidence": {**payload["promotion_evidence"], "new_state_id": uid(1)},
        }
        self.replace_binding(other)
        found = self.problems2()
        self.assertTrue(any("another state" in p for p in found), found)

    def replace_binding(self, payload: dict[str, Any]) -> None:
        """Rewrite the binding record of v1 as a record whose payload is ``payload`` and whose
        columns are otherwise the same (an attacker with file access who also fixes the hash)."""
        binding_id = ids.evidence_id_for(DECISION)
        with self.uow() as u:
            event = u.evidence.get(binding_id)
            assert event is not None
        forged = EvidenceSubmission.create(
            payload=payload,
            evidence_id=binding_id,
            run_id=event.run_id,
            attempt_id=event.attempt_id,
            correlation_id=event.correlation_id,
            operation_id=event.operation_id,
            kind=event.kind,
            event_name=event.event_name,
            provenance=event.provenance,
            created_at=event.created_at,
            state_id=event.state_id,
            parent_state_id=event.parent_state_id,
            state_hash=event.state_hash,
        )
        self.tamper(
            "UPDATE evidence_events SET content_hash = ?, payload_ref = ?, content_json = ? "
            "WHERE evidence_id = ?",
            (
                forged.event.content_hash,
                forged.event.payload_ref,
                canonical_json(forged.event.to_dict()),
                binding_id,
            ),
        )
        self.tamper(
            "INSERT INTO evidence_artifacts (content_hash, payload_json) VALUES (?, ?)",
            (forged.event.content_hash, forged.payload_json),
        )


class TestBindingPayload(CommitCase):
    def test_the_payload_names_every_invariant_once_with_its_source(self) -> None:
        outcome = run(self.world)
        state = self.commit(outcome=outcome).state
        assert state is not None
        payload = binding_payload(
            outcome.decision.committed(state.state_id),
            outcome.evidence.with_new_state(state.state_id),
            outcome.proof_plan,
            state,
            self.evidence_ids,
        )
        named = [i["invariant_id"] for i in payload["invariants"]]
        self.assertEqual(named, sorted({SEC1, SEC2, SEC3, FUNC1}))
        self.assertEqual(payload["state"]["state_hash"], state.state_hash)
        self.assertEqual(payload["state"]["version"], 1)
        self.assertEqual(payload["decision"]["committed_state_id"], state.state_id)
        self.assertEqual(payload["promotion_evidence"]["new_state_id"], state.state_id)


if __name__ == "__main__":
    import unittest

    unittest.main()
