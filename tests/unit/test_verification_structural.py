"""The structural and consistency gate (P5a step 5; Doc 09 §6, §15, §31; registry §2.8; C-147).

Each finding code has a failing case, built by corrupting one thing in inputs that were produced by
the real pipeline and are otherwise sound. The expectations are the codes C-147 lists; nothing is
computed with the code under test.
"""

from __future__ import annotations

import dataclasses
import unittest
from typing import Any

from core.domain.enums import ReferenceResolution, VerificationResult
from core.domain.impact import (
    AFFECTED_CODES,
    VerificationWorkItem,
    WorkPriority,
    WorkTargetType,
)
from core.domain.resource import Resource
from core.domain.values import Reference
from core.domain.verification import ConstructionStatus, VerificationReason
from core.verification.errors import VerificationInputError
from core.verification.inputs import VerificationInputs
from core.verification.structural import (
    consistency_findings,
    consistency_gate,
    structural_findings,
    structural_gate,
)
from tests.domain_builders import uid
from tests.impact_builders import baseline_work
from tests.pipeline_builders import (
    CANDIDATE_STATE,
    PARENT_STATE,
    inputs_for,
    tampered,
    tampered_graph,
    with_resources,
)
from tests.security_builders import inline, sg
from tests.verification_builders import record

OLD = sg(body=inline("ingress", "tcp", 80, 80, ["10.0.0.0/8"])) + sg("db")
NEW = sg(body=inline("ingress", "tcp", 80, 80, ["10.0.0.0/16"])) + sg("db")


def codes(findings: Any) -> set[str]:
    return {finding.code for finding in findings}


def invariant_work(invariant_id: str = "INV-SEC-001", version: int = 1) -> VerificationWorkItem:
    return VerificationWorkItem(
        target_id=f"INVARIANT:{invariant_id}:{version}",
        target_type=WorkTargetType.INVARIANT,
        reason=sorted(AFFECTED_CODES)[0],
        scope=("aws_security_group.app",),
        required_evidence="L1",
        priority=WorkPriority.BLOCKING,
    )


class TestInputs(unittest.TestCase):
    def test_sound_inputs_build(self) -> None:
        self.assertIsInstance(inputs_for(NEW, OLD), VerificationInputs)
        self.assertIsNone(inputs_for(NEW).parent_resources)

    def test_a_parent_without_a_parent_state_is_refused(self) -> None:
        sound = inputs_for(NEW, OLD)
        with self.assertRaises(VerificationInputError):
            dataclasses.replace(sound, parent_state_id=None)
        with self.assertRaises(VerificationInputError):
            dataclasses.replace(inputs_for(NEW), parent_state_id=PARENT_STATE)

    def test_wrong_types_are_refused_before_anything_runs(self) -> None:
        sound = inputs_for(NEW, OLD)
        for field, bad in (
            ("candidate_resources", ["not a resource"]),
            ("candidate_resources", "text"),
            ("parent_resources", [1]),
            ("candidate_state_hash", "short"),
            ("normalization_version", ""),
            ("candidate_id", "x"),
            ("identity", "report"),
            ("impact", {}),
            ("candidate_graph", 1),
            ("trusted_graph", 1),
            ("invariants", [object()]),
            ("construction", "OK"),
        ):
            with self.subTest(field=field, bad=bad), self.assertRaises(VerificationInputError):
                dataclasses.replace(sound, **{field: bad})

    def test_the_resources_are_stored_as_tuples(self) -> None:
        sound = inputs_for(NEW, OLD)
        listed = dataclasses.replace(sound, candidate_resources=list(sound.candidate_resources))
        self.assertIsInstance(listed.candidate_resources, tuple)

    def test_invariants_are_found_by_id_and_version(self) -> None:
        sound = inputs_for(NEW)
        self.assertEqual(
            sound.invariant("INV-SEC-001", 1).verifier_id, "dail.verify.public_ingress"
        )
        self.assertIsNone(sound.invariant("INV-SEC-001", 2))
        self.assertIsNone(sound.invariant("INV-NOPE-001", 1))


class TestStructural(unittest.TestCase):
    def setUp(self) -> None:
        self.sound = inputs_for(NEW, OLD)

    def test_sound_inputs_have_no_finding(self) -> None:
        self.assertEqual(structural_findings(self.sound, ()), ())
        self.assertEqual(structural_findings(inputs_for(NEW), ()), ())  # a baseline

    def test_construction_that_is_not_ok(self) -> None:
        for status in (ConstructionStatus.INVALID, ConstructionStatus.UNSUPPORTED):
            with self.subTest(status=status):
                bad = dataclasses.replace(self.sound, construction=status, construction_note="x")
                self.assertEqual(codes(structural_findings(bad, ())), {"construction.invalid"})

    def test_a_tampered_fingerprint(self) -> None:
        resources = list(self.sound.candidate_resources)
        resources[0] = tampered(resources[0], fingerprint="0" * 64)
        bad = with_resources(self.sound, resources)
        self.assertEqual(codes(structural_findings(bad, ())), {"resource.fingerprint_mismatch"})

    def test_a_tampered_canonical_json(self) -> None:
        resources = list(self.sound.candidate_resources)
        resources[0] = tampered(resources[0], canonical_json='{"tampered":true}')
        bad = with_resources(self.sound, resources)
        self.assertEqual(codes(structural_findings(bad, ())), {"resource.canonical_json_mismatch"})

    def test_a_duplicate_address(self) -> None:
        resources = [*self.sound.candidate_resources, self.sound.candidate_resources[0]]
        bad = with_resources(self.sound, resources)
        self.assertIn("resource.duplicate_address", codes(structural_findings(bad, ())))

    def test_a_reference_that_resolves_to_nothing(self) -> None:
        base = self.sound.candidate_resources[0]
        ref = Reference(
            base.address, "vpc_id", "aws_vpc.nowhere", "id", ReferenceResolution.SUPPORTED
        )
        broken = self.recreate(base, [ref])
        bad = with_resources(self.sound, [broken, *self.sound.candidate_resources[1:]])
        self.assertEqual(codes(structural_findings(bad, ())), {"reference.unresolved"})

    def test_a_reference_marked_unknown_or_unsupported_is_not_a_finding(self) -> None:
        base = self.sound.candidate_resources[0]
        for status in (ReferenceResolution.UNKNOWN, ReferenceResolution.UNSUPPORTED):
            with self.subTest(status=status):
                ref = Reference(base.address, "vpc_id", "aws_vpc.nowhere", "id", status)
                broken = self.recreate(base, [ref])
                ok = with_resources(self.sound, [broken, *self.sound.candidate_resources[1:]])
                self.assertEqual(structural_findings(ok, ()), ())

    def test_a_reference_to_the_block_of_an_instance_resolves(self) -> None:
        text = (
            'resource "aws_security_group" "g" {\n  count = 2\n}\n'
            'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n'
            '  security_group_id = aws_security_group.g[0].id\n  protocol = "tcp"\n'
            "  from_port = 1\n  to_port = 1\n}\n"
        )
        self.assertEqual(structural_findings(inputs_for(text), ()), ())

    def test_a_wrong_state_hash(self) -> None:
        bad = dataclasses.replace(self.sound, candidate_state_hash="0" * 64)
        self.assertEqual(codes(structural_findings(bad, ())), {"state.hash_mismatch"})

    def test_resources_from_two_normalization_versions(self) -> None:
        resources = list(self.sound.candidate_resources)
        other = dataclasses.replace(resources[0].provenance, normalization_version="other-norm")
        resources[0] = self.recreate(resources[0], list(resources[0].references), provenance=other)
        bad = with_resources(self.sound, resources)
        self.assertIn("state.normalization_mixed", codes(structural_findings(bad, ())))

    def test_a_graph_without_a_node_for_a_resource(self) -> None:
        smaller = inputs_for(OLD.replace(sg("db"), ""), OLD).candidate_graph
        bad = dataclasses.replace(self.sound, candidate_graph=smaller)
        self.assertIn("graph.node_missing", codes(structural_findings(bad, ())))

    def test_a_graph_whose_hash_does_not_recompute(self) -> None:
        graph = tampered_graph(self.sound.candidate_graph, graph_hash="0" * 64)
        bad = dataclasses.replace(self.sound, candidate_graph=graph)
        self.assertIn("graph.hash_mismatch", codes(structural_findings(bad, ())))

    def test_graphs_of_another_state(self) -> None:
        swapped = dataclasses.replace(
            self.sound,
            candidate_graph=self.sound.trusted_graph,
            trusted_graph=self.sound.candidate_graph,
        )
        self.assertEqual(codes(structural_findings(swapped, ())), {"lineage.graph_state_mismatch"})

    def test_an_invariant_the_registry_does_not_define(self) -> None:
        self.assertEqual(
            codes(structural_findings(self.sound, [invariant_work("INV-NOPE-001")])),
            {"work.invariant_unknown"},
        )
        self.assertEqual(
            codes(structural_findings(self.sound, [invariant_work("INV-SEC-001", 7)])),
            {"work.invariant_unknown"},
        )
        self.assertEqual(structural_findings(self.sound, [invariant_work("INV-SEC-001")]), ())

    def test_a_baseline_item_for_a_resource_the_candidate_does_not_have(self) -> None:
        found = structural_findings(self.sound, [baseline_work("aws_vpc.nowhere")])
        self.assertEqual(codes(found), {"work.resource_unknown"})

    def test_findings_are_sorted_and_carry_a_detail(self) -> None:
        bad = dataclasses.replace(
            self.sound, candidate_state_hash="0" * 64, construction=ConstructionStatus.INVALID
        )
        found = structural_findings(bad, ())
        self.assertEqual(
            [(f.code, f.detail) for f in found], sorted((f.code, f.detail) for f in found)
        )
        self.assertTrue(all(f.detail for f in found))

    @staticmethod
    def recreate(
        resource: Resource, references: list[Reference], provenance: Any = None
    ) -> Resource:
        return Resource.create(
            address=resource.address,
            resource_type=resource.resource_type,
            logical_identity=dict(resource.logical_identity),
            attributes=dict(resource.attributes),
            security_attributes=dict(resource.security_attributes),
            semantic_attributes=dict(resource.semantic_attributes),
            references=references,
            provenance=provenance or resource.provenance,
            support_status=resource.support_status,
        )


class TestConsistency(unittest.TestCase):
    def setUp(self) -> None:
        self.sound = inputs_for(NEW, OLD)

    def test_sound_inputs_have_no_finding(self) -> None:
        self.assertEqual(consistency_findings(self.sound), ())
        self.assertEqual(consistency_findings(inputs_for(NEW)), ())  # nothing optional is given

    def test_an_identity_report_for_another_candidate(self) -> None:
        other = inputs_for(NEW, OLD).identity
        forged = tampered(other, candidate_id=uid(999))  # type: ignore[arg-type]
        bad = dataclasses.replace(self.sound, identity=forged)
        self.assertEqual(codes(consistency_findings(bad)), {"identity.candidate_mismatch"})

    def test_an_identity_report_for_another_parent(self) -> None:
        forged = tampered(self.sound.identity, parent_state_id=uid(998))  # type: ignore[arg-type]
        bad = dataclasses.replace(self.sound, identity=forged)
        self.assertEqual(codes(consistency_findings(bad)), {"identity.parent_mismatch"})

    def test_an_identity_report_that_names_resources_the_states_do_not_have(self) -> None:
        other = inputs_for(NEW + sg("extra"), OLD + sg("gone")).identity
        bad = dataclasses.replace(self.sound, identity=other)
        self.assertEqual(codes(consistency_findings(bad)), {"identity.ref_unknown"})

    def test_an_impact_report_for_another_candidate_or_parent(self) -> None:
        for field, expected in (
            ("candidate_id", "impact.candidate_mismatch"),
            ("parent_state_id", "impact.parent_mismatch"),
        ):
            with self.subTest(field=field):
                forged = tampered(self.sound.impact, **{field: uid(997)})  # type: ignore[arg-type]
                bad = dataclasses.replace(self.sound, impact=forged)
                self.assertEqual(codes(consistency_findings(bad)), {expected})

    def test_an_impact_report_of_another_graph_version(self) -> None:
        forged = tampered(self.sound.impact, graph_version="other-graph-9")  # type: ignore[arg-type]
        bad = dataclasses.replace(self.sound, impact=forged)
        self.assertEqual(codes(consistency_findings(bad)), {"impact.graph_version_mismatch"})

    def test_an_impact_report_computed_from_other_graphs(self) -> None:
        elsewhere = inputs_for(NEW + sg("extra"), OLD + sg("extra"))
        bad = dataclasses.replace(
            self.sound,
            candidate_graph=elsewhere.candidate_graph,
            trusted_graph=elsewhere.trusted_graph,
        )
        self.assertEqual(codes(consistency_findings(bad)), {"impact.graph_hash_mismatch"})

    def test_results_of_another_candidate(self) -> None:
        mine = record(candidate_id=CANDIDATE_STATE, candidate_hash=self.sound.candidate_state_hash)
        self.assertEqual(consistency_findings(self.sound, [mine]), ())
        theirs = record(candidate_id=uid(996))
        self.assertEqual(
            codes(consistency_findings(self.sound, [theirs])), {"result.candidate_mismatch"}
        )
        stale = record(candidate_id=CANDIDATE_STATE, candidate_hash="b" * 64)
        self.assertEqual(
            codes(consistency_findings(self.sound, [stale])), {"result.candidate_mismatch"}
        )


class TestGates(unittest.TestCase):
    def setUp(self) -> None:
        self.sound = inputs_for(NEW, OLD)

    def test_a_sound_candidate_passes_both_gates(self) -> None:
        for outcome in (structural_gate(self.sound, ()), consistency_gate(self.sound)):
            self.assertEqual((outcome.result, outcome.reason), (VerificationResult.PASS, None))
            self.assertEqual(outcome.observations["findings"], [])
            self.assertIsNone(outcome.clauses)

    def test_a_finding_fails_the_gate_with_its_reason(self) -> None:
        wrong_hash = dataclasses.replace(self.sound, candidate_state_hash="0" * 64)
        outcome = structural_gate(wrong_hash, ())
        self.assertEqual(
            (outcome.result, outcome.reason),
            (VerificationResult.FAIL, VerificationReason.STRUCTURAL_FINDING),
        )
        self.assertEqual(
            [item["code"] for item in outcome.observations["findings"]], ["state.hash_mismatch"]
        )
        forged = tampered(self.sound.identity, candidate_id=uid(995))  # type: ignore[arg-type]
        consistency = consistency_gate(dataclasses.replace(self.sound, identity=forged))
        self.assertEqual(
            (consistency.result, consistency.reason),
            (VerificationResult.FAIL, VerificationReason.CONSISTENCY_FINDING),
        )

    def test_construction_failure_fails_the_structural_gate_with_its_own_reason(self) -> None:
        bad = dataclasses.replace(
            self.sound, construction=ConstructionStatus.INVALID, construction_note="hcl"
        )
        outcome = structural_gate(bad, ())
        self.assertEqual(
            (outcome.result, outcome.reason),
            (VerificationResult.FAIL, VerificationReason.CONSTRUCTION_INVALID),
        )
        self.assertIn("hcl", outcome.observations["findings"][0]["detail"])

    def test_the_gates_are_deterministic(self) -> None:
        self.assertEqual(structural_gate(self.sound, ()), structural_gate(self.sound, ()))
        self.assertEqual(consistency_gate(self.sound), consistency_gate(self.sound))


if __name__ == "__main__":
    unittest.main()
