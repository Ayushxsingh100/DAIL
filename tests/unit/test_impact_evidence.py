"""Evidence invalidation, carry-forward verdicts and the verification work set (P4 step 6;
Doc 08 §21-§27, §31; C-141).

Historical evidence is retained: the report says what is eligible for the candidate and the next
state, never for the parent. NO PRIOR EVIDENCE is not a pass and carries nothing.
"""

from __future__ import annotations

import dataclasses
import unittest

from core.domain.enums import ImpactStatus
from core.domain.evidence import EvidenceValidity
from core.domain.impact import ReasonCode, WorkPriority, WorkTargetType
from core.impact.inputs import PriorProof
from tests.impact_builders import (
    DB_BLOCK,
    NET,
    PIPE_CANDIDATE,
    PIPE_PARENT,
    codes_of,
    impact_between,
    impacted,
    impacted_ids,
    registry,
)

SEC1, SEC2, SEC3, FUNC = "INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"
VERIFIERS = {
    SEC1: ("dail.verify.public_ingress", "1"),
    SEC2: ("dail.verify.public_ingress", "1"),
    SEC3: ("dail.verify.rds_public_flag", "1"),
    FUNC: ("dail.verify.reachability_cfg", "1"),
}
DATABASE_CHANGED = NET.replace('identifier = "d"', 'identifier = "e"')


def proof(
    invariant_id: str, version: int = 1, *, verifier: tuple[str, str] | None = None
) -> PriorProof:
    verifier_id, verifier_version = verifier or VERIFIERS[invariant_id]
    return PriorProof(
        invariant_id,
        version,
        (f"e-{invariant_id.lower()}-{version}",),
        verifier_id,
        verifier_version,
    )


def all_proofs() -> list[PriorProof]:
    return [proof(invariant_id) for invariant_id in VERIFIERS]


def ok(report, invariant_id: str, version: int = 1) -> bool:  # type: ignore[no-untyped-def]
    return report.carry_forward_ok(
        invariant_id, version, candidate_id=PIPE_CANDIDATE, parent_state_id=PIPE_PARENT
    )


class TestInvalidation(unittest.TestCase):
    def setUp(self) -> None:
        self.report = impact_between(NET, DATABASE_CHANGED, prior=all_proofs())

    def test_the_two_impacted_invariants_lose_eligibility_for_the_candidate(self) -> None:
        self.assertEqual(impacted_ids(self.report), {FUNC, SEC3})
        for item in self.report.affected_invariants:
            with self.subTest(invariant=item.invariant_id):
                self.assertIs(item.status, ImpactStatus.AFFECTED)
                self.assertIs(item.evidence_validity, EvidenceValidity.INVALID)

    def test_the_prior_evidence_is_retained_not_deleted(self) -> None:
        # Doc 08 §21: "Historical evidence is retained. Its eligibility ... becomes invalid."
        by_id = impacted(self.report)
        self.assertEqual(by_id[FUNC].prior_evidence_ids, ("e-inv-func-001-1",))
        self.assertEqual(by_id[SEC3].prior_evidence_ids, ("e-inv-sec-003-1",))

    def test_an_impacted_invariant_is_never_a_carry_forward_candidate(self) -> None:
        for invariant_id in (FUNC, SEC3):
            self.assertFalse(ok(self.report, invariant_id))
        keys = {c.key() for c in self.report.carry_forward_candidates}
        self.assertTrue(keys.isdisjoint({(FUNC, 1), (SEC3, 1)}))

    def test_unaffected_invariants_with_a_matching_proof_are_candidates(self) -> None:
        self.assertEqual(
            {c.key() for c in self.report.carry_forward_candidates}, {(SEC1, 1), (SEC2, 1)}
        )
        for invariant_id in (SEC1, SEC2):
            self.assertTrue(ok(self.report, invariant_id))
        by_key = {u.key(): u for u in self.report.unaffected}
        self.assertTrue(by_key[(SEC1, 1)].carry_forward_eligible)
        self.assertIs(by_key[(SEC1, 1)].reason, ReasonCode.NO_CHANGE_IN_FOOTPRINT)
        self.assertEqual(by_key[(SEC1, 1)].prior_evidence_ids, ("e-inv-sec-001-1",))

    def test_the_verdict_is_for_this_candidate_and_parent_only(self) -> None:
        other = "44444444-4444-4444-8444-444444444444"
        self.assertFalse(
            self.report.carry_forward_ok(SEC1, 1, candidate_id=other, parent_state_id=PIPE_PARENT)
        )
        self.assertFalse(
            self.report.carry_forward_ok(
                SEC1, 1, candidate_id=PIPE_CANDIDATE, parent_state_id=other
            )
        )

    def test_the_prior_proofs_are_untouched(self) -> None:
        proofs = all_proofs()
        before = [(p.key(), p.evidence_ids, p.verifier_id, p.verifier_version) for p in proofs]
        impact_between(NET, DATABASE_CHANGED, prior=proofs)
        self.assertEqual(
            before, [(p.key(), p.evidence_ids, p.verifier_id, p.verifier_version) for p in proofs]
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proofs[0].evidence_ids = ()  # type: ignore[misc]

    def test_an_uncertain_invariant_is_uncertain_for_evidence_too(self) -> None:
        ops_single = 'resource "aws_security_group" "ops" {\n  name = "ops"\n}\n'
        ops_keyed = (
            'resource "aws_security_group" "ops" {\n  for_each = toset(["a", "b"])\n'
            '  name = "ops-${each.key}"\n}\n'
        )
        report = impact_between(NET + ops_single, NET + ops_keyed, prior=all_proofs())
        for invariant_id in (SEC1, SEC2):
            item = impacted(report)[invariant_id]
            self.assertIs(item.evidence_validity, EvidenceValidity.UNCERTAIN)
            self.assertEqual(len(item.prior_evidence_ids), 1)
            self.assertFalse(ok(report, invariant_id))


class TestCarryForwardEligibility(unittest.TestCase):
    def test_a_missing_proof_is_not_a_pass_and_carries_nothing(self) -> None:
        report = impact_between(NET, DATABASE_CHANGED, prior=[])
        for unaffected in report.unaffected:
            self.assertFalse(unaffected.carry_forward_eligible)
            self.assertIs(unaffected.reason, ReasonCode.NO_PRIOR_EVIDENCE)
            self.assertEqual(unaffected.prior_evidence_ids, ())
        self.assertEqual(report.carry_forward_candidates, ())
        self.assertFalse(ok(report, SEC1))

    def test_a_proof_of_another_verifier_version_is_not_reusable(self) -> None:
        proofs = [proof(SEC1, verifier=("dail.verify.public_ingress", "2")), proof(SEC2)]
        report = impact_between(NET, DATABASE_CHANGED, prior=proofs)
        by_key = {u.key(): u for u in report.unaffected}
        self.assertIs(by_key[(SEC1, 1)].reason, ReasonCode.VERIFIER_CHANGED)
        self.assertFalse(by_key[(SEC1, 1)].carry_forward_eligible)
        self.assertEqual(by_key[(SEC1, 1)].prior_evidence_ids, ("e-inv-sec-001-1",))
        self.assertTrue(by_key[(SEC2, 1)].carry_forward_eligible)
        self.assertFalse(ok(report, SEC1))
        self.assertTrue(ok(report, SEC2))

    def test_a_proof_of_another_verifier_is_not_reusable(self) -> None:
        proofs = [proof(SEC1, verifier=("some.other.verifier", "1"))]
        report = impact_between(NET, DATABASE_CHANGED, prior=proofs)
        by_key = {u.key(): u for u in report.unaffected}
        self.assertIs(by_key[(SEC1, 1)].reason, ReasonCode.VERIFIER_CHANGED)

    def test_a_proof_of_another_invariant_version_is_not_reusable(self) -> None:
        # Doc 08 §22: "invariant definition version changed: not reusable for the new version"
        definitions = registry()
        v2 = dataclasses.replace(definitions[SEC1], version=2)
        chosen = [v2, definitions[SEC2], definitions[SEC3], definitions[FUNC]]
        report = impact_between(NET, DATABASE_CHANGED, prior=[proof(SEC1, 1)], invariants=chosen)
        by_key = {u.key(): u for u in report.unaffected}
        self.assertIs(by_key[(SEC1, 2)].reason, ReasonCode.INVARIANT_VERSION_CHANGED)
        self.assertFalse(by_key[(SEC1, 2)].carry_forward_eligible)
        self.assertFalse(ok(report, SEC1, 2))
        self.assertFalse(ok(report, SEC1, 1))  # version 1 is not one of this report's invariants

    def test_both_versions_given_only_the_proven_one_carries(self) -> None:
        definitions = registry()
        v2 = dataclasses.replace(definitions[SEC1], version=2)
        chosen = [definitions[SEC1], v2, definitions[SEC2], definitions[SEC3], definitions[FUNC]]
        report = impact_between(NET, DATABASE_CHANGED, prior=[proof(SEC1, 1)], invariants=chosen)
        self.assertTrue(ok(report, SEC1, 1))
        self.assertFalse(ok(report, SEC1, 2))

    def test_no_change_at_all_leaves_every_proven_invariant_a_candidate(self) -> None:
        report = impact_between(NET, NET, prior=all_proofs())
        self.assertEqual(report.affected_invariants, ())
        self.assertEqual(
            {c.key() for c in report.carry_forward_candidates}, {(k, 1) for k in VERIFIERS}
        )

    def test_eligibility_is_a_precondition_not_a_decision(self) -> None:
        # the report names candidates; whether P6 policy permits carrying is not decided here
        report = impact_between(NET, NET, prior=all_proofs())
        self.assertTrue(all(c.evidence_ids for c in report.carry_forward_candidates))
        self.assertFalse(hasattr(report, "carried_forward"))


class TestWorkSet(unittest.TestCase):
    def setUp(self) -> None:
        self.report = impact_between(
            NET,
            DATABASE_CHANGED + 'resource "aws_subnet" "new" {\n  cidr_block = "10.0.7.0/24"\n}\n',
        )

    def test_one_item_per_impacted_invariant_and_one_per_created_resource(self) -> None:
        targets = sorted(w.target_id for w in self.report.verification_work)
        self.assertEqual(
            targets,
            [
                "INVARIANT:INV-FUNC-001:1",
                "INVARIANT:INV-SEC-003:1",
                "RESOURCE:aws_subnet.new",
            ],
        )

    def test_every_item_is_blocking(self) -> None:
        # Doc 08 §26: every impacted obligation is mandatory before promotion
        for item in self.report.verification_work:
            self.assertIs(item.priority, WorkPriority.BLOCKING)

    def test_an_invariant_item_names_the_level_and_the_verifier(self) -> None:
        by_id = {w.target_id: w for w in self.report.verification_work}
        func = by_id["INVARIANT:INV-FUNC-001:1"]
        self.assertIs(func.target_type, WorkTargetType.INVARIANT)
        self.assertIn("L1", func.required_evidence)
        self.assertIn("dail.verify.reachability_cfg", func.required_evidence)
        self.assertIn("aws_db_instance.database", func.scope)
        self.assertIs(func.reason, ReasonCode.SCOPE_RESOURCE_CHANGED)
        sec3 = by_id["INVARIANT:INV-SEC-003:1"]
        self.assertIn("dail.verify.rds_public_flag", sec3.required_evidence)
        self.assertIs(sec3.reason, ReasonCode.SCOPE_TYPE_CHANGED)

    def test_a_created_resource_item_is_baseline_work(self) -> None:
        by_id = {w.target_id: w for w in self.report.verification_work}
        item = by_id["RESOURCE:aws_subnet.new"]
        self.assertIs(item.target_type, WorkTargetType.RESOURCE)
        self.assertIs(item.reason, ReasonCode.CREATED_BASELINE)
        self.assertEqual(item.scope, ("aws_subnet.new",))
        self.assertIn("BASELINE", item.required_evidence)

    def test_the_strongest_reason_names_the_item(self) -> None:
        text = NET.replace(DB_BLOCK, "")
        report = impact_between(NET, text)
        by_id = {w.target_id: w for w in report.verification_work}
        # deletion outranks the absent-endpoint uncertainty that comes with it
        self.assertIs(by_id["INVARIANT:INV-FUNC-001:1"].reason, ReasonCode.DELETED_IN_SCOPE)
        absent = impact_between(text, text)
        (item,) = absent.verification_work
        self.assertIs(item.reason, ReasonCode.ENDPOINT_ABSENT)
        self.assertIn("aws_instance.app", item.scope)  # the endpoints are in the scope

    def test_an_unaffected_invariant_owes_no_work(self) -> None:
        report = impact_between(NET, NET, prior=all_proofs())
        self.assertEqual(report.verification_work, ())


class TestExplanationChain(unittest.TestCase):
    """Doc 08 §27: changed resource, dependency path, invariant scope, impact reason, prior
    evidence invalidated, verification requested."""

    def test_every_impacted_invariant_has_its_whole_chain(self) -> None:
        report = impact_between(
            NET, NET.replace('description = "d"', 'description = "e"'), prior=all_proofs()
        )
        work_targets = {w.target_id for w in report.verification_work}
        refs = {c.address for c in report.changed_resources}
        for item in report.affected_invariants:
            with self.subTest(invariant=item.invariant_id):
                self.assertTrue(item.changed_resource_refs)  # the changed resource
                self.assertTrue(set(item.changed_resource_refs) <= refs)
                self.assertTrue(item.dependency_paths)  # the path
                self.assertTrue(all(r.scope_element for r in item.reasons))  # the scope element
                self.assertTrue(all(r.code and r.detail for r in item.reasons))  # the reason
                self.assertTrue(item.prior_evidence_ids)  # the evidence that loses eligibility
                self.assertIs(item.evidence_validity, EvidenceValidity.INVALID)
                self.assertIn(
                    f"INVARIANT:{item.invariant_id}:{item.invariant_version}", work_targets
                )

    def test_a_dependency_reason_names_the_walk_token_and_a_path(self) -> None:
        report = impact_between(NET, NET.replace('description = "d"', 'description = "e"'))
        func = impacted(report)[FUNC]
        self.assertTrue(func.reasons[0].scope_element.startswith("walk:"))
        self.assertTrue(func.dependency_paths[0].steps)

    def test_reasons_and_codes_are_in_the_closed_vocabulary(self) -> None:
        report = impact_between(NET, NET.replace('description = "d"', 'description = "e"'))
        for item in report.affected_invariants:
            for code in codes_of(item):
                self.assertIsInstance(code, ReasonCode)
        self.assertEqual(
            set(report.reasons),
            {
                ReasonCode.SCOPE_TYPE_CHANGED,
                ReasonCode.FOOTPRINT_MEMBER_CHANGED,
                ReasonCode.NO_PRIOR_EVIDENCE,  # the unaffected invariant has no proof here
            },
        )

    def test_the_report_names_the_versions_and_hashes_it_was_computed_from(self) -> None:
        report = impact_between(NET, NET)
        self.assertEqual(report.algorithm_version, "dail-impact-1")
        self.assertEqual(report.graph_version, "dail-graph-2")
        for value in (
            report.trusted_graph_hash,
            report.candidate_graph_hash,
            report.identity_report_hash,
        ):
            self.assertEqual(len(value), 64)


if __name__ == "__main__":
    unittest.main()
