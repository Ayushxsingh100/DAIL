"""The impact engine against the 18 transition fixtures (P4 step 7; Doc 15 §11.2; C-70, C-89).

Expected sets come from two places only, never from the engine:

- ``expected.json`` of each fixture (hand-written, D2): ``truth_changed``, ``oracle_affected`` and
  ``required_affected``. ``AFFECTED ⊇ required_affected`` is the recall floor; ``oracle_affected``
  is what precision is measured against.
- ``EXPECTED`` below: the engine result for each fixture, derived by hand from the registry
  footprints (§3.5, §5.4, §6.6) and the fixture's ``changes`` block before the engine was run on any
  fixture. Impact is resource-level (C-140), so the engine reports an invariant whenever a changed
  resource is in its footprint, which is why it can exceed ``oracle_affected`` (R1) but never
  ``required_affected``.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass
from pathlib import Path

from core.domain.enums import ImpactStatus
from core.domain.impact import ChangeFlag, ImpactReport, ImpactType, ReasonCode, WorkTargetType
from core.terraform_model.normalization import NormalizationOutcome, normalize_directory
from tests import fixture_catalog as fc
from tests.impact_builders import (
    NOW,
    codes_of,
    impact_of_outcomes,
    impacted,
    impacted_ids,
)

SEC1, SEC2, SEC3, FUNC = "INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"
ROOT = fc.REPO_ROOT

_OUTCOMES: dict[str, NormalizationOutcome] = {}


def outcome(folder: str) -> NormalizationOutcome:
    if folder not in _OUTCOMES:
        _OUTCOMES[folder] = normalize_directory(ROOT / folder, None, now=NOW)
    return _OUTCOMES[folder]


def run(fixture: fc.Fixture) -> ImpactReport:
    before, after = outcome(fixture.data["parent"]), outcome(fixture.data["config"])
    binding = fixture.data["bindings"][FUNC]
    return impact_of_outcomes(
        before.resources,
        after.resources,
        list(after.moves),
        source=binding["S"],
        destination=binding["D"],
    )


def transitions() -> dict[str, fc.Fixture]:
    """The 18 fixtures that have an ``impact`` block, by fixture id."""
    found = {
        fixture.data["fixture_id"]: fixture
        for fixture in fc.load_all().values()
        if fixture.data["impact"] is not None
    }
    return dict(sorted(found.items()))


@dataclass(frozen=True)
class Expect:
    engine: frozenset[str]  # invariants reported AFFECTED or UNCERTAIN
    extras_vs_oracle: frozenset[str]
    note: str


def ids(*names: str) -> frozenset[str]:
    return frozenset(names)


# Hand-derived before running the engine on any fixture (see the report, section 5).
EXPECTED: dict[str, Expect] = {
    "process_stale_parent_reject_v1": Expect(
        ids(FUNC, SEC1, SEC2), ids(), "sg.app modified, SSH rule deleted: in SEC and in SG(S)"
    ),
    "process_verifier_error_escalate_v1": Expect(
        ids(FUNC, SEC1, SEC2), ids(), "the same transition as the stale-parent process fixture"
    ),
    "canonical_security_repair_breaks_function_reject_v1": Expect(
        ids(FUNC, SEC1, SEC2), ids(), "both groups modified, both rules deleted"
    ),
    "canonical_safe_repair_promote_v1": Expect(
        ids(FUNC, SEC1, SEC2), ids(), "sg.app modified, SSH rule deleted"
    ),
    "func_unknown_dependency_unknown_v1": Expect(
        ids(FUNC, SEC1, SEC2), ids(), "the rule with an unresolved source group is modified"
    ),
    "func_unsupported_relationship_unsupported_v1": Expect(
        ids(FUNC), ids(), "an aws_network_acl is created: relevant-unsupported for FUNC only"
    ),
    "ambiguous_identity_uncertain_v1": Expect(
        ids(SEC1, SEC2), ids(), "the ops groups have an uncertain identity: SEC scope"
    ),
    "rds_deleted_dependency_fail_v1": Expect(
        ids(FUNC, SEC3), ids(), "the database D is deleted: FUNC endpoint and SEC-003 scope"
    ),
    "sg_created_resource_fail_v1": Expect(
        ids(SEC1, SEC2), ids(), "a new group is created: SEC scope, attached to nothing"
    ),
    "sg_replacement_resource_promote_v1": Expect(
        ids(FUNC, SEC1, SEC2),
        ids(FUNC, SEC1, SEC2),
        "SG(D) is replaced: in SEC and in the FUNC footprint, yet no result changes (oracle: none)",
    ),
    "ec2_rds_5432_break_fail_v1": Expect(
        ids(FUNC, SEC1, SEC2), ids(), "sg.app modified, egress rule deleted"
    ),
    "ec2_rds_5432_pass_v1": Expect(ids(FUNC, SEC1, SEC2), ids(), "the database rule is modified"),
    "rds_publicly_accessible_fail_v1": Expect(
        ids(FUNC, SEC3),
        ids(FUNC),
        "D modified: a footprint resource of FUNC, but publicly_accessible is not (field level)",
    ),
    "rds_publicly_accessible_pass_v1": Expect(
        ids(FUNC, SEC3), ids(FUNC), "D modified back: the same reasoning as the fail fixture"
    ),
    "sg_private_postgres_pass_v1": Expect(
        ids(FUNC, SEC1, SEC2), ids(), "the database rule is modified"
    ),
    "sg_private_ssh_pass_v1": Expect(ids(FUNC, SEC1, SEC2), ids(), "the SSH rule is modified"),
    "sg_public_postgres_fail_v1": Expect(
        ids(FUNC, SEC1, SEC2), ids(), "the database rule is modified"
    ),
    "sg_public_ssh_fail_v1": Expect(
        ids(FUNC, SEC1, SEC2), ids(), "sg.app modified, the SSH rule is created"
    ),
}
# Invariants whose result is UNCERTAINTY (an incomplete walk or an absent endpoint) per fixture.
EXPECTED_UNCERTAINTY: dict[str, frozenset[str]] = {
    "func_unknown_dependency_unknown_v1": ids(FUNC, SEC1, SEC2),
    "rds_deleted_dependency_fail_v1": ids(FUNC),
}


class TestCatalog(unittest.TestCase):
    def test_there_are_eighteen_transitions_and_the_table_covers_them_exactly(self) -> None:
        found = transitions()
        self.assertEqual(len(found), 18)
        self.assertEqual(set(found), set(EXPECTED))

    def test_the_table_is_consistent_with_expected_json(self) -> None:
        # a guard on the hand derivation itself: engine ⊇ required, and the extras vs the oracle
        for fixture_id, fixture in transitions().items():
            impact = fixture.data["impact"]
            expect = EXPECTED[fixture_id]
            with self.subTest(fixture=fixture_id):
                self.assertTrue(set(impact["required_affected"]) <= expect.engine)
                self.assertEqual(
                    expect.engine - set(impact["oracle_affected"]), expect.extras_vs_oracle
                )
                self.assertEqual(set(impact["oracle_affected"]) - expect.engine, set())


class TestRecall(unittest.TestCase):
    """The hard floor: AFFECTED ∪ UNCERTAIN ⊇ required_affected ⊇ truth_changed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.reports = {fixture_id: run(fixture) for fixture_id, fixture in transitions().items()}

    def test_every_transition_reports_at_least_the_required_affected_set(self) -> None:
        for fixture_id, fixture in transitions().items():
            required = set(fixture.data["impact"]["required_affected"])
            with self.subTest(fixture=fixture_id):
                self.assertTrue(required <= impacted_ids(self.reports[fixture_id]))

    def test_every_transition_reports_everything_whose_truth_changed(self) -> None:
        for fixture_id, fixture in transitions().items():
            truth = set(fixture.data["impact"]["truth_changed"])
            with self.subTest(fixture=fixture_id):
                self.assertTrue(truth <= impacted_ids(self.reports[fixture_id]))

    def test_every_transition_reports_at_least_the_oracle_set(self) -> None:
        for fixture_id, fixture in transitions().items():
            oracle = set(fixture.data["impact"]["oracle_affected"])
            with self.subTest(fixture=fixture_id):
                self.assertTrue(oracle <= impacted_ids(self.reports[fixture_id]))

    def test_the_process_fixtures_report_their_nominal_sets(self) -> None:
        for fixture_id in ("process_stale_parent_reject_v1", "process_verifier_error_escalate_v1"):
            with self.subTest(fixture=fixture_id):
                self.assertEqual(impacted_ids(self.reports[fixture_id]), {FUNC, SEC1, SEC2})


class TestLockedExtras(unittest.TestCase):
    """Precision, measured and locked. Any extra or missing entry fails (R1)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.reports = {fixture_id: run(fixture) for fixture_id, fixture in transitions().items()}

    def test_the_engine_reports_exactly_the_hand_derived_set(self) -> None:
        for fixture_id, expect in EXPECTED.items():
            with self.subTest(fixture=fixture_id, note=expect.note):
                self.assertEqual(impacted_ids(self.reports[fixture_id]), set(expect.engine))

    def test_no_transition_has_an_extra_against_required_affected(self) -> None:
        for fixture_id, fixture in transitions().items():
            required = set(fixture.data["impact"]["required_affected"])
            with self.subTest(fixture=fixture_id):
                self.assertEqual(impacted_ids(self.reports[fixture_id]) - required, set())

    def test_the_extras_against_the_oracle_are_the_locked_ones(self) -> None:
        total = 0
        for fixture_id, fixture in transitions().items():
            oracle = set(fixture.data["impact"]["oracle_affected"])
            extras = impacted_ids(self.reports[fixture_id]) - oracle
            total += len(extras)
            with self.subTest(fixture=fixture_id):
                self.assertEqual(extras, set(EXPECTED[fixture_id].extras_vs_oracle))
        self.assertEqual(
            total, 5
        )  # sg_replacement 3, the two rds_publicly_accessible fixtures 1 each

    def test_nothing_the_oracle_names_is_missed(self) -> None:
        for fixture_id, fixture in transitions().items():
            oracle = set(fixture.data["impact"]["oracle_affected"])
            with self.subTest(fixture=fixture_id):
                self.assertEqual(oracle - impacted_ids(self.reports[fixture_id]), set())

    def test_the_uncertainty_records_are_the_locked_ones(self) -> None:
        for fixture_id, report in self.reports.items():
            with_uncertainty = {
                item.invariant_id
                for item in report.affected_invariants
                if ImpactType.UNCERTAINTY in item.impact_types
            }
            with self.subTest(fixture=fixture_id):
                self.assertEqual(with_uncertainty, set(EXPECTED_UNCERTAINTY.get(fixture_id, ids())))

    def test_the_unresolved_content_rule_fires_on_no_fixture(self) -> None:
        # C-117 (R2): the only resource with unresolved content is the modified rule of
        # func_unknown_dependency_unknown_v1, so the unchanged-but-unresolved rule never fires
        for fixture_id, report in self.reports.items():
            with self.subTest(fixture=fixture_id):
                synthetic = [
                    c
                    for c in report.changed_resources
                    if c.change_type.value == "UNCERTAIN"
                    and ChangeFlag.UNRESOLVED_CONTENT in c.flags
                ]
                self.assertEqual(synthetic, [])
                self.assertNotIn(ReasonCode.UNRESOLVED_CONTENT, report.reasons)

    def test_only_the_unaffected_invariants_are_candidates_to_carry(self) -> None:
        for fixture_id, report in self.reports.items():
            with self.subTest(fixture=fixture_id):
                self.assertEqual(len(report.affected_invariants) + len(report.unaffected), 4)
                self.assertEqual(report.carry_forward_candidates, ())  # no prior proofs are given


class TestSpecificFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reports = {fixture_id: run(fixture) for fixture_id, fixture in transitions().items()}

    def test_ambiguous_identity_is_uncertain_for_sec_only(self) -> None:
        report = self.reports["ambiguous_identity_uncertain_v1"]
        for invariant_id in (SEC1, SEC2):
            item = impacted(report)[invariant_id]
            self.assertIs(item.status, ImpactStatus.UNCERTAIN)
            self.assertIn(ImpactType.IDENTITY, item.impact_types)
            self.assertEqual(codes_of(item), {ReasonCode.IDENTITY_UNCERTAIN})
        self.assertEqual({u.invariant_id for u in report.unaffected}, {FUNC, SEC3})

    def test_rds_deleted_is_direct_for_func_and_sec3_with_a_deletion_reason(self) -> None:
        report = self.reports["rds_deleted_dependency_fail_v1"]
        func, sec3 = impacted(report)[FUNC], impacted(report)[SEC3]
        self.assertIn(ReasonCode.DELETED_IN_SCOPE, codes_of(func))
        self.assertIn(ReasonCode.ENDPOINT_ABSENT, codes_of(func))  # D is an absent seed
        self.assertIn(ImpactType.DIRECT, func.impact_types)
        self.assertIs(func.status, ImpactStatus.AFFECTED)
        self.assertEqual(codes_of(sec3), {ReasonCode.DELETED_IN_SCOPE})
        self.assertEqual(sec3.impact_types, (ImpactType.DIRECT,))
        self.assertEqual({u.invariant_id for u in report.unaffected}, {SEC1, SEC2})

    def test_the_deleted_subnet_group_does_not_reach_any_invariant(self) -> None:
        # aws_db_subnet_group is tolerated, not relevant (registry 2.7, C-15)
        report = self.reports["rds_deleted_dependency_fail_v1"]
        for item in report.affected_invariants:
            self.assertNotIn("aws_db_subnet_group.db", item.changed_resource_refs)

    def test_a_created_network_acl_affects_func_only_and_owes_baseline_work(self) -> None:
        report = self.reports["func_unsupported_relationship_unsupported_v1"]
        self.assertEqual(impacted_ids(report), {FUNC})
        item = impacted(report)[FUNC]
        self.assertEqual(codes_of(item), {ReasonCode.CREATED_IN_SCOPE})
        self.assertEqual(item.reasons[0].scope_element, "resource_types:aws_network_acl")
        self.assertIn(ImpactType.BASELINE, item.impact_types)
        baseline = [w for w in report.verification_work if w.target_type is WorkTargetType.RESOURCE]
        self.assertEqual([w.target_id for w in baseline], ["RESOURCE:aws_network_acl.extra"])
        self.assertEqual({u.invariant_id for u in report.unaffected}, {SEC1, SEC2, SEC3})

    def test_an_unknown_dependency_records_an_incomplete_walk(self) -> None:
        report = self.reports["func_unknown_dependency_unknown_v1"]
        for invariant_id in (FUNC, SEC1, SEC2):
            item = impacted(report)[invariant_id]
            self.assertIs(item.status, ImpactStatus.AFFECTED)  # the rule is modified
            self.assertIn(ReasonCode.WALK_INCOMPLETE, codes_of(item))
            self.assertIn(ImpactType.UNCERTAINTY, item.impact_types)
        records = [r for r in report.uncertainty if r.invariant_id == FUNC]
        self.assertTrue(any("source_security_group_id" in r.detail for r in records))

    def test_a_replaced_group_affects_the_two_security_invariants_and_func(self) -> None:
        report = self.reports["sg_replacement_resource_promote_v1"]
        self.assertEqual(impacted_ids(report), {SEC1, SEC2, FUNC})
        for item in report.affected_invariants:
            self.assertEqual(codes_of(item), {ReasonCode.REPLACED_IN_SCOPE})
        self.assertEqual({u.invariant_id for u in report.unaffected}, {SEC3})

    def test_a_created_group_affects_sec_only_with_baseline_work(self) -> None:
        report = self.reports["sg_created_resource_fail_v1"]
        self.assertEqual(impacted_ids(report), {SEC1, SEC2})
        self.assertEqual({u.invariant_id for u in report.unaffected}, {FUNC, SEC3})
        targets = sorted(w.target_id for w in report.verification_work)
        self.assertEqual(
            targets,
            [
                "INVARIANT:INV-SEC-001:1",
                "INVARIANT:INV-SEC-002:1",
                "RESOURCE:aws_security_group.bastion",
            ],
        )

    def test_a_database_modification_reaches_func_even_though_the_field_is_outside_it(self) -> None:
        # R1: resource-level impact; publicly_accessible is not in the FUNC footprint (field level)
        for fixture_id in ("rds_publicly_accessible_fail_v1", "rds_publicly_accessible_pass_v1"):
            report = self.reports[fixture_id]
            self.assertEqual(impacted_ids(report), {FUNC, SEC3})
            self.assertEqual(codes_of(impacted(report)[FUNC]), {ReasonCode.SCOPE_RESOURCE_CHANGED})

    def test_every_work_item_of_every_fixture_is_blocking(self) -> None:
        for fixture_id, report in self.reports.items():
            with self.subTest(fixture=fixture_id):
                self.assertTrue(
                    all(w.priority.value == "BLOCKING" for w in report.verification_work)
                )

    def test_the_repository_layout_is_what_the_helper_assumes(self) -> None:
        self.assertTrue((Path(ROOT) / "fixtures").is_dir())


if __name__ == "__main__":
    unittest.main()
