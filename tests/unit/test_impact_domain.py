"""The impact domain types (P4 step 3; Doc 08 §21-§27, §31-§32; C-138, C-141).

Expectations come from the specification text and from the guards of C-138: one record per
invariant, an invariant is impacted or unaffected, AFFECTED means INVALID evidence, priority never
makes a check optional, sorted everywhere, and a report hash that ignores only its id and clock.
"""

from __future__ import annotations

import dataclasses
import unittest
from datetime import timedelta

from core.domain.enums import ChangeType, DependencyStatus, ImpactStatus
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.evidence import EvidenceValidity
from core.domain.graph import Relationship
from core.domain.impact import (
    AFFECTED_CODES,
    IMPACT_ALGORITHM_VERSION,
    REASON_DEFINITIONS,
    UNAFFECTED_CODES,
    UNCERTAIN_CODES,
    CarryForwardCandidate,
    ChangedResource,
    ChangeFlag,
    ImpactedInvariant,
    ImpactReason,
    ImpactReport,
    ImpactType,
    ReasonCode,
    StepDirection,
    UnaffectedInvariant,
    UncertaintyRecord,
    WorkPriority,
    WorkTargetType,
)
from tests.domain_builders import at, uid
from tests.impact_builders import (
    CANDIDATE,
    HASH_A,
    HASH_B,
    HASH_C,
    PARENT,
    affected_invariant,
    baseline_work,
    changed,
    path,
    reason,
    report,
    step,
    unaffected,
    uncertain_invariant,
    work_for,
)


class TestVocabularies(unittest.TestCase):
    def test_the_reason_codes_are_the_closed_list_of_c_138(self) -> None:
        self.assertEqual(
            {c.value for c in ReasonCode},
            {
                "SCOPE_RESOURCE_CHANGED",
                "SCOPE_TYPE_CHANGED",
                "FOOTPRINT_MEMBER_CHANGED",
                "CREATED_IN_SCOPE",
                "DELETED_IN_SCOPE",
                "REPLACED_IN_SCOPE",
                "IDENTITY_UNCERTAIN",
                "UNRESOLVED_CONTENT",
                "WALK_INCOMPLETE",
                "ENDPOINT_ABSENT",
                "CREATED_BASELINE",
                "NO_CHANGE_IN_FOOTPRINT",
                "NO_PRIOR_EVIDENCE",
                "INVARIANT_VERSION_CHANGED",
                "VERIFIER_CHANGED",
            },
        )
        self.assertEqual(set(REASON_DEFINITIONS), set(ReasonCode))

    def test_every_code_is_in_exactly_one_group(self) -> None:
        groups = [AFFECTED_CODES, UNCERTAIN_CODES, UNAFFECTED_CODES, {ReasonCode.CREATED_BASELINE}]
        for code in ReasonCode:
            self.assertEqual(sum(code in g for g in groups), 1, code)

    def test_impact_types_priorities_and_directions(self) -> None:
        self.assertEqual(
            {t.value for t in ImpactType},
            {"DIRECT", "DEPENDENCY", "IDENTITY", "UNCERTAINTY", "BASELINE"},
        )
        self.assertEqual(
            {p.value for p in WorkPriority}, {"BLOCKING", "HIGH", "NORMAL", "ADVISORY"}
        )
        self.assertEqual({d.value for d in StepDirection}, {"FORWARD", "REVERSE"})

    def test_the_algorithm_version(self) -> None:
        self.assertEqual(IMPACT_ALGORITHM_VERSION, "dail-impact-1")
        self.assertEqual(report().algorithm_version, "dail-impact-1")


class TestChangedResource(unittest.TestCase):
    def test_created_has_only_a_candidate_ref_and_deleted_only_a_trusted_ref(self) -> None:
        created = changed("a.x", ChangeType.CREATED)
        deleted = changed("a.x", ChangeType.DELETED)
        self.assertEqual((created.trusted_ref, created.candidate_ref), (None, "a.x"))
        self.assertEqual((deleted.trusted_ref, deleted.candidate_ref), ("a.x", None))

    def test_the_address_is_the_candidate_ref_else_the_trusted_ref(self) -> None:
        moved = ChangedResource("b.y", "a.x", "b.y", "a", ChangeType.UNCERTAIN, ())
        self.assertEqual(moved.refs(), ("a.x", "b.y"))
        with self.assertRaises(DomainValidationError):
            ChangedResource("a.x", "a.x", "b.y", "a", ChangeType.UNCERTAIN, ())

    def test_guards(self) -> None:
        bad = (
            lambda: ChangedResource("a.x", None, None, "a", ChangeType.MODIFIED, ()),
            lambda: ChangedResource("a.x", "a.x", "a.x", "a", ChangeType.UNCHANGED, ()),
            lambda: ChangedResource("a.x", "a.x", "a.x", "a", ChangeType.CREATED, ()),
            lambda: ChangedResource("a.x", "a.x", "a.x", "a", ChangeType.DELETED, ()),
            lambda: ChangedResource("a.x", "a.x", "a.x", "", ChangeType.MODIFIED, ()),
            lambda: ChangedResource("a.x", "a.x", "a.x", "a", "MODIFIED", ()),  # type: ignore[arg-type]
            lambda: ChangedResource(
                "a.x",
                "a.x",
                "a.x",
                "a",
                ChangeType.MODIFIED,
                (ChangeFlag.UNSUPPORTED_TYPE, ChangeFlag.UNRESOLVED_CONTENT),
            ),
        )
        for make in bad:
            with self.subTest(make=make), self.assertRaises(DomainValidationError):
                make()

    def test_flags_are_kept_sorted(self) -> None:
        ok = ChangedResource(
            "a.x",
            "a.x",
            "a.x",
            "a",
            ChangeType.UNCERTAIN,
            (ChangeFlag.UNRESOLVED_CONTENT, ChangeFlag.UNSUPPORTED_TYPE),
        )
        self.assertEqual(len(ok.flags), 2)

    def test_round_trip(self) -> None:
        item = ChangedResource(
            "a.x", "a.x", "a.x", "a", ChangeType.UNCERTAIN, (ChangeFlag.UNRESOLVED_CONTENT,)
        )
        self.assertEqual(ChangedResource.from_dict(item.to_dict()), item)


class TestReasonsAndPaths(unittest.TestCase):
    def test_an_impact_reason_must_be_an_impact_code(self) -> None:
        for code in (ReasonCode.NO_PRIOR_EVIDENCE, ReasonCode.CREATED_BASELINE):
            with self.subTest(code=code), self.assertRaises(DomainValidationError):
                reason(code)

    def test_reason_text_is_required(self) -> None:
        with self.assertRaises(DomainValidationError):
            ImpactReason(ReasonCode.SCOPE_TYPE_CHANGED, "a.x", "", "d")
        with self.assertRaises(DomainValidationError):
            ImpactReason(ReasonCode.SCOPE_TYPE_CHANGED, "a.x", "e", "")

    def test_a_walk_level_reason_has_no_changed_ref(self) -> None:
        item = ImpactReason(ReasonCode.WALK_INCOMPLETE, None, "walk", "a seed is absent")
        self.assertIsNone(item.changed_ref)
        self.assertEqual(ImpactReason.from_dict(item.to_dict()), item)

    def test_steps_must_form_a_chain(self) -> None:
        ok = path(
            "a.x",
            step(from_node="RESOURCE:a.x", to_node="RESOURCE:a.y"),
            step(HASH_B, "RESOURCE:a.y", "RESOURCE:a.z"),
        )
        self.assertEqual(len(ok.steps), 2)
        with self.assertRaises(DomainValidationError):
            path(
                "a.x",
                step(from_node="RESOURCE:a.x", to_node="RESOURCE:a.y"),
                step(HASH_B, "RESOURCE:a.q", "RESOURCE:a.z"),
            )

    def test_a_step_needs_a_real_edge_key(self) -> None:
        with self.assertRaises(DomainValidationError):
            step(edge_key="short")

    def test_an_empty_path_means_the_changed_resource_is_a_seed(self) -> None:
        self.assertEqual(path("a.x").steps, ())

    def test_path_round_trip(self) -> None:
        item = path(
            "a.x",
            step(
                relationship=Relationship.ROUTE_TABLE_BELONGS_TO_VPC,
                direction=StepDirection.REVERSE,
                status=DependencyStatus.UNCERTAIN,
            ),
        )
        self.assertEqual(type(item).from_dict(item.to_dict()), item)


class TestImpactedInvariant(unittest.TestCase):
    def test_affected_means_invalid_and_uncertain_means_uncertain(self) -> None:
        self.assertIs(affected_invariant().evidence_validity, EvidenceValidity.INVALID)
        self.assertIs(uncertain_invariant().evidence_validity, EvidenceValidity.UNCERTAIN)
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(affected_invariant(), evidence_validity=EvidenceValidity.UNCERTAIN)
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(uncertain_invariant(), evidence_validity=EvidenceValidity.INVALID)
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(affected_invariant(), evidence_validity=EvidenceValidity.VALID)

    def test_unaffected_is_not_an_impact_status(self) -> None:
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(affected_invariant(), status=ImpactStatus.UNAFFECTED)

    def test_the_status_follows_the_reasons(self) -> None:
        # AFFECTED exactly when some reason is an affected code
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(
                affected_invariant(),
                reasons=(reason(ReasonCode.IDENTITY_UNCERTAIN),),
                impact_types=(ImpactType.IDENTITY,),
            )
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(
                uncertain_invariant(),
                status=ImpactStatus.AFFECTED,
                evidence_validity=EvidenceValidity.INVALID,
            )

    def test_impact_types_must_match_the_reasons(self) -> None:
        for types in (
            (ImpactType.DIRECT, ImpactType.IDENTITY),  # no identity reason
            (ImpactType.BASELINE, ImpactType.DIRECT),  # no CREATED_IN_SCOPE reason
            (ImpactType.DIRECT, ImpactType.UNCERTAINTY),  # no uncertainty reason
            (),
        ):
            with self.subTest(types=types), self.assertRaises(DomainValidationError):
                dataclasses.replace(affected_invariant(), impact_types=types)

    def test_created_in_scope_is_baseline_and_uncertainty_codes_are_uncertainty(self) -> None:
        item = affected_invariant(
            refs=("a.new", "a.sg"),
            reasons=[
                reason(ReasonCode.CREATED_IN_SCOPE, "a.new", "resource_types:a"),
                reason(ReasonCode.WALK_INCOMPLETE, None, "walk", "a seed is absent"),
            ],
            types=(ImpactType.BASELINE, ImpactType.DIRECT, ImpactType.UNCERTAINTY),
        )
        self.assertEqual(len(item.impact_types), 3)

    def test_a_reason_or_path_naming_an_unlisted_resource_is_refused(self) -> None:
        with self.assertRaises(DomainValidationError):
            affected_invariant(reasons=[reason(ref="other.x")])
        with self.assertRaises(DomainValidationError):
            affected_invariant(paths=[path("other.x")])

    def test_lists_must_be_sorted_and_unique(self) -> None:
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(affected_invariant(), changed_resource_refs=("b.x", "a.x"))
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(affected_invariant(), changed_resource_refs=("a.x", "a.x"))
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(affected_invariant(), prior_evidence_ids=("z", "a"))
        r1, r2 = reason(detail="a"), reason(detail="b")
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(affected_invariant(), reasons=(r2, r1))
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(affected_invariant(), reasons=(r1, r1))

    def test_at_least_one_reason_and_a_positive_integer_version(self) -> None:
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(affected_invariant(), reasons=())
        for version in (0, -1, 1.0, True):
            with self.subTest(version=version), self.assertRaises(DomainValidationError):
                affected_invariant(version=version)  # type: ignore[arg-type]

    def test_prior_evidence_is_carried_unchanged(self) -> None:
        self.assertEqual(affected_invariant(evidence=["e2", "e1"]).prior_evidence_ids, ("e1", "e2"))

    def test_round_trip(self) -> None:
        item = affected_invariant(
            evidence=["e1"],
            paths=[path("aws_security_group.app", step())],
            types=(ImpactType.DEPENDENCY,),
            reasons=[reason(ReasonCode.FOOTPRINT_MEMBER_CHANGED, element="walk:X:FORWARD")],
        )
        self.assertEqual(ImpactedInvariant.from_dict(item.to_dict()), item)


class TestWorkAndUnaffected(unittest.TestCase):
    def test_work_target_prefix_and_reason_kind(self) -> None:
        good = work_for(affected_invariant())
        self.assertEqual(good.target_id, "INVARIANT:INV-SEC-001:1")
        for kwargs in (
            {"target_id": "RESOURCE:INV-SEC-001:1"},
            {"reason": ReasonCode.CREATED_BASELINE},
            {"reason": ReasonCode.NO_PRIOR_EVIDENCE},
            {"scope": ()},
            {"required_evidence": ""},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(DomainValidationError):
                dataclasses.replace(good, **kwargs)
        base = baseline_work("a.x")
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(base, reason=ReasonCode.SCOPE_TYPE_CHANGED)
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(base, target_id="INVARIANT:a:1")

    def test_priority_is_data_not_a_way_to_skip_a_check(self) -> None:
        item = dataclasses.replace(work_for(affected_invariant()), priority=WorkPriority.ADVISORY)
        # Doc 08 §26: priority never changes whether a required invariant is mandatory; the work
        # item is still in the report and still tied to an impacted invariant
        self.assertIs(item.priority, WorkPriority.ADVISORY)
        self.assertEqual(
            len(
                report(
                    work=[
                        item,
                        work_for(uncertain_invariant()),
                        baseline_work("aws_internet_gateway.new"),
                    ]
                ).verification_work
            ),
            3,
        )

    def test_eligible_needs_no_change_reason_and_evidence(self) -> None:
        ok = unaffected("INV-SEC-003", eligible=True, evidence=["e1"])
        self.assertTrue(ok.carry_forward_eligible)
        for kwargs in (
            {"prior_evidence_ids": ()},
            {"reason": ReasonCode.NO_PRIOR_EVIDENCE},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(DomainValidationError):
                dataclasses.replace(ok, **kwargs)

    def test_not_eligible_needs_a_reason_why(self) -> None:
        with self.assertRaises(DomainValidationError):
            unaffected("INV-SEC-003", eligible=False, reason_code=ReasonCode.NO_CHANGE_IN_FOOTPRINT)
        for code in (
            ReasonCode.NO_PRIOR_EVIDENCE,
            ReasonCode.INVARIANT_VERSION_CHANGED,
            ReasonCode.VERIFIER_CHANGED,
        ):
            self.assertFalse(unaffected("INV-SEC-003", reason_code=code).carry_forward_eligible)

    def test_unaffected_reason_must_be_an_unaffected_code(self) -> None:
        with self.assertRaises(DomainValidationError):
            unaffected("INV-SEC-003", reason_code=ReasonCode.SCOPE_TYPE_CHANGED)

    def test_the_eligible_flag_is_a_bool(self) -> None:
        with self.assertRaises(DomainValidationError):
            UnaffectedInvariant("INV-SEC-003", 1, ("e",), 1, ReasonCode.NO_CHANGE_IN_FOOTPRINT)  # type: ignore[arg-type]

    def test_uncertainty_record_needs_an_uncertainty_code(self) -> None:
        UncertaintyRecord("INV-FUNC-001", 1, ReasonCode.WALK_INCOMPLETE, "a seed is absent")
        with self.assertRaises(DomainValidationError):
            UncertaintyRecord("INV-FUNC-001", 1, ReasonCode.SCOPE_TYPE_CHANGED, "d")

    def test_round_trips(self) -> None:
        for item in (
            work_for(affected_invariant()),
            baseline_work("a.x"),
            unaffected("INV-SEC-003", eligible=True, evidence=["e1"]),
            UncertaintyRecord("INV-FUNC-001", 1, ReasonCode.ENDPOINT_ABSENT, "D is absent"),
            CarryForwardCandidate("INV-SEC-003", 1, ("e1",)),
        ):
            self.assertEqual(type(item).from_dict(item.to_dict()), item)  # type: ignore[attr-defined]

    def test_a_carry_forward_candidate_needs_evidence(self) -> None:
        with self.assertRaises(DomainValidationError):
            CarryForwardCandidate("INV-SEC-003", 1, ())


class TestReportGuards(unittest.TestCase):
    def test_a_valid_report_builds_and_derives_its_parts(self) -> None:
        built = report()
        self.assertEqual([c.key() for c in built.carry_forward_candidates], [("INV-SEC-003", 1)])
        self.assertEqual(built.carry_forward_candidates[0].evidence_ids, ("evidence-3",))
        self.assertIn(ReasonCode.CREATED_BASELINE, built.reasons)
        self.assertEqual(list(built.reasons), sorted(built.reasons, key=lambda c: c.value))

    def test_an_invariant_cannot_be_impacted_and_unaffected(self) -> None:
        with self.assertRaises(DomainValidationError):
            report(unaffected_invariants=[unaffected("INV-SEC-001")])

    def test_an_invariant_cannot_be_impacted_twice(self) -> None:
        item = affected_invariant()
        with self.assertRaises(DomainValidationError):
            report(
                affected=[item, item],
                work=[work_for(item), baseline_work("aws_internet_gateway.new")],
            )

    def test_every_impacted_invariant_owes_one_work_item(self) -> None:
        sec, func = affected_invariant(), uncertain_invariant()
        with self.assertRaises(DomainValidationError):
            report(
                affected=[sec, func],
                work=[work_for(sec), baseline_work("aws_internet_gateway.new")],
            )
        with self.assertRaises(DomainValidationError):
            report(
                affected=[sec, func],
                work=[
                    work_for(sec),
                    work_for(sec),
                    work_for(func),
                    baseline_work("aws_internet_gateway.new"),
                ],
            )

    def test_work_for_an_unimpacted_invariant_is_refused(self) -> None:
        sec = affected_invariant()
        stray = work_for(affected_invariant("INV-SEC-009"))
        with self.assertRaises(DomainValidationError):
            report(
                affected=[sec],
                work=[work_for(sec), stray, baseline_work("aws_internet_gateway.new")],
            )

    def test_every_created_resource_owes_one_baseline_item(self) -> None:
        sec, func = affected_invariant(), uncertain_invariant()
        with self.assertRaises(DomainValidationError):
            report(affected=[sec, func], work=[work_for(sec), work_for(func)])
        with self.assertRaises(DomainValidationError):
            report(
                affected=[sec, func],
                work=[
                    work_for(sec),
                    work_for(func),
                    baseline_work("aws_internet_gateway.new"),
                    baseline_work("aws_security_group.app"),
                ],
            )

    def test_uncertainty_must_name_an_impacted_invariant(self) -> None:
        with self.assertRaises(DomainValidationError):
            report(
                uncertainty=[UncertaintyRecord("INV-SEC-003", 1, ReasonCode.WALK_INCOMPLETE, "d")]
            )
        ok = report(
            uncertainty=[UncertaintyRecord("INV-SEC-001", 1, ReasonCode.WALK_INCOMPLETE, "d")]
        )
        self.assertEqual(len(ok.uncertainty), 1)

    def test_the_constructor_checks_the_derived_candidates_and_reasons(self) -> None:
        built = report()
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, carry_forward_candidates=())
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, reasons=())
        with self.assertRaises(DomainValidationError):
            dataclasses.replace(built, reasons=tuple(reversed(built.reasons)))

    def test_unsorted_parts_are_refused(self) -> None:
        built = report()
        for field in ("changed_resources", "affected_invariants", "verification_work"):
            with self.subTest(field=field), self.assertRaises(DomainValidationError):
                dataclasses.replace(built, **{field: tuple(reversed(getattr(built, field)))})

    def test_ids_hashes_and_time_are_validated(self) -> None:
        built = report()
        for kwargs in (
            {"report_id": "x"},
            {"parent_state_id": "x"},
            {"candidate_id": "x"},
            {"trusted_graph_hash": "short"},
            {"candidate_graph_hash": "G" * 64},
            {"identity_report_hash": ""},
            {"graph_version": ""},
            {"created_at": built.created_at.replace(tzinfo=None)},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(DomainValidationError):
                dataclasses.replace(built, **kwargs)

    def test_create_sorts_its_inputs(self) -> None:
        sec, func = affected_invariant(), uncertain_invariant()
        built = report(
            affected=[func, sec],
            work=[baseline_work("aws_internet_gateway.new"), work_for(func), work_for(sec)],
            changed_resources=[
                changed("aws_internet_gateway.new", ChangeType.CREATED),
                changed("aws_security_group.ops", ChangeType.UNCERTAIN),
                changed("aws_security_group.app"),
            ],
        )
        self.assertEqual(
            [a.key() for a in built.affected_invariants], [("INV-FUNC-001", 1), ("INV-SEC-001", 1)]
        )
        self.assertEqual(
            [c.address for c in built.changed_resources],
            ["aws_internet_gateway.new", "aws_security_group.app", "aws_security_group.ops"],
        )


class TestHash(unittest.TestCase):
    def test_the_hash_ignores_report_id_and_created_at(self) -> None:
        one = report()
        other = report(report_id=uid(999), now=at(4000))
        self.assertNotEqual(one.report_id, other.report_id)
        self.assertNotEqual(one.created_at, other.created_at)
        self.assertEqual(one.content_hash, other.content_hash)

    def test_the_hash_depends_on_everything_else(self) -> None:
        base = report().content_hash
        sec = affected_invariant()
        func = uncertain_invariant()
        variants = {
            "parent": report(parent_state_id=uid(5)),
            "candidate": report(candidate_id=uid(6)),
            "trusted graph": report(trusted_graph_hash=HASH_B),
            "candidate graph": report(candidate_graph_hash=HASH_A),
            "identity report": report(identity_report_hash=HASH_A),
            "graph version": report(graph_version="dail-graph-3"),
            "evidence": report(
                affected=[affected_invariant(evidence=["e1"]), func],
                work=[work_for(sec), work_for(func), baseline_work("aws_internet_gateway.new")],
            ),
            "carry": report(
                unaffected_invariants=[unaffected("INV-SEC-002"), unaffected("INV-SEC-003")]
            ),
            "uncertainty": report(
                uncertainty=[UncertaintyRecord("INV-SEC-001", 1, ReasonCode.WALK_INCOMPLETE, "d")]
            ),
        }
        for name, variant in variants.items():
            with self.subTest(change=name):
                self.assertNotEqual(variant.content_hash, base)

    def test_a_tampered_hash_or_content_is_detected(self) -> None:
        built = report()
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(built, content_hash="0" * 64)
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(built, trusted_graph_hash=HASH_C)
        with self.assertRaises(HashMismatchError):
            dataclasses.replace(built, algorithm_version="dail-impact-2")

    def test_round_trip_keeps_the_hash(self) -> None:
        built = report(
            uncertainty=[UncertaintyRecord("INV-SEC-001", 1, ReasonCode.WALK_INCOMPLETE, "d")]
        )
        again = ImpactReport.from_dict(built.to_dict())
        self.assertEqual(again, built)
        self.assertEqual(again.content_hash, built.content_hash)
        self.assertEqual(again.created_at, built.created_at + timedelta(0))

    def test_from_dict_checks_keys_and_hash(self) -> None:
        data = report().to_dict()
        with self.assertRaises(DomainValidationError):
            ImpactReport.from_dict({**data, "extra": 1})
        data["content_hash"] = "f" * 64
        with self.assertRaises(HashMismatchError):
            ImpactReport.from_dict(data)


class TestCarryForwardOk(unittest.TestCase):
    def ok(
        self,
        built: ImpactReport,
        invariant_id: str = "INV-SEC-003",
        version: int = 1,
        **kwargs: str,
    ) -> bool:
        arguments = {"candidate_id": CANDIDATE, "parent_state_id": PARENT, **kwargs}
        return built.carry_forward_ok(invariant_id, version, **arguments)

    def test_true_for_an_eligible_unaffected_invariant_of_this_candidate_and_parent(self) -> None:
        self.assertTrue(self.ok(report()))

    def test_false_for_the_wrong_candidate_or_parent(self) -> None:
        built = report()
        self.assertFalse(self.ok(built, candidate_id=uid(7)))
        self.assertFalse(self.ok(built, parent_state_id=uid(8)))

    def test_false_when_not_eligible(self) -> None:
        self.assertFalse(self.ok(report(), "INV-SEC-002"))

    def test_false_for_an_impacted_invariant(self) -> None:
        built = report()
        self.assertFalse(self.ok(built, "INV-SEC-001"))
        self.assertFalse(self.ok(built, "INV-FUNC-001"))

    def test_false_for_an_unknown_invariant_or_a_wrong_version(self) -> None:
        built = report()
        self.assertFalse(self.ok(built, "INV-NOPE-001"))
        self.assertFalse(self.ok(built, "INV-SEC-003", 2))

    def test_false_for_a_tampered_report(self) -> None:
        built = report()
        object.__setattr__(built, "trusted_graph_hash", HASH_C)  # bypasses the constructor
        self.assertNotEqual(built.content_hash, built.compute_hash())
        self.assertFalse(self.ok(built))

    def test_false_when_a_candidate_was_added_by_hand(self) -> None:
        built = report()
        object.__setattr__(
            built,
            "carry_forward_candidates",
            (*built.carry_forward_candidates, CarryForwardCandidate("INV-SEC-002", 1, ("e",))),
        )
        self.assertFalse(self.ok(built, "INV-SEC-002"))

    def test_a_report_with_no_prior_proofs_offers_no_carry_forward(self) -> None:
        built = report(unaffected_invariants=[unaffected("INV-SEC-002"), unaffected("INV-SEC-003")])
        self.assertEqual(built.carry_forward_candidates, ())
        self.assertFalse(self.ok(built))


class TestNoFloats(unittest.TestCase):
    def test_a_float_version_is_refused_everywhere(self) -> None:
        with self.assertRaises(DomainValidationError):
            UncertaintyRecord("INV-SEC-001", 1.5, ReasonCode.WALK_INCOMPLETE, "d")  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            CarryForwardCandidate("INV-SEC-003", 1.0, ("e",))  # type: ignore[arg-type]
        self.assertIs(WorkTargetType.INVARIANT.value, "INVARIANT")


if __name__ == "__main__":
    unittest.main()
