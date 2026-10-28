"""The impact computation (P4 step 5; Doc 08 §6-§20, §30-§35; C-140).

Scenarios are Terraform text run through the whole pipeline (normalize, identity, graphs, impact).
Expected sets are derived by hand from the registry footprints (§3.5, §5.4, §6.6): which invariant
a changed resource reaches, and by which path, is read off the ``.tf`` text, not from the engine.
"""

from __future__ import annotations

import dataclasses
import unittest

from core.domain.enums import ChangeType, ImpactStatus, InvariantCategory
from core.domain.evidence import EvidenceValidity
from core.domain.graph import Relationship
from core.domain.impact import (
    ChangeFlag,
    ImpactReport,
    ImpactType,
    ReasonCode,
    StepDirection,
    WorkTargetType,
)
from core.identity.engine import compare
from core.impact.engine import compute_impact
from core.impact.errors import ImpactInputError
from core.impact.inputs import PriorProof
from tests.graph_builders import hand_ref, hand_resource
from tests.identity_builders import normalize
from tests.impact_builders import (
    NET,
    NOW,
    PIPE_CANDIDATE,
    PIPE_PARENT,
    codes_of,
    graph_of,
    impact_between,
    impact_of_outcomes,
    impacted,
    impacted_ids,
    registry,
)

SEC = {"INV-SEC-001", "INV-SEC-002"}
DB_BLOCK = (
    'resource "aws_db_instance" "database" {\n  identifier = "d"\n'
    "  vpc_security_group_ids = [aws_security_group.db.id]\n}\n"
)
NEW_SUBNET = (
    'resource "aws_subnet" "new" {\n  vpc_id = aws_vpc.main.id\n'
    '  cidr_block = "10.0.7.0/24"\n}\n'
)
VPC_OLD = 'cidr_block = "10.0.0.0/16" }\nresource "aws_vpc" "elsewhere"'
VPC_NEW = 'cidr_block = "10.1.0.0/16" }\nresource "aws_vpc" "elsewhere"'
FUNC = "INV-FUNC-001"
SEC3 = "INV-SEC-003"
R = Relationship


def changed_net(old: str, new: str) -> str:
    assert NET.count(old) == 1, old
    return NET.replace(old, new)


# --- direct impact ----------------------------------------------------------------------------


class TestDirect(unittest.TestCase):
    def test_a_modified_database_affects_its_two_invariants_by_scope_element(self) -> None:
        report = impact_between(NET, changed_net('identifier = "d"', 'identifier = "e"'))
        self.assertEqual(impacted_ids(report), {FUNC, SEC3})
        by_id = impacted(report)
        func, sec3 = by_id[FUNC], by_id[SEC3]
        self.assertEqual([r.code for r in func.reasons], [ReasonCode.SCOPE_RESOURCE_CHANGED])
        self.assertIn("resources:aws_db_instance.database", func.reasons[0].scope_element)
        self.assertIn("binding:DESTINATION", func.reasons[0].scope_element)
        self.assertEqual([r.code for r in sec3.reasons], [ReasonCode.SCOPE_TYPE_CHANGED])
        self.assertEqual(sec3.reasons[0].scope_element, "resource_types:aws_db_instance")
        for item in (func, sec3):
            self.assertEqual(item.impact_types, (ImpactType.DIRECT,))
            self.assertIs(item.status, ImpactStatus.AFFECTED)
            self.assertIs(item.evidence_validity, EvidenceValidity.INVALID)
            self.assertEqual(item.changed_resource_refs, ("aws_db_instance.database",))
            self.assertEqual(item.dependency_paths[0].steps, ())

    def test_a_modified_security_group_is_direct_for_sec_and_dependency_for_func(self) -> None:
        report = impact_between(NET, changed_net('description = "d"', 'description = "e"'))
        self.assertEqual(impacted_ids(report), SEC | {FUNC})
        for invariant_id in SEC:
            item = impacted(report)[invariant_id]
            self.assertEqual(item.impact_types, (ImpactType.DIRECT,))
            self.assertEqual(item.reasons[0].code, ReasonCode.SCOPE_TYPE_CHANGED)
            self.assertEqual(item.reasons[0].scope_element, "resource_types:aws_security_group")
        func = impacted(report)[FUNC]
        self.assertEqual(func.impact_types, (ImpactType.DEPENDENCY,))
        self.assertEqual(func.reasons[0].code, ReasonCode.FOOTPRINT_MEMBER_CHANGED)
        self.assertEqual(func.reasons[0].scope_element, "walk:INSTANCE_USES_SECURITY_GROUP:FORWARD")

    def test_the_dependency_path_runs_from_the_changed_group_to_the_source_endpoint(self) -> None:
        report = impact_between(NET, changed_net('description = "d"', 'description = "e"'))
        (path,) = impacted(report)[FUNC].dependency_paths
        self.assertEqual(path.changed_ref, "aws_security_group.app")
        (step,) = path.steps
        self.assertEqual(step.from_node, "RESOURCE:aws_security_group.app")
        self.assertEqual(step.to_node, "RESOURCE:aws_instance.app")
        self.assertIs(step.relationship, R.INSTANCE_USES_SECURITY_GROUP)
        # the edge runs instance -> group; the path goes the other way, so the step is REVERSE
        self.assertIs(step.direction, StepDirection.REVERSE)
        self.assertEqual(len(step.edge_key), 64)

    def test_every_change_type_is_an_impact_source(self) -> None:
        # Doc 08 §6: MODIFIED, CREATED, DELETED, REPLACED and UNCERTAIN are potential sources
        modified = impact_between(NET, changed_net('description = "d"', 'description = "e"'))
        replaced = impact_between(NET, changed_net('name = "db"', 'name = "db2"'))
        extra = 'resource "aws_security_group" "extra" {\n  name = "x"\n}\n'
        created = impact_between(NET, NET + extra)
        deleted = impact_between(NET + extra, NET)
        for name, report in (
            ("modified", modified),
            ("replaced", replaced),
            ("created", created),
            ("deleted", deleted),
        ):
            with self.subTest(change=name):
                self.assertTrue(impacted_ids(report) >= SEC)


# --- dependency (transitive) impact ------------------------------------------------------------


class TestTransitive(unittest.TestCase):
    def test_a_rule_reaches_func_through_the_database_group(self) -> None:
        report = impact_between(NET, changed_net("from_port = 5432", "from_port = 5433"))
        self.assertEqual(impacted_ids(report), SEC | {FUNC})
        func = impacted(report)[FUNC]
        self.assertEqual(func.reasons[0].code, ReasonCode.FOOTPRINT_MEMBER_CHANGED)
        self.assertEqual(
            func.reasons[0].scope_element, "walk:RULE_BELONGS_TO_SECURITY_GROUP:REVERSE"
        )
        (path,) = func.dependency_paths
        self.assertEqual(path.changed_ref, "aws_security_group_rule.to_db")
        first, second = path.steps
        # rule -> group follows the edge (FORWARD); group -> D goes against D -> group (REVERSE)
        self.assertEqual(
            (first.from_node, first.to_node),
            (
                "RESOURCE:aws_security_group_rule.to_db",
                "RESOURCE:aws_security_group.db",
            ),
        )
        self.assertIs(first.direction, StepDirection.FORWARD)
        self.assertEqual(first.relationship, R.RULE_BELONGS_TO_SECURITY_GROUP)
        self.assertEqual(
            (second.from_node, second.to_node),
            (
                "RESOURCE:aws_security_group.db",
                "RESOURCE:aws_db_instance.database",
            ),
        )
        self.assertIs(second.direction, StepDirection.REVERSE)
        self.assertEqual(second.relationship, R.DB_USES_SECURITY_GROUP)

    def test_a_route_table_reaches_func_by_reverse_traversal_from_the_vpc(self) -> None:
        report = impact_between(
            NET,
            changed_net(
                'resource "aws_route_table" "public" { vpc_id = aws_vpc.main.id }',
                'resource "aws_route_table" "public" {\n  vpc_id = aws_vpc.main.id\n'
                '  tags = { x = "1" }\n}',
            ),
        )
        self.assertEqual(impacted_ids(report), {FUNC})
        func = impacted(report)[FUNC]
        self.assertEqual(func.impact_types, (ImpactType.DEPENDENCY,))
        self.assertEqual(func.reasons[0].scope_element, "walk:ROUTE_TABLE_BELONGS_TO_VPC:REVERSE")
        (path,) = func.dependency_paths
        self.assertEqual(len(path.steps), 3)  # route table -> vpc -> (subnet or group) -> endpoint
        self.assertIs(path.steps[0].relationship, R.ROUTE_TABLE_BELONGS_TO_VPC)
        self.assertIs(path.steps[0].direction, StepDirection.FORWARD)
        self.assertEqual(path.steps[0].from_node, "RESOURCE:aws_route_table.public")
        self.assertEqual(path.steps[0].to_node, "RESOURCE:aws_vpc.main")

    def test_the_vpc_itself_reaches_func(self) -> None:
        report = impact_between(
            NET,
            changed_net(
                'cidr_block = "10.0.0.0/16" }\nresource "aws_vpc" "elsewhere"',
                'cidr_block = "10.1.0.0/16" }\nresource "aws_vpc" "elsewhere"',
            ),
        )
        self.assertEqual(impacted_ids(report), {FUNC})
        self.assertEqual(
            impacted(report)[FUNC].reasons[0].code, ReasonCode.FOOTPRINT_MEMBER_CHANGED
        )

    def test_the_source_subnet_reaches_func(self) -> None:
        report = impact_between(
            NET,
            changed_net('cidr_block = "10.0.1.0/24"', 'cidr_block = "10.0.2.0/24"'),
        )
        self.assertEqual(impacted_ids(report), {FUNC})

    def test_a_dependency_reached_through_the_walk_is_not_a_scope_element(self) -> None:
        report = impact_between(NET, changed_net('description = "d"', 'description = "e"'))
        self.assertNotIn(ImpactType.DIRECT, impacted(report)[FUNC].impact_types)


# --- unrelated changes remain unaffected -------------------------------------------------------


class TestUnrelated(unittest.TestCase):
    def assertNothing(self, report: ImpactReport) -> None:
        self.assertEqual(
            report.affected_invariants, (), [i.invariant_id for i in report.affected_invariants]
        )
        self.assertEqual(len(report.unaffected), 4)
        self.assertTrue(report.changed_resources)

    def test_a_tag_on_the_internet_gateway_affects_nothing(self) -> None:
        self.assertNothing(
            impact_between(
                NET,
                changed_net(
                    'resource "aws_internet_gateway" "igw" { vpc_id = aws_vpc.main.id }',
                    'resource "aws_internet_gateway" "igw" {\n  vpc_id = aws_vpc.main.id\n'
                    '  tags = { x = "1" }\n}',
                ),
            )
        )

    def test_a_route_table_association_change_affects_nothing(self) -> None:
        # registry 6.6: aws_route_table_association is not in the footprint
        self.assertNothing(
            impact_between(
                NET,
                changed_net(
                    "route_table_id = aws_route_table.public.id",
                    "route_table_id = aws_route_table.elsewhere.id",
                ),
            )
        )

    def test_a_subnet_the_source_does_not_use_affects_nothing(self) -> None:
        self.assertNothing(
            impact_between(
                NET, changed_net('cidr_block = "10.0.9.0/24"', 'cidr_block = "10.0.8.0/24"')
            )
        )

    def test_a_route_table_of_another_vpc_affects_nothing(self) -> None:
        self.assertNothing(
            impact_between(
                NET,
                changed_net(
                    'resource "aws_route_table" "elsewhere" { vpc_id = aws_vpc.elsewhere.id }',
                    'resource "aws_route_table" "elsewhere" {\n  vpc_id = aws_vpc.elsewhere.id\n'
                    '  tags = { x = "1" }\n}',
                ),
            )
        )

    def test_an_unrelated_instance_and_its_group_rule_affect_nothing_in_func_or_sec3(self) -> None:
        report = impact_between(
            NET,
            changed_net(
                'ami = "a"\n  subnet_id = aws_subnet.other.id',
                'ami = "b"\n  subnet_id = aws_subnet.other.id',
            ),
        )
        self.assertNothing(report)

    def test_a_rule_on_a_group_nothing_uses_is_sec_only(self) -> None:
        report = impact_between(NET, changed_net("from_port = 80", "from_port = 81"))
        self.assertEqual(impacted_ids(report), SEC)  # FUNC: its target is not in SG(S) or SG(D)

    def test_a_new_unconnected_subnet_affects_no_invariant_but_owes_baseline_work(self) -> None:
        report = impact_between(
            NET,
            NET + NEW_SUBNET,
        )
        self.assertEqual(report.affected_invariants, ())
        (item,) = report.verification_work
        self.assertIs(item.target_type, WorkTargetType.RESOURCE)
        self.assertEqual(item.target_id, "RESOURCE:aws_subnet.new")
        self.assertIs(item.reason, ReasonCode.CREATED_BASELINE)

    def test_nothing_changed_means_nothing_affected(self) -> None:
        report = impact_between(NET, NET)
        self.assertEqual(report.affected_invariants, ())
        self.assertEqual(report.changed_resources, ())
        self.assertEqual(report.verification_work, ())


# --- created, deleted, replaced ---------------------------------------------------------------

EXTRA_SG = 'resource "aws_security_group" "extra" {\n  name = "x"\n}\n'


class TestCreatedDeletedReplaced(unittest.TestCase):
    def test_a_created_group_is_baseline_work_and_sec_impact(self) -> None:
        report = impact_between(NET, NET + EXTRA_SG)
        self.assertEqual(impacted_ids(report), SEC)  # attached to nothing, so not FUNC
        for invariant_id in SEC:
            item = impacted(report)[invariant_id]
            self.assertEqual(item.reasons[0].code, ReasonCode.CREATED_IN_SCOPE)
            self.assertEqual(item.impact_types, (ImpactType.BASELINE, ImpactType.DIRECT))
        kinds = {(w.target_type, w.target_id, w.reason) for w in report.verification_work}
        self.assertIn(
            (
                WorkTargetType.RESOURCE,
                "RESOURCE:aws_security_group.extra",
                ReasonCode.CREATED_BASELINE,
            ),
            kinds,
        )
        self.assertEqual(len(report.verification_work), 3)  # two invariants, one created resource

    def test_a_created_resource_infers_no_safety_from_missing_history(self) -> None:
        # Doc 08 §16: no historical evidence for the new resource; it owes baseline work
        report = impact_between(NET, NET + EXTRA_SG, prior=[])
        self.assertTrue(all(item.prior_evidence_ids == () for item in report.affected_invariants))
        self.assertEqual(len(report.verification_work), 3)

    def test_a_deleted_rule_is_found_in_the_trusted_graph(self) -> None:
        report = impact_between(NET, changed_net_without_rule("to_app"))
        self.assertEqual(impacted_ids(report), SEC | {FUNC})
        for item in report.affected_invariants:
            self.assertEqual(item.reasons[0].code, ReasonCode.DELETED_IN_SCOPE)
        self.assertEqual(impacted(report)[FUNC].impact_types, (ImpactType.DEPENDENCY,))
        change = next(
            c for c in report.changed_resources if c.address == "aws_security_group_rule.to_app"
        )
        self.assertIs(change.change_type, ChangeType.DELETED)

    def test_a_deleted_database_affects_func_and_sec3_and_the_absent_endpoint_is_recorded(
        self,
    ) -> None:
        text = NET.replace(DB_BLOCK, "")
        self.assertNotEqual(text, NET)
        report = impact_between(NET, text)
        self.assertEqual(impacted_ids(report), {FUNC, SEC3})
        func = impacted(report)[FUNC]
        self.assertEqual(codes_of(func), {ReasonCode.DELETED_IN_SCOPE, ReasonCode.ENDPOINT_ABSENT})
        self.assertIs(func.status, ImpactStatus.AFFECTED)  # AFFECTED wins the merge
        self.assertIn(ImpactType.UNCERTAINTY, func.impact_types)
        self.assertEqual(codes_of(impacted(report)[SEC3]), {ReasonCode.DELETED_IN_SCOPE})
        self.assertTrue(any(r.code is ReasonCode.ENDPOINT_ABSENT for r in report.uncertainty))

    def test_replacement_is_at_least_as_conservative_as_modification(self) -> None:
        replaced = impact_between(NET, changed_net('name = "db"', 'name = "db2"'))
        modified = impact_between(
            NET, changed_net('name = "db"', 'name = "db"\n  description = "x"')
        )
        change = next(c for c in replaced.changed_resources if c.address == "aws_security_group.db")
        self.assertIs(change.change_type, ChangeType.REPLACED)
        self.assertTrue(impacted_ids(modified) <= impacted_ids(replaced))
        self.assertEqual(impacted_ids(replaced), SEC | {FUNC})
        for item in replaced.affected_invariants:
            self.assertEqual(item.reasons[0].code, ReasonCode.REPLACED_IN_SCOPE)
            self.assertIs(item.status, ImpactStatus.AFFECTED)


def changed_net_without_rule(name: str) -> str:
    start = NET.index(f'resource "aws_security_group_rule" "{name}"')
    end = NET.index("\n}\n", start) + 3
    return NET[:start] + NET[end:]


# --- identity uncertainty -----------------------------------------------------------------------

OPS_SINGLE = 'resource "aws_security_group" "ops" {\n  name = "ops"\n}\n'
OPS_KEYED = (
    'resource "aws_security_group" "ops" {\n  for_each = toset(["a", "b"])\n'
    '  name = "ops-${each.key}"\n}\n'
)


class TestIdentityUncertainty(unittest.TestCase):
    def setUp(self) -> None:
        self.report = impact_between(NET + OPS_SINGLE, NET + OPS_KEYED)

    def test_the_security_invariants_are_uncertain_with_identity(self) -> None:
        self.assertEqual(impacted_ids(self.report), SEC)
        for invariant_id in SEC:
            item = impacted(self.report)[invariant_id]
            self.assertIs(item.status, ImpactStatus.UNCERTAIN)
            self.assertIs(item.evidence_validity, EvidenceValidity.UNCERTAIN)
            self.assertIn(ImpactType.IDENTITY, item.impact_types)
            self.assertEqual(codes_of(item), {ReasonCode.IDENTITY_UNCERTAIN})

    def test_func_and_sec3_stay_unaffected(self) -> None:
        unaffected = {u.invariant_id for u in self.report.unaffected}
        self.assertEqual(unaffected, {FUNC, SEC3})

    def test_all_three_uncertain_resources_are_listed(self) -> None:
        item = impacted(self.report)["INV-SEC-001"]
        self.assertEqual(
            item.changed_resource_refs,
            (
                "aws_security_group.ops",
                'aws_security_group.ops["a"]',
                'aws_security_group.ops["b"]',
            ),
        )

    def test_an_uncertain_identity_never_preserves_old_evidence(self) -> None:
        proofs = [
            PriorProof("INV-SEC-001", 1, ("e1",), "dail.verify.public_ingress", "1"),
            PriorProof("INV-FUNC-001", 1, ("e2",), "dail.verify.reachability_cfg", "1"),
        ]
        report = impact_between(NET + OPS_SINGLE, NET + OPS_KEYED, prior=proofs)
        sec1 = impacted(report)["INV-SEC-001"]
        self.assertEqual(sec1.prior_evidence_ids, ("e1",))  # retained as history, not reusable
        self.assertFalse(
            report.carry_forward_ok(
                "INV-SEC-001", 1, candidate_id=PIPE_CANDIDATE, parent_state_id=PIPE_PARENT
            )
        )
        # the unaffected FUNC invariant has a matching proof and is eligible
        self.assertTrue(
            report.carry_forward_ok(
                "INV-FUNC-001", 1, candidate_id=PIPE_CANDIDATE, parent_state_id=PIPE_PARENT
            )
        )

    def test_uncertainty_records_name_the_resources(self) -> None:
        details = {r.detail for r in self.report.uncertainty if r.invariant_id == "INV-SEC-001"}
        self.assertIn("aws_security_group.ops has an uncertain identity", details)

    def test_the_work_set_asks_for_both_security_invariants(self) -> None:
        targets = {w.target_id for w in self.report.verification_work}
        self.assertEqual(targets, {"INVARIANT:INV-SEC-001:1", "INVARIANT:INV-SEC-002:1"})


# --- dependency uncertainty ---------------------------------------------------------------------

UNKNOWN_SUBNET_OLD = (
    "  subnet_id = aws_subnet.app.id\n  vpc_security_group_ids = [aws_security_group.app.id]"
)
UNKNOWN_SUBNET_NEW = (
    "  subnet_id = var.unset\n  vpc_security_group_ids = [aws_security_group.app.id]"
)


class TestDependencyUncertainty(unittest.TestCase):
    """An incomplete footprint (C-140 item 5), in isolation and next to C-117."""

    UNKNOWN = NET.replace(UNKNOWN_SUBNET_OLD, UNKNOWN_SUBNET_NEW)

    @staticmethod
    def ghost(other_cidr: str = "10.0.9.0/24", igw_tag: str = "a") -> tuple[tuple, ...]:  # type: ignore[type-arg]
        """A source whose subnet is a Ref to an object the state does not hold: the walk is
        incomplete (an absent target), but no value is unknown, so C-117 does not fire."""

        def value(text: str) -> dict[str, object]:
            return {"form": "ATTRIBUTE", "value": text}

        source = hand_resource(
            "aws_instance.app",
            attributes={
                "subnet_id": {
                    "form": "ATTRIBUTE",
                    "value": {"$dail": "ref", "address": "aws_subnet.gone", "attribute": "id"},
                }
            },
            references=[hand_ref("aws_instance.app", "aws_subnet.gone", "subnet_id")],
        )
        other = hand_resource("aws_subnet.other", attributes={"cidr_block": value(other_cidr)})
        igw = hand_resource("aws_internet_gateway.igw", attributes={"tag": value(igw_tag)})
        return (source, other, igw)

    @classmethod
    def ghost_report(cls, **changes: str) -> ImpactReport:
        func = registry()["INV-FUNC-001"]
        narrow = dataclasses.replace(
            func,
            category=InvariantCategory.SECURITY,  # no binding needed: the endpoint is in the scope
            scope=dataclasses.replace(
                func.scope,
                resources=("aws_instance.app",),
                relationships=("INSTANCE_IN_SUBNET:FORWARD",),
            ),
        )
        return impact_of_outcomes(
            cls.ghost(), cls.ghost(**changes), [], invariants=[narrow], bound=False  # type: ignore[arg-type]
        )

    def test_the_fixture_text_really_has_an_unknown_subnet(self) -> None:
        self.assertNotEqual(self.UNKNOWN, NET)

    def test_a_changed_walkable_type_under_an_incomplete_walk_is_uncertain(self) -> None:
        report = self.ghost_report(other_cidr="10.0.8.0/24")  # a subnet: could be the one S uses
        self.assertEqual(impacted_ids(report), {FUNC})
        func = impacted(report)[FUNC]
        self.assertIs(func.status, ImpactStatus.UNCERTAIN)
        self.assertEqual(codes_of(func), {ReasonCode.WALK_INCOMPLETE})
        self.assertEqual(func.impact_types, (ImpactType.UNCERTAINTY,))
        self.assertEqual(func.changed_resource_refs, ("aws_subnet.other",))
        self.assertIs(func.evidence_validity, EvidenceValidity.UNCERTAIN)

    def test_a_change_of_a_type_the_walk_can_never_reach_is_not_made_uncertain(self) -> None:
        report = self.ghost_report(igw_tag="b")
        self.assertEqual(report.affected_invariants, ())

    def test_the_same_change_with_a_complete_walk_is_unaffected(self) -> None:
        new = NET.replace('cidr_block = "10.0.9.0/24"', 'cidr_block = "10.0.8.0/24"')
        self.assertEqual(impact_between(NET, new).affected_invariants, ())

    def test_the_uncertainty_is_recorded_with_its_reason(self) -> None:
        report = self.ghost_report(other_cidr="10.0.8.0/24")
        records = [r for r in report.uncertainty if r.invariant_id == FUNC]
        self.assertTrue(records)
        self.assertTrue(all(r.code is ReasonCode.WALK_INCOMPLETE for r in records))
        self.assertTrue(any("INSTANCE_IN_SUBNET" in r.detail for r in records))
        self.assertTrue(any("aws_subnet.gone" in r.detail for r in records))

    def test_an_unknown_subnet_is_uncertain_even_before_anything_else_changes(self) -> None:
        # the source carries an unknown value: C-117 (registry 2.9) makes the footprint uncertain
        report = impact_between(self.UNKNOWN, self.UNKNOWN)
        self.assertEqual(impacted_ids(report), {FUNC})
        func = impacted(report)[FUNC]
        self.assertEqual(codes_of(func), {ReasonCode.UNRESOLVED_CONTENT})

    def test_an_unknown_subnet_plus_a_changed_subnet_is_uncertain_by_both_rules(self) -> None:
        new = self.UNKNOWN.replace('cidr_block = "10.0.9.0/24"', 'cidr_block = "10.0.8.0/24"')
        report = impact_between(self.UNKNOWN, new)
        func = impacted(report)[FUNC]
        self.assertIs(func.status, ImpactStatus.UNCERTAIN)
        self.assertEqual(
            codes_of(func), {ReasonCode.UNRESOLVED_CONTENT, ReasonCode.WALK_INCOMPLETE}
        )

    def test_a_missing_edge_never_yields_unaffected_on_a_walkable_change(self) -> None:
        for kwargs in ({"other_cidr": "10.0.8.0/24"},):
            with self.subTest(change=kwargs):
                self.assertIn(FUNC, impacted_ids(self.ghost_report(**kwargs)))
        for old, replacement in (
            ('cidr_block = "10.0.9.0/24"', 'cidr_block = "10.0.8.0/24"'),  # a subnet
            ('cidr_block = "10.9.0.0/16"', 'cidr_block = "10.8.0.0/16"'),  # a vpc
        ):
            with self.subTest(change=old):
                report = impact_between(self.UNKNOWN, self.UNKNOWN.replace(old, replacement))
                self.assertIn(FUNC, impacted_ids(report))

    def test_the_security_invariants_are_not_made_uncertain_by_a_func_walk(self) -> None:
        new = self.UNKNOWN.replace('cidr_block = "10.0.9.0/24"', 'cidr_block = "10.0.8.0/24"')
        self.assertNotIn("INV-SEC-001", impacted_ids(impact_between(self.UNKNOWN, new)))

    def test_an_absent_endpoint_is_uncertain_even_when_nothing_changed(self) -> None:
        # R6: a configuration without the bound endpoints gives an absent seed, never "unaffected"
        no_database = NET.replace(DB_BLOCK, "")
        report = impact_between(no_database, no_database)
        self.assertEqual(impacted_ids(report), {FUNC})
        func = impacted(report)[FUNC]
        self.assertIs(func.status, ImpactStatus.UNCERTAIN)
        self.assertEqual(codes_of(func), {ReasonCode.ENDPOINT_ABSENT})

    def test_a_missing_binding_is_uncertain(self) -> None:
        report = impact_between(NET, NET, bound=False)
        self.assertEqual(impacted_ids(report), {FUNC})
        self.assertEqual(codes_of(impacted(report)[FUNC]), {ReasonCode.ENDPOINT_ABSENT})


# --- unresolved content (C-117) -----------------------------------------------------------------

LOOSE = NET.replace('cidr_blocks = ["0.0.0.0/0"]', "cidr_blocks = [var.unset]")


class TestUnresolvedContent(unittest.TestCase):
    def test_an_unchanged_footprint_resource_with_unresolved_content_is_uncertain(self) -> None:
        self.assertNotEqual(LOOSE, NET)
        report = impact_between(LOOSE, LOOSE)
        self.assertEqual(impacted_ids(report), SEC | {FUNC})  # the rule is in all three footprints
        for item in report.affected_invariants:
            self.assertIs(item.status, ImpactStatus.UNCERTAIN)
            self.assertIn(ImpactType.UNCERTAINTY, item.impact_types)
            self.assertEqual(codes_of(item), {ReasonCode.UNRESOLVED_CONTENT})
        (change,) = report.changed_resources
        self.assertEqual(change.address, "aws_security_group_rule.to_app")
        self.assertIs(change.change_type, ChangeType.UNCERTAIN)
        self.assertIn(ChangeFlag.UNRESOLVED_CONTENT, change.flags)

    def test_unresolved_content_outside_every_footprint_changes_nothing(self) -> None:
        text = NET.replace(
            'resource "aws_internet_gateway" "igw" { vpc_id = aws_vpc.main.id }',
            'resource "aws_internet_gateway" "igw" {\n  vpc_id = aws_vpc.main.id\n'
            "  tags = { x = var.unset }\n}",
        )
        self.assertNotEqual(text, NET)
        report = impact_between(text, text)
        self.assertEqual(report.affected_invariants, ())
        self.assertEqual(report.changed_resources, ())

    def test_the_rule_can_only_add_uncertainty(self) -> None:
        # the same transition without the unknown value: a subset of the invariants
        plain = impact_between(NET, NET)
        loose = impact_between(LOOSE, LOOSE)
        self.assertTrue(impacted_ids(plain) <= impacted_ids(loose))

    def test_an_unresolved_change_in_the_footprint_is_affected_not_merely_uncertain(self) -> None:
        # the unresolved rule is also modified: AFFECTED wins the merge
        new = LOOSE.replace("from_port = 0", "from_port = 1")
        report = impact_between(LOOSE, new)
        for item in report.affected_invariants:
            self.assertIs(item.status, ImpactStatus.AFFECTED)


# --- merging ------------------------------------------------------------------------------------


class TestMerging(unittest.TestCase):
    def test_several_changes_keep_all_their_reasons_without_duplicates(self) -> None:
        new = changed_net('description = "d"', 'description = "e"').replace(
            'ami = "a"\n  subnet_id = aws_subnet.app.id',
            'ami = "b"\n  subnet_id = aws_subnet.app.id',
        )
        report = impact_between(NET, new)
        func = impacted(report)[FUNC]
        self.assertEqual(func.changed_resource_refs, ("aws_instance.app", "aws_security_group.app"))
        self.assertEqual(len(func.reasons), 2)
        self.assertEqual(len({r.sort_key() for r in func.reasons}), 2)
        self.assertEqual(len(func.dependency_paths), 2)
        self.assertEqual(
            {c for c in codes_of(func)},
            {ReasonCode.FOOTPRINT_MEMBER_CHANGED, ReasonCode.SCOPE_RESOURCE_CHANGED},
        )
        self.assertEqual(func.impact_types, (ImpactType.DEPENDENCY, ImpactType.DIRECT))

    def test_there_is_one_record_per_invariant(self) -> None:
        report = impact_between(NET, changed_net('description = "d"', 'description = "e"'))
        keys = [item.key() for item in report.affected_invariants]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(
            {item.key() for item in report.affected_invariants}.isdisjoint(
                {u.key() for u in report.unaffected}
            )
        )

    def test_an_invariant_with_two_paths_to_one_change_keeps_one_canonical_path(self) -> None:
        # the vpc is two hops from S (through the subnet) and from D (through its group)
        report = impact_between(
            NET,
            changed_net(
                'cidr_block = "10.0.0.0/16" }\nresource "aws_vpc" "elsewhere"',
                'cidr_block = "10.1.0.0/16" }\nresource "aws_vpc" "elsewhere"',
            ),
        )
        self.assertEqual(len(impacted(report)[FUNC].dependency_paths), 1)


# --- a cycle ------------------------------------------------------------------------------------


class TestCycle(unittest.TestCase):
    def test_a_reference_cycle_terminates(self) -> None:
        view = {"forms": {}, "inline_rules": [], "inline_indeterminate": []}

        def group(name: str, other: str, extra: str = "") -> object:
            address = f"aws_security_group.{name}"
            return hand_resource(
                address,
                attributes={"vpc_id": {"form": "ATTRIBUTE", "value": extra or name}},
                security_attributes=view,
                references=[hand_ref(address, f"aws_security_group.{other}", "vpc_id")],
            )

        before = (group("a", "b"), group("b", "a"))
        after = (group("a", "b"), group("b", "a", extra="changed"))
        definitions = registry()
        func = definitions["INV-FUNC-001"]
        cyclic = dataclasses.replace(
            func,
            scope=dataclasses.replace(
                func.scope,
                resources=("aws_security_group.a", "aws_security_group.b"),
                relationships=("REFERENCE[aws_security_group.vpc_id]:FORWARD",),
            ),
        )
        report = impact_of_outcomes(
            before,  # type: ignore[arg-type]
            after,  # type: ignore[arg-type]
            [],
            invariants=[cyclic],
            bound=False,
        )
        self.assertEqual(impacted_ids(report), {FUNC})


# --- input checks -------------------------------------------------------------------------------


class Pieces:
    """The parts of one impact run, so a test can break exactly one of them."""

    def __init__(self) -> None:
        self.before = normalize(NET)
        self.after = normalize(changed_net('description = "d"', 'description = "e"'))
        self.definitions = list(registry().values())
        self.identity = compare(
            self.before.resources,
            self.after.resources,
            self.after.moves,
            parent_state_id=PIPE_PARENT,
            candidate_id=PIPE_CANDIDATE,
            now=NOW,
        )
        self.trusted_graph = graph_of(self.before.resources, invariants=self.definitions)
        self.candidate_graph = graph_of(self.after.resources, invariants=self.definitions)

    def run(self, **overrides: object) -> ImpactReport:
        arguments: dict[str, object] = {
            "trusted": self.before.resources,
            "candidate": self.after.resources,
            "identity": self.identity,
            "trusted_graph": self.trusted_graph,
            "candidate_graph": self.candidate_graph,
            "invariants": self.definitions,
            "prior": (),
            "parent_state_id": PIPE_PARENT,
            "candidate_id": PIPE_CANDIDATE,
            "now": NOW,
        }
        arguments.update(overrides)
        return compute_impact(**arguments)  # type: ignore[arg-type]


class TestInputChecks(unittest.TestCase):
    def setUp(self) -> None:
        self.pieces = Pieces()

    def test_the_unbroken_run_works(self) -> None:
        self.assertEqual(impacted_ids(self.pieces.run()), SEC | {FUNC})

    def test_an_identity_report_of_another_candidate_or_parent_is_refused(self) -> None:
        other = "33333333-3333-4333-8333-333333333333"
        with self.assertRaises(ImpactInputError):
            self.pieces.run(candidate_id=other)
        with self.assertRaises(ImpactInputError):
            self.pieces.run(parent_state_id=other)

    def test_a_graph_that_lacks_a_resource_is_refused(self) -> None:
        trusted = self.pieces.before.resources
        short = graph_of(trusted[1:], invariants=self.pieces.definitions)
        with self.assertRaises(ImpactInputError):
            self.pieces.run(trusted_graph=short)

    def test_a_graph_of_a_state_with_other_addresses_is_refused(self) -> None:
        bigger = normalize(NET + 'resource "aws_subnet" "new" {\n  cidr_block = "10.0.7.0/24"\n}\n')
        other = graph_of(bigger.resources, invariants=self.pieces.definitions)
        with self.assertRaises(ImpactInputError):
            self.pieces.run(candidate_graph=other)

    def test_an_invariant_without_a_node_in_a_graph_is_refused(self) -> None:
        without_func = [d for d in self.pieces.definitions if d.invariant_id != FUNC]
        thin = graph_of(self.pieces.after.resources, invariants=without_func, bound=False)
        with self.assertRaises(ImpactInputError):
            self.pieces.run(candidate_graph=thin)

    def test_duplicate_invariants_are_refused(self) -> None:
        with self.assertRaises(ImpactInputError):
            self.pieces.run(invariants=[*self.pieces.definitions, self.pieces.definitions[0]])

    def test_duplicate_or_foreign_prior_proofs_are_refused(self) -> None:
        proof = PriorProof("INV-SEC-001", 1, ("e",), "dail.verify.public_ingress", "1")
        with self.assertRaises(ImpactInputError):
            self.pieces.run(prior=[proof, proof])
        with self.assertRaises(ImpactInputError):
            self.pieces.run(prior=[PriorProof("INV-NOPE-001", 1, ("e",), "v", "1")])
        with self.assertRaises(ImpactInputError):
            self.pieces.run(prior=["not a proof"])

    def test_an_identity_report_that_leaves_a_resource_out_is_refused(self) -> None:
        with self.assertRaises(ImpactInputError):
            self.pieces.run(candidate=self.pieces.after.resources[:-1])

    def test_duplicate_addresses_are_refused(self) -> None:
        resources = self.pieces.before.resources
        with self.assertRaises(ImpactInputError):
            self.pieces.run(trusted=(*resources, resources[0]))

    def test_non_resources_and_a_non_identity_report_are_refused(self) -> None:
        with self.assertRaises(ImpactInputError):
            self.pieces.run(trusted=["aws_vpc.main"])
        with self.assertRaises(ImpactInputError):
            self.pieces.run(identity="report")

    def test_resources_of_another_normalization_version_are_refused(self) -> None:
        resource = self.pieces.after.resources[0]
        odd = dataclasses.replace(
            resource,
            provenance=dataclasses.replace(resource.provenance, normalization_version="other"),
        )
        with self.assertRaises(ImpactInputError):
            self.pieces.run(candidate=(odd, *self.pieces.after.resources[1:]))

    def test_proof_evidence_must_not_be_empty(self) -> None:
        with self.assertRaises(ImpactInputError):
            PriorProof("INV-SEC-001", 1, (), "v", "1")
        with self.assertRaises(ImpactInputError):
            PriorProof("", 1, ("e",), "v", "1")
        with self.assertRaises(ImpactInputError):
            PriorProof("INV-SEC-001", 0, ("e",), "v", "1")


if __name__ == "__main__":
    unittest.main()
