"""The identity engine (Doc 07 §5-§13, §30, §34, §36; Doc 12 §9; C-121 to C-126; P3b step 4).

Expected values come from the Doc 07 / Doc 12 text, the C-90 and C-125/C-126 rules and Terraform's
documented behaviour in C-76, not from the output of the engine. Configurations are written as
HCL and go through the real pipeline (parse, evaluate, normalize); the engine itself never imports
``core.terraform_model``.
"""

from __future__ import annotations

import inspect
import random
import unittest
from collections.abc import Sequence
from dataclasses import replace

from core.domain.enums import ChangeType, IdentityStatus, ResourceSupport
from core.domain.identity import (
    EvidenceType,
    IdentityConfidence,
    IdentityReport,
)
from core.domain.resource import Resource
from core.identity.engine import IdentityInputError, compare
from core.identity.findings import (
    REPLACE_TRIGGER_FIELDS,
    Evidencer,
    ambiguous_blocks,
    replace_trigger_verdict,
)
from core.identity.strategy import IDENTITY_ALGORITHM_VERSION
from tests.identity_builders import (
    CANDIDATE,
    NOW,
    PARENT,
    change_of,
    changes,
    compare_texts,
    evidence_types,
    make_resource,
    normalize,
    resources_of,
)

LF = chr(10)
VAR_N = 'variable "n" {}'


def block(header: str, *lines: str) -> str:
    return header + " {" + LF + "".join(f"  {line}" + LF for line in lines) + "}"


def tf(*blocks: str) -> str:
    return LF.join(blocks) + LF


def vpc(label: str = "v", *args: str, cidr: str = "10.0.0.0/16") -> str:
    return block(f'resource "aws_vpc" "{label}"', *args, f'cidr_block = "{cidr}"')


def sg(label: str = "g", *args: str, name: str | None = '"g"') -> str:
    named = [] if name is None else [f"name = {name}"]
    return block(f'resource "aws_security_group" "{label}"', *named, *args)


def moved(source: str, target: str) -> str:
    return block("moved", f"from = {source}", f"to = {target}")


def rule(cidrs: str = '["10.0.0.0/8"]', port: int = 22) -> str:
    return block(
        "ingress",
        f"from_port = {port}",
        f"to_port = {port}",
        'protocol = "tcp"',
        f"cidr_blocks = {cidrs}",
    )


def match_of(report: IdentityReport, address: str):  # type: ignore[no-untyped-def]
    found = [
        m
        for m in report.resource_matches
        if address in (m.trusted_resource_ref, m.candidate_resource_ref)
    ]
    assert len(found) == 1, (address, [m.key for m in found])
    return found[0]


def compare_resources(
    trusted: Sequence[Resource],
    candidate: Sequence[Resource],
    moves: Sequence[tuple[str, str]] = (),
    **kwargs: object,
) -> IdentityReport:
    return compare(
        trusted,
        candidate,
        moves,
        parent_state_id=PARENT,
        candidate_id=CANDIDATE,
        now=NOW,
        **kwargs,  # type: ignore[arg-type]
    )


class PartitionMixin(unittest.TestCase):
    def assert_partition(
        self, trusted: Sequence[Resource], candidate: Sequence[Resource], report: IdentityReport
    ) -> None:
        """Every input resource is in exactly one match (C-124 rule 11)."""
        seen_t = sorted(
            m.trusted_resource_ref for m in report.resource_matches if m.trusted_resource_ref
        )
        seen_c = sorted(
            m.candidate_resource_ref for m in report.resource_matches if m.candidate_resource_ref
        )
        self.assertEqual(seen_t, sorted(r.address for r in trusted))
        self.assertEqual(seen_c, sorted(r.address for r in candidate))


class TestExactAddress(PartitionMixin):
    def test_same_address_and_type_with_equal_fingerprints_is_same_and_unchanged(self) -> None:
        """Doc 12 §9 row 1; Doc 07 §9, §10."""
        text = tf(vpc(), sg(), sg("h", name='"h"'))
        report = compare_texts(text, text)
        self.assertEqual(
            changes(report),
            {
                "aws_security_group.g->aws_security_group.g": "UNCHANGED",
                "aws_security_group.h->aws_security_group.h": "UNCHANGED",
                "aws_vpc.v->aws_vpc.v": "UNCHANGED",
            },
        )
        for m in report.resource_matches:
            self.assertEqual(m.identity_status, IdentityStatus.SAME)
            self.assertEqual(m.confidence, IdentityConfidence.HIGH)
            self.assertEqual(m.rule, EvidenceType.FINGERPRINT_EQUAL)
            kinds = {e.evidence_type for e in report.evidence_for(m)}
            self.assertEqual(kinds, {EvidenceType.EXACT_ADDRESS, EvidenceType.FINGERPRINT_EQUAL})

    def test_same_address_and_type_with_changed_semantics_is_same_and_modified(self) -> None:
        """Doc 12 §9 row 2; Doc 07 §9."""
        report = compare_texts(tf(vpc(cidr="10.0.0.0/16")), tf(vpc(cidr="10.1.0.0/16")))
        self.assertEqual(changes(report), {"aws_vpc.v->aws_vpc.v": "MODIFIED"})
        only = report.resource_matches[0]
        self.assertEqual(
            (only.identity_status, only.confidence), (IdentityStatus.SAME, IdentityConfidence.HIGH)
        )
        self.assertEqual(only.rule, EvidenceType.FINGERPRINT_DIFFERENT)
        proof = {e.evidence_type: e for e in report.evidence_for(only)}
        self.assertEqual(
            set(proof), {EvidenceType.EXACT_ADDRESS, EvidenceType.FINGERPRINT_DIFFERENT}
        )
        observed = proof[EvidenceType.FINGERPRINT_DIFFERENT].to_dict()["observed_value"]
        self.assertNotEqual(observed["trusted"], observed["candidate"])

    def test_a_trusted_resource_with_no_candidate_is_deleted(self) -> None:
        """Doc 12 §9 row 5; Doc 07 §9, §34."""
        report = compare_texts(tf(vpc(), vpc("w")), tf(vpc()))
        self.assertEqual(change_of(report, "aws_vpc.w"), "DELETED")
        deleted = match_of(report, "aws_vpc.w")
        self.assertEqual(deleted.identity_status, IdentityStatus.DIFFERENT)
        self.assertIsNone(deleted.confidence)
        self.assertIsNone(deleted.candidate_resource_ref)
        self.assertEqual(deleted.rule, EvidenceType.NO_COUNTERPART)

    def test_a_candidate_resource_with_no_trusted_counterpart_is_created(self) -> None:
        """Doc 12 §9 row 6; Doc 07 §9."""
        report = compare_texts(tf(vpc()), tf(vpc(), vpc("w")))
        self.assertEqual(change_of(report, "aws_vpc.w"), "CREATED")
        created = match_of(report, "aws_vpc.w")
        self.assertEqual(created.identity_status, IdentityStatus.DIFFERENT)
        self.assertIsNone(created.confidence)
        self.assertIsNone(created.trusted_resource_ref)

    def test_a_renamed_resource_without_a_moved_block_is_deleted_and_created(self) -> None:
        """Doc 07 §34: same content, different address, no evidence of identity."""
        report = compare_texts(tf(vpc("old")), tf(vpc("new")))
        self.assertEqual(
            changes(report), {"aws_vpc.old->-": "DELETED", "-->aws_vpc.new": "CREATED"}
        )

    def test_the_same_name_at_a_different_address_is_never_paired(self) -> None:
        """Doc 07 §34 'Same name, different address: not automatically SAME'. The two groups have
        the same name and the same content, so their fingerprints are equal, and still they are
        not paired."""
        trusted = tf(sg("a", name='"shared"'))
        candidate = tf(sg("b", name='"shared"'))
        before, after = resources_of(trusted)[0], resources_of(candidate)[0]
        self.assertEqual(before.fingerprint, after.fingerprint)
        self.assertEqual(
            changes(compare_texts(trusted, candidate)),
            {
                "aws_security_group.a->-": "DELETED",
                "-->aws_security_group.b": "CREATED",
            },
        )

    def test_swapped_names_between_two_addresses_stay_with_the_addresses(self) -> None:
        trusted = tf(sg("a", name='"one"'), sg("b", name='"two"'))
        candidate = tf(sg("a", name='"two"'), sg("b", name='"one"'))
        report = compare_texts(trusted, candidate)
        self.assertEqual(change_of(report, "aws_security_group.a"), "REPLACED")
        self.assertEqual(change_of(report, "aws_security_group.b"), "REPLACED")

    def test_security_rule_and_cidr_order_alone_do_not_change_anything(self) -> None:
        """Doc 07 §34 'Security-rule ordering changes only: UNCHANGED after canonicalization'."""
        first = tf(
            sg("g", rule('["10.0.0.0/8", "192.168.0.0/16"]', 22), rule('["172.16.0.0/12"]', 443)),
        )
        second = tf(
            sg("g", rule('["172.16.0.0/12"]', 443), rule('["192.168.0.0/16", "10.0.0.0/8"]', 22)),
        )
        self.assertEqual(
            changes(compare_texts(first, second)),
            {"aws_security_group.g->aws_security_group.g": "UNCHANGED"},
        )

    def test_a_cidr_change_in_a_rule_is_a_modification(self) -> None:
        first = tf(sg("g", rule('["0.0.0.0/0"]', 22)))
        second = tf(sg("g", rule('["10.0.0.0/8"]', 22)))
        self.assertEqual(
            changes(compare_texts(first, second)),
            {"aws_security_group.g->aws_security_group.g": "MODIFIED"},
        )

    def test_empty_sides(self) -> None:
        self.assertEqual(changes(compare_texts(tf(vpc()), "")), {"aws_vpc.v->-": "DELETED"})
        self.assertEqual(changes(compare_texts("", tf(vpc()))), {"-->aws_vpc.v": "CREATED"})
        self.assertEqual(compare_texts("", "").resource_matches, ())

    def test_the_doc_12_matrix_in_one_comparison(self) -> None:
        trusted = tf(
            vpc("same"),
            vpc("edit", cidr="10.0.0.0/16"),
            sg("swap", name='"x"'),
            vpc("gone"),
            vpc("amb"),
        )
        candidate = tf(
            vpc("same"),
            vpc("edit", cidr="10.9.0.0/16"),
            sg("swap", name='"y"'),
            vpc("made"),
            vpc("amb", 'for_each = toset(["a", "b"])'),
        )
        report = compare_texts(trusted, candidate)
        by = {m.key: m for m in report.resource_matches}
        expected = {
            "aws_vpc.same->aws_vpc.same": (IdentityStatus.SAME, ChangeType.UNCHANGED),
            "aws_vpc.edit->aws_vpc.edit": (IdentityStatus.SAME, ChangeType.MODIFIED),
            "aws_security_group.swap->aws_security_group.swap": (
                IdentityStatus.SAME,
                ChangeType.REPLACED,
            ),
            "aws_vpc.gone->-": (IdentityStatus.DIFFERENT, ChangeType.DELETED),
            "-->aws_vpc.made": (IdentityStatus.DIFFERENT, ChangeType.CREATED),
            "aws_vpc.amb->-": (IdentityStatus.UNCERTAIN, ChangeType.UNCERTAIN),
            '-->aws_vpc.amb["a"]': (IdentityStatus.UNCERTAIN, ChangeType.UNCERTAIN),
            '-->aws_vpc.amb["b"]': (IdentityStatus.UNCERTAIN, ChangeType.UNCERTAIN),
        }
        self.assertEqual({k: (m.identity_status, m.change_type) for k, m in by.items()}, expected)


class TestReplacement(PartitionMixin):
    """RT-1 (C-90, C-126): aws_security_group.name is the only controlled field."""

    def test_the_controlled_list_is_exactly_the_v1_list(self) -> None:
        self.assertEqual(dict(REPLACE_TRIGGER_FIELDS), {"aws_security_group": ("name",)})

    def test_a_known_name_change_is_replacement(self) -> None:
        report = compare_texts(tf(sg(name='"db"')), tf(sg(name='"db-v2"')))
        m = match_of(report, "aws_security_group.g")
        self.assertEqual(
            (m.identity_status, m.change_type, m.confidence),
            (IdentityStatus.SAME, ChangeType.REPLACED, IdentityConfidence.HIGH),
        )
        self.assertEqual(m.rule, EvidenceType.REPLACE_TRIGGER_FIELD)
        proof = next(
            e
            for e in report.evidence_for(m)
            if e.evidence_type is EvidenceType.REPLACE_TRIGGER_FIELD
        )
        observed = proof.to_dict()["observed_value"]
        self.assertEqual(observed["field"], "name")
        self.assertEqual((observed["trusted"], observed["candidate"]), ("db", "db-v2"))

    def test_an_unknown_name_on_a_side_is_uncertain_not_replaced(self) -> None:
        """Doc 07 §12 'rather than inventing REPLACED'."""
        known, unknown = tf(sg(name='"x"')), tf(VAR_N, sg(name="var.n"))
        for before, after in ((known, unknown), (unknown, known)):
            report = compare_texts(before, after)
            m = match_of(report, "aws_security_group.g")
            self.assertEqual(m.change_type, ChangeType.UNCERTAIN)
            self.assertEqual(m.identity_status, IdentityStatus.UNCERTAIN)
            self.assertEqual(m.confidence, IdentityConfidence.LOW)
            self.assertEqual(m.rule, EvidenceType.REPLACE_TRIGGER_UNRESOLVED)

    def test_a_name_set_on_one_side_only_is_uncertain(self) -> None:
        """The provider computes a name when none is set (C-126): absent against a value cannot be
        judged. An explicit null is absent (C-120)."""
        for unset in (tf(sg(name=None)), tf(sg(name="null"))):
            for before, after in ((unset, tf(sg(name='"x"'))), (tf(sg(name='"x"')), unset)):
                report = compare_texts(before, after)
                m = match_of(report, "aws_security_group.g")
                self.assertEqual(m.change_type, ChangeType.UNCERTAIN)
                self.assertEqual(m.rule, EvidenceType.REPLACE_TRIGGER_UNRESOLVED)

    def test_a_name_absent_on_both_sides_gives_no_replacement_evidence(self) -> None:
        first = tf(sg("g", 'description = "a"', name=None))
        second = tf(sg("g", 'description = "b"', name="null"))
        report = compare_texts(first, second)
        m = match_of(report, "aws_security_group.g")
        self.assertEqual(m.change_type, ChangeType.MODIFIED)
        self.assertFalse(
            {EvidenceType.REPLACE_TRIGGER_FIELD, EvidenceType.REPLACE_TRIGGER_UNRESOLVED}
            & {e.evidence_type for e in report.evidence_for(m)}
        )

    def test_the_same_unknown_name_on_both_sides_is_modified_and_flagged(self) -> None:
        first = tf(VAR_N, sg("g", 'description = "a"', name="var.n"))
        second = tf(VAR_N, sg("g", 'description = "b"', name="var.n"))
        report = compare_texts(first, second)
        m = match_of(report, "aws_security_group.g")
        self.assertEqual(m.change_type, ChangeType.MODIFIED)
        kinds = {e.evidence_type for e in report.evidence_for(m)}
        self.assertIn(EvidenceType.UNRESOLVED_CONTENT, kinds)
        self.assertNotIn(EvidenceType.REPLACE_TRIGGER_UNRESOLVED, kinds)

    def test_a_name_that_is_a_reference_is_unresolved_too(self) -> None:
        vpcs = tf(vpc("a"), vpc("b"))
        same = compare_texts(
            tf(vpcs, sg("g", 'description = "a"', name="aws_vpc.a.id")),
            tf(vpcs, sg("g", 'description = "b"', name="aws_vpc.a.id")),
        )
        self.assertEqual(change_of(same, "aws_security_group.g"), "MODIFIED")
        other = compare_texts(tf(vpcs, sg(name="aws_vpc.a.id")), tf(vpcs, sg(name="aws_vpc.b.id")))
        self.assertEqual(change_of(other, "aws_security_group.g"), "UNCERTAIN")

    def test_an_unchanged_name_with_another_change_is_modified(self) -> None:
        report = compare_texts(
            tf(sg("g", 'description = "a"', name='"db"')),
            tf(sg("g", 'description = "b"', name='"db"')),
        )
        m = match_of(report, "aws_security_group.g")
        self.assertEqual(m.change_type, ChangeType.MODIFIED)
        kinds = {e.evidence_type for e in report.evidence_for(m)}
        self.assertEqual(
            kinds & {EvidenceType.REPLACE_TRIGGER_FIELD, EvidenceType.REPLACE_TRIGGER_UNRESOLVED},
            set(),
        )

    def test_an_argument_outside_the_list_is_modified_even_if_terraform_would_replace(self) -> None:
        """Known limitation (C-126): the list has one field. name_prefix, vpc_id and the others are
        reported MODIFIED; whether the list grows is a register decision."""
        report = compare_texts(
            tf(vpc(), sg("g", 'name_prefix = "a-"', name=None)),
            tf(vpc(), sg("g", 'name_prefix = "b-"', name=None)),
        )
        self.assertEqual(change_of(report, "aws_security_group.g"), "MODIFIED")

    def test_replaced_is_never_concluded_for_an_unsupported_type(self) -> None:
        text = block('resource "aws_db_subnet_group" "d"', 'name = "%s"')
        report = compare_texts(tf(text % "a"), tf(text % "b"))
        m = match_of(report, "aws_db_subnet_group.d")
        self.assertEqual(m.change_type, ChangeType.MODIFIED)
        self.assertIn(
            EvidenceType.UNSUPPORTED_TYPE, {e.evidence_type for e in report.evidence_for(m)}
        )

    def test_an_unsupported_resource_of_a_listed_type_is_not_replaced(self) -> None:
        """Defence: an aws_security_group that is UNSUPPORTED (for example kept for its depth)."""
        first = make_resource(
            "aws_security_group.g",
            "aws_security_group",
            attributes={"name": {"form": "ATTRIBUTE", "value": "a"}},
            support=ResourceSupport.UNSUPPORTED,
        )
        second = make_resource(
            "aws_security_group.g",
            "aws_security_group",
            attributes={"name": {"form": "ATTRIBUTE", "value": "b"}},
            support=ResourceSupport.UNSUPPORTED,
        )
        report = compare_resources([first], [second])
        self.assertEqual(report.resource_matches[0].change_type, ChangeType.MODIFIED)

    def test_the_table_is_data_a_longer_list_needs_no_change_of_the_algorithm(self) -> None:
        before = resources_of(tf(vpc(cidr="10.0.0.0/16")))[0]
        after = resources_of(tf(vpc(cidr="10.1.0.0/16")))[0]
        evidencer = Evidencer(IDENTITY_ALGORITHM_VERSION)
        verdict, _ = replace_trigger_verdict(before, after, evidencer)
        self.assertIsNone(verdict)
        verdict, proof = replace_trigger_verdict(
            before, after, evidencer, {"aws_vpc": ("cidr_block",)}
        )
        self.assertIs(verdict, ChangeType.REPLACED)
        self.assertEqual(proof[0].evidence_type, EvidenceType.REPLACE_TRIGGER_FIELD)


class TestExplicitMoves(PartitionMixin):
    def test_a_resource_level_move_pairs_the_resources(self) -> None:
        report = compare_texts(tf(vpc("a")), tf(vpc("b"), moved("aws_vpc.a", "aws_vpc.b")))
        m = match_of(report, "aws_vpc.a")
        self.assertEqual(
            (m.trusted_resource_ref, m.candidate_resource_ref), ("aws_vpc.a", "aws_vpc.b")
        )
        self.assertEqual(
            (m.change_type, m.identity_status, m.confidence),
            (ChangeType.UNCHANGED, IdentityStatus.SAME, IdentityConfidence.HIGH),
        )
        kinds = {e.evidence_type for e in report.evidence_for(m)}
        self.assertIn(EvidenceType.EXPLICIT_MOVE, kinds)
        self.assertNotIn(EvidenceType.EXACT_ADDRESS, kinds)

    def test_a_moved_and_modified_resource_is_modified_not_hidden(self) -> None:
        report = compare_texts(
            tf(vpc("a", cidr="10.0.0.0/16")),
            tf(vpc("b", cidr="10.1.0.0/16"), moved("aws_vpc.a", "aws_vpc.b")),
        )
        self.assertEqual(changes(report), {"aws_vpc.a->aws_vpc.b": "MODIFIED"})

    def test_a_resource_level_move_carries_every_instance_with_its_key(self) -> None:
        each = 'for_each = toset(["x", "y"])'
        report = compare_texts(
            tf(vpc("a", each)), tf(vpc("b", each), moved("aws_vpc.a", "aws_vpc.b"))
        )
        self.assertEqual(
            changes(report),
            {
                'aws_vpc.a["x"]->aws_vpc.b["x"]': "UNCHANGED",
                'aws_vpc.a["y"]->aws_vpc.b["y"]': "UNCHANGED",
            },
        )

    def test_an_instance_level_move_pairs_exactly_that_instance(self) -> None:
        """The pair is MODIFIED, not UNCHANGED: the instance key is part of logical_identity
        (C-113), so a move that changes the key changes the fingerprint (Doc 07 §9: different
        fingerprint with correspondence is MODIFIED). The instance that is not moved is unchanged.
        """
        trusted = tf(vpc("v", 'for_each = toset(["x", "y"])'))
        candidate = tf(
            vpc("v", 'for_each = toset(["z", "y"])'), moved('aws_vpc.v["x"]', 'aws_vpc.v["z"]')
        )
        before = {r.address: r for r in resources_of(trusted)}['aws_vpc.v["x"]']
        after = {r.address: r for r in resources_of(candidate)}['aws_vpc.v["z"]']
        self.assertEqual(before.attributes, after.attributes)
        self.assertNotEqual(before.logical_identity, after.logical_identity)
        report = compare_texts(trusted, candidate)
        self.assertEqual(
            changes(report),
            {
                'aws_vpc.v["x"]->aws_vpc.v["z"]': "MODIFIED",
                'aws_vpc.v["y"]->aws_vpc.v["y"]': "UNCHANGED",
            },
        )
        pair = match_of(report, 'aws_vpc.v["x"]')
        self.assertEqual(
            (pair.trusted_resource_ref, pair.candidate_resource_ref),
            ('aws_vpc.v["x"]', 'aws_vpc.v["z"]'),
        )
        self.assertIn(
            EvidenceType.EXPLICIT_MOVE, {e.evidence_type for e in report.evidence_for(pair)}
        )

    def test_chained_moves_reach_the_final_address(self) -> None:
        report = compare_texts(
            tf(vpc("a")),
            tf(vpc("c"), moved("aws_vpc.a", "aws_vpc.b"), moved("aws_vpc.b", "aws_vpc.c")),
        )
        self.assertEqual(changes(report), {"aws_vpc.a->aws_vpc.c": "UNCHANGED"})
        m = report.resource_matches[0]
        move = next(
            e for e in report.evidence_for(m) if e.evidence_type is EvidenceType.EXPLICIT_MOVE
        )
        self.assertEqual(
            move.to_dict()["observed_value"]["statements"],
            [["aws_vpc.a", "aws_vpc.b"], ["aws_vpc.b", "aws_vpc.c"]],
        )

    def test_the_trusted_configurations_own_moved_blocks_are_not_an_input(self) -> None:
        """C-121: they describe how the trusted state itself was reached. compare() has no
        parameter for them, and a stale block in the trusted text changes nothing."""
        self.assertEqual(
            list(inspect.signature(compare).parameters),
            [
                "trusted",
                "candidate",
                "candidate_moves",
                "parent_state_id",
                "candidate_id",
                "now",
                "strategy",
            ],
        )
        stale = tf(vpc("v"), moved("aws_vpc.old", "aws_vpc.v"))
        trusted = normalize(stale)
        self.assertEqual(trusted.moves, (("aws_vpc.old", "aws_vpc.v"),))
        report = compare_resources(trusted.resources, resources_of(tf(vpc("v"))), [])
        self.assertEqual(changes(report), {"aws_vpc.v->aws_vpc.v": "UNCHANGED"})
        plain = compare_texts(tf(vpc("v")), tf(vpc("v")))
        self.assertEqual(report.content_hash, plain.content_hash)

    def test_a_candidate_move_whose_source_has_no_trusted_object_changes_nothing(self) -> None:
        """History (C-123): the object was moved in an earlier run."""
        text = tf(vpc("b"))
        report = compare_texts(text, tf(text, moved("aws_vpc.a", "aws_vpc.b")))
        self.assertEqual(changes(report), {"aws_vpc.b->aws_vpc.b": "UNCHANGED"})

    def test_a_move_into_an_occupied_address_is_a_conflict(self) -> None:
        """C-123: Terraform skips the move and the existing object keeps the address
        (move_execute.go L157-L164). DAIL keeps every involved match UNCERTAIN."""
        report = compare_texts(
            tf(vpc("a"), vpc("b", cidr="10.1.0.0/16")),
            tf(vpc("b", cidr="10.1.0.0/16"), moved("aws_vpc.a", "aws_vpc.b")),
        )
        self.assertEqual(
            changes(report),
            {"aws_vpc.a->-": "UNCERTAIN", "aws_vpc.b->aws_vpc.b": "UNCERTAIN"},
        )
        for address in ("aws_vpc.a", "aws_vpc.b"):
            m = match_of(report, address)
            self.assertEqual(m.rule, EvidenceType.CONFLICTING_MOVE)
            self.assertEqual(m.confidence, IdentityConfidence.LOW)
        move = next(e for e in report.evidence if e.evidence_type is EvidenceType.CONFLICTING_MOVE)
        self.assertEqual(move.to_dict()["observed_value"]["statement"], ["aws_vpc.a", "aws_vpc.b"])

    def test_two_objects_reaching_one_candidate_address_are_all_uncertain(self) -> None:
        trusted = resources_of(tf(vpc("a", "count = 1"), vpc("c", "count = 1")))
        candidate = resources_of(tf(vpc("b", "count = 1")))
        report = compare_resources(
            trusted,
            candidate,
            [("aws_vpc.a", "aws_vpc.b"), ("aws_vpc.c[0]", "aws_vpc.b[0]")],
        )
        self.assertEqual(
            {m.key: m.change_type.value for m in report.resource_matches},
            {
                "aws_vpc.a[0]->aws_vpc.b[0]": "UNCERTAIN",
                "aws_vpc.c[0]->-": "UNCERTAIN",
            },
        )

    def test_a_move_to_an_address_the_candidate_does_not_have_is_a_deletion_with_evidence(
        self,
    ) -> None:
        """C-123: the object is moved and then has no configuration (move_statement.go L72-L76:
        'the user will see the unexpected deletion in the plan')."""
        report = compare_texts(tf(vpc("a")), tf(moved("aws_vpc.a", "aws_vpc.b")))
        m = match_of(report, "aws_vpc.a")
        self.assertEqual(m.change_type, ChangeType.DELETED)
        self.assertEqual(m.rule, EvidenceType.EXPLICIT_MOVE)
        move = next(
            e for e in report.evidence_for(m) if e.evidence_type is EvidenceType.EXPLICIT_MOVE
        )
        observed = move.to_dict()["observed_value"]
        self.assertEqual(
            (observed["from"], observed["to"], observed["target_in_candidate"]),
            ("aws_vpc.a", "aws_vpc.b", False),
        )

    def test_a_moved_object_is_not_part_of_an_ambiguity_at_its_target(self) -> None:
        """C-125: the statement says where the object went. It goes to aws_vpc.b, which the
        candidate does not have as a no-key instance: the object is deleted there, and the
        for_each instances next to it are created. Nothing is chosen between them."""
        trusted = resources_of(tf(vpc("a")))
        candidate = resources_of(tf(vpc("b", 'for_each = toset(["x", "y"])')))
        report = compare_resources(trusted, candidate, [("aws_vpc.a", "aws_vpc.b")])
        self.assertEqual(
            changes(report),
            {
                "aws_vpc.a->-": "DELETED",
                '-->aws_vpc.b["x"]': "CREATED",
                '-->aws_vpc.b["y"]': "CREATED",
            },
        )
        self.assertEqual(match_of(report, "aws_vpc.a").rule, EvidenceType.EXPLICIT_MOVE)

    def test_a_moved_instance_inside_its_block_is_not_part_of_an_ambiguity(self) -> None:
        """The same, inside one block: v["x"] is moved to v["w"], which the candidate does not
        have, next to the unrelated v["a"] and v["b"]. The statement settles where v["x"] went."""
        trusted = resources_of(tf(vpc("v", 'for_each = toset(["x"])')))
        candidate = resources_of(tf(vpc("v", 'for_each = toset(["a", "b"])')))
        report = compare_resources(trusted, candidate, [('aws_vpc.v["x"]', 'aws_vpc.v["w"]')])
        self.assertEqual(
            changes(report),
            {
                'aws_vpc.v["x"]->-': "DELETED",
                '-->aws_vpc.v["a"]': "CREATED",
                '-->aws_vpc.v["b"]': "CREATED",
            },
        )

    def test_a_move_onto_a_block_with_an_unknown_number_of_instances_is_uncertain(self) -> None:
        report = compare_texts(
            tf(vpc("a")),
            tf(VAR_N, vpc("b", "count = var.n"), moved("aws_vpc.a", "aws_vpc.b")),
        )
        m = match_of(report, "aws_vpc.a")
        self.assertEqual(m.change_type, ChangeType.UNCERTAIN)
        self.assertEqual(m.rule, EvidenceType.INDETERMINATE_BLOCK)

    def test_an_instance_move_out_of_an_indeterminate_trusted_block_does_not_create(self) -> None:
        """The source instance may or may not exist, so the target cannot be called CREATED."""
        trusted = resources_of(tf(VAR_N, vpc("a", "count = var.n")))
        candidate = resources_of(tf(vpc("b", "count = 1")))
        report = compare_resources(trusted, candidate, [("aws_vpc.a[0]", "aws_vpc.b[0]")])
        self.assertEqual(change_of(report, "aws_vpc.b[0]"), "UNCERTAIN")
        self.assertEqual(change_of(report, "aws_vpc.a"), "UNCERTAIN")

    def test_the_order_of_the_moves_does_not_matter(self) -> None:
        trusted = resources_of(tf(vpc("a"), vpc("x")))
        candidate = resources_of(tf(vpc("c"), vpc("y")))
        moves = [("aws_vpc.a", "aws_vpc.b"), ("aws_vpc.b", "aws_vpc.c"), ("aws_vpc.x", "aws_vpc.y")]
        reference = compare_resources(trusted, candidate, moves)
        for order in (moves[::-1], [moves[2], moves[0], moves[1]]):
            self.assertEqual(
                compare_resources(trusted, candidate, order).content_hash, reference.content_hash
            )

    def test_a_type_changing_move_is_a_conflict(self) -> None:
        """P3a-2 refuses these; the engine keeps the defence (C-124 rule 3)."""
        trusted = [make_resource("aws_vpc.a", "aws_vpc")]
        candidate = [make_resource("aws_subnet.b", "aws_subnet")]
        report = compare_resources(trusted, candidate, [("aws_vpc.a", "aws_subnet.b")])
        m = report.resource_matches[0]
        self.assertEqual(
            (m.trusted_resource_ref, m.candidate_resource_ref), ("aws_vpc.a", "aws_subnet.b")
        )
        self.assertEqual(m.change_type, ChangeType.UNCERTAIN)
        self.assertEqual(m.rule, EvidenceType.CONFLICTING_MOVE)

    def test_two_types_at_one_address_are_a_conflict(self) -> None:
        report = compare_resources(
            [make_resource("aws_vpc.a", "aws_vpc")], [make_resource("aws_vpc.a", "aws_subnet")]
        )
        self.assertEqual(report.resource_matches[0].change_type, ChangeType.UNCERTAIN)
        self.assertEqual(report.resource_matches[0].rule, EvidenceType.CONFLICTING_MOVE)

    def test_the_candidate_resource_a_blocked_move_aimed_at_is_uncertain_not_created(self) -> None:
        """a to b is skipped because b is occupied, then b to c carries the object at b on. The
        candidate's b is where a was meant to go: it is not a creation, it is part of the conflict.
        """
        trusted = resources_of(tf(vpc("a"), vpc("b")))
        candidate = resources_of(tf(vpc("b"), vpc("c")))
        report = compare_resources(
            trusted, candidate, [("aws_vpc.a", "aws_vpc.b"), ("aws_vpc.b", "aws_vpc.c")]
        )
        self.assertEqual(
            changes(report),
            {
                "aws_vpc.a->-": "UNCERTAIN",
                "aws_vpc.b->aws_vpc.c": "UNCERTAIN",
                "-->aws_vpc.b": "UNCERTAIN",
            },
        )
        for m in report.resource_matches:
            self.assertEqual(m.rule, EvidenceType.CONFLICTING_MOVE)

    def test_a_blocked_chain_leaves_everything_it_touched_uncertain(self) -> None:
        trusted = resources_of(tf(vpc("a"), vpc("c")))
        candidate = resources_of(tf(vpc("c")))
        report = compare_resources(
            trusted, candidate, [("aws_vpc.a", "aws_vpc.b"), ("aws_vpc.b", "aws_vpc.c")]
        )
        self.assertEqual({m.change_type for m in report.resource_matches}, {ChangeType.UNCERTAIN})
        self.assertEqual(len(report.resource_matches), 2)


class TestImplicitCountMoves(PartitionMixin):
    """C-76 (Terraform 1.15.8): count added or removed moves x to x[0] and x[0] to x."""

    def test_adding_count_pairs_the_no_key_instance_with_index_zero(self) -> None:
        report = compare_texts(tf(vpc()), tf(vpc("v", "count = 2")))
        self.assertEqual(
            changes(report),
            {"aws_vpc.v->aws_vpc.v[0]": "MODIFIED", "-->aws_vpc.v[1]": "CREATED"},
        )
        m = match_of(report, "aws_vpc.v[0]")
        kinds = {e.evidence_type for e in report.evidence_for(m)}
        self.assertIn(EvidenceType.IMPLICIT_COUNT_MOVE, kinds)
        self.assertEqual(
            (m.identity_status, m.confidence), (IdentityStatus.SAME, IdentityConfidence.HIGH)
        )

    def test_removing_count_pairs_index_zero_with_the_no_key_instance(self) -> None:
        report = compare_texts(tf(vpc("v", "count = 2")), tf(vpc()))
        self.assertEqual(
            changes(report),
            {"aws_vpc.v[0]->aws_vpc.v": "MODIFIED", "aws_vpc.v[1]->-": "DELETED"},
        )

    def test_index_one_and_above_never_move(self) -> None:
        report = compare_texts(tf(vpc("v", "count = 3")), tf(vpc()))
        self.assertEqual(change_of(report, "aws_vpc.v[1]"), "DELETED")
        self.assertEqual(change_of(report, "aws_vpc.v[2]"), "DELETED")

    def test_nothing_is_implicit_for_for_each(self) -> None:
        for before, after in (
            (tf(vpc("v", 'for_each = toset(["a"])')), tf(vpc())),
            (tf(vpc("v", "count = 1")), tf(vpc("v", 'for_each = toset(["0"])'))),
            (tf(vpc("v", 'for_each = toset(["0"])')), tf(vpc("v", "count = 1"))),
        ):
            report = compare_texts(before, after)
            self.assertEqual(
                sorted(m.change_type.value for m in report.resource_matches), ["CREATED", "DELETED"]
            )
            self.assertNotIn(
                EvidenceType.IMPLICIT_COUNT_MOVE, {e.evidence_type for e in report.evidence}
            )

    def test_an_explicit_statement_on_the_block_replaces_the_implicit_move(self) -> None:
        """move_statement.go L176-L182: with an explicit move the user may choose another key."""
        trusted = resources_of(tf(vpc()))
        candidate = resources_of(tf(vpc("v", "count = 2")))
        report = compare_resources(trusted, candidate, [("aws_vpc.v", "aws_vpc.v[1]")])
        self.assertEqual(
            changes(report),
            {"aws_vpc.v->aws_vpc.v[1]": "MODIFIED", "-->aws_vpc.v[0]": "CREATED"},
        )
        m = match_of(report, "aws_vpc.v[1]")
        kinds = {e.evidence_type for e in report.evidence_for(m)}
        self.assertIn(EvidenceType.EXPLICIT_MOVE, kinds)
        self.assertNotIn(EvidenceType.IMPLICIT_COUNT_MOVE, kinds)

    def test_an_unknown_count_in_the_candidate_is_not_an_implicit_move(self) -> None:
        report = compare_texts(tf(vpc()), tf(VAR_N, vpc("v", "count = var.n")))
        self.assertEqual(changes(report), {"aws_vpc.v->aws_vpc.v": "UNCERTAIN"})
        self.assertEqual(report.resource_matches[0].rule, EvidenceType.INDETERMINATE_BLOCK)


class TestAmbiguity(PartitionMixin):
    """AMB-1 (C-90, C-125)."""

    def test_one_trusted_instance_and_two_candidates_are_all_uncertain(self) -> None:
        report = compare_texts(tf(vpc("ops")), tf(vpc("ops", 'for_each = toset(["a", "b"])')))
        self.assertEqual(
            changes(report),
            {
                "aws_vpc.ops->-": "UNCERTAIN",
                '-->aws_vpc.ops["a"]': "UNCERTAIN",
                '-->aws_vpc.ops["b"]': "UNCERTAIN",
            },
        )
        for m in report.resource_matches:
            self.assertEqual(
                (m.identity_status, m.rule, m.confidence),
                (
                    IdentityStatus.UNCERTAIN,
                    EvidenceType.AMBIGUOUS_CANDIDATES,
                    IdentityConfidence.LOW,
                ),
            )

    def test_all_the_counterparts_are_preserved_as_evidence(self) -> None:
        """Doc 07 §11 'preserve all supporting evidence'."""
        report = compare_texts(tf(vpc("ops")), tf(vpc("ops", 'for_each = toset(["a", "b"])')))
        for m in report.resource_matches:
            (proof,) = (
                e
                for e in report.evidence_for(m)
                if e.evidence_type is EvidenceType.AMBIGUOUS_CANDIDATES
            )
            observed = proof.to_dict()["observed_value"]
            self.assertEqual(observed["trusted"], ["aws_vpc.ops"])
            self.assertEqual(observed["candidate"], ['aws_vpc.ops["a"]', 'aws_vpc.ops["b"]'])

    def test_the_symmetric_case_is_uncertain_too(self) -> None:
        """Doc 07 §11 'or vice versa' (the extension of C-125): two trusted, one candidate."""
        report = compare_texts(tf(vpc("ops", 'for_each = toset(["a", "b"])')), tf(vpc("ops")))
        self.assertEqual(
            changes(report),
            {
                'aws_vpc.ops["a"]->-': "UNCERTAIN",
                'aws_vpc.ops["b"]->-': "UNCERTAIN",
                "-->aws_vpc.ops": "UNCERTAIN",
            },
        )

    def test_one_to_one_replacement_is_a_deletion_and_a_creation(self) -> None:
        """C-76: Terraform plans a destroy and a create; the 1:1 case is not ambiguous."""
        report = compare_texts(
            tf(vpc("g", 'for_each = toset(["a"])')), tf(vpc("g", 'for_each = toset(["b"])'))
        )
        self.assertEqual(
            changes(report), {'aws_vpc.g["a"]->-': "DELETED", '-->aws_vpc.g["b"]': "CREATED"}
        )

    def test_count_growth_is_an_implicit_move_and_a_creation_not_an_ambiguity(self) -> None:
        report = compare_texts(tf(vpc()), tf(vpc("v", "count = 2")))
        self.assertNotIn("UNCERTAIN", changes(report).values())

    def test_for_each_keys_that_overlap_keep_the_common_key(self) -> None:
        report = compare_texts(
            tf(vpc("g", 'for_each = toset(["a", "b"])')),
            tf(vpc("g", 'for_each = toset(["a", "c"])')),
        )
        self.assertEqual(
            changes(report),
            {
                'aws_vpc.g["a"]->aws_vpc.g["a"]': "UNCHANGED",
                'aws_vpc.g["b"]->-': "DELETED",
                '-->aws_vpc.g["c"]': "CREATED",
            },
        )

    def test_a_moved_block_removes_the_ambiguity(self) -> None:
        """C-90 'and no moved block'. The move is given directly: P3a-2 reads a key-less from
        of a resource that still has for_each as 'still declared' and refuses it."""
        trusted = resources_of(tf(vpc("ops")))
        candidate = resources_of(tf(vpc("ops", 'for_each = toset(["a", "b"])')))
        report = compare_resources(trusted, candidate, [("aws_vpc.ops", 'aws_vpc.ops["a"]')])
        self.assertEqual(
            changes(report),
            {
                'aws_vpc.ops->aws_vpc.ops["a"]': "MODIFIED",
                '-->aws_vpc.ops["b"]': "CREATED",
            },
        )

    def test_the_result_does_not_depend_on_the_order_of_the_inputs(self) -> None:
        trusted = list(resources_of(tf(vpc("ops"), vpc("k"))))
        candidate = list(
            resources_of(tf(vpc("ops", 'for_each = toset(["a", "b", "c"])'), vpc("k")))
        )
        reference = compare_resources(trusted, candidate)
        rng = random.Random(20261028)
        for _ in range(20):
            shuffled = compare_resources(
                rng.sample(trusted, len(trusted)), rng.sample(candidate, len(candidate))
            )
            self.assertEqual(shuffled.content_hash, reference.content_hash)

    def test_blocks_of_different_names_are_not_mixed(self) -> None:
        report = compare_texts(
            tf(vpc("a"), vpc("b")), tf(vpc("a", 'for_each = toset(["x", "y"])'), vpc("c"))
        )
        self.assertEqual(change_of(report, "aws_vpc.b"), "DELETED")
        self.assertEqual(change_of(report, "aws_vpc.c"), "CREATED")
        self.assertEqual(change_of(report, "aws_vpc.a"), "UNCERTAIN")

    def test_module_paths_are_part_of_the_block(self) -> None:
        found = ambiguous_blocks(
            ["module.m.aws_vpc.v"],
            ['module.m.aws_vpc.v["a"]', 'module.m.aws_vpc.v["b"]', 'module.n.aws_vpc.v["a"]'],
        )
        self.assertEqual(list(found), ["module.m.aws_vpc.v"])
        self.assertEqual(
            found["module.m.aws_vpc.v"][1], ('module.m.aws_vpc.v["a"]', 'module.m.aws_vpc.v["b"]')
        )

    def test_ambiguous_blocks_needs_both_sides(self) -> None:
        self.assertEqual(ambiguous_blocks(["aws_vpc.v"], []), {})
        self.assertEqual(ambiguous_blocks([], ["aws_vpc.v[0]", "aws_vpc.v[1]"]), {})
        self.assertEqual(ambiguous_blocks(["aws_vpc.v[0]"], ["aws_vpc.v[1]"]), {})


class TestIndeterminateBlocks(PartitionMixin):
    """Missing knowledge is never proof of absence (Doc 07, core principle; C-124 rules 1 and 2)."""

    def test_a_placeholder_is_uncertain_even_when_both_sides_are_identical(self) -> None:
        text = tf(VAR_N, vpc("v", "count = var.n"))
        report = compare_texts(text, text)
        self.assertEqual(changes(report), {"aws_vpc.v->aws_vpc.v": "UNCERTAIN"})
        m = report.resource_matches[0]
        self.assertEqual(m.rule, EvidenceType.INDETERMINATE_BLOCK)
        self.assertEqual(m.identity_status, IdentityStatus.UNCERTAIN)

    def test_a_placeholder_on_one_side_only_is_uncertain_not_created_or_deleted(self) -> None:
        text = tf(VAR_N, vpc("v", "count = var.n"))
        self.assertEqual(changes(compare_texts("", text)), {"-->aws_vpc.v": "UNCERTAIN"})
        self.assertEqual(changes(compare_texts(text, "")), {"aws_vpc.v->-": "UNCERTAIN"})

    def test_instances_of_an_indeterminate_candidate_block_are_never_deleted(self) -> None:
        report = compare_texts(tf(vpc("v", "count = 2")), tf(VAR_N, vpc("v", "count = var.n")))
        self.assertEqual(
            changes(report),
            {
                "aws_vpc.v[0]->-": "UNCERTAIN",
                "aws_vpc.v[1]->-": "UNCERTAIN",
                "-->aws_vpc.v": "UNCERTAIN",
            },
        )

    def test_instances_of_an_indeterminate_trusted_block_are_never_created(self) -> None:
        report = compare_texts(tf(VAR_N, vpc("v", "count = var.n")), tf(vpc("v", "count = 2")))
        self.assertEqual(
            changes(report),
            {
                "aws_vpc.v->-": "UNCERTAIN",
                "-->aws_vpc.v[0]": "UNCERTAIN",
                "-->aws_vpc.v[1]": "UNCERTAIN",
            },
        )
        for m in report.resource_matches:
            self.assertEqual(m.rule, EvidenceType.INDETERMINATE_BLOCK)

    def test_other_blocks_next_to_a_placeholder_are_classified_normally(self) -> None:
        text = tf(VAR_N, vpc("v", "count = var.n"), vpc("w"))
        report = compare_texts(
            text, tf(VAR_N, vpc("v", "count = var.n"), vpc("w", cidr="10.2.0.0/16"))
        )
        self.assertEqual(change_of(report, "aws_vpc.w"), "MODIFIED")

    def test_a_placeholder_moves_with_its_block(self) -> None:
        report = compare_texts(
            tf(VAR_N, vpc("a", "count = var.n")),
            tf(VAR_N, vpc("b", "count = var.n"), moved("aws_vpc.a", "aws_vpc.b")),
        )
        self.assertEqual(changes(report), {"aws_vpc.a->aws_vpc.b": "UNCERTAIN"})


class TestUnsupportedTypes(PartitionMixin):
    """C-124 rule 8: classified on the syntactic fact, flagged for impact."""

    ACL = block('resource "aws_network_acl" "n"', 'vpc_id = "vpc-1"', 'tags = { Name = "%s" }')

    def test_an_unsupported_pair_with_equal_content_is_unchanged_and_flagged(self) -> None:
        report = compare_texts(tf(self.ACL % "a"), tf(self.ACL % "a"))
        m = match_of(report, "aws_network_acl.n")
        self.assertEqual(m.change_type, ChangeType.UNCHANGED)
        self.assertIn(
            EvidenceType.UNSUPPORTED_TYPE, {e.evidence_type for e in report.evidence_for(m)}
        )

    def test_an_unsupported_pair_with_different_content_is_modified_and_flagged(self) -> None:
        report = compare_texts(tf(self.ACL % "a"), tf(self.ACL % "b"))
        m = match_of(report, "aws_network_acl.n")
        self.assertEqual(m.change_type, ChangeType.MODIFIED)
        proof = next(
            e for e in report.evidence_for(m) if e.evidence_type is EvidenceType.UNSUPPORTED_TYPE
        )
        observed = proof.to_dict()["observed_value"]
        self.assertEqual(observed["trusted_support"], "UNSUPPORTED")
        self.assertEqual(observed["candidate_support"], "UNSUPPORTED")

    def test_created_and_deleted_unsupported_resources_are_flagged_too(self) -> None:
        report = compare_texts(tf(self.ACL % "a"), "")
        self.assertEqual(change_of(report, "aws_network_acl.n"), "DELETED")
        self.assertIn(EvidenceType.UNSUPPORTED_TYPE, evidence_types(report, "aws_network_acl.n"))
        report = compare_texts("", tf(self.ACL % "a"))
        self.assertEqual(change_of(report, "aws_network_acl.n"), "CREATED")
        self.assertIn(EvidenceType.UNSUPPORTED_TYPE, evidence_types(report, "aws_network_acl.n"))

    def test_supported_resources_carry_no_unsupported_flag(self) -> None:
        report = compare_texts(tf(vpc()), tf(vpc(cidr="10.9.0.0/16")))
        self.assertNotIn(EvidenceType.UNSUPPORTED_TYPE, {e.evidence_type for e in report.evidence})


class TestUnresolvedContent(PartitionMixin):
    """C-117 carried to P4: equal fingerprints do not prove an unresolved element unchanged."""

    def test_equal_fingerprints_with_an_unknown_value_are_flagged(self) -> None:
        text = tf(VAR_N, sg(name="var.n"))
        report = compare_texts(text, text)
        m = match_of(report, "aws_security_group.g")
        self.assertEqual(m.change_type, ChangeType.UNCHANGED)
        proof = next(
            e for e in report.evidence_for(m) if e.evidence_type is EvidenceType.UNRESOLVED_CONTENT
        )
        observed = proof.to_dict()["observed_value"]
        self.assertEqual(observed["trusted"][0]["path"], "attributes.name.value")
        self.assertEqual(observed["trusted"][0]["kind"], "unknown")
        self.assertEqual(observed["candidate"], observed["trusted"])

    def test_an_unresolved_direction_form_is_flagged(self) -> None:
        dynamic = block(
            'dynamic "ingress"',
            "for_each = var.ports",
            "content {",
            "  from_port = ingress.value",
            "  to_port = ingress.value",
            '  protocol = "tcp"',
            '  cidr_blocks = ["10.0.0.0/8"]',
            "}",
        )
        text = tf('variable "ports" {}', sg("g", dynamic))
        report = compare_texts(text, text)
        proof = next(
            e for e in report.evidence if e.evidence_type is EvidenceType.UNRESOLVED_CONTENT
        )
        paths = [entry["path"] for entry in proof.to_dict()["observed_value"]["trusted"]]
        self.assertIn("security_attributes.forms.ingress", paths)

    def test_an_unknown_or_unsupported_reference_is_flagged(self) -> None:
        subnet = block(
            'resource "aws_subnet" "s"', "vpc_id = aws_vpc.v[0].id", 'cidr_block = "10.0.1.0/24"'
        )
        text = tf(VAR_N, vpc("v", "count = var.n"), subnet)
        report = compare_texts(text, text)
        flagged = [e for e in report.evidence if e.evidence_type is EvidenceType.UNRESOLVED_CONTENT]
        self.assertEqual(len(flagged), 1)
        entries = flagged[0].to_dict()["observed_value"]["trusted"]
        self.assertIn(("reference", "references.vpc_id"), [(e["kind"], e["path"]) for e in entries])

    def test_resolved_pairs_carry_no_flag(self) -> None:
        text = tf(vpc(), sg("g", rule(), name='"x"'))
        report = compare_texts(text, text)
        self.assertNotIn(
            EvidenceType.UNRESOLVED_CONTENT, {e.evidence_type for e in report.evidence}
        )

    def test_created_and_deleted_resources_carry_no_flag(self) -> None:
        text = tf(VAR_N, sg(name="var.n"))
        for report in (compare_texts(text, ""), compare_texts("", text)):
            self.assertNotIn(
                EvidenceType.UNRESOLVED_CONTENT, {e.evidence_type for e in report.evidence}
            )

    def test_the_flag_does_not_change_the_change_type(self) -> None:
        first = tf(VAR_N, sg("g", 'description = "a"', name="var.n"))
        second = tf(VAR_N, sg("g", 'description = "b"', name="var.n"))
        self.assertEqual(
            change_of(compare_texts(first, second), "aws_security_group.g"), "MODIFIED"
        )


class TestInput(unittest.TestCase):
    def test_resources_of_different_normalization_versions_are_refused(self) -> None:
        one = make_resource("aws_vpc.a", "aws_vpc", version="dail-tf-norm-1")
        two = make_resource("aws_vpc.a", "aws_vpc", version="dail-tf-norm-2")
        with self.assertRaises(IdentityInputError) as caught:
            compare_resources([one], [two])
        self.assertIn("different versions", str(caught.exception))

    def test_a_mixed_version_on_one_side_is_refused_too(self) -> None:
        one = make_resource("aws_vpc.a", "aws_vpc", version="dail-tf-norm-1")
        two = make_resource("aws_vpc.b", "aws_vpc", version="dail-tf-norm-2")
        with self.assertRaises(IdentityInputError):
            compare_resources([one, two], [])

    def test_a_resource_with_no_normalization_version_is_refused(self) -> None:
        bare = make_resource("aws_vpc.a", "aws_vpc", version=None)
        with self.assertRaises(IdentityInputError) as caught:
            compare_resources([bare], [])
        self.assertIn("normalization_version", str(caught.exception))
        with self.assertRaises(IdentityInputError):
            compare_resources([], [bare])

    def test_duplicate_addresses_on_a_side_are_refused(self) -> None:
        a = make_resource("aws_vpc.a", "aws_vpc")
        with self.assertRaises(IdentityInputError) as caught:
            compare_resources([a, a], [])
        self.assertIn("not unique", str(caught.exception))
        with self.assertRaises(IdentityInputError):
            compare_resources([], [a, a])

    def test_the_same_address_on_both_sides_is_fine(self) -> None:
        a = make_resource("aws_vpc.a", "aws_vpc")
        self.assertEqual(
            compare_resources([a], [a]).resource_matches[0].change_type, ChangeType.UNCHANGED
        )

    def test_something_that_is_not_a_resource_is_refused(self) -> None:
        with self.assertRaises(IdentityInputError):
            compare_resources([object()], [])  # type: ignore[list-item]
        with self.assertRaises(IdentityInputError):
            compare_resources([], [{"address": "aws_vpc.a"}])  # type: ignore[list-item]

    def test_a_placeholder_with_an_instance_key_is_refused(self) -> None:
        bad = make_resource("aws_vpc.a[0]", "aws_vpc", support=ResourceSupport.UNKNOWN)
        with self.assertRaises(IdentityInputError):
            compare_resources([bad], [])

    def test_malformed_moves_are_refused(self) -> None:
        a = make_resource("aws_vpc.a", "aws_vpc")
        for moves in (
            [("aws_vpc.a",)],
            ["ab"],
            [("aws_vpc.a", "aws_vpc.a")],
            [("aws_vpc.a", "aws_vpc.b[")],
        ):
            with self.subTest(moves=moves), self.assertRaises(IdentityInputError):
                compare_resources([a], [a], moves)  # type: ignore[arg-type]

    def test_cyclic_ambiguous_moves_are_refused(self) -> None:
        a = make_resource("aws_vpc.a", "aws_vpc")
        for moves in (
            [("aws_vpc.a", "aws_vpc.b"), ("aws_vpc.b", "aws_vpc.a")],
            [("aws_vpc.a", "aws_vpc.b"), ("aws_vpc.a", "aws_vpc.c")],
        ):
            with self.subTest(moves=moves), self.assertRaises(IdentityInputError):
                compare_resources([a], [a], moves)

    def test_bad_ids_and_clock_are_refused(self) -> None:
        a = make_resource("aws_vpc.a", "aws_vpc")
        with self.assertRaises(ValueError):
            compare([a], [a], [], parent_state_id="x", candidate_id=CANDIDATE, now=NOW)

    def test_the_error_is_a_domain_validation_error(self) -> None:
        from core.domain.errors import DomainValidationError

        self.assertTrue(issubclass(IdentityInputError, DomainValidationError))

    def test_there_is_no_input_for_llm_suggestions_provider_ids_or_plan_actions(self) -> None:
        """Doc 07 §34 'Suggestion is not identity evidence'; §7 unavailable is not negative."""
        names = set(inspect.signature(compare).parameters)
        for word in ("llm", "suggest", "hint", "provider", "plan", "similar", "mapping"):
            self.assertFalse([n for n in names if word in n.lower()], word)


class TestReportShape(PartitionMixin):
    def test_the_partition_holds_in_a_mixed_comparison(self) -> None:
        trusted_text = tf(
            vpc("same"),
            vpc("gone"),
            vpc("amb"),
            VAR_N,
            vpc("unk", "count = var.n"),
            sg("g", name='"x"'),
        )
        candidate_text = tf(
            vpc("same"),
            vpc("made"),
            vpc("amb", 'for_each = toset(["a", "b"])'),
            VAR_N,
            vpc("unk", "count = 2"),
            sg("g", name='"y"'),
        )
        trusted, candidate = resources_of(trusted_text), resources_of(candidate_text)
        report = compare_resources(trusted, candidate)
        self.assert_partition(trusted, candidate, report)

    def test_the_report_names_the_algorithm_and_validates(self) -> None:
        report = compare_texts(tf(vpc()), tf(vpc()))
        self.assertEqual(report.algorithm_version, "dail-identity-1")
        self.assertEqual(report.parent_state_id, PARENT)
        self.assertEqual(report.candidate_id, CANDIDATE)
        self.assertEqual(IdentityReport.from_dict(report.to_dict()), report)

    def test_a_shuffled_input_gives_the_same_report_hash(self) -> None:
        trusted = list(resources_of(tf(vpc("a"), vpc("b"), sg("g", name='"x"'), vpc("c"))))
        candidate = list(
            resources_of(tf(vpc("a"), vpc("d"), sg("g", name='"y"'), vpc("c", cidr="10.7.0.0/16")))
        )
        reference = compare_resources(trusted, candidate)
        rng = random.Random(7)
        for _ in range(15):
            again = compare_resources(
                rng.sample(trusted, len(trusted)), rng.sample(candidate, len(candidate))
            )
            self.assertEqual(again.content_hash, reference.content_hash)

    def test_every_rationale_names_an_evidence_type_that_the_match_holds(self) -> None:
        trusted_text = tf(vpc("same"), vpc("gone"), vpc("amb"), sg("g", name='"x"'))
        candidate_text = tf(
            vpc("same"),
            vpc("amb", 'for_each = toset(["a", "b"])'),
            sg("g", name='"y"'),
            vpc("made"),
        )
        report = compare_texts(trusted_text, candidate_text)
        for m in report.resource_matches:
            held = {e.evidence_type for e in report.evidence_for(m)}
            self.assertIn(m.rule, held, m.key)

    def test_an_unchanged_report_has_no_uncertain_or_changed_entries(self) -> None:
        report = compare_texts(tf(vpc(), sg()), tf(vpc(), sg()))
        self.assertEqual({k: len(v) for k, v in report.summary.items() if v}, {"unchanged": 2})

    def test_replacing_a_match_in_a_copy_is_caught_by_the_report_hash(self) -> None:
        report = compare_texts(tf(vpc()), tf(vpc(cidr="10.9.0.0/16")))
        data = report.to_dict()
        data["resource_matches"][0] = {**data["resource_matches"][0], "change_type": "UNCHANGED"}
        with self.assertRaises(ValueError):
            IdentityReport.from_dict(data)
        self.assertEqual(
            replace(report, report_id=report.report_id).content_hash, report.content_hash
        )


if __name__ == "__main__":
    unittest.main()
