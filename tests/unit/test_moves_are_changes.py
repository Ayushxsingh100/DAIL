"""Every move is a change (P6d; C-177, which supersedes C-129's resource-level clause; C-76, C-127).

The rule, quoted from the P6d work package (section 3.1) and the authors' decision of 31 Oct 2026
(paper audit round 3, finding C-01, "Every resource move counts as a change"):

1. A pair made by a ``moved`` block of the candidate, or by Terraform's implicit ``count`` move
   (C-76: ``x`` <-> ``x[0]``), is never UNCHANGED, even when the fingerprints are equal. With equal
   fingerprints it is MODIFIED with ``moved = true`` and evidence that names the move. With
   different fingerprints it is MODIFIED (``moved = true``), or REPLACED / UNCERTAIN exactly as
   RT-1 decides.
2. No new ``ChangeType`` value; the flag lives on the identity match and its evidence.
3. Impact treats every such pair as a change source with reason "moved"; it is never dropped.
4. No evidence is carried across a REPLACED pair (unchanged rule).
5. ``AddressOnlyIdentity`` (C-127) does not follow moves.

Expected values come from those sentences. Configurations go through the real pipeline.
"""

from __future__ import annotations

import unittest

from core.domain.enums import ChangeType, ImpactStatus
from core.domain.errors import DomainValidationError
from core.domain.evidence import EvidenceValidity
from core.domain.identity import EvidenceType, IdentityMatch, IdentityReport
from core.domain.impact import ChangedResource, ChangeFlag
from core.identity.strategy import AddressOnlyIdentity
from core.impact.inputs import PriorProof
from tests.identity_builders import compare_texts
from tests.impact_builders import NET, impact_between, impacted

LF = chr(10)


def block(header: str, *lines: str) -> str:
    return header + " {" + LF + "".join(f"  {line}" + LF for line in lines) + "}"


def tf(*blocks: str) -> str:
    return LF.join(blocks) + LF


def vpc(label: str, *args: str, cidr: str = "10.0.0.0/16") -> str:
    return block(f'resource "aws_vpc" "{label}"', *args, f'cidr_block = "{cidr}"')


def group(label: str, *args: str, name: str = "g") -> str:
    return block(f'resource "aws_security_group" "{label}"', f'name = "{name}"', *args)


def moved(source: str, target: str) -> str:
    return block("moved", f"from = {source}", f"to = {target}")


def pair_of(report: IdentityReport, trusted_ref: str) -> IdentityMatch:
    (found,) = (m for m in report.resource_matches if m.trusted_resource_ref == trusted_ref)
    return found


def kinds(report: IdentityReport, match: IdentityMatch) -> set[EvidenceType]:
    return {item.evidence_type for item in report.evidence_for(match)}


def move_evidence(report: IdentityReport, match: IdentityMatch) -> dict[str, object]:
    (item,) = (
        e
        for e in report.evidence_for(match)
        if e.evidence_type in (EvidenceType.EXPLICIT_MOVE, EvidenceType.IMPLICIT_COUNT_MOVE)
    )
    observed = item.to_dict()["observed_value"]
    assert isinstance(observed, dict)
    return observed


class TestIdentity(unittest.TestCase):
    def assert_moved_modified(
        self, report: IdentityReport, trusted_ref: str, candidate_ref: str
    ) -> IdentityMatch:
        match = pair_of(report, trusted_ref)
        self.assertEqual(match.candidate_resource_ref, candidate_ref)
        self.assertIs(match.change_type, ChangeType.MODIFIED)
        self.assertTrue(match.moved)
        self.assertTrue(match.to_dict()["moved"])
        return match

    def test_explicit_rename_with_no_other_change(self) -> None:
        report = compare_texts(tf(vpc("a")), tf(vpc("b"), moved("aws_vpc.a", "aws_vpc.b")))
        match = self.assert_moved_modified(report, "aws_vpc.a", "aws_vpc.b")
        # the fingerprints are equal: the evidence says so, and the move is what decides
        self.assertIn(EvidenceType.FINGERPRINT_EQUAL, kinds(report, match))
        self.assertIs(match.rule, EvidenceType.EXPLICIT_MOVE)
        evidence = move_evidence(report, match)
        self.assertEqual((evidence["from"], evidence["to"]), ("aws_vpc.a", "aws_vpc.b"))
        self.assertEqual(evidence["statements"], [["aws_vpc.a", "aws_vpc.b"]])
        self.assertEqual(report.summary["unchanged"], ())

    def test_adding_count_moves_x_to_x0(self) -> None:
        report = compare_texts(tf(vpc("v")), tf(vpc("v", "count = 1")))
        match = self.assert_moved_modified(report, "aws_vpc.v", "aws_vpc.v[0]")
        self.assertIn(EvidenceType.IMPLICIT_COUNT_MOVE, kinds(report, match))
        self.assertNotIn(EvidenceType.EXPLICIT_MOVE, kinds(report, match))
        evidence = move_evidence(report, match)
        self.assertEqual((evidence["from"], evidence["to"]), ("aws_vpc.v", "aws_vpc.v[0]"))

    def test_removing_count_moves_x0_to_x(self) -> None:
        report = compare_texts(tf(vpc("v", "count = 1")), tf(vpc("v")))
        match = self.assert_moved_modified(report, "aws_vpc.v[0]", "aws_vpc.v")
        self.assertIn(EvidenceType.IMPLICIT_COUNT_MOVE, kinds(report, match))

    def test_instance_key_change(self) -> None:
        trusted = tf(vpc("v", 'for_each = toset(["x", "y"])'))
        candidate = tf(
            vpc("v", 'for_each = toset(["z", "y"])'), moved('aws_vpc.v["x"]', 'aws_vpc.v["z"]')
        )
        report = compare_texts(trusted, candidate)
        self.assert_moved_modified(report, 'aws_vpc.v["x"]', 'aws_vpc.v["z"]')
        # the instance nobody moved is still compared on content alone
        untouched = pair_of(report, 'aws_vpc.v["y"]')
        self.assertIs(untouched.change_type, ChangeType.UNCHANGED)
        self.assertFalse(untouched.moved)

    def test_resource_level_move_of_keyed_instances(self) -> None:
        each = 'for_each = toset(["x", "y"])'
        report = compare_texts(
            tf(vpc("a", each)), tf(vpc("b", each), moved("aws_vpc.a", "aws_vpc.b"))
        )
        self.assert_moved_modified(report, 'aws_vpc.a["x"]', 'aws_vpc.b["x"]')
        self.assert_moved_modified(report, 'aws_vpc.a["y"]', 'aws_vpc.b["y"]')

    def test_chained_move_is_one_pair(self) -> None:
        report = compare_texts(
            tf(vpc("a")),
            tf(vpc("c"), moved("aws_vpc.a", "aws_vpc.b"), moved("aws_vpc.b", "aws_vpc.c")),
        )
        self.assertEqual(len(report.resource_matches), 1)
        match = self.assert_moved_modified(report, "aws_vpc.a", "aws_vpc.c")
        self.assertEqual(
            move_evidence(report, match)["statements"],
            [["aws_vpc.a", "aws_vpc.b"], ["aws_vpc.b", "aws_vpc.c"]],
        )

    def test_move_plus_an_argument_change(self) -> None:
        report = compare_texts(
            tf(vpc("a")),
            tf(vpc("b", "enable_dns_hostnames = true"), moved("aws_vpc.a", "aws_vpc.b")),
        )
        match = self.assert_moved_modified(report, "aws_vpc.a", "aws_vpc.b")
        self.assertIn(EvidenceType.FINGERPRINT_DIFFERENT, kinds(report, match))
        self.assertIn(EvidenceType.EXPLICIT_MOVE, kinds(report, match))

    def test_move_plus_a_security_group_name_change_is_replaced(self) -> None:
        report = compare_texts(
            tf(group("a", name="one")),
            tf(group("b", name="two"), moved("aws_security_group.a", "aws_security_group.b")),
        )
        match = pair_of(report, "aws_security_group.a")
        self.assertEqual(match.candidate_resource_ref, "aws_security_group.b")
        self.assertIs(match.change_type, ChangeType.REPLACED)
        self.assertTrue(match.moved)
        self.assertIn(EvidenceType.REPLACE_TRIGGER_FIELD, kinds(report, match))
        self.assertIn(EvidenceType.EXPLICIT_MOVE, kinds(report, match))

    def test_address_only_identity_does_not_follow_moves(self) -> None:
        report = compare_texts(
            tf(vpc("a")),
            tf(vpc("b"), moved("aws_vpc.a", "aws_vpc.b")),
            strategy=AddressOnlyIdentity(),
        )
        self.assertEqual(
            {m.key: m.change_type for m in report.resource_matches},
            {"aws_vpc.a->-": ChangeType.DELETED, "-->aws_vpc.b": ChangeType.CREATED},
        )
        self.assertFalse(any(m.moved for m in report.resource_matches))

    def test_an_unmoved_equal_pair_is_still_unchanged(self) -> None:
        report = compare_texts(tf(vpc("a")), tf(vpc("a")))
        (match,) = report.resource_matches
        self.assertIs(match.change_type, ChangeType.UNCHANGED)
        self.assertFalse(match.moved)
        self.assertFalse(match.to_dict()["moved"])


class TestMatchGuards(unittest.TestCase):
    """The domain refuses a match that would hide a move (rule 1), whoever builds it."""

    EV = "a" * 64

    def make(self, trusted: str | None, candidate: str | None, change: ChangeType, moved: bool):
        rule = EvidenceType.FINGERPRINT_EQUAL
        return IdentityMatch.create(
            trusted_ref=trusted,
            candidate_ref=candidate,
            change_type=change,
            rule=rule,
            evidence_ids=[self.EV],
            moved=moved,
        )

    def test_a_moved_pair_cannot_be_unchanged(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.make("aws_vpc.a", "aws_vpc.b", ChangeType.UNCHANGED, True)

    def test_a_pair_across_addresses_must_say_moved(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.make("aws_vpc.a", "aws_vpc.b", ChangeType.MODIFIED, False)
        with self.assertRaises(DomainValidationError):
            self.make("aws_vpc.a", "aws_vpc.b", ChangeType.UNCHANGED, False)

    def test_a_pair_at_one_address_is_not_moved(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.make("aws_vpc.a", "aws_vpc.a", ChangeType.MODIFIED, True)

    def test_one_sided_matches_are_not_moved(self) -> None:
        with self.assertRaises(DomainValidationError):
            self.make("aws_vpc.a", None, ChangeType.DELETED, True)
        with self.assertRaises(DomainValidationError):
            self.make(None, "aws_vpc.b", ChangeType.CREATED, True)

    def test_moved_round_trips_and_is_required(self) -> None:
        match = self.make("aws_vpc.a", "aws_vpc.b", ChangeType.MODIFIED, True)
        data = match.to_dict()
        self.assertEqual(IdentityMatch.from_dict(data), match)
        del data["moved"]
        with self.assertRaises(DomainValidationError):
            IdentityMatch.from_dict(data)
        with self.assertRaises(DomainValidationError):
            IdentityMatch.from_dict({**match.to_dict(), "moved": "yes"})

    def test_an_uncertain_pair_across_addresses_is_moved(self) -> None:
        match = self.make("aws_vpc.a", "aws_vpc.b", ChangeType.UNCERTAIN, True)
        self.assertTrue(match.moved)


# --- impact -----------------------------------------------------------------------------------

LONE = 'resource "aws_security_group" "lone" {\n  name = "lone"\n  vpc_id = aws_vpc.main.id\n}\n'
SOLO = 'resource "aws_security_group" "solo" {\n  name = "lone"\n  vpc_id = aws_vpc.main.id\n}\n'
MOVE = "moved {\n  from = aws_security_group.lone\n  to = aws_security_group.solo\n}\n"
SEC1, SEC2, SEC3, FUNC = "INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"


def proof(invariant_id: str) -> PriorProof:
    return PriorProof(
        invariant_id=invariant_id,
        invariant_version=1,
        evidence_ids=(f"e-{invariant_id.lower()}",),
        verifier_id={
            SEC1: "dail.verify.public_ingress",
            SEC2: "dail.verify.public_ingress",
            SEC3: "dail.verify.rds_public_flag",
            FUNC: "dail.verify.reachability_cfg",
        }[invariant_id],
        verifier_version="1",
    )


class TestImpact(unittest.TestCase):
    def source_of(self, report, address: str) -> ChangedResource:  # type: ignore[no-untyped-def]
        (found,) = (c for c in report.changed_resources if c.address == address)
        return found

    def test_a_pure_rename_is_a_change_source_flagged_moved(self) -> None:
        report = impact_between(NET + LONE, NET + SOLO + MOVE)
        changed = self.source_of(report, "aws_security_group.solo")
        self.assertEqual(
            (changed.trusted_ref, changed.candidate_ref, changed.change_type),
            ("aws_security_group.lone", "aws_security_group.solo", ChangeType.MODIFIED),
        )
        self.assertIn(ChangeFlag.MOVED, changed.flags)
        # every security group is in the SEC footprint (registry §3.5, C-64)
        found = impacted(report)
        for invariant in (SEC1, SEC2):
            self.assertIs(found[invariant].status, ImpactStatus.AFFECTED)
            self.assertIn("aws_security_group.solo", found[invariant].changed_resource_refs)

    def test_a_pure_rename_does_not_carry_the_sec_proofs(self) -> None:
        prior = [proof(SEC1), proof(SEC2), proof(SEC3), proof(FUNC)]
        report = impact_between(NET + LONE, NET + SOLO + MOVE, prior=prior)
        for invariant in (SEC1, SEC2):
            self.assertFalse(
                report.carry_forward_ok(
                    invariant,
                    1,
                    candidate_id=report.candidate_id,
                    parent_state_id=report.parent_state_id,
                )
            )

    def test_adding_count_is_a_change_source_flagged_moved(self) -> None:
        counted = LONE.replace('  name = "lone"\n', '  count = 1\n  name = "lone"\n')
        report = impact_between(NET + LONE, NET + counted)
        changed = self.source_of(report, "aws_security_group.lone[0]")
        self.assertIn(ChangeFlag.MOVED, changed.flags)
        self.assertIs(impacted(report)[SEC1].status, ImpactStatus.AFFECTED)

    def test_moved_and_replaced_carries_no_evidence(self) -> None:
        renamed = SOLO.replace('name = "lone"', 'name = "other"')
        prior = [proof(SEC1), proof(SEC2), proof(SEC3), proof(FUNC)]
        report = impact_between(NET + LONE, NET + renamed + MOVE, prior=prior)
        changed = self.source_of(report, "aws_security_group.solo")
        self.assertIs(changed.change_type, ChangeType.REPLACED)
        self.assertIn(ChangeFlag.MOVED, changed.flags)
        for invariant in (SEC1, SEC2):
            item = impacted(report)[invariant]
            self.assertIs(item.status, ImpactStatus.AFFECTED)
            self.assertIs(item.evidence_validity, EvidenceValidity.INVALID)
            self.assertFalse(
                report.carry_forward_ok(
                    invariant,
                    1,
                    candidate_id=report.candidate_id,
                    parent_state_id=report.parent_state_id,
                )
            )
            self.assertNotIn(invariant, {c.invariant_id for c in report.carry_forward_candidates})

    def test_the_moved_flag_needs_both_refs(self) -> None:
        with self.assertRaises(DomainValidationError):
            ChangedResource(
                address="aws_vpc.a",
                trusted_ref="aws_vpc.a",
                candidate_ref=None,
                resource_type="aws_vpc",
                change_type=ChangeType.DELETED,
                flags=(ChangeFlag.MOVED,),
            )


if __name__ == "__main__":
    unittest.main()
