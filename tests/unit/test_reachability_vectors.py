"""INV-FUNC-001: the conformance vectors F1 to F20 (P5b step 4; registry §6.3, §6.4, §8; C-151..).

HAND DERIVATION, written before the predicate existed and before any run. The base is the canonical
configuration (fixture ``patch_safe``): VPC ``main`` 10.0.0.0/16; subnets ``app`` 10.0.1.0/24,
``db_a`` 10.0.2.0/24, ``db_b`` 10.0.3.0/24; route table ``public`` with 0.0.0.0/0 -> igw; group
``app`` (``ingress = []``, egress by the rule ``app_egress_all``: ``-1`` to 0.0.0.0/0); group ``db``
(``egress = []``, ingress by the rule ``app_to_db_5432``: tcp 5432 from group ``app``); instance
``app`` (subnet ``app``, groups [app]); database ``database`` (engine postgres, no port, groups
[db]); a tolerated ``aws_db_subnet_group``. Bindings: S = aws_instance.app and
D = aws_db_instance.database.

Canonical: no row 1 (both exist); no row 2 cause (no relevant-unsupported type; the only route is
wider than the VPC CIDR; no ``propagating_vgws``; no interface block; no ``security_groups``; both
have ``vpc_security_group_ids`` and ``S`` a ``subnet_id``; ``app`` has an explicit-empty ingress and
an egress rule, ``db`` an explicit-empty egress and an ingress rule, so neither is MIXED; a baseline
has no RETAINED-INLINE group); E2 holds (no port, engine postgres); E3: ``db`` is in VPC main; E4:
subnet ``app`` is in VPC main, so VPC(S) = VPC(D); E5: ``app_egress_all`` permits TCP/5432 and
0.0.0.0/0 covers 10.0.0.0/16; E6: ``app_to_db_5432`` permits 5432 and its source group ``app`` is in
SG(S). Row 6.

    F1    no edit. As above.                                          registry PASS, row 6
    F2    rule app_to_db_5432 removed. E6 fails, nothing indeterminate    FAIL, row 9
          or partial.
    F3    ingress tcp 5432 from 10.0.1.0/24 instead of the group.        PASS, row 6
          ADDR(S) = subnet 10.0.1.0/24, which the CIDR covers.
    F4    as F3, S in subnet db_b 10.0.3.0/24. The CIDR does not touch   FAIL, row 9
          10.0.3.0/24.
    F5    rule app_egress_all removed. Out(app) is empty, E5 fails.      FAIL, row 9
    F6    egress only tcp 5432 to 10.0.2.0/24. E5 fails; the CIDR        UNKNOWN, row 8
          partly covers the VPC CIDR.
    F7    route 10.0.2.0/24 -> network_interface_id. Inside the VPC      UNSUPPORTED, row 2
          CIDR and not local.
    F8    route 0.0.0.0/0 -> igw removed. That route never applied       PASS, row 6
          (wider than the VPC CIDR).
    F9    an aws_network_acl. Relevant-unsupported type.                 UNSUPPORTED, row 2
    F10   D removed (a baseline; and a parent that had D: DELETED).      FAIL, row 1
    F11   D.port = 3306. E2 definitely false.                            FAIL, row 3
    F12   D without vpc_security_group_ids. Default group not modelled.  UNSUPPORTED, row 2
    F13   ingress from 10.0.1.0/25, S.private_ip unset. ADDR(S) =        UNKNOWN, row 8
          10.0.1.0/24 is only partly covered.
    F13b  as F13 with S.private_ip = 10.0.1.10. ADDR(S) = 10.0.1.10/32,  PASS, row 6
          inside the /25.
    F14   S in a subnet of a second VPC. E3 holds, VPC(S) != VPC(D).     FAIL, row 5
    F15   the aws_db_subnet_group is present (the canonical has it).     PASS, row 6
          Tolerated; the assumption is recorded.
    F16   S has a network_interface block (C-78).                        UNSUPPORTED, row 2
    F17   a route table of VPC(D) sets propagating_vgws = [] (C-78).     UNSUPPORTED, row 2
    F18   an aws_vpc_security_group_vpc_association.                     UNSUPPORTED, row 2
    F19   parent: db has an inline ingress block; candidate: the db      UNSUPPORTED, row 2
          ingress argument absent (RETAINED-INLINE, C-84).
    F20   an aws_default_vpc. Relevant-unsupported type.                 UNSUPPORTED, row 2

In every line the right-hand column is also the registry's answer in section 8 (F13 has two).

The fixtures with a non-trivial FUNC result, derived the same way from their diff against the
canonical text: ``func_unknown_dependency`` (the source group of ``app_to_db_5432`` is a variable
without a value: E6 fails with determinate rules, an indeterminate rule could satisfy it) row 7
UNKNOWN; ``func_unsupported_relationship`` (an ``aws_network_acl``) row 2 UNSUPPORTED;
``rds_deleted_dependency`` (D deleted, with a parent) row 1 FAIL; ``ec2_rds_5432_break`` (app
``egress = []``, no egress rule) row 9 FAIL; ``patch_regression`` (rule ``app_to_db_5432`` removed)
row 9 FAIL. The 20-fixture test compares all of them with ``expected.json`` in step 6.
"""

from __future__ import annotations

import unittest
from typing import Any

from core.domain.enums import VerificationResult
from core.domain.verification import VerificationReason
from core.verification.outcome import PredicateOutcome
from tests.func_builders import (
    APP_EGRESS,
    APP_TO_DB,
    DB_GROUP,
    IGW_ROUTE,
    PUBLIC_IP_LINE,
    SOURCE_LINE,
    SUBNET_LINE,
    canonical,
    edit,
    edits,
)
from tests.reach_builders import evaluate

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
R = VerificationReason


class Vectors(unittest.TestCase):
    def check(
        self,
        outcome: PredicateOutcome,
        result: VerificationResult,
        row: int,
        reason: VerificationReason | None,
    ) -> None:
        self.assertEqual(
            (outcome.result, outcome.observations["row"], outcome.reason), (result, row, reason)
        )

    def test_the_canonical_text_is_what_the_derivation_assumes(self) -> None:
        text = canonical()
        for part in (APP_TO_DB, APP_EGRESS, IGW_ROUTE, SOURCE_LINE, SUBNET_LINE, DB_GROUP):
            self.assertEqual(text.count(part), 1, part[:60])

    def test_f1_canonical(self) -> None:
        outcome = evaluate(canonical())
        self.check(outcome, P, 6, None)
        self.assertIsNone(outcome.clauses)

    def test_f2_the_database_rule_removed(self) -> None:
        self.check(evaluate(edit(canonical(), APP_TO_DB, "")), F, 9, R.PATH_MISSING)

    def test_f3_ingress_from_the_app_subnet(self) -> None:
        text = edit(canonical(), SOURCE_LINE, '  cidr_blocks              = ["10.0.1.0/24"]\n')
        self.check(evaluate(text), P, 6, None)

    def test_f4_the_same_rule_with_the_instance_in_another_subnet(self) -> None:
        text = edits(
            canonical(),
            (SOURCE_LINE, '  cidr_blocks              = ["10.0.1.0/24"]\n'),
            (SUBNET_LINE, "  subnet_id                   = aws_subnet.db_b.id\n"),
        )
        self.check(evaluate(text), F, 9, R.PATH_MISSING)

    def test_f5_no_egress_at_all(self) -> None:
        self.check(evaluate(edit(canonical(), APP_EGRESS, "")), F, 9, R.PATH_MISSING)

    def test_f6_egress_only_to_a_database_subnet(self) -> None:
        narrow = """resource "aws_security_group_rule" "app_egress_all" {
  type              = "egress"
  protocol          = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_blocks       = ["10.0.2.0/24"]
  security_group_id = aws_security_group.app.id
}
"""
        outcome = evaluate(edit(canonical(), APP_EGRESS, narrow))
        self.check(outcome, U, 8, R.COVERAGE_PARTIAL)

    def test_f7_an_intra_vpc_route_to_a_network_interface(self) -> None:
        extra = (
            IGW_ROUTE
            + '\n  route {\n    cidr_block           = "10.0.2.0/24"\n'
            + '    network_interface_id = "eni-0123"\n  }\n'
        )
        self.check(evaluate(edit(canonical(), IGW_ROUTE, extra)), S, 2, R.ROUTE_UNSUPPORTED)

    def test_f8_the_internet_gateway_route_removed(self) -> None:
        self.check(evaluate(edit(canonical(), IGW_ROUTE, "")), P, 6, None)

    def test_f9_a_network_acl(self) -> None:
        text = canonical() + '\nresource "aws_network_acl" "x" {\n  vpc_id = aws_vpc.main.id\n}\n'
        self.check(evaluate(text), S, 2, R.TYPE_RELEVANT_UNSUPPORTED)

    def test_f10_the_database_deleted(self) -> None:
        # a baseline without D, and a candidate whose parent had it (identity: DELETED)
        db_start = canonical().index('resource "aws_db_subnet_group" "db"')
        gone = canonical()[:db_start]
        self.check(evaluate(gone), F, 1, R.ENDPOINT_ABSENT)
        self.check(evaluate(gone, canonical()), F, 1, R.ENDPOINT_ABSENT)

    def test_f11_the_database_listens_elsewhere(self) -> None:
        text = edit(
            canonical(),
            "  publicly_accessible         = false\n",
            "  publicly_accessible         = false\n  port                        = 3306\n",
        )
        self.check(evaluate(text), F, 3, R.PORT_MISMATCH)

    def test_f12_the_database_without_security_groups(self) -> None:
        text = edit(canonical(), "  vpc_security_group_ids      = [aws_security_group.db.id]\n", "")
        self.check(evaluate(text), S, 2, R.MODEL_UNSUPPORTED)

    def test_f13_a_partly_covering_ingress_without_a_private_ip(self) -> None:
        text = edit(canonical(), SOURCE_LINE, '  cidr_blocks              = ["10.0.1.0/25"]\n')
        self.check(evaluate(text), U, 8, R.COVERAGE_PARTIAL)

    def test_f13b_the_same_with_a_private_ip_inside_the_range(self) -> None:
        text = edits(
            canonical(),
            (SOURCE_LINE, '  cidr_blocks              = ["10.0.1.0/25"]\n'),
            (
                PUBLIC_IP_LINE,
                "  associate_public_ip_address = true\n"
                '  private_ip                  = "10.0.1.10"\n}',
            ),
        )
        self.check(evaluate(text), P, 6, None)

    def test_f14_the_instance_in_a_second_vpc(self) -> None:
        text = edit(canonical(), SUBNET_LINE, "  subnet_id                   = aws_subnet.far.id\n")
        text += (
            '\nresource "aws_vpc" "other" {\n  cidr_block = "10.1.0.0/16"\n}\n'
            '\nresource "aws_subnet" "far" {\n  vpc_id            = aws_vpc.other.id\n'
            '  cidr_block        = "10.1.1.0/24"\n  availability_zone = "us-east-1a"\n}\n'
        )
        self.check(evaluate(text), F, 5, R.VPC_MISMATCH)

    def test_f15_the_tolerated_subnet_group_is_recorded(self) -> None:
        outcome = evaluate(canonical())
        self.check(outcome, P, 6, None)
        self.assertIn("tolerated type: aws_db_subnet_group (C-15)", outcome.assumptions)
        without = canonical()[: canonical().index('resource "aws_db_subnet_group" "db"')]
        without += canonical()[canonical().index('resource "aws_db_instance" "database"') :]
        without = without.replace(
            "  db_subnet_group_name        = aws_db_subnet_group.db.name\n", ""
        )
        self.assertNotIn(
            "tolerated type: aws_db_subnet_group (C-15)", evaluate(without).assumptions
        )

    def test_f16_an_interface_block_on_the_instance(self) -> None:
        block = (
            "  associate_public_ip_address = true\n"
            "  network_interface {\n    device_index         = 0\n"
            '    network_interface_id = "eni-0123"\n  }\n}'
        )
        outcome = evaluate(edit(canonical(), PUBLIC_IP_LINE, block))
        self.check(outcome, S, 2, R.INTERFACE_UNSUPPORTED)

    def test_f17_propagating_vgws_even_empty(self) -> None:
        old = 'resource "aws_route_table" "public" {\n  vpc_id = aws_vpc.main.id\n'
        outcome = evaluate(edit(canonical(), old, old + "  propagating_vgws = []\n"))
        self.check(outcome, S, 2, R.ROUTE_UNSUPPORTED)

    def test_f18_a_security_group_vpc_association(self) -> None:
        text = canonical() + (
            '\nresource "aws_vpc_security_group_vpc_association" "x" {\n'
            "  security_group_id = aws_security_group.app.id\n"
            "  vpc_id            = aws_vpc.main.id\n}\n"
        )
        self.check(evaluate(text), S, 2, R.TYPE_RELEVANT_UNSUPPORTED)

    def test_f19_the_database_group_keeps_its_inline_ingress(self) -> None:
        inline = DB_GROUP.replace(
            "  egress      = []\n",
            '  egress      = []\n\n  ingress {\n    protocol        = "tcp"\n'
            "    from_port       = 5432\n    to_port         = 5432\n"
            "    security_groups = [aws_security_group.app.id]\n  }\n",
        )
        parent = edits(canonical(), (APP_TO_DB, ""), (DB_GROUP, inline))
        outcome = evaluate(canonical(), parent)
        self.check(outcome, S, 2, R.GROUP_RETAINED_INLINE)
        causes = [item["cause"] for item in outcome.observations["row2_causes"]]
        self.assertEqual(causes, ["group.retained_inline"])
        self.assertIn("aws_security_group.db", outcome.observations["row2_causes"][0]["detail"])

    def test_f20_a_default_vpc(self) -> None:
        self.check(
            evaluate(canonical() + '\nresource "aws_default_vpc" "d" {}\n'),
            S,
            2,
            R.TYPE_RELEVANT_UNSUPPORTED,
        )


def observed(outcome: PredicateOutcome) -> dict[str, Any]:
    return dict(outcome.observations)


class TestTheEvaluatedPath(unittest.TestCase):
    def test_the_pass_records_the_path_the_registry_asks_for(self) -> None:
        obs = observed(evaluate(canonical()))
        self.assertEqual(obs["port"], 5432)
        self.assertEqual(
            dict(obs["path"]),
            {
                "S": "aws_instance.app",
                "subnet": "aws_subnet.app",
                "vpc_s": "aws_vpc.main",
                "sg_s": ["aws_security_group.app"],
                "egress_rule": "aws_security_group_rule.app_egress_all",
                "sg_d": ["aws_security_group.db"],
                "ingress_rule": "aws_security_group_rule.app_to_db_5432",
                "vpc_d": "aws_vpc.main",
            },
        )
        self.assertEqual(obs["failing_conditions"], [])
        self.assertEqual(obs["row2_causes"], [])

    def test_the_failing_condition_is_named(self) -> None:
        self.assertEqual(
            observed(evaluate(edit(canonical(), APP_TO_DB, "")))["failing_conditions"], ["E6"]
        )
        self.assertEqual(
            observed(evaluate(edit(canonical(), APP_EGRESS, "")))["failing_conditions"], ["E5"]
        )

    def test_the_assumptions_are_a_sorted_closed_list(self) -> None:
        self.assertEqual(
            evaluate(canonical()).assumptions,
            (
                "IPv4 only",
                "M1: RDS security groups and subnet group share one VPC (C-15, C-77, uncited)",
                "M4: default network ACL assumed (no NACL type present)",
                "tolerated type: aws_db_subnet_group (C-15)",
            ),
        )


if __name__ == "__main__":
    unittest.main()
