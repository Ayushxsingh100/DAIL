"""INV-FUNC-001, row by row (P5b step 4; registry §6.2, §6.3, §6.4; C-151 to C-154).

Every expected value is derived by hand from the registry text on the canonical topology (see the
derivation in ``test_reachability_vectors.py``): E5 and E6 are stated per rule (``v4(r)`` is the
CIDR list of one rule, so coverage is not pooled across rules); row 7 is "an indeterminate rule
could satisfy it"; row 2 comes before rows 3 to 9 and row 1 before row 2. Where the registry is
silent the choice is UNSUPPORTED (R5) or the cautious reading, and the test says so.
"""

from __future__ import annotations

import dataclasses
import random
import unittest
from collections.abc import Callable
from typing import Any

from core.domain.enums import VerificationResult
from core.domain.invariant import Invariant
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.domain.verification import VerificationReason
from core.verification.inputs import VerificationInputs
from core.verification.outcome import PredicateOutcome
from core.verification.reachability import evaluate_reachability
from tests.func_builders import (
    APP_EGRESS,
    APP_GROUP,
    APP_SGS_LINE,
    APP_TO_DB,
    DB_GROUP,
    DB_SGS_LINE,
    PUBLIC_IP_LINE,
    SUBNET_LINE,
    attribute,
    canonical,
    edit,
    edits,
    egress_5432,
    ingress_5432,
    rule,
    with_attributes,
)
from tests.reach_builders import definition, evaluate, inputs

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
R = VerificationReason
VAR = 'variable "u" {}\n'
TABLE = 'resource "aws_route_table" "public" {\n  vpc_id = aws_vpc.main.id\n'
INGRESS_BLOCK = (
    '\n  ingress {\n    protocol = "tcp"\n    from_port = 22\n    to_port = 22\n'
    '    cidr_blocks = ["10.0.0.0/8"]\n  }\n'
)
EGRESS_BLOCK = (
    '\n  egress {\n    protocol = "-1"\n    from_port = 0\n    to_port = 0\n'
    '    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
)


def swap_ingress(body: str) -> str:
    """The canonical text with ``app_to_db_5432`` replaced by another ingress rule on ``db``."""
    return edit(canonical(), APP_TO_DB, ingress_5432("ingress_x", body))


def swap_egress(body: str) -> str:
    return edit(canonical(), APP_EGRESS, egress_5432("egress_x", body))


class Check(unittest.TestCase):
    def check(
        self,
        outcome: PredicateOutcome,
        result: VerificationResult,
        row: int,
        reason: VerificationReason | None,
    ) -> None:
        self.assertEqual(
            (outcome.result, outcome.observations["row"], outcome.reason),
            (result, row, reason),
            outcome.observations,
        )


def replaced(
    given: VerificationInputs, address: str, build: Callable[[Resource], Resource]
) -> VerificationInputs:
    found = [build(r) if r.address == address else r for r in given.candidate_resources]
    return dataclasses.replace(given, candidate_resources=tuple(found))


def with_parameters(given: VerificationInputs, **parameters: Any) -> Invariant:
    base = definition(given)
    merged = {**thaw_json(base.predicate["parameters"]), **parameters}
    merged = {key: value for key, value in merged.items() if value is not None}
    return dataclasses.replace(base, predicate={**thaw_json(base.predicate), "parameters": merged})


class TestParameters(Check):
    def test_bad_parameters_are_unsupported_never_a_pass(self) -> None:
        given = inputs(canonical())
        cases = {
            "wrong port": {"port": 3306},
            "no port": {"port": None},
            "no source": {"S": None},
            "empty destination": {"D": ""},
            "same endpoint": {"S": "aws_instance.app", "D": "aws_instance.app"},
            "source of the wrong type": {"S": "aws_subnet.app"},
            "destination of the wrong type": {"D": "aws_instance.app"},
            "a number as the source": {"S": 7},
        }
        for name, parameters in cases.items():
            with self.subTest(case=name):
                outcome = evaluate_reachability(with_parameters(given, **parameters), given)
                self.assertEqual((outcome.result, outcome.reason), (S, R.PARAMETERS_INVALID))

    def test_parameters_that_are_not_an_object(self) -> None:
        given = inputs(canonical())
        base = definition(given)
        broken = dataclasses.replace(
            base, predicate={"registry": "registry-v1.0", "parameters": "x"}
        )
        outcome = evaluate_reachability(broken, given)
        self.assertEqual((outcome.result, outcome.reason), (S, R.PARAMETERS_INVALID))

    def test_a_binding_the_trusted_state_does_not_have(self) -> None:
        given = inputs(canonical(), canonical())
        outcome = evaluate_reachability(with_parameters(given, S="aws_instance.ghost"), given)
        self.assertEqual((outcome.result, outcome.reason), (S, R.PARAMETERS_INVALID))


class TestEndpoints(Check):
    MOVE = "\nmoved {\n  from = aws_instance.app\n  to   = aws_instance.web\n}\n"

    def renamed(self) -> str:
        text = canonical().replace('resource "aws_instance" "app"', 'resource "aws_instance" "web"')
        self.assertNotEqual(text, canonical())
        return text

    def test_a_moved_source_is_followed(self) -> None:
        outcome = evaluate(self.renamed() + self.MOVE, canonical())
        self.check(outcome, P, 6, None)
        self.assertEqual(outcome.observations["path"]["S"], "aws_instance.web")
        endpoint = outcome.observations["endpoints"]["S"]
        self.assertEqual(
            (endpoint["trusted"], endpoint["candidate"]), ("aws_instance.app", "aws_instance.web")
        )
        self.assertIn(endpoint["match"], ("UNCHANGED", "MODIFIED"))

    def test_a_renamed_source_without_a_move_is_a_created_endpoint_and_the_old_one_is_gone(
        self,
    ) -> None:
        # C-152: no heuristic match; DELETED is absent
        outcome = evaluate(self.renamed(), canonical())
        self.check(outcome, F, 1, R.ENDPOINT_ABSENT)
        self.assertEqual(outcome.observations["endpoints"]["S"]["match"], "DELETED")

    def test_a_moved_database_is_followed(self) -> None:
        text = canonical().replace(
            'resource "aws_db_instance" "database"', 'resource "aws_db_instance" "db2"'
        )
        text += "\nmoved {\n  from = aws_db_instance.database\n  to   = aws_db_instance.db2\n}\n"
        self.check(evaluate(text, canonical()), P, 6, None)

    def test_an_uncertain_endpoint_is_unknown_never_fail_or_pass(self) -> None:
        # a placeholder (unknown count) is always UNCERTAIN in the identity report
        text = VAR + edit(
            canonical(),
            'resource "aws_instance" "app" {\n',
            'resource "aws_instance" "app" {\n  count = var.u\n',
        )
        outcome = evaluate(text, canonical())
        self.check(outcome, U, 4, R.RESOURCE_INDETERMINATE)
        self.assertEqual(outcome.observations["endpoints"]["S"]["match"], "UNCERTAIN")

    def test_a_placeholder_endpoint_in_a_baseline_is_unknown(self) -> None:
        text = VAR + edit(
            canonical(),
            'resource "aws_instance" "app" {\n',
            'resource "aws_instance" "app" {\n  count = var.u\n',
        )
        self.check(evaluate(text), U, 4, R.RESOURCE_INDETERMINATE)

    def test_an_endpoint_that_is_itself_unsupported_is_unknown_by_c_152(self) -> None:
        given = inputs(canonical())

        def broken(resource: Resource) -> Resource:
            return Resource.create(
                address=resource.address,
                resource_type=resource.resource_type,
                logical_identity={},
                attributes={"$content": {"$dail": "unsupported", "reason": "limit.json_depth"}},
                security_attributes={},
                semantic_attributes={},
                references=(),
                provenance=resource.provenance,
                support_status=dataclasses.replace(
                    resource, support_status=resource.support_status
                ).support_status.__class__.UNSUPPORTED,
            )

        outcome = evaluate_reachability(
            definition(given), replaced(given, "aws_db_instance.database", broken)
        )
        self.check(outcome, U, 4, R.RESOURCE_INDETERMINATE)

    def test_a_parent_without_an_identity_report_is_unsupported(self) -> None:
        given = dataclasses.replace(inputs(canonical(), canonical()), identity=None)
        outcome = evaluate_reachability(definition(given), given)
        self.assertEqual((outcome.result, outcome.reason), (S, R.IDENTITY_MISSING))

    def test_an_indexed_binding(self) -> None:
        text = edit(
            canonical(),
            'resource "aws_instance" "app" {\n',
            'resource "aws_instance" "app" {\n  count = 1\n',
        )
        given = inputs(text)
        outcome = evaluate_reachability(with_parameters(given, S="aws_instance.app[0]"), given)
        self.check(outcome, P, 6, None)

    def test_an_absent_source_in_a_baseline(self) -> None:
        start = canonical().index('resource "aws_instance" "app"')
        end = canonical().index('resource "aws_db_subnet_group"')
        self.check(evaluate(canonical()[:start] + canonical()[end:]), F, 1, R.ENDPOINT_ABSENT)


class TestRowTwo(Check):
    def test_row_one_comes_before_row_two(self) -> None:
        start = canonical().index('resource "aws_db_subnet_group" "db"')
        text = (
            canonical()[:start]
            + '\nresource "aws_network_acl" "x" {\n  vpc_id = aws_vpc.main.id\n}\n'
        )
        self.check(evaluate(text), F, 1, R.ENDPOINT_ABSENT)

    def test_row_two_comes_before_row_three(self) -> None:
        text = edit(
            canonical(),
            "  publicly_accessible         = false\n",
            "  publicly_accessible         = false\n  port = 3306\n",
        )
        text += '\nresource "aws_network_acl" "x" {\n  vpc_id = aws_vpc.main.id\n}\n'
        self.check(evaluate(text), S, 2, R.TYPE_RELEVANT_UNSUPPORTED)

    def test_every_cause_is_reported_and_the_first_in_the_fixed_order_names_the_reason(
        self,
    ) -> None:
        text = canonical() + '\nresource "aws_network_acl" "x" {\n  vpc_id = aws_vpc.main.id\n}\n'
        text = edit(
            text,
            PUBLIC_IP_LINE,
            "  associate_public_ip_address = true\n  network_interface {\n    device_index = 0\n"
            '    network_interface_id = "eni-1"\n  }\n}',
        )
        outcome = evaluate(text)
        self.check(outcome, S, 2, R.TYPE_RELEVANT_UNSUPPORTED)
        self.assertEqual(
            [c["cause"] for c in outcome.observations["row2_causes"]],
            ["type.relevant_unsupported", "interface.unsupported"],
        )
        self.assertEqual(outcome.observations["relevant_unsupported"], ["aws_network_acl.x"])

    def test_name_based_security_groups(self) -> None:
        text = edit(
            canonical(),
            PUBLIC_IP_LINE,
            '  associate_public_ip_address = true\n  security_groups = ["default"]\n}',
        )
        self.check(evaluate(text), S, 2, R.MODEL_UNSUPPORTED)

    def test_an_empty_name_list_uses_nothing(self) -> None:
        text = edit(
            canonical(),
            PUBLIC_IP_LINE,
            "  associate_public_ip_address = true\n  security_groups = []\n}",
        )
        self.check(evaluate(text), P, 6, None)

    def test_a_name_list_that_cannot_be_fixed_is_unsupported_by_r5(self) -> None:
        text = VAR + edit(
            canonical(),
            PUBLIC_IP_LINE,
            "  associate_public_ip_address = true\n  security_groups = var.u\n}",
        )
        self.check(evaluate(text), S, 2, R.MODEL_UNSUPPORTED)

    def test_the_default_security_group_and_default_vpc_are_not_modelled(self) -> None:
        for name, text in {
            "S without a subnet": edit(canonical(), SUBNET_LINE, ""),
            "S without groups": edit(canonical(), APP_SGS_LINE, ""),
            "S with an empty group list": edit(
                canonical(), APP_SGS_LINE, "  vpc_security_group_ids      = []\n"
            ),
            "D with an empty group list": edit(
                canonical(), DB_SGS_LINE, "  vpc_security_group_ids      = []\n"
            ),
        }.items():
            with self.subTest(case=name):
                self.check(evaluate(text), S, 2, R.MODEL_UNSUPPORTED)

    def test_a_mixed_group_of_either_side(self) -> None:
        block = INGRESS_BLOCK
        app_with_block = APP_GROUP.replace("  ingress     = []\n", "")
        app_with_block = app_with_block[: app_with_block.rindex("}")] + block + "}\n"
        db_with_block = DB_GROUP[: DB_GROUP.rindex("}")] + block + "}\n"
        for group, old, new in (
            ("db", DB_GROUP, db_with_block),
            ("app", APP_GROUP, app_with_block),
        ):
            text = edit(canonical(), old, new)
            with self.subTest(group=group):
                outcome = evaluate(text)
                self.check(outcome, S, 2, R.GROUP_MIXED)

    def test_a_group_outside_both_sides_may_be_mixed(self) -> None:
        extra = (
            '\nresource "aws_security_group" "other" {\n  vpc_id = aws_vpc.main.id\n'
            + INGRESS_BLOCK.lstrip("\n")
            + "}\n"
            + rule("o", "ingress", "tcp", 80, 80, "other", '  cidr_blocks = ["10.0.0.0/8"]\n')
        )
        self.check(evaluate(canonical() + extra), P, 6, None)

    def test_retained_inline_egress_of_the_source_group(self) -> None:
        egress_block = EGRESS_BLOCK
        parent = edits(
            canonical(),
            (APP_EGRESS, ""),
            (APP_GROUP, APP_GROUP[: APP_GROUP.rindex("}")] + egress_block + "}\n"),
        )
        outcome = evaluate(canonical(), parent)
        self.check(outcome, S, 2, R.GROUP_RETAINED_INLINE)
        self.assertIn("aws_security_group.app", outcome.observations["row2_causes"][0]["detail"])

    def test_retention_of_the_other_direction_does_not_matter(self) -> None:
        # S reads egress only: an ingress retained by the source group is not a cause
        ingress_block = INGRESS_BLOCK
        app_without = APP_GROUP.replace("  ingress     = []\n", "")
        parent = edit(
            canonical(), APP_GROUP, app_without[: app_without.rindex("}")] + ingress_block + "}\n"
        )
        self.check(evaluate(edit(canonical(), APP_GROUP, app_without), parent), P, 6, None)
        # D reads ingress only: an egress retained by the database group is not a cause
        egress_block = EGRESS_BLOCK
        db_without = DB_GROUP.replace("  egress      = []\n", "")
        parent = edit(
            canonical(), DB_GROUP, db_without[: db_without.rindex("}")] + egress_block + "}\n"
        )
        self.check(evaluate(edit(canonical(), DB_GROUP, db_without), parent), P, 6, None)

    def test_a_direction_that_cannot_be_fixed_is_unsupported_not_no_rules(self) -> None:
        # C-120(c): the egress of SG(S) and the ingress of SG(D)
        db = VAR + edits(
            canonical(),
            (DB_GROUP, DB_GROUP.replace("  egress      = []", "  ingress     = var.u")),
            (APP_TO_DB, ""),
        )
        self.check(evaluate(db), S, 2, R.FORMS_UNRESOLVED)
        app = VAR + edits(
            canonical(),
            (APP_GROUP, APP_GROUP.replace("  ingress     = []", "  egress      = var.u")),
            (APP_EGRESS, ""),
        )
        self.check(evaluate(app), S, 2, R.FORMS_UNRESOLVED)

    def test_an_unresolved_direction_beside_a_rule_resource_is_mixed_by_the_conservative_reading(
        self,
    ) -> None:
        text = VAR + edit(
            canonical(), APP_GROUP, APP_GROUP.replace("  ingress     = []", "  ingress     = var.u")
        )
        self.check(evaluate(text), S, 2, R.GROUP_MIXED)

    def test_an_unsupported_rule_of_a_group_on_either_side(self) -> None:
        bad = rule("bad", "egress", "tcp", 80, 80, "app", '  cidr_blocks = ["10.0.0.1/8"]\n')
        self.check(evaluate(canonical() + "\n" + bad), S, 2, R.RULE_UNSUPPORTED)

    def test_an_unsupported_rule_of_another_group_is_not_read(self) -> None:
        other = '\nresource "aws_security_group" "other" {\n  vpc_id = aws_vpc.main.id\n}\n'
        text = (
            canonical()
            + other
            + rule("bad", "egress", "tcp", 80, 80, "other", '  cidr_blocks = ["10.0.0.1/8"]\n')
        )
        self.check(evaluate(text), P, 6, None)

    def test_an_unsupported_engine_or_port(self) -> None:
        given = inputs(canonical())
        for name in ("engine", "port"):

            def damage(resource: Resource, name: str = name) -> Resource:
                attributes = thaw_json(resource.attributes)
                attributes[name] = attribute(
                    {"$dail": "unsupported", "reason": "function.unsupported"}
                )
                return with_attributes(resource, attributes)

            with self.subTest(argument=name):
                outcome = evaluate_reachability(
                    definition(given), replaced(given, "aws_db_instance.database", damage)
                )
                self.check(outcome, S, 2, R.VALUE_UNSUPPORTED)


class TestRoutes(Check):
    def routed(self, route_block: str, table: str = TABLE) -> str:
        return edit(canonical(), TABLE, table + route_block)

    def test_a_local_route_inside_the_vpc_is_fine(self) -> None:
        block = '  route {\n    cidr_block = "10.0.0.0/16"\n    gateway_id = "local"\n  }\n'
        self.check(evaluate(self.routed(block)), P, 6, None)

    def test_a_non_local_route_equal_to_the_vpc_cidr_applies(self) -> None:
        block = '  route {\n    cidr_block = "10.0.0.0/16"\n    gateway_id = "igw-1"\n  }\n'
        self.check(evaluate(self.routed(block)), S, 2, R.ROUTE_UNSUPPORTED)

    def test_a_route_wider_or_outside_never_applies(self) -> None:
        for destination in ("10.0.0.0/8", "192.168.0.0/16", "0.0.0.0/1"):
            block = (
                f'  route {{\n    cidr_block = "{destination}"\n'
                '    nat_gateway_id = "nat-1"\n  }\n'
            )
            with self.subTest(destination=destination):
                self.check(evaluate(self.routed(block)), P, 6, None)

    def test_an_ipv6_only_route_is_not_read(self) -> None:
        block = '  route {\n    ipv6_cidr_block = "fd00::/8"\n    nat_gateway_id = "nat-1"\n  }\n'
        self.check(evaluate(self.routed(block)), P, 6, None)

    def test_a_route_table_of_another_vpc_is_not_ours(self) -> None:
        other = (
            '\nresource "aws_vpc" "other" {\n  cidr_block = "10.1.0.0/16"\n}\n'
            '\nresource "aws_route_table" "elsewhere" {\n  vpc_id = aws_vpc.other.id\n'
            '  propagating_vgws = ["vgw-1"]\n  route {\n    cidr_block = "10.0.2.0/24"\n'
            '    nat_gateway_id = "nat-1"\n  }\n}\n'
        )
        self.check(evaluate(canonical() + other), P, 6, None)

    def test_a_route_table_of_a_vpc_that_is_not_configured_is_not_ours(self) -> None:
        other = (
            '\nresource "aws_route_table" "elsewhere" {\n  vpc_id = "vpc-9"\n'
            '  route {\n    cidr_block = "10.0.2.0/24"\n    nat_gateway_id = "nat-1"\n  }\n}\n'
        )
        self.check(evaluate(canonical() + other), P, 6, None)

    def test_a_route_table_whose_vpc_cannot_be_fixed_may_be_ours(self) -> None:
        # registry silent (R5): UNSUPPORTED when it has an M3 route or propagating_vgws
        table = (
            VAR + '\nresource "aws_route_table" "maybe" {\n  vpc_id = var.u\n'
            '  route {\n    cidr_block = "10.0.2.0/24"\n    nat_gateway_id = "nat-1"\n  }\n}\n'
        )
        self.check(evaluate(table + canonical()), S, 2, R.ROUTE_UNSUPPORTED)
        harmless = (
            VAR + '\nresource "aws_route_table" "maybe" {\n  vpc_id = var.u\n'
            '  route {\n    cidr_block = "0.0.0.0/0"\n    nat_gateway_id = "nat-1"\n  }\n}\n'
        )
        self.check(evaluate(harmless + canonical()), P, 6, None)

    def test_a_destination_target_or_expansion_that_cannot_be_fixed(self) -> None:
        cases = {
            "destination": '  route {\n    cidr_block = var.u\n    nat_gateway_id = "nat-1"\n  }\n',
            "target": '  route {\n    cidr_block = "10.0.2.0/24"\n    gateway_id = var.u\n  }\n',
            "prefix list": (
                '  route {\n    destination_prefix_list_id = "pl-1"\n'
                '    nat_gateway_id = "nat-1"\n  }\n'
            ),
            "expansion": (
                '  dynamic "route" {\n    for_each = var.u\n    content {\n'
                '      cidr_block = "10.0.2.0/24"\n      nat_gateway_id = "nat-1"\n    }\n  }\n'
            ),
        }
        for name, block in cases.items():
            with self.subTest(case=name):
                self.check(evaluate(VAR + self.routed(block)), S, 2, R.ROUTE_UNSUPPORTED)

    def test_propagating_vgws_of_our_table_even_empty(self) -> None:
        self.check(evaluate(self.routed("  propagating_vgws = []\n")), S, 2, R.ROUTE_UNSUPPORTED)

    def test_the_causes_say_which_route(self) -> None:
        block = '  route {\n    cidr_block = "10.0.2.0/24"\n    nat_gateway_id = "nat-1"\n  }\n'
        outcome = evaluate(self.routed(block))
        (cause,) = outcome.observations["row2_causes"]
        self.assertEqual(cause["cause"], "route.unsupported")
        self.assertIn("aws_route_table.public", cause["detail"])
        self.assertIn("10.0.2.0/24", cause["detail"])


class TestRowsThreeToFive(Check):
    def with_db(self, line: str) -> str:
        return edit(
            canonical(),
            "  publicly_accessible         = false\n",
            "  publicly_accessible         = false\n" + line,
        )

    def test_the_listener_port(self) -> None:
        cases = [
            ("  port = 5432\n", P, 6, None),
            ('  port = "5432"\n', P, 6, None),
            ("  port = 5433\n", F, 3, R.PORT_MISMATCH),
            ("  port = 5432\n  # engine stays postgres\n", P, 6, None),
        ]
        for line, result, row, reason in cases:
            with self.subTest(line=line):
                self.check(evaluate(self.with_db(line)), result, row, reason)

    def test_the_port_wins_over_the_engine(self) -> None:
        text = edit(
            self.with_db("  port = 5432\n"),
            '  engine                      = "postgres"',
            '  engine                      = "mysql"',
        )
        self.check(evaluate(text), P, 6, None)

    def test_another_engine_without_a_port_is_definitely_not_postgres(self) -> None:
        text = edit(canonical(), '"postgres"', '"mysql"')
        self.check(evaluate(text), F, 3, R.PORT_MISMATCH)

    def test_neither_port_nor_engine_is_a_registry_gap(self) -> None:
        text = edit(canonical(), '  engine                      = "postgres"\n', "")
        self.check(evaluate(text), S, 2, R.MODEL_UNSUPPORTED)

    def test_an_unresolved_listener_is_unknown_by_the_gap_reading(self) -> None:
        # registry row 4 names E3 and E4, not E2; an unresolved E2 cannot be a PASS
        self.check(evaluate(VAR + self.with_db("  port = var.u\n")), U, 4, R.ATTRIBUTE_UNRESOLVED)
        text = VAR + edit(canonical(), '"postgres"', "var.u")
        self.check(evaluate(text), U, 4, R.ATTRIBUTE_UNRESOLVED)

    def test_row_three_comes_before_row_four(self) -> None:
        text = VAR + edit(
            self.with_db("  port = 3306\n"), SUBNET_LINE, "  subnet_id                   = var.u\n"
        )
        self.check(evaluate(text), F, 3, R.PORT_MISMATCH)

    def test_values_that_cannot_be_fixed_are_unknown(self) -> None:
        cases = {
            "D groups": edit(canonical(), DB_SGS_LINE, "  vpc_security_group_ids      = var.u\n"),
            "D group vpc": edit(
                canonical(), DB_GROUP, DB_GROUP.replace("aws_vpc.main.id", "var.u")
            ),
            "S subnet": edit(canonical(), SUBNET_LINE, "  subnet_id                   = var.u\n"),
            "subnet vpc": edit(
                canonical(),
                'resource "aws_subnet" "app" {\n  vpc_id                  = aws_vpc.main.id\n',
                'resource "aws_subnet" "app" {\n  vpc_id                  = var.u\n',
            ),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.check(evaluate(VAR + text), U, 4, R.ATTRIBUTE_UNRESOLVED)

    def test_row_four_comes_before_row_five(self) -> None:
        far = (
            '\nresource "aws_vpc" "other" {\n  cidr_block = "10.1.0.0/16"\n}\n'
            '\nresource "aws_subnet" "far" {\n  vpc_id = aws_vpc.other.id\n'
            '  cidr_block = "10.1.1.0/24"\n}\n'
        )
        text = edits(
            canonical(),
            (SUBNET_LINE, "  subnet_id                   = aws_subnet.far.id\n"),
            (DB_SGS_LINE, "  vpc_security_group_ids      = var.u\n"),
        )
        self.check(evaluate(VAR + text + far), U, 4, R.ATTRIBUTE_UNRESOLVED)

    def test_things_outside_the_model_are_unsupported_by_r5(self) -> None:
        other = '\nresource "aws_vpc" "other" {\n  cidr_block = "10.1.0.0/16"\n}\n' + (
            '\nresource "aws_security_group" "away" {\n  vpc_id = aws_vpc.other.id\n}\n'
        )
        cases = {
            "D groups in two VPCs": edit(
                canonical(),
                DB_SGS_LINE,
                "  vpc_security_group_ids      = "
                "[aws_security_group.db.id, aws_security_group.away.id]\n",
            )
            + other,
            "a literal group id on D": edit(
                canonical(), DB_SGS_LINE, '  vpc_security_group_ids      = ["sg-123"]\n'
            ),
            "a literal VPC id on a D group": edit(
                canonical(), DB_GROUP, DB_GROUP.replace("aws_vpc.main.id", '"vpc-123"')
            ),
            "a literal subnet id on S": edit(
                canonical(), SUBNET_LINE, '  subnet_id                   = "subnet-123"\n'
            ),
            "an invalid private_ip": edit(
                canonical(),
                PUBLIC_IP_LINE,
                '  associate_public_ip_address = true\n  private_ip = "not-an-ip"\n}',
            ),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.assertEqual(evaluate(text).result, S, name)


class TestRowsSixToNine(Check):
    def test_e5_by_the_destination_group(self) -> None:
        text = swap_egress("  source_security_group_id = aws_security_group.db.id\n")
        outcome = evaluate(text)
        self.check(outcome, P, 6, None)
        self.assertEqual(
            outcome.observations["path"]["egress_rule"], "aws_security_group_rule.egress_x"
        )

    def test_e5_by_a_cidr_list_that_covers_the_vpc_as_a_union(self) -> None:
        text = swap_egress('  cidr_blocks = ["10.0.0.0/17", "10.0.128.0/17"]\n')
        self.check(evaluate(text), P, 6, None)

    def test_the_port_range_decides_whether_a_rule_counts(self) -> None:
        cases = [
            ("tcp", 5000, 6000, P, 6),
            ("tcp", 5433, 5433, F, 9),
            ("tcp", 5432, 5432, P, 6),
            ("udp", 5432, 5432, F, 9),
            ("-1", 0, 0, P, 6),
        ]
        for protocol, low, high, result, row in cases:
            text = edit(
                canonical(),
                APP_EGRESS,
                rule(
                    "egress_x",
                    "egress",
                    protocol,
                    low,
                    high,
                    "app",
                    '  cidr_blocks = ["0.0.0.0/0"]\n',
                ),
            )
            with self.subTest(protocol=protocol, low=low, high=high):
                outcome = evaluate(text)
                self.assertEqual((outcome.result, outcome.observations["row"]), (result, row))

    def test_coverage_is_per_rule_not_pooled(self) -> None:
        # E5 says v4(r) covers CIDR(VPC(D)) for one rule r: two rules with a half each do not
        halves = egress_5432("half_a", '  cidr_blocks = ["10.0.0.0/17"]\n') + egress_5432(
            "half_b", '  cidr_blocks = ["10.0.128.0/17"]\n'
        )
        outcome = evaluate(edit(canonical(), APP_EGRESS, halves))
        self.check(outcome, U, 8, R.COVERAGE_PARTIAL)  # each half partly covers the VPC

    def test_e6_by_the_group_of_the_source(self) -> None:
        self.check(evaluate(canonical()), P, 6, None)

    def test_e6_by_self_needs_the_group_to_be_one_of_the_source(self) -> None:
        self_rule = ingress_5432("db_self", "  self = true\n")
        both = DB_SGS_LINE.replace("[aws_security_group.db.id]", "[aws_security_group.db.id]")
        text = edit(canonical(), APP_TO_DB, self_rule)
        self.check(evaluate(text), F, 9, R.PATH_MISSING)  # db is not a group of S
        in_both = edit(
            text,
            APP_SGS_LINE,
            "  vpc_security_group_ids      = "
            "[aws_security_group.app.id, aws_security_group.db.id]\n",
        )
        self.check(evaluate(in_both), P, 6, None)
        self.assertEqual(both, DB_SGS_LINE)

    def test_e6_by_a_cidr_around_a_private_ip(self) -> None:
        text = swap_ingress('  cidr_blocks = ["10.0.1.0/25"]\n')
        inside = edit(
            text,
            PUBLIC_IP_LINE,
            '  associate_public_ip_address = true\n  private_ip = "10.0.1.10"\n}',
        )
        outside = edit(
            text,
            PUBLIC_IP_LINE,
            '  associate_public_ip_address = true\n  private_ip = "10.0.1.200"\n}',
        )
        self.check(evaluate(inside), P, 6, None)
        self.check(evaluate(outside), F, 9, R.PATH_MISSING)  # one address is covered or it is not

    def test_an_unresolved_private_ip_falls_back_to_the_subnet(self) -> None:
        text = VAR + edit(
            swap_ingress('  cidr_blocks = ["10.0.1.0/25"]\n'),
            PUBLIC_IP_LINE,
            "  associate_public_ip_address = true\n  private_ip = var.u\n}",
        )
        self.check(evaluate(text), U, 8, R.COVERAGE_PARTIAL)

    def test_ipv6_is_not_modelled(self) -> None:
        self.check(evaluate(swap_ingress('  ipv6_cidr_blocks = ["::/0"]\n')), F, 9, R.PATH_MISSING)
        self.check(evaluate(swap_egress('  ipv6_cidr_blocks = ["::/0"]\n')), F, 9, R.PATH_MISSING)

    def test_a_disjoint_cidr_is_not_a_partial_cover(self) -> None:
        self.check(
            evaluate(swap_ingress('  cidr_blocks = ["10.0.3.0/24"]\n')), F, 9, R.PATH_MISSING
        )

    def test_row_seven_an_unresolved_source_group_could_satisfy_e6(self) -> None:
        text = VAR + swap_ingress("  source_security_group_id = var.u\n")
        outcome = evaluate(text)
        self.check(outcome, U, 7, R.RULE_INDETERMINATE)
        (item,) = outcome.observations["indeterminate_rules"]
        self.assertEqual(
            (item["condition"], item["rule"]), ("E6", "aws_security_group_rule.ingress_x")
        )

    def test_row_seven_counts_a_resolved_source_with_an_unresolved_port(self) -> None:
        # R3: the mirror of the gap of C-150. The rule could supply the permission, so it is not
        # dropped (dropping it could turn a possible PASS into an unsound FAIL). Pinned.
        broken = rule(
            "ingress_x",
            "ingress",
            "tcp",
            5432,
            5432,
            "db",
            "  source_security_group_id = aws_security_group.app.id\n",
        ).replace("from_port = 5432", "from_port = var.u")
        self.check(evaluate(VAR + edit(canonical(), APP_TO_DB, broken)), U, 7, R.RULE_INDETERMINATE)

    def test_row_seven_ignores_an_indeterminate_rule_that_cannot_satisfy(self) -> None:
        elsewhere = '\nresource "aws_security_group" "other" {\n  vpc_id = aws_vpc.main.id\n}\n'
        broken = rule(
            "ingress_x",
            "ingress",
            "tcp",
            5432,
            5432,
            "db",
            "  source_security_group_id = aws_security_group.other.id\n",
        ).replace("from_port = 5432", "from_port = var.u")
        self.check(
            evaluate(VAR + edit(canonical(), APP_TO_DB, broken) + elsewhere), F, 9, R.PATH_MISSING
        )

    def test_row_seven_a_rule_of_a_pseudo_group_with_an_unresolved_target(self) -> None:
        loose = (
            'resource "aws_security_group_rule" "loose" {\n  type = "ingress"\n  protocol = "tcp"\n'
            "  from_port = 5432\n  to_port = 5432\n  security_group_id = var.u\n"
            "  source_security_group_id = aws_security_group.app.id\n}\n"
        )
        self.check(evaluate(VAR + edit(canonical(), APP_TO_DB, loose)), U, 7, R.RULE_INDETERMINATE)
        external = loose.replace("var.u", '"sg-0123"')
        self.check(evaluate(edit(canonical(), APP_TO_DB, external)), F, 9, R.PATH_MISSING)

    def test_row_seven_a_rule_resource_that_is_a_placeholder(self) -> None:
        text = VAR + edit(
            canonical(),
            'resource "aws_security_group_rule" "app_to_db_5432" {\n',
            'resource "aws_security_group_rule" "app_to_db_5432" {\n  count = var.u\n',
        )
        self.check(evaluate(text), U, 7, R.RULE_INDETERMINATE)

    def test_row_seven_a_rule_whose_type_cannot_be_fixed(self) -> None:
        # a rule of unknown direction counts for both directions; the database group must not
        # declare an explicit empty egress, or the rule would make it MIXED (next test)
        text = VAR + edits(
            canonical(),
            ('  type                     = "ingress"\n', "  type                     = var.u\n"),
            (DB_GROUP, DB_GROUP.replace("  egress      = []\n", "")),
        )
        self.check(evaluate(text), U, 7, R.RULE_INDETERMINATE)

    def test_a_rule_of_unknown_direction_on_a_group_with_an_explicit_empty_egress_is_mixed(
        self,
    ) -> None:
        # the rule might be an egress rule on a group that declares `egress = []` (registry §2.6,
        # read as for INV-SEC-001/002): row 2, which comes before row 7
        text = VAR + edit(
            canonical(),
            '  type                     = "ingress"\n',
            "  type                     = var.u\n",
        )
        self.check(evaluate(text), S, 2, R.GROUP_MIXED)

    def test_row_seven_a_prefix_list(self) -> None:
        self.check(
            evaluate(swap_ingress('  prefix_list_ids = ["pl-1"]\n')), U, 7, R.RULE_INDETERMINATE
        )

    def test_row_seven_an_unresolved_group_of_the_source(self) -> None:
        text = VAR + edits(
            canonical(),
            (APP_TO_DB, ""),
            (APP_SGS_LINE, "  vpc_security_group_ids      = [aws_security_group.app.id, var.u]\n"),
        )
        self.check(evaluate(text), U, 7, R.ATTRIBUTE_UNRESOLVED)

    def test_an_unresolved_group_does_not_spoil_a_pass_that_already_holds(self) -> None:
        text = VAR + edit(
            canonical(),
            APP_SGS_LINE,
            "  vpc_security_group_ids      = [aws_security_group.app.id, var.u]\n",
        )
        self.check(evaluate(text), P, 6, None)

    def test_row_seven_comes_before_row_eight(self) -> None:
        both = ingress_5432("narrow", '  cidr_blocks = ["10.0.1.0/25"]\n') + ingress_5432(
            "loose", "  source_security_group_id = var.u\n"
        )
        self.check(evaluate(VAR + edit(canonical(), APP_TO_DB, both)), U, 7, R.RULE_INDETERMINATE)

    def test_row_seven_applies_when_either_failing_condition_could_be_satisfied(self) -> None:
        # E5 fails for good (no egress); E6 could be satisfied. Cautious reading of "it": UNKNOWN
        text = VAR + edits(
            canonical(),
            (APP_EGRESS, ""),
            (APP_TO_DB, ingress_5432("loose", "  source_security_group_id = var.u\n")),
        )
        outcome = evaluate(text)
        self.check(outcome, U, 7, R.RULE_INDETERMINATE)
        self.assertEqual(outcome.observations["failing_conditions"], ["E5", "E6"])

    def test_both_conditions_failing_without_any_possibility_is_row_nine(self) -> None:
        text = edits(canonical(), (APP_EGRESS, ""), (APP_TO_DB, ""))
        outcome = evaluate(text)
        self.check(outcome, F, 9, R.PATH_MISSING)
        self.assertEqual(outcome.observations["failing_conditions"], ["E5", "E6"])


class TestOrderAndOutcome(Check):
    def test_resource_order_does_not_change_the_outcome(self) -> None:
        given = inputs(canonical())
        base = evaluate_reachability(definition(given), given)
        rng = random.Random(20261029)
        resources = list(given.candidate_resources)
        for _ in range(6):
            rng.shuffle(resources)
            shuffled = dataclasses.replace(given, candidate_resources=tuple(resources))
            self.assertEqual(evaluate_reachability(definition(shuffled), shuffled), base)

    def test_the_observations_are_plain_json(self) -> None:
        import json

        for text in (
            canonical(),
            edit(canonical(), APP_TO_DB, ""),
            canonical() + '\nresource "aws_default_vpc" "d" {}\n',
        ):
            json.dumps(dict(evaluate(text).observations))

    def test_no_clauses_and_a_fixed_key_set(self) -> None:
        outcome = evaluate(canonical())
        self.assertIsNone(outcome.clauses)
        keys = (
            "row reason detail endpoints port path row2_causes unresolved failing_conditions "
            "indeterminate_rules partial_coverage relevant_unsupported"
        ).split()
        self.assertEqual(sorted(outcome.observations), sorted(keys))
        # the same keys on every path, not only on the one that happens to set them
        for text in (
            edit(canonical(), APP_TO_DB, ""),
            canonical() + '\nresource "aws_default_vpc" "d" {}\n',
        ):
            self.assertEqual(sorted(evaluate(text).observations), sorted(keys))


if __name__ == "__main__":
    unittest.main()
