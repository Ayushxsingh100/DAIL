"""INV-FUNC-001: an unresolved entry of vpc_security_group_ids (P5b-fix step 1; registry §6.3, §6.4;
C-155 item 7, C-156).

Every expected value is derived by hand from the registry text on the canonical topology (see the
derivation in ``test_reachability_vectors.py``), not from the code under test.

* E3: "each entry references a configured aws_security_group with a resolved vpc_id". An entry of
  ``D.vpc_security_group_ids`` that is unresolved (a variable without a value, or a group whose
  ``count`` is unknown) leaves E3 unresolved: row 4, UNKNOWN. Rows 1 to 3 come first, row 2 causes
  win over row 4, and row 4 comes before rows 5 to 9, so the result is UNKNOWN whether or not the
  path is otherwise established (a path built from the known groups is not a PASS, and a missing
  path is not a FAIL).
* The registry says nothing about an unresolved entry of ``S.vpc_security_group_ids``. C-156 reads
  it the same way (row 4): whether that group is MIXED or RETAINED-INLINE (row 2) cannot be
  checked. C-155 item 13 records that the authors may relax it to PASS in registry v1.1.
* A literal AWS id stays UNSUPPORTED (C-155 item 7), and the engine is compared with the exact
  string ``"postgres"`` of E2.
"""

from __future__ import annotations

import dataclasses
import unittest

from core.domain.enums import VerificationResult
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.domain.verification import VerificationReason
from core.verification.outcome import PredicateOutcome
from core.verification.reachability import evaluate_reachability
from tests.func_builders import (
    APP_SGS_LINE,
    APP_TO_DB,
    DB_SGS_LINE,
    IGW_ROUTE,
    attribute,
    canonical,
    edit,
    edits,
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
INTRA_ROUTE = '  route {\n    cidr_block = "10.0.2.0/24"\n    nat_gateway_id = "nat-1"\n  }\n'

# the group lines, with the text that stands for one more entry in the list
DB_LIST = "[aws_security_group.db.id, {}]"
APP_LIST = "[aws_security_group.app.id, {}]"
PLACEHOLDER = (
    '\nresource "aws_security_group" "extra" {\n  count       = var.u\n  name        = "extra"\n'
    '  description = "unknown count"\n  vpc_id      = aws_vpc.main.id\n}\n'
)
RESOLVED = (
    '\nresource "aws_security_group" "extra" {\n  name        = "extra"\n'
    '  description = "an extra group"\n  vpc_id      = aws_vpc.main.id\n'
    "  ingress     = []\n  egress      = []\n}\n"
)


def sgs(value: str) -> str:
    return f"  vpc_security_group_ids      = {value}\n"


def on_db(value: str, text: str | None = None) -> str:
    return edit(text or canonical(), DB_SGS_LINE, sgs(value))


def on_app(value: str, text: str | None = None) -> str:
    return edit(text or canonical(), APP_SGS_LINE, sgs(value))


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


class TestUnresolvedEntryOfD(Check):
    def test_a_variable_among_the_entries(self) -> None:
        text = VAR + on_db(DB_LIST.format("var.u"))
        outcome = evaluate(text)
        self.check(outcome, U, 4, R.ATTRIBUTE_UNRESOLVED)
        self.assertTrue(outcome.observations["unresolved"])

    def test_a_concat_with_a_variable(self) -> None:
        text = VAR + on_db("concat([aws_security_group.db.id], [var.u])")
        self.check(evaluate(text), U, 4, R.ATTRIBUTE_UNRESOLVED)

    def test_the_whole_list_unresolved_stays_row_four(self) -> None:
        self.check(evaluate(VAR + on_db("var.u")), U, 4, R.ATTRIBUTE_UNRESOLVED)

    def test_a_placeholder_group_among_the_entries(self) -> None:
        text = VAR + on_db(DB_LIST.format("aws_security_group.extra[0].id")) + PLACEHOLDER
        outcome = evaluate(text)
        self.check(outcome, U, 4, R.ATTRIBUTE_UNRESOLVED)
        self.assertTrue(outcome.observations["unresolved"])

    def test_the_path_not_established_is_still_unknown_never_a_fail(self) -> None:
        # without the ingress rule row 9 would say FAIL; E3 is unresolved, so row 4 comes first
        text = VAR + on_db(DB_LIST.format("var.u"), edit(canonical(), APP_TO_DB, ""))
        self.check(evaluate(text), U, 4, R.ATTRIBUTE_UNRESOLVED)

    def test_a_resolved_extra_group_changes_nothing(self) -> None:
        text = on_db(DB_LIST.format("aws_security_group.extra.id")) + RESOLVED
        self.check(evaluate(text), P, 6, None)

    def test_a_literal_group_id_is_unsupported(self) -> None:
        text = on_db(DB_LIST.format('"sg-0123456789abcdef0"'))
        self.check(evaluate(text), S, 2, R.MODEL_UNSUPPORTED)

    def test_rows_one_to_three_and_row_two_come_before_row_four(self) -> None:
        unresolved = VAR + on_db(DB_LIST.format("var.u"))
        self.check(evaluate(edit(unresolved, '"postgres"', '"mysql"')), F, 3, R.PORT_MISMATCH)
        self.check(
            evaluate(edit(unresolved, IGW_ROUTE, IGW_ROUTE + INTRA_ROUTE)),
            S,
            2,
            R.ROUTE_UNSUPPORTED,
        )
        self.check(
            evaluate(
                unresolved.replace('resource "aws_db_instance" "database"', 'resource "x" "y"')
            ),
            F,
            1,
            R.ENDPOINT_ABSENT,
        )

    def test_row_four_comes_before_rows_five_to_nine(self) -> None:
        far = (
            '\nresource "aws_vpc" "other" {\n  cidr_block = "10.1.0.0/16"\n}\n'
            '\nresource "aws_subnet" "far" {\n  vpc_id = aws_vpc.other.id\n'
            '  cidr_block = "10.1.1.0/24"\n}\n'
        )
        text = edits(
            canonical(),
            (
                "  subnet_id                   = aws_subnet.app.id\n",
                "  subnet_id                   = aws_subnet.far.id\n",
            ),
            (DB_SGS_LINE, sgs(DB_LIST.format("var.u"))),
        )
        self.check(evaluate(VAR + text + far), U, 4, R.ATTRIBUTE_UNRESOLVED)


class TestUnresolvedEntryOfS(Check):
    """C-156 rule 2: the registry is silent; the conservative reading is row 4."""

    def test_a_variable_among_the_entries(self) -> None:
        outcome = evaluate(VAR + on_app(APP_LIST.format("var.u")))
        self.check(outcome, U, 4, R.ATTRIBUTE_UNRESOLVED)
        self.assertTrue(outcome.observations["unresolved"])

    def test_a_concat_with_a_variable(self) -> None:
        text = VAR + on_app("concat([aws_security_group.app.id], [var.u])")
        self.check(evaluate(text), U, 4, R.ATTRIBUTE_UNRESOLVED)

    def test_the_whole_list_unresolved_stays_row_four(self) -> None:
        self.check(evaluate(VAR + on_app("var.u")), U, 4, R.ATTRIBUTE_UNRESOLVED)

    def test_a_placeholder_group_among_the_entries(self) -> None:
        text = VAR + on_app(APP_LIST.format("aws_security_group.extra[0].id")) + PLACEHOLDER
        self.check(evaluate(text), U, 4, R.ATTRIBUTE_UNRESOLVED)

    def test_the_path_not_established_is_still_unknown_never_a_fail(self) -> None:
        text = VAR + on_app(APP_LIST.format("var.u"), edit(canonical(), APP_TO_DB, ""))
        self.check(evaluate(text), U, 4, R.ATTRIBUTE_UNRESOLVED)

    def test_a_resolved_extra_group_changes_nothing(self) -> None:
        text = on_app(APP_LIST.format("aws_security_group.extra.id")) + RESOLVED
        self.check(evaluate(text), P, 6, None)

    def test_a_literal_group_id_is_unsupported(self) -> None:
        text = on_app(APP_LIST.format('"sg-0123456789abcdef0"'))
        self.check(evaluate(text), S, 2, R.MODEL_UNSUPPORTED)


class TestAReferenceToAPlaceholderGroup(Check):
    """A reference that names a group of unknown ``count`` cannot come from the text (the evaluator
    gives an unknown value for it), so the stored view is damaged by hand: the entry is a ``Ref``
    to the placeholder. E3 is unresolved all the same (row 4)."""

    def check_entry(self, owner: str, own: str) -> None:
        base = inputs(VAR + canonical() + PLACEHOLDER)
        placeholder = {"$dail": "ref", "address": "aws_security_group.extra", "attribute": "id"}
        known = {"$dail": "ref", "address": f"aws_security_group.{own}", "attribute": "id"}

        def damage(resource: Resource) -> Resource:
            attributes = thaw_json(resource.attributes)
            attributes["vpc_security_group_ids"] = attribute([known, placeholder])
            return with_attributes(resource, attributes)

        found = [damage(r) if r.address == owner else r for r in base.candidate_resources]
        given = dataclasses.replace(base, candidate_resources=tuple(found))
        outcome = evaluate_reachability(definition(given), given)
        self.check(outcome, U, 4, R.ATTRIBUTE_UNRESOLVED)
        self.assertTrue(any("placeholder" in line for line in outcome.observations["unresolved"]))

    def test_an_entry_of_d(self) -> None:
        self.check_entry("aws_db_instance.database", "db")

    def test_an_entry_of_s(self) -> None:
        self.check_entry("aws_instance.app", "app")


class TestTheEngineIsComparedExactly(Check):
    """Registry E2: ``engine == "postgres"``, the exact string."""

    def test_the_exact_string_is_a_pass(self) -> None:
        self.check(evaluate(canonical()), P, 6, None)

    def test_another_casing_is_not_postgres(self) -> None:
        for spelling in ("Postgres", "POSTGRES", "PostgreS"):
            with self.subTest(engine=spelling):
                text = edit(canonical(), '"postgres"', f'"{spelling}"')
                self.check(evaluate(text), F, 3, R.PORT_MISMATCH)

    def test_a_port_still_wins_over_the_engine(self) -> None:
        text = edit(
            canonical(),
            '  engine                      = "postgres"',
            '  engine                      = "Postgres"\n  port = 5432',
        )
        self.check(evaluate(text), P, 6, None)


if __name__ == "__main__":
    unittest.main()
