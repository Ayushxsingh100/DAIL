"""INV-SEC-003: RDS instances are not publicly accessible (P5a step 4; registry §5, §8; C-146).

Expected values are derived by hand from registry §5.2 and §5.3:

    R1  ``publicly_accessible`` absent                 -> false (provider default, V05)  -> PASS
    R2  ``publicly_accessible = true``                 -> a resolved true                -> FAIL
    R3  ``publicly_accessible = var.public``, no value -> unresolved                     -> UNKNOWN
    R4  no ``aws_db_instance`` at all                  -> vacuous, count 0               -> PASS

§5.3 gives the order FAIL, then UNKNOWN, then PASS. It has no row for a value that depends on an
unsupported construct (registry §2.4 would call that UNSUPPORTED); the implementation puts
UNSUPPORTED between FAIL and UNKNOWN, the same order as §3.4, and records the gap (R5).
"""

from __future__ import annotations

import unittest

from core.domain.enums import VerificationResult
from core.domain.jsonvalue import thaw_json
from core.domain.verification import VerificationReason
from core.verification.rds_public_flag import PredicateOutcome, evaluate_rds_public_flag
from core.verification.views import ViewError
from tests.security_builders import resources_of, with_security

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
R = VerificationReason
DB = "aws_db_instance.database"


def db(body: str = "", name: str = "database") -> str:
    return f'resource "aws_db_instance" "{name}" {{\n  identifier = "d"\n{body}}}\n'


def run(text: str) -> PredicateOutcome:
    return evaluate_rds_public_flag(resources_of(text))


class TestRegistryVectors(unittest.TestCase):
    def test_r1_absent_is_false(self) -> None:
        outcome = run(db())
        self.assertEqual((outcome.result, outcome.reason, outcome.clauses), (P, None, None))
        self.assertEqual(outcome.observations["instances"], 1)
        self.assertEqual(outcome.observations["values"], [{"address": DB, "value": "absent"}])

    def test_r2_true_fails(self) -> None:
        outcome = run(db("  publicly_accessible = true\n"))
        self.assertEqual((outcome.result, outcome.reason), (F, R.PREDICATE_VIOLATED))
        self.assertEqual(outcome.observations["values"], [{"address": DB, "value": "true"}])

    def test_r3_unresolved_is_unknown(self) -> None:
        text = 'variable "public" {}\n' + db("  publicly_accessible = var.public\n")
        outcome = run(text)
        self.assertEqual((outcome.result, outcome.reason), (U, R.ATTRIBUTE_UNRESOLVED))
        (item,) = outcome.observations["values"]
        self.assertTrue(item["value"].startswith("unknown:"), item)

    def test_r4_no_instance_is_vacuous_with_count_zero(self) -> None:
        outcome = run('resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n')
        self.assertEqual((outcome.result, outcome.reason), (P, None))
        self.assertEqual(outcome.observations["instances"], 0)
        self.assertEqual(outcome.observations["values"], [])


class TestValues(unittest.TestCase):
    def test_explicit_false_and_null_are_false(self) -> None:
        for body, shown in (
            ("  publicly_accessible = false\n", "false"),
            ("  publicly_accessible = null\n", "absent"),
        ):
            with self.subTest(body=body):
                outcome = run(db(body))
                self.assertIs(outcome.result, P)
                self.assertEqual(outcome.observations["values"][0]["value"], shown)

    def test_terraform_converts_the_text_true_and_false(self) -> None:
        self.assertIs(run(db('  publicly_accessible = "true"\n')).result, F)
        self.assertIs(run(db('  publicly_accessible = "false"\n')).result, P)

    def test_a_reference_and_a_computed_attribute_are_both_unresolved(self) -> None:
        vpc = 'resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        for expression, shown in (
            ("aws_vpc.v.id", "ref:aws_vpc.v.id"),
            ("aws_vpc.v.enable_dns_support", "unknown:resource.computed:enable_dns_support"),
        ):
            with self.subTest(expression=expression):
                outcome = run(vpc + db(f"  publicly_accessible = {expression}\n"))
                self.assertIs(outcome.result, U)
                self.assertEqual(outcome.observations["values"][0]["value"], shown)

    def test_a_value_of_the_wrong_type_is_unsupported(self) -> None:
        for body in (
            "  publicly_accessible = 5\n",
            '  publicly_accessible = "yes"\n',
            "  publicly_accessible = []\n",
        ):
            with self.subTest(body=body):
                self.assertIs(run(db(body)).result, S)

    def test_an_unsupported_value_is_unsupported_not_unknown(self) -> None:
        resource = next(iter(resources_of(db("  publicly_accessible = true\n"))))
        security = thaw_json(resource.security_attributes)
        security["publicly_accessible"] = {"$dail": "unsupported", "reason": "function.unsupported"}
        outcome = evaluate_rds_public_flag([with_security(resource, security)])
        self.assertEqual((outcome.result, outcome.reason), (S, R.RULE_UNSUPPORTED))


class TestOrderAndCount(unittest.TestCase):
    TWO = 'variable "public" {}\n'

    def test_a_resolved_true_beats_an_unresolved_value(self) -> None:
        text = (
            self.TWO
            + db("  publicly_accessible = true\n", "a")
            + db("  publicly_accessible = var.public\n", "b")
        )
        self.assertIs(run(text).result, F)

    def test_an_unresolved_value_beats_a_false_one(self) -> None:
        text = (
            self.TWO
            + db("  publicly_accessible = false\n", "a")
            + db("  publicly_accessible = var.public\n", "b")
        )
        self.assertIs(run(text).result, U)

    def test_unsupported_sits_between_fail_and_unknown(self) -> None:
        base = resources_of(
            self.TWO + db(name="a") + db("  publicly_accessible = var.public\n", "b")
        )
        a = next(r for r in base if r.address == "aws_db_instance.a")
        security = thaw_json(a.security_attributes)
        security["publicly_accessible"] = {"$dail": "unsupported", "reason": "function.unsupported"}
        mixed = [with_security(a, security), *[r for r in base if r is not a]]
        self.assertIs(evaluate_rds_public_flag(mixed).result, S)  # beats UNKNOWN from b

    def test_each_instance_of_a_counted_resource_is_one_instance(self) -> None:
        text = (
            'resource "aws_db_instance" "d" {\n  count = 2\n  identifier = "d"\n'
            "  publicly_accessible = true\n}\n"
        )
        outcome = run(text)
        self.assertIs(outcome.result, F)
        self.assertEqual(outcome.observations["instances"], 2)
        self.assertEqual(
            [item["address"] for item in outcome.observations["values"]],
            ["aws_db_instance.d[0]", "aws_db_instance.d[1]"],
        )

    def test_an_unknown_count_is_an_indeterminate_resource(self) -> None:
        text = (
            'variable "n" {}\nresource "aws_db_instance" "d" {\n  count = var.n\n'
            '  identifier = "d"\n}\n'
        )
        outcome = run(text)
        self.assertEqual((outcome.result, outcome.reason), (U, R.ATTRIBUTE_UNRESOLVED))
        self.assertEqual(outcome.observations["placeholders"], ["aws_db_instance.d"])

    def test_other_database_types_are_out_of_scope(self) -> None:
        text = 'resource "aws_rds_cluster_instance" "c" {\n  publicly_accessible = true\n}\n'
        self.assertIs(run(text).result, P)


class TestEvidenceFields(unittest.TestCase):
    def test_the_assumption_is_recorded(self) -> None:
        self.assertEqual(
            run(db()).assumptions, ("absent publicly_accessible is false (registry 5.2, V05)",)
        )

    def test_the_tolerated_type_is_recorded_when_present(self) -> None:
        text = db() + 'resource "aws_db_subnet_group" "g" {\n  subnet_ids = []\n}\n'
        self.assertIn("tolerated type: aws_db_subnet_group (C-15)", run(text).assumptions)

    def test_a_view_that_is_not_the_shape_p3a_writes_is_an_error(self) -> None:
        resource = next(iter(resources_of(db())))
        for bad in ({"surprise": 1}, {"publicly_accessible": {"$dail": "weird"}}):
            with self.subTest(bad=bad), self.assertRaises(ViewError):
                evaluate_rds_public_flag([with_security(resource, bad)])

    def test_the_result_does_not_depend_on_resource_order(self) -> None:
        text = db("  publicly_accessible = true\n", "a") + db(name="b") + db(name="c")
        resources = list(resources_of(text))
        self.assertEqual(
            evaluate_rds_public_flag(resources), evaluate_rds_public_flag(list(reversed(resources)))
        )


if __name__ == "__main__":
    unittest.main()
