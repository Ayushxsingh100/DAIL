"""Baseline verification of created resources (P5a step 5; Doc 08 §16; registry §2.7; C-148).

P4 emits one RESOURCE work item per CREATED resource. Expected results are derived by hand from
C-148:
a created group or rule runs PIP(22) and PIP(5432) restricted to the groups it contributes to; a
created database runs INV-SEC-003 for that instance; a created relevant-unsupported resource is
UNSUPPORTED; a placeholder is UNKNOWN; any other type is PASS with ``applicable = false``.
"""

from __future__ import annotations

import dataclasses
import unittest

from core.domain.enums import ResourceSupport, VerificationResult
from core.domain.resource import Resource
from core.domain.verification import VerificationReason
from core.verification.baseline import verify_baseline
from core.verification.public_ingress import evaluate_public_ingress
from tests.pipeline_builders import inputs_for
from tests.security_builders import VARS, inline, rule, sg

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
R = VerificationReason
ANY4 = ["0.0.0.0/0"]
OLD = sg("db")
NEW = "aws_security_group.new"


def db(body: str = "", name: str = "database") -> str:
    return f'resource "aws_db_instance" "{name}" {{\n  identifier = "d"\n{body}}}\n'


def baseline(address: str, candidate: str, parent: str | None = OLD):  # type: ignore[no-untyped-def]
    return verify_baseline(address, inputs_for(candidate, parent))


class TestSecurityGroups(unittest.TestCase):
    def test_a_created_group_open_on_ssh_fails(self) -> None:
        item = baseline(NEW, OLD + sg("new", inline("ingress", "tcp", 22, 22, ANY4)))
        self.assertEqual(
            (item.result, item.reason, item.applicable), (F, R.PREDICATE_VIOLATED, True)
        )
        self.assertEqual(item.observations["groups"], [NEW])
        self.assertEqual(
            item.observations["predicates"],
            {
                "22": {"IPV4": "FAIL", "IPV6": "PASS"},
                "5432": {"IPV4": "PASS", "IPV6": "PASS"},
            },
        )
        self.assertEqual(
            (item.verifier_id, item.verifier_version), ("dail.verify.public_ingress", "1")
        )

    def test_a_created_group_open_on_postgres_fails(self) -> None:
        item = baseline(NEW, OLD + sg("new", inline("ingress", "tcp", 5432, 5432, ANY4)))
        self.assertEqual(item.result, F)
        self.assertEqual(item.observations["predicates"]["22"], {"IPV4": "PASS", "IPV6": "PASS"})
        self.assertEqual(item.observations["predicates"]["5432"]["IPV4"], "FAIL")

    def test_a_clean_created_group_passes_and_is_applicable(self) -> None:
        item = baseline(NEW, OLD + sg("new", inline("ingress", "tcp", 443, 443, ["10.0.0.0/8"])))
        self.assertEqual((item.result, item.reason, item.applicable), (P, None, True))

    def test_a_created_group_with_an_unresolved_source_is_unknown(self) -> None:
        text = VARS + OLD + sg("new", inline("ingress", "tcp", 22, 22, "[var.ssh_cidr]"))
        item = verify_baseline(NEW, inputs_for(text, OLD))
        self.assertEqual((item.result, item.reason), (U, R.RULE_INDETERMINATE))

    def test_a_created_group_that_is_mixed_is_unsupported(self) -> None:
        text = (
            OLD
            + sg("new", inline("ingress", "tcp", 443, 443, ["10.0.0.0/8"]))
            + rule(
                "r", "ingress", "tcp", 80, 80, ["10.0.0.0/8"], target="aws_security_group.new.id"
            )
        )
        for address in (NEW, "aws_security_group_rule.r"):
            with self.subTest(address=address):
                item = baseline(address, text)
                self.assertEqual((item.result, item.reason), (S, R.GROUP_MIXED))

    def test_a_created_rule_reports_the_group_it_contributes_to(self) -> None:
        text = OLD + rule("r", "ingress", "tcp", 22, 22, ANY4, target="aws_security_group.db.id")
        item = baseline("aws_security_group_rule.r", text)
        self.assertEqual((item.result, item.reason), (F, R.PREDICATE_VIOLATED))
        self.assertEqual(item.observations["groups"], ["aws_security_group.db"])

    def test_a_created_rule_on_an_external_group_is_a_pseudo_group(self) -> None:
        text = OLD + rule("r", "ingress", "tcp", 22, 22, ANY4, target='"sg-0123abcd"')
        item = baseline("aws_security_group_rule.r", text)
        self.assertEqual(item.result, F)
        self.assertEqual(item.observations["groups"], ["EXTERNAL:sg-0123abcd"])

    def test_the_restriction_never_turns_another_groups_violation_into_a_pass(self) -> None:
        # 'bad' already exists in the parent and is public on 22. The created rule is on 'db' and
        # clean, so its own item passes; the invariant item still carries the global FAIL.
        parent = OLD + sg("bad", inline("ingress", "tcp", 22, 22, ANY4))
        text = parent + rule(
            "r", "ingress", "tcp", 443, 443, ["10.0.0.0/8"], target="aws_security_group.db.id"
        )
        inputs = inputs_for(text, parent)
        item = verify_baseline("aws_security_group_rule.r", inputs)
        self.assertEqual((item.result, item.reason), (P, None))
        self.assertEqual(item.observations["groups"], ["aws_security_group.db"])
        self.assertEqual(evaluate_public_ingress(22, inputs.candidate_resources).result, F)

    def test_a_baseline_without_a_parent(self) -> None:
        item = verify_baseline(NEW, inputs_for(sg("new", inline("ingress", "tcp", 22, 22, ANY4))))
        self.assertEqual(item.result, F)


class TestDatabases(unittest.TestCase):
    def test_public_clean_and_unknown(self) -> None:
        public = baseline("aws_db_instance.database", OLD + db("  publicly_accessible = true\n"))
        self.assertEqual((public.result, public.reason), (F, R.PREDICATE_VIOLATED))
        self.assertEqual(public.observations["value"], "true")
        self.assertEqual(
            (public.verifier_id, public.verifier_version), ("dail.verify.rds_public_flag", "1")
        )
        clean = baseline("aws_db_instance.database", OLD + db())
        self.assertEqual(
            (clean.result, clean.applicable, clean.observations["value"]), (P, True, "absent")
        )
        text = VARS + OLD + db("  publicly_accessible = var.u\n")
        unknown = verify_baseline("aws_db_instance.database", inputs_for(text, OLD))
        self.assertEqual((unknown.result, unknown.reason), (U, R.ATTRIBUTE_UNRESOLVED))

    def test_only_the_created_instance_is_judged(self) -> None:
        parent = OLD + db("  publicly_accessible = true\n", "old")
        text = parent + db(name="new")
        self.assertEqual(baseline("aws_db_instance.new", text, parent).result, P)


class TestOtherTypes(unittest.TestCase):
    def test_a_relevant_unsupported_resource_is_unsupported(self) -> None:
        text = OLD + 'resource "aws_default_security_group" "d" {\n  vpc_id = "vpc-1"\n}\n'
        item = baseline("aws_default_security_group.d", text)
        self.assertEqual(
            (item.result, item.reason, item.applicable), (S, R.TYPE_RELEVANT_UNSUPPORTED, True)
        )

    def test_an_unrelated_type_passes_but_says_it_is_not_applicable(self) -> None:
        text = OLD + 'resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        item = baseline("aws_vpc.v", text)
        self.assertEqual((item.result, item.reason, item.applicable), (P, None, False))
        self.assertEqual(
            item.assumptions, ("registry-v1.0 declares no baseline predicate for aws_vpc",)
        )
        self.assertEqual((item.verifier_id, item.verifier_version), ("dail.verify.baseline", "1"))

    def test_a_placeholder_is_unknown_whatever_its_type(self) -> None:
        for type_name in ("aws_vpc", "aws_security_group", "aws_db_instance"):
            with self.subTest(type=type_name):
                text = VARS + OLD + f'resource "{type_name}" "p" {{\n  count = var.u\n}}\n'
                item = verify_baseline(f"{type_name}.p", inputs_for(text, OLD))
                self.assertEqual((item.result, item.reason), (U, R.RESOURCE_INDETERMINATE))
                self.assertTrue(item.applicable)

    def test_an_unreadable_created_resource_is_unsupported_not_a_pass(self) -> None:
        # content too deep to keep: UNSUPPORTED, with the reason in place of the content
        for type_name, address in (
            ("aws_security_group", "aws_security_group.new"),
            ("aws_db_instance", "aws_db_instance.database"),
        ):
            with self.subTest(type=type_name):
                inputs = inputs_for(OLD + sg("new") + db(), OLD)
                base = next(r for r in inputs.candidate_resources if r.address == address)
                broken = Resource.create(
                    address=address,
                    resource_type=type_name,
                    logical_identity={},
                    attributes={"$content": {"$dail": "unsupported", "reason": "limit.json_depth"}},
                    security_attributes={},
                    semantic_attributes={},
                    references=(),
                    provenance=base.provenance,
                    support_status=ResourceSupport.UNSUPPORTED,
                )
                rest = [r for r in inputs.candidate_resources if r.address != address]
                swapped = dataclasses.replace(inputs, candidate_resources=(*rest, broken))
                item = verify_baseline(address, swapped)
                self.assertEqual((item.result, item.reason), (S, R.RULE_UNSUPPORTED))

    def test_a_resource_the_candidate_does_not_have(self) -> None:
        item = baseline("aws_vpc.nowhere", OLD)
        self.assertEqual((item.result, item.reason), (S, R.STRUCTURAL_FINDING))

    def test_a_definition_set_without_the_invariant_is_unsupported_not_a_pass(self) -> None:
        inputs = inputs_for(OLD + sg("new"), OLD)
        without = dataclasses.replace(
            inputs,
            invariants=tuple(i for i in inputs.invariants if i.invariant_id != "INV-SEC-001"),
        )
        item = verify_baseline(NEW, without)
        self.assertEqual((item.result, item.reason), (S, R.INVARIANT_UNKNOWN))


if __name__ == "__main__":
    unittest.main()
