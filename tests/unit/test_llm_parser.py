"""The structured-response parser (P7a; Doc 10 §11, §22, §25; C-183, C-184, C-187).

Expected values come from the quoted spec text:

§11 "LLMRepairResponse { schema_version, status = PATCH | NO_SOLUTION | UNCERTAIN | INVALID,
summary, patch, changed_addresses[], assumptions[], rationale }. status: required enum. ...
patch: Terraform HCL patch or null depending on status. ... assumptions: explicit assumptions;
never treated as verified facts. rationale: generation explanation; not a safety proof."

§22 "Malformed JSON/schema: INVALID ... Missing patch: NO_SOLUTION or INVALID ... Unsupported
resource: reject/UNSUPPORTED. Forbidden operation: reject. Ambiguous patch boundaries: reject; never
guess. Extraneous text in structured-only mode: reject or parse only under explicitly versioned
tolerant parser." P7a has no tolerant parser.

§25 "Any confidence score returned by the model is advisory metadata only."
"""

from __future__ import annotations

import json
import unittest

from llm.schemas.records import FailureClass
from llm.schemas.repair_response import RESPONSE_SCHEMA_VERSION, RepairStatus
from llm.validation.parser import PARSER_VERSION, parse_response
from tests.llm_builders import reply

F = FailureClass
TYPES = ("aws_security_group", "aws_security_group_rule", "aws_instance", "aws_db_instance")
SCOPE = ("aws_security_group.app", "aws_security_group_rule.app_ssh_public")


def parse(raw: str):  # type: ignore[no-untyped-def]
    return parse_response(raw, allowed_types=TYPES, allowed_scope=SCOPE)


def body(**changes: object) -> dict[str, object]:
    data = json.loads(reply())
    data.update(changes)
    return data


class TestValid(unittest.TestCase):
    def test_a_valid_patch(self) -> None:
        outcome = parse(reply())
        self.assertIsNone(outcome.failure_class)
        self.assertEqual(outcome.errors, ())
        assert outcome.response is not None
        self.assertIs(outcome.response.status, RepairStatus.PATCH)
        self.assertIn("aws_security_group", outcome.response.patch or "")
        self.assertEqual(
            outcome.response.changed_addresses, ("aws_security_group_rule.app_ssh_public",)
        )
        self.assertEqual(outcome.response.schema_version, RESPONSE_SCHEMA_VERSION)
        self.assertEqual(outcome.parser_version, PARSER_VERSION)

    def test_whitespace_around_the_object_is_not_extraneous_text(self) -> None:
        self.assertIsNone(parse("\n  " + reply() + "\n").failure_class)

    def test_no_solution_without_a_patch(self) -> None:
        outcome = parse(reply("NO_SOLUTION"))
        self.assertIs(outcome.failure_class, F.NO_SOLUTION)
        assert outcome.response is not None
        self.assertIs(outcome.response.status, RepairStatus.NO_SOLUTION)

    def test_uncertain_without_a_patch_is_an_inability_signal(self) -> None:
        outcome = parse(reply("UNCERTAIN"))
        assert outcome.response is not None
        self.assertIs(outcome.response.status, RepairStatus.UNCERTAIN)
        self.assertIs(outcome.failure_class, F.NO_SOLUTION)

    def test_a_model_that_reports_its_own_output_invalid(self) -> None:
        outcome = parse(reply("INVALID"))
        self.assertIs(outcome.failure_class, F.INVALID_OUTPUT)

    def test_assumptions_and_rationale_are_kept_as_text_only(self) -> None:
        outcome = parse(reply())
        assert outcome.response is not None
        self.assertEqual(outcome.response.assumptions, ("the app group keeps its egress rule",))
        self.assertEqual(outcome.response.rationale, "the rule opens 22 to 0.0.0.0/0")


class TestInvalidOutput(unittest.TestCase):
    def assert_invalid(self, raw: str) -> None:
        outcome = parse(raw)
        self.assertIs(outcome.failure_class, F.INVALID_OUTPUT, outcome.errors)
        self.assertIsNone(outcome.response)
        self.assertTrue(outcome.errors)

    def test_malformed_json(self) -> None:
        self.assert_invalid('{"status": "PATCH",')
        self.assert_invalid("")
        self.assert_invalid("PATCH")

    def test_not_an_object(self) -> None:
        self.assert_invalid(json.dumps([body()]))
        self.assert_invalid('"PATCH"')

    def test_a_missing_required_field(self) -> None:
        for name in (
            "schema_version",
            "status",
            "summary",
            "patch",
            "changed_addresses",
            "assumptions",
            "rationale",
        ):
            data = body()
            del data[name]
            with self.subTest(field=name):
                self.assert_invalid(json.dumps(data))

    def test_an_unknown_status(self) -> None:
        self.assert_invalid(json.dumps(body(status="DONE")))
        self.assert_invalid(json.dumps(body(status="patch")))

    def test_patch_with_a_null_or_empty_patch(self) -> None:
        for value in (None, "", "   \n"):
            with self.subTest(patch=value):
                self.assert_invalid(json.dumps(body(patch=value)))

    def test_no_solution_with_a_patch(self) -> None:
        data = json.loads(reply("NO_SOLUTION"))
        data["patch"] = 'resource "aws_security_group" "x" {}'
        self.assert_invalid(json.dumps(data))

    def test_extra_fields_are_rejected(self) -> None:
        self.assert_invalid(json.dumps(body(verified=True)))
        self.assert_invalid(json.dumps(body(promote=True)))

    def test_text_around_the_json_is_rejected(self) -> None:
        self.assert_invalid("Here is the patch:\n" + reply())
        self.assert_invalid(reply() + "\nHope this helps.")
        self.assert_invalid("```json\n" + reply() + "\n```")

    def test_wrong_types(self) -> None:
        for name, value in (
            ("summary", 3),
            ("summary", ""),
            ("patch", ["x"]),
            ("changed_addresses", "aws_security_group.app"),
            ("changed_addresses", [1]),
            ("changed_addresses", ["aws_security_group.app", "aws_security_group.app"]),
            ("assumptions", "one"),
            ("assumptions", [None]),
            ("rationale", None),
            ("schema_version", "dail-llm-repair-response/0"),
        ):
            with self.subTest(field=name, value=value):
                self.assert_invalid(json.dumps(body(**{name: value})))

    def test_duplicate_keys_and_non_json_numbers_are_rejected(self) -> None:
        self.assert_invalid(reply()[:-1] + ', "status": "NO_SOLUTION"}')
        self.assert_invalid(json.dumps(body()).replace('"patch"', '"confidence": NaN, "patch"'))

    def test_a_patch_without_declared_addresses_has_ambiguous_boundaries(self) -> None:
        self.assert_invalid(json.dumps(body(changed_addresses=[])))


class TestScopeAndSupport(unittest.TestCase):
    def test_a_changed_address_of_an_unsupported_type(self) -> None:
        outcome = parse(json.dumps(body(changed_addresses=["aws_lambda_function.f"])))
        self.assertIs(outcome.failure_class, F.UNSUPPORTED)

    def test_a_changed_address_outside_the_allowed_scope(self) -> None:
        outcome = parse(json.dumps(body(changed_addresses=["aws_db_instance.database"])))
        self.assertIs(outcome.failure_class, F.POLICY_VIOLATION)

    def test_a_malformed_address_is_invalid_output(self) -> None:
        outcome = parse(json.dumps(body(changed_addresses=["not an address"])))
        self.assertIs(outcome.failure_class, F.INVALID_OUTPUT)


class TestConfidence(unittest.TestCase):
    def test_a_confidence_is_kept_as_metadata_only(self) -> None:
        high = parse(json.dumps(body(confidence=0.99)))
        low = parse(json.dumps(body(confidence=0.01)))
        none = parse(reply())
        assert high.response and low.response and none.response
        self.assertEqual(high.response.confidence, 0.99)
        self.assertIsNone(none.response.confidence)
        # it changes nothing else: status, failure class and patch are the same
        for outcome in (high, low):
            self.assertIs(outcome.failure_class, none.failure_class)
            self.assertIs(outcome.response.status, none.response.status)
            self.assertEqual(outcome.response.patch, none.response.patch)

    def test_a_confidence_never_rescues_an_invalid_response(self) -> None:
        outcome = parse(json.dumps(body(patch=None, confidence=1.0)))
        self.assertIs(outcome.failure_class, F.INVALID_OUTPUT)

    def test_a_confidence_of_the_wrong_type_is_invalid(self) -> None:
        for value in ("very", True, [0.5], {"p": 1}):
            with self.subTest(value=value):
                outcome = parse(json.dumps(body(confidence=value)))
                self.assertIs(outcome.failure_class, F.INVALID_OUTPUT)


if __name__ == "__main__":
    unittest.main()
