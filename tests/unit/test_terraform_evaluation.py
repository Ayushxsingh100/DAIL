"""Configuration evaluation: variables, locals, limits, modules and the move table (P3a-2 step 5;
Doc 04 §4, §17; C-92, C-100 to C-105).

Facts about Terraform 1.15.8 behind the expectations were measured with ``terraform validate``
and ``terraform plan`` (builtin ``terraform_data`` resources, scratch directories outside the
repository, no credentials) or taken from ``internal/refactoring/move_validate.go`` at tag v1.15.8.
"""

from __future__ import annotations

import ast
import dataclasses
import tempfile
import unittest
from pathlib import Path

from core.domain.errors import DomainValidationError, UnauthorizedConstructionError
from core.domain.hashing import content_hash
from core.terraform_model import evaluation as evaluation_module
from core.terraform_model.config import (
    PARSER_VERSION,
    ParsedConfiguration,
    ParseStatus,
    load_configuration,
)
from core.terraform_model.evaluation import (
    EVALUATOR_VERSION,
    EvaluationOutcome,
    evaluate_configuration,
)
from core.terraform_model.instances import (
    MAX_INSTANCES_PER_CONFIGURATION,
    MAX_INSTANCES_PER_RESOURCE,
)
from core.terraform_model.values import (
    NULL,
    TRUE,
    Known,
    Ref,
    Unknown,
    Unsupported,
    Value,
    ValueModelError,
    known_object,
    known_tuple,
)

ROOT = Path(__file__).resolve().parents[2]
OK = ParseStatus.OK
INVALID = ParseStatus.INVALID
UNSUPPORTED = ParseStatus.UNSUPPORTED


def parse(text: str) -> ParsedConfiguration:
    with tempfile.TemporaryDirectory() as directory:
        (Path(directory) / "main.tf").write_text(text, encoding="utf-8", newline="\n")
        outcome = load_configuration(Path(directory))
    assert outcome.status is OK, outcome.diagnostics
    assert outcome.configuration is not None
    return outcome.configuration


def run(text: str, variables: dict[str, object] | None = None) -> EvaluationOutcome:
    return evaluate_configuration(parse(text), variables)


def codes(outcome: EvaluationOutcome) -> list[str]:
    return [d.code for d in outcome.diagnostics]


def tup(*items: object) -> Value:
    from core.terraform_model.values import from_json

    return known_tuple(
        i if isinstance(i, Known | Unknown | Unsupported | Ref) else from_json(i) for i in items
    )


class TestOutcome(unittest.TestCase):
    TEXT = (
        'variable "env" {\n  default = "dev"\n}\n'
        'locals {\n  name = "app-${var.env}"\n}\n'
        'resource "aws_vpc" "main" {\n  tag = local.name\n}\n'
        'resource "aws_subnet" "s" {\n  count = 2\n  vpc = aws_vpc.main.id\n}\n'
    )

    def test_a_valid_configuration_is_ok_with_its_data(self) -> None:
        parsed = parse(self.TEXT)
        outcome = evaluate_configuration(parsed, {"env": "prod"})
        self.assertEqual(outcome.status, OK)
        self.assertEqual(outcome.diagnostics, ())
        self.assertEqual(
            list(outcome.instances), ["aws_subnet.s[0]", "aws_subnet.s[1]", "aws_vpc.main"]
        )
        self.assertEqual(
            outcome.instances["aws_vpc.main"].arguments["tag"].value, Known("app-prod")
        )
        self.assertEqual(
            outcome.instances["aws_subnet.s[1]"].arguments["vpc"].value, Ref("aws_vpc.main", "id")
        )
        self.assertEqual(dict(outcome.variables), {"env": Known("prod")})
        self.assertEqual(dict(outcome.locals), {"name": Known("app-prod")})
        self.assertEqual(outcome.moves, ())
        self.assertEqual(dict(outcome.indeterminate), {})

    def test_versions_and_hashes(self) -> None:
        parsed = parse(self.TEXT)
        outcome = evaluate_configuration(parsed, {"env": "prod"})
        self.assertEqual(outcome.evaluator_version, "dail-tf-eval-1")
        self.assertEqual(EVALUATOR_VERSION, "dail-tf-eval-1")
        self.assertEqual(outcome.parser_version, PARSER_VERSION)
        self.assertEqual(outcome.configuration_hash, parsed.configuration_hash)
        self.assertEqual(outcome.variables_hash, content_hash({"env": "prod"}))

    def test_the_variables_hash_follows_the_scenario_not_its_order(self) -> None:
        parsed = parse('variable "a" {}\nvariable "b" {}\n')
        first = evaluate_configuration(parsed, {"a": 1, "b": [1, 2]})
        second = evaluate_configuration(parsed, {"b": [1, 2], "a": 1})
        other = evaluate_configuration(parsed, {"a": 2, "b": [1, 2]})
        none = evaluate_configuration(parsed)
        self.assertEqual(first.variables_hash, second.variables_hash)
        self.assertNotEqual(first.variables_hash, other.variables_hash)
        self.assertEqual(none.variables_hash, evaluate_configuration(parsed, {}).variables_hash)
        self.assertNotEqual(none.variables_hash, first.variables_hash)

    def test_evaluation_is_deterministic(self) -> None:
        parsed = parse(self.TEXT)
        first = evaluate_configuration(parsed, {"env": "x"})
        second = evaluate_configuration(parsed, {"env": "x"})
        self.assertEqual(first, second)

    def test_the_outcome_is_guarded_and_frozen(self) -> None:
        outcome = run(self.TEXT)
        fields = {f.name: getattr(outcome, f.name) for f in dataclasses.fields(outcome)}
        with self.assertRaises(UnauthorizedConstructionError):
            EvaluationOutcome(**fields)
        with self.assertRaises(UnauthorizedConstructionError):
            EvaluationOutcome(**fields, _token=object())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            outcome.status = INVALID  # type: ignore[misc]
        with self.assertRaises(TypeError):
            outcome.instances["x"] = outcome.instances["aws_vpc.main"]  # type: ignore[index]

    def test_the_guard_checks_what_the_outcome_claims(self) -> None:
        outcome = run(self.TEXT)
        token = evaluation_module._OUTCOME_TOKEN
        fields = {f.name: getattr(outcome, f.name) for f in dataclasses.fields(outcome)}
        with self.assertRaises(DomainValidationError):
            EvaluationOutcome(
                **{**fields, "status": UNSUPPORTED}, _token=token
            )  # status vs diagnostics
        with self.assertRaises(DomainValidationError):
            EvaluationOutcome(
                **{**fields, "instances": dict(reversed(list(outcome.instances.items())))},
                _token=token,
            )
        with self.assertRaises(DomainValidationError):
            EvaluationOutcome(
                **{**fields, "instances": {"aws_vpc.other": outcome.instances["aws_vpc.main"]}},
                _token=token,
            )
        broken = run('module "m" {\n  source = "./m"\n}\n')
        broken_fields = {f.name: getattr(broken, f.name) for f in dataclasses.fields(broken)}
        with self.assertRaises(DomainValidationError):
            EvaluationOutcome(
                **{**broken_fields, "moves": (("a.b", "a.c"),)}, _token=token
            )  # data without OK
        two = run('module "a" {\n  source = "./a"\n}\nmodule "b" {\n  source = "./b"\n}\n')
        two_fields = {f.name: getattr(two, f.name) for f in dataclasses.fields(two)}
        self.assertEqual(len(two.diagnostics), 2)
        with self.assertRaises(DomainValidationError):
            EvaluationOutcome(
                **{**two_fields, "diagnostics": tuple(reversed(two.diagnostics))}, _token=token
            )

    def test_data_is_present_only_when_ok(self) -> None:
        outcome = run(
            'variable "v" {\n'
            "  default = 1\n"
            "}\n"
            'resource "aws_x" "x" {}\n'
            'module "m" {\n'
            '  source = "./m"\n'
            "}\n"
        )
        self.assertEqual(outcome.status, UNSUPPORTED)
        self.assertEqual(
            (dict(outcome.instances), dict(outcome.variables), dict(outcome.locals), outcome.moves),
            ({}, {}, {}, ()),
        )
        self.assertRegex(outcome.variables_hash, r"^[0-9a-f]{64}$")


class TestVariables(unittest.TestCase):
    def values(self, declaration: str, variables: dict[str, object] | None = None) -> Value:
        outcome = run(f'variable "v" {{\n{declaration}\n}}\n', variables)
        self.assertEqual(outcome.status, OK, outcome.diagnostics)
        return outcome.variables["v"]

    def test_scenario_value_then_default_then_unknown(self) -> None:
        self.assertEqual(self.values('  default = "d"', {"v": "s"}), Known("s"))
        self.assertEqual(self.values('  default = "d"'), Known("d"))
        self.assertEqual(self.values("  type = string"), Unknown("variable.no_value"))
        self.assertEqual(self.values("  type = string", {"v": "x"}), Known("x"))

    def test_a_scenario_value_replaces_the_default_entirely(self) -> None:
        self.assertEqual(self.values('  default = ["a", "b"]', {"v": ["c"]}), tup("c"))

    def test_json_values(self) -> None:
        self.assertEqual(
            self.values("  type = any", {"v": {"a": [1, True, None], "b": "x"}}),
            known_object({"a": tup(1, True, None), "b": Known("x")}),
        )

    def test_type_constraints_convert_the_value(self) -> None:
        cases = [
            ("string", 5, Known("5")),
            ("number", "7", Known(7)),
            ("bool", "true", TRUE),
            ("list(string)", [1, 2], tup("1", "2")),
            ("map(number)", {"a": "1"}, known_object({"a": Known(1)})),
            (
                "object({a = string, b = optional(number, 3)})",
                {"a": "x"},
                known_object({"a": Known("x"), "b": Known(3)}),
            ),
            ("tuple([string, number])", ["a", "1"], tup("a", 1)),
        ]
        for constraint, raw, expected in cases:
            with self.subTest(constraint=constraint):
                self.assertEqual(self.values(f"  type = {constraint}", {"v": raw}), expected)

    def test_defaults_are_converted_too(self) -> None:
        self.assertEqual(self.values('  type = number\n  default = "5"'), Known(5))

    def test_a_failed_conversion_or_unreadable_constraint_is_unsupported(self) -> None:
        self.assertEqual(
            self.values("  type = number", {"v": "abc"}), Unsupported("variable.type_mismatch")
        )
        self.assertEqual(
            self.values("  type = list(string)", {"v": {"a": 1}}),
            Unsupported("variable.type_mismatch"),
        )
        self.assertEqual(
            self.values("  type = object({a = string})", {"v": {}}),
            Unsupported("variable.type_mismatch"),
        )
        self.assertEqual(self.values("  type = strnig"), Unsupported("variable.type_constraint"))
        self.assertEqual(self.values("  type = list"), Unsupported("variable.type_constraint"))

    def test_null_and_nullable(self) -> None:
        self.assertEqual(
            self.values('  default = "d"', {"v": None}), NULL
        )  # nullable defaults to true
        self.assertEqual(
            self.values('  default = "d"\n  nullable = false', {"v": None}), Known("d")
        )
        self.assertEqual(
            self.values("  nullable = false", {"v": None}), Unsupported("variable.null_not_allowed")
        )
        # nullable must be a literal bool
        outcome = run(
            'variable "x" {\n  default = true\n}\nvariable "v" {\n  nullable = true && true\n}\n'
        )
        self.assertEqual(outcome.variables["v"], Unknown("variable.no_value"))
        bad = run('variable "v" {\n  nullable = "yes"\n}\n')
        self.assertEqual(bad.variables["v"], Unsupported("variable.nullable"))

    def test_unused_variables_are_still_in_the_outcome(self) -> None:
        outcome = run('variable "a" {}\nvariable "b" {\n  default = 2\n}\n')
        self.assertEqual(
            dict(outcome.variables), {"a": Unknown("variable.no_value"), "b": Known(2)}
        )

    def test_a_default_cannot_refer_to_anything(self) -> None:
        # validate: "Variables not allowed" in a default; here the reference is undeclared
        outcome = run('variable "a" {\n  default = 1\n}\nvariable "b" {\n  default = var.a\n}\n')
        self.assertEqual(outcome.status, INVALID)

    def test_a_default_may_call_functions(self) -> None:
        self.assertEqual(self.values('  default = upper("a")'), Known("A"))

    def test_a_scenario_value_for_an_undeclared_variable_is_unsupported(self) -> None:
        # Measured: `-var nope=1` is an error, a tfvars file only warns, TF_VAR_nope is ignored
        outcome = run('variable "a" {\n  default = 1\n}\n', {"nope": 1})
        self.assertEqual(outcome.status, UNSUPPORTED)
        self.assertEqual(codes(outcome), ["eval.undeclared_variable_value"])
        self.assertIn("nope", outcome.diagnostics[0].message)

    def test_floats_are_refused(self) -> None:
        with self.assertRaises(ValueModelError):
            run('variable "a" {}\n', {"a": 1.5})
        with self.assertRaises(ValueModelError):
            run('variable "a" {}\n', {"a": [1, {"b": 2.0}]})

    def test_a_validation_block_is_noted_when_the_variable_is_used(self) -> None:
        text = (
            'variable "port" {\n'
            "  type = number\n"
            "  validation {\n"
            "    condition = var.port > 0\n"
            '    error_message = "x"\n'
            "  }\n"
            "}\n"
            'variable "other" {\n  default = 1\n}\n'
            'resource "aws_x" "x" {\n  p = var.port\n  o = var.other\n}\n'
        )
        used = run(text, {"port": 22})
        self.assertEqual(used.status, OK)
        self.assertEqual([d.code for d in used.diagnostics], ["eval.variable_validation"])
        self.assertEqual(used.diagnostics[0].severity.value, "UNSUPPORTED_CONSTRUCT")
        self.assertEqual(used.instances["aws_x.x"].arguments["p"].value, Known(22))
        unused = run(text.replace("p = var.port", "p = 1"), {"port": 22})
        self.assertEqual(unused.diagnostics, ())

    def test_the_validation_condition_is_not_evaluated(self) -> None:
        text = (
            'variable "v" {\n'
            "  validation {\n"
            "    condition = var.v > 100\n"
            '    error_message = "x"\n'
            "  }\n"
            "}\n"
            'resource "aws_x" "x" {\n'
            "  v = var.v\n"
            "}\n"
        )
        outcome = run(text, {"v": 1})  # the condition is false; the value is still the value
        self.assertEqual(outcome.instances["aws_x.x"].arguments["v"].value, Known(1))


class TestLocals(unittest.TestCase):
    def test_locals_chain_and_are_reported(self) -> None:
        text = "locals {\n  a = 1\n  b = local.a + 1\n  c = [local.a, local.b]\n}\n"
        outcome = run(text)
        self.assertEqual(outcome.status, OK)
        self.assertEqual(dict(outcome.locals), {"a": Known(1), "b": Known(2), "c": tup(1, 2)})

    def test_an_unknown_input_makes_the_local_unknown(self) -> None:
        outcome = run('variable "v" {}\nlocals {\n  a = var.v\n  b = "${local.a}-x"\n}\n')
        self.assertEqual(
            dict(outcome.locals),
            {"a": Unknown("variable.no_value"), "b": Unknown("variable.no_value")},
        )

    def test_a_cycle_is_invalid(self) -> None:
        # validate: Error: Cycle: local.b (expand), local.a (expand)
        outcome = run("locals {\n  a = local.b\n  b = local.a\n}\n")
        self.assertEqual(outcome.status, INVALID)
        self.assertIn("eval.cycle", codes(outcome))
        self.assertEqual(dict(outcome.locals), {})

    def test_a_local_that_uses_a_resource(self) -> None:
        text = (
            'resource "aws_vpc" "v" {\n'
            '  cidr = "10.0.0.0/16"\n'
            "}\n"
            "locals {\n"
            "  c = aws_vpc.v.cidr\n"
            "  i = aws_vpc.v.id\n"
            "}\n"
        )
        outcome = run(text)
        self.assertEqual(
            dict(outcome.locals), {"c": Known("10.0.0.0/16"), "i": Ref("aws_vpc.v", "id")}
        )

    def test_locals_are_evaluated_when_unused(self) -> None:
        outcome = run("locals {\n  x = local.nope\n}\n")
        self.assertEqual(outcome.status, INVALID)
        self.assertEqual(codes(outcome), ["eval.undeclared_reference"])


class TestInvalidFindings(unittest.TestCase):
    """What terraform validate rejects is INVALID."""

    def status(self, text: str) -> tuple[ParseStatus, list[str]]:
        outcome = run(text)
        return outcome.status, codes(outcome)

    def test_each_of_them(self) -> None:
        cases = {
            "undeclared variable": (
                'resource "aws_x" "x" {\n  a = var.nope\n}\n',
                "eval.undeclared_reference",
            ),
            "undeclared local": (
                'resource "aws_x" "x" {\n  a = local.nope\n}\n',
                "eval.undeclared_reference",
            ),
            "undeclared resource": (
                'resource "aws_x" "x" {\n  a = aws_y.y.id\n}\n',
                "eval.undeclared_reference",
            ),
            "undeclared data": (
                'resource "aws_x" "x" {\n  a = data.aws_y.y.id\n}\n',
                "eval.undeclared_reference",
            ),
            "each without for_each": (
                'resource "aws_x" "x" {\n  a = each.key\n}\n',
                "eval.each_context",
            ),
            "count.index without count": (
                'resource "aws_x" "x" {\n  a = count.index\n}\n',
                "eval.count_context",
            ),
            "count and for_each": (
                'resource "aws_x" "x" {\n  count = 1\n  for_each = {}\n}\n',
                "eval.count_and_for_each",
            ),
            "attribute and block": (
                'resource "aws_x" "x" {\n  a = []\n  a {\n    b = 1\n  }\n}\n',
                "eval.attribute_and_block",
            ),
            "resource cycle": (
                'resource "aws_x" "x" {\n'
                "  a = aws_y.y.b\n"
                "}\n"
                'resource "aws_y" "y" {\n'
                "  b = aws_x.x.a\n"
                "}\n",
                "eval.resource_cycle",
            ),
            "each in count": (
                'resource "aws_x" "x" {\n  count = 1\n  a = each.key\n}\n',
                "eval.each_context",
            ),
        }
        for label, (text, code) in cases.items():
            with self.subTest(label):
                status, found = self.status(text)
                self.assertEqual(status, INVALID)
                self.assertIn(code, found)

    def test_a_reference_in_a_branch_not_taken_still_counts(self) -> None:
        status, found = self.status('resource "aws_x" "x" {\n  a = true ? 1 : var.nope\n}\n')
        self.assertEqual((status, found), (INVALID, ["eval.undeclared_reference"]))

    def test_per_value_problems_do_not_change_the_status(self) -> None:
        text = (
            'variable "v" {}\n'
            'resource "aws_x" "x" {\n  a = var.v\n  b = abs(1)\n  c = [1][5]\n}\n'
        )
        outcome = run(text)
        self.assertEqual((outcome.status, outcome.diagnostics), (OK, ()))
        arguments = outcome.instances["aws_x.x"].arguments
        self.assertEqual(arguments["a"].value, Unknown("variable.no_value"))
        self.assertEqual(arguments["b"].value, Unsupported("function.not_implemented:abs"))
        self.assertEqual(arguments["c"].value, Unsupported("eval.invalid_index"))

    def test_invalid_wins_over_unsupported(self) -> None:
        outcome = run(
            'module "m" {\n  source = "./m"\n}\nresource "aws_x" "x" {\n  a = var.nope\n}\n'
        )
        self.assertEqual(outcome.status, INVALID)
        self.assertEqual(sorted(codes(outcome)), ["eval.module_call", "eval.undeclared_reference"])


class TestWholeConfigurationUnsupported(unittest.TestCase):
    def test_a_module_call(self) -> None:
        outcome = run('module "net" {\n  source = "./net"\n}\n')
        self.assertEqual((outcome.status, codes(outcome)), (UNSUPPORTED, ["eval.module_call"]))
        self.assertIn("net", outcome.diagnostics[0].message)
        self.assertEqual(outcome.diagnostics[0].line, 1)

    def test_a_reference_to_a_module_is_unsupported_not_invalid(self) -> None:
        outcome = run(
            'module "net" {\n'
            '  source = "./net"\n'
            "}\n"
            'resource "aws_x" "x" {\n'
            "  a = module.net.id\n"
            "}\n"
        )
        self.assertEqual(outcome.status, UNSUPPORTED)

    def many(self, resources: int, per_resource: int) -> str:
        return "".join(
            f'resource "aws_x" "r{i}" {{\n  count = {per_resource}\n}}\n' for i in range(resources)
        )

    def test_a_resource_that_refers_to_itself(self) -> None:
        # Terraform 1.15.8: validate accepts it, plan fails ("Self-referential block")
        for body in ("a = aws_x.x.id", "a = aws_x.x.a", "count = length(aws_x.x)"):
            with self.subTest(body=body):
                outcome = run('resource "aws_x" "x" {\n  ' + body + "\n}\n")
                self.assertEqual(
                    (outcome.status, codes(outcome)), (UNSUPPORTED, ["eval.self_reference"])
                )

    def test_the_instance_limit_of_the_configuration(self) -> None:
        at_limit = run(self.many(10, 1000))
        self.assertEqual(
            (at_limit.status, len(at_limit.instances)), (OK, MAX_INSTANCES_PER_CONFIGURATION)
        )
        over = run(self.many(10, 1000) + 'resource "aws_x" "extra" {}\n')
        self.assertEqual(
            (over.status, codes(over)), (UNSUPPORTED, ["limit.instances_per_configuration"])
        )
        self.assertEqual(dict(over.instances), {})

    def test_the_instance_limit_of_one_resource(self) -> None:
        at_limit = run(self.many(1, MAX_INSTANCES_PER_RESOURCE))
        self.assertEqual(
            (at_limit.status, len(at_limit.instances)), (OK, MAX_INSTANCES_PER_RESOURCE)
        )
        over = run(self.many(1, MAX_INSTANCES_PER_RESOURCE + 1))
        self.assertEqual(
            (over.status, codes(over)), (UNSUPPORTED, ["limit.instances_per_resource"])
        )

    def test_unknown_and_unsupported_expansion_do_not_count(self) -> None:
        text = (
            'variable "n" {}\n'
            'resource "aws_x" "x" {\n'
            "  count = var.n\n"
            "}\n"
            'resource "aws_y" "y" {\n'
            '  for_each = ["a"]\n'
            "}\n"
        )
        outcome = run(text)
        self.assertEqual(outcome.status, OK)
        self.assertEqual(sorted(outcome.indeterminate), ["aws_x.x", "aws_y.y"])
        self.assertEqual(dict(outcome.instances), {})
        self.assertEqual(
            outcome.indeterminate["aws_x.x"].reason,
            Unknown("expansion.count_unknown:variable.no_value"),
        )
        self.assertEqual(outcome.indeterminate["aws_y.y"].reason, Unsupported("for_each.list"))


class TestMoves(unittest.TestCase):
    BASE = 'resource "aws_x" "new" {}\n'

    def moves(self, text: str) -> EvaluationOutcome:
        return run(self.BASE + text)

    def test_static_pairs_in_canonical_syntax(self) -> None:
        outcome = self.moves(
            "moved {\n  from = aws_x.old\n  to = aws_x.new\n}\n"
            'moved {\n  from = aws_x.a[0]\n  to = aws_x.b["k"]\n}\n'
            'moved {\n  from = aws_x.c["q\\"r"]\n  to = aws_x.d[2]\n}\n'
        )
        self.assertEqual(outcome.status, OK, outcome.diagnostics)
        self.assertEqual(
            outcome.moves,
            (
                ("aws_x.old", "aws_x.new"),
                ("aws_x.a[0]", 'aws_x.b["k"]'),
                ('aws_x.c["q' + chr(92) + '"r"]', "aws_x.d[2]"),
            ),
        )

    def test_moves_are_not_applied(self) -> None:
        text = 'resource "aws_x" "keep" {}\nmoved {\n  from = aws_x.gone\n  to = aws_x.keep\n}\n'
        outcome = run(text)
        self.assertEqual(list(outcome.instances), ["aws_x.keep"])
        self.assertEqual(outcome.moves, (("aws_x.gone", "aws_x.keep"),))

    def test_chains_are_allowed(self) -> None:
        outcome = self.moves(
            "moved {\n"
            "  from = aws_x.a\n"
            "  to = aws_x.b\n"
            "}\n"
            "moved {\n"
            "  from = aws_x.b\n"
            "  to = aws_x.new\n"
            "}\n"
        )
        self.assertEqual(outcome.status, OK, outcome.diagnostics)
        self.assertEqual(outcome.moves, (("aws_x.a", "aws_x.b"), ("aws_x.b", "aws_x.new")))

    def test_the_same_move_twice_is_not_ambiguous(self) -> None:
        stmt = "moved {\n  from = aws_x.a\n  to = aws_x.new\n}\n"
        self.assertEqual(self.moves(stmt + stmt).status, OK)

    def test_to_an_address_that_is_not_declared_is_not_a_configuration_error(self) -> None:
        self.assertEqual(
            self.moves("moved {\n  from = aws_x.a\n  to = aws_x.nowhere\n}\n").status, OK
        )

    def test_count_transitions(self) -> None:
        text = (
            'resource "aws_y" "y" {\n'
            "  count = 2\n"
            "}\n"
            "moved {\n"
            "  from = aws_y.old\n"
            "  to = aws_y.y[0]\n"
            "}\n"
        )
        outcome = run(text)
        self.assertEqual((outcome.status, outcome.moves), (OK, (("aws_y.old", "aws_y.y[0]"),)))

    def test_what_is_not_a_static_resource_address(self) -> None:
        cases = [
            "to = aws_x.new\n  from = module.m.aws_x.a",
            "from = data.aws_x.a\n  to = aws_x.new",
            'from = aws_x.a["${var.k}"]\n  to = aws_x.new',
            "from = aws_x.a[var.i]\n  to = aws_x.new",
            "from = aws_x.a[-1]\n  to = aws_x.new",
            "from = aws_x\n  to = aws_x.new",
            "from = aws_x.a.b\n  to = aws_x.new",
            'from = lower("a")\n  to = aws_x.new',
            "from = aws_x.a[1.5]\n  to = aws_x.new",
            "from = aws_x.a[true]\n  to = aws_x.new",
        ]
        for body in cases:
            with self.subTest(body=body):
                outcome = self.moves("moved {\n  " + body + "\n}\n")
                self.assertEqual(
                    (outcome.status, codes(outcome)), (UNSUPPORTED, ["eval.move_not_static"])
                )

    def test_a_move_between_types(self) -> None:
        outcome = self.moves("moved {\n  from = aws_y.a\n  to = aws_x.new\n}\n")
        self.assertEqual((outcome.status, codes(outcome)), (UNSUPPORTED, ["eval.move_type_change"]))

    def test_a_move_to_itself(self) -> None:
        outcome = self.moves("moved {\n  from = aws_x.a\n  to = aws_x.a\n}\n")
        self.assertEqual((outcome.status, codes(outcome)), (UNSUPPORTED, ["eval.move_redundant"]))

    def test_the_source_still_declared(self) -> None:
        # ValidateMoves: "Moved object still exists"
        outcome = self.moves("moved {\n  from = aws_x.new\n  to = aws_x.other\n}\n")
        self.assertEqual((outcome.status, codes(outcome)), (UNSUPPORTED, ["eval.move_from_exists"]))

    def test_an_instance_source_that_still_exists(self) -> None:
        text = 'resource "aws_y" "y" {\n  count = 2\n}\n'
        exists = run(text + "moved {\n  from = aws_y.y[1]\n  to = aws_y.z\n}\n")
        self.assertEqual(codes(exists), ["eval.move_from_exists"])
        gone = run(text + "moved {\n  from = aws_y.y[2]\n  to = aws_y.z\n}\n")
        self.assertEqual((gone.status, gone.moves), (OK, (("aws_y.y[2]", "aws_y.z"),)))
        whole = run(text + "moved {\n  from = aws_y.y\n  to = aws_y.z\n}\n")
        self.assertEqual(codes(whole), ["eval.move_from_exists"])

    def test_an_instance_source_of_a_resource_with_unknown_expansion(self) -> None:
        text = (
            'variable "n" {}\n'
            'resource "aws_y" "y" {\n'
            "  count = var.n\n"
            "}\n"
            "moved {\n"
            "  from = aws_y.y[0]\n"
            "  to = aws_y.z\n"
            "}\n"
        )
        self.assertEqual(codes(run(text)), ["eval.move_undecidable"])

    def test_ambiguous_moves(self) -> None:
        two_destinations = self.moves(
            "moved {\n"
            "  from = aws_x.a\n"
            "  to = aws_x.b\n"
            "}\n"
            "moved {\n"
            "  from = aws_x.a\n"
            "  to = aws_x.c\n"
            "}\n"
        )
        self.assertEqual(codes(two_destinations), ["eval.move_ambiguous"])
        two_sources = self.moves(
            "moved {\n"
            "  from = aws_x.a\n"
            "  to = aws_x.c\n"
            "}\n"
            "moved {\n"
            "  from = aws_x.b\n"
            "  to = aws_x.c\n"
            "}\n"
        )
        self.assertEqual(codes(two_sources), ["eval.move_ambiguous"])

    def test_cycles(self) -> None:
        two = self.moves(
            "moved {\n"
            "  from = aws_x.a\n"
            "  to = aws_x.b\n"
            "}\n"
            "moved {\n"
            "  from = aws_x.b\n"
            "  to = aws_x.a\n"
            "}\n"
        )
        self.assertEqual((two.status, codes(two)), (UNSUPPORTED, ["eval.move_cycle"]))
        three = self.moves(
            "moved {\n"
            "  from = aws_x.a\n"
            "  to = aws_x.b\n"
            "}\n"
            "moved {\n"
            "  from = aws_x.b\n"
            "  to = aws_x.c\n"
            "}\n"
            "moved {\n  from = aws_x.c\n  to = aws_x.a\n}\n"
        )
        self.assertEqual(codes(three), ["eval.move_cycle"])

    def test_a_cycle_through_an_instance_and_its_resource(self) -> None:
        cycle = self.moves(
            "moved {\n"
            "  from = aws_x.a\n"
            "  to = aws_x.b\n"
            "}\n"
            "moved {\n"
            "  from = aws_x.b[0]\n"
            "  to = aws_x.a\n"
            "}\n"
        )
        self.assertEqual(codes(cycle), ["eval.move_cycle"])

    def test_a_cycle_is_reported_only_when_nothing_else_is_wrong(self) -> None:
        # as ValidateMoves: cycles are the last resort
        both = self.moves(
            "moved {\n"
            "  from = aws_x.a\n"
            "  to = aws_x.a\n"
            "}\n"
            "moved {\n"
            "  from = aws_x.b\n"
            "  to = aws_x.c\n"
            "}\n"
            "moved {\n  from = aws_x.c\n  to = aws_x.b\n}\n"
        )
        self.assertEqual(codes(both), ["eval.move_redundant"])

    def test_no_moves_means_an_empty_table(self) -> None:
        self.assertEqual(run(self.BASE).moves, ())

    def test_legacy_index_form(self) -> None:
        outcome = self.moves("moved {\n  from = aws_x.a.0\n  to = aws_x.new\n}\n")
        self.assertEqual(outcome.moves, (("aws_x.a[0]", "aws_x.new"),))


class TestRegistries(unittest.TestCase):
    def test_every_code_in_evaluation_is_registered(self) -> None:
        source = (ROOT / "core" / "terraform_model" / "evaluation.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        skipped: set[int] = set()
        for node in ast.walk(tree):
            targets = (
                node.targets if isinstance(node, ast.Assign) else [getattr(node, "target", None)]
            )
            if any(isinstance(t, ast.Name) and t.id in ("REASONS", "DIAGNOSTICS") for t in targets):
                skipped |= {id(inner) for inner in ast.walk(node)}
        strings: set[str] = set()
        reasons: set[str] = set()
        diagnostic_codes: set[str] = set()
        for node in ast.walk(tree):
            if id(node) in skipped:
                continue
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                strings.add(node.value)
            if not isinstance(node, ast.Call):
                continue
            called = (
                node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            )
            first = node.args[0] if node.args else None
            if called == "Unsupported" and isinstance(first, ast.Constant):
                reasons.add(str(first.value))
            if called in ("report", "_diagnostic", "Diagnostic"):
                for argument in node.args[:2]:
                    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                        diagnostic_codes.add(argument.value)
        self.assertEqual(sorted(reasons - set(evaluation_module.REASONS)), [])
        self.assertEqual(sorted(set(evaluation_module.REASONS) - reasons - strings), [])
        known = {code for code in strings if code.startswith(("eval.", "limit."))}
        self.assertEqual(sorted(known - set(evaluation_module.DIAGNOSTICS)), [])
        self.assertEqual(sorted(set(evaluation_module.DIAGNOSTICS) - strings), [])


if __name__ == "__main__":
    unittest.main()
