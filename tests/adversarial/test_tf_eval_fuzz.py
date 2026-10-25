"""Evaluator fuzzing (P3a-2 step 6; Doc 12 §22 "Parser fuzzing"; Doc 14 §2; C-102 to C-105).

Doc 12 §22: parsers and evaluators receive malformed and boundary inputs, "deeply nested
structures", "invalid references". Cases here are random expression trees over the whole grammar
(including constructs outside the function subset and unknown root names), deeply nested
expressions, loops over large collections, and random configurations with huge ``count`` values,
``for_each`` over every kind of value, ``dynamic`` blocks, self-referencing locals and resources,
and ``moved`` blocks.

The generators are deterministic (``tests/eval_generators.py``): they use ``random.Random`` with
the fixed seeds in ``SEEDS`` (printed when the module finishes), so a failure names a seed and a
case index that reproduce it.

Properties checked for every case:
- ``evaluate_expression`` returns a value and ``evaluate_configuration`` returns an outcome; neither
  raises (``RecursionError`` included) and neither hangs: each case runs under a time budget, and a
  watchdog (``faulthandler``) turns an endless loop into a traceback and exit;
- C-105 holds: no expression takes more than 10,000 steps, no configuration has more than 10,000
  instances or a resource with more than 1,000;
- an outcome is consistent: its status follows from its diagnostics, data is present only when
  OK, instances are sorted by address and no value contains a float;
- no diagnostic has an ``internal.`` code.
"""

from __future__ import annotations

import faulthandler
import random
import time
import unittest
from collections import Counter
from unittest import mock

from core.domain.hashing import canonical_json
from core.terraform_model import evaluate as evaluate_module
from core.terraform_model.config import ParseStatus
from core.terraform_model.evaluate import MAX_STEPS, Scope, evaluate_expression
from core.terraform_model.evaluation import evaluate_configuration
from core.terraform_model.hcl.errors import HclError
from core.terraform_model.instances import (
    MAX_INSTANCES_PER_CONFIGURATION,
    MAX_INSTANCES_PER_RESOURCE,
)
from core.terraform_model.values import (
    Known,
    Ref,
    Unknown,
    Unsupported,
    Value,
    known_tuple,
    to_canonical,
    walk,
)
from tests import eval_generators as gen
from tests.unit.test_terraform_config import DirectoryCase

SEEDS = (20261025, 1, 7, 424242, 99991)
CASE_BUDGET_SECONDS = 30.0
WATCHDOG_SECONDS = 1200

OK = ParseStatus.OK
COUNTS: Counter[str] = Counter()


def setUpModule() -> None:
    faulthandler.dump_traceback_later(WATCHDOG_SECONDS, exit=True)


def tearDownModule() -> None:
    faulthandler.cancel_dump_traceback_later()
    print(f"\ntf-eval-fuzz seeds: {SEEDS}")
    print(f"tf-eval-fuzz cases: {sum(COUNTS.values())} ({dict(COUNTS)})")


def check_value(case: unittest.TestCase, value: Value, label: str) -> None:
    case.assertIsInstance(value, Known | Unsupported | Unknown | Ref, label)
    for item in walk(value):
        if isinstance(item, Known):
            case.assertNotIsInstance(item.value, float, label)
    canonical_json(to_canonical(value))


class RecordingEvaluators:
    """Remembers every evaluator that runs, to read how many steps each took."""

    def __init__(self) -> None:
        self.evaluators: list[evaluate_module._Evaluator] = []
        self._original = evaluate_module._Evaluator.__init__

    def __enter__(self) -> RecordingEvaluators:
        recorder = self
        original = self._original

        def init(evaluator: evaluate_module._Evaluator, scope: Scope) -> None:
            original(evaluator, scope)
            recorder.evaluators.append(evaluator)

        self._patch = mock.patch.object(evaluate_module._Evaluator, "__init__", init)
        self._patch.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._patch.stop()

    @property
    def max_steps(self) -> int:
        return max((e.steps for e in self.evaluators), default=0)


class TestExpressionFuzz(unittest.TestCase):
    def run_expression(self, text: str, label: str, scope: Scope | None = None) -> Value:
        started = time.monotonic()
        with RecordingEvaluators() as recorder:
            try:
                expression = gen.parse_expression(text)
            except HclError:
                COUNTS["expression rejected by the parser"] += 1
                return Unsupported("test.parse")
            value = evaluate_expression(
                expression, scope if scope is not None else gen.make_scope()
            )
        self.assertLess(time.monotonic() - started, CASE_BUDGET_SECONDS, label)
        self.assertLessEqual(recorder.max_steps, MAX_STEPS + 1, label)
        check_value(self, value, label)
        return value

    def test_random_expressions_over_the_full_grammar(self) -> None:
        for seed in SEEDS:
            rng = random.Random(seed)
            generator = gen.ExpressionGenerator(rng, unknown_roots=True)
            for index in range(150):
                text = generator.expr(rng.randint(1, 6))
                self.run_expression(text, f"seed {seed} case {index}: {text}")
                COUNTS["random expressions"] += 1

    def test_deeply_nested_expressions(self) -> None:
        for seed in SEEDS:
            rng = random.Random(seed + 1)
            generator = gen.ExpressionGenerator(rng)
            for index in range(30):
                depth = rng.randint(5, 80)
                text = generator.nested(depth)
                self.run_expression(text, f"seed {seed} nested {index} depth {depth}")
                COUNTS["nested expressions"] += 1

    def test_deep_for_nesting(self) -> None:
        for depth in range(1, 25):
            text = "[for a0 in var.l : a0]"
            for level in range(1, depth):
                text = f"[for a{level} in var.l : {text}]"
            value = self.run_expression(text, f"for depth {depth}")
            if depth <= 2:
                self.assertIsInstance(value, Known)
            COUNTS["deep for nesting"] += 1

    def test_loops_over_large_collections(self) -> None:
        big = known_tuple(Known(i) for i in range(1500))
        scope = gen.make_scope({"big": big, "bigger": known_tuple(Known(i) for i in range(5000))})
        texts = [
            "[for x in var.big : x]",
            "[for x in var.big : x if x < 3]",
            "{for x in var.big : x => x}",
            '{for x in var.big : "k${x}" => x if x < 5}',
            "[for x in var.big : [for y in var.big : y]]",
            "[for x in var.l : [for y in var.big : y]]",
            "length([for x in var.bigger : x if x > 4990])",
            'join(",", var.big)',
            "flatten([var.big, var.big])",
            "toset(var.bigger)",
            "length(toset(var.bigger))",
            "distinct(var.big)",
            "concat(var.big, var.big, var.big)",
            '[for x in var.big : "${x}-${x}" if x == 7]',
            "length(var.bigger) > 4999",
            "var.big[1499]",
            "var.big[1500]",
            'merge({for x in var.l : "a${x}" => x}, {for x in var.bigger : "b${x}" => x if x < 3})',
            '[for k, v in {for x in var.l : "a${x}" => x} : [for z in var.big : z if z < 2]]',
        ]
        for index, text in enumerate(texts):
            value = self.run_expression(text, f"large {index}: {text}", scope)
            COUNTS["large collections"] += 1
            if text == "[for x in var.big : x]":
                self.assertEqual(value, Unsupported("limit.for_elements"))
            if text == "[for x in var.big : x if x < 3]":
                self.assertEqual(value, known_tuple(Known(i) for i in range(3)))

    def test_self_reference_and_unknown_roots(self) -> None:
        cases = [
            ("local.self", {"self": "local.self"}),
            ("local.a", {"a": "local.b", "b": "local.c", "c": "local.a"}),
            ("local.a", {"a": "[for x in local.a : x]"}),
            ("nothing.here.id", {}),
            ("var", {}),
            ("local", {}),
            ("[for x in local.long : x]", {"long": "local.long"}),
            ("local.z", {f"l{i}": f"local.l{i + 1}" for i in range(400)} | {"z": "local.l0"}),
        ]
        for index, (text, locals_text) in enumerate(cases):
            scope = Scope(
                variables=gen.scenario_variables(),
                locals={name: gen.parse_expression(t) for name, t in locals_text.items()},
            )
            value = self.run_expression(text, f"self reference {index}: {text}", scope)
            self.assertIsInstance(value, Unsupported)
            COUNTS["self references and unknown roots"] += 1


class ConfigurationGenerator:
    COUNTS = (
        ["0", "1", "2", "3", "var.n", "length(var.l)", '"2"'] * 6
        + ["var.u", "-1", "1.5", "null", "true", '"abc"', "[1]", "10000000000000000000000000000"]
        + ["1000", "1001", "5000"]
    )
    FOR_EACHES = [
        'toset(["a", "b"])',
        "{a = 1, b = 2}",
        "var.m",
        "var.o",
        "toset(var.l)",
        "{}",
    ] * 4 + ["var.u", '["x"]', "null", "toset([1, 2])", "var.n", "toset([var.u])", "var.nested"]

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.expressions = gen.ExpressionGenerator(rng, unknown_roots=False)
        self.kinds: list[str] = []

    def prefix(self, j: int) -> str:
        return "data." if self.kinds[j] == "data" else ""

    def reference(self) -> str:
        rng = self.rng
        j = rng.randrange(len(self.kinds))
        base = f"{self.prefix(j)}aws_t{j}.r{j}"
        return rng.choice(
            [
                f"{base}.id", f"{base}[0].id", f"{base}[*].id", base, f"{base}.arn",
                f'{base}["a"].name', f"length({base})", f"{base}[0]", f"{base}.a", f"{base}[1].a",
                f"[for r in {base} : r.id]", f"{{for k, r in {base} : k => r.a}}",
            ]
        )  # fmt: skip

    def expression(self, depth: int = 2) -> str:
        rng = self.rng
        if rng.random() < 0.3:
            return self.reference()
        text = self.expressions.expr(depth)
        if rng.random() < 0.2:
            text = f"[{text}, {self.reference()}]"
        return text

    def body(self) -> str:
        rng = self.rng
        lines = []
        for name in rng.sample(("a", "b", "c", "d"), rng.randint(0, 3)):
            lines.append(f"  {name} = {self.expression()}")
        form = rng.random()
        if form < 0.15:
            lines.append(f"  ingress = {rng.choice(('[]', self.expression()))}")
        elif form < 0.3:
            lines.append(f"  ingress {{\n    from_port = {self.expression(1)}\n  }}")
        if rng.random() < 0.3:
            lines.append(
                f'  dynamic "rule" {{\n    for_each = {self.expression(1)}\n'
                f"    content {{\n      v = [rule.value, {self.expression(1)}]\n"
                "    }\n  }"
            )
        if rng.random() < 0.1:
            lines.append('  provisioner "local-exec" {\n    command = "echo"\n  }')
        if rng.random() < 0.1:
            flag = rng.choice(("true", "false", "var.n"))
            lines.append(f"  lifecycle {{\n    prevent_destroy = {flag}\n  }}")
        if rng.random() < 0.1:
            lines.append(f"  depends_on = [{self.reference().split('[')[0].split('.id')[0]}]")
        return "\n".join(lines)

    def text(self) -> tuple[str, dict[str, object]]:
        rng = self.rng
        resources = rng.randint(1, 5)
        self.kinds = ["resource" if rng.random() < 0.93 else "data" for _ in range(resources)]
        parts = []
        for name in gen.VARIABLE_NAMES:
            if rng.random() < 0.99:
                default = ""
                if rng.random() < 0.2:
                    default = f"\n  default = {rng.choice(('1', '[1]', '{a = 1}', 'null'))}"
                parts.append(f'variable "{name}" {{\n  type = any{default}\n}}')
        if rng.random() < 0.95:
            sources = "\n".join(f"  {k} = {v}" for k, v in gen.LOCAL_SOURCES.items())
            parts.append("locals {\n" + sources + "\n}")
        if rng.random() < 0.05:
            parts.append(
                "locals {\n  loop_a = local.loop_b\n  loop_b = local.loop_a\n  me = local.me\n}"
            )
        for i in range(resources):
            meta = ""
            roll = rng.random()
            if roll < 0.4:
                meta = f"  count = {rng.choice(self.COUNTS)}\n"
            elif roll < 0.7:
                meta = f"  for_each = {rng.choice(self.FOR_EACHES)}\n"
            elif roll < 0.72:
                meta = "  count = 1\n  for_each = {}\n"
            parts.append(f'{self.kinds[i]} "aws_t{i}" "r{i}" {{\n{meta}{self.body()}\n}}')
        for _ in range(rng.choice((0, 0, 0, 1, 2, 3))):
            a, b = rng.randrange(resources + 2), rng.randrange(resources + 2)
            source = f"aws_t{a}.r{a}{rng.choice(('', '[0]'))}"
            target = f"aws_t{b}.r{b}{rng.choice(('', '[0]', '[\"a\"]', '[1]'))}"
            parts.append(f"moved {{\n  from = {source}\n  to = {target}\n}}")
        if rng.random() < 0.03:
            parts.append('module "m" {\n  source = "./m"\n}')
        scenario: dict[str, object] = {}
        values = (
            ("n", 2),
            ("s", "x"),
            ("l", [1, 2]),
            ("m", {"k": "v"}),
            ("e", []),
            ("o", {"a": 1}),
        )
        for name, value in values:
            if rng.random() < 0.7:
                scenario[name] = value
        if rng.random() < 0.03:
            scenario["nothing"] = 1
        return "\n\n".join(parts) + "\n", scenario


class TestConfigurationFuzz(DirectoryCase):
    def check_outcome(self, outcome: object, label: str) -> None:
        from core.terraform_model.evaluation import EvaluationOutcome

        self.assertIsInstance(outcome, EvaluationOutcome, label)
        assert isinstance(outcome, EvaluationOutcome)
        self.assertIn(outcome.status, set(ParseStatus), label)
        self.assertLessEqual(len(outcome.instances), MAX_INSTANCES_PER_CONFIGURATION, label)
        per_resource: Counter[str] = Counter()
        for address, instance in outcome.instances.items():
            per_resource[f"{instance.kind}.{instance.type}.{instance.name}"] += 1
            self.assertEqual(address, instance.address, label)
        self.assertLessEqual(
            max(per_resource.values(), default=0), MAX_INSTANCES_PER_RESOURCE, label
        )
        self.assertEqual(list(outcome.instances), sorted(outcome.instances), label)
        if outcome.status is not OK:
            self.assertEqual(
                (
                    dict(outcome.instances),
                    dict(outcome.indeterminate),
                    dict(outcome.variables),
                    outcome.moves,
                ),
                ({}, {}, {}, ()),
                label,
            )
        for code in (d.code for d in outcome.diagnostics):
            self.assertFalse(code.startswith("internal."), f"{label}: {code}")
        for argument_value in self.all_values(outcome):
            check_value(self, argument_value, label)

    @staticmethod
    def all_values(outcome: object) -> list[Value]:
        from core.terraform_model.evaluation import EvaluationOutcome
        from core.terraform_model.instances import EvaluatedArgument

        assert isinstance(outcome, EvaluationOutcome)
        found: list[Value] = [*outcome.variables.values(), *outcome.locals.values()]
        stack: list[EvaluatedArgument] = []
        for instance in outcome.instances.values():
            stack.extend(instance.arguments.values())
        while stack:
            argument = stack.pop()
            if argument.value is not None:
                found.append(argument.value)
            for block in argument.blocks:
                stack.extend(block.arguments.values())
        return found

    def test_random_configurations(self) -> None:
        for seed in SEEDS:
            rng = random.Random(seed + 2)
            generator = ConfigurationGenerator(rng)
            for index in range(80):
                text, scenario = generator.text()
                label = f"seed {seed} configuration {index}"
                outcome = self.load({"main.tf": text})
                if outcome.configuration is None:
                    COUNTS["configurations rejected by the loader"] += 1
                    continue
                started = time.monotonic()
                with RecordingEvaluators() as recorder:
                    result = evaluate_configuration(outcome.configuration, scenario)
                self.assertLess(
                    time.monotonic() - started, CASE_BUDGET_SECONDS, label + "\n" + text
                )
                self.assertLessEqual(recorder.max_steps, MAX_STEPS + 1, label)
                self.check_outcome(result, label + "\n" + text)
                COUNTS["random configurations"] += 1
                COUNTS[f"outcome {result.status.value}"] += 1

    def test_the_generator_reaches_every_outcome_and_most_cases_load(self) -> None:
        # a guard on the generator itself: a fuzz that is always INVALID proves little
        seen: Counter[str] = Counter()
        rng = random.Random(SEEDS[0] + 2)
        generator = ConfigurationGenerator(rng)
        for _ in range(120):
            text, scenario = generator.text()
            outcome = self.load({"main.tf": text})
            if outcome.configuration is None:
                seen["not loaded"] += 1
                continue
            seen[evaluate_configuration(outcome.configuration, scenario).status.value] += 1
        self.assertGreater(seen["OK"], 10, seen)
        self.assertGreater(seen["INVALID"], 3, seen)
        self.assertGreater(seen["UNSUPPORTED"], 3, seen)
        self.assertLess(seen["not loaded"], 60, seen)

    def test_huge_counts_and_for_each_are_bounded(self) -> None:
        for count in ("1000", "1001", "100000", "10000000000000000000000000000000", "var.big_n"):
            text = (
                'variable "big_n" {\n  default = 100000000\n}\n'
                f'resource "aws_x" "x" {{\n  count = {count}\n  n = count.index\n}}\n'
            )
            outcome = self.load({"main.tf": text})
            assert outcome.configuration is not None
            result = evaluate_configuration(outcome.configuration, {})
            self.check_outcome(result, f"count {count}")
            expected = OK if count == "1000" else ParseStatus.UNSUPPORTED
            self.assertEqual(result.status, expected, count)
            COUNTS["huge counts"] += 1

    def test_many_resources_stay_within_the_configuration_limit(self) -> None:
        text = "".join(f'resource "aws_x" "r{i}" {{\n  count = 999\n}}\n' for i in range(12))
        outcome = self.load({"main.tf": text})
        assert outcome.configuration is not None
        result = evaluate_configuration(outcome.configuration, {})
        self.assertEqual(result.status, ParseStatus.UNSUPPORTED)
        self.assertEqual(len(result.instances), 0)
        COUNTS["many resources"] += 1

    def test_self_referencing_resources(self) -> None:
        # a resource that refers to itself passes validate and fails plan: UNSUPPORTED; a cycle
        # between two resources is rejected by validate ("Cycle"): INVALID
        unsupported = ParseStatus.UNSUPPORTED
        cases = [
            ('resource "aws_x" "x" {\n  a = aws_x.x.a\n}\n', unsupported),
            ('resource "aws_x" "x" {\n  count = length(aws_x.x)\n}\n', unsupported),
            ('resource "aws_x" "x" {\n  for_each = aws_x.x\n}\n', unsupported),
            (
                'resource "aws_x" "x" {\n'
                "  a = aws_y.y.a\n"
                "}\n"
                'resource "aws_y" "y" {\n'
                "  a = aws_x.x.a\n"
                "}\n",
                ParseStatus.INVALID,
            ),
            ('resource "aws_x" "x" {\n  count = 2\n  a = aws_x.x[*].a\n}\n', unsupported),
            ('resource "aws_x" "x" {\n  a = [for r in aws_x.x : r]\n}\n', unsupported),
            (
                'resource "aws_x" "x" {\n'
                '  dynamic "d" {\n'
                "    for_each = aws_x.x\n"
                "    content {}\n"
                "  }\n"
                "}\n",
                unsupported,
            ),
            ("locals {\n  a = local.a\n}\n", ParseStatus.INVALID),
        ]
        for index, (text, expected) in enumerate(cases):
            outcome = self.load({"main.tf": text})
            assert outcome.configuration is not None
            result = evaluate_configuration(outcome.configuration, {})
            self.check_outcome(result, f"self reference {index}")
            self.assertEqual(result.status, expected, text)
            COUNTS["self-referencing resources"] += 1


CASES_BY_CONSTRUCTION = len(SEEDS) * (150 + 30 + 80)


class TestTheFuzzIsLargeEnough(unittest.TestCase):
    def test_the_cases_declared_are_at_least_a_thousand(self) -> None:
        self.assertGreaterEqual(CASES_BY_CONSTRUCTION, 1000)

    def test_at_least_a_thousand_cases_ran_when_the_whole_module_ran(self) -> None:
        if not COUNTS:
            self.skipTest("run on its own; the count is checked when the whole module runs")
        self.assertGreaterEqual(sum(COUNTS.values()), 1000, dict(COUNTS))


if __name__ == "__main__":
    unittest.main()
