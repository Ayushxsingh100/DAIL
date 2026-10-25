"""Seeded generators of expressions and configurations for the evaluator's property and fuzz tests.

Standard library plus ``core.terraform_model``. Not a test module. Every generator takes a
``random.Random``, so a failing case is reproduced from its seed and index.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Mapping

from core.terraform_model.evaluate import Scope
from core.terraform_model.hcl.ast import Attribute, Expression
from core.terraform_model.hcl.parser import parse_file
from core.terraform_model.values import (
    Known,
    Unknown,
    Value,
    known_object,
    known_tuple,
)

FUNCTIONS_IN_SUBSET = (
    "toset", "tolist", "tomap", "tostring", "tonumber", "tobool", "concat", "merge", "length",
    "element", "lookup", "contains", "distinct", "flatten", "keys", "values", "coalesce",
    "compact", "lower", "upper", "join", "split", "format", "cidrsubnet", "cidrhost",
)  # fmt: skip
FUNCTIONS_OUTSIDE = ("abs", "max", "try", "can", "jsonencode", "regex", "file", "timestamp")
BINARY = ("+", "-", "*", "/", "%", "<", "<=", ">", ">=", "==", "!=", "&&", "||")
STRINGS = ('"a"', '"b"', '""', '"10"', '"true"', '"x y"', '"10.0.0.0/8"', '"%s-%d"', '"a,b"')
NUMBERS = ("0", "1", "2", "3", "5", "10", "100", "1.5", "0.25", "1e3", "255")
UNKNOWN_ROOTS = ("nothing.here", "aws_x.y.id", "data.a.b.c", "each.key", "count.index", "self.id")


def scenario_variables() -> dict[str, Value]:
    return {
        "n": Known(3),
        "s": Known("x"),
        "l": known_tuple([Known(1), Known(2), Known(3)]),
        "o": known_object({"a": Known(1), "b": Known("z")}),
        "u": Unknown("variable.no_value"),
        "e": known_tuple([]),
        "m": known_object({"k1": Known("v1"), "k2": Known("v2")}),
        "nested": known_tuple([known_object({"a": Known(1)}), known_object({"a": Known(2)})]),
    }


VARIABLE_NAMES = tuple(scenario_variables())
LOCAL_SOURCES = {"k0": "1", "k1": '"text"', "k2": "[local.k0, 2]", "k3": "{a = local.k0}"}


def parse_expression(text: str) -> Expression:
    body = parse_file(f"x = {text}\n", "gen.tf")
    item = body.items[0]
    assert isinstance(item, Attribute)
    return item.expr


def make_scope(extra: Mapping[str, Value] | None = None) -> Scope:
    variables = scenario_variables()
    if extra:
        variables.update(extra)
    locals_ = {name: parse_expression(text) for name, text in LOCAL_SOURCES.items()}
    return Scope(variables=variables, locals=locals_)


class ExpressionGenerator:
    """Random expressions over the whole grammar the evaluator handles (and some it does not)."""

    def __init__(self, rng: random.Random, *, unknown_roots: bool = False) -> None:
        self.rng = rng
        self.unknown_roots = unknown_roots

    def leaf(self, scope_names: tuple[str, ...] = ()) -> str:
        rng = self.rng
        choice = rng.random()
        if choice < 0.3:
            return rng.choice(NUMBERS)
        if choice < 0.5:
            return rng.choice(STRINGS)
        if choice < 0.58:
            return rng.choice(("true", "false", "null"))
        if choice < 0.75:
            return f"var.{rng.choice(VARIABLE_NAMES)}"
        if choice < 0.83:
            return f"local.{rng.choice(tuple(LOCAL_SOURCES))}"
        if choice < 0.9 and scope_names:
            return rng.choice(scope_names)
        if self.unknown_roots and choice < 0.95:
            return rng.choice(UNKNOWN_ROOTS)
        return rng.choice(NUMBERS)

    def expr(self, depth: int, scope_names: tuple[str, ...] = ()) -> str:
        rng = self.rng
        if depth <= 0 or rng.random() < 0.15:
            return self.leaf(scope_names)
        kind = rng.choice(
            ("binary", "binary", "unary", "cond", "tuple", "object", "template", "call", "call",
             "call", "for_tuple", "for_object", "index", "attr", "splat", "paren")
        )  # fmt: skip

        def sub() -> str:
            return self.expr(depth - 1, scope_names)

        if kind == "binary":
            return f"({sub()} {rng.choice(BINARY)} {sub()})"
        if kind == "unary":
            return f"({rng.choice(('-', '!'))}{sub()})"
        if kind == "cond":
            return f"({sub()} ? {sub()} : {sub()})"
        if kind == "tuple":
            return "[" + ", ".join(sub() for _ in range(rng.randint(0, 4))) + "]"
        if kind == "object":
            keys = rng.sample(("a", "b", "c", "d"), rng.randint(0, 3))
            return "{" + ", ".join(f"{key} = {sub()}" for key in keys) + "}"
        if kind == "template":
            return '"' + rng.choice(("", "p-")) + "${" + sub() + "}" + rng.choice(("", "-s")) + '"'
        if kind == "call":
            name = rng.choice(FUNCTIONS_IN_SUBSET if rng.random() < 0.9 else FUNCTIONS_OUTSIDE)
            return f"{name}(" + ", ".join(sub() for _ in range(rng.randint(0, 3))) + ")"
        if kind == "for_tuple":
            inner = (*scope_names, "x")
            body = self.expr(depth - 1, inner)
            condition = f" if {self.expr(depth - 1, inner)}" if rng.random() < 0.3 else ""
            return f"[for x in {sub()} : {body}{condition}]"
        if kind == "for_object":
            inner = (*scope_names, "k", "v")
            key, value = self.expr(depth - 1, inner), self.expr(depth - 1, inner)
            group = "..." if rng.random() < 0.2 else ""
            return f"{{for k, v in {sub()} : {key} => {value}{group}}}"
        if kind == "index":
            return f"{sub()}[{sub()}]"
        if kind == "attr":
            return f"({sub()}).{rng.choice(('a', 'b', 'k1'))}"
        if kind == "splat":
            return f"({sub()})[*]" if rng.random() < 0.5 else f"({sub()})[*].a"
        return f"({sub()})"

    def nested(self, depth: int) -> str:
        """A deeply nested but small expression: brackets, parentheses and conditionals."""
        shapes = ("[{}]", "({})", "{{a = {}}}", "(true ? {} : 0)", "[for x in [{}] : x]")
        text = "1"
        for _ in range(depth):
            text = self.rng.choice(shapes).format(text)
        return text


class TypedGenerator:
    """Well-typed expressions: most evaluate to a fully known value, so that a property about
    unknowns is not satisfied just because the expression was ill-typed."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def num(self, d: int, names: tuple[str, ...] = ()) -> str:
        rng = self.rng
        if d <= 0 or rng.random() < 0.2:
            return rng.choice(["0", "1", "2", "3", "7", "10", "1.5", "var.n", "local.k0", *names])

        def n() -> str:
            return self.num(d - 1, names)

        kind = rng.choice(("op", "op", "neg", "cond", "length", "element", "tonumber"))
        if kind == "op":
            return f"({n()} {rng.choice(('+', '-', '*'))} {n()})"
        if kind == "neg":
            return f"(-{n()})"
        if kind == "cond":
            return f"({self.boolean(d - 1, names)} ? {n()} : {n()})"
        if kind == "length":
            collection = rng.choice((self.list_num(d - 1), self.list_str(d - 1), self.obj(d - 1)))
            return f"length({collection})"
        if kind == "element":
            return f"element({self.list_num(d - 1)}, {n()})"
        return f'tonumber("{rng.choice(("1", "2.5", "10", "-3"))}")'

    def string(self, d: int, names: tuple[str, ...] = ()) -> str:
        rng = self.rng
        if d <= 0 or rng.random() < 0.2:
            return rng.choice(('"a"', '"bc"', '""', "var.s", "local.k1", '"x y"'))

        def s() -> str:
            return self.string(d - 1, names)

        def n() -> str:
            return self.num(d - 1, names)

        kind = rng.choice(
            ("template", "upper", "lower", "join", "format", "cond", "tostring", "element",
             "lookup", "concat")
        )  # fmt: skip
        if kind == "template":
            return '"${' + n() + "}-${" + s() + '}"'
        if kind == "upper":
            return f"upper({s()})"
        if kind == "lower":
            return f"lower({s()})"
        if kind == "join":
            return f'join(",", {self.list_str(d - 1)})'
        if kind == "format":
            return f'format("%s-%d", {s()}, {n()})'
        if kind == "cond":
            return f"({self.boolean(d - 1, names)} ? {s()} : {s()})"
        if kind == "tostring":
            return f"tostring({n()})"
        if kind == "element":
            return f"element({self.list_str(d - 1)}, {n()})"
        if kind == "lookup":
            return f'lookup({{a = {s()}}}, "{rng.choice(("a", "z"))}", "d")'
        return '"${' + s() + "}${" + s() + '}"'

    def boolean(self, d: int, names: tuple[str, ...] = ()) -> str:
        rng = self.rng
        if d <= 0 or rng.random() < 0.2:
            return rng.choice(("true", "false"))

        def b() -> str:
            return self.boolean(d - 1, names)

        kind = rng.choice(("cmp", "eq", "and", "not", "contains"))
        if kind == "cmp":
            operator = rng.choice(("<", "<=", ">", ">="))
            return f"({self.num(d - 1, names)} {operator} {self.num(d - 1, names)})"
        if kind == "eq":
            operator = rng.choice(("==", "!="))
            return f"({self.string(d - 1, names)} {operator} {self.string(d - 1, names)})"
        if kind == "and":
            return f"({b()} {rng.choice(('&&', '||'))} {b()})"
        if kind == "not":
            return f"(!{b()})"
        return f"contains({self.list_str(d - 1)}, {self.string(d - 1, names)})"

    def list_num(self, d: int) -> str:
        rng = self.rng
        if d <= 0 or rng.random() < 0.2:
            return rng.choice(("[1, 2, 3]", "[3, 1, 2]", "[10]", "var.l", "[0, 5]"))
        kind = rng.choice(("lit", "concat", "for", "toset", "flatten", "distinct"))
        if kind == "lit":
            return "[" + ", ".join(self.num(d - 1) for _ in range(rng.randint(1, 3))) + "]"
        if kind == "concat":
            return f"concat({self.list_num(d - 1)}, {self.list_num(d - 1)})"
        if kind == "for":
            return f"[for x in {self.list_num(d - 1)} : {self.num(d - 1, ('x',))}]"
        if kind == "toset":
            return f"tolist(toset({self.list_num(d - 1)}))"
        if kind == "flatten":
            return f"flatten([{self.list_num(d - 1)}, {self.list_num(d - 1)}])"
        return f"distinct({self.list_num(d - 1)})"

    def list_str(self, d: int) -> str:
        rng = self.rng
        if d <= 0 or rng.random() < 0.2:
            return rng.choice(('["a", "b"]', '["b", "a", "b"]', '["x"]', "[]"))
        kind = rng.choice(("lit", "split", "compact", "toset", "keys", "for", "concat"))
        if kind == "lit":
            return "[" + ", ".join(self.string(d - 1) for _ in range(rng.randint(1, 3))) + "]"
        if kind == "split":
            return f'split(",", {self.string(d - 1)})'
        if kind == "compact":
            return f"compact({self.list_str(d - 1)})"
        if kind == "toset":
            return f"tolist(toset({self.list_str(d - 1)}))"
        if kind == "keys":
            return f"keys({self.obj(d - 1)})"
        if kind == "for":
            return "[for x in " + self.list_str(d - 1) + ' : "${x}-${' + self.num(d - 1) + '}"]'
        return f"concat({self.list_str(d - 1)}, {self.list_str(d - 1)})"

    def obj(self, d: int) -> str:
        rng = self.rng
        if d <= 0 or rng.random() < 0.2:
            return rng.choice(("{a = 1}", "var.o", "var.m", "{}"))
        kind = rng.choice(("lit", "merge", "for"))
        if kind == "lit":
            keys = rng.sample(("a", "b", "c"), rng.randint(1, 3))
            items = [f"{k} = {rng.choice((self.num(d - 1), self.string(d - 1)))}" for k in keys]
            return "{" + ", ".join(items) + "}"
        if kind == "merge":
            return f"merge({self.obj(d - 1)}, {self.obj(d - 1)})"
        return f"{{for k, v in {self.obj(d - 1)} : k => v}}"

    def any(self, d: int) -> str:
        makers: tuple[Callable[[int], str], ...] = (
            self.num,
            self.string,
            self.boolean,
            self.list_num,
            self.list_str,
            self.obj,
        )
        return self.rng.choice(makers)(d)
