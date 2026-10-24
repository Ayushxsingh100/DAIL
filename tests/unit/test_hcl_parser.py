"""HCL parser conformance (P3a-1 step 3; Doc 04 §4, §23, §18; Doc 12 §22; C-91, C-93).

Every expected tree below is written by hand from ``hclsyntax/spec.md`` (hashicorp/hcl v2.25.0,
ADR-003); none is captured from the parser. Source ranges are metadata and excluded from
equality, so the trees use one dummy range. Cases marked "C-95" follow behaviour that the
specification leaves open and that was settled against Terraform 1.15.8 (register row C-95).

The valid table has well over 60 cases and the invalid table well over 30, each asserting its
rule code. Doc 04 §23: "Valid/invalid HCL".
"""

from __future__ import annotations

import dataclasses
import unittest
from collections.abc import Callable
from decimal import Decimal

from core.terraform_model.hcl.ast import (
    Attribute,
    AttrStep,
    BinaryOp,
    BinaryOperator,
    Block,
    Body,
    Conditional,
    Expression,
    ForExpr,
    ForKind,
    FunctionCall,
    GetAttr,
    Heredoc,
    IdentifierKey,
    Index,
    IndexStep,
    Label,
    LegacyIndexStep,
    Literal,
    LiteralKind,
    Object,
    ObjectItem,
    Parenthesized,
    ScopeTraversal,
    SourceRange,
    Splat,
    SplatKind,
    Strip,
    Template,
    TemplateFor,
    TemplateIf,
    TemplateInterpolation,
    TemplateLiteral,
    TraversalStep,
    Tuple,
    UnaryOp,
    UnaryOperator,
)
from core.terraform_model.hcl.errors import RULES, HclLimitError, HclSyntaxError
from core.terraform_model.hcl.parser import MAX_NESTING_DEPTH, parse_file

R = SourceRange("t.tf", 1, 1, 1, 1, 0, 0)
Op = BinaryOperator

# --- tree builders (hand-written expectations) -----------------------------------------------


def num(value: int | Decimal, text: str | None = None) -> Literal:
    return Literal(LiteralKind.NUMBER, value, str(value) if text is None else text, R)


def string(value: str, text: str | None = None) -> Literal:
    return Literal(LiteralKind.STRING, value, f'"{value}"' if text is None else text, R)


TRUE = Literal(LiteralKind.BOOL, True, "true", R)
FALSE = Literal(LiteralKind.BOOL, False, "false", R)
NULL = Literal(LiteralKind.NULL, None, "null", R)


def var(root: str, *steps: TraversalStep) -> ScopeTraversal:
    return ScopeTraversal(root, tuple(steps), R)


def at(name: str) -> AttrStep:
    return AttrStep(name, R)


def ix(key: Expression) -> IndexStep:
    return IndexStep(key, R)


def lg(index: int) -> LegacyIndexStep:
    return LegacyIndexStep(index, R)


def lit(text: str) -> TemplateLiteral:
    return TemplateLiteral(text, R)


def interp(expr: Expression, left: bool = False, right: bool = False) -> TemplateInterpolation:
    return TemplateInterpolation(expr, Strip(left, right), R)


def tpl(*parts: object) -> Template:
    return Template(parts, R)  # type: ignore[arg-type]


def binop(op: BinaryOperator, left: Expression, right: Expression) -> BinaryOp:
    return BinaryOp(op, left, right, R)


def neg(operand: Expression) -> UnaryOp:
    return UnaryOp(UnaryOperator.NEG, operand, R)


def inv(operand: Expression) -> UnaryOp:
    return UnaryOp(UnaryOperator.NOT, operand, R)


def call(name: str, *args: Expression, expand: bool = False) -> FunctionCall:
    return FunctionCall(name, tuple(args), expand, R)


def tup(*elements: Expression) -> Tuple:
    return Tuple(tuple(elements), R)


def item(key: IdentifierKey | Expression, value: Expression) -> ObjectItem:
    return ObjectItem(key, value, R)


def ik(name: str) -> IdentifierKey:
    return IdentifierKey(name, R)


def obj(*items: ObjectItem) -> Object:
    return Object(tuple(items), R)


def cond(c: Expression, t: Expression, f: Expression) -> Conditional:
    return Conditional(c, t, f, R)


def paren(expr: Expression) -> Parenthesized:
    return Parenthesized(expr, R)


def for_tuple(
    key_var: str | None,
    value_var: str,
    collection: Expression,
    value: Expression,
    condition: Expression | None = None,
) -> ForExpr:
    return ForExpr(ForKind.TUPLE, key_var, value_var, collection, None, value, condition, False, R)


def for_object(
    key_var: str | None,
    value_var: str,
    collection: Expression,
    key: Expression,
    value: Expression,
    condition: Expression | None = None,
    group: bool = False,
) -> ForExpr:
    return ForExpr(ForKind.OBJECT, key_var, value_var, collection, key, value, condition, group, R)


def splat(source: Expression, kind: SplatKind, *steps: TraversalStep) -> Splat:
    return Splat(source, kind, tuple(steps), R)


def attribute(name: str, expr: Expression) -> Attribute:
    return Attribute(name, expr, R, R)


def label(value: str, quoted: bool = True) -> Label:
    return Label(value, quoted, R)


def block(
    type_: str, labels: tuple[Label, ...], *items: Attribute | Block, one_line: bool = False
) -> Block:
    return Block(type_, labels, Body(tuple(items), R), one_line, R, R)


def expr_of(source: str) -> Expression:
    body = parse_file(f"x = {source}\n", "t.tf")
    (only,) = body.items
    assert isinstance(only, Attribute)
    return only.expr


def code_of(text: str) -> str:
    try:
        parse_file(text, "t.tf")
    except (HclSyntaxError, HclLimitError) as exc:
        return exc.code
    raise AssertionError(f"no error for {text!r}")


# --- valid expressions -----------------------------------------------------------------------

D = Decimal

VALID_EXPRESSIONS: list[tuple[str, str, Expression]] = [
    # Literal values (spec, "Literal Values", "Numeric Literals")
    ("int", "5", num(5)),
    ("zero", "0", num(0)),
    ("leading zeros", "007", num(7, "007")),
    ("decimal", "1.5", num(D("1.5"))),
    ("decimal keeps trailing zero in text", "1.50", num(D("1.50"), "1.50")),
    ("exponent integral", "1e3", num(1000, "1e3")),
    ("exponent upper plus", "1E+3", num(1000, "1E+3")),
    ("exponent negative", "1.5e-3", num(D("0.0015"), "1.5e-3")),
    ("true", "true", TRUE),
    ("false", "false", FALSE),
    ("null", "null", NULL),
    # Strings (spec, "Template Expressions")
    ("empty string", '""', string("")),
    ("plain string", '"abc"', string("abc")),
    ("string with comment markers", '"a # b /* c */ // d"', string("a # b /* c */ // d")),
    ("escaped dollar", '"$${x}"', string("${x}", '"$${x}"')),
    ("escaped percent", '"%%{x}"', string("%{x}", '"%%{x}"')),
    ("dollar without brace", '"$x %y $"', string("$x %y $")),
    # Template interpolation and directives
    ("interpolation", '"a${b}c"', tpl(lit("a"), interp(var("b")), lit("c"))),
    ("only interpolation", '"${b}"', tpl(interp(var("b")))),
    ("two interpolations", '"${a}${b}"', tpl(interp(var("a")), interp(var("b")))),
    (
        "nested quoted template",
        '"${"x${1}"}"',
        tpl(interp(tpl(lit("x"), interp(num(1))))),
    ),
    (
        "if directive with else",
        '"%{ if a }x%{ else }y%{ endif }"',
        tpl(TemplateIf(var("a"), (lit("x"),), (lit("y"),), Strip(), Strip(), Strip(), R)),
    ),
    (
        "if directive without else",
        '"%{ if a }x%{ endif }"',
        tpl(TemplateIf(var("a"), (lit("x"),), None, Strip(), None, Strip(), R)),
    ),
    (
        "for directive, one variable (spec example)",
        '"%{ for v in [true] }${v}%{ endfor }"',
        tpl(TemplateFor(None, "v", tup(TRUE), (interp(var("v")),), Strip(), Strip(), R)),
    ),
    (
        "for directive, two variables",
        '"%{ for k, v in a }${k}=${v}%{ endfor }"',
        tpl(
            TemplateFor(
                "k",
                "v",
                var("a"),
                (interp(var("k")), lit("="), interp(var("v"))),
                Strip(),
                Strip(),
                R,
            )
        ),
    ),
    (
        "directive nested in directive",
        '"%{ if a }%{ if b }x%{ endif }%{ endif }"',
        tpl(
            TemplateIf(
                var("a"),
                (TemplateIf(var("b"), (lit("x"),), None, Strip(), None, Strip(), R),),
                None,
                Strip(),
                None,
                Strip(),
                R,
            )
        ),
    ),
    # Strip markers (spec, "Template Literals": the two examples)
    (
        "strip marker in interpolation",
        '"hello ${~ "world" }"',
        tpl(lit("hello"), interp(string("world"), left=True)),
    ),
    (
        "strip markers in directives",
        '"%{ if true ~} hello %{~ endif }"',
        tpl(
            TemplateIf(TRUE, (lit("hello"),), None, Strip(False, True), None, Strip(True, False), R)
        ),
    ),
    (
        "strip does not touch values",
        '"${"hello" ~}${" world"}"',
        tpl(interp(string("hello"), right=True), interp(string(" world"))),
    ),
    (
        "strip right removes the space after",
        '"${a ~} b"',
        tpl(interp(var("a"), right=True), lit("b")),
    ),
    (
        "strip stops at a non-literal",
        '"${a ~}${b} c"',
        tpl(interp(var("a"), right=True), interp(var("b")), lit(" c")),
    ),
    # Heredocs (spec, "Template Expressions")
    ("heredoc", "<<EOT\nhi\nthere\nEOT\n", Heredoc("EOT", False, (lit("hi\nthere\n"),), R)),
    ("heredoc keeps indentation", "<<EOT\n  hi\nEOT\n", Heredoc("EOT", False, (lit("  hi\n"),), R)),
    (
        "heredoc with interpolation",
        "<<EOT\nhi ${a}\nEOT\n",
        Heredoc("EOT", False, (lit("hi "), interp(var("a")), lit("\n")), R),
    ),
    (
        "heredoc dash",
        "<<-EOT\n    a\n      b\n    EOT\n",
        Heredoc("EOT", True, (lit("a\n  b\n"),), R),
    ),
    ("heredoc empty", "<<EOT\nEOT\n", Heredoc("EOT", False, (), R)),
    (
        "heredoc does not process escapes",
        "<<EOT\na\\nb\nEOT\n",
        Heredoc("EOT", False, (lit("a\\nb\n"),), R),
    ),
    (
        "heredoc strip marker works per line",
        "<<EOT\nA\n%{~ if true ~}\n  x\n%{ endif }\nEOT\n",
        Heredoc(
            "EOT",
            False,
            (
                lit("A"),
                TemplateIf(TRUE, (lit("  x\n"),), None, Strip(True, True), None, Strip(), R),
                lit("\n"),
            ),
            R,
        ),
    ),
    # Tuples and objects (spec, "Collection Values")
    ("empty tuple", "[]", tup()),
    ("empty tuple with newline", "[\n]", tup()),
    ("tuple", "[1, 2, 3]", tup(num(1), num(2), num(3))),
    ("tuple trailing comma", "[1, 2,]", tup(num(1), num(2))),
    ("tuple over lines", "[\n  1,\n  2,\n]", tup(num(1), num(2))),
    ("nested tuple", "[[1], []]", tup(tup(num(1)), tup())),
    ("empty object", "{}", obj()),
    ("object with equals", "{a = 1}", obj(item(ik("a"), num(1)))),
    ("object with colon", "{a: 1}", obj(item(ik("a"), num(1)))),
    ("object commas", '{a = 1, b = "x"}', obj(item(ik("a"), num(1)), item(ik("b"), string("x")))),
    ("object trailing comma", "{a = 1,}", obj(item(ik("a"), num(1)))),
    (
        "object newline separated",
        "{\n  a = 1\n  b = 2\n}",
        obj(item(ik("a"), num(1)), item(ik("b"), num(2))),
    ),
    (
        "object comma and newline",
        "{\n  a = 1,\n  b = 2,\n}",
        obj(item(ik("a"), num(1)), item(ik("b"), num(2))),
    ),
    ("object string key", '{"a b" = 1}', obj(item(string("a b"), num(1)))),
    ("object parenthesized key is a variable", "{(foo) = 1}", obj(item(paren(var("foo")), num(1)))),
    ("object number key", "{1 = 2}", obj(item(num(1), num(2)))),
    ("object keyword key is a name", "{true = 1}", obj(item(ik("true"), num(1)))),
    ("object traversal key is an expression", "{a.b = 1}", obj(item(var("a", at("b")), num(1)))),
    (
        "object value over lines in parentheses",
        "{a = (1\n + 2)}",
        obj(item(ik("a"), paren(binop(Op.ADD, num(1), num(2))))),
    ),
    ("object in tuple", "[{a = 1}, {}]", tup(obj(item(ik("a"), num(1))), obj())),
    # Traversals (spec, "Variables", "Index Operator", "Attribute Access Operator")
    ("variable", "a", var("a")),
    ("dashed variable", "a-b", var("a-b")),
    ("attribute chain", "aws_vpc.main.id", var("aws_vpc", at("main"), at("id"))),
    ("constant index", "a[0]", var("a", ix(num(0)))),
    ("string index", 'a["k"]', var("a", ix(string("k")))),
    ("mixed traversal", "a.b[0].c", var("a", at("b"), ix(num(0)), at("c"))),
    ("legacy index", "a.0", var("a", lg(0))),
    ("legacy index then attribute", "a.0.b", var("a", lg(0), at("b"))),
    ("legacy index then bracket", "a.1[2]", var("a", lg(1), ix(num(2)))),
    ("non-constant index", "a[b]", Index(var("a"), var("b"), False, R)),
    ("index with expression", "a[1 + 1]", Index(var("a"), binop(Op.ADD, num(1), num(1)), False, R)),
    ("negative index is not constant", "a[-1]", Index(var("a"), neg(num(1)), False, R)),
    (
        "traversal continues after a non-constant index",
        "a[b].c",
        GetAttr(Index(var("a"), var("b"), False, R), "c", R),
    ),
    ("index of a tuple", "[1][0]", Index(tup(num(1)), num(0), False, R)),
    ("attribute of a call", "f(a).b", GetAttr(call("f", var("a")), "b", R)),
    ("legacy index of a call", "f(a).0", Index(call("f", var("a")), num(0), True, R)),
    ("attribute of a parenthesized term", "(a).b", GetAttr(paren(var("a")), "b", R)),
    ("attribute of a keyword literal", "null.a", GetAttr(NULL, "a", R)),
    ("index may span lines", "a[\n0\n]", var("a", ix(num(0)))),
    # Splats (spec, "Splat Operators")
    ("attribute splat", "a.*.b", splat(var("a"), SplatKind.ATTRIBUTE, at("b"))),
    ("bare attribute splat", "a.*", splat(var("a"), SplatKind.ATTRIBUTE)),
    ("full splat", "a[*].b", splat(var("a"), SplatKind.FULL, at("b"))),
    ("bare full splat", "a[*]", splat(var("a"), SplatKind.FULL)),
    (
        "spec example: tuple.*.foo.bar[0]",
        "tuple.*.foo.bar[0]",
        Index(splat(var("tuple"), SplatKind.ATTRIBUTE, at("foo"), at("bar")), num(0), False, R),
    ),
    (
        "spec example: tuple[*].foo.bar[0]",
        "tuple[*].foo.bar[0]",
        splat(var("tuple"), SplatKind.FULL, at("foo"), at("bar"), ix(num(0))),
    ),
    (
        "splat after a traversal",
        "a.b[0].c[*].d",
        splat(var("a", at("b"), ix(num(0)), at("c")), SplatKind.FULL, at("d")),
    ),
    (
        "attribute splat then legacy index applies to the result",
        "a.*.b.0",
        Index(splat(var("a"), SplatKind.ATTRIBUTE, at("b")), num(0), True, R),
    ),
    ("full splat with a legacy index", "a[*].0", splat(var("a"), SplatKind.FULL, lg(0))),
    # Function calls (spec, "Functions and Function Calls")
    ("call without arguments", "f()", call("f")),
    ("call", "f(a, 1)", call("f", var("a"), num(1))),
    ("call with trailing comma", "f(a,)", call("f", var("a"))),
    ("call expanding the last argument", "f(a...)", call("f", var("a"), expand=True)),
    (
        "call expanding after other arguments",
        "f(a, b...)",
        call("f", var("a"), var("b"), expand=True),
    ),
    ("call over lines", "f(\n  a,\n  b\n)", call("f", var("a"), var("b"))),
    ("call of a keyword name", "null(a)", call("null", var("a"))),
    ("namespaced call", "provider::p::f(a)", call("provider::p::f", var("a"))),
    ("namespaced core call", "core::upper(a)", call("core::upper", var("a"))),
    ("nested calls", "f(g(a), h())", call("f", call("g", var("a")), call("h"))),
    # Operators and precedence (spec, "Operations", lines 641-657)
    ("unary minus", "-a", neg(var("a"))),
    ("unary not", "!a", inv(var("a"))),
    ("unary applied twice", "!!a", inv(inv(var("a")))),
    ("unary binds weaker than traversal", "-a.b", neg(var("a", at("b")))),
    ("unary binds tighter than binary", "-1 + 2", binop(Op.ADD, neg(num(1)), num(2))),
    ("unary not before comparison", "!a == b", binop(Op.EQ, inv(var("a")), var("b"))),
    ("minus with spaces", "a - b", binop(Op.SUB, var("a"), var("b"))),
    ("minus before a number", "a -1", binop(Op.SUB, var("a"), num(1))),
    (
        "level 6 over level 5",
        "a + b * c",
        binop(Op.ADD, var("a"), binop(Op.MUL, var("b"), var("c"))),
    ),
    ("level 6 first", "a * b + c", binop(Op.ADD, binop(Op.MUL, var("a"), var("b")), var("c"))),
    (
        "level 5 over level 4",
        "a < b + c",
        binop(Op.LT, var("a"), binop(Op.ADD, var("b"), var("c"))),
    ),
    (
        "level 4 over level 3",
        "a == b < c",
        binop(Op.EQ, var("a"), binop(Op.LT, var("b"), var("c"))),
    ),
    (
        "level 3 over level 2",
        "a && b == c",
        binop(Op.AND, var("a"), binop(Op.EQ, var("b"), var("c"))),
    ),
    (
        "level 2 over level 1",
        "a || b && c",
        binop(Op.OR, var("a"), binop(Op.AND, var("b"), var("c"))),
    ),
    ("level 1 first", "a && b || c", binop(Op.OR, binop(Op.AND, var("a"), var("b")), var("c"))),
    (
        "every level in one chain",
        "a || b && c == d < e + f * g",
        binop(
            Op.OR,
            var("a"),
            binop(
                Op.AND,
                var("b"),
                binop(
                    Op.EQ,
                    var("c"),
                    binop(
                        Op.LT, var("d"), binop(Op.ADD, var("e"), binop(Op.MUL, var("f"), var("g")))
                    ),
                ),
            ),
        ),
    ),
    (
        "spec associativity: x / y * z",
        "x / y * z",
        binop(Op.MUL, binop(Op.DIV, var("x"), var("y")), var("z")),
    ),
    (
        "left associative minus",
        "a - b - c",
        binop(Op.SUB, binop(Op.SUB, var("a"), var("b")), var("c")),
    ),
    (
        "left associative remainder",
        "a % b * c",
        binop(Op.MUL, binop(Op.MOD, var("a"), var("b")), var("c")),
    ),
    (
        "left associative equality",
        "a == b != c",
        binop(Op.NE, binop(Op.EQ, var("a"), var("b")), var("c")),
    ),
    (
        "left associative comparison",
        "a < b >= c",
        binop(Op.GE, binop(Op.LT, var("a"), var("b")), var("c")),
    ),
    (
        "left associative or",
        "a || b || c",
        binop(Op.OR, binop(Op.OR, var("a"), var("b")), var("c")),
    ),
    (
        "parentheses override precedence",
        "(a + b) * c",
        binop(Op.MUL, paren(binop(Op.ADD, var("a"), var("b"))), var("c")),
    ),
    ("parentheses over lines", "(\na\n)", paren(var("a"))),
    # Conditional (spec, "Conditional Operator")
    ("conditional", "a ? b : c", cond(var("a"), var("b"), var("c"))),
    (
        "conditional is right associative",
        "a ? b : c ? d : e",
        cond(var("a"), var("b"), cond(var("c"), var("d"), var("e"))),
    ),
    (
        "conditional in the true branch",
        "a ? b ? c : d : e",
        cond(var("a"), cond(var("b"), var("c"), var("d")), var("e")),
    ),
    (
        "conditional binds weaker than ||",
        "a || b ? c : d",
        cond(binop(Op.OR, var("a"), var("b")), var("c"), var("d")),
    ),
    (
        "false branch takes the whole expression",
        "a ? b : c || d",
        cond(var("a"), var("b"), binop(Op.OR, var("c"), var("d"))),
    ),
    (
        "conditional over lines in parentheses",
        "(a ?\n b :\n c)",
        paren(cond(var("a"), var("b"), var("c"))),
    ),
    # For expressions (spec, "For Expressions": the examples)
    (
        "spec: [for v in [a, b]: v]",
        '[for v in ["a", "b"]: v]',
        for_tuple(None, "v", tup(string("a"), string("b")), var("v")),
    ),
    (
        "spec: [for i, v in ...: i]",
        '[for i, v in ["a", "b"]: i]',
        for_tuple("i", "v", tup(string("a"), string("b")), var("i")),
    ),
    (
        "spec: {for i, v in ...: v => i}",
        '{for i, v in ["a", "b"]: v => i}',
        for_object("i", "v", tup(string("a"), string("b")), var("v"), var("i")),
    ),
    (
        "spec: grouping ellipsis",
        '{for i, v in ["a", "a", "b"]: v => i...}',
        for_object(
            "i", "v", tup(string("a"), string("a"), string("b")), var("v"), var("i"), group=True
        ),
    ),
    (
        "spec: if filter",
        '[for i, v in ["a", "b", "c"]: v if i < 2]',
        for_tuple(
            "i",
            "v",
            tup(string("a"), string("b"), string("c")),
            var("v"),
            binop(Op.LT, var("i"), num(2)),
        ),
    ),
    (
        "for with spaces around the colon",
        "[for v in a : v]",
        for_tuple(None, "v", var("a"), var("v")),
    ),
    (
        "object for with if",
        "{for k, v in a : k => v if v}",
        for_object("k", "v", var("a"), var("k"), var("v"), var("v")),
    ),
    (
        "object for with grouping and if",
        "{for k, v in a : k => v... if v}",
        for_object("k", "v", var("a"), var("k"), var("v"), var("v"), group=True),
    ),
    (
        "for over lines",
        "[\n  for v in a :\n  v\n  if v\n]",
        for_tuple(None, "v", var("a"), var("v"), var("v")),
    ),
    (
        "for variables may be named in, if and for",
        "[for in in a : in]",
        for_tuple(None, "in", var("a"), var("in")),
    ),
    (
        "for variable named for",
        "[for for in a : for]",
        for_tuple(None, "for", var("a"), var("for")),
    ),
    (
        "for nested in the collection",
        "[for x in [for y in a : y] : x]",
        for_tuple(None, "x", for_tuple(None, "y", var("a"), var("y")), var("x")),
    ),
    (
        "for value with a conditional",
        "[for x in a : x ? 1 : 2]",
        for_tuple(None, "x", var("a"), cond(var("x"), num(1), num(2))),
    ),
    (
        "collection that is a conditional",
        "[for x in a ? b : c : x]",
        for_tuple(None, "x", cond(var("a"), var("b"), var("c")), var("x")),
    ),
    (
        "spec: key literally named for, quoted",
        '{"for" = 1, baz = 2}',
        obj(item(string("for"), num(1)), item(ik("baz"), num(2))),
    ),
    (
        "spec: key named for, reordered",
        "{baz = 2, for = 1}",
        obj(item(ik("baz"), num(2)), item(ik("for"), num(1))),
    ),
    (
        "spec: parenthesized variable named for",
        "[(for), foo, baz]",
        tup(paren(var("for")), var("foo"), var("baz")),
    ),
    (
        "spec: parenthesized key named for",
        "{(for) = 1, baz = 2}",
        obj(item(paren(var("for")), num(1)), item(ik("baz"), num(2))),
    ),
    # Comments in expressions (spec, "Comments and Whitespace")
    ("inline comment between operands", "1 /* c */ + 2", binop(Op.ADD, num(1), num(2))),
    (
        "inline comment across lines is whitespace",
        "1 /* a\n b */ + 2",
        binop(Op.ADD, num(1), num(2)),
    ),
    ("line comment in a tuple", "[1, # c\n 2]", tup(num(1), num(2))),
    ("slash comment in a call", "f(a, // c\n b)", call("f", var("a"), var("b"))),
    (
        "inline comment in an object",
        "{a = 1, /* c */ b = 2}",
        obj(item(ik("a"), num(1)), item(ik("b"), num(2))),
    ),
    (
        "line comment in an object",
        "{\n a = 1 # c\n b = 2 // d\n}",
        obj(item(ik("a"), num(1)), item(ik("b"), num(2))),
    ),
    ("comment inside an interpolation", '"${ a /* c */ }"', tpl(interp(var("a")))),
]


class TestValidExpressions(unittest.TestCase):
    def test_table_has_at_least_sixty_cases(self) -> None:
        self.assertGreaterEqual(len(VALID_EXPRESSIONS), 60)
        names = [name for name, _, _ in VALID_EXPRESSIONS]
        self.assertEqual(len(names), len(set(names)), "case names must be unique")

    def test_every_valid_case_parses_to_the_hand_written_tree(self) -> None:
        for name, source, expected in VALID_EXPRESSIONS:
            with self.subTest(case=name):
                self.assertEqual(expr_of(source), expected)

    def test_every_binary_operator(self) -> None:
        table = {
            "*": Op.MUL,
            "/": Op.DIV,
            "%": Op.MOD,
            "+": Op.ADD,
            "-": Op.SUB,
            ">": Op.GT,
            ">=": Op.GE,
            "<": Op.LT,
            "<=": Op.LE,
            "==": Op.EQ,
            "!=": Op.NE,
            "&&": Op.AND,
            "||": Op.OR,
        }
        self.assertEqual(len(table), 13)
        for symbol, op in table.items():
            with self.subTest(op=symbol):
                self.assertEqual(expr_of(f"a {symbol} b"), binop(op, var("a"), var("b")))

    def test_every_escape_sequence(self) -> None:
        cases = {
            r"\n": "\n",
            r"\r": "\r",
            r"\t": "\t",
            r"\"": '"',
            r"\\": "\\",
            r"\u0041": "A",
            r"\u20AC": "\u20ac",
            r"\U0001F600": "\U0001f600",
        }
        for escape, value in cases.items():
            with self.subTest(escape=escape):
                self.assertEqual(expr_of(f'"{escape}"'), string(value, f'"{escape}"'))

    def test_numbers_are_exact_and_never_floats(self) -> None:
        for source in ("1.5", "1e3", "0.1", "1e-3", "123456789012345678901234567890.5", "1e400"):
            with self.subTest(source=source):
                tree = expr_of(source)
                assert isinstance(tree, Literal)
                self.assertIsInstance(tree.value, (int, Decimal))
                self.assertNotIsInstance(tree.value, float)
                self.assertEqual(tree.text, source)
        self.assertEqual(expr_of("0.1").value, D("0.1"))  # type: ignore[attr-defined]
        self.assertEqual(expr_of("1e3").value, 1000)  # type: ignore[attr-defined]
        self.assertEqual(expr_of("1e400").value, D("1e400"))  # type: ignore[attr-defined]

    def test_a_huge_integer_literal_is_not_converted_to_a_giant_int(self) -> None:
        tree = expr_of("9" * 5000)
        assert isinstance(tree, Literal)
        self.assertIsInstance(tree.value, Decimal)
        tree = expr_of("1e999999")
        assert isinstance(tree, Literal)
        self.assertIsInstance(tree.value, Decimal)

    def test_unicode_is_kept_exactly(self) -> None:
        self.assertEqual(expr_of('"e\u0301"'), string("e\u0301"))
        self.assertEqual(expr_of('"\u00e9"'), string("\u00e9"))
        self.assertNotEqual(expr_of('"e\u0301"'), expr_of('"\u00e9"'))

    def test_trees_are_hashable_and_immutable(self) -> None:
        tree = expr_of("[a.b, {c = 1}]")
        hash(tree)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            tree.elements = ()  # type: ignore[attr-defined]
        for field in dataclasses.fields(Tuple):
            self.assertNotIn(field.type, ("list", "dict", "set"))


# --- structure -------------------------------------------------------------------------------


class TestStructure(unittest.TestCase):
    def body(self, text: str) -> Body:
        return parse_file(text, "t.tf")

    def test_attribute(self) -> None:
        self.assertEqual(self.body("a = 1\n").items, (attribute("a", num(1)),))

    def test_attribute_at_the_end_of_the_file_needs_no_newline(self) -> None:
        self.assertEqual(self.body("a = 1").items, (attribute("a", num(1)),))

    def test_empty_inputs(self) -> None:
        for text in ("", "\n\n", "  \t\n", "# only a comment", "/* c */", "// c\n"):
            with self.subTest(text=text):
                self.assertEqual(self.body(text).items, ())

    def test_blocks_with_zero_one_and_two_labels(self) -> None:
        text = 'a {\n}\nb "x" {\n}\nc "x" "y" {\n}\n'
        self.assertEqual(
            self.body(text).items,
            (
                block("a", ()),
                block("b", (label("x"),)),
                block("c", (label("x"), label("y"))),
            ),
        )

    def test_identifier_labels(self) -> None:
        self.assertEqual(
            self.body("a b c {\n}\n").items,
            (block("a", (label("b", False), label("c", False))),),
        )

    def test_mixed_labels_and_label_escapes(self) -> None:
        self.assertEqual(
            self.body('a "x\\u0079" z {\n}\n').items,
            (block("a", (label("xy"), label("z", False))),),
        )
        self.assertEqual(self.body('a "$${b}" {\n}\n').items, (block("a", (label("${b}"),)),))

    def test_nested_blocks_and_attributes_keep_source_order(self) -> None:
        text = 'r "t" "n" {\n  a = 1\n  b {\n    c = 2\n  }\n  d = 3\n}\n'
        self.assertEqual(
            self.body(text).items,
            (
                block(
                    "r",
                    (label("t"), label("n")),
                    attribute("a", num(1)),
                    block("b", (), attribute("c", num(2))),
                    attribute("d", num(3)),
                ),
            ),
        )

    def test_one_line_blocks(self) -> None:
        self.assertEqual(self.body("a {}\n").items, (block("a", (), one_line=True),))
        self.assertEqual(
            self.body("a { b = 1 }\n").items,
            (block("a", (), attribute("b", num(1)), one_line=True),),
        )
        self.assertEqual(
            self.body('a "x" {b=[\n1]}\n').items,
            (block("a", (label("x"),), attribute("b", tup(num(1))), one_line=True),),
        )
        self.assertEqual(self.body("a { /* c */ }\n").items, (block("a", (), one_line=True),))

    def test_a_block_that_opens_with_a_comment_is_multi_line(self) -> None:
        self.assertEqual(
            self.body("a { # c\n  b = 1\n}\n").items,
            (block("a", (), attribute("b", num(1))),),
        )

    def test_block_at_the_end_of_the_file_needs_no_newline(self) -> None:
        self.assertEqual(self.body("a {\n}").items, (block("a", ()),))
        self.assertEqual(self.body("a {}").items, (block("a", (), one_line=True),))

    def test_c84_three_forms_of_inline_rules_stay_distinct(self) -> None:
        # Registry §2.6 / C-84: ``ingress { }`` (blocks), ``ingress = []`` (explicit empty) and
        # an absent argument are three different syntax forms.
        blocks = self.body("sg {\n  ingress {\n  }\n}\n").items[0]
        explicit_empty = self.body("sg {\n  ingress = []\n}\n").items[0]
        absent = self.body("sg {\n}\n").items[0]
        assert (
            isinstance(blocks, Block)
            and isinstance(explicit_empty, Block)
            and isinstance(absent, Block)
        )
        self.assertIsInstance(blocks.body.items[0], Block)
        self.assertEqual(blocks.body.items[0], block("ingress", ()))
        self.assertEqual(explicit_empty.body.items, (attribute("ingress", tup()),))
        self.assertIsInstance(explicit_empty.body.items[0], Attribute)
        self.assertEqual(absent.body.items, ())
        self.assertNotEqual(blocks.body.items, explicit_empty.body.items)

    def test_block_and_attribute_with_the_same_name_are_both_kept(self) -> None:
        body = self.body("sg {\n  ingress = []\n  ingress {\n  }\n}\n")
        (sg,) = body.items
        assert isinstance(sg, Block)
        self.assertEqual(len(sg.body.items), 2)

    def test_duplicate_attributes_are_kept_for_the_structural_check(self) -> None:
        # Duplicate detection is a Terraform structural rule (C-94), done by the loader.
        self.assertEqual(len(self.body("a = 1\na = 2\n").items), 2)

    def test_comments_in_every_position_the_spec_allows(self) -> None:
        text = (
            "# leading\n"
            "/* inline */ a /* before eq */ = /* after eq */ 1 # trailing\n"
            "// slash\n"
            "b { # after open\n"
            "  # own line\n"
            "  c = 2 /* then */ // more\n"
            "} # after close\n"
            "d {} /* after one-line */ # x\n"
            "# at the end without newline"
        )
        self.assertEqual(
            self.body(text).items,
            (
                attribute("a", num(1)),
                block("b", (), attribute("c", num(2))),
                block("d", (), one_line=True),
            ),
        )

    def test_crlf_line_endings(self) -> None:
        self.assertEqual(
            self.body('a = 1\r\nb "x" {\r\n  c = 2\r\n}\r\n').items,
            (attribute("a", num(1)), block("b", (label("x"),), attribute("c", num(2)))),
        )

    def test_attribute_values_may_be_any_expression_at_the_top_level(self) -> None:
        text = 'tags = {\n  Name = "x"\n  Env  = var.env\n}\n'
        (tags,) = self.body(text).items
        assert isinstance(tags, Attribute)
        self.assertEqual(
            tags.expr, obj(item(ik("Name"), string("x")), item(ik("Env"), var("var", at("env"))))
        )

    def test_heredoc_ends_the_attribute(self) -> None:
        body = self.body("a = <<EOT\nhi\nEOT\nb = 1\n")
        self.assertEqual(
            body.items,
            (attribute("a", Heredoc("EOT", False, (lit("hi\n"),), R)), attribute("b", num(1))),
        )


class TestRanges(unittest.TestCase):
    def test_ranges_follow_the_text(self) -> None:
        body = parse_file('ab = "x"\n', "f.tf")
        (attr,) = body.items
        assert isinstance(attr, Attribute)
        self.assertEqual(attr.name_range, SourceRange("f.tf", 1, 1, 1, 3, 0, 2))
        self.assertEqual(attr.expr.range, SourceRange("f.tf", 1, 6, 1, 9, 5, 8))
        self.assertEqual(attr.range, SourceRange("f.tf", 1, 1, 1, 9, 0, 8))

    def test_block_range_covers_header_to_closing_brace(self) -> None:
        body = parse_file('a "b" {\n  c = 1\n}\n', "f.tf")
        (blk,) = body.items
        assert isinstance(blk, Block)
        self.assertEqual(blk.range, SourceRange("f.tf", 1, 1, 3, 2, 0, 17))
        self.assertEqual(blk.type_range, SourceRange("f.tf", 1, 1, 1, 2, 0, 1))
        self.assertEqual(blk.labels[0].range, SourceRange("f.tf", 1, 3, 1, 6, 2, 5))

    def test_binary_operation_range(self) -> None:
        body = parse_file("x = a + bb\n", "f.tf")
        (attr,) = body.items
        assert isinstance(attr, Attribute)
        self.assertEqual(attr.expr.range, SourceRange("f.tf", 1, 5, 1, 11, 4, 10))

    def test_byte_offsets_count_utf8(self) -> None:
        body = parse_file('é = "\u20ac"\n', "f.tf")
        (attr,) = body.items
        assert isinstance(attr, Attribute)
        self.assertEqual(attr.name_range.end_byte, 2)
        self.assertEqual(attr.expr.range.start_byte, 5)
        self.assertEqual(attr.expr.range.end_byte, 10)
        self.assertEqual(attr.expr.range.start_column, 5)


# --- invalid inputs --------------------------------------------------------------------------

INVALID: list[tuple[str, str, str]] = [
    # (case, source, rule code)
    ("a number cannot start an item", "1 = 2\n", "parse.expected_argument_or_block"),
    ("argument names must not be quoted", '"a" = 1\n', "parse.expected_argument_or_block"),
    ("an equals sign cannot start an item", "= 1\n", "parse.expected_argument_or_block"),
    ("unmatched closing brace", "a = 1\n}\n", "parse.unexpected_token"),
    ("missing expression", "a =\n", "parse.expected_expression"),
    ("closing paren where an expression belongs", "a = )\n", "parse.expected_expression"),
    ("unary plus does not exist", "a = +1\n", "parse.expected_expression"),
    ("empty parentheses", "a = ()\n", "parse.expected_expression"),
    ("tuple with only a comma", "a = [,]\n", "parse.expected_expression"),
    ("tuple with a double comma", "a = [1,,2]\n", "parse.expected_expression"),
    ("call with only a comma", "a = f(,)\n", "parse.expected_expression"),
    ("empty interpolation", 'a = "${}"\n', "parse.expected_expression"),
    ("empty index", "a = b[]\n", "parse.expected_expression"),
    ("operator at the end of a line", "a = 1 +\n  2\n", "parse.expected_expression"),
    ("conditional split by a line break", "a = b ?\n  1 : 2\n", "parse.expected_expression"),
    ("block header without a brace", "a b\n", "parse.invalid_block_definition"),
    ("brace on the next line", 'a "b"\n{\n}\n', "parse.invalid_block_definition"),
    ("equals after a label", 'variable "a" b = 1\n', "parse.invalid_block_definition"),
    ("number as a label", "a 1 {\n}\n", "parse.invalid_block_definition"),
    ("interpolation in a label", 'a "${x}" {\n}\n', "parse.template_in_label"),
    ("directive in a label", 'a "%{ if x }y%{ endif }" {\n}\n', "parse.template_in_label"),
    ("two arguments on one line", "a = 1 b = 2\n", "parse.missing_newline_after_argument"),
    (
        "closing brace on the argument line",
        "a {\n  b = 1 }\n",
        "parse.missing_newline_after_argument",
    ),
    ("semicolon is not a separator", "a = 1;\n", "lex.invalid_character"),
    ("block followed by a block", "a {}\nb {} c {}\n", "parse.missing_newline_after_block"),
    ("token after a one-line block", "a { b = 1 } x\n", "parse.missing_newline_after_block"),
    ("multi-line block followed by a token", "a {\n} b\n", "parse.missing_newline_after_block"),
    ("one-line block with two arguments", "a { b = 1, c = 2 }\n", "parse.single_line_block"),
    ("one-line block with a nested block", "a { b {} }\n", "parse.single_line_block"),
    ("one-line block continued on the next line", "a { b = 1\n}\n", "parse.single_line_block"),
    ("block without its closing brace", "a {\n  b = 1\n", "parse.unclosed_block"),
    ("one-line block cut off", "a {", "parse.unclosed_block"),
    ("nested block without its closing brace", "a {\n  b {\n  }\n", "parse.unclosed_block"),
    ("tuple without its bracket", "a = [1, 2", "parse.unclosed_bracket"),
    ("parenthesis without its partner", "a = (1", "parse.unclosed_bracket"),
    ("call without its parenthesis", "a = f(1", "parse.unclosed_bracket"),
    ("object without its brace", "a = {b = 1", "parse.unclosed_bracket"),
    ("index without its bracket", "a = x[1", "parse.unclosed_bracket"),
    ("tuple items need commas", "a = [1 2]\n", "parse.missing_item_separator"),
    ("a line break is not a tuple separator", "a = [1\n2]\n", "parse.missing_item_separator"),
    ("object key without a value", "a = {b}\n", "parse.missing_attribute_value"),
    ("object key and value on different lines", "a = {b\n= 1}\n", "parse.missing_attribute_value"),
    ("object value on the next line", "a = {b =\n1}\n", "parse.expected_expression"),
    ("object items need a separator", "a = {b = 1 c = 2}\n", "parse.missing_attribute_separator"),
    ("call arguments need commas", "a = f(x y)\n", "parse.missing_argument_separator"),
    ("expanded argument that is not last", "a = f(x..., y)\n", "parse.expand_not_last"),
    ("expanded argument with a trailing comma", "a = f(x...,)\n", "parse.expand_not_last"),
    ("namespace without a name", "a = x::\n", "parse.invalid_function_name"),
    ("namespaced name that is not a call", "a = x::y\n", "parse.invalid_function_name"),
    ("dot without a name", "a = b.\n", "parse.invalid_attribute_name"),
    ("dot and an operator", "a = b.+\n", "parse.invalid_attribute_name"),
    ("two dots", "a = b..c\n", "parse.invalid_attribute_name"),
    ("attribute on the next line", "a = b\n  .c\n", "parse.expected_argument_or_block"),
    ("chained legacy indexes", "a = b.0.0\n", "parse.invalid_legacy_index"),
    ("legacy index with an exponent", "a = b.1e3\n", "parse.invalid_legacy_index"),
    ("splat inside an attribute-only splat", "a = b.*.c.*.d\n", "parse.nested_splat"),
    ("conditional without a false branch", "a = b ? c\n", "parse.missing_conditional_colon"),
    ("colon on the next line", "a = b ? c\n  : d\n", "parse.missing_conditional_colon"),
    (
        "for without a variable (spec: [for, foo, baz])",
        "a = [for, foo, baz]\n",
        "parse.invalid_for",
    ),
    (
        "object for without a variable (spec: {for = 1})",
        "a = {for = 1, baz = 2}\n",
        "parse.invalid_for",
    ),
    ("for without the in keyword", "a = [for x y : x]\n", "parse.invalid_for"),
    ("for with three variables", "a = [for a, b, c in y : a]\n", "parse.invalid_for"),
    ("for without a colon", "a = [for x in y x]\n", "parse.invalid_for"),
    ("tuple for with grouping", "a = [for x in y : x...]\n", "parse.invalid_for"),
    ("tuple for with a key", "a = [for x in y : x => x]\n", "parse.invalid_for"),
    ("object for without a key", "a = {for x in y : x}\n", "parse.invalid_for"),
    ("for with a missing second variable", "a = [for x, in y : x]\n", "parse.invalid_for"),
    ("unknown directive keyword", 'a = "%{ iffy }"\n', "parse.invalid_template_directive"),
    ("directive without a keyword", 'a = "%{ 1 }"\n', "parse.invalid_template_directive"),
    (
        "else with arguments",
        'a = "%{ if x }a%{ else y }b%{ endif }"\n',
        "parse.invalid_template_directive",
    ),
    ("for directive without a variable", 'a = "%{ for }"\n', "parse.invalid_template_directive"),
    ("for directive without in", 'a = "%{ for x y }"\n', "parse.invalid_template_directive"),
    ("else without if", 'a = "%{ else }"\n', "parse.unbalanced_directive"),
    ("endif without if", 'a = "%{ endif }"\n', "parse.unbalanced_directive"),
    ("endfor without for", 'a = "%{ endfor }"\n', "parse.unbalanced_directive"),
    ("if without endif", 'a = "%{ if x }a"\n', "parse.unbalanced_directive"),
    ("for closed by endif", 'a = "%{ for x in y }a%{ endif }"\n', "parse.unbalanced_directive"),
    ("if closed by endfor", 'a = "%{ if x }a%{ endfor }"\n', "parse.unbalanced_directive"),
    ("heredoc directive unbalanced", "a = <<EOT\n%{ endif }\nEOT\n", "parse.unbalanced_directive"),
    # Errors found by the lexer reach the caller through parse_file
    ("invalid escape in a value", 'a = "\\q"\n', "lex.invalid_escape"),
    ("unterminated string", 'a = "abc\n', "lex.newline_in_string"),
    ("unterminated comment", "a = 1 /* x\n", "lex.unterminated_comment"),
    ("unterminated heredoc", "a = <<EOT\nhi\n", "lex.unterminated_heredoc"),
    ("bad heredoc introduction", "a = << EOT\nhi\nEOT\n", "lex.invalid_heredoc_intro"),
    ("bitwise operator", "a = b & c\n", "lex.invalid_character"),
    ("byte order mark", "\ufeffa = 1\n", "lex.invalid_character"),
    ("lone surrogate", "a = \ud800\n", "lex.invalid_utf8"),
]


class TestInvalidInputs(unittest.TestCase):
    def test_table_has_at_least_thirty_cases(self) -> None:
        self.assertGreaterEqual(len(INVALID), 30)
        names = [name for name, _, _ in INVALID]
        self.assertEqual(len(names), len(set(names)))

    def test_every_invalid_case_raises_its_rule_code(self) -> None:
        for name, source, code in INVALID:
            with self.subTest(case=name):
                self.assertEqual(code_of(source), code)

    def test_every_error_is_a_syntax_error_with_a_location(self) -> None:
        for name, source, code in INVALID:
            with self.subTest(case=name):
                try:
                    parse_file(source, "e.tf")
                except HclSyntaxError as exc:
                    self.assertEqual(exc.range.file, "e.tf")
                    self.assertGreaterEqual(exc.range.start_line, 1)
                    self.assertGreaterEqual(exc.range.start_column, 1)
                    self.assertIn(code, RULES)
                else:
                    self.fail("no error")

    def test_error_location_points_at_the_problem(self) -> None:
        with self.assertRaises(HclSyntaxError) as caught:
            parse_file("a = 1\nb = 2 c = 3\n", "e.tf")
        rng = caught.exception.range
        self.assertEqual((rng.start_line, rng.start_column), (2, 7))

    def test_a_tab_is_one_column(self) -> None:
        with self.assertRaises(HclSyntaxError) as caught:
            parse_file("\ta = 1 b\n", "e.tf")
        self.assertEqual(caught.exception.range.start_column, 8)

    def test_the_first_error_is_reported(self) -> None:
        self.assertEqual(code_of("a = ]\nb = )\n"), "parse.expected_expression")
        self.assertEqual(code_of("a = (\nb = ]\n"), "parse.unclosed_bracket")

    def test_every_parse_rule_in_the_registry_is_exercised_by_a_case(self) -> None:
        exercised = {code for _, _, code in INVALID}
        parse_rules = {code for code in RULES if code.startswith("parse.")}
        self.assertEqual(parse_rules - exercised, set(), "a parse rule has no invalid case")


# --- limits and robustness (C-93, Doc 12 §22) -----------------------------------------------


def nested(open_: str, close: str, depth: int, inner: str = "1") -> str:
    return f"x = {open_ * depth}{inner}{close * depth}\n"


class TestNestingLimit(unittest.TestCase):
    def assert_limit(self, build: Callable[[int], str]) -> None:
        parse_file(build(MAX_NESTING_DEPTH), "t.tf")  # exactly at the limit: fine
        with self.assertRaises(HclLimitError) as caught:
            parse_file(build(MAX_NESTING_DEPTH + 1), "t.tf")
        self.assertEqual(caught.exception.code, "limit.nesting_depth")

    def test_the_limit_is_64(self) -> None:
        self.assertEqual(MAX_NESTING_DEPTH, 64)

    def test_nested_tuples(self) -> None:
        self.assert_limit(lambda n: nested("[", "]", n))

    def test_nested_objects(self) -> None:
        self.assert_limit(lambda n: "x = " + "{a = " * n + "1" + "}" * n + "\n")

    def test_nested_parentheses(self) -> None:
        self.assert_limit(lambda n: nested("(", ")", n))

    def test_nested_calls(self) -> None:
        self.assert_limit(lambda n: "x = " + "f(" * n + "1" + ")" * n + "\n")

    def test_nested_indexes(self) -> None:
        self.assert_limit(lambda n: "x = a" + "[b" * (n - 1) + "[1" + "]" * n + "\n")

    def test_nested_unary_operators(self) -> None:
        self.assert_limit(lambda n: "x = " + "!" * n + "a\n")

    def test_chained_conditionals(self) -> None:
        self.assert_limit(lambda n: "x = " + "a ? b : " * n + "c\n")

    def test_nested_for_expressions(self) -> None:
        self.assert_limit(lambda n: "x = " + "[for v in " * n + "a" + " : v]" * n + "\n")

    def test_nested_interpolations(self) -> None:
        self.assert_limit(lambda n: 'x = "' + '${"' * (n - 1) + "${1}" + '"}' * (n - 1) + '"\n')

    def test_nested_directives(self) -> None:
        self.assert_limit(lambda n: 'x = "' + "%{ if a }" * n + "x" + "%{ endif }" * n + '"\n')

    def test_nested_blocks(self) -> None:
        self.assert_limit(lambda n: "a {\n" * n + "b = 1\n" + "}\n" * n)

    def test_nesting_counts_across_construct_kinds(self) -> None:
        def build(n: int) -> str:
            half = n // 2
            rest = n - half
            return "x = " + "[" * half + "(" * rest + "1" + ")" * rest + "]" * half + "\n"

        self.assert_limit(build)

    def test_a_chain_of_operators_counts_one_level_per_operator(self) -> None:
        # A left-associative chain is a tree as deep as the chain is long, so it counts (C-93).
        self.assert_limit(lambda n: "x = 1" + " + 1" * n + "\n")
        self.assert_limit(lambda n: "x = a" + " && a" * n + "\n")

    def test_a_chain_of_postfix_operations_counts_one_level_per_operation(self) -> None:
        self.assert_limit(lambda n: "x = f(a)" + ".b" * n + "\n")
        self.assert_limit(lambda n: "x = f(a)" + "[1]" * n + "\n")
        self.assert_limit(lambda n: "x = a" + "[b]" * n + "\n")

    def test_nesting_is_released_when_a_construct_ends(self) -> None:
        # Siblings do not add up: 64 levels, then another 64 levels.
        deep = "[" * MAX_NESTING_DEPTH + "1" + "]" * MAX_NESTING_DEPTH
        inner = "[" * (MAX_NESTING_DEPTH - 1) + "1" + "]" * (MAX_NESTING_DEPTH - 1)
        parse_file(f"x = [{inner}, {inner}]\ny = {deep}\n", "t.tf")
        chain = "1" + " + 1" * (MAX_NESTING_DEPTH - 1)
        parse_file(f"x = {chain}\ny = {chain}\nz = [{chain}, {chain}]\n", "t.tf")

    def test_very_deep_input_is_a_limit_error_not_a_recursion_error(self) -> None:
        for build in (
            lambda: "x = " + "[" * 100_000 + "\n",
            lambda: "x = " + "(" * 100_000 + "\n",
            lambda: "x = " + "!" * 100_000 + "a\n",
            lambda: "x = " + "a ? b : " * 50_000 + "c\n",
            lambda: "x = " + "f(" * 100_000 + "\n",
            lambda: "x = 1" + " + 1" * 100_000 + "\n",
            lambda: "x = f(a)" + ".b" * 100_000 + "\n",
            lambda: "a {\n" * 50_000,
        ):
            with self.subTest(build=build()[:12]):
                with self.assertRaises(HclLimitError) as caught:
                    parse_file(build(), "t.tf")
                self.assertEqual(caught.exception.code, "limit.nesting_depth")

    def test_long_flat_inputs_are_fine(self) -> None:
        # Flat sequences do not deepen the tree.
        parse_file("x = [" + "1, " * 50_000 + "1]\n", "t.tf")
        parse_file("x = {" + "".join(f"k{i} = 1, " for i in range(20_000)) + "}\n", "t.tf")
        parse_file("x = f(" + "a, " * 50_000 + "a)\n", "t.tf")
        parse_file("x = a" + "".join(f".c{i}" for i in range(50_000)) + "\n", "t.tf")
        parse_file("x = a" + "[0]" * 50_000 + "\n", "t.tf")
        parse_file('x = "' + "${a}" * 50_000 + '"\n', "t.tf")
        parse_file("".join(f"a{i} = 1\n" for i in range(50_000)), "t.tf")


class TestPurityAndRobustness(unittest.TestCase):
    TEXT = 'a "b" {\n  c = [for x in y : "${x}"]\n  d = <<-EOT\n    hi\n    EOT\n}\n'

    def test_parse_file_is_deterministic(self) -> None:
        first = parse_file(self.TEXT, "t.tf")
        second = parse_file(self.TEXT, "t.tf")
        self.assertEqual(first, second)
        self.assertEqual(repr(first), repr(second))

    def test_the_file_name_is_only_metadata(self) -> None:
        self.assertEqual(parse_file(self.TEXT, "a.tf"), parse_file(self.TEXT, "b.tf"))
        self.assertNotEqual(
            repr(parse_file(self.TEXT, "a.tf")), repr(parse_file(self.TEXT, "b.tf"))
        )

    def test_a_million_character_string_literal(self) -> None:
        body = parse_file('x = "' + "a" * 1_000_000 + '"\n', "t.tf")
        (attr,) = body.items
        assert isinstance(attr, Attribute) and isinstance(attr.expr, Literal)
        self.assertEqual(len(str(attr.expr.value)), 1_000_000)

    def test_unicode_edge_cases_are_accepted_or_rejected_cleanly(self) -> None:
        for text in (
            'x = "\x00"\n',
            'x = "\u202e"\n',
            'x = "e\u0301"\n',
            "# \x00\u202e\n",
            "x = 1 # \u0378\n",
        ):
            with self.subTest(text=text):
                parse_file(text, "t.tf")
        for text in ("x = \x00\n", "\u202ex = 1\n", "x\u200d = 1\n"):
            with self.subTest(text=text):
                self.assertEqual(code_of(text), "lex.invalid_character")


if __name__ == "__main__":
    unittest.main()
