"""Immutable syntax tree for the HCL native syntax (Doc 04 §4 "HCL / Terraform parsing"; C-91).

Every node is a frozen dataclass with ``slots``. Fields hold only scalars, enums, ``Decimal``,
other nodes and tuples of nodes (no list, dict or set), so a tree is hashable and cannot be
changed after the parser built it. Every node carries a ``SourceRange``.

Equality is structural: the ``range`` field is excluded from ``==`` and from hashing, so two
trees that differ only in where the text was written compare equal. ``repr`` shows the ranges.

Numbers keep the source text and an exact value: ``int`` when the literal is integral and small,
otherwise ``decimal.Decimal``. A float never appears (C-33: canonical JSON rejects floats).

Strings are the exact code points of the source after the escape sequences of the pinned
specification were applied. No Unicode normalization is performed (C-95).

Grammar source: ``hclsyntax/spec.md`` of ``hashicorp/hcl`` at tag ``v2.25.0`` (commit
00057cf06d7b38a3f89e6e54d622eee98322b314), recorded in ADR-003.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from decimal import Decimal


@dataclass(frozen=True, slots=True)
class SourceRange:
    """A half-open span of one file. Lines and columns start at 1; ``end_*`` is exclusive.

    Columns count Unicode code points (a tab is one column, as the pinned specification says).
    Byte offsets count bytes of the UTF-8 encoding of the whole file.
    """

    file: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    start_byte: int
    end_byte: int


class LiteralKind(enum.StrEnum):
    STRING = "STRING"
    NUMBER = "NUMBER"
    BOOL = "BOOL"
    NULL = "NULL"


class SplatKind(enum.StrEnum):
    ATTRIBUTE = "ATTRIBUTE"  # ``.*`` (attrSplat)
    FULL = "FULL"  # ``[*]`` (fullSplat)


class ForKind(enum.StrEnum):
    TUPLE = "TUPLE"  # ``[for ...]``
    OBJECT = "OBJECT"  # ``{for ...}``


class BinaryOperator(enum.StrEnum):
    MUL = "*"
    DIV = "/"
    MOD = "%"
    ADD = "+"
    SUB = "-"
    GT = ">"
    GE = ">="
    LT = "<"
    LE = "<="
    EQ = "=="
    NE = "!="
    AND = "&&"
    OR = "||"


class UnaryOperator(enum.StrEnum):
    NEG = "-"
    NOT = "!"


# --- Expressions -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Literal:
    """A number, ``true``/``false``, ``null``, or a quoted string with no template sequence.

    ``text`` is the source text (for a string, including its quotes). ``value`` is ``str``,
    ``int``, ``Decimal``, ``bool`` or ``None`` according to ``kind``.
    """

    kind: LiteralKind
    value: str | int | Decimal | bool | None
    text: str
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Strip:
    """The ``~`` strip markers of one template sequence (spec, "Template Literals")."""

    left: bool = False
    right: bool = False


@dataclass(frozen=True, slots=True)
class TemplateLiteral:
    """Literal text of a template, after escapes and strip markers were applied."""

    text: str
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class TemplateInterpolation:
    """``${ expr }``."""

    expr: Expression
    strip: Strip
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class TemplateIf:
    """``%{ if cond } ... %{ else } ... %{ endif }``; ``false_parts`` is None without ``else``."""

    condition: Expression
    true_parts: tuple[TemplatePart, ...]
    false_parts: tuple[TemplatePart, ...] | None
    strip_if: Strip
    strip_else: Strip | None
    strip_endif: Strip
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class TemplateFor:
    """``%{ for k, v in coll } ... %{ endfor }``; ``key_var`` is None with a single variable."""

    key_var: str | None
    value_var: str
    collection: Expression
    parts: tuple[TemplatePart, ...]
    strip_for: Strip
    strip_endfor: Strip
    range: SourceRange = field(compare=False)


TemplatePart = TemplateLiteral | TemplateInterpolation | TemplateIf | TemplateFor


@dataclass(frozen=True, slots=True)
class Template:
    """A quoted template with at least one interpolation or directive.

    A quoted string with only literal text is a ``Literal`` of kind STRING instead.
    """

    parts: tuple[TemplatePart, ...]
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Heredoc:
    """``<<MARKER`` or ``<<-MARKER`` template.

    ``strip_indent`` is True for ``<<-``. The literal parts are already de-indented in that case.
    The text keeps the newline sequence of every line, including the last content line.
    """

    marker: str
    strip_indent: bool
    parts: tuple[TemplatePart, ...]
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Tuple:
    elements: tuple[Expression, ...]
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class IdentifierKey:
    """An object key written as a bare identifier: a literal attribute name (spec, "Collection
    Values"), not a variable reference."""

    name: str
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class ObjectItem:
    key: IdentifierKey | Expression
    value: Expression
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Object:
    items: tuple[ObjectItem, ...]
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class AttrStep:
    """``.name``"""

    name: str
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class IndexStep:
    """``[key]``. Inside a ``ScopeTraversal`` the key is always a ``Literal``."""

    key: Expression
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class LegacyIndexStep:
    """``.0`` (spec, "Index Operator": the legacy index operator)."""

    index: int
    range: SourceRange = field(compare=False)


TraversalStep = AttrStep | IndexStep | LegacyIndexStep


@dataclass(frozen=True, slots=True)
class ScopeTraversal:
    """A variable with the attribute accesses and constant indexes written directly after it.

    ``aws_vpc.main.id`` is root ``aws_vpc`` with steps ``main`` and ``id``. A step whose key is
    not a literal (``a[b]``), a splat, or a step on any other kind of term ends the traversal and
    is a separate ``Index``, ``GetAttr`` or ``Splat`` node.
    """

    root: str
    steps: tuple[TraversalStep, ...]
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class FunctionCall:
    """``name(args)``; a namespaced name keeps its ``::`` separators (``provider::p::f``)."""

    name: str
    args: tuple[Expression, ...]
    expand_final: bool
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Conditional:
    condition: Expression
    true_expr: Expression
    false_expr: Expression
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class BinaryOp:
    op: BinaryOperator
    left: Expression
    right: Expression
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class UnaryOp:
    op: UnaryOperator
    operand: Expression
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class ForExpr:
    """``[for k, v in coll : value if cond]`` or ``{for k, v in coll : key => value... if cond}``.

    With one iteration variable, ``key_var`` is None and ``value_var`` is that variable.
    ``key_expr`` is set for the object form only; ``group`` is the trailing ``...``.
    """

    kind: ForKind
    key_var: str | None
    value_var: str
    collection: Expression
    key_expr: Expression | None
    value_expr: Expression
    condition: Expression | None
    group: bool
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Splat:
    """``source.*.a.b`` (attribute-only) or ``source[*].a[0]`` (full).

    ``steps`` are applied to every element. For the attribute-only form they are attribute
    accesses only; anything after them applies to the whole result and is a separate node.
    """

    source: Expression
    kind: SplatKind
    steps: tuple[TraversalStep, ...]
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Index:
    """``collection[key]`` where the collection is not a plain traversal or the key is not a
    literal; ``legacy`` is True for the ``.0`` form."""

    collection: Expression
    key: Expression
    legacy: bool
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class GetAttr:
    """``target.name`` where the target is not a plain traversal."""

    target: Expression
    name: str
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Parenthesized:
    expr: Expression
    range: SourceRange = field(compare=False)


Expression = (
    Literal
    | Template
    | Heredoc
    | Tuple
    | Object
    | ScopeTraversal
    | FunctionCall
    | Conditional
    | BinaryOp
    | UnaryOp
    | ForExpr
    | Splat
    | Index
    | GetAttr
    | Parenthesized
)


# --- Structure ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Attribute:
    """``name = expr``. ``ingress = []`` is an Attribute whose expression is an empty Tuple,
    which stays distinct from a ``Block`` of type ``ingress`` (registry §2.6, C-84)."""

    name: str
    expr: Expression
    name_range: SourceRange = field(compare=False)
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Label:
    """A block label: a quoted string (``quoted`` True) or a bare identifier."""

    value: str
    quoted: bool
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Block:
    """``type "label" ... { body }``; ``one_line`` is True for ``type { name = expr }``."""

    type: str
    labels: tuple[Label, ...]
    body: Body
    one_line: bool
    type_range: SourceRange = field(compare=False)
    range: SourceRange = field(compare=False)


@dataclass(frozen=True, slots=True)
class Body:
    """Attributes and blocks in source order."""

    items: tuple[Attribute | Block, ...]
    range: SourceRange = field(compare=False)
