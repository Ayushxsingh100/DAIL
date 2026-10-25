"""Type conversion for the evaluator: primitives, unification and type constraints (Doc 04 §17).

Everything here works on the values of ``values.py`` and raises ``Fail`` when Terraform would
raise an evaluation error or when DAIL cannot reproduce Terraform exactly. The evaluator turns a
``Fail`` into an ``Unsupported`` value (C-103: an error Terraform raises while evaluating is
unsupported here, never INVALID, because ``terraform validate`` is a separate gate, C-99).

Terraform behaviour reproduced here was measured on Terraform 1.15.8 with ``terraform console``
(scratch directory outside the repository, no credentials; listed in the P3a-2 report):
``tostring(1e3)`` is ``"1000"``, ``tostring(0.1)`` is ``"0.1"``, ``tonumber("1e3")`` is 1000,
``tonumber("+5")`` is 5, ``tonumber("5.")`` is 5, ``tonumber(".5")`` is 0.5, ``tonumber(" 5")``
and ``tonumber("0x10")`` are errors, ``tobool("TRUE")`` is an error, and ``tostring(-0)`` is
``"-0"`` (so DAIL treats a negative zero as unsupported rather than print ``"0"``).

Reference pages (``hashicorp/web-unified-docs`` commit ``fefc7502dba86c70716f0109c324c85829229b2f``,
``content/terraform/v1.15.x/docs/``): ``language/expressions/type-constraints.mdx`` for the type
constraint syntax and the conversion rules.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Final

from core.terraform_model.hcl.ast import (
    Expression,
    FunctionCall,
    IdentifierKey,
    Literal,
    LiteralKind,
    Object,
    Parenthesized,
    ScopeTraversal,
    Tuple,
)
from core.terraform_model.values import (
    NULL,
    Known,
    Ref,
    SetValue,
    Unknown,
    Unsupported,
    Value,
    ValueModelError,
    known_object,
    known_set,
    normalize_number,
)

# Reason codes of the Unsupported values made by this module and by the evaluator (the others are
# in ``functions.py`` and ``evaluate.py``). tests/unit/test_terraform_evaluate.py checks that every
# code written in the source is listed in its module's table.
REASONS: Final[dict[str, str]] = {
    "value.null": "A null value where Terraform needs a value.",
    "type.conversion": "A value cannot be converted to the type that is needed.",
    "type.unify": "The values have no common type DAIL can compute.",
    "type.constraint": "A variable type constraint DAIL cannot read.",
    "number.parse": "A string that Terraform does not read as a number.",
    "number.range": "A number outside the range DAIL keeps exactly.",
    "number.not_integer": "A whole number is needed.",
    "number.negative_zero": "Terraform prints a negative zero as -0; DAIL does not model it.",
    "limit.value_depth": "A value nested deeper than the limit.",
}

_MAX_TYPE_DEPTH: Final = 64
_NUMBER_TEXT: Final = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")


class Fail(Exception):
    """An evaluation error: the expression's value is ``Unsupported(reason)``."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# --- Numbers -----------------------------------------------------------------------------------


def number_text(number: int | Decimal) -> str:
    """How Terraform prints a number in a string: plain digits, no exponent (``1e3`` is
    ``1000``, ``1e-7`` is ``0.0000001``)."""
    if isinstance(number, int):
        return str(number)
    return format(number, "f")


def parse_number(text: str) -> int | Decimal:
    """Terraform's reading of a string as a number: optional sign, digits with an optional dot
    (``5.`` and ``.5`` are numbers), optional exponent. No spaces, no hex, no ``_``."""
    if _NUMBER_TEXT.fullmatch(text) is None:
        raise Fail("number.parse", f"{text[:30]!r} is not a decimal number")
    return make_number(Decimal(text))


def make_number(number: int | Decimal) -> int | Decimal:
    """A canonical number, or ``Fail`` for a value DAIL does not keep exactly."""
    if isinstance(number, Decimal) and number.is_zero() and number.is_signed():
        raise Fail("number.negative_zero", "a negative zero")
    try:
        return normalize_number(number)
    except ValueModelError as error:
        raise Fail("number.range", str(error)) from error


# --- Primitive access ----------------------------------------------------------------------------


def kind_of(value: Value) -> str:
    """``string``, ``number``, ``bool``, ``null``, ``tuple``, ``set``, ``object``, ``ref``,
    ``unknown`` or ``unsupported``."""
    if isinstance(value, Ref):
        return "ref"
    if isinstance(value, Unknown):
        return "unknown"
    if isinstance(value, Unsupported):
        return "unsupported"
    payload = value.value
    if payload is None:
        return "null"
    if isinstance(payload, bool):
        return "bool"
    if isinstance(payload, int | Decimal):
        return "number"
    if isinstance(payload, str):
        return "string"
    if isinstance(payload, tuple):
        return "tuple"
    if isinstance(payload, SetValue):
        return "set"
    return "object"


def as_string(value: Value) -> str:
    """The string a primitive converts to (Terraform's implicit conversion), else ``Fail``."""
    kind = kind_of(value)
    if not isinstance(value, Known):
        raise Fail("type.conversion", f"a {kind} value is not a string")
    payload = value.value
    if kind == "string":
        return str(payload)
    if kind == "bool":
        return "true" if payload else "false"
    if kind == "number":
        return number_text(payload)
    if kind == "null":
        raise Fail("value.null", "a null value cannot be a string")
    raise Fail("type.conversion", f"a {kind} cannot be converted to a string")


def as_number(value: Value) -> int | Decimal:
    kind = kind_of(value)
    if not isinstance(value, Known):
        raise Fail("type.conversion", f"a {kind} value is not a number")
    payload = value.value
    if kind == "number":
        return payload  # type: ignore[no-any-return]
    if kind == "string":
        return parse_number(payload)
    if kind == "null":
        raise Fail("value.null", "a null value cannot be a number")
    raise Fail("type.conversion", f"a {kind} cannot be converted to a number")


def as_bool(value: Value) -> bool:
    kind = kind_of(value)
    if not isinstance(value, Known):
        raise Fail("type.conversion", f"a {kind} value is not a bool")
    payload = value.value
    if kind == "bool":
        return bool(payload)
    if kind == "string" and payload in ("true", "false"):
        return bool(payload == "true")
    if kind == "null":
        raise Fail("value.null", "a null value cannot be a bool")
    raise Fail("type.conversion", f"a {kind} cannot be converted to a bool")


def as_int(value: Value) -> int:
    """A whole number (an integral ``Decimal`` is already an ``int``)."""
    number = as_number(value)
    if isinstance(number, int):
        return number
    raise Fail("number.not_integer", f"{number_text(number)} is not a whole number")


def as_elements(value: Value, *, sets: bool = True) -> tuple[Value, ...]:
    """The elements of a list, tuple or (when ``sets``) set, else ``Fail``."""
    if isinstance(value, Known):
        payload = value.value
        if isinstance(payload, tuple):
            return payload
        if sets and isinstance(payload, SetValue):
            return payload.elements
    raise Fail("type.conversion", f"a {kind_of(value)} is not a list")


def as_mapping(value: Value) -> MappingProxyType[str, Value]:
    if isinstance(value, Known) and isinstance(value.value, MappingProxyType):
        return value.value
    raise Fail("type.conversion", f"a {kind_of(value)} is not a map or object")


# --- Unification ---------------------------------------------------------------------------------


def shape(value: Value, depth: int = 0) -> Any:
    """A structural type signature. ``None`` stands for a value of any type (null, unknown,
    unsupported)."""
    if depth > _MAX_TYPE_DEPTH:
        raise Fail("limit.value_depth", "value nested too deeply")
    kind = kind_of(value)
    if kind in ("null", "unknown", "unsupported"):
        return None
    if kind in ("string", "number", "bool"):
        return kind
    if kind == "ref":
        return "string"
    assert isinstance(value, Known)
    payload = value.value
    if kind == "tuple":
        return ("tuple", tuple(shape(item, depth + 1) for item in payload))
    if kind == "set":
        return ("set", tuple(shape(item, depth + 1) for item in payload.elements))
    return ("object", tuple((key, shape(item, depth + 1)) for key, item in payload.items()))


def _compatible(left: Any, right: Any) -> bool:
    if left is None or right is None:
        return True
    if isinstance(left, str) or isinstance(right, str):
        return bool(left == right)
    kind_left, parts_left = left
    kind_right, parts_right = right
    if kind_left != kind_right:
        return False
    if kind_left == "object":
        if [name for name, _ in parts_left] != [name for name, _ in parts_right]:
            return False
        return all(
            _compatible(a, b) for (_, a), (_, b) in zip(parts_left, parts_right, strict=True)
        )
    # tuple and set: the elements of a list must have one type; a tuple of other length is a
    # different type
    if len(parts_left) != len(parts_right):
        return all(_compatible(a, b) for a in parts_left for b in parts_right)
    return all(_compatible(a, b) for a, b in zip(parts_left, parts_right, strict=True))


def unify(values: Sequence[Value]) -> list[Value]:
    """Convert values to the single type Terraform would pick for a list of them.

    Primitives of different types become strings (``[1, "a"]`` is ``["1", "a"]``). Null,
    unknown and unsupported values and references are left alone. Collections must have the same
    shape; a primitive together with a collection, or two shapes that differ, is ``Fail``.
    """
    primitive_kinds = {kind_of(v) for v in values if kind_of(v) in ("string", "number", "bool")}
    has_ref = any(isinstance(v, Ref) for v in values)
    collections = [v for v in values if kind_of(v) in ("tuple", "set", "object")]
    if collections:
        if primitive_kinds or has_ref:
            raise Fail("type.unify", "a collection and a primitive have no common type")
        first = shape(collections[0])
        for other in collections[1:]:
            if not _compatible(first, shape(other)):
                raise Fail("type.unify", "the elements have different types")
        return list(values)
    if len(primitive_kinds) > 1 or (primitive_kinds and primitive_kinds != {"string"} and has_ref):
        return [
            Known(as_string(v)) if kind_of(v) in ("string", "number", "bool") else v for v in values
        ]
    return list(values)


_PRIMITIVE_KINDS: Final = ("string", "number", "bool")


def _flat_primitives(value: Value) -> set[str] | None:
    """The primitive kinds in a primitive or in a flat collection of primitives; None when the
    value holds a nested collection."""
    kind = kind_of(value)
    if kind in _PRIMITIVE_KINDS:
        return {kind}
    if kind == "ref":
        return {"string"}
    if kind in ("null", "unknown", "unsupported"):
        return set()
    assert isinstance(value, Known)
    payload = value.value
    items = (
        payload
        if kind == "tuple"
        else payload.elements if kind == "set" else tuple(payload.values())
    )
    kinds: set[str] = set()
    for item in items:
        inner = _flat_primitives(item) if kind_of(item) not in ("tuple", "set", "object") else None
        if inner is None:
            return None
        kinds |= inner
    return kinds


def _stringify(value: Value) -> Value:
    kind = kind_of(value)
    if kind in _PRIMITIVE_KINDS:
        return Known(as_string(value))
    if not isinstance(value, Known) or kind in ("null", "ref"):
        return value
    payload = value.value
    if kind == "tuple":
        return Known(tuple(_stringify(item) for item in payload))
    if kind == "set":
        return known_set(_stringify(item) for item in payload.elements)
    return known_object({name: _stringify(item) for name, item in payload.items()})


def unify_pair(chosen: Value, other: Value) -> Value:
    """The value of ``chosen`` converted to the type that a conditional's two results share.

    ``true ? 1 : "a"`` is ``"1"`` and ``false ? [1] : ["a"]`` is ``["a"]`` (measured on Terraform
    1.15.8). Primitives of different types, alone or in flat collections of the same kind, unify to
    strings; nested collections must have the same shape; anything else has no common type DAIL
    computes (``Fail``).
    """
    kinds_left, kinds_right = kind_of(chosen), kind_of(other)
    wild = ("null", "unknown", "unsupported")
    if kinds_left in wild or kinds_right in wild:
        return chosen
    collection = ("tuple", "set", "object")
    if (kinds_left in collection) != (kinds_right in collection) or (
        kinds_left in collection and kinds_left != kinds_right
    ):
        raise Fail("type.unify", f"a {kinds_left} and a {kinds_right} have no common type")
    left, right = _flat_primitives(chosen), _flat_primitives(other)
    if left is None or right is None:
        if not _compatible(shape(chosen), shape(other)):
            raise Fail("type.unify", "the results have different types")
        return chosen
    return _stringify(chosen) if len(left | right) > 1 else chosen


# --- Type constraints ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TypeSpec:
    """A Terraform type constraint: ``any``, ``string``, ``number``, ``bool``, ``list``, ``set``,
    ``map``, ``object`` or ``tuple``."""

    kind: str
    element: TypeSpec | None = None
    attributes: tuple[tuple[str, TypeSpec, bool, Value | None], ...] = ()
    elements: tuple[TypeSpec, ...] = ()


ANY: Final = TypeSpec("any")
_PRIMITIVES: Final = ("string", "number", "bool", "any")
_COLLECTIONS: Final = ("list", "set", "map")


def parse_type(expr: Expression, depth: int = 0) -> TypeSpec:
    """Read a type constraint expression (``string``, ``list(string)``, ``object({...})``)."""
    if depth > _MAX_TYPE_DEPTH:
        raise Fail("type.constraint", "type constraint nested too deeply")
    while isinstance(expr, Parenthesized):
        expr = expr.expr
    if isinstance(expr, ScopeTraversal):
        if not expr.steps and expr.root in _PRIMITIVES:
            return TypeSpec(expr.root)
        raise Fail("type.constraint", f"{expr.root} is not a type")
    if not isinstance(expr, FunctionCall):
        raise Fail("type.constraint", "a type constraint is a type name or a type function")
    name, args = expr.name, expr.args
    if name in _COLLECTIONS and len(args) == 1:
        return TypeSpec(name, element=parse_type(args[0], depth + 1))
    if name == "object" and len(args) == 1:
        return _parse_object_type(args[0], depth)
    if name == "tuple" and len(args) == 1:
        inner = args[0]
        if isinstance(inner, Tuple):
            return TypeSpec(
                "tuple", elements=tuple(parse_type(e, depth + 1) for e in inner.elements)
            )
    raise Fail("type.constraint", f"{name}(...) is not a type constraint")


def _parse_object_type(arg: Expression, depth: int) -> TypeSpec:
    if not isinstance(arg, Object):
        raise Fail("type.constraint", "object() takes an object of attribute types")
    attributes: list[tuple[str, TypeSpec, bool, Value | None]] = []
    seen: set[str] = set()
    for item in arg.items:
        name = _key_name(item.key, "an attribute name must be an identifier or a string")
        if name in seen:
            raise Fail("type.constraint", f"attribute {name} is declared twice")
        seen.add(name)
        value = item.value
        optional, default = False, None
        if (
            isinstance(value, FunctionCall)
            and value.name == "optional"
            and 1 <= len(value.args) <= 2
        ):
            optional = True
            spec = parse_type(value.args[0], depth + 1)
            if len(value.args) == 2:
                default = _constant(value.args[1])
        else:
            spec = parse_type(value, depth + 1)
        attributes.append((name, spec, optional, default))
    attributes.sort(key=lambda a: a[0])
    return TypeSpec("object", attributes=tuple(attributes))


def _key_name(key: IdentifierKey | Expression, message: str) -> str:
    if isinstance(key, IdentifierKey):
        return key.name
    if isinstance(key, Literal) and key.kind is LiteralKind.STRING:
        return str(key.value)
    if isinstance(key, ScopeTraversal) and not key.steps:
        return key.root
    raise Fail("type.constraint", message)


def _constant(expr: Expression) -> Value:
    """The default of ``optional(T, default)``: a literal, or a tuple/object of literals."""
    while isinstance(expr, Parenthesized):
        expr = expr.expr
    if isinstance(expr, Literal):
        if expr.kind is LiteralKind.NULL:
            return NULL
        return Known(expr.value)
    if isinstance(expr, Tuple):
        return Known(tuple(_constant(e) for e in expr.elements))
    if isinstance(expr, Object):
        items: dict[str, Value] = {}
        for item in expr.items:
            name = _key_name(item.key, "an optional() default must be a constant")
            items[name] = _constant(item.value)
        return known_object(items)
    raise Fail("type.constraint", "an optional() default must be a constant")


def convert_to(value: Value, spec: TypeSpec) -> Value:
    """Convert a value to a type constraint as Terraform does for a variable, else ``Fail``."""
    if isinstance(value, Unknown | Unsupported):
        return value
    kind = spec.kind
    if kind == "any":
        return value
    if isinstance(value, Ref):
        if kind == "string":
            return value
        raise Fail("type.conversion", f"a reference is not a {kind}")
    payload = value.value
    if payload is None:
        return value
    if kind == "string":
        return Known(as_string(value))
    if kind == "number":
        return Known(as_number(value))
    if kind == "bool":
        return Known(as_bool(value))
    element = spec.element if spec.element is not None else ANY
    if kind in ("list", "set"):
        converted = [convert_to(item, element) for item in as_elements(value)]
        if element.kind == "any":
            converted = unify(converted)
        return Known(tuple(converted)) if kind == "list" else known_set(converted)
    if kind == "map":
        mapping = as_mapping(value)
        pairs = {k: convert_to(v, element) for k, v in mapping.items()}
        if element.kind == "any":
            keys = list(pairs)
            pairs = dict(zip(keys, unify([pairs[k] for k in keys]), strict=True))
        return known_object(pairs)
    if kind == "tuple":
        items = as_elements(value, sets=False)
        if len(items) != len(spec.elements):
            raise Fail("type.conversion", "a tuple of a different length")
        return Known(tuple(convert_to(i, s) for i, s in zip(items, spec.elements, strict=True)))
    # object
    mapping = as_mapping(value)
    result: dict[str, Value] = {}
    for name, attr_spec, optional, default in spec.attributes:
        if name in mapping:
            result[name] = convert_to(mapping[name], attr_spec)
        elif optional:
            result[name] = NULL if default is None else convert_to(default, attr_spec)
        else:
            raise Fail("type.conversion", f"the object has no attribute {name}")
    return known_object(result)
