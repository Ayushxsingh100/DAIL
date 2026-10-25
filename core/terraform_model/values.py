"""The value model of the evaluator (Doc 04 §17; registry §2.2; C-102).

A value is one of four things:

- ``Known(payload)``: fixed by the configuration and the scenario's variable values;
- ``Unknown(reason)``: cannot be fixed (a data source attribute, a provider-computed attribute, a
  variable without a value). Never replaced by a default;
- ``Unsupported(reason)``: could be fixed, but DAIL does not implement the construct. Never
  approximated;
- ``Ref(address, attribute)``: an identity reference to a configured resource instance, for example
  ``Ref("aws_security_group.db", "id")``. It is a known value (registry §2.2: it "identifies the
  configured resource instance it names, not a concrete AWS ID").

Propagation (C-102): an operation on an unknown or unsupported operand is itself unknown or
unsupported, never a known value, and **unsupported beats unknown**, which beats known. A
collection that holds an unknown element stays a ``Known`` collection with that element unknown;
only an operation that needs the whole value becomes unknown.

The payload of ``Known`` is one of: ``str``; ``int``; ``Decimal`` (not integral; an integral number
is always an ``int``); ``bool``; ``None``; a ``tuple`` of values (Terraform tuple and list); a
``SetValue`` (elements sorted, duplicates removed); a ``MappingProxyType`` from ``str`` to value,
with sorted keys (Terraform object and map). **No float** anywhere (C-33: canonical JSON rejects
it); a float is refused at construction.

Standard library only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal, localcontext
from types import MappingProxyType
from typing import Any

# Terraform numbers are arbitrary precision; DAIL computes exactly and refuses what it cannot
# represent exactly (``number_context``).
_MAX_DIGITS = 1000


class ValueModelError(ValueError):
    """A value that the model refuses to build (a float, a payload of the wrong type)."""


def normalize_number(number: int | Decimal) -> int | Decimal:
    """The canonical form of a number: an ``int`` when integral, else a normalized ``Decimal``."""
    if isinstance(number, bool):
        raise ValueModelError("a bool is not a number")
    if isinstance(number, int):
        return number
    if not number.is_finite():
        raise ValueModelError(f"{number} is not a finite number")
    # ``normalize`` would round to the 28 digits of the default decimal context; the exact context
    # raises instead, so a number is never changed silently.
    with number_context():
        try:
            if number == number.to_integral_value():
                if number.adjusted() > _MAX_DIGITS:
                    raise ValueModelError("the number is too large to keep as an integer")
                return int(number)
            return number.normalize()
        except ArithmeticError as error:
            raise ValueModelError("the number cannot be kept exactly") from error


@dataclass(frozen=True, slots=True)
class Unknown:
    """A value that cannot be fixed from the configuration and the scenario values."""

    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueModelError("an Unknown needs a reason code")


@dataclass(frozen=True, slots=True)
class Unsupported:
    """A value that could be fixed but needs a construct DAIL does not implement."""

    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueModelError("an Unsupported needs a reason code")


@dataclass(frozen=True, slots=True)
class Ref:
    """An identity reference to a configured instance: ``address`` is the instance address
    (``aws_security_group.db``, ``aws_security_group.ops["a"]``) and ``attribute`` is ``id``."""

    address: str
    attribute: str

    def __post_init__(self) -> None:
        if not self.address or not self.attribute:
            raise ValueModelError("a Ref needs an address and an attribute")


@dataclass(frozen=True, slots=True)
class SetValue:
    """A Terraform set: unique known elements in canonical order, then unknown elements."""

    elements: tuple[Value, ...]


@dataclass(frozen=True, slots=True)
class Known:
    """A known value; see the module docstring for the payload types.

    ``computed_from`` is set only on the object that stands for a resource instance used as a
    value (``aws_x.y``): it names the instance, and says that an attribute missing from the object
    is a provider-computed attribute (unknown), not a mistake. It takes no part in equality.
    """

    value: Any
    computed_from: str | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        payload = self.value
        if isinstance(payload, float):
            raise ValueModelError("a float is never a value (C-33)")
        if payload is None or isinstance(payload, str | bool):
            return
        if isinstance(payload, int | Decimal):
            object.__setattr__(self, "value", normalize_number(payload))
            return
        if isinstance(payload, tuple):
            _require_values(payload)
            return
        if isinstance(payload, SetValue):
            _require_values(payload.elements)
            return
        if isinstance(payload, Mapping):
            for key in payload:
                if not isinstance(key, str):
                    raise ValueModelError("object keys are strings")
            _require_values(payload.values())
            ordered = dict(sorted(payload.items()))
            if list(ordered) != list(payload) or not isinstance(payload, MappingProxyType):
                object.__setattr__(self, "value", MappingProxyType(ordered))
            return
        raise ValueModelError(f"{type(payload).__name__} is not a value payload")


Value = Known | Unknown | Unsupported | Ref


def _require_values(items: Iterable[object]) -> None:
    for item in items:
        if not isinstance(item, Known | Unknown | Unsupported | Ref):
            raise ValueModelError(f"{type(item).__name__} is not a value")


# --- Construction helpers -----------------------------------------------------------------------

NULL = Known(None)
TRUE = Known(True)
FALSE = Known(False)
EMPTY_TUPLE = Known(())


def known_tuple(items: Iterable[Value]) -> Known:
    return Known(tuple(items))


def known_object(items: Mapping[str, Value]) -> Known:
    return Known(MappingProxyType(dict(sorted(items.items()))))


def known_set(items: Iterable[Value]) -> Known:
    """A set: known elements sorted and deduplicated, unknown ones after them by reason."""
    known: list[Value] = []
    problems: list[Value] = []
    for item in items:
        (known if is_fully_known(item) else problems).append(item)
    unique: list[Value] = []
    for item in sorted(known, key=sort_key):
        # compare sort keys: Known(True) == Known(1) in Python, but a bool is not a number
        if not unique or sort_key(unique[-1]) != sort_key(item):
            unique.append(item)
    problems.sort(key=sort_key)
    return Known(SetValue(tuple(unique + problems)))


# --- Ordering -------------------------------------------------------------------------------------


def sort_key(value: Value) -> tuple[Any, ...]:
    """A total order over values, used for sets and for deterministic walks.

    The first component is the kind, so values of different kinds never compare payloads.
    """
    if isinstance(value, Known):
        payload = value.value
        if payload is None:
            return (0,)
        if isinstance(payload, bool):
            return (1, payload)
        if isinstance(payload, int | Decimal):
            return (2, Decimal(payload))
        if isinstance(payload, str):
            return (3, payload)
        if isinstance(payload, tuple):
            return (4, tuple(sort_key(item) for item in payload))
        if isinstance(payload, SetValue):
            return (5, tuple(sort_key(item) for item in payload.elements))
        return (6, tuple((key, sort_key(item)) for key, item in payload.items()))
    if isinstance(value, Ref):
        return (7, value.address, value.attribute)
    if isinstance(value, Unknown):
        return (8, value.reason)
    return (9, value.reason)


# --- Questions about a value ----------------------------------------------------------------------


def children(value: Value) -> tuple[Value, ...]:
    """The elements of a collection in the canonical walk order (empty for anything else)."""
    if isinstance(value, Known):
        payload = value.value
        if isinstance(payload, tuple):
            return payload
        if isinstance(payload, SetValue):
            return payload.elements
        if isinstance(payload, MappingProxyType):
            return tuple(payload.values())
    return ()


def walk(value: Value) -> Iterable[Value]:
    """Every value inside ``value`` (itself first), depth first, in the canonical order."""
    stack = [value]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(children(current)))


def first_problem_value(value: Value) -> Unknown | Unsupported | None:
    """The first Unsupported in the walk order, else the first Unknown, else None."""
    first_unknown: Unknown | None = None
    for item in walk(value):
        if isinstance(item, Unsupported):
            return item
        if isinstance(item, Unknown) and first_unknown is None:
            first_unknown = item
    return first_unknown


def first_problem(value: Value) -> str | None:
    """The reason of the first Unsupported, else of the first Unknown, else None."""
    problem = first_problem_value(value)
    return None if problem is None else problem.reason


def is_fully_known(value: Value) -> bool:
    """True when no Unknown and no Unsupported appears anywhere inside ``value``."""
    return first_problem_value(value) is None


def combine(*operands: Value) -> Unknown | Unsupported | None:
    """The propagation rule for an operation on its operands, looking at the operands themselves.

    Returns the first Unsupported operand, else the first Unknown operand, else None (every operand
    is known at its top level). A nested problem inside a collection is not looked at: use
    ``combine_deep`` for an operation that needs the whole value.
    """
    first_unknown: Unknown | None = None
    for operand in operands:
        if isinstance(operand, Unsupported):
            return operand
        if isinstance(operand, Unknown) and first_unknown is None:
            first_unknown = operand
    return first_unknown


def combine_deep(*operands: Value) -> Unknown | Unsupported | None:
    """Like ``combine`` but for an operation that needs every operand completely known."""
    first_unknown: Unknown | None = None
    for operand in operands:
        problem = first_problem_value(operand)
        if isinstance(problem, Unsupported):
            return problem
        if problem is not None and first_unknown is None:
            first_unknown = problem if isinstance(problem, Unknown) else None
    return first_unknown


# --- Numbers ---------------------------------------------------------------------------------


def number_context() -> Any:
    """A decimal context for exact arithmetic: it raises ``decimal.Inexact`` instead of rounding.

    Use as ``with number_context() as ctx: ctx.add(a, b)``. Terraform computes with 512-bit
    floating point; DAIL keeps only results it can represent exactly and treats the rest as
    unsupported (``number.inexact``).
    """
    import decimal

    context = decimal.Context(
        prec=_MAX_DIGITS,
        rounding=decimal.ROUND_HALF_EVEN,
        Emin=-_MAX_DIGITS * 10,
        Emax=_MAX_DIGITS * 10,
        traps=[
            decimal.Inexact,
            decimal.Overflow,
            decimal.InvalidOperation,
            decimal.DivisionByZero,
            decimal.Underflow,
        ],
    )
    return localcontext(context)


# --- JSON conversion -------------------------------------------------------------------------


def from_json(data: object) -> Value:
    """Convert a scenario value (``None``, bool, int, str, list, dict) into a ``Known`` value.

    A float is refused (``ValueModelError``): callers pass integers or strings. A ``Decimal`` is
    accepted. The conversion of a list gives a tuple (the type constraint of a variable decides
    what it becomes).
    """
    if isinstance(data, float):
        raise ValueModelError("a float is refused: pass an integer or a string")
    if data is None or isinstance(data, str | bool | int | Decimal):
        return Known(data)
    if isinstance(data, list | tuple):
        return Known(tuple(from_json(item) for item in data))
    if isinstance(data, Mapping):
        items: dict[str, Value] = {}
        for key, item in data.items():
            if not isinstance(key, str):
                raise ValueModelError("object keys are strings")
            items[key] = from_json(item)
        return known_object(items)
    raise ValueModelError(f"{type(data).__name__} is not a JSON value")


def to_canonical(value: Value) -> object:
    """A JSON-ready form (only str, int, bool, None, list, dict) for hashing and evidence.

    A ``Decimal`` becomes ``{"$decimal": "<text>"}``, a set ``{"$set": [...]}``, a reference
    ``{"$ref": ..., "attribute": ...}``, and an unknown or unsupported value
    ``{"$unknown": reason}`` or ``{"$unsupported": reason}``.
    """
    if isinstance(value, Unknown):
        return {"$unknown": value.reason}
    if isinstance(value, Unsupported):
        return {"$unsupported": value.reason}
    if isinstance(value, Ref):
        return {"$ref": value.address, "attribute": value.attribute}
    payload = value.value
    if isinstance(payload, Decimal):
        return {"$decimal": format(payload, "f")}
    if isinstance(payload, tuple):
        return [to_canonical(item) for item in payload]
    if isinstance(payload, SetValue):
        return {"$set": [to_canonical(item) for item in payload.elements]}
    if isinstance(payload, MappingProxyType):
        return {key: to_canonical(item) for key, item in payload.items()}
    return payload
