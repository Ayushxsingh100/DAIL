"""The verifier's reader of the stored value encoding (C-112, C-144; P5a step 3).

``Resource.attributes`` hold values in the canonical encoding of ``core.terraform_model.canonical``
(its module docstring is the table). This module decodes that JSON back into plain Python values
so the predicates can ask "is this field resolved?" without importing the modelling package:

| Encoded | Decoded |
|---|---|
| string, bool, null, integer | itself |
| list | ``tuple`` in order |
| ``{"$dail":"decimal","value":"1.5"}`` | ``Decimal`` |
| ``{"$dail":"set","items":[...]}`` | ``SetValue`` in the stored (sorted) order |
| ``{"$dail":"map","items":{...}}`` and plain objects | read-only mapping |
| ``{"$dail":"unknown"|"unsupported","reason":...}`` | ``Unknown`` / ``Unsupported`` |
| ``{"$dail":"ref","address":...,"attribute":...}`` | ``Ref`` |

A shape the encoder never writes (an unknown tag, a missing or extra key, a float, nesting beyond
the domain's JSON limit) raises ``ValueDecodeError``: a stored view that cannot be read is an
error, never "no value". Arguments (``{"form": ...}``) decode to ``Argument`` and ``Block``.

Standard library only.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Any, Final

TAG: Final = "$dail"
MAX_DEPTH: Final = 64  # the domain's JSON nesting limit (core.domain.jsonvalue)
FORMS: Final = ("ATTRIBUTE", "BLOCKS", "DYNAMIC", "MIXED")


class ValueDecodeError(ValueError):
    """Stored JSON that is not in the canonical encoding."""


@dataclass(frozen=True, slots=True)
class Unknown:
    """Cannot be fixed from the configuration and variable values alone (registry §2.2)."""

    reason: str


@dataclass(frozen=True, slots=True)
class Unsupported:
    """Could be fixed, but DAIL does not implement the construct."""

    reason: str


@dataclass(frozen=True, slots=True)
class Ref:
    """An identity reference to a configured resource instance (registry §2.2)."""

    address: str
    attribute: str


@dataclass(frozen=True, slots=True)
class SetValue:
    items: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class Block:
    type: str
    labels: tuple[Any, ...]
    arguments: Mapping[str, Argument]
    from_dynamic: bool


@dataclass(frozen=True, slots=True)
class Argument:
    """One argument in the form it was written in: an attribute, or blocks (with the reasons that
    some blocks could not be expanded)."""

    form: str
    value: Any
    blocks: tuple[Block, ...]
    indeterminate: tuple[Any, ...]


def _text(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ValueDecodeError(f"{where}: must be text")
    return value


def _keys(data: Mapping[str, Any], expected: set[str], where: str) -> None:
    if set(data) != expected:
        raise ValueDecodeError(f"{where}: keys must be {sorted(expected)}, got {sorted(data)}")


def decode(encoded: object, _depth: int = 0) -> Any:
    """The value of one encoded JSON value."""
    if _depth > MAX_DEPTH:
        raise ValueDecodeError("value nested deeper than the JSON limit")
    if encoded is None or isinstance(encoded, str | bool | int):
        return encoded
    if isinstance(encoded, list):
        return tuple(decode(item, _depth + 1) for item in encoded)
    if isinstance(encoded, dict):
        if not all(isinstance(key, str) for key in encoded):
            raise ValueDecodeError("object keys must be text")
        if TAG in encoded:
            return _decode_tagged(encoded, _depth)
        return MappingProxyType({key: decode(item, _depth + 1) for key, item in encoded.items()})
    raise ValueDecodeError(f"{type(encoded).__name__} is not a JSON value")


def _decode_tagged(encoded: Mapping[str, Any], depth: int) -> Any:
    tag = encoded[TAG]
    if not isinstance(tag, str):
        raise ValueDecodeError("the $dail tag must be text")
    if tag in ("unknown", "unsupported"):
        _keys(encoded, {TAG, "reason"}, tag)
        reason = _text(encoded["reason"], f"{tag}.reason")
        return Unknown(reason) if tag == "unknown" else Unsupported(reason)
    if tag == "ref":
        _keys(encoded, {TAG, "address", "attribute"}, "ref")
        return Ref(
            _text(encoded["address"], "ref.address"), _text(encoded["attribute"], "ref.attribute")
        )
    if tag == "decimal":
        _keys(encoded, {TAG, "value"}, "decimal")
        text = _text(encoded["value"], "decimal.value")
        try:
            number = Decimal(text)
        except InvalidOperation:
            raise ValueDecodeError(f"decimal.value: {text!r} is not a number") from None
        if not number.is_finite():
            raise ValueDecodeError("decimal.value: must be finite")
        return number
    if tag == "set":
        _keys(encoded, {TAG, "items"}, "set")
        items = encoded["items"]
        if not isinstance(items, list):
            raise ValueDecodeError("set.items: must be a list")
        return SetValue(tuple(decode(item, depth + 1) for item in items))
    if tag == "map":
        _keys(encoded, {TAG, "items"}, "map")
        items = encoded["items"]
        if not isinstance(items, dict) or not all(isinstance(key, str) for key in items):
            raise ValueDecodeError("map.items: must be an object")
        return MappingProxyType({key: decode(item, depth + 1) for key, item in items.items()})
    raise ValueDecodeError(f"unknown $dail tag {tag!r}")


def _walk(value: object) -> Iterator[object]:
    """Every node of a decoded value in reading order, without recursion."""
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        yield item
        if isinstance(item, tuple):
            stack.extend(reversed(item))
        elif isinstance(item, SetValue):
            stack.extend(reversed(item.items))
        elif isinstance(item, Mapping):
            stack.extend(reversed(list(item.values())))


def first_problem(value: object) -> Unknown | Unsupported | Ref | None:
    """The first unknown, unsupported or reference value anywhere inside ``value``."""
    for item in _walk(value):
        if isinstance(item, Unknown | Unsupported | Ref):
            return item
    return None


def has_problem(value: object) -> bool:
    """Whether ``value`` is, or contains, something that is not fixed by the configuration alone."""
    return first_problem(value) is not None


def has_unresolved(value: object) -> bool:
    """Whether ``value`` is, or contains, an unknown or unsupported value.

    Unlike ``has_problem`` a reference counts as resolved: it names a configured resource (registry
    §2.2), which is what a source security group normally is."""
    return any(isinstance(item, Unknown | Unsupported) for item in _walk(value))


def describe(problem: Unknown | Unsupported | Ref) -> str:
    """Short stable text of a problem value, for observations."""
    if isinstance(problem, Ref):
        return f"ref:{problem.address}.{problem.attribute}"
    kind = "unknown" if isinstance(problem, Unknown) else "unsupported"
    return f"{kind}:{problem.reason}"


def decode_argument(encoded: object, _depth: int = 0) -> Argument:
    """The argument written in the form ``encode_argument`` records."""
    if _depth > MAX_DEPTH:
        raise ValueDecodeError("arguments nested deeper than the JSON limit")
    if not isinstance(encoded, dict):
        raise ValueDecodeError("an argument must be an object")
    form = encoded.get("form")
    if form not in FORMS:
        raise ValueDecodeError(f"argument form {form!r} is not one of {FORMS}")
    if form == "ATTRIBUTE":
        _keys(encoded, {"form", "value"}, "argument")
        return Argument("ATTRIBUTE", decode(encoded["value"]), (), ())
    _keys(encoded, {"form", "blocks", "indeterminate"}, "argument")
    raw_blocks, raw_reasons = encoded["blocks"], encoded["indeterminate"]
    if not isinstance(raw_blocks, list) or not isinstance(raw_reasons, list):
        raise ValueDecodeError("argument blocks and indeterminate must be lists")
    blocks = tuple(_decode_block(block, _depth + 1) for block in raw_blocks)
    return Argument(form, None, blocks, tuple(decode(reason) for reason in raw_reasons))


def _decode_block(encoded: object, depth: int) -> Block:
    if not isinstance(encoded, dict):
        raise ValueDecodeError("a block must be an object")
    _keys(encoded, {"type", "labels", "arguments", "from_dynamic"}, "block")
    labels, arguments = encoded["labels"], encoded["arguments"]
    if not isinstance(labels, list) or not isinstance(arguments, dict):
        raise ValueDecodeError("block labels must be a list and arguments an object")
    if not isinstance(encoded["from_dynamic"], bool):
        raise ValueDecodeError("block.from_dynamic must be a boolean")
    return Block(
        _text(encoded["type"], "block.type"),
        tuple(decode(label) for label in labels),
        MappingProxyType(
            {
                str(name): decode_argument(argument, depth + 1)
                for name, argument in arguments.items()
            }
        ),
        encoded["from_dynamic"],
    )
