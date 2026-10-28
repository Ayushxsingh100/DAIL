"""Reading the canonical value encoding of C-112 without importing ``core.terraform_model``.

A resource argument is ``{"form": "ATTRIBUTE", "value": V}`` (or another form for blocks). ``V``
is a JSON value in which a tagged object with the reserved key ``"$dail"`` is a reference, an
unknown, an unsupported value, a decimal, a set or an escaped map. Only what the slot rules need
is decoded: the elements of a value (a scalar, a list, or the items of a set) and the class of
one element.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from core.domain.hashing import canonical_json
from core.domain.jsonvalue import thaw_json

TAG: Final = "$dail"
_MAX_FACT_TEXT: Final = 80


class ElementKind(StrEnum):
    REF = "REF"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"
    LITERAL = "LITERAL"
    NULL = "NULL"


@dataclass(frozen=True)
class Element:
    """One classified element of an argument value."""

    kind: ElementKind
    value: Any
    detail: str  # the reason of an unknown or unsupported value, the shape of a literal, else ""

    @property
    def address(self) -> str:
        """The address of a ``Ref`` element."""
        return str(self.value["address"])


@dataclass(frozen=True)
class Argument:
    """What a resource says about one argument: absent, or a form with a value."""

    present: bool
    form: str | None
    value: Any


def read_argument(attributes: Mapping[str, Any], name: str) -> Argument:
    raw = thaw_json(attributes.get(name)) if name in attributes else None
    if not isinstance(raw, dict) or "form" not in raw:
        return Argument(present=False, form=None, value=None)
    form = raw["form"]
    return Argument(present=True, form=form, value=raw.get("value"))


def _tag(value: Any) -> str | None:
    if isinstance(value, dict) and isinstance(value.get(TAG), str):
        return str(value[TAG])
    return None


def _shape(value: Any) -> str:
    tag = _tag(value)
    if tag == "decimal":
        return "number"
    if tag == "set" or isinstance(value, list):
        return "collection"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "number"
    return "literal"


def classify(value: Any) -> Element:
    """The class of one element. A nested collection or object is a LITERAL with that shape."""
    tag = _tag(value)
    if value is None:
        return Element(ElementKind.NULL, None, "")
    if tag == "ref":
        return Element(ElementKind.REF, value, "")
    if tag == "unknown":
        return Element(ElementKind.UNKNOWN, value, str(value.get("reason", "")))
    if tag == "unsupported":
        return Element(ElementKind.UNSUPPORTED, value, str(value.get("reason", "")))
    return Element(ElementKind.LITERAL, value, _shape(value))


def elements_of(value: Any) -> list[Element]:
    """The elements of an argument value: the items of a set, the members of a list, or the value
    itself. A null element is kept (as NULL) so the caller can tell "empty" from "null"."""
    if _tag(value) == "set":
        items = value.get("items", [])
        return [classify(item) for item in items] if isinstance(items, list) else [classify(value)]
    if isinstance(value, list):
        return [classify(item) for item in value]
    return [classify(value)]


def render(element: Element) -> str:
    """Short, stable text of an element, for evidence."""
    if element.kind is ElementKind.REF:
        return f"Ref({element.value['address']}, {element.value.get('attribute', 'id')})"
    if element.kind is ElementKind.UNKNOWN:
        return f"Unknown({element.detail})"
    if element.kind is ElementKind.UNSUPPORTED:
        return f"Unsupported({element.detail})"
    text = canonical_json(element.value)
    if len(text) > _MAX_FACT_TEXT:
        return text[: _MAX_FACT_TEXT - 3] + "..."
    return text


def top_level(source_attribute: str) -> str:
    """The top-level argument name of a ``Reference.source_attribute`` such as
    ``vpc_security_group_ids`` or ``route[0].gateway_id`` (R3 of the P3c prompt)."""
    cut = len(source_attribute)
    for mark in ("[", "."):
        position = source_attribute.find(mark)
        if position != -1:
            cut = min(cut, position)
    return source_attribute[:cut]
