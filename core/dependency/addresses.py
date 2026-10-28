"""Canonical resource addresses as the dependency engine reads them (Doc 07 §15, §21; C-133).

An address is ``type.name[key]`` (a data source is ``data.type.name[key]``, a module object
``module.name...``). The engine needs the *block* (the address without its last instance key), to
fan a block-level reference out to its instances, and the resource type, for the typed
relationship slots. Keys are ``[0]`` or ``["text"]`` with Terraform's escaping of the quote and the
backslash, so brackets inside quotes are not structure.

This mirrors the helper of ``core.identity``; the two packages may not import each other (C-131,
R14, R15), so the few lines are repeated.
"""

from __future__ import annotations

from typing import Final

from core.dependency.errors import DependencyInputError

_BACKSLASH: Final = chr(92)
_QUOTE: Final = chr(34)


def split_key(address: str) -> tuple[str, str | None]:
    """``(block, key)`` for an address; ``key`` is ``None`` for a key-less address."""
    if not isinstance(address, str) or address == "":
        raise DependencyInputError(f"not an address: {address!r}")
    in_string = False
    opened: int | None = None
    last: tuple[int, int] | None = None
    index = 0
    while index < len(address):
        char = address[index]
        if in_string:
            if char == _BACKSLASH:
                index += 1  # the escaped character is text
            elif char == _QUOTE:
                in_string = False
        elif char == _QUOTE:
            if opened is None:
                raise DependencyInputError(f"quote outside an instance key in address {address!r}")
            in_string = True
        elif char == "[":
            if opened is not None:
                raise DependencyInputError(f"malformed instance key in address {address!r}")
            opened = index
        elif char == "]":
            if opened is None:
                raise DependencyInputError(f"malformed instance key in address {address!r}")
            last = (opened, index)
            opened = None
        index += 1
    if in_string or opened is not None:
        raise DependencyInputError(f"unterminated instance key in address {address!r}")
    if last is None or last[1] != len(address) - 1:
        return address, None
    if last[0] == 0:
        raise DependencyInputError(f"address {address!r} is only an instance key")
    return address[: last[0]], address[last[0] :]


def block_of(address: str) -> str:
    """The address without its last instance key."""
    return split_key(address)[0]


def has_key(address: str) -> bool:
    return split_key(address)[1] is not None


def object_kind(address: str) -> str:
    """``module`` for a module object, ``data`` for a data source, else ``resource``."""
    if address.startswith("module."):
        return "module"
    if address.startswith("data."):
        return "data"
    return "resource"


def type_of(address: str) -> str:
    """The resource type an address names, ``module`` for a module object.

    Text before the first dot, after a leading ``data.``. Nothing is validated: an address that
    does not look like ``type.name`` gives its first segment.
    """
    kind = object_kind(address)
    if kind == "module":
        return "module"
    rest = address[len("data.") :] if kind == "data" else address
    return rest.split(".", 1)[0]
