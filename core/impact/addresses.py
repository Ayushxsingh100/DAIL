"""Canonical resource addresses as the impact engine reads them (Doc 08 §7; C-140).

An address is ``type.name[key]``. The engine needs the *block* (the address without its last
instance key), because a change at a key-less block address matches the instances of that block in
the other state, and the other way round (C-140 item 3). Keys are ``[0]`` or ``["text"]`` with
Terraform's escaping of the quote and the backslash, so brackets inside quotes are not structure.

The same few lines exist in ``core.identity`` and ``core.dependency``; the engines may not import
each other (R14, R15, R16), so they are repeated.
"""

from __future__ import annotations

from typing import Final

from core.impact.errors import ImpactInputError

_BACKSLASH: Final = chr(92)
_QUOTE: Final = chr(34)


def split_key(address: str) -> tuple[str, str | None]:
    """``(block, key)`` for an address; ``key`` is ``None`` for a key-less address."""
    if not isinstance(address, str) or address == "":
        raise ImpactInputError(f"not an address: {address!r}")
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
                raise ImpactInputError(f"quote outside an instance key in address {address!r}")
            in_string = True
        elif char == "[":
            if opened is not None:
                raise ImpactInputError(f"malformed instance key in address {address!r}")
            opened = index
        elif char == "]":
            if opened is None:
                raise ImpactInputError(f"malformed instance key in address {address!r}")
            last = (opened, index)
            opened = None
        index += 1
    if in_string or opened is not None:
        raise ImpactInputError(f"unterminated instance key in address {address!r}")
    if last is None or last[1] != len(address) - 1:
        return address, None
    if last[0] == 0:
        raise ImpactInputError(f"address {address!r} is only an instance key")
    return address[: last[0]], address[last[0] :]


def block_of(address: str) -> str:
    """The address without its last instance key."""
    return split_key(address)[0]


def same_object(first: str, second: str) -> bool:
    """Whether two refs name the same object for the footprint test: equal addresses, or a
    key-less block address against an instance of that block (either way round)."""
    if first == second:
        return True
    first_block, first_key = split_key(first)
    second_block, second_key = split_key(second)
    if first_block != second_block:
        return False
    return first_key is None or second_key is None


def type_of(address: str) -> str:
    """The resource type an address names (the text before the first dot)."""
    return address.removeprefix("data.").split(".", 1)[0]
