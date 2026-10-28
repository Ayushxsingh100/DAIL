"""Canonical resource addresses as the identity engine reads them (Doc 07 §6; C-122, C-123).

An address is ``[module.name[key].]type.name[key]``. The only part the engine needs is the *block*
(the address without its last instance key) and that last key: ``aws_x.a["k"]`` is the instance
``["k"]`` of the block ``aws_x.a``. Keys are ``[0]`` (``count``) or ``["text"]`` (``for_each``,
with Terraform's escaping of ``"`` and ``\\`` inside the text), so brackets inside quotes are not
structure.

Nothing here validates that a block is a real Terraform address: the engine only compares what the
normalizer produced.
"""

from __future__ import annotations

from typing import Final

from core.identity.errors import IdentityInputError

_BACKSLASH: Final = chr(92)
_QUOTE: Final = chr(34)


def split_key(address: str) -> tuple[str, str | None]:
    """``(block, key)`` for an address; ``key`` is ``None`` for a key-less address."""
    if not isinstance(address, str) or address == "":
        raise IdentityInputError(f"not an address: {address!r}")
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
                raise IdentityInputError(f"quote outside an instance key in address {address!r}")
            in_string = True
        elif char == "[":
            if opened is not None:
                raise IdentityInputError(f"malformed instance key in address {address!r}")
            opened = index
        elif char == "]":
            if opened is None:
                raise IdentityInputError(f"malformed instance key in address {address!r}")
            last = (opened, index)
            opened = None
        index += 1
    if in_string or opened is not None:
        raise IdentityInputError(f"unterminated instance key in address {address!r}")
    if last is None or last[1] != len(address) - 1:
        return address, None
    if last[0] == 0:
        raise IdentityInputError(f"address {address!r} is only an instance key")
    return address[: last[0]], address[last[0] :]


def block_of(address: str) -> str:
    """The address without its last instance key."""
    return split_key(address)[0]


def key_of(address: str) -> str | None:
    """The last instance key of an address, with its brackets, or ``None``."""
    return split_key(address)[1]


def key_kind(key: str | None) -> str:
    """``none`` (no key), ``int`` (``[0]``) or ``str`` (``["text"]``)."""
    if key is None:
        return "none"
    if key.startswith("[" + _QUOTE):
        return "str"
    return "int"
