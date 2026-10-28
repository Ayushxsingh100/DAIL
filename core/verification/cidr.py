"""CIDR ranges and coverage by interval union (registry §2.5, §3.3; C-146; P5a step 3).

Registry §2.5: "Covers means set containment of address ranges. A list of CIDRs covers a range R
when the union of the listed ranges contains R." The IPv4 clause asks whether the union of a
group's determinate port-p IPv4 sources contains ``0.0.0.0/0``, and the IPv6 clause whether the
union of the IPv6 sources contains ``::/0`` (S4 and S5 split the range, S6 documents that coverage
split across two groups is not detected).

``covers`` sorts the ranges once and sweeps them once, so it is linear after sorting and never
lists addresses (an IPv6 ``/0`` has 2**128 of them). It does not use ``ipaddress`` overlap
shortcuts: the union rule is the specification, so it is written out.

Standard library only.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

IPV4_ANY: Final = "0.0.0.0/0"
IPV6_ANY: Final = "::/0"


class CidrError(ValueError):
    """Text that is not a strictly parsed CIDR, or a coverage question across address families."""


@dataclass(frozen=True, slots=True)
class Network:
    """An address range as integers: ``first`` and ``last`` inclusive."""

    version: int
    first: int
    last: int


def parse_network(text: str) -> Network:
    """A CIDR as a range. Strict: a prefix is required, host bits must be zero (registry §2.5)."""
    if not isinstance(text, str):
        raise CidrError(f"{type(text).__name__} is not CIDR text")
    if text != text.strip() or "/" not in text:
        raise CidrError(f"{text!r} is not a CIDR")
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as error:
        raise CidrError(f"{text!r}: {error}") from None
    return Network(network.version, int(network.network_address), int(network.broadcast_address))


def covers(cidrs: Iterable[str], target: str) -> bool:
    """Whether the union of ``cidrs`` contains every address of ``target``.

    The members must be of the target's address family; an invalid member is an error, never
    ignored (an ignored member could turn a FAIL into a PASS)."""
    wanted = parse_network(target)
    members = [parse_network(text) for text in cidrs]
    for member in members:
        if member.version != wanted.version:
            raise CidrError("a coverage question mixes IPv4 and IPv6")
    cursor = wanted.first  # the first address not yet known to be covered
    for member in sorted(members, key=lambda network: network.first):
        if member.first > cursor:
            break  # a gap before this range, and every later range starts after it
        if member.last >= cursor:
            cursor = member.last + 1
        if cursor > wanted.last:
            return True
    return cursor > wanted.last
