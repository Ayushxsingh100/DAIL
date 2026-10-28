"""Which rules can let TCP traffic to a port through (registry §2.5, §3.3; C-146; P5a step 3).

Registry §2.5: ``permits_tcp(r, p)`` is true when protocol(r) = ALL, or when protocol(r) = TCP and
``from_port <= p <= to_port``. That is defined for a rule whose protocol and ports are resolved.

Registry §3.3 asks of an indeterminate rule whether it "could permit TCP/p (its protocol or ports
unresolved, or they permit p)": ``may_permit_tcp``. An unresolved protocol or port may be anything,
so it could permit; a resolved protocol other than ALL and TCP never permits TCP.

Protocols are the canonical text of ``security_rules.canonical_protocol`` (ALL, TCP, UDP, ICMP,
ICMPV6, or a number's text); an unresolved protocol is ``None``.

Standard library only.
"""

from __future__ import annotations


class PortsError(ValueError):
    """``permits_tcp`` was asked about a rule whose protocol or ports are not resolved."""


def permits_tcp(
    protocol: str | None, from_port: int | None, to_port: int | None, port: int
) -> bool:
    """Registry §2.5, for a rule with a resolved protocol (and ports, for TCP)."""
    if protocol is None:
        raise PortsError("the protocol is not resolved")
    if protocol == "ALL":
        return True
    if protocol == "TCP":
        if from_port is None or to_port is None:
            raise PortsError("a TCP rule without both ports is not decided here")
        return from_port <= port <= to_port
    return False


def may_permit_tcp(
    protocol: str | None, from_port: int | None, to_port: int | None, port: int
) -> bool:
    """Registry §3.3: could this (possibly unresolved) rule permit TCP to ``port``?"""
    if protocol is None or protocol == "ALL":
        return True
    if protocol == "TCP":
        if from_port is None or to_port is None:
            return True
        return from_port <= port <= to_port
    return False
