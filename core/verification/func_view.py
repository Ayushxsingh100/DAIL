"""The verifier's reader of the INV-FUNC-001 inputs (registry §6.2, §6.3, §6.6; C-151, C-153).

Typed, frozen views of the stored resources the reachability predicate reads: the instance ``S``,
the database ``D``, a subnet, a VPC, a security group's VPC and a route table. They are built on
``values.decode`` from ``Resource.attributes`` (the C-112 encoding keeps every configured argument),
so a field the registry's footprint (§6.6) names is always there to be read.

**A fact is one of four things** (``Fact.state``): ``absent`` (the argument is not written, or is
an explicit null, which the provider reads as "not set"), ``known`` (a value; a reference is a known
``Ref``), ``unknown`` (it cannot be fixed from the configuration and variable values) and
``unsupported`` (a construct DAIL does not implement, or an argument written as a block where a
value is expected). A list is a known value even when an element is unresolved; ``items_of`` yields
the elements with the unresolved ones as ``Unknown`` or ``Unsupported`` objects.

**A stored shape the reader cannot read raises ``ViewError``**; it is never "absent". A resource of
the wrong type is also a ``ViewError``. A placeholder (UNKNOWN support: its ``count`` or
``for_each`` could not be fixed) is read with an empty ``attributes``, so every fact is ``absent``;
the view keeps ``support`` so that the predicate never mistakes a placeholder for a resource
without the argument.

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from core.domain.enums import ResourceSupport
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.verification.cidr import CidrError, Network, parse_network
from core.verification.values import (
    Argument,
    SetValue,
    Unknown,
    Unsupported,
    ValueDecodeError,
    decode_argument,
)
from core.verification.views import ViewError

ABSENT_STATE: Final = "absent"
KNOWN: Final = "known"
UNKNOWN_STATE: Final = "unknown"
UNSUPPORTED_STATE: Final = "unsupported"

_INTERFACE_ARGUMENTS: Final = ("network_interface", "primary_network_interface")
_ROUTE_TARGETS: Final = (
    "gateway_id",
    "nat_gateway_id",
    "network_interface_id",
    "transit_gateway_id",
    "vpc_peering_connection_id",
    "vpc_endpoint_id",
    "egress_only_gateway_id",
    "carrier_gateway_id",
    "core_network_arn",
    "local_gateway_id",
    "instance_id",
)


@dataclass(frozen=True, slots=True)
class Fact:
    state: str
    value: Any = None
    reason: str | None = None


ABSENT: Final = Fact(ABSENT_STATE)


def _fact_of_value(value: Any) -> Fact:
    if value is None:
        return ABSENT
    if isinstance(value, Unknown):
        return Fact(UNKNOWN_STATE, reason=value.reason)
    if isinstance(value, Unsupported):
        return Fact(UNSUPPORTED_STATE, reason=value.reason)
    return Fact(KNOWN, value)


def _fact_of_argument(argument: Argument) -> Fact:
    if argument.form != "ATTRIBUTE":
        return Fact(UNSUPPORTED_STATE, reason="form.block")
    return _fact_of_value(argument.value)


def _argument(encoded: object, where: str) -> Argument:
    try:
        return decode_argument(encoded)
    except ValueDecodeError as error:
        raise ViewError(f"{where}: {error}") from None


def items_of(fact: Fact) -> tuple[Any, ...]:
    """The elements of a fact: none if absent, the one value if it is not a collection, and the
    unresolved fact as one ``Unknown`` or ``Unsupported`` item."""
    if fact.state == ABSENT_STATE:
        return ()
    if fact.state == UNKNOWN_STATE:
        return (Unknown(fact.reason or ""),)
    if fact.state == UNSUPPORTED_STATE:
        return (Unsupported(fact.reason or ""),)
    if isinstance(fact.value, tuple):
        return fact.value
    if isinstance(fact.value, SetValue):
        return fact.value.items
    return (fact.value,)


def _attributes(resource: Resource, expected_type: str) -> dict[str, Any]:
    if resource.resource_type != expected_type:
        raise ViewError(f"{resource.address}: a {resource.resource_type}, not an {expected_type}")
    return dict(thaw_json(resource.attributes))


def _read(attributes: Mapping[str, Any], name: str, owner: str) -> Fact:
    if name not in attributes:
        return ABSENT
    return _fact_of_argument(_argument(attributes[name], f"{owner}.{name}"))


def _has_blocks(encoded: object, where: str) -> bool:
    """Whether an argument that holds blocks (or a list of them) holds any, or might."""
    argument = _argument(encoded, where)
    if argument.form != "ATTRIBUTE":
        return bool(argument.blocks) or bool(argument.indeterminate)
    value = argument.value
    if value is None:
        return False
    if isinstance(value, Unknown | Unsupported):
        return True
    if isinstance(value, tuple):
        return len(value) > 0
    if isinstance(value, SetValue):
        return len(value.items) > 0
    return True


@dataclass(frozen=True, slots=True)
class InstanceView:
    address: str
    support: ResourceSupport
    subnet_id: Fact
    vpc_security_group_ids: Fact
    security_groups: Fact
    private_ip: Fact
    interface_blocks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DatabaseView:
    address: str
    support: ResourceSupport
    port: Fact
    engine: Fact
    vpc_security_group_ids: Fact


@dataclass(frozen=True, slots=True)
class SubnetView:
    address: str
    support: ResourceSupport
    vpc_id: Fact
    cidr_block: Fact


@dataclass(frozen=True, slots=True)
class VpcView:
    address: str
    support: ResourceSupport
    cidr_block: Fact


@dataclass(frozen=True, slots=True)
class GroupNetworkView:
    address: str
    support: ResourceSupport
    vpc_id: Fact


def read_instance(resource: Resource) -> InstanceView:
    attributes = _attributes(resource, "aws_instance")
    owner = resource.address
    return InstanceView(
        address=owner,
        support=resource.support_status,
        subnet_id=_read(attributes, "subnet_id", owner),
        vpc_security_group_ids=_read(attributes, "vpc_security_group_ids", owner),
        security_groups=_read(attributes, "security_groups", owner),
        private_ip=_read(attributes, "private_ip", owner),
        interface_blocks=tuple(
            name
            for name in _INTERFACE_ARGUMENTS
            if name in attributes and _has_blocks(attributes[name], f"{owner}.{name}")
        ),
    )


def read_database(resource: Resource) -> DatabaseView:
    attributes = _attributes(resource, "aws_db_instance")
    owner = resource.address
    return DatabaseView(
        address=owner,
        support=resource.support_status,
        port=_read(attributes, "port", owner),
        engine=_read(attributes, "engine", owner),
        vpc_security_group_ids=_read(attributes, "vpc_security_group_ids", owner),
    )


def read_subnet(resource: Resource) -> SubnetView:
    attributes = _attributes(resource, "aws_subnet")
    owner = resource.address
    return SubnetView(
        address=owner,
        support=resource.support_status,
        vpc_id=_read(attributes, "vpc_id", owner),
        cidr_block=_read(attributes, "cidr_block", owner),
    )


def read_vpc(resource: Resource) -> VpcView:
    attributes = _attributes(resource, "aws_vpc")
    return VpcView(
        address=resource.address,
        support=resource.support_status,
        cidr_block=_read(attributes, "cidr_block", resource.address),
    )


def read_group_network(resource: Resource) -> GroupNetworkView:
    attributes = _attributes(resource, "aws_security_group")
    return GroupNetworkView(
        address=resource.address,
        support=resource.support_status,
        vpc_id=_read(attributes, "vpc_id", resource.address),
    )


# --- route tables ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RouteView:
    """One route. ``state``: ``ipv4`` (a CIDR destination), ``ipv6_only``, ``unresolved`` (a
    destination that cannot be fixed, or a prefix list) or ``unsupported``. ``target``: ``local``
    (``gateway_id = "local"`` and no other target), ``other`` (any other target, and also no target:
    conservative), ``unresolved`` or ``unsupported``."""

    state: str
    destination: Network | None
    target: str

    def sort_key(self) -> tuple[str, int, int, str]:
        first = -1 if self.destination is None else self.destination.first
        last = -1 if self.destination is None else self.destination.last
        return (self.state, first, last, self.target)


@dataclass(frozen=True, slots=True)
class RouteTableView:
    address: str
    support: ResourceSupport
    vpc_id: Fact
    routes: tuple[RouteView, ...]
    routes_unresolved: str | None  # why the set of routes cannot be fixed, else None
    propagating_vgws_present: bool


def _destination(fields: Mapping[str, Fact]) -> tuple[str, Network | None]:
    prefix_list = fields["destination_prefix_list_id"]
    cidr = fields["cidr_block"]
    ipv6 = fields["ipv6_cidr_block"]
    if prefix_list.state != ABSENT_STATE:
        return "unresolved", None
    if cidr.state == KNOWN:
        try:
            if not isinstance(cidr.value, str):
                raise CidrError("not text")
            return "ipv4", parse_network(cidr.value)
        except CidrError:
            return "unsupported", None
    if cidr.state == UNKNOWN_STATE:
        return "unresolved", None
    if cidr.state == UNSUPPORTED_STATE:
        return "unsupported", None
    if ipv6.state == KNOWN:
        return "ipv6_only", None
    if ipv6.state == UNKNOWN_STATE:
        return "unresolved", None
    return "unsupported", None


def _target(fields: Mapping[str, Fact]) -> str:
    present = {name: fields[name] for name in _ROUTE_TARGETS if fields[name].state != ABSENT_STATE}
    gateway = present.get("gateway_id")
    if (
        gateway is not None
        and gateway.state == KNOWN
        and gateway.value == "local"
        and len(present) == 1
    ):
        return "local"
    if any(fact.state == UNSUPPORTED_STATE for fact in present.values()):
        return "unsupported"
    if any(fact.state == UNKNOWN_STATE for fact in present.values()):
        return "unresolved"
    return "other"


_ROUTE_FIELDS: Final = (
    "cidr_block",
    "ipv6_cidr_block",
    "destination_prefix_list_id",
    *_ROUTE_TARGETS,
)


def _route(fields: Mapping[str, Fact]) -> RouteView:
    state, destination = _destination(fields)
    return RouteView(state, destination, _target(fields))


def _routes(encoded: object, owner: str) -> tuple[tuple[RouteView, ...], str | None]:
    where = f"{owner}.route"
    argument = _argument(encoded, where)
    found: list[RouteView] = []
    unresolved: str | None = None
    if argument.form != "ATTRIBUTE":
        for block in argument.blocks:
            fields = {
                name: (
                    _fact_of_argument(block.arguments[name]) if name in block.arguments else ABSENT
                )
                for name in _ROUTE_FIELDS
            }
            found.append(_route(fields))
        if argument.indeterminate:
            unresolved = "route.expansion"
    else:
        value = argument.value
        if value is None:
            elements: tuple[Any, ...] = ()
        elif isinstance(value, Unknown | Unsupported):
            return (), f"route.{value.reason}"
        elif isinstance(value, tuple):
            elements = value
        elif isinstance(value, SetValue):
            elements = value.items
        else:
            raise ViewError(f"{where}: a list of routes was expected")
        for element in elements:
            if isinstance(element, Unknown | Unsupported):
                unresolved = f"route.{element.reason}"
            elif isinstance(element, Mapping):
                found.append(
                    _route({name: _fact_of_value(element.get(name)) for name in _ROUTE_FIELDS})
                )
            else:
                raise ViewError(f"{where}: a route must be an object")
    return tuple(sorted(found, key=RouteView.sort_key)), unresolved


def read_route_table(resource: Resource) -> RouteTableView:
    attributes = _attributes(resource, "aws_route_table")
    owner = resource.address
    routes, unresolved = (
        _routes(attributes["route"], owner) if "route" in attributes else ((), None)
    )
    return RouteTableView(
        address=owner,
        support=resource.support_status,
        vpc_id=_read(attributes, "vpc_id", owner),
        routes=routes,
        routes_unresolved=unresolved,
        propagating_vgws_present="propagating_vgws" in attributes,
    )
