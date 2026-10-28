"""The verifier's reader of the stored security view (C-144, C-146, C-149; P5a step 3).

P3a stores, for each ``aws_security_group``, ``security_attributes`` with ``inline_rules`` (one view
per inline rule), ``forms`` (the form of each direction) and ``inline_indeterminate`` (the reasons
that some inline rule is unresolved), and for each ``aws_security_group_rule`` a ``rule`` view and
its ``target`` (module docstring of ``core.terraform_model.security_rules``). This module reads that
shape into typed, frozen records. It does not import the modelling package; a test compares the
two readers field by field (C-144).

**Forms** (``security_rules.direction_form``): ``blocks``, ``explicit_empty``, ``absent``,
``dynamic`` (all blocks from ``dynamic`` blocks), ``mixed`` (static plus dynamic blocks) and
``unresolved`` (the attribute-form value cannot be fixed). A resolved dynamic expansion yields
rules, so for registry §2.6 ``blocks``, ``dynamic`` and ``mixed`` all mean "has inline blocks".

**What the view does not say (R1, C-149).** The stored rule view does not say *which field* of a
rule is unresolved. Registry §3.3 needs that for IPv4 and IPv6 apart, so the reader goes back to
``attributes``, which keep every argument as written: exact for a rule resource; for inline rules
the union over the blocks of one direction (the stored blocks are sorted, so a rule cannot be paired
with its block). The union can only add UNKNOWN. ``Rule.ipv4_unresolved`` and ``ipv6_unresolved``
are those flags; they are never set on a determinate rule.

**Placeholders.** A security group or rule resource that is an UNKNOWN placeholder (its ``count`` or
``for_each`` could not be fixed, C-114) or UNSUPPORTED (its content was too deep to keep) has an
empty
security view. P3a's index reads that as a group with no rules; here it is listed apart
(``SecurityConfig.unknown_resources`` / ``unsupported_resources``), never as "no rules". A resource
whose view is not the shape P3a writes raises ``ViewError``.

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Final

from core.domain.enums import ResourceSupport
from core.domain.hashing import canonical_json
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.verification.values import (
    Argument,
    SetValue,
    Unknown,
    Unsupported,
    ValueDecodeError,
    decode_argument,
    describe,
    has_problem,
)

INGRESS: Final = "INGRESS"
EGRESS: Final = "EGRESS"
ORIGIN_INLINE: Final = "INLINE"
ORIGIN_RULE_RESOURCE: Final = "RULE_RESOURCE"
SELF_TOKEN: Final = "SELF"
SECURITY_GROUP_TYPE: Final = "aws_security_group"
SECURITY_GROUP_RULE_TYPE: Final = "aws_security_group_rule"
FORMS: Final = ("blocks", "explicit_empty", "absent", "dynamic", "mixed", "unresolved")
DIRECTIONS: Final = (("ingress", INGRESS), ("egress", EGRESS))

_RULE_KEYS: Final = frozenset(
    {
        "direction",
        "protocol",
        "from_port",
        "to_port",
        "ipv4_sources",
        "ipv6_sources",
        "source_security_groups",
        "prefix_list_ids",
        "self",
        "target_security_group",
        "determinate",
        "unsupported",
        "problems",
        "origin",
        "description",
    }
)
_GROUP_KEYS: Final = frozenset({"forms", "inline_indeterminate", "inline_rules"})
_RULE_RESOURCE_KEYS: Final = frozenset({"rule", "target"})
_RULE_FIELDS: Final = ("cidr_blocks", "ipv6_cidr_blocks")


class ViewError(ValueError):
    """A stored security view that is not the shape P3a writes."""


@dataclass(frozen=True, slots=True)
class Rule:
    """One allow rule as stored (``CanonicalSecurityRule`` of P3a), plus the unresolved families."""

    direction: str | None  # INGRESS, EGRESS, or None when a rule resource's type is unresolved
    protocol: str | None  # ALL, TCP, UDP, ICMP, ICMPV6, a number's text; None when unresolved
    from_port: int | None
    to_port: int | None
    ipv4_sources: tuple[str, ...]
    ipv6_sources: tuple[str, ...]
    source_security_groups: tuple[str, ...]
    prefix_list_ids: tuple[str, ...]
    self_reference: bool
    target: str  # the owning group, or EXTERNAL:<id> / UNRESOLVED:<rule address>
    origin: str
    description: str | None
    source_address: str
    determinate: bool
    unsupported: bool
    problems: tuple[str, ...]
    ipv4_unresolved: bool = False
    ipv6_unresolved: bool = False

    def core_json(self) -> dict[str, Any]:
        """The fields that decide equivalence, as ``CanonicalSecurityRule.core_json`` has them."""
        return {
            "direction": self.direction,
            "protocol": self.protocol,
            "from_port": self.from_port,
            "to_port": self.to_port,
            "ipv4_sources": list(self.ipv4_sources),
            "ipv6_sources": list(self.ipv6_sources),
            "source_security_groups": list(self.source_security_groups),
            "prefix_list_ids": list(self.prefix_list_ids),
            "self": self.self_reference,
            "target_security_group": self.target,
            "determinate": self.determinate,
            "unsupported": self.unsupported,
            "problems": list(self.problems),
        }

    def rule_key(self) -> str:
        return canonical_json(self.core_json())

    def sort_key(self) -> tuple[str, str, str, str]:
        return (self.rule_key(), self.origin, self.source_address, self.description or "")


@dataclass(frozen=True, slots=True)
class GroupView:
    """The rules of one group or pseudo-group, as an index only: no predicate is evaluated."""

    ingress: tuple[Rule, ...]
    egress: tuple[Rule, ...]
    unresolved_direction: tuple[Rule, ...]
    forms: Mapping[str, str] | None  # None for a pseudo-group
    inline_indeterminate: tuple[Any, ...]  # as stored (encoded reasons)
    indeterminate_blocks: Mapping[
        str, tuple[str, ...]
    ]  # per direction, blocks that cannot be expanded


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    groups: Mapping[str, GroupView]
    unknown_resources: tuple[str, ...]  # SG / rule resources that are UNKNOWN placeholders
    unsupported_resources: tuple[str, ...]  # SG / rule resources whose content was not kept


# --- shape checks --------------------------------------------------------------------------------


def _fail(where: str, message: str) -> ViewError:
    return ViewError(f"{where}: {message}")


def _texts(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _fail(where, "must be a list of text")
    return tuple(value)


def _optional_int(value: object, where: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(where, "must be an integer or null")
    return value


def _flag(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise _fail(where, "must be a boolean")
    return value


def _optional_text(value: object, where: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise _fail(where, "must be text or null")
    return value


def read_rule(view: object, *, owner: str) -> Rule:
    """One stored rule view; ``owner`` is the address of the resource that holds it."""
    where = f"{owner}: rule view"
    if not isinstance(view, dict) or set(view) != _RULE_KEYS:
        raise _fail(where, f"must be an object with the keys {sorted(_RULE_KEYS)}")
    direction = view["direction"]
    if direction not in (None, INGRESS, EGRESS):
        raise _fail(where, f"direction {direction!r} is not INGRESS, EGRESS or null")
    origin = view["origin"]
    if origin not in (ORIGIN_INLINE, ORIGIN_RULE_RESOURCE):
        raise _fail(where, f"origin {origin!r} is not INLINE or RULE_RESOURCE")
    target = view["target_security_group"]
    if not isinstance(target, str) or target == "":
        raise _fail(where, "target_security_group must be text")
    return Rule(
        direction=direction,
        protocol=_optional_text(view["protocol"], f"{where}.protocol"),
        from_port=_optional_int(view["from_port"], f"{where}.from_port"),
        to_port=_optional_int(view["to_port"], f"{where}.to_port"),
        ipv4_sources=_texts(view["ipv4_sources"], f"{where}.ipv4_sources"),
        ipv6_sources=_texts(view["ipv6_sources"], f"{where}.ipv6_sources"),
        source_security_groups=_texts(
            view["source_security_groups"], f"{where}.source_security_groups"
        ),
        prefix_list_ids=_texts(view["prefix_list_ids"], f"{where}.prefix_list_ids"),
        self_reference=_flag(view["self"], f"{where}.self"),
        target=owner if target == SELF_TOKEN else target,
        origin=origin,
        description=_optional_text(view["description"], f"{where}.description"),
        source_address=owner,
        determinate=_flag(view["determinate"], f"{where}.determinate"),
        unsupported=_flag(view["unsupported"], f"{where}.unsupported"),
        problems=_texts(view["problems"], f"{where}.problems"),
    )


# --- unresolved families (C-149) ---------------------------------------------------------------


def _argument(encoded: object, where: str) -> Argument:
    try:
        return decode_argument(encoded)
    except ValueDecodeError as error:
        raise _fail(where, str(error)) from None


def _field_unresolved(argument: Argument | None) -> bool:
    """Whether one rule field is unresolved. A field written as a block is not a value at all,
    which P3a records as an unsupported rule; treated as unresolved here."""
    if argument is None:
        return False
    if argument.form != "ATTRIBUTE":
        return True
    return has_problem(argument.value)


def _resource_families(attributes: Mapping[str, Any], owner: str) -> tuple[bool, bool]:
    """Exact flags of a rule resource, from its own arguments."""
    flags = []
    for name in _RULE_FIELDS:
        encoded = attributes.get(name)
        flags.append(
            False if encoded is None else _field_unresolved(_argument(encoded, f"{owner}.{name}"))
        )
    return flags[0], flags[1]


def _direction_details(
    encoded: object, owner: str, name: str
) -> tuple[bool, bool, tuple[str, ...]]:
    """For one direction of a group: whether some block leaves IPv4 or IPv6 sources unresolved, and
    the reasons of blocks that could not be expanded at all."""
    if encoded is None:
        return False, False, ()
    where = f"{owner}.{name}"
    argument = _argument(encoded, where)
    v4 = v6 = False
    placeholders: list[str] = []
    if argument.form == "ATTRIBUTE":
        value = argument.value
        elements: tuple[Any, ...] = ()
        if isinstance(value, tuple):
            elements = value
        elif isinstance(value, SetValue):
            elements = value.items
        for element in elements:
            if isinstance(element, Mapping):
                v4 = v4 or has_problem(element.get("cidr_blocks"))
                v6 = v6 or has_problem(element.get("ipv6_cidr_blocks"))
            elif isinstance(element, Unknown | Unsupported):
                placeholders.append(describe(element))
            else:
                placeholders.append("unsupported:normalize.inline_form")
        return v4, v6, tuple(sorted(set(placeholders)))
    for block in argument.blocks:
        v4 = v4 or _field_unresolved(block.arguments.get("cidr_blocks"))
        v6 = v6 or _field_unresolved(block.arguments.get("ipv6_cidr_blocks"))
    placeholders = [describe(reason) for reason in argument.indeterminate if _is_problem(reason)]
    if len(placeholders) != len(argument.indeterminate):
        raise _fail(where, "indeterminate holds something that is not a reason")
    return v4, v6, tuple(sorted(set(placeholders)))


def _is_problem(value: object) -> bool:
    return isinstance(value, Unknown | Unsupported)


# --- resources ---------------------------------------------------------------------------------


def _security(resource: Resource, expected: frozenset[str]) -> dict[str, Any]:
    security = thaw_json(resource.security_attributes)
    if set(security) != expected:
        raise _fail(
            resource.address,
            f"security_attributes keys must be {sorted(expected)}, got {sorted(security)}",
        )
    return dict(security)


def _group_parts(
    resource: Resource,
) -> tuple[list[Rule], Mapping[str, str], tuple[Any, ...], dict[str, tuple[str, ...]]]:
    security = _security(resource, _GROUP_KEYS)
    owner = resource.address
    forms = security["forms"]
    if (
        not isinstance(forms, dict)
        or set(forms) != {"ingress", "egress"}
        or not all(value in FORMS for value in forms.values())
    ):
        raise _fail(owner, f"forms must give ingress and egress one of {FORMS}")
    if not isinstance(security["inline_indeterminate"], list):
        raise _fail(owner, "inline_indeterminate must be a list")
    if not isinstance(security["inline_rules"], list):
        raise _fail(owner, "inline_rules must be a list")
    attributes = thaw_json(resource.attributes)
    details = {
        name: _direction_details(attributes.get(name), owner, name) for name, _ in DIRECTIONS
    }
    rules = []
    for view in security["inline_rules"]:
        rule = read_rule(view, owner=owner)
        if rule.origin != ORIGIN_INLINE or rule.direction not in (INGRESS, EGRESS):
            raise _fail(owner, "an inline rule must be INLINE and have a direction")
        if not rule.determinate:
            name = "ingress" if rule.direction == INGRESS else "egress"
            rule = replace(rule, ipv4_unresolved=details[name][0], ipv6_unresolved=details[name][1])
        rules.append(rule)
    blocks = {name: details[name][2] for name, _ in DIRECTIONS}
    return rules, MappingProxyType(dict(forms)), tuple(security["inline_indeterminate"]), blocks


def _rule_of_resource(resource: Resource) -> Rule:
    security = _security(resource, _RULE_RESOURCE_KEYS)
    rule = read_rule(security["rule"], owner=resource.address)
    if rule.origin != ORIGIN_RULE_RESOURCE:
        raise _fail(resource.address, "a rule resource's rule must be RULE_RESOURCE")
    if not rule.determinate:
        v4, v6 = _resource_families(thaw_json(resource.attributes), resource.address)
        rule = replace(rule, ipv4_unresolved=v4, ipv6_unresolved=v6)
    return rule


def rules_of(resource: Resource) -> tuple[Rule, ...]:
    """The rules a resource holds: inline rules of a group, the rule of a rule resource."""
    if resource.support_status is not ResourceSupport.SUPPORTED:
        return ()
    if resource.resource_type == SECURITY_GROUP_TYPE:
        return tuple(_group_parts(resource)[0])
    if resource.resource_type == SECURITY_GROUP_RULE_TYPE:
        return (_rule_of_resource(resource),)
    return ()


def read_security(resources: Iterable[Resource]) -> SecurityConfig:
    """Every group and pseudo-group with its rules, and the resources that could not be read.

    Every ``aws_security_group`` appears (even without rules); a pseudo-group appears when a rule
    resource targets it. Rules with equal keys are all kept, in a fixed order (Doc 04 §18)."""
    by_target: dict[str, list[Rule]] = {}
    parts: dict[str, tuple[Mapping[str, str], tuple[Any, ...], dict[str, tuple[str, ...]]]] = {}
    unknown: list[str] = []
    unsupported: list[str] = []
    for resource in resources:
        if resource.resource_type not in (SECURITY_GROUP_TYPE, SECURITY_GROUP_RULE_TYPE):
            continue
        if resource.support_status is ResourceSupport.UNKNOWN:
            unknown.append(resource.address)
            continue
        if resource.support_status is ResourceSupport.UNSUPPORTED:
            unsupported.append(resource.address)
            continue
        if resource.resource_type == SECURITY_GROUP_TYPE:
            rules, forms, reasons, blocks = _group_parts(resource)
            by_target.setdefault(resource.address, [])
            parts[resource.address] = (forms, reasons, blocks)
        else:
            rules = [_rule_of_resource(resource)]
        for rule in rules:
            by_target.setdefault(rule.target, []).append(rule)
    nothing: Mapping[str, tuple[str, ...]] = MappingProxyType({"ingress": (), "egress": ()})
    groups: dict[str, GroupView] = {}
    for target in sorted(by_target):
        ordered = sorted(by_target[target], key=Rule.sort_key)
        found = parts.get(target)
        groups[target] = GroupView(
            ingress=tuple(r for r in ordered if r.direction == INGRESS),
            egress=tuple(r for r in ordered if r.direction == EGRESS),
            unresolved_direction=tuple(r for r in ordered if r.direction is None),
            forms=None if found is None else found[0],
            inline_indeterminate=() if found is None else found[1],
            indeterminate_blocks=nothing if found is None else MappingProxyType(found[2]),
        )
    return SecurityConfig(
        MappingProxyType(groups), tuple(sorted(unknown)), tuple(sorted(unsupported))
    )


def index_rules(resources: Iterable[Resource]) -> Mapping[str, GroupView]:
    """``core.terraform_model.security_rules.index_rules``, read by the verifier."""
    return read_security(resources).groups
