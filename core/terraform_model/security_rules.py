"""Canonical security-group rules (Doc 04 §8, §16.1; registry §2.5, §2.6; C-84, C-116).

A ``CanonicalSecurityRule`` is the one semantic form of an allow rule, whether it was written as
an inline ``ingress``/``egress`` block of an ``aws_security_group`` (``origin INLINE``) or as an
``aws_security_group_rule`` (``origin RULE_RESOURCE``). Both forms give the same ``rule_key()``.

- **Protocol** (registry §2.5): compared case-insensitively; ``-1``/``all`` is ``ALL`` (ports are
  ``null``), ``tcp``/``6`` is ``TCP``, ``udp``/``17`` ``UDP``, ``icmp``/``1`` ``ICMP``,
  ``icmpv6``/``58`` ``ICMPV6``, any other number is that number's text. Any other name cannot be
  canonicalised (``protocol.unsupported``).
- **CIDRs** (registry §2.5): parsed with ``ipaddress`` and ``strict=True``; an invalid CIDR, or one
  with host bits set, makes the rule UNSUPPORTED (``cidr.invalid``). Listed in canonical text form,
  sorted (by address, then prefix length) and without duplicates.
- **TCP** with ``from_port > to_port`` is UNSUPPORTED (``ports.inverted``).
- **Indeterminate** (registry §2.6): an unknown value anywhere, a non-empty ``prefix_list_ids``, or
  an unresolved block adds a problem and makes ``determinate`` false. ``unsupported`` is true when
  a problem makes the rule UNSUPPORTED rather than UNKNOWN (an invalid CIDR, inverted ports, an
  unsupported value, a field of the wrong type).
- **Target**: the canonical address of the owning group, or a pseudo-group key:
  ``EXTERNAL:<literal id>`` or ``UNRESOLVED:<rule address>`` (registry §2.6).

Inside a ``Resource`` the rule is stored without the address of the resource it belongs to, so that
renaming the resource does not change its fingerprint (Doc 05 §5.2): an inline rule's target is
the token ``SELF`` and no ``source_address`` is stored. ``index_rules`` rebuilds the full rules.

Problem codes are the reason of the unknown or unsupported value itself (for example
``variable.no_value``), or one of ``PROBLEM_CODES``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from core.domain.hashing import canonical_json
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.terraform_model.canonical import JSON, encode, sorted_by_text
from core.terraform_model.convert import Fail, as_int, as_string, kind_of
from core.terraform_model.instances import ArgumentForm, EvaluatedArgument, EvaluatedInstance
from core.terraform_model.values import (
    Known,
    Ref,
    SetValue,
    Unknown,
    Unsupported,
    Value,
    first_problem_value,
)

INGRESS: Final = "INGRESS"
EGRESS: Final = "EGRESS"
ORIGIN_INLINE: Final = "INLINE"
ORIGIN_RULE_RESOURCE: Final = "RULE_RESOURCE"
SELF_TOKEN: Final = "SELF"
SECURITY_GROUP_TYPE: Final = "aws_security_group"

# Problems that are not the reason of an unknown or unsupported value. "U" = the rule is
# UNSUPPORTED, "I" = indeterminate (unknown).
PROBLEM_CODES: Final[Mapping[str, tuple[str, str]]] = {
    "cidr.invalid": ("U", "A CIDR that is malformed or has host bits set (registry §2.5)."),
    "ports.inverted": ("U", "A TCP rule with from_port greater than to_port (registry §2.5)."),
    "ports.invalid": ("U", "A port that is not a whole number from 0 to 65535."),
    "ports.missing": ("U", "A TCP or UDP rule without from_port or to_port."),
    "protocol.missing": ("U", "A rule without a protocol."),
    "protocol.unsupported": ("U", "A protocol name that cannot be canonicalised."),
    "type.invalid": ("U", "A rule resource type other than ingress or egress."),
    "field.type": ("U", "A rule field of a type it cannot have."),
    "field.form": ("U", "A rule field written as a block."),
    "prefix_list_ids.present": ("I", "A non-empty prefix_list_ids: its contents are not known."),
    "ref.derived": ("I", "A value computed from a reference (the ID is not known)."),
}

# Rule fields read from a block or a rule resource.
_FIELDS: Final = (
    "protocol",
    "from_port",
    "to_port",
    "cidr_blocks",
    "ipv6_cidr_blocks",
    "security_groups",
    "source_security_group_id",
    "self",
    "prefix_list_ids",
    "description",
)


@dataclass(frozen=True, slots=True)
class CanonicalSecurityRule:
    """One allow rule in canonical form (C-116)."""

    direction: str | None  # INGRESS, EGRESS, or None when the type of a rule resource is unresolved
    protocol: str | None  # ALL, TCP, UDP, ICMP, ICMPV6, a number's text; None when unresolved
    from_port: int | None
    to_port: int | None
    ipv4_sources: tuple[str, ...]
    ipv6_sources: tuple[str, ...]
    source_security_groups: tuple[str, ...]
    prefix_list_ids: tuple[str, ...]
    self_reference: bool
    target_security_group: str
    origin: str
    description: str | None
    source_address: str
    determinate: bool
    unsupported: bool
    problems: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        """The full canonical JSON, with sorted keys when serialised."""
        return {**self.core_json(), "origin": self.origin, "description": self.description,
                "source_address": self.source_address}  # fmt: skip

    def core_json(self) -> dict[str, Any]:
        """The fields that decide equivalence: no origin, no description, no source address."""
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
            "target_security_group": self.target_security_group,
            "determinate": self.determinate,
            "unsupported": self.unsupported,
            "problems": list(self.problems),
        }

    def rule_key(self) -> str:
        """Canonical text of the fields that decide equivalence (origin, description and source
        address excluded): two rules with equal keys are the same rule."""
        return canonical_json(self.core_json())

    def view_json(self) -> dict[str, Any]:
        """The JSON stored in a ``Resource``: no source address, and an inline rule's target is
        ``SELF`` (rename-stable, Doc 05 §5.2)."""
        view = self.core_json()
        view["origin"] = self.origin
        view["description"] = self.description
        if self.origin == ORIGIN_INLINE and self.target_security_group == self.source_address:
            view["target_security_group"] = SELF_TOKEN
        return view

    @classmethod
    def from_view(cls, view: Mapping[str, Any], *, owner: str) -> CanonicalSecurityRule:
        """Rebuild the rule from a ``Resource`` view; ``owner`` is the address of the resource."""
        target = view["target_security_group"]
        return cls(
            direction=view["direction"],
            protocol=view["protocol"],
            from_port=view["from_port"],
            to_port=view["to_port"],
            ipv4_sources=tuple(view["ipv4_sources"]),
            ipv6_sources=tuple(view["ipv6_sources"]),
            source_security_groups=tuple(view["source_security_groups"]),
            prefix_list_ids=tuple(view["prefix_list_ids"]),
            self_reference=view["self"],
            target_security_group=owner if target == SELF_TOKEN else target,
            origin=view["origin"],
            description=view["description"],
            source_address=owner,
            determinate=view["determinate"],
            unsupported=view["unsupported"],
            problems=tuple(view["problems"]),
        )


# --- Fields --------------------------------------------------------------------------------------


class _Problems:
    def __init__(self) -> None:
        self.codes: set[str] = set()
        self.unsupported = False

    def add(self, code: str, *, unsupported: bool) -> None:
        self.codes.add(code)
        self.unsupported = self.unsupported or unsupported

    def structural(self, code: str, detail: str | None = None) -> None:
        kind = PROBLEM_CODES[code][0]
        self.add(code if detail is None else f"{code}:{detail}", unsupported=kind == "U")

    def value(self, problem: Unknown | Unsupported | Ref) -> None:
        if isinstance(problem, Ref):
            self.add(f"ref.derived:{problem.address}.{problem.attribute}", unsupported=False)
        else:
            self.add(problem.reason, unsupported=isinstance(problem, Unsupported))


def canonical_protocol(text: str) -> str | None:
    """The canonical protocol of registry §2.5, or None for a name that cannot be canonicalised."""
    lowered = text.lower()
    if lowered in ("-1", "all"):
        return "ALL"
    if lowered in ("tcp", "6"):
        return "TCP"
    if lowered in ("udp", "17"):
        return "UDP"
    if lowered in ("icmp", "1"):
        return "ICMP"
    if lowered in ("icmpv6", "58"):
        return "ICMPV6"
    if lowered.isascii() and lowered.isdigit():
        return str(int(lowered))
    return None


def _scalar(value: Value | None, problems: _Problems) -> Known | None:
    """A known non-null value, else None (absent, null, or a problem that was recorded)."""
    if value is None:
        return None
    if isinstance(value, Unknown | Unsupported | Ref):
        problems.value(value)
        return None
    return None if kind_of(value) == "null" else value


def _strings(value: Value | None, field: str, problems: _Problems) -> list[str]:
    """The strings of a list or set field; unresolved items are recorded as problems."""
    if value is None:
        return []
    if isinstance(value, Unknown | Unsupported | Ref):
        problems.value(value)
        return []
    payload = value.value
    if payload is None:
        return []
    if isinstance(payload, SetValue):
        items: tuple[Value, ...] = payload.elements
    elif isinstance(payload, tuple):
        items = payload
    else:
        problems.structural("field.type", field)
        return []
    found: list[str] = []
    for item in items:
        if isinstance(item, Unknown | Unsupported | Ref):
            problems.value(item)
        elif kind_of(item) == "string":
            found.append(str(item.value))
        else:
            problems.structural("field.type", field)
    return found


def _cidrs(texts: Iterable[str], version: int, problems: _Problems) -> tuple[str, ...]:
    networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for text in texts:
        try:
            network = ipaddress.ip_network(text, strict=True)
        except ValueError:
            problems.structural("cidr.invalid", text)
            continue
        if network.version != version or "/" not in text:
            problems.structural("cidr.invalid", text)
            continue
        networks.add(network)
    ordered = sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))
    return tuple(str(network) for network in ordered)


def _sources(value: Value | None, field: str, problems: _Problems) -> list[str]:
    """Security-group sources: a reference is the instance address, a literal is external."""
    found: list[str] = []
    if value is None:
        return found
    items: list[Value]
    if isinstance(value, Known) and isinstance(value.value, tuple | SetValue):
        payload = value.value
        items = list(payload.elements if isinstance(payload, SetValue) else payload)
    else:
        items = [value]
    for item in items:
        if isinstance(item, Ref):
            found.append(item.address)
        elif isinstance(item, Unknown | Unsupported):
            problems.value(item)
        elif kind_of(item) == "null":
            continue
        elif kind_of(item) == "string":
            found.append(f"EXTERNAL:{item.value}")
        else:
            problems.structural("field.type", field)
    return found


def _bool(value: Value | None, field: str, problems: _Problems) -> bool:
    known = _scalar(value, problems)
    if known is None:
        return False
    if isinstance(known.value, bool):
        return known.value
    problems.structural("field.type", field)
    return False


def _port(value: Value | None, problems: _Problems) -> int | None:
    known = _scalar(value, problems)
    if known is None:
        return None
    try:
        number = as_int(known)
    except Fail:
        problems.structural("ports.invalid")
        return None
    if not 0 <= number <= 65535 and number != -1:
        problems.structural("ports.invalid")
    return number


def _description(value: Value | None, problems: _Problems) -> str | None:
    known = _scalar(value, problems)
    if known is None:
        return None
    try:
        return as_string(known)
    except Fail:
        problems.structural("field.type", "description")
        return None


def _absent(value: Value | None) -> bool:
    return value is None or (isinstance(value, Known) and value.value is None)


def build_rule(
    fields: Mapping[str, Value],
    *,
    direction: str | None,
    target: str,
    origin: str,
    source_address: str,
    extra_problems: Iterable[Unknown | Unsupported] = (),
    problems: _Problems | None = None,
) -> CanonicalSecurityRule:
    """The canonical rule for the fields of one inline block or one rule resource."""
    problems = problems if problems is not None else _Problems()
    for problem in extra_problems:
        problems.value(problem)
    protocol = _protocol(fields.get("protocol"), problems)
    from_port, to_port = _ports(fields, protocol, problems)
    ipv4 = _cidrs(_strings(fields.get("cidr_blocks"), "cidr_blocks", problems), 4, problems)
    ipv6 = _cidrs(
        _strings(fields.get("ipv6_cidr_blocks"), "ipv6_cidr_blocks", problems), 6, problems
    )
    sources = _sources(fields.get("security_groups"), "security_groups", problems)
    sources += _sources(
        fields.get("source_security_group_id"), "source_security_group_id", problems
    )
    prefix_lists = sorted(set(_strings(fields.get("prefix_list_ids"), "prefix_list_ids", problems)))
    if prefix_lists:
        problems.structural("prefix_list_ids.present")
    return CanonicalSecurityRule(
        direction=direction,
        protocol=protocol,
        from_port=from_port,
        to_port=to_port,
        ipv4_sources=ipv4,
        ipv6_sources=ipv6,
        source_security_groups=tuple(sorted(set(sources))),
        prefix_list_ids=tuple(prefix_lists),
        self_reference=_bool(fields.get("self"), "self", problems),
        target_security_group=target,
        origin=origin,
        description=_description(fields.get("description"), problems),
        source_address=source_address,
        determinate=not problems.codes,
        unsupported=problems.unsupported,
        problems=tuple(sorted(problems.codes)),
    )


def _protocol(raw: Value | None, problems: _Problems) -> str | None:
    if _absent(raw):
        problems.structural("protocol.missing")
        return None
    known = _scalar(raw, problems)
    if known is None:
        return None  # an unresolved value; its reason is recorded
    try:
        text = as_string(known)
    except Fail:
        problems.structural("field.type", "protocol")
        return None
    protocol = canonical_protocol(text)
    if protocol is None:
        problems.structural("protocol.unsupported", text.lower())
        return text.lower()
    return protocol


def _ports(
    fields: Mapping[str, Value], protocol: str | None, problems: _Problems
) -> tuple[int | None, int | None]:
    low = _port(fields.get("from_port"), problems)
    high = _port(fields.get("to_port"), problems)
    if protocol == "ALL":
        return None, None  # ports are ignored (registry §2.5)
    if protocol in ("TCP", "UDP") and (
        _absent(fields.get("from_port")) or _absent(fields.get("to_port"))
    ):
        problems.structural("ports.missing")
    if protocol == "TCP" and low is not None and high is not None and low > high:
        problems.structural("ports.inverted")
    return low, high


# --- Inline rules and rule resources -------------------------------------------------------------


def block_fields(
    arguments: Mapping[str, EvaluatedArgument], problems: list[Unsupported]
) -> dict[str, Value]:
    """The rule fields of an inline block; a field written as a block is a recorded problem."""
    fields: dict[str, Value] = {}
    for name, argument in arguments.items():
        if name not in _FIELDS:
            continue
        if argument.form is ArgumentForm.ATTRIBUTE and argument.value is not None:
            fields[name] = argument.value
        else:
            problems.append(Unsupported("field.form"))
    return fields


def direction_form(
    instance: EvaluatedInstance, name: str
) -> tuple[str, list[Unknown | Unsupported]]:
    """The form of one direction of a security group (C-84) and the reasons it is unresolved:
    ``blocks``, ``explicit_empty``, ``absent``, ``dynamic``, ``mixed``, or ``unresolved`` for an
    attribute-form value that cannot be fixed."""
    argument = instance.arguments.get(name)
    if argument is None:
        return "absent", []
    if argument.form is ArgumentForm.BLOCKS:
        return "blocks", list(argument.indeterminate)
    if argument.form is ArgumentForm.DYNAMIC:
        return "dynamic", list(argument.indeterminate)
    if argument.form is ArgumentForm.MIXED:
        return "mixed", list(argument.indeterminate)
    value = argument.value
    assert value is not None
    if isinstance(value, Unknown | Unsupported):
        return "unresolved", [value]
    if isinstance(value, Known):
        payload = value.value
        if payload is None:
            return "absent", []  # an explicit null is the provider's "not set"
        if isinstance(payload, tuple) and not payload:
            return "explicit_empty", []
        if isinstance(payload, tuple | SetValue):
            problem = first_problem_value(value)
            return "blocks", [] if problem is None else [problem]
    return "unresolved", [Unsupported("normalize.inline_form")]


@dataclass(frozen=True, slots=True)
class InlineRules:
    rules: tuple[CanonicalSecurityRule, ...]
    forms: Mapping[str, str]
    indeterminate: tuple[JSON, ...]


def inline_rules(instance: EvaluatedInstance) -> InlineRules:
    """The canonical inline rules of a security group, sorted, with the form of each direction
    (C-84) and the reasons that some inline rule is unresolved."""
    rules: list[CanonicalSecurityRule] = []
    forms: dict[str, str] = {}
    reasons: list[JSON] = []
    for name, direction in (("ingress", INGRESS), ("egress", EGRESS)):
        form, form_reasons = direction_form(instance, name)
        forms[name] = form
        reasons.extend(encode(reason) for reason in form_reasons)
        argument = instance.arguments.get(name)
        if argument is None:
            continue
        for fields, extra in _inline_field_sets(argument, reasons):
            rules.append(
                build_rule(
                    fields,
                    direction=direction,
                    target=instance.address,
                    origin=ORIGIN_INLINE,
                    source_address=instance.address,
                    extra_problems=extra,
                )
            )
    ordered = sorted(rules, key=lambda rule: canonical_json(rule.view_json()))
    return InlineRules(
        tuple(ordered),
        MappingProxyType(forms),
        tuple(sorted_by_text(list({canonical_json(r): r for r in reasons}.values()))),
    )


def _inline_field_sets(
    argument: EvaluatedArgument, reasons: list[JSON]
) -> list[tuple[dict[str, Value], list[Unsupported]]]:
    """The rule fields of every inline rule of one direction: one set per block, or per element of
    an attribute-form list. An unresolved element is a recorded reason, not a rule."""
    sets: list[tuple[dict[str, Value], list[Unsupported]]] = []
    if argument.form is not ArgumentForm.ATTRIBUTE:
        for block in argument.blocks:
            extra: list[Unsupported] = []
            sets.append((block_fields(block.arguments, extra), extra))
        return sets
    value = argument.value
    if not isinstance(value, Known) or not isinstance(value.value, tuple | SetValue):
        return sets
    payload = value.value
    for element in payload.elements if isinstance(payload, SetValue) else payload:
        if isinstance(element, Known) and isinstance(element.value, MappingProxyType):
            sets.append(({k: v for k, v in element.value.items() if k in _FIELDS}, []))
        elif isinstance(element, Unknown | Unsupported):
            reasons.append(encode(element))
        else:
            reasons.append(encode(Unsupported("normalize.inline_form")))
    return sets


def resource_rule(instance: EvaluatedInstance) -> CanonicalSecurityRule:
    """The canonical rule of an ``aws_security_group_rule`` instance."""
    fields: dict[str, Value] = {}
    extra: list[Unsupported] = []
    for name, argument in instance.arguments.items():
        if name in _FIELDS or name in ("type", "security_group_id"):
            if argument.form is ArgumentForm.ATTRIBUTE and argument.value is not None:
                fields[name] = argument.value
            else:
                extra.append(Unsupported("field.form"))
    problems = _Problems()
    return build_rule(
        fields,
        direction=_direction(fields.get("type"), problems),
        target=_target(fields.get("security_group_id"), instance.address),
        origin=ORIGIN_RULE_RESOURCE,
        source_address=instance.address,
        extra_problems=extra,
        problems=problems,
    )


def _direction(value: Value | None, problems: _Problems) -> str | None:
    known = _scalar(value, problems)
    if known is None:
        if value is None or kind_of(value) == "null":
            problems.structural("type.invalid", "missing")
        return None
    text = known.value if isinstance(known.value, str) else ""
    if text == "ingress":
        return INGRESS
    if text == "egress":
        return EGRESS
    problems.structural("type.invalid", str(text)[:40])
    return None


def _target(value: Value | None, rule_address: str) -> str:
    """The pseudo-group key of a rule resource (registry §2.6)."""
    if isinstance(value, Ref) and value.address.split(".", 1)[0] == SECURITY_GROUP_TYPE:
        return value.address
    if isinstance(value, Known) and isinstance(value.value, str):
        return f"EXTERNAL:{value.value}"
    return f"UNRESOLVED:{rule_address}"


# --- The index -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GroupRules:
    """The rules of one group (or pseudo-group), as an index only: no predicate is evaluated."""

    ingress: tuple[CanonicalSecurityRule, ...]
    egress: tuple[CanonicalSecurityRule, ...]
    unresolved_direction: tuple[CanonicalSecurityRule, ...]
    inline_forms: Mapping[str, str] | None  # None for a pseudo-group
    inline_indeterminate: tuple[JSON, ...]


def rules_of(resource: Resource) -> tuple[CanonicalSecurityRule, ...]:
    """The canonical rules held by a normalized resource."""
    security = thaw_json(resource.security_attributes)
    if resource.resource_type == "aws_security_group":
        return tuple(
            CanonicalSecurityRule.from_view(view, owner=resource.address)
            for view in security.get("inline_rules", [])
        )
    if resource.resource_type == "aws_security_group_rule" and "rule" in security:
        return (CanonicalSecurityRule.from_view(security["rule"], owner=resource.address),)
    return ()


def index_rules(resources: Iterable[Resource]) -> Mapping[str, GroupRules]:
    """Index every rule by the group it belongs to; sorted and pure.

    Every ``aws_security_group`` appears (even without rules); a pseudo-group (``EXTERNAL:...``,
    ``UNRESOLVED:...``) appears when a rule resource targets it. Rules with equal keys are all
    kept, in a fixed order, so no duplicate changes the meaning of the index (Doc 04 §18).
    """
    by_target: dict[str, list[CanonicalSecurityRule]] = {}
    forms: dict[str, Mapping[str, str]] = {}
    reasons: dict[str, tuple[JSON, ...]] = {}
    for resource in resources:
        if resource.resource_type == "aws_security_group":
            security = thaw_json(resource.security_attributes)
            by_target.setdefault(resource.address, [])
            forms[resource.address] = MappingProxyType(dict(security.get("forms", {})))
            reasons[resource.address] = tuple(security.get("inline_indeterminate", []))
        for rule in rules_of(resource):
            by_target.setdefault(rule.target_security_group, []).append(rule)
    index: dict[str, GroupRules] = {}
    for target in sorted(by_target):
        ordered = sorted(
            by_target[target],
            key=lambda r: (r.rule_key(), r.origin, r.source_address, r.description or ""),
        )
        index[target] = GroupRules(
            ingress=tuple(r for r in ordered if r.direction == INGRESS),
            egress=tuple(r for r in ordered if r.direction == EGRESS),
            unresolved_direction=tuple(r for r in ordered if r.direction is None),
            inline_forms=forms.get(target),
            inline_indeterminate=reasons.get(target, ()),
        )
    return MappingProxyType(index)
