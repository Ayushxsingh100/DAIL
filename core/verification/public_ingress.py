"""INV-SEC-001 and INV-SEC-002: no public ingress to TCP/p, ``PIP(p)`` (registry §3, §4; C-146).

For every security group ``g``, configured or pseudo (``EXTERNAL:<id>``, ``UNRESOLVED:<rule>``):

    D(g)   = ingress rules of g that are determinate and permit TCP/p
    IPv4   violates4(g) := the union of their IPv4 sources covers 0.0.0.0/0
    IPv6   violates6(g) := the union of their IPv6 sources covers ::/0
    possible4(g) := an indeterminate ingress rule could permit TCP/p and its IPv4 sources are
                    unresolved or include a prefix list (possible6 likewise for IPv6)

Each clause is decided in this order (registry §3.4), per address family:

    FAIL         a group that is not MIXED and not RETAINED-INLINE violates
    UNSUPPORTED  a MIXED group; a RETAINED-INLINE group; an ingress rule that is UNSUPPORTED; a
                 relevant-unsupported type (§2.7) anywhere
    UNKNOWN      some group has ``possible``
    PASS         otherwise

and the invariant is FAIL if either clause FAILs, otherwise the worse clause. The scope is every
group, attached or not (C-64); coverage split across two groups is not detected (S6, v1).

**How the stored view maps to the registry** (C-146; ``views`` module docstring):

* ``blocks``, ``dynamic`` and ``mixed`` all mean "has inline blocks" for MIXED and RETAINED-INLINE;
  a block that cannot be expanded is an indeterminate rule that could be anything (both families
  possible); the ``unresolved`` ingress form is UNSUPPORTED, never "no rules" (C-120(c)).
* A rule whose direction is unresolved or invalid (a rule resource's ``type``) counts as a possible
  ingress rule and as a rule of every direction for MIXED, never silently skipped: UNSUPPORTED if it
  is, otherwise indeterminate. For such a rule *any* known source also makes a family possible (the
  registry does not cover a rule that may not be ingress at all; this keeps a public source from
  being dropped).
* An UNKNOWN security group or rule resource (unknown ``count`` or ``for_each``) is an indeterminate
  rule of both families; an unreadable one is UNSUPPORTED (R5).
* An unresolved egress direction matters only through MIXED: with a rule resource targeting the
  group it cannot be decided and the group is treated as MIXED (UNSUPPORTED).

Registry §3.3 has one consequence the authors should know about (Open row C-150): a rule whose
protocol or port is unresolved but whose IPv4 source is known, such as 0.0.0.0/0, is not
``possible`` by the text, so it gives PASS. It is implemented as written and reported in
``indeterminate_rules``.

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from core.domain.enums import VerificationResult
from core.domain.identity import IdentityReport
from core.domain.resource import Resource
from core.domain.verification import VerificationReason
from core.verification.cidr import IPV4_ANY, IPV6_ANY, covers
from core.verification.outcome import CLAUSE_IPV4, CLAUSE_IPV6, PredicateOutcome, combine
from core.verification.ports import may_permit_tcp, permits_tcp
from core.verification.retention import BLOCK_FORMS, ingress_retention
from core.verification.views import (
    ORIGIN_RULE_RESOURCE,
    GroupView,
    Rule,
    SecurityConfig,
    read_security,
)

RELEVANT_UNSUPPORTED: Final = frozenset(
    {
        "aws_vpc_security_group_ingress_rule",
        "aws_default_security_group",
        "aws_vpc_security_group_rules_exclusive",
    }
)
TOLERATED_TYPE: Final = "aws_db_subnet_group"
ASSUMPTIONS: Final = (
    "egress contents are not read",
    "scope: every group, attached or not (C-64)",
    "v1: coverage split across groups is not detected (S6)",
)
TOLERATED_ASSUMPTION: Final = "tolerated type: aws_db_subnet_group (C-15)"

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
R = VerificationReason

_FAMILIES: Final = (
    (CLAUSE_IPV4, IPV4_ANY, "ipv4_sources", "ipv4_unresolved"),
    (CLAUSE_IPV6, IPV6_ANY, "ipv6_sources", "ipv6_unresolved"),
)
# the first reason that applies names an UNSUPPORTED result
_UNSUPPORTED_ORDER: Final = (
    R.GROUP_MIXED,
    R.GROUP_RETAINED_INLINE,
    R.IDENTITY_MISSING,
    R.FORMS_UNRESOLVED,
    R.RULE_UNSUPPORTED,
    R.TYPE_RELEVANT_UNSUPPORTED,
)


@dataclass(frozen=True, slots=True)
class GroupStatus:
    """What the predicate finds for one group, per address family (used by baseline items too)."""

    group: str
    clauses: Mapping[str, VerificationResult]
    reasons: tuple[VerificationReason, ...]  # why the group is UNSUPPORTED, in priority order
    violations: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True, slots=True)
class Analysis:
    port: int
    config: SecurityConfig
    groups: Mapping[str, GroupStatus]
    relevant_unsupported: tuple[str, ...]
    tolerated: bool
    outcome: PredicateOutcome


def _is_mixed(view: GroupView, rule_resources: Sequence[Rule]) -> bool:
    """Registry §2.6 MIXED, with the conservative reading of a direction that cannot be fixed."""
    forms = view.forms
    if forms is None or not rule_resources:
        return False
    if any(forms[name] in BLOCK_FORMS for name in ("ingress", "egress")):
        return True
    if any(forms[name] == "unresolved" for name in ("ingress", "egress")):
        return True  # whether inline blocks exist cannot be told
    for name, direction in (("ingress", "INGRESS"), ("egress", "EGRESS")):
        if forms[name] == "explicit_empty" and any(
            rule.direction in (direction, None) for rule in rule_resources
        ):
            return True
    return False


def _could_expose(rule: Rule, port: int, family: tuple[str, str, str, str]) -> bool:
    """``possible`` for one indeterminate rule and one address family (registry §3.3)."""
    if not may_permit_tcp(rule.protocol, rule.from_port, rule.to_port, port):
        return False
    _, _, sources, unresolved = family
    if getattr(rule, unresolved) or rule.prefix_list_ids:
        return True
    return rule.direction is None and bool(getattr(rule, sources))


def _violation(
    group: str, family: tuple[str, str, str, str], rules: Sequence[Rule]
) -> Mapping[str, Any]:
    name, _, sources, _ = family
    contributing = [rule for rule in rules if getattr(rule, sources)]
    ranges = {
        "ALL" if rule.protocol == "ALL" else f"{rule.from_port}-{rule.to_port}"
        for rule in contributing
    }
    return {
        "group": group,
        "family": name,
        "rules": sorted({rule.source_address for rule in contributing}),
        "cidrs": sorted({cidr for rule in contributing for cidr in getattr(rule, sources)}),
        "port_ranges": sorted(ranges),
    }


def _group_status(
    address: str,
    view: GroupView,
    port: int,
    retention: VerificationReason | None,
) -> tuple[GroupStatus, bool]:
    """The status of one group, and whether it is MIXED."""
    directional = (*view.ingress, *view.egress, *view.unresolved_direction)
    rule_resources = [rule for rule in directional if rule.origin == ORIGIN_RULE_RESOURCE]
    ingress_like = (*view.ingress, *view.unresolved_direction)
    mixed = _is_mixed(view, rule_resources)
    forms_unresolved = view.forms is not None and view.forms["ingress"] == "unresolved"
    reasons = [
        reason
        for reason, applies in (
            (R.GROUP_MIXED, mixed),
            (
                retention if retention is not None else R.GROUP_RETAINED_INLINE,
                retention is not None,
            ),
            (R.FORMS_UNRESOLVED, forms_unresolved),
            (R.RULE_UNSUPPORTED, any(rule.unsupported for rule in ingress_like)),
        )
        if applies
    ]
    evaluated = not mixed and retention is None
    decided = [
        rule
        for rule in view.ingress
        if rule.determinate and permits_tcp(rule.protocol, rule.from_port, rule.to_port, port)
    ]
    blocks_unexpandable = bool(view.indeterminate_blocks["ingress"])
    indeterminate = [rule for rule in ingress_like if not rule.determinate and not rule.unsupported]
    clauses: dict[str, VerificationResult] = {}
    violations: list[Mapping[str, Any]] = []
    for family in _FAMILIES:
        name, wanted, sources, _ = family
        union = [cidr for rule in decided for cidr in getattr(rule, sources)]
        if evaluated and covers(union, wanted):
            clauses[name] = F
            violations.append(_violation(address, family, decided))
        elif reasons:
            clauses[name] = S
        elif blocks_unexpandable or any(
            _could_expose(rule, port, family) for rule in indeterminate
        ):
            clauses[name] = U
        else:
            clauses[name] = P
    ordered = tuple(reason for reason in _UNSUPPORTED_ORDER if reason in reasons)
    return GroupStatus(address, clauses, ordered, tuple(violations)), mixed


def _rule_entries(group: str, rules: Iterable[Rule]) -> list[dict[str, Any]]:
    return [
        {
            "group": group,
            "rule": rule.source_address,
            "origin": rule.origin,
            "reasons": list(rule.problems),
        }
        for rule in rules
    ]


def _sorted_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        entries, key=lambda item: (item["group"], item["rule"], item["origin"], item["reasons"])
    )


def analyse(
    port: int,
    resources: Iterable[Resource],
    *,
    parent_resources: Iterable[Resource] | None = None,
    identity: IdentityReport | None = None,
) -> Analysis:
    """Evaluate ``PIP(port)`` for a candidate (``parent_resources`` is ``None`` for a baseline)."""
    candidate = list(resources)
    config = read_security(candidate)
    parent = None if parent_resources is None else {r.address: r for r in parent_resources}
    relevant = tuple(
        sorted(r.address for r in candidate if r.resource_type in RELEVANT_UNSUPPORTED)
    )
    statuses: dict[str, GroupStatus] = {}
    mixed_groups: list[str] = []
    retained: list[str] = []
    identity_missing: list[str] = []
    unresolved_forms: list[str] = []
    indeterminate: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []
    unresolved_type: list[str] = []
    for address, view in config.groups.items():
        retention = None
        if view.forms is not None and view.forms["ingress"] == "absent":
            retention = ingress_retention(address, parent=parent, identity=identity)
        status, mixed = _group_status(address, view, port, retention)
        statuses[address] = status
        if mixed:
            mixed_groups.append(address)
        if retention is R.GROUP_RETAINED_INLINE:
            retained.append(address)
        if retention is R.IDENTITY_MISSING:
            identity_missing.append(address)
        if view.forms is not None and view.forms["ingress"] == "unresolved":
            unresolved_forms.append(address)
        ingress_like = (*view.ingress, *view.unresolved_direction)
        indeterminate += _rule_entries(
            address,
            (rule for rule in ingress_like if not rule.determinate and not rule.unsupported),
        )
        for block_reason in view.indeterminate_blocks["ingress"]:
            indeterminate.append(
                {"group": address, "rule": address, "origin": "INLINE", "reasons": [block_reason]}
            )
        unsupported += _rule_entries(address, (rule for rule in ingress_like if rule.unsupported))
        unresolved_type += [rule.source_address for rule in view.unresolved_direction]
    placeholders = sorted({*config.unknown_resources, *config.unsupported_resources})
    clauses: dict[str, VerificationResult] = {}
    for name, _, _, _ in _FAMILIES:
        values = [status.clauses[name] for status in statuses.values()]
        if F in values:
            clauses[name] = F
        elif S in values or relevant or config.unsupported_resources:
            clauses[name] = S
        elif U in values or config.unknown_resources:
            clauses[name] = U
        else:
            clauses[name] = P
    result = combine(clauses)
    reason = _reason(result, statuses, relevant, config)
    violations = sorted(
        (item for status in statuses.values() for item in status.violations),
        key=lambda item: (item["group"], item["family"]),
    )
    observations: dict[str, Any] = {
        "port": port,
        "groups_evaluated": len(config.groups),
        "violations": [dict(item) for item in violations],
        "mixed_groups": sorted(mixed_groups),
        "retained_inline": [{"group": g, "direction": "ingress"} for g in sorted(retained)],
        "unresolved_forms": sorted(unresolved_forms),
        "identity_missing": sorted(identity_missing),
        "indeterminate_rules": _sorted_entries(indeterminate),
        "unsupported_rules": _sorted_entries(unsupported),
        "unresolved_type_rules": sorted(unresolved_type),
        "relevant_unsupported": list(relevant),
        "placeholders": placeholders,
    }
    tolerated = any(r.resource_type == TOLERATED_TYPE for r in candidate)
    assumptions = tuple(sorted((*ASSUMPTIONS, *((TOLERATED_ASSUMPTION,) if tolerated else ()))))
    outcome = PredicateOutcome(result, reason, clauses, observations, assumptions)
    return Analysis(port, config, statuses, relevant, tolerated, outcome)


def _reason(
    result: VerificationResult,
    statuses: Mapping[str, GroupStatus],
    relevant: tuple[str, ...],
    config: SecurityConfig,
) -> VerificationReason | None:
    if result is F:
        return R.PREDICATE_VIOLATED
    if result is U:
        return R.RULE_INDETERMINATE
    if result is not S:
        return None
    present = {reason for status in statuses.values() for reason in status.reasons}
    if relevant:
        present.add(R.TYPE_RELEVANT_UNSUPPORTED)
    if config.unsupported_resources:
        present.add(R.RULE_UNSUPPORTED)
    return next(reason for reason in _UNSUPPORTED_ORDER if reason in present)


def evaluate_public_ingress(
    port: int,
    resources: Iterable[Resource],
    *,
    parent_resources: Iterable[Resource] | None = None,
    identity: IdentityReport | None = None,
) -> PredicateOutcome:
    """``PIP(port)``: INV-SEC-001 for 22, INV-SEC-002 for 5432."""
    return analyse(port, resources, parent_resources=parent_resources, identity=identity).outcome


__all__ = [
    "RELEVANT_UNSUPPORTED",
    "Analysis",
    "GroupStatus",
    "PredicateOutcome",
    "analyse",
    "evaluate_public_ingress",
]
