"""Node construction (C-132).

Resource nodes carry structural attributes only: ``kind``, ``resource_type`` and
``support_status``; a security-group-rule node also the canonical rule summary of Doc 07 §18, and a
security-group node its inline forms and rule keys as P3a recorded them (C-116, C-120). Never the
fingerprint and never a raw attribute value, so a tag change leaves the graph hash unchanged.

``rule_key`` is the P3a canonical text of the fields that decide equivalence (the same text as
``CanonicalSecurityRule.rule_key()``, which a test compares), so an inline rule and a rule resource
with the same meaning carry the same key (registry §2.6).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from core.dependency.addresses import object_kind, type_of
from core.dependency.errors import DependencyInputError
from core.domain.enums import ResourceSupport
from core.domain.graph import (
    GraphNode,
    NodeType,
    invariant_node_id,
    resource_node_id,
    semantic_node_id,
)
from core.domain.hashing import canonical_json
from core.domain.invariant import Invariant
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource

SECURITY_GROUP: Final = "aws_security_group"
SECURITY_GROUP_RULE: Final = "aws_security_group_rule"
SELF_TOKEN: Final = "SELF"

# The fields of a canonical rule that decide equivalence (CanonicalSecurityRule.core_json).
RULE_KEY_FIELDS: Final = (
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
)

_ABSENT_SUPPORT: Final = {"module": "UNSUPPORTED", "data": "UNSUPPORTED", "resource": "UNKNOWN"}


def rule_key(view: Mapping[str, Any], owner: str) -> str:
    """The canonical text of a rule view; an inline rule aimed at ``SELF`` is aimed at ``owner``."""
    core = {name: view[name] for name in RULE_KEY_FIELDS}
    if core["target_security_group"] == SELF_TOKEN:
        core["target_security_group"] = owner
    return canonical_json(core)


def _security_view(resource: Resource) -> dict[str, Any]:
    view = thaw_json(resource.security_attributes)
    assert isinstance(view, dict)
    return view


def _rule_summary(resource: Resource) -> dict[str, Any]:
    view = _security_view(resource)
    rule = view.get("rule")
    if not isinstance(rule, dict):
        raise DependencyInputError(
            f"{resource.address}: a supported security group rule has no canonical rule view "
            "(security_attributes.rule), so Doc 07 §18 cannot be met"
        )
    return {
        "direction": rule["direction"],
        "protocol": rule["protocol"],
        "from_port": rule["from_port"],
        "to_port": rule["to_port"],
        "rule_key": rule_key(rule, resource.address),
        "determinate": rule["determinate"],
        "unsupported": rule["unsupported"],
    }


def _group_summary(resource: Resource) -> dict[str, Any]:
    view = _security_view(resource)
    forms, inline, indeterminate = (
        view.get("forms"),
        view.get("inline_rules"),
        view.get("inline_indeterminate"),
    )
    if not isinstance(forms, dict) or not isinstance(inline, list):
        raise DependencyInputError(
            f"{resource.address}: a supported security group has no inline rule view "
            "(security_attributes.forms and inline_rules), so Doc 07 §18 cannot be met"
        )
    reasons = indeterminate if isinstance(indeterminate, list) else []
    return {
        "inline_forms": {name: forms[name] for name in sorted(forms)},
        "inline_rule_keys": sorted(rule_key(rule, resource.address) for rule in inline),
        "inline_indeterminate": sorted(reasons, key=canonical_json),
    }


def resource_node(resource: Resource) -> GraphNode:
    """The node of a resource of the state, whatever its support status."""
    attributes: dict[str, Any] = {
        "kind": "resource",
        "resource_type": resource.resource_type,
        "support_status": resource.support_status.value,
    }
    if resource.support_status is ResourceSupport.SUPPORTED:
        if resource.resource_type == SECURITY_GROUP_RULE:
            attributes.update(_rule_summary(resource))
        elif resource.resource_type == SECURITY_GROUP:
            attributes.update(_group_summary(resource))
    return GraphNode(
        node_id=resource_node_id(resource.address),
        node_type=NodeType.RESOURCE,
        ref_id=resource.address,
        attributes=attributes,
    )


def outside_node(address: str) -> GraphNode:
    """The node of an address that is no resource of the state: a data source, a module object, or
    an address nothing in the state has (``absent``). It is kept, never dropped (Doc 07 §15)."""
    kind = object_kind(address)
    node_kind = "absent" if kind == "resource" else kind
    return GraphNode(
        node_id=resource_node_id(address),
        node_type=NodeType.RESOURCE,
        ref_id=address,
        attributes={
            "kind": node_kind,
            "resource_type": type_of(address),
            "support_status": _ABSENT_SUPPORT[kind],
        },
    )


def _semantic(token: str, kind: str) -> GraphNode:
    return GraphNode(
        node_id=semantic_node_id(token),
        node_type=NodeType.SEMANTIC,
        ref_id=token,
        attributes={"kind": kind},
    )


def unresolved_node(owner: str, argument: str) -> GraphNode:
    """``SEMANTIC:UNRESOLVED:<owner>#<argument>``: a relationship DAIL cannot resolve (C-133)."""
    return _semantic(f"UNRESOLVED:{owner}#{argument}", "unresolved")


def external_node(owner: str, argument: str) -> GraphNode:
    """``SEMANTIC:EXTERNAL:<owner>#<argument>``: an object outside the configuration (C-133)."""
    return _semantic(f"EXTERNAL:{owner}#{argument}", "external")


def port_node(protocol: str, port: int) -> GraphNode:
    """``SEMANTIC:<PROTOCOL>/<port>``, for example ``SEMANTIC:TCP/5432`` (C-134)."""
    return _semantic(f"{protocol}/{port}", "protocol_port")


def invariant_node(invariant: Invariant) -> GraphNode:
    return GraphNode(
        node_id=invariant_node_id(invariant.invariant_id, invariant.version),
        node_type=NodeType.INVARIANT,
        ref_id=invariant.invariant_id,
        attributes={"category": invariant.category.value, "name": invariant.name},
    )
