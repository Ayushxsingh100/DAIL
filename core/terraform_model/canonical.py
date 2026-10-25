"""Canonical JSON encoding of evaluated values and arguments (Doc 04 §6.1; C-33, C-112).

``encode`` turns a P3a-2 value into a JSON value (``str``, ``int``, ``bool``, ``None``, list,
dict; never a float) that goes into the JSON fields of a ``core.domain.resource.Resource``. The
encoding is **injective**: two different values never share an encoding, so an unknown value
cannot be mistaken for a string, and a user map cannot be mistaken for a tagged value. It is
deterministic and does not depend on the order of anything whose order is not semantic.

| Value | Encoding |
|---|---|
| string, bool, null, integer | itself |
| non-integral number | ``{"$dail":"decimal","value":"<text>"}`` (the text Terraform prints) |
| tuple / list | JSON list, element order kept |
| set | ``{"$dail":"set","items":[...]}``, items sorted by their canonical JSON text |
| object, map | sorted keys; with a key ``"$dail"``: ``{"$dail":"map","items":{...}}`` |
| reference | ``{"$dail":"ref","address":"...","attribute":"..."}`` |
| unknown | ``{"$dail":"unknown","reason":"..."}`` |
| unsupported | ``{"$dail":"unsupported","reason":"..."}`` |

``values.to_canonical`` is not used for this: it tags with ``$decimal``, ``$set`` and ``$ref`` but
does not escape a user key of that name, so a user object ``{"$decimal": "1"}`` encodes like the
decimal 1, and it is not injective. A decoder exists only in the tests, to prove injectivity.

Arguments (``encode_argument``) keep the form they were written in (registry §2.6, C-84):
``{"form":"ATTRIBUTE","value":...}`` or ``{"form":"BLOCKS"|"DYNAMIC"|"MIXED","blocks":[...],
"indeterminate":[...]}``. Block order is kept, except for names whose blocks are a set in the
provider schema (``SET_POLICIES``), and the elements of a set-typed attribute are sorted too.

Provider facts (``SET_POLICIES``): hashicorp/aws 6.53.0, ``terraform providers schema -json``,
SHA-256 ``d6eca2ffe2141a23a742999b09c67b93c3e99939aacfff4e9afe37702664e9b2``, as filtered in
TerraPreserve D1 (``validation/d1_to_verify/schema/schema_filtered.json`` at ``c26ffed``): each
name below has the type ``set`` (an argument) or the nesting mode ``set`` (a block).
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Final

from core.domain.hashing import canonical_json
from core.terraform_model.convert import number_text
from core.terraform_model.instances import ArgumentForm, EvaluatedArgument, EvaluatedBlock
from core.terraform_model.values import Ref, SetValue, Unknown, Unsupported, Value

TAG: Final = "$dail"
MAX_ENCODE_DEPTH: Final = 60

JSON = Any


class EncodeError(ValueError):
    """A value nested too deeply to encode (the domain JSON limit is 64 levels)."""


@dataclass(frozen=True, slots=True)
class SetPolicy:
    """Which orders are not semantic for one resource type.

    ``arguments`` are top-level argument names whose blocks, or whose attribute-form elements, are
    sorted; ``nested`` are names that are sorted wherever they occur inside an argument.
    """

    arguments: frozenset[str] = frozenset()
    nested: frozenset[str] = frozenset()


_CIDR_LISTS: Final = frozenset({"cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids"})
_RULE_NESTED: Final = _CIDR_LISTS | {"security_groups"}

SET_POLICIES: Final = MappingProxyType(
    {
        "aws_security_group": SetPolicy(frozenset({"ingress", "egress"}), _RULE_NESTED),
        "aws_security_group_rule": SetPolicy(_CIDR_LISTS, _CIDR_LISTS),
        "aws_route_table": SetPolicy(frozenset({"route", "propagating_vgws"})),
        "aws_instance": SetPolicy(
            frozenset(
                {
                    "security_groups",
                    "vpc_security_group_ids",
                    "secondary_private_ips",
                    "ebs_block_device",
                    "ephemeral_block_device",
                    "network_interface",
                    "secondary_network_interface",
                }
            )
        ),
        "aws_db_instance": SetPolicy(
            frozenset({"vpc_security_group_ids", "enabled_cloudwatch_logs_exports"})
        ),
        "aws_db_subnet_group": SetPolicy(frozenset({"subnet_ids"})),
    }
)
NO_POLICY: Final = SetPolicy()


def policy_for(resource_type: str) -> SetPolicy:
    return SET_POLICIES.get(resource_type, NO_POLICY)


def text_of(encoded: JSON) -> str:
    """The canonical JSON text of an encoded value (the key that sets are sorted by)."""
    return canonical_json(encoded)


def sorted_by_text(items: list[JSON]) -> list[JSON]:
    return sorted(items, key=text_of)


# --- Values -------------------------------------------------------------------------------------


def encode(value: Value, nested: frozenset[str] = frozenset(), _depth: int = 0) -> JSON:
    """The canonical JSON of a value. ``nested`` names the object keys whose list is a set."""
    if _depth > MAX_ENCODE_DEPTH:
        raise EncodeError("value nested too deeply")
    if isinstance(value, Unknown):
        return {TAG: "unknown", "reason": value.reason}
    if isinstance(value, Unsupported):
        return {TAG: "unsupported", "reason": value.reason}
    if isinstance(value, Ref):
        return {TAG: "ref", "address": value.address, "attribute": value.attribute}
    payload = value.value
    if payload is None or isinstance(payload, str | bool | int):
        return payload
    if isinstance(payload, Decimal):
        return {TAG: "decimal", "value": number_text(payload)}
    if isinstance(payload, tuple):
        return [encode(item, nested, _depth + 1) for item in payload]
    if isinstance(payload, SetValue):
        items = [encode(item, nested, _depth + 1) for item in payload.elements]
        return {TAG: "set", "items": sorted_by_text(items)}
    members: dict[str, JSON] = {}
    for key, item in payload.items():
        encoded = encode(item, nested, _depth + 1)
        if key in nested and isinstance(encoded, list):
            encoded = sorted_by_text(encoded)
        members[key] = encoded
    if TAG in members:
        return {TAG: "map", "items": members}
    return members


# --- Arguments ----------------------------------------------------------------------------------


def encode_argument(
    argument: EvaluatedArgument, policy: SetPolicy = NO_POLICY, *, top: bool = True
) -> JSON:
    """The canonical JSON of an argument, in the form it was written in."""
    return _argument(argument, policy, top, 0)


def _argument(argument: EvaluatedArgument, policy: SetPolicy, top: bool, depth: int) -> JSON:
    if depth > MAX_ENCODE_DEPTH:
        raise EncodeError("blocks nested too deeply")
    sets = (top and argument.name in policy.arguments) or argument.name in policy.nested
    if argument.form is ArgumentForm.ATTRIBUTE:
        assert argument.value is not None
        encoded = encode(argument.value, policy.nested)
        if sets:
            encoded = _sort_elements(encoded)
        return {"form": "ATTRIBUTE", "value": encoded}
    blocks = [_block(block, policy, depth + 1) for block in argument.blocks]
    if sets:
        blocks = sorted_by_text(blocks)
    reasons = sorted_by_text([encode(reason) for reason in argument.indeterminate])
    return {"form": argument.form.value, "blocks": blocks, "indeterminate": reasons}


def _block(block: EvaluatedBlock, policy: SetPolicy, depth: int) -> JSON:
    return {
        "type": block.type,
        "labels": [encode(label) for label in block.labels],
        "arguments": {
            name: _argument(argument, policy, False, depth)
            for name, argument in sorted(block.arguments.items())
        },
        "from_dynamic": block.from_dynamic,
    }


def _sort_elements(encoded: JSON) -> JSON:
    """The elements of an attribute-form set argument (a tuple, or an already sorted set)."""
    if isinstance(encoded, list):
        return sorted_by_text(encoded)
    return encoded


def json_depth(encoded: JSON) -> int:
    """The nesting depth of a JSON value (a scalar is 0), computed without recursion."""
    deepest = 0
    stack: list[tuple[JSON, int]] = [(encoded, 0)]
    while stack:
        item, depth = stack.pop()
        deepest = max(deepest, depth)
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return deepest
