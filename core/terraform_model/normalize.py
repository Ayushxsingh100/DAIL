"""Per-instance normalization into ``core.domain.resource.Resource`` (Doc 04 §5, §6, §7; C-33,
C-112 to C-118).

``normalize_instance`` turns one ``EvaluatedInstance`` into one ``Resource``:

- ``attributes``: the canonical encoding (``canonical.py``) of **every** configured argument,
  sorted by name, so nothing is dropped; an unknown or unsupported value stays in it with its
  reason;
- ``logical_identity``: the naming fields of the type that are present, and the instance key;
- ``security_attributes`` and ``semantic_attributes``: type-specific views, duplicated from
  ``attributes`` on purpose (C-113). **Absent is omitted, never ``null``; an explicit ``null``
  stays ``null``** (one policy, Doc 04 §6.1);
- ``support_status`` (C-114): the nine supported types are ``SUPPORTED``; every other type,
  including the tolerated ``aws_db_subnet_group``, is ``UNSUPPORTED`` and is kept, never dropped;
  value-level unknowns never change it;
- ``provenance``: where the facts came from, with the parser, evaluator and normalization
  versions. The Terraform CLI version is not recorded here: the core never runs the CLI.

``normalize_indeterminate`` makes the one placeholder ``Resource`` (``UNKNOWN``) of a resource
whose expansion cannot be fixed. The package has no clock: the caller passes ``now``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any, Final

from core.domain.enums import ProvenanceSourceKind, ResourceSupport
from core.domain.errors import DomainValidationError
from core.domain.resource import Resource
from core.domain.values import Provenance, Reference
from core.terraform_model.canonical import (
    JSON,
    MAX_ENCODE_DEPTH,
    EncodeError,
    encode,
    encode_argument,
    json_depth,
    policy_for,
)
from core.terraform_model.config import PARSER_VERSION
from core.terraform_model.evaluation import EVALUATOR_VERSION
from core.terraform_model.hcl.ast import SourceRange
from core.terraform_model.instances import (
    EvaluatedInstance,
    EvaluatedResource,
    MetaArguments,
)
from core.terraform_model.security_rules import inline_rules, resource_rule

NORMALIZATION_VERSION: Final = "dail-tf-norm-1"
TOOL_NAME: Final = "dail-terraform-model"
SOURCE_COMPONENT: Final = "core.terraform_model"
TRANSFORMATION_STEPS: Final = ("parse", "validate", "evaluate", "expand", "normalize")

# Doc 04 §1.3 / registry §1.3: the nine supported types. aws_db_subnet_group is tolerated
# (registry §2.7), which is still UNSUPPORTED here (C-114).
SUPPORTED_TYPES: Final = frozenset(
    {
        "aws_vpc",
        "aws_subnet",
        "aws_route_table",
        "aws_route_table_association",
        "aws_internet_gateway",
        "aws_instance",
        "aws_security_group",
        "aws_security_group_rule",
        "aws_db_instance",
    }
)
TOLERATED_TYPES: Final = frozenset({"aws_db_subnet_group"})

# Doc 04 §7: the naming fields of a type ("not alone a stable identity guarantee").
NAMING_FIELDS: Final[Mapping[str, tuple[str, ...]]] = {
    "aws_security_group": ("name", "name_prefix"),
    "aws_db_instance": ("identifier", "identifier_prefix"),
    "aws_db_subnet_group": ("name", "name_prefix"),
}

# The fields of the semantic view, per type (Doc 04 §7); absent fields are omitted (C-113).
SEMANTIC_FIELDS: Final[Mapping[str, tuple[str, ...]]] = {
    "aws_vpc": ("cidr_block",),
    "aws_subnet": ("vpc_id", "cidr_block", "availability_zone"),
    "aws_route_table": ("vpc_id",),
    "aws_route_table_association": ("subnet_id", "route_table_id"),
    "aws_internet_gateway": ("vpc_id",),
    "aws_instance": ("subnet_id", "private_ip"),
    "aws_security_group": ("vpc_id",),
    "aws_db_instance": ("engine", "port", "db_subnet_group_name"),
    "aws_db_subnet_group": ("subnet_ids",),
}

# The fields of the security view that are plain copies of an argument, per type.
SECURITY_FIELDS: Final[Mapping[str, tuple[str, ...]]] = {
    "aws_db_instance": ("publicly_accessible", "vpc_security_group_ids"),
    "aws_instance": ("vpc_security_group_ids", "security_groups", "associate_public_ip_address"),
    "aws_subnet": ("map_public_ip_on_launch",),
}

_MAX_VIEW_DEPTH: Final = MAX_ENCODE_DEPTH


def support_of(resource_type: str) -> ResourceSupport:
    return (
        ResourceSupport.SUPPORTED
        if resource_type in SUPPORTED_TYPES
        else ResourceSupport.UNSUPPORTED
    )


def make_provenance(source: SourceRange, address: str, now: datetime) -> Provenance:
    return Provenance(
        source_kind=ProvenanceSourceKind.TERRAFORM_CONFIG,
        source_component=SOURCE_COMPONENT,
        source_reference=f"{source.file}:{source.start_line}:{address}",
        observed_at=now,
        tool_name=TOOL_NAME,
        tool_version=PARSER_VERSION,
        parser_version=PARSER_VERSION,
        normalization_version=NORMALIZATION_VERSION,
        algorithm_version=EVALUATOR_VERSION,
        transformation_steps=TRANSFORMATION_STEPS,
    )


# --- Views ---------------------------------------------------------------------------------------


def encode_arguments(instance: EvaluatedInstance) -> dict[str, JSON]:
    """The canonical encoding of every argument, sorted by name (``attributes``)."""
    policy = policy_for(instance.type)
    return {
        name: encode_argument(argument, policy)
        for name, argument in sorted(instance.arguments.items())
    }


def view_value(encoded: JSON) -> JSON:
    """What a view holds for an argument: the value of an ATTRIBUTE, else the whole encoding."""
    if isinstance(encoded, dict) and encoded.get("form") == "ATTRIBUTE":
        return encoded["value"]
    return encoded


def copy_fields(attributes: Mapping[str, JSON], names: Iterable[str]) -> dict[str, JSON]:
    """The named arguments that are present, as views (absent ones are omitted)."""
    return {name: view_value(attributes[name]) for name in names if name in attributes}


def key_kind(key: int | str | None) -> str:
    return "none" if key is None else "int" if isinstance(key, int) else "str"


def meta_view(meta: MetaArguments, kind: str) -> dict[str, JSON]:
    """``semantic_attributes.meta``: the meta-arguments that change semantics (C-113). ``kind`` is
    the kind of the instance key: ``none``, ``int``, ``str``, or ``unknown`` (no instances)."""
    view: dict[str, JSON] = {
        "count_present": meta.count is not None,
        "for_each_present": meta.for_each is not None,
        "key_kind": kind,
    }
    if meta.create_before_destroy is not None:
        view["create_before_destroy"] = encode(meta.create_before_destroy)
    if meta.provider is not None:
        view["provider"] = meta.provider
    return view


def security_view(instance: EvaluatedInstance, attributes: Mapping[str, JSON]) -> dict[str, JSON]:
    view: dict[str, JSON] = copy_fields(attributes, SECURITY_FIELDS.get(instance.type, ()))
    if instance.type == "aws_security_group":
        inline = inline_rules(instance)
        view["inline_rules"] = [rule.view_json() for rule in inline.rules]
        view["forms"] = dict(inline.forms)
        view["inline_indeterminate"] = list(inline.indeterminate)
    elif instance.type == "aws_security_group_rule":
        rule = resource_rule(instance)
        view["rule"] = rule.view_json()
        view["target"] = rule.target_security_group
    return view


def semantic_view(instance: EvaluatedInstance, attributes: Mapping[str, JSON]) -> dict[str, JSON]:
    resource_type = instance.type
    view: dict[str, JSON] = copy_fields(attributes, SEMANTIC_FIELDS.get(resource_type, ()))
    arguments = instance.arguments
    if resource_type == "aws_route_table":
        if "route" in attributes:
            view["routes"] = attributes["route"]
        view["propagating_vgws_present"] = "propagating_vgws" in arguments
    if resource_type == "aws_instance":
        view["network_interface_present"] = "network_interface" in arguments
        view["primary_network_interface_present"] = "primary_network_interface" in arguments
    if resource_type in TOLERATED_TYPES:
        view["tolerated"] = True
    view["meta"] = meta_view(instance.meta, key_kind(instance.key))
    return view


def logical_identity(
    instance: EvaluatedInstance, attributes: Mapping[str, JSON]
) -> dict[str, JSON]:
    identity = copy_fields(attributes, NAMING_FIELDS.get(instance.type, ()))
    if instance.key is not None:
        identity["key"] = instance.key
    return identity


# --- Resources -----------------------------------------------------------------------------------


def _check_depth(*fields: Mapping[str, Any]) -> None:
    for field in fields:
        if json_depth(dict(field)) > _MAX_VIEW_DEPTH:
            raise EncodeError("normalized content nested too deeply")


def _require_kind(kind: str, address: str) -> None:
    if kind != "resource":
        raise ValueError(f"{address} is a {kind}: only resources become Resource objects")


def normalize_instance(
    instance: EvaluatedInstance,
    *,
    now: datetime,
    references: Iterable[Reference] = (),
    record_id: str | None = None,
) -> Resource:
    """One ``Resource`` for one resource instance (never for a data source)."""
    _require_kind(instance.kind, instance.address)
    refs = tuple(references)
    provenance = make_provenance(instance.source_range, instance.address, now)
    try:
        attributes = encode_arguments(instance)
        identity = logical_identity(instance, attributes)
        security = security_view(instance, attributes)
        semantic = semantic_view(instance, attributes)
        _check_depth(attributes, identity, security, semantic)
        return Resource.create(
            address=instance.address,
            resource_type=instance.type,
            logical_identity=identity,
            attributes=attributes,
            security_attributes=security,
            semantic_attributes=semantic,
            references=refs,
            provenance=provenance,
            support_status=support_of(instance.type),
            record_id=record_id,
        )
    except (EncodeError, DomainValidationError):
        return _too_deep(instance, refs, provenance, record_id)


def _too_deep(
    instance: EvaluatedInstance,
    references: tuple[Reference, ...],
    provenance: Provenance,
    record_id: str | None,
) -> Resource:
    """A resource whose content is nested deeper than the domain JSON limit: kept, UNSUPPORTED,
    with the reason in place of the content (nothing is silently dropped)."""
    reason: JSON = {"$dail": "unsupported", "reason": "limit.json_depth"}
    return Resource.create(
        address=instance.address,
        resource_type=instance.type,
        logical_identity={} if instance.key is None else {"key": instance.key},
        attributes={"$content": reason},
        security_attributes={},
        semantic_attributes={"meta": meta_view(instance.meta, key_kind(instance.key))},
        references=references,
        provenance=provenance,
        support_status=ResourceSupport.UNSUPPORTED,
        record_id=record_id,
    )


def normalize_indeterminate(
    resource: EvaluatedResource,
    *,
    now: datetime,
    references: Iterable[Reference] = (),
    record_id: str | None = None,
) -> Resource:
    """The placeholder ``Resource`` of a resource that has no instances (C-114): ``UNKNOWN``."""
    _require_kind(resource.kind, resource.address)
    return Resource.create(
        address=resource.address,
        resource_type=resource.type,
        logical_identity={},
        attributes={},
        security_attributes={},
        semantic_attributes={
            "indeterminate": encode(resource.reason),
            "meta": meta_view(resource.meta, "unknown"),
        },
        references=tuple(references),
        provenance=make_provenance(resource.source_range, resource.address, now),
        support_status=ResourceSupport.UNKNOWN,
        record_id=record_id,
    )


__all__ = [
    "NORMALIZATION_VERSION",
    "SUPPORTED_TYPES",
    "TOLERATED_TYPES",
    "normalize_indeterminate",
    "normalize_instance",
    "support_of",
]
