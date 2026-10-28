"""The relationship slots of Doc 07 §16 as data (C-133 item 4).

A slot says: the argument(s) ``arguments`` of a resource of ``source_type`` hold a reference to a
resource of ``target_type``, and the relationship is ``relationship``. The engine reads this table;
there are no per-type branches in code, so adding an argument later is a table change plus a
register row (an argument name is a provider fact; the names are those of C-112).

A slot may name several arguments (the instance's two security-group arguments are alternatives).
It is one slot: when none of its arguments yields an element the slot is **unset** (S4), once.

``REFERENCE_ARGUMENTS`` are arguments that hold a reference but have no Doc 07 §16 type
(``aws_security_group_rule.source_security_group_id``, the rule's source group): a ``Ref`` is only
a TERRAFORM_REFERENCE edge, an unresolved value or a literal adds an uncertainty edge, and an
absent argument adds nothing (C-133 item 5).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from core.domain.graph import Relationship


@dataclass(frozen=True)
class Slot:
    source_type: str
    arguments: tuple[str, ...]
    target_type: str
    relationship: Relationship

    @property
    def label(self) -> str:
        """The name used in the unresolved node of a slot with nothing in it."""
        return "+".join(self.arguments)


SLOTS: Final[tuple[Slot, ...]] = (
    Slot("aws_subnet", ("vpc_id",), "aws_vpc", Relationship.SUBNET_BELONGS_TO_VPC),
    Slot("aws_route_table", ("vpc_id",), "aws_vpc", Relationship.ROUTE_TABLE_BELONGS_TO_VPC),
    Slot(
        "aws_route_table_association",
        ("subnet_id",),
        "aws_subnet",
        Relationship.ASSOCIATES_SUBNET,
    ),
    Slot(
        "aws_route_table_association",
        ("route_table_id",),
        "aws_route_table",
        Relationship.ASSOCIATES_ROUTE_TABLE,
    ),
    Slot("aws_internet_gateway", ("vpc_id",), "aws_vpc", Relationship.IGW_ATTACHED_TO_VPC),
    Slot("aws_instance", ("subnet_id",), "aws_subnet", Relationship.INSTANCE_IN_SUBNET),
    Slot(
        "aws_instance",
        ("vpc_security_group_ids", "security_groups"),
        "aws_security_group",
        Relationship.INSTANCE_USES_SECURITY_GROUP,
    ),
    Slot(
        "aws_db_instance",
        ("vpc_security_group_ids",),
        "aws_security_group",
        Relationship.DB_USES_SECURITY_GROUP,
    ),
    Slot(
        "aws_security_group_rule",
        ("security_group_id",),
        "aws_security_group",
        Relationship.RULE_BELONGS_TO_SECURITY_GROUP,
    ),
)


@dataclass(frozen=True)
class ReferenceArgument:
    source_type: str
    argument: str


REFERENCE_ARGUMENTS: Final[tuple[ReferenceArgument, ...]] = (
    ReferenceArgument("aws_security_group_rule", "source_security_group_id"),
)


def slots_for(resource_type: str) -> tuple[Slot, ...]:
    return tuple(slot for slot in SLOTS if slot.source_type == resource_type)


def reference_arguments_for(resource_type: str) -> tuple[ReferenceArgument, ...]:
    return tuple(item for item in REFERENCE_ARGUMENTS if item.source_type == resource_type)
