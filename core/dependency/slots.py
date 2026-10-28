"""The relationship slots of Doc 07 §16, and the RDS placement slot of C-136, as data (C-133
item 4).

A slot says: the argument(s) ``arguments`` of a resource of ``source_type`` hold a reference to a
resource of ``target_type``, and the relationship is ``relationship``. The engine reads this table;
there are no per-type branches in code, so adding an argument later is a table change plus a
register row (an argument name is a provider fact; the names are those of C-112).

``status_floor`` is the best status an edge of the slot can have: KNOWN for the section 16
rows (no floor), UNSUPPORTED for the RDS subnet placement of C-136, whose target type
``aws_db_subnet_group`` is not a supported type (Doc 07 §23, the known RDS gap), so every edge
of that slot is UNSUPPORTED whatever the value.

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

from core.domain.enums import DependencyStatus
from core.domain.graph import Relationship


@dataclass(frozen=True)
class Slot:
    source_type: str
    arguments: tuple[str, ...]
    target_type: str
    relationship: Relationship
    status_floor: DependencyStatus = DependencyStatus.KNOWN

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
    # C-136: not a Doc 07 section 16 row; the placement of an RDS instance
    Slot(
        "aws_db_instance",
        ("db_subnet_group_name",),
        "aws_db_subnet_group",
        Relationship.DB_SUBNET_PLACEMENT,
        DependencyStatus.UNSUPPORTED,
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
