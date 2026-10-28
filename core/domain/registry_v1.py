"""The four registry-v1.0 invariants as data (Doc 08 §7-§8, §13; registry §2.7, §3.5, §5.4, §6.6,
§10; C-139; P4 step 2).

``registry_v1_invariants`` builds INV-SEC-001, INV-SEC-002, INV-SEC-003 and INV-FUNC-001, all at
version 1, as ``Invariant`` definitions. Nothing here evaluates a predicate: ``predicate`` is a
pointer into the registry (``registry``, ``section``, ``parameters``), and P5 owns evaluation and
may extend it only with a new version.

The scope of each definition is the declared footprint the impact walk realises:

- INV-SEC-001 and INV-SEC-002: every security group and rule, plus the relevant-unsupported types
  of §2.7. Nothing is followed (§3.5: instance and database attachments are not in the footprint).
- INV-SEC-003: the database type.
- INV-FUNC-001: the endpoints ``S`` and ``D`` (the bindings), the 26 relevant-unsupported types of
  §2.7, and the **walk policy** in ``relationships``: the relationship classes, each with a
  direction, that lead from the endpoints to the rest of the §6.6 footprint. FORWARD follows an
  edge from its source to its target, REVERSE from its target to its source. Route-table
  associations and the internet gateway are not in the policy (§6.6 "Not in the footprint"), and
  neither is the RDS subnet placement (C-15).

The lists below are copied from the registry text once; ``tests/unit/test_registry_v1.py`` types
them again by hand and also reads the specification file.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from core.domain.enums import InvariantCategory
from core.domain.errors import DomainValidationError
from core.domain.invariant import Invariant, InvariantScope
from core.domain.jsonvalue import require_text

REGISTRY_TAG: Final = "registry-v1.0"

# Registry §2.7, "Relevant-unsupported types (presence anywhere in the configuration)".
SEC_RELEVANT_UNSUPPORTED: Final = (
    "aws_vpc_security_group_ingress_rule",
    "aws_default_security_group",
    "aws_vpc_security_group_rules_exclusive",
)
FUNC_RELEVANT_UNSUPPORTED: Final = (
    "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule",
    "aws_default_security_group",
    "aws_network_interface",
    "aws_network_interface_attachment",
    "aws_network_interface_sg_attachment",
    "aws_network_acl",
    "aws_network_acl_rule",
    "aws_network_acl_association",
    "aws_default_network_acl",
    "aws_route",
    "aws_default_route_table",
    "aws_main_route_table_association",
    "aws_vpc_ipv4_cidr_block_association",
    "aws_vpc_peering_connection",
    "aws_ec2_transit_gateway_vpc_attachment",
    "aws_vpc_endpoint",
    "aws_vpc_security_group_rules_exclusive",
    "aws_vpc_security_group_vpc_association",
    "aws_vpn_gateway_route_propagation",
    "aws_vpc_route_server_propagation",
    "aws_default_subnet",
    "aws_default_vpc",
    "aws_vpc_peering_connection_accepter",
    "aws_vpc_peering_connection_options",
    "aws_ec2_transit_gateway_vpc_attachment_accepter",
)

# The walk policy of INV-FUNC-001 (C-139): <RELATIONSHIP>:<direction> or
# REFERENCE[<source_type>.<argument>]:<direction>.
FUNC_WALK_POLICY: Final = (
    "INSTANCE_IN_SUBNET:FORWARD",
    "SUBNET_BELONGS_TO_VPC:FORWARD",
    "INSTANCE_USES_SECURITY_GROUP:FORWARD",
    "DB_USES_SECURITY_GROUP:FORWARD",
    "REFERENCE[aws_security_group.vpc_id]:FORWARD",
    "RULE_BELONGS_TO_SECURITY_GROUP:REVERSE",
    "ROUTE_TABLE_BELONGS_TO_VPC:REVERSE",
)

# Registry §3.5: the footprint names of the two public-ingress invariants.
_SEC_PROPERTIES: Final = (
    "egress.presence",
    "forms",
    "ingress.cidr_blocks",
    "ingress.from_port",
    "ingress.ipv6_cidr_blocks",
    "ingress.prefix_list_ids",
    "ingress.protocol",
    "ingress.security_groups",
    "ingress.self",
    "ingress.to_port",
    "relevant_unsupported.presence",
    "rule.cidr_blocks",
    "rule.existence",
    "rule.from_port",
    "rule.ipv6_cidr_blocks",
    "rule.prefix_list_ids",
    "rule.protocol",
    "rule.security_group_id",
    "rule.self",
    "rule.source_security_group_id",
    "rule.to_port",
    "rule.type",
    "security_group.existence",
)
# Registry §5.4.
_SEC_003_PROPERTIES: Final = ("aws_db_instance.existence", "aws_db_instance.publicly_accessible")
# Registry §6.6.
_FUNC_PROPERTIES: Final = (
    "D.engine",
    "D.existence",
    "D.port",
    "D.vpc_security_group_ids",
    "S.existence",
    "S.network_interface",
    "S.primary_network_interface",
    "S.private_ip",
    "S.security_groups",
    "S.subnet_id",
    "S.vpc_security_group_ids",
    "moves.naming_S_or_D",
    "relevant_unsupported.presence",
    "route_table.propagating_vgws",
    "route_table.routes_inside_vpc",
    "security_group.egress_of_SG(S)",
    "security_group.existence",
    "security_group.forms",
    "security_group.ingress_of_SG(D)",
    "security_group.vpc_id",
    "security_group_rule.fields",
    "subnet.cidr_block",
    "subnet.existence",
    "subnet.vpc_id",
    "vpc.cidr_block",
    "vpc.existence",
)

# The longest chain of the walk from a seed: S to its subnet to the VPC to a route table.
_FUNC_DEPTH: Final = 3


def _check_binding(value: object, name: str) -> str:
    return require_text(value, f"registry_v1_invariants.{name}")


def registry_v1_invariants(
    now: datetime, *, source: str, destination: str
) -> tuple[Invariant, ...]:
    """The four ``registry-v1.0`` invariant definitions, sorted by id.

    ``source`` and ``destination`` are the bindings ``S`` and ``D`` of INV-FUNC-001 (full instance
    addresses). ``now`` is only ``created_at``; it is not part of ``definition_hash``.
    """
    s = _check_binding(source, "source")
    d = _check_binding(destination, "destination")
    if s == d:
        raise DomainValidationError(
            "registry_v1_invariants: source and destination must be different addresses"
        )
    public_ingress = {
        "verifier_id": "dail.verify.public_ingress",
        "verifier_version": "1",
    }

    def security(
        invariant_id: str, name: str, description: str, section: str, port: int
    ) -> Invariant:
        return Invariant(
            invariant_id=invariant_id,
            version=1,
            name=name,
            category=InvariantCategory.SECURITY,
            description=description,
            predicate={
                "registry": REGISTRY_TAG,
                "section": section,
                "parameters": {"p": port},
            },
            scope=InvariantScope(
                resources=(),
                resource_types=("aws_security_group", "aws_security_group_rule")
                + SEC_RELEVANT_UNSUPPORTED,
                relationships=(),
                properties=_SEC_PROPERTIES,
                dependency_depth=0,
            ),
            created_at=now,
            **public_ingress,
        )

    sec_001 = security(
        "INV-SEC-001",
        "No public SSH ingress",
        "No security group in the configuration admits TCP port 22 from the entire IPv4 "
        "internet, or from the entire IPv6 internet (registry-v1.0 §3).",
        "§3",
        22,
    )
    sec_002 = security(
        "INV-SEC-002",
        "No public PostgreSQL ingress",
        "No security group in the configuration admits TCP port 5432 from the entire IPv4 "
        "internet, or from the entire IPv6 internet (registry-v1.0 §4).",
        "§4",
        5432,
    )
    sec_003 = Invariant(
        invariant_id="INV-SEC-003",
        version=1,
        name="RDS not publicly accessible",
        category=InvariantCategory.SECURITY,
        description=(
            "For every configured aws_db_instance instance, publicly_accessible is false "
            "(registry-v1.0 §5)."
        ),
        predicate={"registry": REGISTRY_TAG, "section": "§5", "parameters": {}},
        scope=InvariantScope(
            resources=(),
            resource_types=("aws_db_instance",),
            relationships=(),
            properties=_SEC_003_PROPERTIES,
            dependency_depth=0,
        ),
        verifier_id="dail.verify.rds_public_flag",
        verifier_version="1",
        created_at=now,
    )
    func_001 = Invariant(
        invariant_id="INV-FUNC-001",
        version=1,
        name="Application can reach database on TCP/5432",
        category=InvariantCategory.FUNCTIONAL,
        description=(
            "The source S can reach the destination D on TCP/5432 at configuration level "
            "(registry-v1.0 §6)."
        ),
        predicate={
            "registry": REGISTRY_TAG,
            "section": "§6",
            "parameters": {"S": s, "D": d, "port": 5432},
        },
        scope=InvariantScope(
            resources=(s, d),
            resource_types=FUNC_RELEVANT_UNSUPPORTED,
            relationships=FUNC_WALK_POLICY,
            properties=_FUNC_PROPERTIES,
            dependency_depth=_FUNC_DEPTH,
        ),
        verifier_id="dail.verify.reachability_cfg",
        verifier_version="1",
        created_at=now,
    )
    return tuple(sorted((sec_001, sec_002, sec_003, func_001), key=lambda i: i.invariant_id))
