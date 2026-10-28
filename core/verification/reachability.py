"""INV-FUNC-001: the application can reach the database on TCP/5432, ``REACH(S, D, 5432)``.

Registry §6 (``dail.verify.reachability_cfg`` version 1; C-151 to C-154). The result is decided by
the first row of the table of §6.4 that applies:

    1  S or D is absent (deleted, with no move)                                   FAIL
    2  a relevant-unsupported type, an M3 route, name-based security groups, no groups or no
       subnet, a MIXED or RETAINED-INLINE group, an interface block, ``propagating_vgws``, an
       unsupported value or rule                                                   UNSUPPORTED
    3  E2 definitely false (the port, or the engine when there is no port)         FAIL
    4  E3 or E4 needs a value that is unresolved, or an endpoint is indeterminate  UNKNOWN
    5  E3 holds and VPC(S) differs from VPC(D)                                     FAIL
    6  E5 and E6 hold with determinate rules                                       PASS
    7  E5 or E6 fails, but an indeterminate rule could satisfy it                  UNKNOWN
    8  E5 or E6 fails, and a CIDR partly covers its target                         UNKNOWN
    9  otherwise                                                                   FAIL

so that a PASS needs every one of E1 to E7 and nothing that is unresolved can make a PASS: row 6
uses determinate rules only. The definitions that make the rows precise (what ``src_sg`` is,
"partly covers", "could satisfy", ``ADDR(S)``, the M3 test) are in C-153, with the registry text
beside each; a case the registry does not decide is UNSUPPORTED and listed there as a spec gap
(R5).

The endpoints are the bindings ``S`` and ``D`` of the definition: addresses of the trusted state,
followed across moves through the identity report (C-152). A PASS is a statement about
configuration prerequisites in this model, not about packets (registry §6.1).

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from core.domain.enums import ChangeType, ResourceSupport, VerificationResult
from core.domain.invariant import Invariant
from core.domain.registry_v1 import FUNC_RELEVANT_UNSUPPORTED
from core.domain.resource import Resource
from core.domain.verification import VerificationReason
from core.verification.cidr import CidrError, Network, covers, overlaps, parse_network
from core.verification.func_view import (
    ABSENT_STATE,
    KNOWN,
    UNKNOWN_STATE,
    UNSUPPORTED_STATE,
    Fact,
    RouteTableView,
    items_of,
    read_database,
    read_group_network,
    read_instance,
    read_route_table,
    read_subnet,
    read_vpc,
)
from core.verification.inputs import VerificationInputs
from core.verification.outcome import PredicateOutcome
from core.verification.ports import may_permit_tcp, permits_tcp
from core.verification.retention import inline_retention
from core.verification.values import Ref, Unknown, Unsupported
from core.verification.views import (
    SECURITY_GROUP_TYPE,
    GroupView,
    Rule,
    SecurityConfig,
    group_is_mixed,
    read_security,
)

PORT: Final = 5432
TOLERATED_TYPE: Final = "aws_db_subnet_group"
ASSUMPTIONS: Final = (
    "IPv4 only",
    "M1: RDS security groups and subnet group share one VPC (C-15, C-77, uncited)",
    "M4: default network ACL assumed (no NACL type present)",
)
TOLERATED_ASSUMPTION: Final = "tolerated type: aws_db_subnet_group (C-15)"

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
R = VerificationReason

# The fixed order of the row 2 causes; the first names the reason (C-153).
_RANK_TYPE, _RANK_ROUTE, _RANK_VGWS, _RANK_INTERFACE, _RANK_NAMES = 0, 1, 2, 3, 4
_RANK_MISSING, _RANK_MIXED, _RANK_RETAINED, _RANK_FORMS, _RANK_VALUE, _RANK_MODEL = (
    5,
    6,
    7,
    8,
    9,
    10,
)


@dataclass(frozen=True, slots=True)
class _Cause:
    rank: int
    code: VerificationReason
    detail: str

    def sort_key(self) -> tuple[int, str, str]:
        return (self.rank, self.code.value, self.detail)


@dataclass(frozen=True, slots=True)
class _Endpoint:
    trusted: str
    state: str  # found | absent | indeterminate
    resource: Resource | None
    candidate: str | None
    match: str


class _Finish(Exception):
    """Raised to stop with a finished outcome (an early row, or an input that is not usable)."""

    def __init__(self, outcome: PredicateOutcome) -> None:
        super().__init__("finished")
        self.outcome = outcome


@dataclass(slots=True)
class _Sides:
    """The groups of one side: configured group addresses, unresolved entries, causes found."""

    groups: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)


def _coerce_port(fact: Fact) -> tuple[str, int | None]:
    """The port as ``("value", n)``, or ``("absent" | "unresolved" | "unsupported", None)``."""
    if fact.state == ABSENT_STATE:
        return "absent", None
    if fact.state == UNKNOWN_STATE:
        return "unresolved", None
    if fact.state == UNSUPPORTED_STATE:
        return "unsupported", None
    value = fact.value
    if isinstance(value, bool):
        return "unsupported", None
    if isinstance(value, int):
        return "value", value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return "value", int(value)
    return "unsupported", None


class _Evaluation:
    def __init__(self, definition: Invariant, inputs: VerificationInputs) -> None:
        self.definition = definition
        self.inputs = inputs
        self.by_address = {r.address: r for r in inputs.candidate_resources}
        self.parent = (
            None
            if inputs.parent_resources is None
            else {r.address: r for r in inputs.parent_resources}
        )
        self.config: SecurityConfig = read_security(inputs.candidate_resources)
        self.causes: list[_Cause] = []
        self.unresolved: list[str] = []  # why row 4 applies
        self.endpoint_reasons: list[str] = []
        self.observations: dict[str, Any] = {
            "row": 0,
            "reason": None,
            "detail": None,
            "unresolved": [],
            "endpoints": {},
            "port": PORT,
            "path": {
                "S": None,
                "subnet": None,
                "vpc_s": None,
                "sg_s": None,
                "egress_rule": None,
                "sg_d": None,
                "ingress_rule": None,
                "vpc_d": None,
            },
            "row2_causes": [],
            "failing_conditions": [],
            "indeterminate_rules": [],
            "partial_coverage": [],
            "relevant_unsupported": [],
        }
        tolerated = any(r.resource_type == TOLERATED_TYPE for r in inputs.candidate_resources)
        self.assumptions = tuple(
            sorted((*ASSUMPTIONS, *((TOLERATED_ASSUMPTION,) if tolerated else ())))
        )

    # --- finishing -------------------------------------------------------------------------------

    def finish(
        self, result: VerificationResult, row: int, reason: VerificationReason | None
    ) -> PredicateOutcome:
        self.observations["row"] = row
        self.observations["reason"] = None if reason is None else reason.value
        self.observations["row2_causes"] = [
            {"cause": c.code.value, "detail": c.detail}
            for c in sorted(self.causes, key=_Cause.sort_key)
        ]
        return PredicateOutcome(result, reason, None, self.observations, self.assumptions)

    def stop(
        self, result: VerificationResult, row: int, reason: VerificationReason, detail: str
    ) -> _Finish:
        self.observations["detail"] = detail
        return _Finish(self.finish(result, row, reason))

    def cause(self, rank: int, code: VerificationReason, detail: str) -> None:
        self.causes.append(_Cause(rank, code, detail))

    # --- parameters and endpoints ----------------------------------------------------------------

    def parameters(self) -> tuple[str, str]:
        parameters = self.definition.predicate.get("parameters")
        if not isinstance(parameters, Mapping):
            raise self.stop(S, 0, R.PARAMETERS_INVALID, "parameters is not an object")
        source, destination, port = parameters.get("S"), parameters.get("D"), parameters.get("port")
        if not isinstance(source, str) or not isinstance(destination, str):
            raise self.stop(S, 0, R.PARAMETERS_INVALID, "S and D must be text")
        if not source.startswith("aws_instance.") or not destination.startswith("aws_db_instance."):
            raise self.stop(
                S, 0, R.PARAMETERS_INVALID, "S must be an aws_instance and D an aws_db_instance"
            )
        if source == destination:
            raise self.stop(S, 0, R.PARAMETERS_INVALID, "S and D must differ")
        if isinstance(port, bool) or port != PORT:
            raise self.stop(S, 0, R.PARAMETERS_INVALID, f"the port must be {PORT}")
        return source, destination

    def resolve(self, binding: str, label: str) -> _Endpoint:
        if self.parent is None:
            resource = self.by_address.get(binding)
            if resource is None:
                return _Endpoint(binding, "absent", None, None, "BASELINE")
            return self._found(binding, resource, "BASELINE")
        if binding not in self.parent:
            raise self.stop(
                S, 0, R.PARAMETERS_INVALID, f"{label} {binding} is not in the trusted state"
            )
        identity = self.inputs.identity
        if identity is None:
            raise self.stop(S, 0, R.IDENTITY_MISSING, "a parent without an identity report")
        match = next(
            (m for m in identity.resource_matches if m.trusted_resource_ref == binding), None
        )
        if match is None:
            raise self.stop(
                S, 0, R.IDENTITY_MISSING, f"the identity report has no match for {binding}"
            )
        kind = match.change_type
        if kind is ChangeType.DELETED:
            return _Endpoint(binding, "absent", None, None, kind.value)
        if kind is ChangeType.UNCERTAIN:
            return _Endpoint(
                binding, "indeterminate", None, match.candidate_resource_ref, kind.value
            )
        resource = self.by_address.get(match.candidate_resource_ref or "")
        if resource is None:
            raise self.stop(
                S, 0, R.IDENTITY_MISSING, f"{binding} is matched to a resource the candidate lacks"
            )
        return self._found(binding, resource, kind.value)

    def _found(self, binding: str, resource: Resource, match: str) -> _Endpoint:
        if resource.support_status is not ResourceSupport.SUPPORTED:
            return _Endpoint(binding, "indeterminate", None, resource.address, match)
        return _Endpoint(binding, "found", resource, resource.address, match)

    # --- the groups, the subnet and the VPCs -----------------------------------------------------

    def groups_of(self, fact: Fact, label: str) -> _Sides:
        side = _Sides()
        for item in items_of(fact):
            if isinstance(item, Ref):
                found = self.by_address.get(item.address)
                if found is None or found.resource_type != SECURITY_GROUP_TYPE:
                    self.cause(
                        _RANK_MODEL,
                        R.MODEL_UNSUPPORTED,
                        f"{label}: {item.address} is not a configured security group",
                    )
                elif found.support_status is ResourceSupport.SUPPORTED:
                    side.groups.append(found.address)
                else:
                    side.unresolved.append(f"{label}: {found.address} is a placeholder")
            elif isinstance(item, Unknown):
                side.unresolved.append(f"{label}: {item.reason}")
            elif isinstance(item, Unsupported):
                self.cause(_RANK_VALUE, R.VALUE_UNSUPPORTED, f"{label}: {item.reason}")
            elif isinstance(item, str):
                self.cause(
                    _RANK_MODEL,
                    R.MODEL_UNSUPPORTED,
                    f"{label}: the group id {item!r} is not a configured group",
                )
            else:
                self.cause(
                    _RANK_VALUE, R.VALUE_UNSUPPORTED, f"{label}: an entry that is not a group"
                )
        side.groups = sorted(set(side.groups))
        return side

    def vpc_of(self, fact: Fact, label: str) -> str | None:
        """The address of the configured VPC that a ``vpc_id`` references, else ``None`` (and the
        cause or the unresolved reason is recorded)."""
        if fact.state == ABSENT_STATE:
            self.cause(
                _RANK_MODEL, R.MODEL_UNSUPPORTED, f"{label}: no vpc_id (default VPC not modelled)"
            )
        elif fact.state == UNKNOWN_STATE:
            self.unresolved.append(f"{label}: vpc_id {fact.reason}")
        elif fact.state == UNSUPPORTED_STATE:
            self.cause(_RANK_VALUE, R.VALUE_UNSUPPORTED, f"{label}: vpc_id {fact.reason}")
        elif isinstance(fact.value, Ref):
            vpc = self.by_address.get(fact.value.address)
            if vpc is None or vpc.resource_type != "aws_vpc":
                self.cause(
                    _RANK_MODEL, R.MODEL_UNSUPPORTED, f"{label}: vpc_id is not a configured aws_vpc"
                )
            elif vpc.support_status is not ResourceSupport.SUPPORTED:
                self.unresolved.append(f"{label}: {vpc.address} is a placeholder")
            else:
                return vpc.address
        else:
            self.cause(
                _RANK_MODEL,
                R.MODEL_UNSUPPORTED,
                f"{label}: vpc_id is a literal id, so the VPC CIDR is unknown",
            )
        return None

    def network_of(self, vpc: str | None, label: str) -> Network | None:
        if vpc is None:
            return None
        fact = read_vpc(self.by_address[vpc]).cidr_block
        return self._cidr(fact, f"{label}: the CIDR of {vpc}")

    def _cidr(self, fact: Fact, label: str) -> Network | None:
        if fact.state == KNOWN and isinstance(fact.value, str):
            try:
                return parse_network(fact.value)
            except CidrError:
                self.cause(_RANK_VALUE, R.VALUE_UNSUPPORTED, f"{label} is not a CIDR")
                return None
        if fact.state == UNKNOWN_STATE:
            self.unresolved.append(f"{label} {fact.reason}")
        elif fact.state == ABSENT_STATE:
            self.cause(_RANK_MODEL, R.MODEL_UNSUPPORTED, f"{label} is not written")
        else:
            self.cause(_RANK_VALUE, R.VALUE_UNSUPPORTED, f"{label} {fact.reason}")
        return None


def evaluate_reachability(definition: Invariant, inputs: VerificationInputs) -> PredicateOutcome:
    """``REACH(S, D, 5432)`` for a candidate (no parent resources means a baseline)."""
    run = _Evaluation(definition, inputs)
    try:
        return _decide(run)
    except _Finish as done:
        return done.outcome


# --- the rows -------------------------------------------------------------------------------------


def _decide(run: _Evaluation) -> PredicateOutcome:
    source, destination = run.parameters()
    endpoints = {"S": run.resolve(source, "S"), "D": run.resolve(destination, "D")}
    run.observations["endpoints"] = {
        label: {"trusted": e.trusted, "candidate": e.candidate, "match": e.match}
        for label, e in endpoints.items()
    }
    run.observations["relevant_unsupported"] = sorted(
        r.address
        for r in run.inputs.candidate_resources
        if r.resource_type in FUNC_RELEVANT_UNSUPPORTED
    )
    # row 1
    gone = [label for label, e in endpoints.items() if e.state == "absent"]
    if gone:
        raise run.stop(F, 1, R.ENDPOINT_ABSENT, f"absent: {', '.join(gone)}")
    # row 2: every cause that can be evaluated, then the reason by the fixed order
    s_end, d_end = endpoints["S"], endpoints["D"]
    for label, endpoint in endpoints.items():
        if endpoint.state == "indeterminate":
            run.endpoint_reasons.append(
                f"{label} is {endpoint.match.lower()}: {endpoint.candidate or endpoint.trusted}"
            )
    model = _Model(run, s_end, d_end)
    model.collect_causes()
    if run.causes:
        first = min(run.causes, key=_Cause.sort_key)
        raise _Finish(run.finish(S, 2, first.code))
    # row 3
    model.check_listener()
    # row 4
    if run.endpoint_reasons or run.unresolved:
        reason = R.RESOURCE_INDETERMINATE if run.endpoint_reasons else R.ATTRIBUTE_UNRESOLVED
        run.observations["unresolved"] = sorted([*run.endpoint_reasons, *run.unresolved])
        raise _Finish(run.finish(U, 4, reason))
    # row 5
    if model.vpc_s != model.vpc_d:
        raise run.stop(
            F, 5, R.VPC_MISMATCH, f"VPC(S) {model.vpc_s} differs from VPC(D) {model.vpc_d}"
        )
    return model.reach()


class _Model:
    """The path from S to D: the facts the rows read, in the order the registry names them."""

    def __init__(self, run: _Evaluation, s_end: _Endpoint, d_end: _Endpoint) -> None:
        self.run = run
        self.s_end, self.d_end = s_end, d_end
        self.instance = read_instance(s_end.resource) if s_end.resource is not None else None
        self.database = read_database(d_end.resource) if d_end.resource is not None else None
        self.sg_s = _Sides()
        self.sg_d = _Sides()
        self.vpc_s: str | None = None
        self.vpc_d: str | None = None
        self.net_d: Network | None = None
        self.addr_s: Network | None = None
        self.subnet: str | None = None
        self.loaded = False

    # --- row 2 -----------------------------------------------------------------------------------

    def collect_causes(self) -> None:
        run = self.run
        types = run.observations["relevant_unsupported"]
        if types:
            run.cause(_RANK_TYPE, R.TYPE_RELEVANT_UNSUPPORTED, ", ".join(types))
        self._load()
        self._groups_and_forms()
        self._routes()

    def _load(self) -> None:
        run, inst, db = self.run, self.instance, self.database
        if inst is not None:
            if inst.interface_blocks:
                run.cause(
                    _RANK_INTERFACE,
                    R.INTERFACE_UNSUPPORTED,
                    f"{inst.address}: {', '.join(inst.interface_blocks)}",
                )
            names = inst.security_groups
            if names.state == KNOWN and not items_of(names):
                pass  # an explicit empty list uses no name-based group
            elif names.state != ABSENT_STATE:
                run.cause(
                    _RANK_NAMES,
                    R.MODEL_UNSUPPORTED,
                    f"{inst.address} uses name-based security_groups",
                )
            self.sg_s = self._side(inst.vpc_security_group_ids, inst.address)
            self._subnet(inst)
        if db is not None:
            self.sg_d = self._side(db.vpc_security_group_ids, db.address)
            self._engine_and_port(db)
        self.loaded = True

    def _side(self, fact: Fact, owner: str) -> _Sides:
        run = self.run
        if fact.state == ABSENT_STATE or (fact.state == KNOWN and not items_of(fact)):
            run.cause(
                _RANK_MISSING,
                R.MODEL_UNSUPPORTED,
                f"{owner} has no vpc_security_group_ids (default group not modelled)",
            )
            return _Sides()
        if fact.state == UNKNOWN_STATE:
            run.unresolved.append(f"{owner}: vpc_security_group_ids {fact.reason}")
            return _Sides()
        side = run.groups_of(fact, f"{owner}.vpc_security_group_ids")
        run.unresolved.extend(side.unresolved)  # E3: every entry must be resolved (C-156)
        return side

    def _subnet(self, inst: Any) -> None:
        run = self.run
        fact = inst.subnet_id
        if fact.state == ABSENT_STATE:
            run.cause(
                _RANK_MISSING,
                R.MODEL_UNSUPPORTED,
                f"{inst.address} has no subnet_id (default VPC not modelled)",
            )
        elif fact.state == UNKNOWN_STATE:
            run.unresolved.append(f"{inst.address}: subnet_id {fact.reason}")
        elif fact.state == UNSUPPORTED_STATE:
            run.cause(_RANK_VALUE, R.VALUE_UNSUPPORTED, f"{inst.address}: subnet_id {fact.reason}")
        elif isinstance(fact.value, Ref):
            found = run.by_address.get(fact.value.address)
            if found is None or found.resource_type != "aws_subnet":
                run.cause(
                    _RANK_MODEL,
                    R.MODEL_UNSUPPORTED,
                    f"{inst.address}: subnet_id is not a configured aws_subnet",
                )
            elif found.support_status is not ResourceSupport.SUPPORTED:
                run.unresolved.append(f"{inst.address}: {found.address} is a placeholder")
            else:
                self.subnet = found.address
                view = read_subnet(found)
                self.vpc_s = run.vpc_of(view.vpc_id, found.address)
        else:
            run.cause(
                _RANK_MODEL,
                R.MODEL_UNSUPPORTED,
                f"{inst.address}: subnet_id is a literal id, not a configured subnet",
            )

    def _engine_and_port(self, db: Any) -> None:
        run = self.run
        kind, _ = _coerce_port(db.port)
        engine = db.engine
        if kind == "unsupported":
            run.cause(_RANK_VALUE, R.VALUE_UNSUPPORTED, f"{db.address}: port")
        if engine.state == UNSUPPORTED_STATE or (
            engine.state == KNOWN and not isinstance(engine.value, str)
        ):
            run.cause(_RANK_VALUE, R.VALUE_UNSUPPORTED, f"{db.address}: engine")
        if kind == "absent" and engine.state == ABSENT_STATE:
            run.cause(
                _RANK_MODEL,
                R.MODEL_UNSUPPORTED,
                f"{db.address} has neither port nor engine (registry gap)",
            )

    def _groups_and_forms(self) -> None:
        run = self.run
        groups = run.config.groups
        parent, identity = run.parent, run.inputs.identity
        for label, side, direction in (("S", self.sg_s, "egress"), ("D", self.sg_d, "ingress")):
            for address in side.groups:
                view = groups.get(address)
                if view is None:
                    continue
                if group_is_mixed(view):
                    run.cause(_RANK_MIXED, R.GROUP_MIXED, f"{address} (SG({label}))")
                forms = view.forms
                if forms is not None and forms[direction] == "unresolved":
                    run.cause(
                        _RANK_FORMS, R.FORMS_UNRESOLVED, f"{address}: {direction} of SG({label})"
                    )
                if forms is not None and forms[direction] == "absent":
                    retention = inline_retention(
                        address, direction, parent=parent, identity=identity
                    )
                    if retention is R.GROUP_RETAINED_INLINE:
                        run.cause(
                            _RANK_RETAINED,
                            R.GROUP_RETAINED_INLINE,
                            f"{address}: {direction} of SG({label})",
                        )
                    elif retention is R.IDENTITY_MISSING:
                        run.cause(
                            _RANK_RETAINED,
                            R.IDENTITY_MISSING,
                            f"{address}: {direction} of SG({label})",
                        )
                for rule in _side_rules(view, direction):
                    if rule.unsupported:
                        run.cause(
                            _RANK_VALUE,
                            R.RULE_UNSUPPORTED,
                            f"{rule.source_address} ({rule.target})",
                        )
        for address, view in groups.items():
            if address.startswith("UNRESOLVED:"):
                for rule in (*view.ingress, *view.egress, *view.unresolved_direction):
                    if rule.unsupported:
                        run.cause(
                            _RANK_VALUE, R.RULE_UNSUPPORTED, f"{rule.source_address} ({address})"
                        )

    def _routes(self) -> None:
        run = self.run
        if self.d_end.resource is None:
            return
        groups_vpcs = []
        for address in self.sg_d.groups:
            fact = read_group_network(run.by_address[address]).vpc_id
            groups_vpcs.append(run.vpc_of(fact, f"SG(D) {address}"))
        known = sorted({v for v in groups_vpcs if v is not None})
        if len(known) > 1:
            run.cause(
                _RANK_MODEL,
                R.MODEL_UNSUPPORTED,
                f"the groups of D are in different VPCs: {', '.join(known)} (M1)",
            )
        elif len(known) == 1 and None not in groups_vpcs:
            self.vpc_d = known[0]
            self.net_d = run.network_of(self.vpc_d, "VPC(D)")
        if self.net_d is None:
            return  # the VPC of D is not known, so the routes of M3 cannot be judged here
        for resource in run.inputs.candidate_resources:
            if resource.resource_type == "aws_route_table":
                self._table(resource)

    def _table(self, resource: Resource) -> None:
        run = self.run
        if resource.support_status is not ResourceSupport.SUPPORTED:
            run.cause(
                _RANK_ROUTE,
                R.ROUTE_UNSUPPORTED,
                f"{resource.address} is a placeholder, it may be a route table of VPC(D)",
            )
            return
        table = read_route_table(resource)
        ours = self._ours(table)
        if ours == "no":
            return
        where = "" if ours == "yes" else " (its vpc_id is unresolved, it may be VPC(D)'s)"
        if table.propagating_vgws_present:
            run.cause(
                _RANK_VGWS, R.ROUTE_UNSUPPORTED, f"{table.address} sets propagating_vgws{where}"
            )
        if table.routes_unresolved is not None:
            run.cause(
                _RANK_ROUTE,
                R.ROUTE_UNSUPPORTED,
                f"{table.address}: its routes cannot be fixed ({table.routes_unresolved}){where}",
            )
        assert self.net_d is not None
        for route in table.routes:
            if route.state == "ipv6_only":
                continue
            if route.state in ("unresolved", "unsupported"):
                run.cause(
                    _RANK_ROUTE,
                    R.ROUTE_UNSUPPORTED,
                    f"{table.address}: a route whose destination is {route.state}{where}",
                )
                continue
            assert route.destination is not None
            inside = (
                route.destination.first >= self.net_d.first
                and route.destination.last <= self.net_d.last
            )
            if inside and route.target != "local":
                text = _network_text(route.destination)
                run.cause(
                    _RANK_ROUTE,
                    R.ROUTE_UNSUPPORTED,
                    f"{table.address}: {text} is inside the VPC CIDR, target {route.target}{where}",
                )

    def _ours(self, table: RouteTableView) -> str:
        fact = table.vpc_id
        if fact.state == KNOWN:
            return (
                "yes" if isinstance(fact.value, Ref) and fact.value.address == self.vpc_d else "no"
            )
        if fact.state == ABSENT_STATE:
            return "no"
        return "maybe"  # unresolved or unsupported: it may be the VPC of D

    # --- row 3 -----------------------------------------------------------------------------------

    def check_listener(self) -> None:
        db = self.database
        if db is None:
            return
        run = self.run
        kind, port = _coerce_port(db.port)
        if kind == "value":
            if port != PORT:
                raise run.stop(F, 3, R.PORT_MISMATCH, f"{db.address}.port is {port}")
            return
        if kind == "unresolved":
            run.unresolved.append(f"{db.address}: port {db.port.reason}")
            return
        engine = db.engine
        if engine.state == UNKNOWN_STATE:
            run.unresolved.append(f"{db.address}: engine {engine.reason}")
        elif engine.state == KNOWN and engine.value != "postgres":  # E2: the exact string
            raise run.stop(F, 3, R.PORT_MISMATCH, f"{db.address}.engine is {engine.value}")

    # --- rows 6 to 9 -----------------------------------------------------------------------------

    def reach(self) -> PredicateOutcome:
        run, inst, config = self.run, self.instance, self.run.config
        assert inst is not None and self.net_d is not None
        self._source_address(inst)
        if run.causes:  # a private_ip or a subnet CIDR that is not an address or a CIDR
            raise _Finish(run.finish(S, 2, min(run.causes, key=_Cause.sort_key).code))
        sg_s, sg_d = set(self.sg_s.groups), set(self.sg_d.groups)
        target_d = _network_text(self.net_d)
        target_s = None if self.addr_s is None else _network_text(self.addr_s)
        out_rules = [(g, r) for g in sorted(sg_s) for r in config.groups[g].egress]
        in_rules = [(h, r) for h in sorted(sg_d) for r in config.groups[h].ingress]
        # E5 and E6 are stated per rule: v4(r) is the CIDR list of one rule, so coverage is not
        # pooled across rules
        e5 = _first(
            out_rules,
            lambda _g, r: bool(set(r.source_security_groups) & sg_d)
            or covers(r.ipv4_sources, target_d),
        )
        e6 = _first(
            in_rules,
            lambda h, r: bool(set(r.source_security_groups) & sg_s)
            or (r.self_reference and h in sg_s)
            or (target_s is not None and covers(r.ipv4_sources, target_s)),
        )
        run.observations["path"].update(
            {
                "S": self.s_end.candidate,
                "subnet": self.subnet,
                "vpc_s": self.vpc_s,
                "sg_s": sorted(sg_s),
                "egress_rule": e5,
                "sg_d": sorted(sg_d),
                "ingress_rule": e6,
                "vpc_d": self.vpc_d,
            }
        )
        if e5 is not None and e6 is not None:
            return run.finish(P, 6, None)
        failing = [name for name, found in (("E5", e5), ("E6", e6)) if found is None]
        run.observations["failing_conditions"] = failing
        sides = (sg_s, sg_d)
        possible = self._possible(failing, sides, out_rules, in_rules, target_d, target_s)
        if possible:
            run.observations["indeterminate_rules"] = possible
            only_groups = all(item["rule"] == "vpc_security_group_ids" for item in possible)
            reason = R.ATTRIBUTE_UNRESOLVED if only_groups else R.RULE_INDETERMINATE
            return run.finish(U, 7, reason)
        partial = _partial(failing, out_rules, in_rules, target_d, target_s)
        if partial:
            run.observations["partial_coverage"] = partial
            return run.finish(U, 8, R.COVERAGE_PARTIAL)
        return run.finish(F, 9, R.PATH_MISSING)

    def _source_address(self, inst: Any) -> None:
        """ADDR(S): ``private_ip/32`` if it resolves, else the CIDR of the subnet of S (§6.3)."""
        run = self.run
        fact = inst.private_ip
        if fact.state == KNOWN:
            try:
                if not isinstance(fact.value, str):
                    raise ValueError("not text")
                self.addr_s = parse_network(f"{ipaddress.IPv4Address(fact.value)}/32")
            except ValueError:  # not text, not an address (CidrError is a ValueError too)
                run.cause(
                    _RANK_VALUE,
                    R.VALUE_UNSUPPORTED,
                    f"{inst.address}: private_ip is not an IPv4 address",
                )
            return
        if fact.state == UNSUPPORTED_STATE:
            run.cause(_RANK_VALUE, R.VALUE_UNSUPPORTED, f"{inst.address}: private_ip {fact.reason}")
            return
        assert self.subnet is not None
        cidr = read_subnet(run.by_address[self.subnet]).cidr_block
        if cidr.state == KNOWN and isinstance(cidr.value, str):
            try:
                self.addr_s = parse_network(cidr.value)
            except CidrError:
                run.cause(
                    _RANK_VALUE, R.VALUE_UNSUPPORTED, f"{self.subnet}: cidr_block is not a CIDR"
                )
        elif cidr.state == ABSENT_STATE:
            run.cause(_RANK_MODEL, R.MODEL_UNSUPPORTED, f"{self.subnet}: cidr_block is not written")
        elif cidr.state == UNSUPPORTED_STATE:
            run.cause(_RANK_VALUE, R.VALUE_UNSUPPORTED, f"{self.subnet}: cidr_block {cidr.reason}")
        # unresolved: ADDR(S) stays unknown, so E6 cannot be judged by a CIDR (see _possible)

    def _possible(
        self,
        failing: list[str],
        sides: tuple[set[str], set[str]],
        out_rules: list[tuple[str, Rule]],
        in_rules: list[tuple[str, Rule]],
        target_d: str,
        target_s: str | None,
    ) -> list[dict[str, Any]]:
        """What could still supply the missing permission (row 7)."""
        config = self.run.config
        sg_s, sg_d = sides
        found: list[dict[str, Any]] = []
        for condition in failing:
            wanted = "EGRESS" if condition == "E5" else "INGRESS"
            own = sg_s if condition == "E5" else sg_d
            side = out_rules if condition == "E5" else in_rules
            candidates: list[tuple[str | None, Rule]] = [
                (g, r) for g, r in side if not r.determinate and not r.unsupported
            ]
            for member in sorted(own):  # a rule with no direction counts for every direction
                candidates += [
                    (member, r)
                    for r in config.groups[member].unresolved_direction
                    if not r.unsupported
                ]
            for address, view in sorted(config.groups.items()):  # an unresolved target may be ours
                if address.startswith("UNRESOLVED:"):
                    every = (*view.ingress, *view.egress, *view.unresolved_direction)
                    candidates += [
                        (None, r)
                        for r in every
                        if r.direction in (wanted, None) and not r.unsupported
                    ]
            for group, rule in candidates:
                if may_permit_tcp(
                    rule.protocol, rule.from_port, rule.to_port, PORT
                ) and _could_match(condition, group, rule, sg_s, sg_d, target_d, target_s):
                    found.append(_entry(condition, rule))
            found += [
                _entry(condition, None)
                for address in config.unknown_resources
                if address.startswith("aws_security_group_rule.")
            ]
            if (
                condition == "E6" and target_s is None
            ):  # ADDR(S) is not known: a CIDR cannot be judged
                found += [
                    _entry(condition, r, "ADDR(S) is not known")
                    for _, r in in_rules
                    if r.determinate
                    and permits_tcp(r.protocol, r.from_port, r.to_port, PORT)
                    and r.ipv4_sources
                ]
            if self.sg_s.unresolved:
                found.append(
                    {
                        "condition": condition,
                        "rule": "vpc_security_group_ids",
                        "reasons": sorted(self.sg_s.unresolved),
                    }
                )
        unique = {(i["condition"], i["rule"], tuple(i["reasons"])): i for i in found}
        return [unique[key] for key in sorted(unique)]


# --- helpers --------------------------------------------------------------------------------------


def _first(pairs: list[tuple[str, Rule]], holds: Callable[[str, Rule], bool]) -> str | None:
    """The first determinate rule of the side that permits TCP/5432 and satisfies ``holds``."""
    for group, rule in pairs:
        permitted = rule.determinate and permits_tcp(
            rule.protocol, rule.from_port, rule.to_port, PORT
        )
        if permitted and holds(group, rule):
            return rule.source_address
    return None


def _could_match(
    condition: str,
    group: str | None,
    rule: Rule,
    sg_s: set[str],
    sg_d: set[str],
    target_d: str,
    target_s: str | None,
) -> bool:
    """Whether an indeterminate rule (that could permit TCP/5432) could be the one E5 or E6 needs:
    its satisfying side is unresolved, or resolved and matching, or only partly matching. A
    resolved satisfying side beside an unresolved port or protocol counts (C-153)."""
    if rule.sources_unresolved or rule.prefix_list_ids or rule.ipv4_unresolved:
        return True
    if condition == "E5":
        return bool(set(rule.source_security_groups) & sg_d) or overlaps(
            rule.ipv4_sources, target_d
        )
    if rule.self_unresolved or (rule.self_reference and (group is None or group in sg_s)):
        return True
    if set(rule.source_security_groups) & sg_s:
        return True
    return target_s is None or overlaps(rule.ipv4_sources, target_s)


def _partial(
    failing: list[str],
    out_rules: list[tuple[str, Rule]],
    in_rules: list[tuple[str, Rule]],
    target_d: str,
    target_s: str | None,
) -> list[dict[str, Any]]:
    """Row 8: a CIDR of a rule that permits TCP/5432 overlaps the target without covering it."""
    found = []
    for condition in failing:
        pairs, target = (out_rules, target_d) if condition == "E5" else (in_rules, target_s)
        if target is None:
            continue
        for _, rule in pairs:
            if (
                rule.determinate
                and permits_tcp(rule.protocol, rule.from_port, rule.to_port, PORT)
                and overlaps(rule.ipv4_sources, target)
            ):
                found.append(
                    {"condition": condition, "rule": rule.source_address, "target": target}
                )
    return sorted(found, key=lambda item: (item["condition"], item["rule"]))


def _side_rules(view: GroupView, direction: str) -> tuple[Rule, ...]:
    """The rules a side reads: the egress rules of SG(S) or the ingress rules of SG(D), and the
    rules with no direction, which count for both."""
    return (view.egress if direction == "egress" else view.ingress) + view.unresolved_direction


def _network_text(network: Network) -> str:
    cls = ipaddress.IPv4Network if network.version == 4 else ipaddress.IPv6Network
    size = network.last - network.first + 1
    prefix = (32 if network.version == 4 else 128) - (size.bit_length() - 1)
    return str(cls((network.first, prefix)))


def _entry(condition: str, rule: Rule | None, note: str | None = None) -> dict[str, Any]:
    if rule is None:
        return {
            "condition": condition,
            "rule": "placeholder",
            "reasons": ["rule resource with an unknown count"],
        }
    reasons = [*rule.problems, *([note] if note else [])]
    return {"condition": condition, "rule": rule.source_address, "reasons": reasons}
