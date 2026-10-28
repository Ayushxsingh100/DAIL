"""Hand-built impact objects for the impact tests (P4). Not a test module.

Everything is deterministic: ids come from ``tests.domain_builders.uid`` and timestamps from ``at``.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from core.dependency.build import build_graph
from core.dependency.invariants import SemanticBinding
from core.domain.enums import ChangeType, DependencyStatus, ImpactStatus
from core.domain.evidence import EvidenceValidity
from core.domain.graph import DependencyGraph, Relationship
from core.domain.impact import (
    ChangedResource,
    ImpactedInvariant,
    ImpactPath,
    ImpactReason,
    ImpactReport,
    ImpactStep,
    ImpactType,
    ReasonCode,
    StepDirection,
    UnaffectedInvariant,
    UncertaintyRecord,
    VerificationWorkItem,
    WorkPriority,
    WorkTargetType,
)
from core.domain.invariant import Invariant
from core.domain.registry_v1 import registry_v1_invariants
from core.domain.resource import Resource
from core.identity.engine import compare
from core.impact.engine import compute_impact
from core.impact.inputs import PriorProof
from tests.domain_builders import at, uid
from tests.identity_builders import normalize

NOW = at(0)
PARENT = uid(101)
CANDIDATE = uid(102)
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def changed(
    address: str,
    change: ChangeType = ChangeType.MODIFIED,
    *,
    resource_type: str | None = None,
    trusted_ref: str | None | bool = True,
    candidate_ref: str | None | bool = True,
) -> ChangedResource:
    """A changed resource; refs default to the address, ``None`` or ``False`` means no ref."""
    trusted = address if trusted_ref is True else (trusted_ref or None)
    candidate = address if candidate_ref is True else (candidate_ref or None)
    if change is ChangeType.CREATED:
        trusted = None
    if change is ChangeType.DELETED:
        candidate = None
    return ChangedResource(
        address=address if candidate is None or candidate == address else candidate,
        trusted_ref=trusted,
        candidate_ref=candidate,
        resource_type=resource_type or address.split(".")[0],
        change_type=change,
        flags=(),
    )


def step(
    edge_key: str = HASH_A,
    from_node: str = "RESOURCE:a.x",
    to_node: str = "RESOURCE:a.y",
    relationship: Relationship = Relationship.RULE_BELONGS_TO_SECURITY_GROUP,
    direction: StepDirection = StepDirection.FORWARD,
    status: DependencyStatus = DependencyStatus.KNOWN,
) -> ImpactStep:
    return ImpactStep(edge_key, from_node, to_node, relationship, direction, status)


def reason(
    code: ReasonCode = ReasonCode.SCOPE_TYPE_CHANGED,
    ref: str | None = "aws_security_group.app",
    element: str = "resource_types:aws_security_group",
    detail: str = "modified",
) -> ImpactReason:
    return ImpactReason(code, ref, element, detail)


def affected_invariant(
    invariant_id: str = "INV-SEC-001",
    version: int = 1,
    *,
    refs: Iterable[str] = ("aws_security_group.app",),
    reasons: Iterable[ImpactReason] | None = None,
    types: Iterable[ImpactType] = (ImpactType.DIRECT,),
    paths: Iterable[ImpactPath] = (),
    evidence: Iterable[str] = (),
) -> ImpactedInvariant:
    return ImpactedInvariant(
        invariant_id=invariant_id,
        invariant_version=version,
        status=ImpactStatus.AFFECTED,
        impact_types=tuple(sorted(types)),
        changed_resource_refs=tuple(sorted(refs)),
        dependency_paths=tuple(paths),
        reasons=tuple(
            sorted(reasons if reasons is not None else [reason()], key=ImpactReason.sort_key)
        ),
        prior_evidence_ids=tuple(sorted(evidence)),
        evidence_validity=EvidenceValidity.INVALID,
    )


def uncertain_invariant(
    invariant_id: str = "INV-FUNC-001",
    version: int = 1,
    *,
    ref: str = "aws_security_group.ops",
    evidence: Iterable[str] = (),
) -> ImpactedInvariant:
    return ImpactedInvariant(
        invariant_id=invariant_id,
        invariant_version=version,
        status=ImpactStatus.UNCERTAIN,
        impact_types=(ImpactType.IDENTITY,),
        changed_resource_refs=(ref,),
        dependency_paths=(),
        reasons=(
            reason(
                ReasonCode.IDENTITY_UNCERTAIN, ref, "walk:RULE_BELONGS_TO_SECURITY_GROUP:REVERSE"
            ),
        ),
        prior_evidence_ids=tuple(sorted(evidence)),
        evidence_validity=EvidenceValidity.UNCERTAIN,
    )


def work_for(
    invariant: ImpactedInvariant, *, scope: Iterable[str] = ("aws_security_group.app",)
) -> VerificationWorkItem:
    return VerificationWorkItem(
        target_id=f"INVARIANT:{invariant.invariant_id}:{invariant.invariant_version}",
        target_type=WorkTargetType.INVARIANT,
        reason=invariant.reasons[0].code,
        scope=tuple(sorted(scope)),
        required_evidence="L1 dail.verify.public_ingress 1",
        priority=WorkPriority.BLOCKING,
    )


def baseline_work(address: str) -> VerificationWorkItem:
    return VerificationWorkItem(
        target_id=f"RESOURCE:{address}",
        target_type=WorkTargetType.RESOURCE,
        reason=ReasonCode.CREATED_BASELINE,
        scope=(address,),
        required_evidence="BASELINE",
        priority=WorkPriority.BLOCKING,
    )


def unaffected(
    invariant_id: str,
    version: int = 1,
    *,
    eligible: bool = False,
    evidence: Iterable[str] = (),
    reason_code: ReasonCode | None = None,
) -> UnaffectedInvariant:
    code = reason_code or (
        ReasonCode.NO_CHANGE_IN_FOOTPRINT if eligible else ReasonCode.NO_PRIOR_EVIDENCE
    )
    return UnaffectedInvariant(invariant_id, version, tuple(sorted(evidence)), eligible, code)


def report(
    *,
    changed_resources: Iterable[ChangedResource] | None = None,
    affected: Iterable[ImpactedInvariant] | None = None,
    work: Iterable[VerificationWorkItem] | None = None,
    uncertainty: Iterable[UncertaintyRecord] = (),
    unaffected_invariants: Iterable[UnaffectedInvariant] | None = None,
    parent_state_id: str = PARENT,
    candidate_id: str = CANDIDATE,
    now: datetime = NOW,
    report_id: str | None = None,
    trusted_graph_hash: str = HASH_A,
    candidate_graph_hash: str = HASH_B,
    identity_report_hash: str = HASH_C,
    graph_version: str = "dail-graph-2",
) -> ImpactReport:
    """A valid report: SEC-001 affected, FUNC uncertain, SEC-003 eligible to carry, SEC-002 not."""
    if affected is None:
        sec = affected_invariant()
        func = uncertain_invariant()
        affected = [sec, func]
    affected_list = list(affected)
    if changed_resources is None:
        changed_resources = [
            changed("aws_security_group.app"),
            changed("aws_security_group.ops", ChangeType.UNCERTAIN),
            changed("aws_internet_gateway.new", ChangeType.CREATED),
        ]
    if work is None:
        work = [work_for(item) for item in affected_list] + [
            baseline_work("aws_internet_gateway.new")
        ]
    if unaffected_invariants is None:
        unaffected_invariants = [
            unaffected("INV-SEC-002"),
            unaffected("INV-SEC-003", eligible=True, evidence=["evidence-3"]),
        ]
    return ImpactReport.create(
        parent_state_id=parent_state_id,
        candidate_id=candidate_id,
        changed_resources=changed_resources,
        affected_invariants=affected_list,
        verification_work=work,
        uncertainty=uncertainty,
        unaffected=unaffected_invariants,
        graph_version=graph_version,
        trusted_graph_hash=trusted_graph_hash,
        candidate_graph_hash=candidate_graph_hash,
        identity_report_hash=identity_report_hash,
        now=now,
        report_id=report_id,
    )


def path(changed_ref: str = "aws_security_group.app", *edges: ImpactStep) -> ImpactPath:
    return ImpactPath(changed_ref, tuple(edges))


# --- graphs from Terraform text, with the registry definitions (tests only) ---------------------

SOURCE = "aws_instance.app"
DESTINATION = "aws_db_instance.database"
STATE = uid(1)


def registry(source: str = SOURCE, destination: str = DESTINATION) -> dict[str, Invariant]:
    """The four registry-v1.0 definitions by id."""
    return {
        item.invariant_id: item
        for item in registry_v1_invariants(NOW, source=source, destination=destination)
    }


def graph_of(
    resources: Iterable[Resource],
    *,
    source: str = SOURCE,
    destination: str = DESTINATION,
    invariants: Iterable[Invariant] | None = None,
    bound: bool = True,
) -> DependencyGraph:
    """A P3c graph with the four registry definitions and the FUNC binding."""
    chosen = (
        list(invariants) if invariants is not None else list(registry(source, destination).values())
    )
    bindings = [SemanticBinding("INV-FUNC-001", source, destination, "TCP", 5432)] if bound else []
    return build_graph(resources, chosen, bindings, state_id=STATE, now=NOW)


# --- a small network in Terraform text, and the whole pipeline from text to an ImpactReport -----

NET = """
variable "unset" {}
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_vpc" "elsewhere" { cidr_block = "10.9.0.0/16" }
resource "aws_subnet" "app" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
resource "aws_subnet" "other" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.9.0/24"
}
resource "aws_internet_gateway" "igw" { vpc_id = aws_vpc.main.id }
resource "aws_route_table" "public" { vpc_id = aws_vpc.main.id }
resource "aws_route_table" "elsewhere" { vpc_id = aws_vpc.elsewhere.id }
resource "aws_route_table_association" "app" {
  subnet_id = aws_subnet.app.id
  route_table_id = aws_route_table.public.id
}
resource "aws_security_group" "app" {
  name = "app"
  description = "d"
  vpc_id = aws_vpc.main.id
}
resource "aws_security_group" "db" {
  name = "db"
  vpc_id = aws_vpc.main.id
}
resource "aws_security_group" "stray" {
  name = "stray"
  vpc_id = aws_vpc.main.id
}
resource "aws_security_group_rule" "to_app" {
  type = "egress"
  protocol = "-1"
  from_port = 0
  to_port = 0
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}
resource "aws_security_group_rule" "to_db" {
  type = "ingress"
  protocol = "tcp"
  from_port = 5432
  to_port = 5432
  source_security_group_id = aws_security_group.app.id
  security_group_id = aws_security_group.db.id
}
resource "aws_security_group_rule" "to_stray" {
  type = "ingress"
  protocol = "tcp"
  from_port = 80
  to_port = 80
  cidr_blocks = ["10.0.0.0/8"]
  security_group_id = aws_security_group.stray.id
}
resource "aws_instance" "app" {
  ami = "a"
  subnet_id = aws_subnet.app.id
  vpc_security_group_ids = [aws_security_group.app.id]
}
resource "aws_instance" "unrelated" {
  ami = "a"
  subnet_id = aws_subnet.other.id
  vpc_security_group_ids = [aws_security_group.stray.id]
}
resource "aws_db_instance" "database" {
  identifier = "d"
  vpc_security_group_ids = [aws_security_group.db.id]
}
"""

DB_BLOCK = (
    'resource "aws_db_instance" "database" {\n  identifier = "d"\n'
    "  vpc_security_group_ids = [aws_security_group.db.id]\n}\n"
)

PIPE_PARENT = uid(201)
PIPE_CANDIDATE = uid(202)


def impact_between(
    trusted_text: str,
    candidate_text: str,
    *,
    prior: Iterable[PriorProof] = (),
    invariants: Iterable[Invariant] | None = None,
    bound: bool = True,
    moves: list[tuple[str, str]] | None = None,
) -> ImpactReport:
    """The whole pipeline for two texts: normalize, identity, graphs, impact."""
    before, after = normalize(trusted_text), normalize(candidate_text)
    return impact_of_outcomes(
        before.resources,
        after.resources,
        list(after.moves) if moves is None else moves,
        prior=prior,
        invariants=invariants,
        bound=bound,
    )


def impact_of_outcomes(
    trusted: tuple[Resource, ...],
    candidate: tuple[Resource, ...],
    moves: list[tuple[str, str]],
    *,
    prior: Iterable[PriorProof] = (),
    invariants: Iterable[Invariant] | None = None,
    bound: bool = True,
    source: str = SOURCE,
    destination: str = DESTINATION,
) -> ImpactReport:
    definitions = (
        list(invariants) if invariants is not None else list(registry(source, destination).values())
    )
    identity = compare(
        trusted,
        candidate,
        moves,
        parent_state_id=PIPE_PARENT,
        candidate_id=PIPE_CANDIDATE,
        now=NOW,
    )
    return compute_impact(
        trusted,
        candidate,
        identity,
        graph_of(
            trusted, invariants=definitions, bound=bound, source=source, destination=destination
        ),
        graph_of(
            candidate, invariants=definitions, bound=bound, source=source, destination=destination
        ),
        definitions,
        tuple(prior),
        parent_state_id=PIPE_PARENT,
        candidate_id=PIPE_CANDIDATE,
        now=NOW,
    )


def impacted(report: ImpactReport) -> dict[str, ImpactedInvariant]:
    """The impacted invariants of a report by id (version 1)."""
    return {item.invariant_id: item for item in report.affected_invariants}


def impacted_ids(report: ImpactReport) -> set[str]:
    return {item.invariant_id for item in report.affected_invariants}


def codes_of(item: ImpactedInvariant) -> set[ReasonCode]:
    return {reason.code for reason in item.reasons}
