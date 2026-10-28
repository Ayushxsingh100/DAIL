"""The mandatory structural and consistency gate (Doc 09 §6, §15, §31; registry §2.8; C-147).

A STRUCTURAL item and a CONSISTENCY item run on every candidate, whether or not the impact report
lists them. Each check that fails is a ``Finding`` with a closed code and a detail text; any finding
fails the item. Nothing here decides promotion.

**Structural** (the candidate on its own):

* the construction status is OK (otherwise ``construction.invalid``; the engine then makes every
  invariant item UNSUPPORTED, registry §2.8);
* each resource's ``fingerprint`` and ``canonical_json`` recompute from its content;
* addresses are unique;
* every reference marked SUPPORTED resolves to a resource of the candidate (an instance address, or
  the address of a block that has instances); UNKNOWN and UNSUPPORTED references are allowed;
* the resources come from one normalization version and the candidate's ``state_hash`` recomputes
  with the domain's own ``resource_set_hash``;
* a graph, if given, has a node for every resource, recomputes its hash, and belongs to the state it
  is used for (the trusted graph to the parent, the candidate graph to the candidate);
* every invariant and every created resource a work item names exists.

**Consistency** (the reports against the candidate and each other):

* the identity report is for this candidate and parent and names only resources the two states have;
* the impact report is for this candidate and parent, was computed with the graph version and the
  graphs given;
* every verification result passed in refers to this candidate and its state hash.

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from core.domain.enums import ReferenceResolution, VerificationResult
from core.domain.errors import DomainValidationError
from core.domain.graph import DependencyGraph, NodeType
from core.domain.hashing import canonical_json, content_hash
from core.domain.impact import VerificationWorkItem, WorkTargetType
from core.domain.resource import Resource
from core.domain.state import resource_set_hash
from core.domain.verification import (
    ConstructionStatus,
    VerificationReason,
    VerificationResultRecord,
)
from core.verification.inputs import VerificationInputs
from core.verification.outcome import PredicateOutcome
from core.verification.retention import block_of


class FindingCode(StrEnum):
    CONSTRUCTION_INVALID = "construction.invalid"
    RESOURCE_FINGERPRINT = "resource.fingerprint_mismatch"
    RESOURCE_CANONICAL = "resource.canonical_json_mismatch"
    RESOURCE_DUPLICATE = "resource.duplicate_address"
    REFERENCE_UNRESOLVED = "reference.unresolved"
    STATE_HASH = "state.hash_mismatch"
    STATE_NORMALIZATION = "state.normalization_mixed"
    GRAPH_NODE_MISSING = "graph.node_missing"
    GRAPH_HASH = "graph.hash_mismatch"
    LINEAGE_GRAPH = "lineage.graph_state_mismatch"
    WORK_INVARIANT_UNKNOWN = "work.invariant_unknown"
    WORK_RESOURCE_UNKNOWN = "work.resource_unknown"
    IDENTITY_CANDIDATE = "identity.candidate_mismatch"
    IDENTITY_PARENT = "identity.parent_mismatch"
    IDENTITY_REF = "identity.ref_unknown"
    IMPACT_CANDIDATE = "impact.candidate_mismatch"
    IMPACT_PARENT = "impact.parent_mismatch"
    IMPACT_GRAPH_VERSION = "impact.graph_version_mismatch"
    IMPACT_GRAPH_HASH = "impact.graph_hash_mismatch"
    RESULT_CANDIDATE = "result.candidate_mismatch"


@dataclass(frozen=True, slots=True)
class Finding:
    code: FindingCode
    detail: str

    def sort_key(self) -> tuple[str, str]:
        return (self.code.value, self.detail)

    def to_json(self) -> dict[str, str]:
        return {"code": self.code.value, "detail": self.detail}


def _sorted(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    return tuple(sorted(set(findings), key=Finding.sort_key))


# --- structural --------------------------------------------------------------------------------


def _resource_findings(resources: Sequence[Resource]) -> list[Finding]:
    found: list[Finding] = []
    seen: dict[str, int] = {}
    for resource in resources:
        seen[resource.address] = seen.get(resource.address, 0) + 1
        payload = resource.fingerprint_payload()
        if resource.canonical_json != canonical_json(payload):
            found.append(Finding(FindingCode.RESOURCE_CANONICAL, resource.address))
        if resource.fingerprint != content_hash(payload):
            found.append(Finding(FindingCode.RESOURCE_FINGERPRINT, resource.address))
    found += [
        Finding(FindingCode.RESOURCE_DUPLICATE, address)
        for address, count in seen.items()
        if count > 1
    ]
    addresses = set(seen)
    blocks = {block_of(address) for address in addresses}
    for resource in resources:
        for ref in resource.references:
            if ref.resolution_status is not ReferenceResolution.SUPPORTED:
                continue
            if ref.target_address not in addresses and ref.target_address not in blocks:
                found.append(
                    Finding(
                        FindingCode.REFERENCE_UNRESOLVED,
                        f"{resource.address}.{ref.source_attribute} -> {ref.target_address}",
                    )
                )
    return found


def _state_findings(inputs: VerificationInputs) -> list[Finding]:
    resources = inputs.candidate_resources
    found: list[Finding] = []
    versions = {resource.provenance.normalization_version for resource in resources}
    if len(versions) > 1:
        shown = sorted(str(version) for version in versions)
        found.append(Finding(FindingCode.STATE_NORMALIZATION, ", ".join(shown)))
    if inputs.candidate_state_hash != resource_set_hash(resources, inputs.normalization_version):
        found.append(Finding(FindingCode.STATE_HASH, inputs.candidate_state_hash))
    return found


def _graph_findings(
    graph: DependencyGraph | None, resources: Sequence[Resource], state_id: str | None, label: str
) -> list[Finding]:
    if graph is None:
        return []
    found: list[Finding] = []
    nodes = {node.ref_id for node in graph.nodes if node.node_type is NodeType.RESOURCE}
    found += [
        Finding(FindingCode.GRAPH_NODE_MISSING, f"{label}: {resource.address}")
        for resource in resources
        if resource.address not in nodes
    ]
    try:
        DependencyGraph.from_dict(graph.to_dict())
    except DomainValidationError as error:
        found.append(Finding(FindingCode.GRAPH_HASH, f"{label}: {error}"))
    if state_id is not None and graph.state_id != state_id:
        found.append(
            Finding(FindingCode.LINEAGE_GRAPH, f"{label} is the graph of {graph.state_id}")
        )
    return found


def _work_findings(
    inputs: VerificationInputs, work: Iterable[VerificationWorkItem]
) -> list[Finding]:
    addresses = {resource.address for resource in inputs.candidate_resources}
    found: list[Finding] = []
    for item in work:
        if item.target_type is WorkTargetType.INVARIANT:
            _, _, rest = item.target_id.partition(":")
            invariant_id, _, version = rest.rpartition(":")
            if not version.isdigit() or inputs.invariant(invariant_id, int(version)) is None:
                found.append(Finding(FindingCode.WORK_INVARIANT_UNKNOWN, item.target_id))
        elif item.target_id.removeprefix("RESOURCE:") not in addresses:
            found.append(Finding(FindingCode.WORK_RESOURCE_UNKNOWN, item.target_id))
    return found


def structural_findings(
    inputs: VerificationInputs, work: Iterable[VerificationWorkItem]
) -> tuple[Finding, ...]:
    """Every structural check that fails for this candidate, sorted."""
    found: list[Finding] = []
    if inputs.construction is not ConstructionStatus.OK:
        note = f": {inputs.construction_note}" if inputs.construction_note else ""
        found.append(
            Finding(FindingCode.CONSTRUCTION_INVALID, f"status {inputs.construction.value}{note}")
        )
    found += _resource_findings(inputs.candidate_resources)
    found += _state_findings(inputs)
    found += _graph_findings(
        inputs.candidate_graph, inputs.candidate_resources, inputs.candidate_id, "candidate graph"
    )
    found += _graph_findings(
        inputs.trusted_graph,
        inputs.parent_resources or (),
        inputs.parent_state_id,
        "trusted graph",
    )
    found += _work_findings(inputs, work)
    return _sorted(found)


# --- consistency -------------------------------------------------------------------------------


def _identity_findings(inputs: VerificationInputs) -> list[Finding]:
    identity = inputs.identity
    if identity is None:
        return []
    found: list[Finding] = []
    if identity.candidate_id != inputs.candidate_id:
        found.append(Finding(FindingCode.IDENTITY_CANDIDATE, identity.candidate_id))
    if identity.parent_state_id != inputs.parent_state_id:
        found.append(Finding(FindingCode.IDENTITY_PARENT, identity.parent_state_id))
    candidate = {resource.address for resource in inputs.candidate_resources}
    parent = {resource.address for resource in inputs.parent_resources or ()}
    for match in identity.resource_matches:
        ref = match.candidate_resource_ref
        if ref is not None and ref not in candidate:
            found.append(Finding(FindingCode.IDENTITY_REF, f"candidate {ref}"))
        ref = match.trusted_resource_ref
        if ref is not None and ref not in parent:
            found.append(Finding(FindingCode.IDENTITY_REF, f"trusted {ref}"))
    return found


def _impact_findings(inputs: VerificationInputs) -> list[Finding]:
    impact = inputs.impact
    if impact is None:
        return []
    found: list[Finding] = []
    if impact.candidate_id != inputs.candidate_id:
        found.append(Finding(FindingCode.IMPACT_CANDIDATE, impact.candidate_id))
    if impact.parent_state_id != inputs.parent_state_id:
        found.append(Finding(FindingCode.IMPACT_PARENT, impact.parent_state_id))
    graph = inputs.candidate_graph
    if graph is not None:
        if impact.graph_version != graph.algorithm_version:
            found.append(
                Finding(
                    FindingCode.IMPACT_GRAPH_VERSION,
                    f"{impact.graph_version} / {graph.algorithm_version}",
                )
            )
        if impact.candidate_graph_hash != graph.graph_hash:
            found.append(Finding(FindingCode.IMPACT_GRAPH_HASH, "candidate graph"))
    trusted = inputs.trusted_graph
    if trusted is not None and impact.trusted_graph_hash != trusted.graph_hash:
        found.append(Finding(FindingCode.IMPACT_GRAPH_HASH, "trusted graph"))
    return found


def consistency_findings(
    inputs: VerificationInputs, results: Iterable[VerificationResultRecord] = ()
) -> tuple[Finding, ...]:
    """Every consistency check that fails for this candidate, sorted."""
    found = _identity_findings(inputs) + _impact_findings(inputs)
    for result in results:
        if (
            result.candidate_id != inputs.candidate_id
            or result.candidate_hash != inputs.candidate_state_hash
        ):
            found.append(Finding(FindingCode.RESULT_CANDIDATE, result.target_id))
    return _sorted(found)


# --- the two mandatory items -------------------------------------------------------------------


def _gate(
    findings: tuple[Finding, ...], inputs: VerificationInputs, reason: VerificationReason
) -> PredicateOutcome:
    observations: dict[str, Any] = {
        "findings": [finding.to_json() for finding in findings],
        "resources": len(inputs.candidate_resources),
    }
    if not findings:
        return PredicateOutcome(VerificationResult.PASS, None, None, observations, ())
    return PredicateOutcome(VerificationResult.FAIL, reason, None, observations, ())


def structural_gate(
    inputs: VerificationInputs, work: Iterable[VerificationWorkItem]
) -> PredicateOutcome:
    findings = structural_findings(inputs, work)
    construction = any(f.code is FindingCode.CONSTRUCTION_INVALID for f in findings)
    reason = (
        VerificationReason.CONSTRUCTION_INVALID
        if construction
        else VerificationReason.STRUCTURAL_FINDING
    )
    return _gate(findings, inputs, reason)


def consistency_gate(
    inputs: VerificationInputs, results: Iterable[VerificationResultRecord] = ()
) -> PredicateOutcome:
    return _gate(
        consistency_findings(inputs, results), inputs, VerificationReason.CONSISTENCY_FINDING
    )
