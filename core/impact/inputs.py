"""Inputs of the impact engine and their checks (C-137).

``PriorProof`` is what the parent state holds for one invariant: the evidence ids and the verifier
that made them (Doc 08 §22). ``check_inputs`` refuses, with ``ImpactInputError``, every combination
that would make the report a guess: an identity report of another candidate or parent, graphs that
disagree with the resource tuples, several normalization or graph versions, an invariant without a
node in a graph, duplicate invariants or proofs, and an identity report that leaves a resource out.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from core.domain.errors import DomainValidationError
from core.domain.graph import DependencyGraph, NodeType
from core.domain.identity import IdentityReport
from core.domain.invariant import Invariant
from core.domain.jsonvalue import require_int, require_text
from core.domain.resource import Resource
from core.impact.errors import ImpactInputError


@dataclass(frozen=True)
class PriorProof:
    """The parent state's proof of one invariant version (what carry-forward would reuse)."""

    invariant_id: str
    invariant_version: int
    evidence_ids: tuple[str, ...]
    verifier_id: str
    verifier_version: str

    def __post_init__(self) -> None:
        try:
            require_text(self.invariant_id, "PriorProof.invariant_id")
            require_int(self.invariant_version, "PriorProof.invariant_version", 1)
            require_text(self.verifier_id, "PriorProof.verifier_id")
            require_text(self.verifier_version, "PriorProof.verifier_version")
            if isinstance(self.evidence_ids, str) or not isinstance(
                self.evidence_ids, list | tuple
            ):
                raise DomainValidationError("PriorProof.evidence_ids: must be a list of text")
            ids = tuple(require_text(i, "PriorProof.evidence_ids") for i in self.evidence_ids)
        except DomainValidationError as error:
            raise ImpactInputError(str(error)) from None
        if not ids:
            raise ImpactInputError(
                "PriorProof.evidence_ids: a proof without evidence proves nothing"
            )
        object.__setattr__(self, "evidence_ids", tuple(sorted(set(ids))))

    def key(self) -> tuple[str, int]:
        return (self.invariant_id, self.invariant_version)


@dataclass(frozen=True)
class CheckedInputs:
    """The inputs after the checks, in canonical order."""

    trusted: dict[str, Resource]
    candidate: dict[str, Resource]
    invariants: tuple[Invariant, ...]
    proofs: dict[tuple[str, int], PriorProof]
    proof_ids: frozenset[str]
    normalization_version: str | None
    graph_version: str


def _by_address(resources: Sequence[Resource], side: str) -> dict[str, Resource]:
    if isinstance(resources, str) or not isinstance(resources, list | tuple):
        raise ImpactInputError(f"{side} resources must be a sequence of Resource objects")
    found: dict[str, Resource] = {}
    for resource in resources:
        if not isinstance(resource, Resource):
            raise ImpactInputError(f"{side} resources must be Resource objects")
        if resource.address in found:
            raise ImpactInputError(f"duplicate {side} resource address {resource.address!r}")
        found[resource.address] = resource
    return found


def _graph_addresses(graph: DependencyGraph) -> set[str]:
    return {
        node.ref_id
        for node in graph.nodes
        if node.node_type is NodeType.RESOURCE and node.attributes.get("kind") == "resource"
    }


def check_inputs(
    trusted: Sequence[Resource],
    candidate: Sequence[Resource],
    identity: IdentityReport,
    trusted_graph: DependencyGraph,
    candidate_graph: DependencyGraph,
    invariants: Sequence[Invariant],
    prior: Sequence[PriorProof],
    *,
    parent_state_id: str,
    candidate_id: str,
) -> CheckedInputs:
    if not isinstance(identity, IdentityReport):
        raise ImpactInputError("identity must be an IdentityReport")
    if identity.parent_state_id != parent_state_id or identity.candidate_id != candidate_id:
        raise ImpactInputError(
            "the identity report belongs to another parent or candidate "
            f"({identity.parent_state_id}/{identity.candidate_id})"
        )
    for name, graph in (("trusted", trusted_graph), ("candidate", candidate_graph)):
        if not isinstance(graph, DependencyGraph):
            raise ImpactInputError(f"the {name} graph must be a DependencyGraph")
    trusted_by = _by_address(trusted, "trusted")
    candidate_by = _by_address(candidate, "candidate")

    if trusted_graph.algorithm_version != candidate_graph.algorithm_version:
        raise ImpactInputError("the two graphs were built by different graph algorithm versions")
    if trusted_graph.normalization_version != candidate_graph.normalization_version:
        raise ImpactInputError("the two graphs carry different normalization versions")
    versions = {
        resource.provenance.normalization_version
        for resource in (*trusted_by.values(), *candidate_by.values())
    }
    if len(versions) > 1 or (versions and versions != {trusted_graph.normalization_version}):
        raise ImpactInputError(
            "the resources and the graphs do not carry one normalization version "
            f"({sorted(map(str, versions))} against {trusted_graph.normalization_version!r})"
        )
    for name, graph, by in (
        ("trusted", trusted_graph, trusted_by),
        ("candidate", candidate_graph, candidate_by),
    ):
        if _graph_addresses(graph) != set(by):
            raise ImpactInputError(f"the {name} graph does not hold exactly the {name} resources")

    # the identity report must account for every resource, or a resource would be silently skipped
    trusted_refs = {m.trusted_resource_ref for m in identity.resource_matches} - {None}
    candidate_refs = {m.candidate_resource_ref for m in identity.resource_matches} - {None}
    if trusted_refs != set(trusted_by) or candidate_refs != set(candidate_by):
        raise ImpactInputError(
            "the identity report does not cover exactly the trusted and candidate resources"
        )

    given = tuple(sorted(invariants, key=lambda i: (i.invariant_id, i.version)))
    if not all(isinstance(item, Invariant) for item in given):
        raise ImpactInputError("the invariants must be Invariant objects")
    keys = [(item.invariant_id, item.version) for item in given]
    if len(keys) != len(set(keys)):
        raise ImpactInputError("duplicate (invariant_id, version) among the invariants")
    node_ids = {
        "trusted": {n.node_id for n in trusted_graph.nodes},
        "candidate": {n.node_id for n in candidate_graph.nodes},
    }
    for item in given:
        wanted = f"INVARIANT:{item.invariant_id}:{item.version}"
        for side, ids in node_ids.items():
            if wanted not in ids:
                raise ImpactInputError(f"{wanted} is not a node of the {side} graph")

    proofs: dict[tuple[str, int], PriorProof] = {}
    for proof in prior:
        if not isinstance(proof, PriorProof):
            raise ImpactInputError("prior proofs must be PriorProof objects")
        if proof.key() in proofs:
            raise ImpactInputError(f"two prior proofs for {proof.key()}")
        proofs[proof.key()] = proof
    ids = {item.invariant_id for item in given}
    for proof in proofs.values():
        if proof.invariant_id not in ids:
            raise ImpactInputError(
                f"a prior proof names {proof.invariant_id!r}, not a given invariant"
            )
    return CheckedInputs(
        trusted=trusted_by,
        candidate=candidate_by,
        invariants=given,
        proofs=proofs,
        proof_ids=frozenset(p.invariant_id for p in proofs.values()),
        normalization_version=trusted_graph.normalization_version,
        graph_version=trusted_graph.algorithm_version,
    )
