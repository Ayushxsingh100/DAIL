"""Builders that run the real pipeline for the structural, baseline and engine tests (P5a).

Terraform text to resources, identity, graphs and impact, then ``VerificationInputs``. Standard
library plus ``core.*`` (tests may import every package; ``core.verification`` may not, R17).
Not a test module.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from core.dependency.build import build_graph
from core.dependency.invariants import SemanticBinding
from core.domain.graph import DependencyGraph
from core.domain.resource import Resource
from core.domain.state import resource_set_hash
from core.domain.verification import ConstructionStatus
from core.identity.engine import compare
from core.impact.engine import compute_impact
from core.terraform_model.normalize import NORMALIZATION_VERSION
from core.verification.inputs import VerificationInputs
from tests.domain_builders import uid
from tests.identity_builders import NOW, normalize
from tests.impact_builders import DESTINATION, SOURCE, registry

PARENT_STATE = uid(401)
CANDIDATE_STATE = uid(402)


def inputs_for(
    candidate_text: str,
    parent_text: str | None = None,
    *,
    construction: ConstructionStatus = ConstructionStatus.OK,
    bound: bool = False,
    source: str = SOURCE,
    destination: str = DESTINATION,
    with_graphs: bool = True,
) -> VerificationInputs:
    """Inputs for a candidate text, with the pipeline of its parent text when it has one.

    ``bound`` adds the INV-FUNC-001 binding (the text then needs both endpoints)."""
    after = normalize(candidate_text)
    definitions = list(registry(source, destination).values())
    bindings = [SemanticBinding("INV-FUNC-001", source, destination, "TCP", 5432)] if bound else []
    candidate_graph = (
        build_graph(after.resources, definitions, bindings, state_id=CANDIDATE_STATE, now=NOW)
        if with_graphs
        else None
    )
    if parent_text is None:
        return VerificationInputs(
            candidate_resources=after.resources,
            parent_resources=None,
            candidate_state_hash=resource_set_hash(after.resources, NORMALIZATION_VERSION),
            normalization_version=NORMALIZATION_VERSION,
            candidate_id=CANDIDATE_STATE,
            parent_state_id=None,
            identity=None,
            impact=None,
            candidate_graph=candidate_graph,
            trusted_graph=None,
            invariants=tuple(definitions),
            construction=construction,
        )
    before = normalize(parent_text)
    identity = compare(
        before.resources,
        after.resources,
        list(after.moves),
        parent_state_id=PARENT_STATE,
        candidate_id=CANDIDATE_STATE,
        now=NOW,
    )
    trusted_graph = build_graph(
        before.resources, definitions, bindings, state_id=PARENT_STATE, now=NOW
    )
    assert candidate_graph is not None or not with_graphs
    impact = None
    if candidate_graph is not None:
        impact = compute_impact(
            before.resources,
            after.resources,
            identity,
            trusted_graph,
            candidate_graph,
            definitions,
            (),
            parent_state_id=PARENT_STATE,
            candidate_id=CANDIDATE_STATE,
            now=NOW,
        )
    return VerificationInputs(
        candidate_resources=after.resources,
        parent_resources=before.resources,
        candidate_state_hash=resource_set_hash(after.resources, NORMALIZATION_VERSION),
        normalization_version=NORMALIZATION_VERSION,
        candidate_id=CANDIDATE_STATE,
        parent_state_id=PARENT_STATE,
        identity=identity,
        impact=impact,
        candidate_graph=candidate_graph,
        trusted_graph=trusted_graph if with_graphs else None,
        invariants=tuple(definitions),
        construction=construction,
    )


def with_resources(inputs: VerificationInputs, resources: Iterable[Resource]) -> VerificationInputs:
    """The same inputs with other candidate resources and a state hash that matches them."""
    chosen = tuple(resources)
    return replace(
        inputs,
        candidate_resources=chosen,
        candidate_state_hash=resource_set_hash(chosen, inputs.normalization_version),
    )


def tampered(resource: Resource, **fields: Any) -> Resource:
    """A copy of a resource with fields set behind the constructor's back (a corrupted record)."""
    clone = copy.copy(resource)
    for name, value in fields.items():
        object.__setattr__(clone, name, value)
    return clone


def tampered_graph(graph: DependencyGraph, **fields: Any) -> DependencyGraph:
    clone = copy.copy(graph)
    for name, value in fields.items():
        object.__setattr__(clone, name, value)
    return clone
