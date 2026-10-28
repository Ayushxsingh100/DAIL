"""Builders for the identity tests (P3b): configuration text to normalized resources to a report.

Standard library plus ``core.domain``, ``core.identity`` and ``core.terraform_model``. Not a test
module. ``core.identity`` itself never imports ``core.terraform_model`` (C-121); the tests do.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from core.domain.enums import ProvenanceSourceKind, ResourceSupport
from core.domain.identity import IdentityReport
from core.domain.resource import Resource
from core.domain.values import Provenance
from core.identity.engine import compare
from core.identity.strategy import IdentityStrategy
from core.terraform_model.config import ParseStatus
from core.terraform_model.evaluation import evaluate_configuration
from core.terraform_model.normalization import NormalizationOutcome, normalize_configuration
from tests.tf_builders import parse_files, parse_text

NOW = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
PARENT = "11111111-1111-4111-8111-111111111111"
CANDIDATE = "22222222-2222-4222-8222-222222222222"


def normalize(
    text: str | Mapping[str, str], variables: Mapping[str, object] | None = None
) -> NormalizationOutcome:
    """Parse, evaluate and normalize configuration text; the status must be OK."""
    parsed = parse_text(text) if isinstance(text, str) else parse_files(text)
    evaluated = evaluate_configuration(parsed, variables)
    outcome = normalize_configuration(parsed, evaluated, now=NOW)
    assert outcome.status is ParseStatus.OK, outcome.diagnostics
    return outcome


def resources_of(
    text: str | Mapping[str, str], variables: Mapping[str, object] | None = None
) -> tuple[Resource, ...]:
    return normalize(text, variables).resources


def compare_texts(
    trusted: str,
    candidate: str,
    *,
    variables: Mapping[str, object] | None = None,
    strategy: IdentityStrategy | None = None,
    moves: list[tuple[str, str]] | None = None,
) -> IdentityReport:
    """Compare two configuration texts. The candidate's own ``moved`` blocks are its moves unless
    ``moves`` is given."""
    before = normalize(trusted, variables)
    after = normalize(candidate, variables)
    chosen = list(after.moves) if moves is None else moves
    extra = {} if strategy is None else {"strategy": strategy}
    return compare(
        before.resources,
        after.resources,
        chosen,
        parent_state_id=PARENT,
        candidate_id=CANDIDATE,
        now=NOW,
        **extra,  # type: ignore[arg-type]
    )


def changes(report: IdentityReport) -> dict[str, str]:
    """Match key to change type, for compact assertions."""
    return {match.key: match.change_type.value for match in report.resource_matches}


def change_of(report: IdentityReport, address: str) -> str:
    """The change type of the match that has ``address`` as its trusted or candidate ref."""
    found = [
        match
        for match in report.resource_matches
        if address in (match.trusted_resource_ref, match.candidate_resource_ref)
    ]
    assert len(found) == 1, (address, [m.key for m in found])
    return found[0].change_type.value


def evidence_types(report: IdentityReport, address: str) -> set[str]:
    """The evidence types attached to the match of ``address``."""
    found = [
        match
        for match in report.resource_matches
        if address in (match.trusted_resource_ref, match.candidate_resource_ref)
    ]
    assert len(found) == 1, address
    return {item.evidence_type.value for item in report.evidence_for(found[0])}


def make_resource(
    address: str,
    resource_type: str,
    *,
    attributes: Mapping[str, object] | None = None,
    support: ResourceSupport = ResourceSupport.SUPPORTED,
    version: str | None = "dail-tf-norm-1",
) -> Resource:
    """A hand-made resource, for inputs the normalizer cannot produce (a type change, no version)"""
    return Resource.create(
        address=address,
        resource_type=resource_type,
        logical_identity={},
        attributes={} if attributes is None else attributes,
        security_attributes={},
        semantic_attributes={},
        references=[],
        provenance=Provenance(
            source_kind=ProvenanceSourceKind.TERRAFORM_CONFIG,
            source_component="tests.identity_builders",
            source_reference=address,
            observed_at=NOW,
            normalization_version=version,
        ),
        support_status=support,
    )
