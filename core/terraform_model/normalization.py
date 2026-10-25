"""Configuration normalization: ``EvaluationOutcome`` to ``Resource`` objects (Doc 04 §4, §5, §24;
C-112 to C-118).

``normalize_configuration(parsed, evaluated, *, now)`` is the last stage of the Doc 04 §4
pipeline (supported-resource filtering, reference extraction, canonical normalization). It returns
a guarded, frozen ``NormalizationOutcome``:

- ``resources``: one ``core.domain.resource.Resource`` per resource instance, one ``UNKNOWN``
  placeholder per resource without instances, sorted by address. Unsupported types are kept
  (``UNSUPPORTED``), never dropped (C-114);
- ``data_sources``: the addresses of the data sources (they are not resources);
- ``rule_index``: the canonical security rules indexed by group (an index only);
- ``moves``: copied from the evaluation, not applied (P3b);
- ``resource_set_hash``: ``core.domain.state.resource_set_hash`` over the resources with the
  normalization version;
- the hashes and versions of every stage.

The data is present only when the status is ``OK``. If the evaluation was not ``OK``, the status
and diagnostics are copied and there are no resources: the failure is never hidden.

``parsed`` is needed besides ``evaluated`` because references are read from the expression trees
(registry §2.2, Doc 07 §15), which the evaluation does not keep; its configuration hash must equal
the one of the evaluation. The package has no clock: ``now`` becomes ``Provenance.observed_at``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import InitVar, dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Final

from core.domain.errors import DomainValidationError, UnauthorizedConstructionError
from core.domain.hashing import content_hash
from core.domain.resource import Resource
from core.domain.state import resource_set_hash
from core.terraform_model.config import (
    Diagnostic,
    DiagnosticSeverity,
    ParsedConfiguration,
    ParseStatus,
    load_configuration,
)
from core.terraform_model.evaluation import (
    EVALUATOR_VERSION,
    EvaluationOutcome,
    evaluate_configuration,
)
from core.terraform_model.normalize import (
    NORMALIZATION_VERSION,
    normalize_indeterminate,
    normalize_instance,
)
from core.terraform_model.references import (
    ReferenceContext,
    references_of,
    references_of_indeterminate,
)
from core.terraform_model.security_rules import GroupRules, index_rules

_NORMALIZATION_TOKEN: Final = object()


def _status_of(diagnostics: tuple[Diagnostic, ...]) -> ParseStatus:
    severities = {d.severity for d in diagnostics}
    if DiagnosticSeverity.INVALID in severities:
        return ParseStatus.INVALID
    if DiagnosticSeverity.UNSUPPORTED in severities:
        return ParseStatus.UNSUPPORTED
    return ParseStatus.OK


@dataclass(frozen=True)
class NormalizationOutcome:
    """The result of normalizing a configuration. Built only by ``normalize_configuration`` (or
    ``normalize_directory``).

    ``resources``, ``data_sources``, ``rule_index``, ``moves`` and ``resource_set_hash`` are
    present only when ``status`` is OK, and ``status`` is the one the diagnostics imply.
    """

    status: ParseStatus
    diagnostics: tuple[Diagnostic, ...]
    resources: tuple[Resource, ...]
    data_sources: tuple[str, ...]
    rule_index: Mapping[str, GroupRules]
    moves: tuple[tuple[str, str], ...]
    resource_set_hash: str | None
    configuration_hash: str | None
    variables_hash: str
    parser_version: str
    evaluator_version: str
    normalization_version: str
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        if _token is not _NORMALIZATION_TOKEN:
            raise UnauthorizedConstructionError(
                "NormalizationOutcome can be created only by normalize_configuration (C-92)"
            )
        if not isinstance(self.status, ParseStatus):
            raise DomainValidationError("NormalizationOutcome.status must be a ParseStatus")
        if self.status is not _status_of(self.diagnostics):
            raise DomainValidationError(
                "NormalizationOutcome.status does not follow from its diagnostics"
            )
        keys = [d.sort_key for d in self.diagnostics]
        if keys != sorted(keys):
            raise DomainValidationError("NormalizationOutcome.diagnostics must be sorted")
        if self.status is not ParseStatus.OK:
            if (
                self.resources
                or self.data_sources
                or self.rule_index
                or self.moves
                or self.resource_set_hash is not None
            ):
                raise DomainValidationError("data is present only when the status is OK")
        else:
            addresses = [resource.address for resource in self.resources]
            if addresses != sorted(addresses) or len(set(addresses)) != len(addresses):
                raise DomainValidationError("resources must be unique and sorted by address")
            expected = resource_set_hash(self.resources, self.normalization_version)
            if self.resource_set_hash != expected:
                raise DomainValidationError("resource_set_hash does not match the resources")
        object.__setattr__(self, "rule_index", MappingProxyType(dict(self.rule_index)))


def _empty(
    status: ParseStatus,
    diagnostics: tuple[Diagnostic, ...],
    *,
    configuration_hash: str | None,
    variables_hash: str,
    parser_version: str,
) -> NormalizationOutcome:
    return NormalizationOutcome(
        status,
        diagnostics,
        (),
        (),
        {},
        (),
        None,
        configuration_hash,
        variables_hash,
        parser_version,
        EVALUATOR_VERSION,
        NORMALIZATION_VERSION,
        _NORMALIZATION_TOKEN,
    )


def normalize_configuration(
    parsed: ParsedConfiguration, evaluated: EvaluationOutcome, *, now: datetime
) -> NormalizationOutcome:
    """Normalize an evaluated configuration into ``Resource`` objects."""
    if evaluated.configuration_hash != parsed.configuration_hash:
        raise ValueError("the parsed configuration is not the one that was evaluated")
    if evaluated.status is not ParseStatus.OK:
        return _empty(
            evaluated.status,
            evaluated.diagnostics,
            configuration_hash=evaluated.configuration_hash,
            variables_hash=evaluated.variables_hash,
            parser_version=evaluated.parser_version,
        )
    context = ReferenceContext(parsed, evaluated.instances, evaluated.indeterminate)
    diagnostics: list[Diagnostic] = list(evaluated.diagnostics)
    resources: list[Resource] = []
    data_sources: set[str] = set()
    for instance in evaluated.instances.values():
        if instance.kind != "resource":
            data_sources.add(instance.address)
            continue
        references, notes = references_of(instance, context)
        diagnostics.extend(notes)
        resources.append(normalize_instance(instance, now=now, references=references))
    for placeholder in evaluated.indeterminate.values():
        if placeholder.kind != "resource":
            data_sources.add(placeholder.address)
            continue
        references, notes = references_of_indeterminate(placeholder, context)
        diagnostics.extend(notes)
        resources.append(normalize_indeterminate(placeholder, now=now, references=references))
    ordered = tuple(sorted(resources, key=lambda resource: resource.address))
    ordered_diagnostics = tuple(sorted(set(diagnostics), key=lambda d: d.sort_key + (d.message,)))
    return NormalizationOutcome(
        _status_of(ordered_diagnostics),
        ordered_diagnostics,
        ordered,
        tuple(sorted(data_sources)),
        index_rules(ordered),
        evaluated.moves,
        resource_set_hash(ordered, NORMALIZATION_VERSION),
        evaluated.configuration_hash,
        evaluated.variables_hash,
        evaluated.parser_version,
        evaluated.evaluator_version,
        NORMALIZATION_VERSION,
        _NORMALIZATION_TOKEN,
    )


def normalize_directory(
    path: Path, variables: Mapping[str, object] | None = None, *, now: datetime
) -> NormalizationOutcome:
    """Parse, evaluate and normalize a Terraform root-module directory."""
    parse = load_configuration(path)
    variables_hash = content_hash(dict(variables or {}))
    if parse.configuration is None:
        return _empty(
            parse.status,
            parse.diagnostics,
            configuration_hash=None,
            variables_hash=variables_hash,
            parser_version=parse.parser_version,
        )
    evaluated = evaluate_configuration(parse.configuration, variables)
    return normalize_configuration(parse.configuration, evaluated, now=now)
