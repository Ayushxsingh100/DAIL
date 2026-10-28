"""Baseline verification of created resources (Doc 08 §16; registry §2.7; C-148).

P4 emits one RESOURCE work item (class BASELINE) for every CREATED resource: a created resource has
no earlier evidence to carry forward, so it is checked on its own.

* A created ``aws_security_group`` or ``aws_security_group_rule`` runs ``PIP(22)`` and ``PIP(5432)``
  and reports the clauses of **the groups that resource contributes to**: the group itself, or the
  group a rule targets. The item result is the worst of the two predicates restricted to those
  groups. The restriction only narrows what is reported; it never turns another group's FAIL into a
  PASS, which the invariant items still carry.
* A created ``aws_db_instance`` runs INV-SEC-003 for that instance.
* A created resource of a relevant-unsupported type (registry §2.7, the security-group list) is
  UNSUPPORTED, even as a placeholder (R5).
* A created placeholder (an unknown ``count`` or ``for_each``) is UNKNOWN.
* Any other type is PASS with ``applicable = false`` and the assumption that the registry declares
  no baseline predicate for it. **This is a modelling assumption, not a proof** (C-148, flagged for
  the authors); the alternative is a distinct NOT_APPLICABLE outcome that never counts as proof.

The verifier ids are those of the invariant definitions given (INV-SEC-001 for groups and rules,
INV-SEC-003 for databases); a definition set without them makes the item UNSUPPORTED, never PASS.

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from core.domain.enums import ResourceSupport, VerificationResult
from core.domain.resource import Resource
from core.domain.verification import VerificationReason
from core.verification.inputs import VerificationInputs
from core.verification.outcome import CLAUSE_IPV4, CLAUSE_IPV6, combine
from core.verification.public_ingress import RELEVANT_UNSUPPORTED, GroupStatus, analyse
from core.verification.rds_public_flag import DB_INSTANCE_TYPE, instance_state
from core.verification.views import (
    SECURITY_GROUP_RULE_TYPE,
    SECURITY_GROUP_TYPE,
    rules_of,
)

BASELINE_VERIFIER: Final = ("dail.verify.baseline", "1")
PORTS: Final = (22, 5432)
P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
R = VerificationReason
_SECURITY_TYPES: Final = (SECURITY_GROUP_TYPE, SECURITY_GROUP_RULE_TYPE)


@dataclass(frozen=True, slots=True)
class BaselineOutcome:
    result: VerificationResult
    reason: VerificationReason | None
    observations: dict[str, Any]
    assumptions: tuple[str, ...]
    applicable: bool
    verifier_id: str
    verifier_version: str


def _verifier(inputs: VerificationInputs, invariant_id: str) -> tuple[str, str] | None:
    definition = inputs.invariant(invariant_id, 1)
    return None if definition is None else (definition.verifier_id, definition.verifier_version)


def _worst(values: list[VerificationResult]) -> VerificationResult:
    """FAIL if any value FAILs, otherwise the worst of UNSUPPORTED, UNKNOWN, PASS."""
    return combine({str(index): value for index, value in enumerate(values)}) if values else P


def _contributing_groups(resource: Resource) -> list[str]:
    if resource.resource_type == SECURITY_GROUP_TYPE:
        return [resource.address]
    return sorted({rule.target for rule in rules_of(resource)})


def _security(
    resource: Resource, inputs: VerificationInputs, ids: tuple[str, str]
) -> BaselineOutcome:
    groups = _contributing_groups(resource)
    predicates: dict[str, dict[str, str]] = {}
    values: list[VerificationResult] = []
    reasons: list[VerificationReason] = []
    for port in PORTS:
        analysis = analyse(
            port,
            inputs.candidate_resources,
            parent_resources=inputs.parent_resources,
            identity=inputs.identity,
        )
        statuses: list[GroupStatus] = [analysis.groups[g] for g in groups if g in analysis.groups]
        shown: dict[str, str] = {}
        for name in (CLAUSE_IPV4, CLAUSE_IPV6):
            clause = _worst([status.clauses[name] for status in statuses])
            shown[name] = clause.value
            values.append(clause)
        predicates[str(port)] = shown
        reasons += [reason for status in statuses for reason in status.reasons]
    result = _worst(values)
    reason: VerificationReason | None = None
    if result is F:
        reason = R.PREDICATE_VIOLATED
    elif result is S:
        reason = reasons[0]
    elif result is U:
        reason = R.RULE_INDETERMINATE
    observations = _base(resource) | {"groups": groups, "predicates": predicates}
    return BaselineOutcome(result, reason, observations, (), True, *ids)


def _base(resource: Resource) -> dict[str, Any]:
    return {"resource": resource.address, "resource_type": resource.resource_type}


def verify_baseline(address: str, inputs: VerificationInputs) -> BaselineOutcome:
    """The baseline item for one created resource of the candidate."""
    resource = next((r for r in inputs.candidate_resources if r.address == address), None)
    if resource is None:
        return BaselineOutcome(
            S,
            R.STRUCTURAL_FINDING,
            {"resource": address, "resource_type": None},
            (),
            True,
            *BASELINE_VERIFIER,
        )
    kind = resource.resource_type
    ids: tuple[str, str] | None
    if kind in _SECURITY_TYPES:
        ids = _verifier(inputs, "INV-SEC-001")
    elif kind == DB_INSTANCE_TYPE:
        ids = _verifier(inputs, "INV-SEC-003")
    else:
        ids = BASELINE_VERIFIER
    if ids is None:
        return BaselineOutcome(
            S, R.INVARIANT_UNKNOWN, _base(resource), (), True, *BASELINE_VERIFIER
        )
    if kind in RELEVANT_UNSUPPORTED:
        return BaselineOutcome(S, R.TYPE_RELEVANT_UNSUPPORTED, _base(resource), (), True, *ids)
    if resource.support_status is ResourceSupport.UNKNOWN:
        return BaselineOutcome(U, R.RESOURCE_INDETERMINATE, _base(resource), (), True, *ids)
    if kind in _SECURITY_TYPES or kind == DB_INSTANCE_TYPE:
        if resource.support_status is ResourceSupport.UNSUPPORTED:
            return BaselineOutcome(S, R.RULE_UNSUPPORTED, _base(resource), (), True, *ids)
        if kind in _SECURITY_TYPES:
            return _security(resource, inputs, ids)
        return _database(resource, ids)
    note = f"registry-v1.0 declares no baseline predicate for {kind}"
    return BaselineOutcome(P, None, _base(resource), (note,), False, *ids)


def _database(resource: Resource, ids: tuple[str, str]) -> BaselineOutcome:
    result, shown = instance_state(resource)
    reasons: Mapping[VerificationResult, VerificationReason | None] = {
        P: None,
        F: R.PREDICATE_VIOLATED,
        U: R.ATTRIBUTE_UNRESOLVED,
        S: R.RULE_UNSUPPORTED,
    }
    return BaselineOutcome(
        result, reasons[result], _base(resource) | {"value": shown}, (), True, *ids
    )
