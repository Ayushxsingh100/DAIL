"""The repair context handed to the model (Doc 10 §6-§8; C-187).

``build_context(inputs)`` returns an ``LLMContext`` with the §6 fields:

* **Neighbourhood (§6, §7).** Only resources relevant to the repair: the addresses an impact report
  names (its changed resources, the changed resources of each affected invariant and every node of
  their dependency paths) plus an explicit ``focus``, restricted to the trusted state. Nothing else
  of the environment is sent.
* **Scope (§15, C-190).** ``allowed_change_scope`` and ``allowed_resource_types`` come from the
  caller's ``AllowedChangeScope`` (its addresses; its types that are in the supported model,
  registry §1.3); the builder never derives them. The allowed operations and attributes are
  stated in ``known_constraints``.
* **Secrets (§8).** Every resource is passed through ``core.domain.redaction.Redactor`` before
  anything else reads it; the count and the policy version are recorded.
* **Unknown facts (§6, §8).** An unresolved value is shown as ``{"$unknown": <reason>}`` (an
  unsupported one as ``{"$unsupported": <reason>}``), never filled, and listed in
  ``unsupported_constraints``; known constraints are listed apart in ``known_constraints``.
* **Boundary (§8).** The parent state id, the trusted-state hash, the objective and the role of
  each invariant (``repair`` or ``protect``) are part of the context.
* **History (§7).** Earlier attempts are excluded unless the caller passes them.

``PRIORITY_OF`` maps each reducible part to its §19 priority; ``llm.adapter.budget`` uses it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from core.domain.change_scope import AllowedChangeScope
from core.domain.enums import ResourceSupport
from core.domain.hashing import content_hash
from core.domain.impact import ImpactReport
from core.domain.invariant import Invariant
from core.domain.jsonvalue import thaw_json
from core.domain.redaction import REDACTION_POLICY_VERSION, Redactor
from core.domain.resource import Resource

CONTEXT_VERSION: Final = "dail-llm-context-1"
PATCH_FORMAT: Final = "TERRAFORM_HCL"  # core.domain.enums.PatchFormat (C-184)
# Registry §1.3: the supported resource types.
SUPPORTED_TYPES: Final = (
    "aws_db_instance",
    "aws_instance",
    "aws_internet_gateway",
    "aws_route_table",
    "aws_route_table_association",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_subnet",
    "aws_vpc",
)
# §19: 1 is kept first, 7 is dropped first.
PRIORITY_OF: Final[Mapping[str, int]] = {
    "objective": 1,
    "repair_invariants": 1,
    "relevant_resources": 2,
    "dependency_summary": 3,
    "constraints": 4,
    "protected_invariants": 5,
    "impact_summary": 6,
    "history": 7,
}
_TAG = "$dail"


@dataclass(frozen=True)
class ContextInputs:
    parent_state_id: str
    trusted_state_hash: str
    resources: tuple[Resource, ...]
    invariants: tuple[Invariant, ...]
    statuses: Mapping[str, str]
    objective: str
    repair_targets: tuple[str, ...]
    scope: AllowedChangeScope
    impact: ImpactReport | None = None
    focus: tuple[str, ...] = ()
    history: tuple[str, ...] = ()


@dataclass(frozen=True)
class LLMContext:
    """§6, plus the boundary (parent, objective), history and what the budget left out."""

    context_version: str
    parent_state_id: str
    trusted_state_hash: str
    objective: str
    relevant_resources: tuple[Mapping[str, Any], ...]
    relevant_invariants: tuple[Mapping[str, Any], ...]
    impact_summary: tuple[str, ...]
    dependency_summary: tuple[str, ...]
    allowed_resource_types: tuple[str, ...]
    allowed_change_scope: tuple[str, ...]
    known_constraints: tuple[str, ...]
    unsupported_constraints: tuple[str, ...]
    patch_format: str
    history: tuple[str, ...] = ()
    omitted: tuple[str, ...] = ()
    redaction_count: int = 0
    redaction_policy_version: str = REDACTION_POLICY_VERSION
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_version": self.context_version,
            "parent_state_id": self.parent_state_id,
            "trusted_state_hash": self.trusted_state_hash,
            "objective": self.objective,
            "relevant_resources": [dict(r) for r in self.relevant_resources],
            "relevant_invariants": [dict(i) for i in self.relevant_invariants],
            "impact_summary": list(self.impact_summary),
            "dependency_summary": list(self.dependency_summary),
            "allowed_resource_types": list(self.allowed_resource_types),
            "allowed_change_scope": list(self.allowed_change_scope),
            "known_constraints": list(self.known_constraints),
            "unsupported_constraints": list(self.unsupported_constraints),
            "patch_format": self.patch_format,
            "history": list(self.history),
            "omitted": list(self.omitted),
            "redaction_count": self.redaction_count,
            "redaction_policy_version": self.redaction_policy_version,
        }

    @property
    def context_hash(self) -> str:
        return content_hash(self.to_dict())


def _neighbourhood(impact: ImpactReport | None, focus: Iterable[str]) -> set[str]:
    found = set(focus)
    if impact is None:
        return found
    for changed in impact.changed_resources:
        found |= set(changed.refs())
    for item in impact.affected_invariants:
        found |= set(item.changed_resource_refs)
        for path in item.dependency_paths:
            found.add(path.changed_ref)
            for step in path.steps:
                found |= {step.from_node, step.to_node}
    return found


def _mark_unknown(value: Any, where: str, notes: list[str]) -> Any:
    if isinstance(value, dict):
        tag = value.get(_TAG)
        if tag in ("unknown", "unsupported"):
            reason = str(value.get("reason", tag))
            notes.append(f"{tag}: {where} ({reason})")
            return {f"${tag}": reason}
        return {k: _mark_unknown(v, f"{where}.{k}", notes) for k, v in value.items()}
    if isinstance(value, list):
        return [_mark_unknown(v, f"{where}[{i}]", notes) for i, v in enumerate(value)]
    return value


def _resource_view(resource: Resource, notes: list[str]) -> dict[str, Any]:
    attributes: dict[str, Any] = {}
    for name, entry in sorted(thaw_json(resource.attributes).items()):
        where = f"{resource.address}.{name}"
        if isinstance(entry, dict) and entry.get("form") == "ATTRIBUTE" and "value" in entry:
            attributes[name] = _mark_unknown(entry["value"], where, notes)
        else:
            attributes[name] = _mark_unknown(entry, where, notes)
    if resource.support_status is not ResourceSupport.SUPPORTED:
        notes.append(f"{resource.support_status.value.lower()}: {resource.address}")
    return {"address": resource.address, "type": resource.resource_type, "attributes": attributes}


def _impact_lines(impact: ImpactReport | None) -> tuple[str, ...]:
    if impact is None:
        return ()
    lines = [
        f"{item.invariant_id} v{item.invariant_version} {item.status.value}: "
        + ", ".join(sorted({reason.code.value for reason in item.reasons}))
        for item in impact.affected_invariants
    ]
    lines += [
        f"changed: {changed.address} ({changed.change_type.value})"
        for changed in impact.changed_resources
    ]
    return tuple(sorted(set(lines)))


def _path_lines(impact: ImpactReport | None) -> tuple[str, ...]:
    if impact is None:
        return ()
    lines = set()
    for item in impact.affected_invariants:
        for path in item.dependency_paths:
            hops = "".join(f" --{step.relationship}--> {step.to_node}" for step in path.steps)
            lines.add(f"{item.invariant_id}: {path.changed_ref}{hops}")
    return tuple(sorted(lines))


def _invariant_view(definition: Invariant, status: str, role: str) -> dict[str, Any]:
    return {
        "invariant_id": definition.invariant_id,
        "version": definition.version,
        "name": definition.name,
        "statement": definition.description,
        "status": status,
        "role": role,
    }


def build_context(inputs: ContextInputs) -> LLMContext:
    trusted = {r.address: r for r in inputs.resources}
    wanted = sorted(_neighbourhood(inputs.impact, inputs.focus) & set(trusted))
    redactor = Redactor()
    notes: list[str] = []
    views: list[dict[str, Any]] = []
    redactions = 0
    for address in wanted:
        result = redactor.redact(_resource_view(trusted[address], notes))
        redactions += result.redaction_count
        views.append(result.payload)
    targets = set(inputs.repair_targets)
    known_ids = {d.invariant_id for d in inputs.invariants}
    if not targets <= known_ids:
        raise ValueError(f"repair targets without a definition: {sorted(targets - known_ids)}")
    invariants = tuple(
        _invariant_view(
            d,
            inputs.statuses.get(d.invariant_id, "UNKNOWN"),
            "repair" if d.invariant_id in targets else "protect",
        )
        for d in sorted(inputs.invariants, key=lambda d: d.invariant_id)
    )
    known = [
        f"do not break {i['invariant_id']} ({i['name']}); proof: Verification Engine only"
        for i in invariants
        if i["role"] == "protect"
    ]
    known.append(f"patch format: {PATCH_FORMAT}")
    if not isinstance(inputs.scope, AllowedChangeScope):
        raise ValueError("ContextInputs.scope must be the caller's AllowedChangeScope (C-190)")
    known.append(
        "allowed operations: " + ", ".join(op.value for op in inputs.scope.operation_types)
    )
    known.append(
        "allowed attributes: "
        + (", ".join(inputs.scope.attributes) if inputs.scope.attributes else "any")
    )
    redacted_notes = redactor.redact(sorted(set(notes)))
    objective = redactor.redact(inputs.objective)
    return LLMContext(
        context_version=CONTEXT_VERSION,
        parent_state_id=inputs.parent_state_id,
        trusted_state_hash=inputs.trusted_state_hash,
        objective=objective.payload,
        relevant_resources=tuple(views),
        relevant_invariants=invariants,
        impact_summary=_impact_lines(inputs.impact),
        dependency_summary=_path_lines(inputs.impact),
        allowed_resource_types=tuple(
            t for t in SUPPORTED_TYPES if t in inputs.scope.resource_types
        ),
        allowed_change_scope=inputs.scope.resource_addresses,
        known_constraints=tuple(sorted(known)),
        unsupported_constraints=tuple(redacted_notes.payload),
        patch_format=PATCH_FORMAT,
        history=tuple(redactor.redact(list(inputs.history)).payload),
        redaction_count=redactions + redacted_notes.redaction_count + objective.redaction_count,
    )


def split_invariants(
    invariants: Sequence[Mapping[str, Any]],
) -> tuple[tuple[Mapping[str, Any], ...], tuple[Mapping[str, Any], ...]]:
    """(repair, protect)."""
    repair = tuple(i for i in invariants if i["role"] == "repair")
    protect = tuple(i for i in invariants if i["role"] == "protect")
    return repair, protect
