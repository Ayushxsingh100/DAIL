"""What generation is given per scenario (P10a Section 3.3 "Input per scenario"; decisions 4 and 5,
C-219, C-220).

``GenerationInput`` is everything generation may know of a scenario: "the S0 directory and its
hashes (through the existing loader), ``target.invariant_id``, the endpoints, the primary variable
values. Nothing else." (plus the scenario id and family, which name the records). It is projected
from the loader's ``ScenarioInput`` by ``generation_input``, which takes the first step only and
refuses a scenario that is not a repair (decision 4: "repair scenarios only").

``change_scope`` is decision 5: every resource address of S0, every supported type, no attribute
restriction and all four operations; ``scope_record`` is its JSON form, recorded with each
candidate and with each replay under every condition.

``focus_for`` is the context's focus (Section 3.3 "Context": "focus = the target invariant's scope
resources"): the S0 resources the target definition's ``scope`` names, by address
(``scope.resources``) or by type (``scope.resource_types``). Nothing is walked from them; the
dependency walk is the impact engine's, and S0 has no impact report.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.domain.change_scope import ALL_OPERATIONS, AllowedChangeScope
from core.domain.invariant import Invariant
from core.domain.resource import Resource
from experiments.loader import ScenarioInput
from experiments.task_text import TASK_TEMPLATE, objective_for
from llm.adapter.context import SUPPORTED_TYPES

REPAIR = "repair"

__all__ = [
    "TASK_TEMPLATE",
    "GenerationError",
    "GenerationInput",
    "change_scope",
    "focus_for",
    "generation_input",
    "objective_for",
    "scope_record",
]


class GenerationError(Exception):
    """Generation cannot run as asked (a scenario that is not a repair, a frozen generation)."""


@dataclass(frozen=True)
class GenerationInput:
    scenario_id: str
    family: str
    s0_dir: Path
    s0_content_hash: str
    target_invariant_id: str
    source_endpoint: str
    destination_endpoint: str
    variable_values: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "family": self.family,
            "s0_content_hash": self.s0_content_hash,
            "target_invariant_id": self.target_invariant_id,
            "source_endpoint": self.source_endpoint,
            "destination_endpoint": self.destination_endpoint,
            "variable_values": dict(self.variable_values),
        }


def generation_input(scenario: ScenarioInput) -> GenerationInput:
    if scenario.target_kind != REPAIR or scenario.target_invariant_id is None:
        raise GenerationError(
            f"{scenario.scenario_id}: only repair scenarios get LLM candidates (C-219)"
        )
    first = scenario.steps[0]
    if first.index != 0:
        raise GenerationError(f"{scenario.scenario_id}: the first step is not S0")
    return GenerationInput(
        scenario_id=scenario.scenario_id,
        family=scenario.family,
        s0_dir=first.directory,
        s0_content_hash=first.content_hash,
        target_invariant_id=scenario.target_invariant_id,
        source_endpoint=scenario.source_endpoint,
        destination_endpoint=scenario.destination_endpoint,
        variable_values=dict(scenario.variable_values),
    )


def config_address(address: str) -> str:
    """``type.name`` of a resource address (an instance key is dropped, C-189)."""
    return address.partition("[")[0]


def change_scope(resources: Iterable[Resource]) -> AllowedChangeScope:
    """Decision 5 (C-220): "every resource address of S0" as configuration addresses."""
    return AllowedChangeScope(
        resource_addresses=tuple(sorted({config_address(r.address) for r in resources})),
        resource_types=SUPPORTED_TYPES,
        attributes=(),
        operation_types=ALL_OPERATIONS,
    )


def scope_record(scope: AllowedChangeScope) -> dict[str, Any]:
    return {
        "resource_addresses": list(scope.resource_addresses),
        "resource_types": list(scope.resource_types),
        "attributes": list(scope.attributes),
        "operation_types": [op.value for op in scope.operation_types],
    }


def focus_for(definition: Invariant, resources: Iterable[Resource]) -> tuple[str, ...]:
    named = set(definition.scope.resources)
    types = set(definition.scope.resource_types)
    return tuple(
        sorted(r.address for r in resources if r.address in named or r.resource_type in types)
    )
