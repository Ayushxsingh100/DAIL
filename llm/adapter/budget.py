"""Token budget and deterministic context reduction (Doc 10 §18-§19).

§18: "Token budgeting is a resource constraint, not a safety constraint. Truncating required context
must not silently occur ... If context exceeds the configured budget, apply deterministic context
reduction. Prioritize directly affected resources/invariants and required constraints. Record what
was omitted. If required information cannot fit, return CONTEXT_INSUFFICIENT rather than fabricate a
repair."

The estimate is ``ceil(characters / 4)`` of the rendered prompt (system and task layers): a fixed,
documented rule, not a tokenizer, so the result is the same on every machine. The input limit is
``max_context_tokens - reserved_output_tokens - safety_margin``.

Reduction drops single items, never part of one, in §19 order: priority 7 first (earlier attempts),
then 6 (impact explanations), 5 (protected invariants), 4 (known and unknown constraints), 3
(dependency paths); inside a priority the last item goes first. Priorities 1 (objective and the
invariants to repair) and 2 (the affected resources) are never dropped: if they do not fit, the
outcome is insufficient and no provider is called. The allowed resource types, the allowed change
scope and the patch format are the generation boundary (§8) and are always sent.
"""

from __future__ import annotations

import dataclasses
import math
from dataclasses import dataclass
from typing import Any, Final

from llm.adapter.context import PRIORITY_OF, LLMContext
from llm.prompts.templates import render
from llm.schemas.records import BudgetConfig

ESTIMATE_RULE: Final = "ceil(characters / 4)"


@dataclass(frozen=True)
class BudgetOutcome:
    context: LLMContext
    insufficient: bool
    omitted: tuple[str, ...]
    missing: tuple[str, ...]
    estimated_input_tokens: int
    estimated_output_tokens: int
    limits: BudgetConfig

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.limits.to_dict(),
            "estimated_input_tokens": self.estimated_input_tokens,
            "estimated_output_tokens": self.estimated_output_tokens,
            "estimate_rule": ESTIMATE_RULE,
            "insufficient": self.insufficient,
            "omitted": list(self.omitted),
            "missing": list(self.missing),
        }


def estimate(context: LLMContext) -> int:
    prompt = render(context)
    return math.ceil((len(prompt.system) + len(prompt.task)) / 4)


# Each reducible part: (group in PRIORITY_OF, context field, filter of the field's items).
def _droppable(context: LLMContext) -> list[tuple[int, str, str, int]]:
    """(priority, group, field, index) for every item that may be dropped, in dropping order."""
    items: list[tuple[int, str, str, int]] = []
    groups = (
        ("history", "history"),
        ("impact_summary", "impact_summary"),
        ("protected_invariants", "relevant_invariants"),
        ("constraints", "unsupported_constraints"),
        ("constraints", "known_constraints"),
        ("dependency_summary", "dependency_summary"),
    )
    for group, name in groups:
        values = getattr(context, name)
        for index in reversed(range(len(values))):
            if group == "protected_invariants" and values[index]["role"] != "protect":
                continue
            items.append((PRIORITY_OF[group], group, name, index))
    items.sort(key=lambda item: -item[0])  # stable: 7, 6, 5, 4, 3
    return items


def _label(context: LLMContext, group: str, name: str, index: int) -> str:
    value = getattr(context, name)[index]
    if group == "protected_invariants":
        return f"{PRIORITY_OF[group]}:{group}:{value['invariant_id']}"
    return f"{PRIORITY_OF[group]}:{group}:{name}[{index}]"


def _with(context: LLMContext, name: str, kept: tuple[Any, ...]) -> LLMContext:
    changes: dict[str, Any] = {name: kept}
    return dataclasses.replace(context, **changes)


def apply_budget(context: LLMContext, limits: BudgetConfig) -> BudgetOutcome:
    current = context
    used = estimate(current)
    omitted: list[str] = []
    dropped: dict[str, set[int]] = {}
    for _priority, group, name, index in _droppable(context):
        if used <= limits.input_limit:
            break
        omitted.append(_label(context, group, name, index))
        dropped.setdefault(name, set()).add(index)
        values = getattr(context, name)
        kept = tuple(v for i, v in enumerate(values) if i not in dropped[name])
        current = _with(current, name, kept)
        used = estimate(current)
    insufficient = used > limits.input_limit
    missing: tuple[str, ...] = ()
    if insufficient:
        repair = sum(i["role"] == "repair" for i in current.relevant_invariants)
        missing = (
            f"1:objective ({len(current.objective)} characters)",
            f"1:repair_invariants ({repair})",
            f"2:relevant_resources ({len(current.relevant_resources)})",
        )
    final = dataclasses.replace(current, omitted=tuple(omitted))
    return BudgetOutcome(
        context=final if omitted else context,
        insufficient=insufficient,
        omitted=tuple(omitted),
        missing=missing,
        estimated_input_tokens=used,
        estimated_output_tokens=limits.reserved_output_tokens,
        limits=limits,
    )
