"""Builders for the P7a LLM-channel tests. Not a test module.

The canonical scenario (Doc 10 §36): the trusted state is ``canonical_regression/baseline`` (public
SSH open, EC2 to RDS on TCP/5432 established); the rejected candidate ``patch_regression`` fixed SSH
and broke the path, so its impact report names the neighbourhood the next repair must look at.
Everything here is built from the fixture directories through the real pipeline; nothing computes
an expected value.
"""

from __future__ import annotations

import json
import secrets
import string
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from functools import cache
from typing import Any

from core.domain.invariant import Invariant
from core.domain.registry_v1_1 import registry_v1_1_invariants
from core.domain.resource import Resource
from llm.adapter.context import ContextInputs, LLMContext, build_context
from llm.schemas.records import BudgetConfig, LLMConfig, RetryPolicy
from llm.schemas.repair_response import RESPONSE_SCHEMA_VERSION
from tests.promotion_pipeline import PipelineRun, fixtures_with_a_parent, pipeline

REGRESSION = "canonical_security_repair_breaks_function_reject_v1"
S, D = "aws_instance.app", "aws_db_instance.database"
OBJECTIVE = (
    "Propose the smallest supported Terraform change that removes the forbidden public SSH rule "
    "while preserving the declared EC2→RDS TCP/5432 requirement. Output: structured PATCH "
    "response only."
)
START = datetime(2026, 11, 11, 9, 0, 0, tzinfo=UTC)


def fake_aws_key() -> str:
    """A fake AWS key id, built at run time so that no secret-shaped literal is in the source."""
    return "AK" + "IA" + "".join(secrets.choice(string.ascii_uppercase) for _ in range(16))


def fake_password() -> str:
    return "pw-" + secrets.token_hex(12)


@cache
def regression_run() -> PipelineRun:
    """The rejected canonical candidate, under registry v1.1."""
    fixture = fixtures_with_a_parent()[REGRESSION]
    definitions = list(registry_v1_1_invariants(START, source=S, destination=D))
    return pipeline(fixture, definitions=definitions, registry_version=2)


def statuses(run: PipelineRun) -> dict[str, str]:
    return {r.invariant_id: r.status.value for r in run.trusted.invariant_refs}


def canonical_inputs(
    *,
    resources: Sequence[Resource] | None = None,
    focus: Sequence[str] = (),
    history: Sequence[str] = (),
    use_impact: bool = True,
) -> ContextInputs:
    run = regression_run()
    return ContextInputs(
        parent_state_id=run.trusted.state_id,
        trusted_state_hash=run.trusted.state_hash,
        resources=tuple(run.trusted.resources if resources is None else resources),
        invariants=tuple(run.definitions),
        statuses=statuses(run),
        objective=OBJECTIVE,
        repair_targets=("INV-SEC-001",),
        impact=run.impact if use_impact else None,
        focus=tuple(focus),
        history=tuple(history),
    )


def canonical_context(**kwargs: Any) -> LLMContext:
    return build_context(canonical_inputs(**kwargs))


def definitions() -> tuple[Invariant, ...]:
    return tuple(regression_run().definitions)


def config(**changes: Any) -> LLMConfig:
    values: dict[str, Any] = {
        "provider": "fake",
        "model_name": "fake-model",
        "model_version": "fake-1",
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 7,
        "max_output_tokens": 1024,
        "timeout_seconds": 30.0,
        "retry_policy_id": "retry-3",
        "prompt_version": "dail-repair-prompt-1",
        "response_schema_version": RESPONSE_SCHEMA_VERSION,
    }
    values.update(changes)
    return LLMConfig(**values)


def retry_policy(max_attempts: int = 3, **changes: Any) -> RetryPolicy:
    values: dict[str, Any] = {
        "policy_id": "retry-3",
        "max_attempts": max_attempts,
        "retry_on": ("TRANSIENT_ERROR", "INVALID_OUTPUT", "CONTEXT_INSUFFICIENT", "NO_SOLUTION"),
        "backoff_seconds": 0.0,
        "prompt_adjustment_policy": "none",
    }
    values.update(changes)
    return RetryPolicy(**values)


def budget(max_context_tokens: int = 200_000, **changes: Any) -> BudgetConfig:
    values: dict[str, Any] = {
        "max_context_tokens": max_context_tokens,
        "reserved_output_tokens": 1024,
        "safety_margin": 256,
    }
    values.update(changes)
    return BudgetConfig(**values)


def reply(status: str = "PATCH", **changes: Any) -> str:
    """A response text as a model would write it (JSON only)."""
    body: dict[str, Any] = {
        "schema_version": RESPONSE_SCHEMA_VERSION,
        "status": status,
        "summary": "remove the public SSH rule",
        "patch": (
            'resource "aws_security_group" "app" {\n  name = "app"\n}\n'
            if status == "PATCH"
            else None
        ),
        "changed_addresses": (
            ["aws_security_group_rule.app_ssh_public"] if status == "PATCH" else []
        ),
        "assumptions": ["the app group keeps its egress rule"],
        "rationale": "the rule opens 22 to 0.0.0.0/0",
    }
    body.update(changes)
    return json.dumps(body)


class Clock:
    """A clock that advances one second per reading."""

    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


class Ids:
    """Deterministic UUIDs (version 4 layout)."""

    def __init__(self, base: int = 7000) -> None:
        self.n = base

    def __call__(self) -> str:
        self.n += 1
        return f"00000000-0000-4000-8000-{self.n:012d}"
