"""Configuration, policy and record types of the LLM channel (Doc 10 §16-§18, §20-§24, §32, §34).

* ``FailureClass`` is §24; ``RETRYABLE`` is the ``retry_on`` set §23 allows.
* ``LLMConfig`` is §16 plus ``seed`` (C-182 pins every experiment model by temperature and seed)
  and, optionally, ``num_ctx``: the model's context window as the local server is asked to use it
  (P10a; P7a verdict limit 5). All of it is recorded on every request (§17); ``num_ctx`` only when
  set, so the records of a configuration without it are unchanged.
* ``RetryPolicy`` is §23; ``max_attempts`` is bounded (1 to 10): "Never retry indefinitely."
* ``BudgetConfig`` is §18.
* ``LLMRequest`` is §20 plus the attempt number, the trusted-state hash (§34 "Persist fixture/state
  hashes"), the context version and the template hash. It holds hashes, not the prompt text.
* ``LLMResponse`` is §21 plus the failure class, latency, token usage, parser version and the patch
  hash (§32, §34). ``raw_response`` is stored redacted (§33).

Standard library only (C-183).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from core.domain.ids import require_uuid
from core.domain.jsonvalue import iso_utc, utc


class FailureClass(StrEnum):
    """§24."""

    TRANSIENT_ERROR = "TRANSIENT_ERROR"
    TIMEOUT = "TIMEOUT"
    RATE_LIMIT = "RATE_LIMIT"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    NO_SOLUTION = "NO_SOLUTION"
    CONTEXT_INSUFFICIENT = "CONTEXT_INSUFFICIENT"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    UNSUPPORTED = "UNSUPPORTED"


RETRYABLE: Final = frozenset(
    {
        FailureClass.TRANSIENT_ERROR,
        FailureClass.INVALID_OUTPUT,
        FailureClass.CONTEXT_INSUFFICIENT,
        FailureClass.NO_SOLUTION,
    }
)
MAX_ATTEMPTS_LIMIT: Final = 10


class GenerationStatus(StrEnum):
    """The final status of one ``generate`` call (§32 "Final generation status")."""

    PATCH = "PATCH"  # a parsed PATCH response: still an untrusted proposal
    FAILED = "FAILED"  # every attempt ended in a failure class
    CONTEXT_INSUFFICIENT = "CONTEXT_INSUFFICIENT"  # §18: no provider call was made
    DISABLED = "DISABLED"  # llm.generation_enabled is off: no provider call was made


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError(f"{name}: must be a non-empty string")
    return value


def _number(value: object, name: str, low: float, high: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise ValueError(f"{name}: must be a finite number")
    if value < low or (high is not None and value > high):
        raise ValueError(f"{name}: out of range")
    return float(value)


def _integer(value: object, name: str, low: int, high: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name}: must be an integer")
    if value < low or (high is not None and value > high):
        raise ValueError(f"{name}: out of range")
    return value


@dataclass(frozen=True)
class LLMConfig:
    """§16: "All fields that can influence generation must be recorded for reproducibility." """

    provider: str
    model_name: str
    model_version: str  # a digest for a local model (C-182)
    temperature: float
    top_p: float
    seed: int | None
    max_output_tokens: int
    timeout_seconds: float
    retry_policy_id: str
    prompt_version: str
    response_schema_version: str
    num_ctx: int | None = None  # P10a: the context window, when the model needs it set

    def __post_init__(self) -> None:
        if self.num_ctx is not None:
            _integer(self.num_ctx, "LLMConfig.num_ctx", 1)
        for name in (
            "provider",
            "model_name",
            "model_version",
            "retry_policy_id",
            "prompt_version",
            "response_schema_version",
        ):
            _text(getattr(self, name), f"LLMConfig.{name}")
        object.__setattr__(
            self, "temperature", _number(self.temperature, "LLMConfig.temperature", 0.0, 2.0)
        )
        object.__setattr__(self, "top_p", _number(self.top_p, "LLMConfig.top_p", 0.0, 1.0))
        if self.seed is not None:
            _integer(self.seed, "LLMConfig.seed", 0)
        _integer(self.max_output_tokens, "LLMConfig.max_output_tokens", 1)
        object.__setattr__(
            self,
            "timeout_seconds",
            _number(self.timeout_seconds, "LLMConfig.timeout_seconds", 0.001),
        )

    def to_dict(self) -> dict[str, Any]:
        extra = {} if self.num_ctx is None else {"num_ctx": self.num_ctx}
        return {
            **extra,
            "provider": self.provider,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "seed": self.seed,
            "max_output_tokens": self.max_output_tokens,
            "timeout_seconds": self.timeout_seconds,
            "retry_policy_id": self.retry_policy_id,
            "prompt_version": self.prompt_version,
            "response_schema_version": self.response_schema_version,
        }


@dataclass(frozen=True)
class RetryPolicy:
    """§23. ``retry_on`` must be a subset of ``RETRYABLE``."""

    policy_id: str
    max_attempts: int
    retry_on: tuple[FailureClass, ...]
    backoff_seconds: float
    prompt_adjustment_policy: str

    def __post_init__(self) -> None:
        _text(self.policy_id, "RetryPolicy.policy_id")
        _integer(self.max_attempts, "RetryPolicy.max_attempts", 1, MAX_ATTEMPTS_LIMIT)
        classes = []
        for item in self.retry_on:
            try:
                failure = FailureClass(item)
            except ValueError as error:
                raise ValueError(f"RetryPolicy.retry_on: unknown failure class {item!r}") from error
            if failure not in RETRYABLE:
                raise ValueError(f"RetryPolicy.retry_on: {failure.value} is not retryable (§23)")
            classes.append(failure)
        object.__setattr__(self, "retry_on", tuple(sorted(set(classes))))
        object.__setattr__(
            self,
            "backoff_seconds",
            _number(self.backoff_seconds, "RetryPolicy.backoff_seconds", 0.0, 600.0),
        )
        if self.prompt_adjustment_policy != "none":
            raise ValueError("RetryPolicy.prompt_adjustment_policy: only 'none' exists in P7a")

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "max_attempts": self.max_attempts,
            "retry_on": [c.value for c in self.retry_on],
            "backoff_seconds": self.backoff_seconds,
            "prompt_adjustment_policy": self.prompt_adjustment_policy,
        }


@dataclass(frozen=True)
class BudgetConfig:
    """§18 limits (tokens)."""

    max_context_tokens: int
    reserved_output_tokens: int
    safety_margin: int

    def __post_init__(self) -> None:
        _integer(self.max_context_tokens, "BudgetConfig.max_context_tokens", 1)
        _integer(self.reserved_output_tokens, "BudgetConfig.reserved_output_tokens", 1)
        _integer(self.safety_margin, "BudgetConfig.safety_margin", 0)

    @property
    def input_limit(self) -> int:
        return self.max_context_tokens - self.reserved_output_tokens - self.safety_margin

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_context_tokens": self.max_context_tokens,
            "reserved_output_tokens": self.reserved_output_tokens,
            "safety_margin": self.safety_margin,
        }


@dataclass(frozen=True)
class LLMRequest:
    """§20, one per attempt."""

    request_id: str
    attempt_id: str
    attempt_number: int
    parent_state_id: str
    trusted_state_hash: str
    context_version: str
    context_hash: str
    prompt_hash: str
    prompt_version: str
    template_hash: str
    model_config: Mapping[str, Any]
    created_at: datetime

    def __post_init__(self) -> None:
        for name in ("request_id", "attempt_id", "parent_state_id"):
            require_uuid(getattr(self, name), f"LLMRequest.{name}")
        _integer(self.attempt_number, "LLMRequest.attempt_number", 1, MAX_ATTEMPTS_LIMIT)
        object.__setattr__(self, "created_at", utc(self.created_at, "LLMRequest.created_at"))
        object.__setattr__(self, "model_config", dict(self.model_config))

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "attempt_id": self.attempt_id,
            "attempt_number": self.attempt_number,
            "parent_state_id": self.parent_state_id,
            "trusted_state_hash": self.trusted_state_hash,
            "context_version": self.context_version,
            "context_hash": self.context_hash,
            "prompt_hash": self.prompt_hash,
            "prompt_version": self.prompt_version,
            "template_hash": self.template_hash,
            "model_config": dict(self.model_config),
            "created_at": iso_utc(self.created_at),
        }


@dataclass(frozen=True)
class LLMResponse:
    """§21, one per attempt (also when the provider failed: then ``raw_response`` is null)."""

    response_id: str
    request_id: str
    raw_response: str | None  # redacted (§33)
    parsed_status: str | None
    extracted_patch: str | None
    response_hash: str | None  # sha256 of the reply text as received
    patch_hash: str | None
    parse_errors: tuple[str, ...]
    failure_class: FailureClass | None
    latency_ms: float | None
    token_usage: Mapping[str, int]
    parser_version: str
    created_at: datetime
    confidence: float | None = None  # §25: advisory metadata only
    validator_version: str | None = None  # P7b: dail-patch-validator-1 when validated
    validation_errors: tuple[str, ...] = ()
    patch_id: str | None = None  # the Patch record of a built candidate
    candidate_tree_hash: str | None = None

    def __post_init__(self) -> None:
        require_uuid(self.response_id, "LLMResponse.response_id")
        require_uuid(self.request_id, "LLMResponse.request_id")
        object.__setattr__(self, "created_at", utc(self.created_at, "LLMResponse.created_at"))
        object.__setattr__(self, "parse_errors", tuple(self.parse_errors))
        object.__setattr__(self, "validation_errors", tuple(self.validation_errors))
        object.__setattr__(self, "token_usage", dict(self.token_usage))

    def to_dict(self) -> dict[str, Any]:
        return {
            "response_id": self.response_id,
            "request_id": self.request_id,
            "raw_response": self.raw_response,
            "parsed_status": self.parsed_status,
            "extracted_patch": self.extracted_patch,
            "response_hash": self.response_hash,
            "patch_hash": self.patch_hash,
            "parse_errors": list(self.parse_errors),
            "failure_class": None if self.failure_class is None else self.failure_class.value,
            "latency_ms": self.latency_ms,
            "token_usage": dict(self.token_usage),
            "parser_version": self.parser_version,
            "created_at": iso_utc(self.created_at),
            "confidence": self.confidence,
            "validator_version": self.validator_version,
            "validation_errors": list(self.validation_errors),
            "patch_id": self.patch_id,
            "candidate_tree_hash": self.candidate_tree_hash,
        }


@dataclass(frozen=True)
class Attempt:
    request: LLMRequest
    response: LLMResponse


@dataclass(frozen=True)
class GenerationResult:
    """The outcome of one ``generate`` call: every attempt, the final status, and what the budget
    left out. A PATCH status is an untrusted proposal; nothing here verifies it."""

    status: GenerationStatus
    failure_class: FailureClass | None
    patch: str | None
    attempts: tuple[Attempt, ...]
    config: LLMConfig
    context_version: str
    context_hash: str
    prompt_version: str
    prompt_hash: str | None
    budget: Mapping[str, Any]
    omitted: tuple[str, ...]
    parser_version: str
    validator_version: str
    detail: str = ""
    extra: Mapping[str, Any] = field(default_factory=dict)
    build: Any = None  # llm.validation.patch.CandidateBuild of the final attempt, if built

    @property
    def retry_count(self) -> int:
        return max(0, len(self.attempts) - 1)

    def observability(self) -> dict[str, Any]:
        """§32, as plain JSON."""
        usage: dict[str, int] = {}
        for attempt in self.attempts:
            for key, value in attempt.response.token_usage.items():
                usage[key] = usage.get(key, 0) + int(value)
        return {
            "request_ids": [a.request.request_id for a in self.attempts],
            "attempt_ids": [a.request.attempt_id for a in self.attempts],
            "provider": self.config.provider,
            "model_name": self.config.model_name,
            "model_version": self.config.model_version,
            "prompt_version": self.prompt_version,
            "prompt_hash": self.prompt_hash,
            "context_version": self.context_version,
            "context_hash": self.context_hash,
            "response_hashes": [a.response.response_hash for a in self.attempts],
            "latency_ms": [a.response.latency_ms for a in self.attempts],
            "token_usage": usage,
            "retry_count": self.retry_count,
            "failure_class": None if self.failure_class is None else self.failure_class.value,
            "parser_version": self.parser_version,
            "validator_version": self.validator_version,
            "status": self.status.value,
            "budget": dict(self.budget),
            "omitted": list(self.omitted),
        }


def failure_classes(values: Iterable[str]) -> tuple[FailureClass, ...]:
    return tuple(FailureClass(v) for v in values)
