"""The provider seam (Doc 10 §24, §30; ADR-006).

§30: "LLMProvider: generate(request: LLMRequest) -> LLMResponse. Provider-specific APIs stay inside
adapter implementations. Domain objects remain provider-neutral. Model metadata is persisted in
LLMRequest. Provider failures map to normalized failure classes."

DAIL's reading (ADR-006): a provider receives a ``ProviderCall`` (the ``LLMRequest`` record, the two
prompt layers, the response schema and the configuration) and returns a ``ProviderReply`` (the reply
text, latency, token usage). The ``LLMResponse`` record is built by ``llm.adapter.generate``
from the reply and the parser, the same way for every provider, so no provider can shape its own
record. A provider that fails raises ``ProviderError`` with one §24 class; anything else it raises
is treated as TRANSIENT_ERROR by the generator, never as a reply.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from llm.schemas.records import FailureClass, LLMConfig, LLMRequest


@dataclass(frozen=True)
class ProviderCall:
    request: LLMRequest
    system: str
    task: str
    response_schema: Mapping[str, Any]
    config: LLMConfig


@dataclass(frozen=True)
class ProviderReply:
    text: str
    latency_ms: float
    token_usage: Mapping[str, int] = field(default_factory=dict)


class ProviderError(Exception):
    """A provider failure, normalized to a §24 class."""

    def __init__(self, failure_class: FailureClass, detail: str) -> None:
        super().__init__(f"{failure_class.value}: {detail}")
        self.failure_class = FailureClass(failure_class)
        self.detail = detail


class LLMProvider(Protocol):
    name: str

    def generate(self, call: ProviderCall) -> ProviderReply: ...
