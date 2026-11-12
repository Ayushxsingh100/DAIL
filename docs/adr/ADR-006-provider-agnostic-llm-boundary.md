# ADR-006: Provider-agnostic LLM boundary

**Status:** Proposed (P7a, 11 Nov 2026; C-182 to C-187). Doc 02 §26 requires this record.

## Context

Doc 10 §30: "LLMProvider: generate(request: LLMRequest) -> LLMResponse. Provider-specific APIs stay
inside adapter implementations. Domain objects remain provider-neutral. Model metadata is persisted
in LLMRequest. Provider failures map to normalized failure classes."

C-71 and C-182 leave one real provider: a local Ollama server. No paid API, no API key, no account.
CI and the default tests use a fake provider and open no network connection.

## Decision

1. **The seam.** `llm.adapter.provider.LLMProvider` has one method,
   `generate(call: ProviderCall) -> ProviderReply`. A `ProviderCall` holds the `LLMRequest` record,
   the system and task prompt layers, the response JSON schema and the `LLMConfig`. A `ProviderReply`
   holds the reply text, the latency and the token usage.
2. **Who builds the records.** `llm.adapter.generate.Generator` builds the `LLMRequest` before the
   call and the `LLMResponse` after it, from the reply and the strict parser, the same way for every
   provider. No provider shapes its own record or its own parse. This is the one difference from the
   letter of §30 (`generate(LLMRequest) -> LLMResponse`): the request record carries hashes, not the
   prompt text, so the provider also needs the prompt; the response record must not depend on the
   provider.
3. **Failures.** A provider raises `ProviderError` with one §24 class. Any other exception from a
   provider is TRANSIENT_ERROR, never a reply.
4. **Implementations.** `FakeProvider` (scripted, no network) and `OllamaProvider` (standard-library
   `urllib`, loopback addresses only, no proxy, optional digest pin). Nothing outside `llm/` imports
   them; `core` and `evidence` never import `llm` (R3).
5. **No framework.** Standard library only (C-183): no LiteLLM, no Instructor, no Pydantic.

## Consequences

* Adding a provider means one class in `llm/adapter/` with the §24 mapping of its errors; prompts,
  parser, records and retries do not change.
* A provider's JSON mode is a hint; the strict parser decides (C-185).
* The prompt text is not in any record; it is rebuilt from the context and the pinned template
  version, and its hash is recorded (§20).

## Revisit when

A second real provider is approved, or the experiment protocol (P10) needs a provider capability the
seam cannot carry.
