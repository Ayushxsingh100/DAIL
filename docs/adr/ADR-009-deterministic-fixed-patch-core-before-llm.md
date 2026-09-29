# ADR-009: Deterministic fixed-patch core before LLM integration

## Status

Accepted.

## Context

Doc 02 §26 requires this decision record. Doc 15 §41 states: "Do not make the LLM the center of the architecture". Milestone M2 requires DAIL to analyze a candidate without an LLM, using `FIXED_PATCH` candidates.

## Decision

The deterministic DAIL core (identity, dependency, impact, verification, promotion) is built and proven first, driven by `FIXED_PATCH` candidates. LLM integration (P7) starts only after promotion exists (P6), and LLM output only ever enters DAIL as an untrusted candidate.

## Consequences

- Every phase before P7 is testable without an LLM, API keys or network access.
- `llm/` contains no code until P7.
- `llm.generation_enabled` defaults to `false`, and `llm.provider` accepts only the deterministic `fake` provider until P7.

## Revisit if

- A spec revision changes the build order; any such change needs a Doc 01 §16 review first.
