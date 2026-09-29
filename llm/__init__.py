"""LLM integration: candidate generation only, never a safety oracle.

Owning spec sections: Doc 10 (provider-neutral adapter, prompt contract,
structured output, patch validation, retries).
Built in: P7a and P7b.

Import restrictions: ``core.*`` and ``evidence.*`` must never import ``llm``
(R3 in tests/contract/test_architecture_boundaries.py). Pydantic is permitted
here only, from P7 (ADR-004). No code yet.
"""
