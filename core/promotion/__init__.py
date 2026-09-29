"""Promotion: the only component allowed to advance Trusted State.

Owning spec sections: Doc 09 §17-41 (conflicting evidence, preconditions,
decision matrix, commit transaction, carry-forward, idempotency, concurrency).
Built in: P6a (policy, decide(), decision completeness) and P6b (commit
transaction, carry-forward, concurrency).

Import restrictions (tests/contract/test_architecture_boundaries.py):
must not import ``core.application`` (R2); must not import ``llm``,
``experiments``, ``scripts``, ``apps``, ``benchmark`` or ``oracle`` (R3).
Standard library only (R7). No code yet.
"""
