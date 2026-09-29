"""Application layer.

Owning spec sections: Doc 14 §14-15, §17, §37-38 (configuration), Doc 14 §30
(health checks), Doc 03 §15 and §24 (orchestration; experiment scope policy
stays out of core domain logic), Doc 02 §4 (layering).
Built in: P0-close (configuration and health), P4 (``VerificationScopePolicy``),
P6b (``EvaluationOrchestrator``).

Import restrictions (tests/contract/test_architecture_boundaries.py):
nothing in ``core.*`` outside ``core.application`` may import this package (R2);
must not import ``llm``, ``experiments``, ``scripts``, ``apps``, ``benchmark``
or ``oracle`` (R3). Standard library only (R7).
"""
