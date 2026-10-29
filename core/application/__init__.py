"""Application layer.

Owning spec sections: Doc 14 §14-15, §17, §37-38 (configuration), Doc 14 §30
(health checks), Doc 03 §15 and §24 (orchestration; experiment scope policy
stays out of core domain logic), Doc 02 §4 (layering).
Built in: P0-close (configuration and health), P4 (``VerificationScopePolicy``),
P6c (the evaluation flow: ``orchestrator.EvaluationOrchestrator``, ``baseline.establish_baseline``,
``recorder.StageRecorder``, ``chain.describe_chain``, ``ids``).

The orchestrator coordinates only (Doc 03 §15): it runs the stages in order, records the evidence
and the audit events of each, and leaves every decision to ``core.promotion``. It reaches the
database through a factory that opens a unit of work and never imports ``sqlite3`` or
``core.persistence`` (the contract test of P6c step 1 pins it).

Import restrictions (tests/contract/test_architecture_boundaries.py):
nothing in ``core.*`` outside ``core.application`` may import this package (R2);
must not import ``llm``, ``experiments``, ``scripts``, ``apps``, ``benchmark``
or ``oracle`` (R3). Standard library only (R7).
"""
