# ADR-001: Modular layered monolith
**Status:** Accepted (Doc 02, Section 3)
DAIL is a research prototype; components are separated by Python interfaces
and run in one process. No microservices/queues. Logical ownership
boundaries (state, invariants, identity, dependency, impact, verification,
promotion, llm, evidence) must stay stable even if file layout changes.
