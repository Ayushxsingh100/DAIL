# Architecture Decision Records

Per Doc 02 Section 26 ("Architecture Decision Records Required"). Each ADR
records one decision, why, and what would make us revisit it.

Status values: **Accepted** (from a spec), **Proposed-default** (chosen to
unblock the build; safe to override *before* the dependent phase starts).

| ADR | Decision | Status |
|---|---|---|
| 001 | Modular layered monolith | Accepted (Doc 02) |
| 002 | Trusted-state lineage is relational (SQLite DAG), not literal Git | Proposed-default |
| 003 | Verification is state-indexed: verify(trusted_state, candidate, invariant) | Proposed-default |
| 004 | Standard-library-first through P2; pydantic/SQLAlchemy migration deferred | Proposed-default |
