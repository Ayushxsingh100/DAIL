# ADR-004: SQLite through a persistence abstraction

## Status

Accepted (C-10).

## Context

Doc 02 names "SQLAlchemy + SQLite" for the storage adapter. Doc 05 §26 makes domain services depend on repository contracts, not SQLAlchemy/SQLite-specific implementations. Doc 05 §37 allows "Pydantic or equivalent" for domain/DTO validation.

## Decision

- Use the standard-library `sqlite3` module behind the Doc 05 §26 repository ports (built in P1b).
- Validation uses frozen dataclasses with explicit checks.
- No SQLAlchemy or Pydantic in the core. Pydantic is permitted only in `llm/`, from P7.
- The database-level immutability triggers are kept.
- The deviation from Doc 02 is confined to the adapter layer.

## Consequences

- The tested storage and immutability triggers are kept.
- No framework migration happens during the P1 rewrite.
- The safety core has zero third-party dependencies, which reviewers can reproduce easily.
- Domain services still depend only on repository ports, so a different adapter can replace the `sqlite3` one without changing domain semantics (Doc 05 §26).

## Revisit if

- Migrations become complex.
- Multi-process access is needed.
- A reviewer requires an ORM mapping.

## Implemented in P1b

The decision above is unchanged. P1b built it: the Doc 05 §26 ports are `typing.Protocol` classes in `core/domain/repositories.py`, and the stdlib `sqlite3` adapter is `core/persistence/` (schema version 4, C-42 to C-44). `sqlite3` may be imported only in `core/persistence/`, `evidence/` and `core/application/health.py` (contract rule R11, C-43). The interim `core/domain/storage.py` of P1a (C-35) is deleted.
