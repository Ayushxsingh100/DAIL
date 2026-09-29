# ADR-004: Standard-library-first through P2
**Status:** Proposed-default

P0-P2 use only Python 3.12 stdlib (dataclasses, enum, hashlib, json, sqlite3,
re, unittest) so the safety-critical core is testable with no network or
secrets (P0 exit criterion). pydantic/SQLAlchemy stay declared as optional
extras in pyproject.toml. Revisit at the start of P3 on a machine with
internet: if adopted, migrate domain models behind the same public
constructors so tests do not change.
