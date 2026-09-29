# ADR-002: Python 3.12 and dependency management

## Status

Accepted.

## Context

Doc 02 §26 requires an ADR for the Python 3.12 and dependency management approach. Doc 14 §7 requires pinned runtime and dependency versions, Doc 14 §39 requires locked direct dependencies and reviewed advisories, and Doc 15 §7.3 requires that a fresh clone can bootstrap and that core tests need no secrets.

## Decision

- Python 3.12 (`requires-python = ">=3.12,<3.13"`).
- `core/` and `evidence/` use the standard library only.
- The dev toolchain is exact-pinned in `pyproject.toml` and hash-locked in `requirements/dev.lock` via pip-tools (`pip-compile --extra=dev --generate-hashes`).
- Later-phase dependency groups are re-verified and locked when their phase starts.
- CI proves the core tests run with zero installed packages before it installs anything.
- Any third-party import in `core/` needs its own ADR. The known future exception is `networkx` in `core/dependency` (ADR-005, P3c).

## Consequences

- The safety core can be bootstrapped and tested on a clean Python 3.12 install with no network access.
- The dev toolchain is reproducible from the lockfile; installs use `--require-hashes`.
- The optional-dependency groups for later phases in `pyproject.toml` are declarations only until their phase re-verifies and locks them.
- `tests/contract/test_architecture_boundaries.py` (rule R7) fails if a third-party import appears in `core/` or `evidence/`.

## Revisit if

- A later phase needs a third-party import in `core/` or `evidence/` (write a dedicated ADR first).
- Python 3.12 can no longer be installed or supported on the project's CI runners or development machines.
