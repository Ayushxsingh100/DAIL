# ADR-013: TerraPreserve lives in a separate repository

## Status

Accepted (N-01).

## Context

TerraPreserve is our benchmark, built by combining TerraGoat, TerraDS and Checkov's rule library and shaped to DAIL's parameters. The benchmark and its independent oracle (ADR-010) must not be shaped by DAIL's own implementation.

## Decision

- TerraPreserve lives in its own repository, with its sources, generator, oracle, scenarios and validation.
- DAIL consumes frozen releases, pinned by version and content hash.
- Pool filtering and parsing use Terraform's own tooling or a parser different from DAIL's, so the benchmark is never selected by what DAIL can parse.
- The 15 Doc 12 §7 canonical fixtures stay in this repository.
- Terraform and AWS provider pins must be identical in both repositories.

## Consequences

- This repository has no `benchmark/` directory and never imports benchmark code.
- The canonical fixtures live under `fixtures/` in the Doc 04 §15 layout.
- A change to the Terraform or AWS provider pins here must be mirrored in the TerraPreserve repository.

## Revisit if

- A frozen TerraPreserve release cannot be consumed by version and content hash.
- The Terraform or AWS provider pins in the two repositories diverge.
