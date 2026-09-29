# ADR-010: Independent oracle separation

## Status

Accepted (N-02).

## Context

Doc 02 §24 defines the oracle boundary. The oracle must never feed the Promotion Controller or a DAIL verifier result, and it must stay independent enough that agreement with DAIL is meaningful.

## Decision

- The oracle lives in the TerraPreserve repository. Nothing here imports it, and it imports nothing from here.
- Its results reach DAIL only as recorded experiment data in P8, stored separately (Doc 05 §19).
- It is written by a different author than DAIL's verifiers, from AWS semantics and the Invariant Registry Specification, never from DAIL's code or guides.
- It reads Terraform through a different input path from DAIL's.

## Consequences

- This repository has no `oracle/` directory.
- `tests/contract/test_architecture_boundaries.py` fails if any file in this repository imports the oracle.
- Oracle results can never change a DAIL decision; they are research labels only.

## Revisit if

- Doc 02 §24 is revised.
- The separate-author or separate-input-path conditions cannot be met; record the deviation and its effect on the independence claim before any experiment uses oracle labels.
