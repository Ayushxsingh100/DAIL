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

## Deviation (P10d, C-233, 21 Nov 2026)

The separate-author condition was not met. DAIL and TerraPreserve's oracle were both written by
Claude Code from work-package prompts written by the same assistant, under the authors' direction;
the oracle was not written by a different human author. Independence rests on:

- separate code in a separate repository;
- a different input path (Terraform plan JSON, against DAIL's own HCL parser);
- the enforced import ban (`tests/contract/test_architecture_boundaries.py` here; TerraPreserve's
  own test there);
- the two-value-set invariance test.

The effect on the independence claim is stated in the paper. TerraPreserve records the same
deviation in its next package. N-02 points to C-233.
