# Specification Index

Per P0 task 8 ("Create documentation index linking Specifications 01–15").
Source PDFs live in the research project's knowledge base, not this repo;
this index records what each specification governs so implementers know
which document to consult for a given decision.

| # | Specification | Governs |
|---|---|---|
| 01 | Software Requirements Specification (SRS) | Overall scope, actors, functional/non-functional requirements |
| 02 | System Architecture Specification | Package architecture, trust boundaries, component ownership |
| 03 | DAIL Specification | Core mechanism definition (identity/dependency/impact/verification/promotion) |
| 04 | Terraform/AWS Specification | Supported resource subset, Terraform semantics DAIL relies on |
| 05 | Data Model Specification | Canonical domain object schemas |
| 06 | State Lifecycle Specification | Trusted/candidate state transitions, invariant lifecycle states |
| 07 | Identity & Dependency Specification | Resource identity resolution rules, dependency graph edge types |
| 08 | Impact/Invalidation Specification | How affected obligations are computed from identity + dependency output |
| 09 | Verification & Promotion Specification | Verification result semantics and aggregation, conflicting-evidence resolution, evidence sufficiency, promotion preconditions, decision matrix, promotion transaction |
| 10 | LLM Integration Specification | Provider-agnostic adapter contract, structured output schema, trust boundary |
| 11 | Evidence Logging Specification | Evidence record schema, audit event schema, redaction rules |
| 12 | Testing & QA Specification | Test pyramid, test matrices for identity/dependency/impact/verification/promotion, canonical fixture set and naming, defect severity, CI quality gates |
| 13 | Experiment Harness Specification | Trial execution, fair-comparison rules, repetition, metrics, reports. Its C1–C4 conditions conflict with Doc 02 §23's A/B/C modes; resolution C-01: A/B/C are the primary pre-declared conditions and Doc 13's baselines are computed as secondary results. |
| 14 | Development & DevOps Specification | Repository structure, branching, CI/CD, secrets management |
| 15 | Implementation Roadmap & Definition of Done | Phase sequencing (P0-P10), exit criteria, master build checklist |

## Supporting sources (below the specs)

- The DAIL Implementation Plan (28 Sep 2026, kept in the research project).
- [`BUILD_SEQUENCE.md`](BUILD_SEQUENCE.md) — the 18 work packages and their order.
- [`DECISIONS_REGISTER.md`](DECISIONS_REGISTER.md) — recorded conflicts and their resolutions.
- The TerraPreserve D0 dataset specification (research project; implemented in the TerraPreserve repository).
- [`docs/specs/INVARIANT_REGISTRY_v1.md`](specs/INVARIANT_REGISTRY_v1.md) — the four protected invariants: exact predicates, results, footprints and conformance vectors (C-17). Normative for P4, P5, D4 and D5.
- [`docs/specs/D0_AMENDMENTS_v1.0.1.md`](specs/D0_AMENDMENTS_v1.0.1.md) — amends TerraPreserve D0 v1.0 (N-03, N-04, N-08; gt_class; canonical topology).

## Precedence

1. A dedicated spec beats a general one on its own topic.
2. Specs beat the plan and the paper, except for resolutions recorded in `DECISIONS_REGISTER.md`.
3. A conflict not in the register means stop and record it; never choose silently (Doc 01 §16).

Always open alongside any phase: Doc 01 §8, Doc 02 §15, Doc 15 §41.
