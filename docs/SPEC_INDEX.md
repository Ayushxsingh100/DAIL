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
| 09 | Verification & Promotion Specification | **Available** — exact verification result aggregation algorithm (Sec. 18), Conflicting Evidence resolution table for oracle/verifier disagreement (Sec. 17), promotion preconditions checklist (Sec. 19). Authoritative for P5/P6. |
| 10 | LLM Integration Specification | Provider-agnostic adapter contract, structured output schema, trust boundary |
| 11 | Evidence Logging Specification | Evidence record schema, audit event schema, redaction rules |
| 12 | Testing & QA Specification | **Available** — full test pyramid, exact test matrices for Identity/Dependency/Impact/Verification/Promotion (Sec. 9-13), fixture naming convention, defect severity levels, CI quality gates. Authoritative for the test suite structure across all phases. |
| 13 | Experiment Harness Specification | Trial execution, fair-comparison rules, repetition policy, `ExperimentReport` contract. **Its baseline-condition design (C1-C4: LLM+DAIL/LLM-only/Deterministic/No-repair) is superseded** by Doc 02 Section 23's A/B/C (Stateless/Stateful-Full/DAIL) design, which the research paper actually built on and extended — see `DAIL_Vision_and_Delta_Briefing.md`, Part 3. |
| 14 | Development & DevOps Specification | Repository structure, branching, CI/CD, secrets management |
| 15 | Implementation Roadmap & Definition of Done | Phase sequencing (P0-P10), exit criteria, master build checklist |

**Correction (this index previously claimed Docs 09 and 12 were missing —
that was wrong, carried forward from a stale early-project note that was
never re-verified). Both are fully present and should be treated as
authoritative for their domains, not as gaps to design around.**

**See also:** `DAIL_Vision_and_Delta_Briefing.md` (in the parent research
project's outputs) for the full set of deltas between these original specs
and what the subsequent research paper and its supporting research
established — including the Doc 13 vs. Doc 02 conflict above, the
two-independent-reachability-checker oracle design, and an open,
unresolved tension between the paper's "Git-backed trusted state" language
and this repository's actual relational/SQLite persistence model.
