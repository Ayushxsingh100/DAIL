# Decisions Register

This register records every conflict found between the 15 `CloudSpartanX_*` specifications, the DAIL Implementation Plan and the paper, together with its resolution and status; a conflict that is not listed here must be stopped and recorded before anyone chooses a side (Doc 01 §16).

| ID | Topic | Resolution | Status |
|---|---|---|---|
| C-01 | Experiment conditions | A/B/C primary; Doc 13 baselines computed as secondary results | Accepted |
| C-02 | Milestone numbering | Build tracked with Doc 15 M1–M6 | Accepted |
| C-03 | Invariant lifecycle | Docs 05/06 win over Doc 03 §10.2 | Accepted |
| C-04 | Where invariant status lives | On `InvariantRef`; the definition is immutable | Accepted |
| C-05 | Candidate status | Doc 06 §5 lifecycle including FAILED | Accepted |
| C-06 | Evidence type list | Doc 11 §5 list; INPUT and NORMALIZATION → CONFIGURATION; DECISION → PROMOTION; STATE_COMMIT → STATE; oracle results in their own table (Doc 05 §19) | Accepted |
| C-07 | Provenance fields | Union of Doc 05 §6 and Doc 11 §21 | Accepted |
| C-08 | Replay modes | One enum: RECONSTRUCT (= REPLAY), REVERIFY, RERUN, REGENERATE | Accepted |
| C-09 | Lifecycle event names | Union of Doc 11 §12 and Doc 06 §28; RETRY_REQUESTED and RETRY_SCHEDULED merged | Accepted |
| C-10 | Persistence stack | stdlib `sqlite3` behind Doc 05 §26 ports; no SQLAlchemy/Pydantic in core (ADR-004) | Accepted 29 Sep 2026 |
| C-11 | Trusted-state storage | Relational lineage (ADR-011) | Accepted in build; paper wording ("Git-backed") pending research review |
| C-12 | Security verifier | DAIL's own deterministic predicate; Checkov recorded as advisory only | Accepted in build; paper text pending |
| C-13 | SSH over IPv6 | Explicit, separately reported clause in the locked scope | Accepted |
| C-14 | INV-SEC-002 / INV-SEC-003 | Adopted; Doc 01 §16 review note and ADR due in P5 | Accepted |
| C-15 | RDS network placement | VPC-level context from the RDS security groups' `vpc_id`; EC2 subnet must be in the same VPC; intra-VPC routing = the VPC local route; NACLs not modeled, stated in evidence | Accepted; paper limitations pending |
| C-16 | Primary Terraform input | HCL configuration primary; plan JSON as extra evidence | Accepted |
| C-17 | Missing invariant specification | Write an Invariant Registry Specification (research/dataset track) before scenario generation | Accepted; document pending |
| C-18 | Scope policy placement | Application layer only | Accepted |
| C-19 | Oracle disagreement | Doc 09 §17 governs promotion; the paper's protocol governs research labels | Accepted; paper alignment pending |
| C-20 | H3 ablation | Pre-declared "DAIL minus identity" (address-only identity) condition; identity-strategy seam built in P3b | Accepted; paper pending |
| C-21 | ADR numbering | Renumbered to Doc 02 §26 in P0-close | Accepted |
| C-22 | Evidence level, carry-forward | L1 minimum for all four invariants; carry-forward on for DAIL, off for Stateful Full | Accepted |
| C-23 | Where AFFECTED is recorded | Candidate-scoped records; vN's `InvariantRef` rows untouched on REJECT; verify against Doc 09 before P6 | Accepted |
| N-01 | Benchmark location | TerraPreserve in a separate repository (ADR-013) | Accepted |
| N-02 | Oracle separation | Separate repository and different author, written from AWS semantics and the registry spec (ADR-010) | Accepted |
| N-03 | Dataset families F3/F7 | Route edits cannot break intra-VPC reachability (the VPC local route cannot be deleted). F3 unsafe = move EC2 to a subnet outside a CIDR-based RDS ingress rule; F7 unsafe = edit a shared hub security group; route edits stay as safe cases | Pending D0 amendment (research track) |
| N-04 | Impact ground truth | Two sets. `truth_changed`: the oracle's value differs from the previous step, and DAIL recall on it must be 100%. `relevant`: a changed attribute lies inside the invariant's footprint, and precision/recall are measured here | Pending (research track, before D5) |
| N-05 | Condition A on change-request families | For F1, F5 and F7, Stateless runs structural checks only; declared in the frozen protocol | Pending protocol freeze |
| N-06 | Guide granularity | 18 work packages (`BUILD_SEQUENCE.md`) | Accepted |
| N-07 | Safety-flag enabling | Safety-critical flags can be set to the conservative value from any layer, but enabled only in a reviewed configuration file (interpretation of Doc 14 §15, §37) | Accepted |
| C-24 | Dev-tool pins vs dependency scan | black 26.3.1 and pytest 9.0.3 replace black 24.10.0 and pytest 8.3.3 so that `pip-audit` reports no known vulnerabilities (PYSEC-2026-2120, PYSEC-2026-2121, PYSEC-2026-1845); `requirements/dev.lock` regenerated with pip-compile (Doc 14 §23, §39) | Accepted 30 Sep 2026 |
| C-25 | Secret variable naming vs stray-variable rule | .env.example suggests the secret lives in CSX_LLM_API_KEY, but the loader rejects every CSX_ variable other than CSX_ENV and CSX__<AREA>__<KEY>; decide before P7a | Open |
| C-26 | Runtime override of safety flags | N-07 allows the conservative value from any layer; the loader rejects every runtime override except observability.log_level, including setting a safety flag to false (fails closed) | Open |
| C-27 | core/terraform_model import boundary | Guide text says "no other core engines"; the enforced rule R6 forbids every other core.* package, including core.domain; decide before P3a | Open |
| C-28 | PR approval with a single developer | Doc 14 §22 puts PR approval before merge; GitHub does not allow self-approval, so protection requires 0 approvals and the external review report serves as the approval record | Open |
