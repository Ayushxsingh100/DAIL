# Architecture Decision Records

Per Doc 02 Section 26 ("Architecture Decision Records Required"). Each ADR
records one decision, why, and what would make us revisit it. ADR-001 to
ADR-010 are the ten records Doc 02 §26 requires; ADR-011 to ADR-013 are
project decisions (see `docs/DECISIONS_REGISTER.md`).

| ADR | Decision | Status |
|---|---|---|
| [001](ADR-001-modular-monolith.md) | Modular layered monolith | Accepted (Doc 02) |
| [002](ADR-002-python-3.12-and-dependency-management.md) | Python 3.12 and dependency management | Accepted |
| 003 | Terraform CLI plus controlled normalization layer | Pending — written in P3a |
| [004](ADR-004-sqlite-through-persistence-abstraction.md) | SQLite through a persistence abstraction | Accepted (C-10) |
| 005 | NetworkX for the dependency graph | Pending — written in P3c |
| 006 | Provider-agnostic LLM boundary | Pending — written in P7a |
| 007 | Promotion Controller as sole trusted-state mutation authority | Pending — written in P6a |
| [008](ADR-008-explicit-uncertainty-result-semantics.md) | Explicit uncertainty result semantics | Accepted (1 Oct 2026) |
| [009](ADR-009-deterministic-fixed-patch-core-before-llm.md) | Deterministic fixed-patch core before LLM integration | Accepted |
| [010](ADR-010-independent-oracle-separation.md) | Independent oracle separation | Accepted (N-02) |
| [011](ADR-011-relational-trusted-state-lineage.md) | Trusted-state lineage is relational (parent-linked rows), not Git | Accepted in build (C-11, 29 Sep 2026); paper wording change pending research review |
| [012](ADR-012-state-indexed-verification.md) | Verification is state-indexed: `verify(trusted_state, candidate, work_item)` | Accepted (29 Sep 2026) |
| [013](ADR-013-terrapreserve-separate-repository.md) | TerraPreserve benchmark lives in a separate repository | Accepted (N-01) |
| [014](ADR-014-terraform-model-import-boundary.md) | `core.terraform_model` may import `core.domain` (rule R6 amended) | Accepted (C-27, 30 Sep 2026) |
