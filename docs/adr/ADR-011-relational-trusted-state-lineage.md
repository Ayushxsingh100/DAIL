# ADR-011: Trusted-state lineage is relational, not literal Git
**Status:** Accepted in build (C-11, 29 Sep 2026); paper wording change pending research review.

**Context.** The paper (Sec. VI-B) says the ledger is "Git-backed: promoted
states = commits, rejected candidates = discarded branches". The
authoritative specs (Doc 02 Sec. 16, Doc 05 Sec. 20, Doc 15 Sec. 8.2) define
TrustedState rows with `parent_state_id` in SQLite behind repository ports.

**Decision.** Implement lineage relationally: `trusted_state.parent_state_id`
forms a content-addressed DAG (hash-verified). This is functionally the
Git-commit model (immutable, parent-linked, hash-identified) without a Git
dependency. Immutability (DATA-INT-006) is enforced with DB triggers.

**Consequences.** The paper's "Git-backed" sentence should be reworded to
"a Git-style, content-addressed, parent-linked ledger persisted in SQLite"
before submission. Revisit only if a reviewer needs literal Git provenance.
