# ADR-015: The identity engine is a pure function over domain resources

**Status:** Accepted (C-121 to C-127, authors, 28 Oct 2026, P3b).

**Context.** Doc 07 asks "what changed between the trusted and the candidate state?" and
requires the answer to be explainable evidence, never an opaque score, never dependent on
iteration order, and never optimistic when knowledge is missing. Every later stage (dependency,
impact, promotion) looks only at what identity says changed, so an error here is an error in
the safety argument. C-20 also asks for a pre-declared "DAIL minus identity" condition
(hypothesis H3), so identity has to be replaceable by a weaker strategy in one place.

**Decision.**

1. `core.identity` is a pure, deterministic, standard-library function over `core.domain.Resource`
   objects: `compare(trusted, candidate, candidate_moves, ...)` returns an `IdentityReport` of
   `IdentityMatch` records and `IdentityEvidence` records (types in `core.domain.identity`). It
   does not import `core.terraform_model`: the Terraform front end hands over `Resource` objects
   and canonical move pairs, and the engine needs nothing else. Contract rule R14 enforces this.
2. Every result is evidence: a closed vocabulary of evidence types (C-122), each with a short
   definition, and a rationale that names the deciding type and the evidence ids. There is no
   score. Provider IDs, plan actions and similarity are not inputs (Doc 07 §7): they are
   unavailable before P9 and heuristic similarity is never sufficient (Doc 07 §5).
3. Missing knowledge is never proof of absence. A resource with an unknown number of instances is
   UNCERTAIN, and so are the unpaired instances of such a block (C-124). Ambiguity (C-125) and
   conflicting moves (C-123) are UNCERTAIN with all evidence kept. UNCERTAIN is a first-class
   output that survives to impact and promotion (Doc 07 §11).
4. Moves follow Terraform 1.15.8 (`internal/refactoring`, C-123): only the candidate's `moved`
   blocks apply, in dependency order, against the trusted objects as the previous state, plus
   the implicit `count` moves of C-76.
5. The strategy is a seam: `IdentityStrategy` with the full `EvidenceIdentity` (default, the only
   one production code may use) and the labelled ablation `AddressOnlyIdentity` (C-127). There is
   no configuration key or environment switch, and the report names the strategy in
   `algorithm_version`.
6. Determinism: inputs are sorted by canonical address, ties are broken by address and never by
   input or hash order, and the report has a `content_hash` over everything except `report_id`
   and `created_at`, so identical inputs can be checked to give identical reports.

**Consequences.** Semantic equivalence across restructuring (an inline rule against an
`aws_security_group_rule`) is not decided here: identity reports the fingerprints (the group
MODIFIED, the rule resource CREATED) and P4/P5 decide equivalence from `rule_index` (registry
§2.9). Persistence of reports is not part of this package. A change to the controlled
replacement list (C-126) or to the ambiguity rule (C-125) is a register decision, not a code
change.

**Revisit when** plan data exists (P9: provider IDs and plan actions become evidence kinds, which
this design accepts as absent today), or when an experiment (H3) shows that the ablation changes
a result.
