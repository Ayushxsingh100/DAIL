# Build Sequence

The build is split into 18 work packages (N-06 in `DECISIONS_REGISTER.md`). Every package ends with a mini-gate or a Doc 15 phase gate, and a gate is passed only after review (see `PHASE_GATES.md`).

## Lane A (build)

| Package | Scope | Needs | Ends with |
|---|---|---|---|
| P0-close | Config, health, skeleton, ADRs, CI, status docs | — | P0 gate |
| P1a | Doc 05 §4.1 enums + `CandidateStatus`; `Reference`, `Provenance`; normalized `Resource`, `TrustedState`, `CandidateState`, `Patch`; invariant definition + `InvariantRef`; transition functions; SM-001–010 and property tests | P0-close | Mini-gate |
| P1b | Repository ports, Doc 05 §20 tables, DATA-INT triggers, storage behind ports, Doc 06 §31 matrix | P1a | P1 gate |
| P2-fix | The six P2 gaps (per-context validity first) plus error evidence, integrity handling, completeness checks, replay enum | P1b | P2 gate → M1 |
| P3a | `core/terraform_model`: parser, normalizer, canonical security rule, fingerprints | P2-fix | Mini-gate |
| P3b | Identity engine + identity-strategy seam | P3a | Mini-gate |
| P3c | Dependency graph, edge status, canonical graph hash | P3a | P3 gate |
| P4 | Impact, typed reverse traversal, per-context invalidation, work set, `VerificationScopePolicy` | P3 | P4 gate |
| P5a | Structural, security (IPv4 + IPv6 clause), baseline verifiers; aggregation; freshness | P4 | Mini-gate |
| P5b | Functional verifier (VPC-level model) | P5a | P5 gate → M2 |
| P6a | Promotion policy, `decide()`, decision completeness | P5 | Mini-gate |
| P6b | Commit transaction, carry-forward, concurrency, orchestrator, fault injection | P6a | P6 gate → M3 |
| P7a | Provider port, fake provider, context builder, prompts, schema | P6 | Mini-gate |
| P7b | Patch validation, retries, injection tests | P7a | P7 gate → M4 |
| P8a | Trials, conditions A/B/C + ablation, frozen replay | P7 | Mini-gate |
| P8b | Oracle-result integration, metric extractor, report | P8a | P8 gate → M5 |
| P9 | AWS sandbox and adapter (parallel with P7/P8) | P6 | P9 gate → M6 |
| P10 | Hardening suites, protocol freeze, pilot on dev split, main run on test split, QA report | All + frozen TerraPreserve v1.0 | P10 gate |

## Lane B (TerraPreserve repository, separate from this repo), in order

1. Invariant Registry Specification and D0 amendments.
2. D1 — acquire sources.
3. D2 — canonical fixtures. These are authored for **this** repository's `fixtures/`, and their expected outputs are derived by hand from the specs.
4. D3 — real-world pool.
5. D4 — generator.
6. D5 — independent oracle plus AWS calibration.
7. D6 — validate and freeze.

Critical path: P1a → P6b.
