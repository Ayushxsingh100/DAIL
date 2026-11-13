# Build Sequence

The build is split into 18 work packages (N-06 in `DECISIONS_REGISTER.md`). Every package ends with a mini-gate or a Doc 15 phase gate, and a gate is passed only after review (see `PHASE_GATES.md`). Work runs strictly one step at a time; D steps are slotted in just before the P step that needs them.

## Sequential queue

| # | Dates (plan) | Work |
|---|---|---|
| 1 | Oct 1–3 | P1a domain model and lifecycles (done) |
| 2 | Oct 4–6 | P1b persistence → P1 gate |
| 3 | Oct 7–8 | P2-fix → P2 gate, M1 |
| 4 | Oct 9–10 | Invariant Registry Specification + D0 amendments (research track) |
| 5 | Oct 11–12 | D1 acquire sources |
| 6 | Oct 13–15 | D2 15 canonical fixtures |
| 7a | Oct 16–19 | P3a-1 HCL parser and structural model (`core/terraform_model/hcl`, loader, C-91 to C-94) |
| 7b | Oct 25–27 | P3a-2 expression evaluation, instance expansion and the move table (`values`, `evaluate`, `instances`, `evaluation`; C-99 to C-105) |
| 7c | Oct 25–27 (P3a-2 passed) | P3a-3 supported-resource filtering, reference extraction, canonical normalization into `core.domain` `Resource`, canonical security rules, fingerprints (`canonical`, `normalize`, `security_rules`, `references`, `normalization`; C-112 to C-118); ends with the P3a mini-gate review |
| 8 | Oct 20–21 | P3b identity |
| 9 | Oct 22–23 | P3c dependency → P3 gate |
| 10 | Oct 24–27 | P4 impact → P4 gate |
| 11 | Oct 28–30 | P5a structural/security/baseline verifiers |
| 12 | Oct 31–Nov 3 | P5b functional verifier → P5 gate, M2 |
| 13 | Nov 4–5 | P6a promotion decision |
| 14 | Nov 6–9 | P6b promotion commit (done) |
| 14b | Nov 6–9 | P6c orchestrator, baseline flow, fixed-patch loop → P6 gate, M3 |
| 14c | Nov 11–13 | P6d every move is a change (C-177) and invariant registry v1.1 (C-178 to C-181; INV-SEC-001/002 version 2), inserted after P6c and before P7a; ends with a PR for external review, after which the user tags `registry-v1.1` |
| 15 | Nov 10–13 | D3 real-world pool |
| 16 | Nov 14–20 | D4 scenario generator |
| 17 | Nov 21–28 | D5 oracle labels + calibration (free route, N-08) |
| 18 | Nov 29–30 | D6 freeze TerraPreserve v1.0 |
| 19 | Dec 1–2 | P7a LLM adapter (fake provider, Ollama) |
| 20 | Dec 3–6 (built 12 Nov 2026) | P7b patch validation: the C-188 patch meaning, the §13 validator, AllowedChangeScope and the operation check, `LLMEvaluationRequest` (C-188 to C-195) → P7 gate, M4 |
| 21 | — | ~~P9 AWS integration (free route) → M6~~ removed by C-71 (advisor, 11 Nov 2026): AWS stays fully offline, no deployment, no AWS account, no live calibration; milestone M6 (AWS Demonstration) is removed |
| 22 | Dec 12–14 (built 12 Nov 2026) | P8a experiment harness: conditions A, B, C, C′ (C-198), open targets (C-196), the TerraPreserve loader with hash pins and label blinding, trials, records and artifacts, the dev-split harness check (C-196 to C-208) |
| 23 | Dec 15–18 (built 13 Nov 2026) | P8b metrics and reports: scoring (the only label reader), the extractor metrics-draft-1, the ExperimentReport, docs/P8_DEV_PILOT.md (C-212 to C-215) → P8 gate, M5 |
| 24–28 | Dec 19–Jan 2 | P10 hardening, protocol freeze + pilot, LLM patch generation, main run, QA report |
| 29 | Jan 3–4 | TerraPreserve v1.1 (real LLM patches) |

Critical path: P1a → P6b.

C-71 (advisor, 11 Nov 2026): the free-of-cost route. LLMs are free open-weight models (local Ollama for wiring checks; free Kaggle or Colab GPUs for the experiment), each pinned by exact digest, quantization, temperature and seed, licence checked; no paid LLM API. AWS stays fully offline, so P9 and M6 are removed.
