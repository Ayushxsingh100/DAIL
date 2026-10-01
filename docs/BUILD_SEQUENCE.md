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
| 7 | Oct 16–19 | P3a Terraform model |
| 8 | Oct 20–21 | P3b identity |
| 9 | Oct 22–23 | P3c dependency → P3 gate |
| 10 | Oct 24–27 | P4 impact → P4 gate |
| 11 | Oct 28–30 | P5a structural/security/baseline verifiers |
| 12 | Oct 31–Nov 3 | P5b functional verifier → P5 gate, M2 |
| 13 | Nov 4–5 | P6a promotion decision |
| 14 | Nov 6–9 | P6b promotion transaction → P6 gate, M3 |
| 15 | Nov 10–13 | D3 real-world pool |
| 16 | Nov 14–20 | D4 scenario generator |
| 17 | Nov 21–28 | D5 oracle labels + calibration (free route, N-08) |
| 18 | Nov 29–30 | D6 freeze TerraPreserve v1.0 |
| 19 | Dec 1–2 | P7a LLM adapter (fake provider, Ollama) |
| 20 | Dec 3–6 | P7b patch validation → P7 gate, M4 |
| 21 | Dec 7–11 | P9 AWS integration (free route) → M6 |
| 22 | Dec 12–14 | P8a experiment harness |
| 23 | Dec 15–18 | P8b metrics and reports → P8 gate, M5 |
| 24–28 | Dec 19–Jan 2 | P10 hardening, protocol freeze + pilot, LLM patch generation, main run, QA report |
| 29 | Jan 3–4 | TerraPreserve v1.1 (real LLM patches) |

Critical path: P1a → P6b.
