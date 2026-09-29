# CloudSpartanX / DAIL

**Dependency-Aware Invariant Ledger for Stateful Promotion of Iterative
LLM-Generated Terraform Infrastructure States.**

This repository implements DAIL: a Terraform-specific, stateful
remediation-control mechanism that treats previously verified infrastructure
properties as protected obligations across iterative state transitions. See
the paper (`DAIL_Paper_LaTeX.tex`, in the research repo) for the full
mechanism, formal model, and evaluation methodology.

## Current build phase

Following `docs/SPEC_INDEX.md` → *Implementation Roadmap & Definition of
Done* (Spec 15), this repository is currently at:

- [x] **P0 — Project Bootstrap**
- [x] **P1 — Domain Foundation** *(gate passed: schemas validate, lineage,
      stable hashes, forbidden transitions rejected, DB-level immutability)*
- [x] **P2 — Evidence Foundation** *(gate passed: persist/resolve, hash
      verify + tamper detection, lineage queries, invalidation keeps history,
      redaction, duplicate events)*
- [ ] P3 — Identity & Dependency  **<- next**
- [ ] P4 — Impact & Invalidation
- [ ] P5 — Verification
- [ ] P6 — Promotion
- [ ] P7 — LLM Integration
- [ ] P8 — Experiment Harness
- [ ] P9 — AWS/Terraform Integration
- [ ] P10 — Hardening & End-to-End

Per Doc 15 Section 41 ("Implementation Rules We Must Not Break"): phases are
built bottom-up and gated — later phases are not started until the current
phase's exit criteria pass. Do not skip ahead.

## Bootstrap (fresh clone → running tests)

P0/P1 have **zero external dependencies** — everything below runs with
nothing but Python 3.12's standard library. This is deliberate: it keeps
"fresh clone can bootstrap" trivially true and means the safety-critical
domain logic can be tested with no network access and no secrets.

```bash
# 1. Clone and enter the repo
git clone <repo-url> cloudspartanx && cd cloudspartanx

# 2. Confirm Python version (must be 3.12.x)
python3 --version

# 3. Run the bootstrap script (creates local sqlite db, runs tests)
bash scripts/bootstrap.sh

# 4. Run tests directly at any time
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Once you have network access and want the full toolchain (formatter, linter,
type checker, pytest, and later phases' dependencies):

```bash
pip install -e ".[dev]"      # black, ruff, mypy, pytest
black --check core tests
ruff check core tests
mypy core
pytest
```

## Repository layout

```
cloudspartanx/
├── core/
│   └── domain/          # P1: Resource, Invariant, TrustedState, CandidateState,
│                         #     lifecycle states, canonical hashing, local storage
│   # (identity/, dependency/, impact/, verification/, promotion/ land in P3-P6)
├── llm/                  # P7: provider-agnostic adapter, prompts, schemas
├── evidence/              # P2: evidence records, audit events, redaction, structured logs
├── experiments/           # P8: trial harness, baselines, metrics
├── fixtures/               # Terraform test fixtures (TerraGoat-derived, etc.)
├── infrastructure/terraform/  # P9: AWS sandbox definitions
├── tests/
│   └── unit/             # fast, no I/O, no network
├── docs/
│   └── SPEC_INDEX.md      # links Specifications 01-15
└── scripts/
    └── bootstrap.sh
```

## Engineering principles (Doc 14, Section 2)

- Keep deterministic safety logic separate from probabilistic LLM integration.
- Trusted State changes only through the application promotion transaction.
- Do not allow logs to substitute for evidence.
- Do not allow model confidence to substitute for verification.
- Do not silently ignore UNKNOWN or UNSUPPORTED results.
