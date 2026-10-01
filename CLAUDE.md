# CLAUDE.md — cloudspartanx (DAIL)

Standing rules for every Claude Code session in this repository. Each work
package comes with its own prompt that adds the task-specific steps. If that
prompt and this file conflict, stop and ask.

## What this repository is

- **DAIL (Dependency-Aware Invariant Ledger)** is a deterministic safety gate for LLM-generated Terraform repairs.
  - An LLM proposes a patch, which becomes an untrusted Candidate State.
  - DAIL works out what changed (identity), what is connected (dependency), and which protected invariants may be affected (impact), then re-verifies them.
  - Only the Promotion Controller may turn a candidate into the next Trusted State.
- **Canonical scenario.** The trusted state has public SSH open and a working EC2 → RDS TCP/5432 path.
  - A candidate that fixes SSH but breaks EC2 → RDS must be REJECTED.
  - A candidate that fixes SSH and keeps the path must be PROMOTED.
- **Research prototype for a journal paper.** Reproducibility and honest status reporting matter as much as the code.
- **What lives elsewhere, not here:**
  - the paper and the 15 specifications (research project);
  - the TerraPreserve benchmark and its independent oracle (a separate repository, ADR-010, ADR-013).
  - Never create `benchmark/`, `oracle/` or `apps/` here, and never import the oracle.

## Where the truth lives

- **Specifications.** Specs 01–15 (`CloudSpartanX_*`, v1.0) govern.
  - They are not in this repository. The work-package prompt quotes what you need.
  - If you need spec text the prompt does not give you, ask. Never reconstruct a spec from memory, from the code, or from the paper.
- **Spec index and precedence rules:** `docs/SPEC_INDEX.md`.
- **Live project state.** Read these at the start of every session instead of relying on memory:
  - `docs/PHASE_GATES.md` — gate status, known gaps, temporary exceptions;
  - `docs/BUILD_SEQUENCE.md` — the 18 work packages and their order;
  - `docs/DECISIONS_REGISTER.md` — recorded conflicts and resolutions;
  - `docs/adr/` — architecture decision records.

## How work is done

1. **One package at a time.** Work on one package, in `docs/BUILD_SEQUENCE.md` order, on its own branch (`feature/<package>`, e.g. `feature/p1a`, `feature/p2-fix`), merged into protected `main` by PR (Doc 14 §9).
2. **Commit messages** use the form `<Package> step N: <what> (Doc NN §X)`.
3. **Tests come from the spec.**
   - When the prompt gives a spec test matrix, write those tests first.
   - Derive expected values from the spec text, never from the implementation.
   - A safety rule's test must be shown to fail when the rule is broken. A test that cannot fail proves nothing.
4. **End every package with a report,** in the format its prompt specifies. If none is given, include:
   - the files changed;
   - each acceptance criterion as IMPLEMENTED or NOT DONE, with file and test evidence;
   - the commands run, with their real output;
   - NOT RUN items;
   - deviations and contradictions found;
   - open questions.
5. **Gates are decided by review.** An external Claude review audits each report against the specs. That review decides whether a gate passes, not a green test suite. The PR description links that verdict; it is the approval record (C-28).

## Gates and honesty (non-negotiable)

- **Never mark a gate or mini-gate as passed,** anywhere: docs, commits, PR text or reports.
- **Change a status in `docs/PHASE_GATES.md` only** when the user pastes a review verdict that says so, and use its wording.
- **Never claim a command ran if it did not.** Write `NOT RUN — <reason>`. Quote real output; never present expected output as observed.
- **Never report that tests pass** without running them in the current session.
- **If something fails, say so plainly.**
  - Do not keep retrying silently until it goes green.
  - Never change a test to match the code.

## DAIL safety semantics (apply in every package)

- **Uncertainty is never a pass.** UNKNOWN, UNSUPPORTED, ERROR and VERIFIER_ERROR never count as PASS. Uncertainty fails closed; it never promotes.
- **The LLM has no authority.** Its output is always an untrusted candidate. Only the Promotion Controller changes Trusted State; candidate evaluation never mutates it.
- **Logs are not evidence,** and model confidence is not verification.
- **History is append-only.** Evidence and trusted states are immutable: new records are appended, never rewritten.
- **Safety defaults.** Safety-critical settings default to their conservative value, and unsafe configuration stops startup.

## Architecture rules (enforced by `tests/contract/`)

- **Standard library only in `core/` and `evidence/`** (Python 3.12, ADR-002, ADR-004).
  - Any third-party import needs its own ADR first.
  - The one known future exception is `networkx` in `core/dependency` (ADR-005, P3c).
- **Import boundaries R1–R7** are in `tests/contract/test_architecture_boundaries.py`. Never loosen that test or its allowlist unless the prompt names the ADR that allows it.
- **No Pydantic or SQLAlchemy in the core.** Pydantic is allowed only in `llm/`, from P7.
- **Configuration.**
  - Code lives in `core/application/config.py`; data lives in `config/`.
  - New keys are added only through schema changes.
  - Safety-critical flags can be enabled only in a reviewed configuration file.

## Conflicts and decisions

- **When the prompt, the specs, the docs and the code disagree, stop.**
  - If the conflict is not already in `docs/DECISIONS_REGISTER.md`, add it as an Open row.
  - Then ask. Never pick a side silently (Doc 01 §16).
- **Never resolve an Open register row** unless the prompt or the user explicitly decides it.

## Scope discipline

- **Stay inside the current package.** No drive-by refactors, renames or improvements elsewhere; list them as suggestions instead.
- **Tests only get stronger.** Never delete, skip or weaken an existing test.
- **No new exemptions.** Never add a mypy, ruff or coverage exemption beyond what the prompt allows. Every temporary exception must be listed in `docs/PHASE_GATES.md`, together with the package that removes it.
- **Behaviour-changing lint/type fixes are not made;** report them instead.
- **Pins are exact.**
  - Change a version only when the prompt says so.
  - Regenerate `requirements/dev.lock` with pip-compile (see `requirements/README.md`); never edit it by hand.
  - Record every pin change in the decisions register.

## Commands

```bash
python3.12 scripts/dev.py bootstrap   # fresh-clone setup, tests, health checks
python3.12 scripts/dev.py test        # stdlib unittest; must pass with no packages installed
python3.12 scripts/dev.py lint        # black --check . ; ruff check . ; mypy
python3.12 scripts/dev.py health
pytest
pip-audit --require-hashes -r requirements/dev.lock
```

Terraform checks are listed in `README.md`.

Before finishing any package, run `dev.py test`, `dev.py lint` and `pytest`. If dependencies changed, also run `pip-audit`.

## Git, GitHub, cloud and secrets

- **Ask the user before any of these:**
  - installing software;
  - creating repositories;
  - pushing, or opening or merging PRs;
  - changing branch protection or repository settings;
  - anything that touches AWS.
- **Never:**
  - force-push or rewrite pushed history;
  - use `--no-verify`;
  - disable or weaken a CI job or gitleaks;
  - commit directly to `main`.
- **Terraform and AWS.**
  - Never run `terraform apply` or `terraform destroy`, and never use AWS credentials, unless the current prompt (P9 onward) says so and the user confirms.
  - No provider blocks or resources before P9.
  - Terraform and AWS provider pins must match the TerraPreserve repository.
- **Secrets.**
  - Never commit or print secrets. Secrets are referenced only as `env:NAME`.
  - Fake secrets in tests are built at runtime.
  - If a scanner flags an intentional fake, add `gitleaks:allow` to that exact line only, and report it.
