# CloudSpartanX / DAIL

**Dependency-Aware Invariant Ledger for Stateful Promotion of Iterative
LLM-Generated Terraform Infrastructure States.**

This repository implements DAIL: a Terraform-specific, stateful
remediation-control mechanism that treats previously verified infrastructure
properties as protected obligations across iterative state transitions. See
the paper (`DAIL_Paper_LaTeX.tex`, in the research repo) for the full
mechanism, formal model, and evaluation methodology.

## Build status

| Phase | Status |
|---|---|
| P0 — Project Bootstrap | PASSED (30 Sep 2026) |
| P1 — Domain Foundation | PASSED (external review, 2 Oct 2026) |
| P2 — Evidence Foundation | PASSED (external review, 4 Oct 2026) |
| P3–P10 | NOT STARTED |

Next step: the research track (Invariant Registry Specification and D0 amendments), then D1.

- Gate status and known gaps: [`docs/PHASE_GATES.md`](docs/PHASE_GATES.md)
- Work packages and order: [`docs/BUILD_SEQUENCE.md`](docs/BUILD_SEQUENCE.md)
- Recorded conflicts and decisions: [`docs/DECISIONS_REGISTER.md`](docs/DECISIONS_REGISTER.md)
- Specification index: [`docs/SPEC_INDEX.md`](docs/SPEC_INDEX.md)
- Architecture decision records: [`docs/adr/`](docs/adr/)

Per Doc 15 Section 41 ("Implementation Rules We Must Not Break"): phases are
built bottom-up and gated — later phases are not started until the current
phase's exit criteria pass. Do not skip ahead.

## Local commands (Doc 14 §12)

All commands run from the repository root. `scripts/dev.py` uses only the
Python 3.12 standard library, so a fresh clone needs no network access and no
secrets.

```bash
python3.12 scripts/dev.py bootstrap   # check Python 3.12, load dev config, create .local/,
                                      # initialize schemas, run tests, run health checks
python3.12 scripts/dev.py test        # python -m unittest discover -s tests -p "test_*.py"
python3.12 scripts/dev.py lint        # black --check . ; ruff check . ; mypy  (needs the dev toolchain)
python3.12 scripts/dev.py health      # one line per health check; exit 1 on any FAIL
```

`bash scripts/bootstrap.sh` is a thin wrapper around `scripts/dev.py bootstrap`
(on Windows use WSL or Git Bash, or call `scripts/dev.py` directly).

## Development notes

- From P2-fix the local development database (`.local/dail.db`) has schema version 5 (C-44, C-59).
  There is no migration tooling before P8a: delete `.local/dail.db` once, then run bootstrap
  again. Bootstrap refuses a database with any other schema version and says so.

## Windows notes

- Use `py -3.12` where the docs say `python3.12`.
- If `terraform init` fails with "forcibly closed by the remote host", Terraform's
  IPv6 connection is being reset. As a temporary workaround, in an admin shell run
  `netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 100 4`, then revert with
  `netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 35 4`.

## Dev toolchain and lockfiles

The dev toolchain is exact-pinned in `pyproject.toml` and hash-locked in
`requirements/dev.lock` (see [`requirements/README.md`](requirements/README.md)).

```bash
# fresh clone of the branch
git clone <repo-url> cloudspartanx && cd cloudspartanx && git checkout feature/p0-close

# zero-dependency bootstrap (no venv, no network)
python3.12 scripts/dev.py bootstrap

# locked dev toolchain
python3.12 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
python -m pip install "pip-tools>=7.4"
pip-compile --extra=dev --generate-hashes --output-file=requirements/dev.lock pyproject.toml
python -m pip install --require-hashes -r requirements/dev.lock
python -m pip install --no-deps -e .
python scripts/dev.py lint
pytest
pip-audit --require-hashes -r requirements/dev.lock

# Terraform (must print 1.15.x)
terraform version
terraform -chdir=infrastructure/terraform init -backend=false
terraform -chdir=infrastructure/terraform providers lock \
  -platform=linux_amd64 -platform=darwin_arm64 -platform=darwin_amd64 -platform=windows_amd64
terraform fmt -check -recursive infrastructure/terraform
terraform -chdir=infrastructure/terraform validate

python scripts/dev.py health

# commit requirements/dev.lock and infrastructure/terraform/.terraform.lock.hcl,
# push the branch, open a PR to main, wait for quality/secrets/terraform to go green,
# merge, confirm green on main, then protect main (PR + the three required checks,
# no force-push, no deletion).
```

## Pinned toolchain

| Tool | Pin |
|---|---|
| Python | 3.12 |
| Terraform | `~> 1.15.0` (CI installs 1.15.8) |
| AWS provider | 6.53.0 |
| black | 26.3.1 |
| ruff | 0.7.0 |
| mypy | 1.13.0 |
| pytest | 9.0.3 |
| pytest-cov | 5.0.0 |
| pip-audit | exact version comes from the lockfile |
| actions/checkout | v6 |
| actions/setup-python | v6 |
| gitleaks-action | v3 |

## Repository layout

```
cloudspartanx/
├── .github/workflows/ci.yml   # quality, secrets, terraform jobs (Doc 14 §22-23)
├── config/
│   ├── base/                  # one versioned default file per area (Doc 14 §14)
│   └── environments/          # dev, test, experiment, staging overrides (Doc 14 §17)
├── core/
│   ├── domain/                # P1/P2: domain objects, lifecycles, canonical hashing, evidence, audit,
│   │                          # redaction, repository ports
│   ├── persistence/           # P1b/P2-fix: SQLite adapter behind the ports (schema version 5)
│   ├── terraform_model/       # P3a: parser, normalizer, canonical security rule, fingerprints
│   ├── identity/              # P3b: identity engine
│   ├── dependency/            # P3c: dependency graph
│   ├── impact/                # P4: impact and invalidation
│   ├── verification/          # P5a/P5b: deterministic verifiers
│   ├── promotion/             # P6a/P6b: promotion decision and transaction
│   └── application/           # configuration + health (P0-close); scope policy (P4);
│                              # EvaluationOrchestrator (P6b)
├── evidence/                  # P2: evidence service, correlation context, structured logs, replay mode
├── llm/                       # P7: adapter/, prompts/, schemas/, validation/
├── experiments/               # P8: trial harness, conditions, metrics
├── fixtures/                  # the 15 Doc 12 §7 canonical fixtures (Doc 04 §15 layout)
│   ├── canonical_regression/{baseline,patch_safe,patch_regression}/
│   ├── identity/  dependency/  impact/  verification/  adversarial/
├── infrastructure/terraform/  # P9: modules/, environments/{dev,test,experiment,staging}/,
│                              # policies/, versions.tf (Doc 14 §18)
├── requirements/              # dev.lock (hash-locked dev toolchain, generated by pip-compile)
├── tests/
│   ├── unit/  integration/  contract/  adversarial/  e2e/
├── docs/                      # PHASE_GATES, BUILD_SEQUENCE, DECISIONS_REGISTER, SPEC_INDEX, adr/
└── scripts/
    ├── dev.py                 # bootstrap | test | lint | health
    └── bootstrap.sh           # wrapper for dev.py bootstrap
```

The TerraPreserve benchmark and its independent oracle live in a separate
repository (ADR-010, ADR-013). This repository contains no `benchmark/` or
`oracle/` directory and never imports them.

## Engineering principles (Doc 14, Section 2)

- Keep deterministic safety logic separate from probabilistic LLM integration.
- Trusted State changes only through the application promotion transaction.
- Do not allow logs to substitute for evidence.
- Do not allow model confidence to substitute for verification.
- Do not silently ignore UNKNOWN or UNSUPPORTED results.
