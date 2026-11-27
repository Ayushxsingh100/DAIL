# DAIL: Dependency-Aware Invariant Ledger

DAIL (Dependency-Aware Invariant Ledger) is a promotion gate for iterative, LLM-generated Terraform repairs. It records the verified properties of the last accepted configuration as protected invariants, works out which of them a candidate change may affect (identity, dependency graph, impact), re-verifies those and every invariant not yet protected, and promotes the candidate only if every required check passes. Uncertainty is never a pass, and the LLM never writes trusted state.


## Status

Complete. All build phases P0–P10 passed external review (`docs/PHASE_GATES.md`). The evaluation ran once, on TerraPreserve v1.0's held-out test split, under the protocol frozen at tag `protocol-v1` (`docs/PROTOCOL_v1.md`, SHA-256 `f860c4c624080730b3164d56ec9adf3a30e1a5426c5a25a3028185563321bcaa`). Results: `docs/P10_RESULTS.md`. QA: `docs/QA_REPORT_v1.md` (QA report 2: PASS).

## Main results

96 test scenarios ([`docs/P10_RESULTS.md`](docs/P10_RESULTS.md)).

- **Missed regressions:** target-only verification (A) 42/42; DAIL (C) 0/42; full re-verification (B) 0/42.
- **H1 (A vs C):** exact cluster sign tests, Holm-adjusted p = 2.38 × 10⁻⁷ (change requests, 24 clusters) and 9.77 × 10⁻⁴ (repairs, 11 clusters).
- **H2 (B vs C) workload:** C needed fewer checks than B in 56 of 58 clusters and more in none (one-sided p = 1.39 × 10⁻¹⁷); 535 checks against 696 (23.1% fewer).
- **H2 non-inferiority (exploratory):** not established. The one-sided 95% upper limit of MR_C − MR_B is 0.0725, above δ_NI = 0.05.
- **Impact analysis:** recall 203/203, precision 203/272; truth recall 69/69.
- **Unsafe promotions:** A 45 of 110 promotions; B, C and C′ 0 of 63. **False rejections:** B, C and C′ 2/65.
- **DAIL–oracle agreement (κ, before adjudication):** 1.0 per invariant over the PASS/FAIL cells. Six DAIL-UNSUPPORTED/oracle-PASS cells are reported apart and were not adjudicated.

H1 follows largely from condition A's design (a target-only check cannot see a regression of another invariant); see the paper.

## Reproducing the results

- **The test suite:** `python3.12 scripts/dev.py bootstrap`, then `python3.12 scripts/dev.py test` (see "Local commands" below). The dev toolchain for `lint` and `pytest` is installed from the hash-locked lockfile: [`requirements/README.md`](requirements/README.md).
- **The evaluation:** the main run is `python -m experiments.mainrun`, as given in [`experiments/README.md`](experiments/README.md) ("The main run"):

  ```bash
  python3.12 -m experiments.mainrun reference [--resume]
  python3.12 -m experiments.mainrun generate [--resume]
  # stop: TerraPreserve labels the export (TP-L2) into $TERRAPRESERVE_PRIVATE/llm_candidates/test/<generation id>/
  python3.12 -m experiments.mainrun analyse
  ```

  What each step does, the environment variables and the output layout are in [`experiments/README.md`](experiments/README.md).
- **TerraPreserve:** the run needs TerraPreserve at tag `terrapreserve-v1.0` and its test split.
- **The guard:** it refuses to run except on the commit tagged `protocol-v1`, with a clean tree.
- **Pins:** Terraform 1.15.8, `hashicorp/aws` 6.53.0 (offline mirror), Python 3.12; for the LLM track, Ollama with the three model digests in `docs/PROTOCOL_v1.md` §8.
- **No deployment:** never `terraform apply`, `destroy` or `plan` in DAIL; no AWS account is used.

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

## Repository map

- `core/`: the deterministic safety logic: domain, persistence, Terraform model, identity, dependency graph, impact, verification and promotion.
- `evidence/`: the evidence service, correlation context, structured logs and replay.
- `llm/`: the local Ollama and fake adapters, prompts, schemas and patch validation (free open-weight models only).
- `experiments/`: the experiment harness, the conditions, the LLM candidates, the metrics, the statistics and the main run.
- `fixtures/`: the canonical Terraform fixtures (test data only).
- `config/`: versioned default configuration and the environment overrides.
- `scripts/`: `dev.py` (bootstrap, test, lint, health) and its shell wrapper.
- `tests/`: unit, integration, contract, adversarial and end-to-end tests.
- `docs/`: the decisions register, phase gates, frozen protocol, results, QA report, defect list and ADRs (`docs/adr/`).

## Companion dataset

TerraPreserve (https://github.com/Ayushxsingh100/terrapreserve), with its separately implemented oracle.

## How this was built

The code in this repository, and TerraPreserve's generator and oracle, were written by an AI coding assistant (Claude Code, Anthropic) from work packages prepared under the authors' direction. Every change was reviewed by an independent review step before merging (`docs/PHASE_GATES.md`). The independence of DAIL and the oracle rests on separate code in separate repositories, a different input path and an enforced import ban, not on separate human authors (C-233).

## Limitations

- Configuration-level only; nothing is deployed.
- Four invariants.
- Nine AWS resource types.
- Replacement is detected only for a security group's `name`.
- Unknown types default-open.
- Module calls are unsupported.

## Citation

See [`CITATION.cff`](CITATION.cff). The paper reference is to be added.

## Licence

Apache-2.0, see [`LICENSE`](LICENSE).
