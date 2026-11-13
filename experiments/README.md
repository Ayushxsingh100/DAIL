# experiments — the P8 experiment harness

Runs TerraPreserve target scenarios through DAIL under the four conditions of C-198 and stores what
happened. It never bypasses DAIL's verification and promotion path: each transition is one
`EvaluationOrchestrator.evaluate` call. P8a builds the harness; scoring, metrics and reports are
P8b.

## Running

The run is read-only towards TerraPreserve. It is free and offline: there is no network, no LLM,
no AWS, and Terraform is never run.

```bash
export TERRAPRESERVE_ROOT=/path/to/TerraPreserve      # a checkout at tag terrapreserve-v1.0
export DAIL_EXPERIMENT_ROOT=/path/outside/both/repos  # where output goes; never committed
python3.12 -m experiments run --name p8a-dev-harness-check --protocol-version draft
python3.12 -m experiments summary --name p8a-dev-harness-check
```

- **Options:** `--conditions A,B,C,C_PRIME` (the default is all four), `--only <scenario ids>` and
  `--workers N` (trials run in threads; each has its own store).
- **Interruptions:** running the same command again resumes. COMPLETED and FAILED trials are
  skipped. An interrupted trial is marked ABORTED and re-run as a new attempt. Nothing stored is
  overwritten.
- **Refusals:** `run` refuses to start in any of these cases:
  - TerraPreserve is not at `terrapreserve-v1.0`;
  - the manifest's SHA-256 is not the pinned
    `665b326a024d295f727cd5648ffc7e0d375b9300584871f238c6bfa48edd2e2d`;
  - any scenario or step hash does not recompute;
  - `DAIL_EXPERIMENT_ROOT` is inside either repository.

## The conditions (C-198)

| Condition | Identity | Scope policy | Promotion policy | What the lineage tracks |
|---|---|---|---|---|
| A, Stateless | evidence | `StatelessScopePolicy(target)` | `stateless_policy(target)` | the repair target only; nothing for a change request (C-205, C-206) |
| B, Stateful Full | evidence | `StatefulFullScopePolicy` | `stateful_full_policy` | the four invariants |
| C, DAIL | evidence | `DailScopePolicy` | `dail_policy` | the four invariants |
| C′, DAIL without identity evidence | `AddressOnlyIdentity` | `DailScopePolicy` | `dail_policy` | the four invariants |

- **Registry:** every condition uses invariant registry v1.1, stored as
  `invariant_registry_version` 2 (C-180, C-203).
- **Open targets:** on a scenario with more than one step after S0 (F8), the repair target is an
  open target on every step but the last (C-196).
- **Early termination:** a trajectory stops at the first decision other than PROMOTE, and the
  remaining steps are recorded as TRUNCATED (C-200).
- **Promotion switch:** automatic promotion is enabled only in the harness's own copy of the
  configuration, by the reviewed file `experiments/config/promotion.toml` (C-207). `config/` keeps
  it off in every environment.

## Where output goes (Doc 13 §41)

```text
$DAIL_EXPERIMENT_ROOT/experiment/<experiment_id>/
  definition/experiment.json      the definition and its pins (Doc 13 §5, §46)
  fixtures/fixtures.json          the scenario and step hashes (§40)
  trials/<trial_id>/events.jsonl  the lifecycle (§7), append-only
  trials/<trial_id>/attempts/<n>/
    store/dail.sqlite             the attempt's own DAIL store (C-202)
    baseline/ generation/ analysis/ verification/ decision/ metrics/
    result.json                   the trial result, with no wall-clock time
    timing.json                   the §6 Trial record with its wall-clock times
```

## Blinding and the test split

- **Labels:** trial execution never reads TerraPreserve labels. The loader gives execution only
  these fields:
  - the scenario id, family, split and template id;
  - the step directories and their hashes;
  - the target's kind and invariant id;
  - the protected invariants;
  - the endpoints;
  - the primary variable values.

  `tests/contract/test_experiment_blinding.py` fails if any module here names `labels`,
  `gt_class`, `oracle`, `mutation_record`, `intent` or `variable_values_alt`. Labels are used only
  for scoring, which is P8b.
- **Test split:** the loader refuses `split = "test"`. The test split, `$TERRAPRESERVE_PRIVATE` and
  the test ids are not read before P10, after the protocol is frozen.
