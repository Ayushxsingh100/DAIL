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

## LLM candidates (P10a)

`experiments/generation/` generates repair candidates with free open-weight models on the local
Ollama server, freezes every attempt, replays the valid ones through DAIL under A, B, C and C′, and
exports them for TerraPreserve's oracle. Everything stays on this machine (C-71, C-218). No label,
`description`, `intent`, `mutation_record` or step after S0 is read
(`tests/contract/test_experiment_blinding.py`, checks (c) and (d)).

```bash
python3.12 -m experiments.generation generate --name p10a-pilot --models KEY,... --per-family 4 --k 1
python3.12 -m experiments.generation replay --name p10a-pilot --replay-name replay-1
python3.12 -m experiments.generation export --name p10a-pilot
python3.12 -m experiments.report pilot --name p10a-pilot --replay-name replay-1 \
    --licence-checks checks.json --doc docs/P10A_MODEL_PILOT
```

- **Scenarios and task (C-219):** repair scenarios only (F2, F4, F8). The model is given S0, the
  fixed task "Repair `<id>`: `<the registry's statement>`. Keep every other protected invariant
  satisfied. Make the smallest change." (`experiments/task_text.py`), and P7's context
  (`build_context`, focus = the target invariant's scope resources).
- **Scope (C-220):** every resource address of S0, every supported type, no attribute restriction,
  all four operations; recorded with every candidate and every replay.
- **Parent:** S0 through the baseline flow with the registry-v1.1 definitions, from a
  configuration-only copy (`*.tf`, `*.tf.json`) of the step directory.
- **Generation:** `llm/adapter/generate.py` only (prompt `dail-repair-prompt-2`, parser 2, validator
  `dail-patch-validator-2`, which refuses a MODIFY that drops the parent's `lifecycle` block, C-221).
  Retry policy `p10a-retry-2`: at most two calls, again only after TRANSIENT_ERROR or
  INVALID_OUTPUT. The seed of repetition k is the pinned seed + k − 1.
- **Switch:** `llm.generation_enabled` is on only in the harness's copy of the configuration, by the
  reviewed `experiments/config/llm.toml` (as C-207 (3) does for promotion); `config/` keeps it off.
- **Models:** pinned in the reviewed `experiments/config/models.toml` by tag, digest, temperature,
  top_p, seed, max_output_tokens, timeout and num_ctx (the budget's context window). A model whose
  installed digest is not the pinned one is refused before anything is written.

```text
$DAIL_EXPERIMENT_ROOT/candidates/<generation_id>/
  definition.json                      what was asked (write once)
  <model>/model.json                   the pin and the installed facts
  <model>/<scenario_id>/<k>/
    records/request-<n>.json           P7's LLMRequest of each call
    records/response-<n>.json          P7's LLMResponse of each call (raw reply redacted)
    patch.tf                           a valid candidate's patch only
    timing.json                        wall-clock time
    attempt.json                       status, failure class and source, parent, scope, hashes
  candidates_manifest.json             every attempt with the SHA-256 of each file
  replay/<replay name>/                one store per candidate and condition; replay.json
  oracle_export/                       the built .tf files per valid candidate; oracle_export.json
  pilot_report/<replay name>/          the pilot report (python -m experiments.report pilot)
```

- **Freezing:** every file is written once. A generation whose manifest exists is frozen and never
  regenerated or edited; an attempt directory without `attempt.json` (an interrupted call) is never
  completed or overwritten. A REGENERATE (Doc 13 §47) is a new name or version, so a new
  `generation_id`.
- **Replay:** each valid candidate is evaluated as a one-step candidate from S0 under every condition
  through `LLMEvaluationRequest`. In the same call the validator rebuilds the directory from the
  frozen reply, the rebuilt tree hash is compared with the frozen one, and the build is deleted. A
  mismatch gets no decision. Invalid attempts are listed as generation failures, never as
  decisions.
- **Export:** for every valid candidate, the built `.tf` files and nothing else, with ids and hashes
  (tree hash and the D4-09 content hash) in `oracle_export.json`. TerraPreserve labels them in its
  own package; DAIL never does.
- **Failure source:** a failed attempt's class is the provider's when there was no reply (a
  connection failure, a timeout, Ollama's 400/404 as UNSUPPORTED), the budget's for
  CONTEXT_INSUFFICIENT, and the model's otherwise (P7a verdict limit 4).
