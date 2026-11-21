"""The frozen experiment protocol v1 (P10d Step 5): ``docs/PROTOCOL_v1.json`` and its rendering
``docs/PROTOCOL_v1.md``.

``build_protocol`` computes the pins from the code (versions, the code hashes of the extractor and
of the statistics package, the TerraPreserve manifest pin, the prompt hash, the model pins of the
experiment's k = 3 track and the Terraform versions) and takes the pre-freeze outcomes of P10d-1 and
P10d-2 from the dev dry run (``docs/P10D_DEV_DRY_RUN.json``). ``render_protocol`` writes the
Markdown from that JSON and the fixed text below. ``tests.unit.test_p10d_protocol`` checks that the
Markdown is the rendering of the JSON and that the pinned code is the current code: a change to
frozen code after the freeze fails it, which makes the change a visible deviation from the
protocol.

The protocol cannot name its own commit; the DAIL commit it freezes is the commit tagged
``protocol-v1`` (the user creates the tag after the verdict and the advisor's sign-off).
"""

from __future__ import annotations

import hashlib
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
PROTOCOL_VERSION: Final = "protocol-v1"
EXPERIMENT_MODELS: Final = (
    "model-qwen2.5-coder-7b-sample",
    "model-granite-3.3-8b-sample",
    "model-phi4-mini-3.8b-sample",
)
CRLF, LF = b"\r\n", b"\n"


def code_hash(packages: Sequence[str]) -> str:
    """The pin hash of ``tests.unit.test_p10a_extractor_version`` over the given packages: SHA-256
    of the path-sorted lines ``<path>:<sha256 of the file with CRLF read as LF>``."""
    found = []
    for package in packages:
        base = REPO_ROOT / package
        for p in base.rglob("*"):
            if p.is_file() and "__pycache__" not in p.parts and p.suffix in (".py", ".json"):
                data = p.read_bytes().replace(CRLF, LF)
                found.append(
                    f"{p.relative_to(REPO_ROOT).as_posix()}:{hashlib.sha256(data).hexdigest()}"
                )
    return hashlib.sha256("\n".join(sorted(found)).encode("utf-8")).hexdigest()


def pins() -> dict[str, Any]:
    from core.domain.registry_v1_1 import REGISTRY_VERSION_V1_1
    from experiments.loader import MANIFEST_SHA256, TERRAPRESERVE_TAG
    from experiments.metrics.extractor import EXTRACTOR_VERSION, METRICS_VERSION
    from experiments.scoring.identity import load_identity_table
    from experiments.stats.dry_run import ANALYSIS_VERSION
    from experiments.terraform_validate import AWS_PROVIDER, AWS_VERSION, TERRAFORM_VERSION
    from llm.prompts.templates import PROMPT_VERSION, template_hash
    from llm.validation.parser import PARSER_VERSION
    from llm.validation.patch import VALIDATOR_VERSION

    models = tomllib.loads(
        (REPO_ROOT / "experiments" / "config" / "models.toml").read_text(encoding="utf-8")
    )["model"]
    return {
        "dail_commit": "the commit tagged protocol-v1 (the commit that holds this file)",
        "registry": f"registry-v1.1 (stored invariant_registry_version {REGISTRY_VERSION_V1_1})",
        "terrapreserve_tag": TERRAPRESERVE_TAG,
        "terrapreserve_manifest_sha256": MANIFEST_SHA256,
        "tp_l1_labels_commit": "4b2d84a69a8cadd2f87574b277efe67dac10b654",
        "prompt_version": PROMPT_VERSION,
        "prompt_template_hash": template_hash(PROMPT_VERSION),
        "llm_parser_version": PARSER_VERSION,
        "patch_validator_version": VALIDATOR_VERSION,
        "metrics_version": METRICS_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "extractor_code_sha256": code_hash(("experiments/metrics", "experiments/scoring")),
        "identity_truth_version": load_identity_table().version,
        "analysis_version": ANALYSIS_VERSION,
        "stats_code_sha256": code_hash(("experiments/stats",)),
        "terraform": TERRAFORM_VERSION,
        "aws_provider": f"{AWS_PROVIDER} {AWS_VERSION}",
        "models": {
            key: {
                k: models[key][k]
                for k in ("tag", "digest", "quantization", "temperature", "top_p", "seed",
                          "max_output_tokens", "num_ctx", "timeout_seconds")  # fmt: skip
            }
            for key in EXPERIMENT_MODELS
        },
        "sampling": "k = 3; temperature 0.7, top_p 0.95, seed rule seed + k - 1 (C-225, C-222)",
    }


def build_protocol(dry_run: Mapping[str, Any]) -> dict[str, Any]:
    cov = dry_run["coverage"]
    return {
        "protocol_version": PROTOCOL_VERSION,
        "pins": pins(),
        "pre_freeze": {
            "source": "docs/P10D_DEV_DRY_RUN.json (DEV DRY RUN, NOT RESULTS)",
            "dry_run_experiment_id": dry_run["experiment_id"],
            "icc_dev": dry_run["icc"],
            "rho_analysis": dry_run["rho_analysis"],
            "coverage_decision": cov["decision"],
            "coverage_reps": dry_run["coverage_reps"],
            "seed": dry_run["seed"],
        },
    }


HYPOTHESES = (
    "> **H1:** DAIL misses fewer regressions than stateless, target-only verification. **H2:** "
    "DAIL needs less verification work than full re-verification with a non-inferior "
    "missed-regression rate. **H3** (exploratory): on restructuring (F5), identity-aware "
    "handling makes fewer identity and transition errors than address-only handling and needs "
    "less work on moves (address-only sees a deletion plus a creation, adding a baseline check "
    "where the type has one), without more missed regressions; covering moves, `count` "
    "re-indexing and SG-`name` replacement. **H4** (descriptive): DAIL blocks candidates that fix "
    "the target but violate a protected invariant. These are hypotheses, not findings."
)

SECTIONS_BEFORE_PINS = """## 2. Conditions (as built: C-198, C-205, C-206, C-197, C-210)

All four conditions use the same verifiers, the same orchestrator and the same promotion
controller; they differ only in identity evidence and in the scope of verification.

- **A, Stateless:** evidence identity; work = the gate items (STRUCTURAL, CONSISTENCY) and the
  repair target's invariant item, or the gate items only for `change_request` scenarios (C-197);
  the required set is exactly those items; no ledger use, no carry-forward. A's lineage tracks
  only what A requires (C-205); a `change_request` baseline holds no invariant (C-206).
- **B, Stateful Full:** evidence identity; work = the gate items, every invariant on the current
  state and every RESOURCE baseline item of the impact work set; carry-forward off.
- **C, DAIL:** evidence identity, `DailScopePolicy`, carry-forward on; the work is the impact work
  set plus an invariant item for every invariant that is not PROTECTED in the parent (U_t, C-210).
- **C′, DAIL without identity evidence (H3, C-20):** `AddressOnlyIdentity`, otherwise as C.

Comparisons: A–C (H1, H4), B–C (H2), C–C′ on F5 (H3).

## 3. Candidates

- **Reference track (primary).** TerraPreserve v1.0's 96 test targets, each step a fixed patch
  admitted by its content hash (C-201). In a multi-step (F8) scenario the repair target is an open
  target on every step but the last (C-196). A trajectory stops at the first decision other than
  PROMOTE; later steps are recorded TRUNCATED (C-200).
- **LLM track (secondary, descriptive, C-228).** Three local models, pinned by digest (section 8);
  k = 3 candidates per model per scenario (C-224) with the sampling of C-225; prompt
  `dail-repair-prompt-3` (C-223); the patch validator `dail-patch-validator-3`, which runs the
  pinned `terraform validate` (C-227); scope = every S0 address, every supported type, all four
  operations (C-220); repair scenarios only (C-219); generated only on the authors' machine with
  the local Ollama server (C-218). No hypothesis rests on it.

## 4. Metrics: `metrics-final-1` (extractor `extractor-5`)

Every proportion carries its numerator and denominator and a Wilson 95% interval; a denominator of
0 gives no value. Truth comes only from TerraPreserve's oracle labels, read only by
`experiments/scoring/`.

**Per transition** (P8b's `metrics-draft-1`, unchanged): unsafe = some invariant FAIL in the step's
truth other than an open target; regression = an invariant PASS in the parent's truth and FAIL in
the step's; unsafe promotions per promotion and per evaluated transition; regressions and missed
regressions per regression; false rejections per safe transition; decision rates; UNKNOWN and
UNSUPPORTED per required check; TRUNCATED per transition; work by kind (gate; invariant items from
impact, from the condition's scope policy, and U_t items; applicable and not-applicable baseline
items), W = gate + invariant + applicable baseline, total, mean and median per transition; Save(C
vs B) on the common prefix of B and C; impact precision and recall (micro) and truth-change
coverage for C and C′; every promoted unsafe transition under C listed with its trace; the
populations `all` and `common_prefix_all` (the sensitivity analysis).

**Per scenario** (new in `metrics-final-1`):

- **Missed regression (MR, C-232, C-239).** An unsafe scenario (class `unsafe`) with a
  regression-inducing step (a step whose candidate makes an invariant FAIL that holds in the parent
  by the oracle) is *caught* under X only if X evaluated its first regression-inducing step and did
  not PROMOTE it; otherwise it is *missed* (X promoted it, or X's trajectory stopped earlier). An
  unsafe scenario with no regression-inducing step is counted apart and is not in MR.
  MR = missed / (caught + missed), on the strata `all`, `kind`, `family` and `tier`.
- **H4 blocked:** an unsafe scenario none of whose unsafe transitions X promoted.
- **Repair success:** every step evaluated and promoted and every invariant PASS at the last step
  (an early termination is a failure).
- **W_{X,s}:** the work of the executed steps, by kind and in total, and per step.

**Agreement and impact:** Cohen's κ per invariant of DAIL's result under B against the truth, over
the PASS/FAIL cells (S0 and every evaluated step), every other cell tabulated apart, computed
before any adjudication (C-237); macro impact precision and recall (per invariant, then the
unweighted mean over the invariants with a non-zero denominator, C-240 (3)); truth recall of I_t
and of V = I_t ∪ U_t on truth_changed (must be 100%; every miss listed, C-240 (6)).

**Identity (H3, identity truth `identity-truth-2`, C-213, C-234):** over the true pairs the table
fixes, with DAIL's UNCERTAIN excluded: the identity error rate (a wrong correspondence) and the
transition error rate (a change type other than the expected one, the move flag included:
MOVE → MODIFIED with `moved`, REPLACE → REPLACED, CREATE → CREATED, DELETE → DELETED; C-240 (1));
the UNCERTAIN share of all pairs; the evidence-transfer error rate (a true replacement kept as the
same object while a required invariant was carried forward, over true replacements; C-240 (2));
excluded pairs counted; on `all` and per family (H3 reads F5); the work difference C′ − C on F5 by
moved resource type.

**LLM track (C-240 (5)):** per generation and model, valid after the gate / attempts; over
validate-valid candidates the oracle class and each condition's decisions by class; any-unsafe@k
(scenarios with at least one validate-valid unsafe candidate / scenarios attempted) and, per
condition, any-unsafe-promoted@k.

## 5. The statistical plan (paper §IV-H; C-231, C-235 to C-241)

- **Population:** the test split, 96 scenarios (48 unsafe). MR strata: 12 target-bearing (F4, F8)
  and 30 change-request (F1, F3, F5, F6, F7) unsafe scenarios with a regression-inducing step
  (C-239); the 6 unsafe F2 scenarios are counted apart. Clusters are templates (controlled) or
  lineages (real-world).
- **Clusters (C-243):** The H1 strata tests and the H2 workload test pool the clusters of both
  tiers and are inferential whatever the number of clusters. For each stratum, the smallest
  two-sided p-value the exact sign test can reach with its number of discordant clusters is
  reported beside the result. Results reported per tier with fewer than 10 clusters are
  descriptive.
- **H1** (A vs C), per stratum: the exact cluster sign test, two-sided, on the cluster MR
  differences, each cluster weighted equally (exact McNemar for single-scenario clusters);
  α = 0.05, Holm across the two strata. Also the scenario-weighted MR difference with Newcombe's
  (1998) paired score interval, method 10, each cell of the paired table divided by
  DEFF = 1 + [(1 + CV²) m̄ − 1] ρ.
- **H2 workload (confirmatory):** the one-sided exact sign test (α = 0.05) on the cluster mean
  per-scenario W_C − W_B over all test scenarios, estimating P(cluster favours C | non-zero
  difference); n₊, n₋, n₀ and the median are reported; also on the common prefix.
- **H2 non-inferiority (exploratory, C-231):** the one-sided 95% upper limit of MR_C − MR_B (the
  upper end of the nominal 90% interval above) against δ_NI = 0.05. With 42 MR scenarios even no
  miss under either condition (DEFF = 1) gives z²/(n + z²) ≈ 0.061 > 0.05: the test cannot pass.
- **H3:** descriptive (C vs C′ on F5), the metrics of section 4.
- **H4:** blocked unsafe F4 test scenarios / all unsafe F4 test scenarios under C, Wilson 95%.
- **Also:** unsafe-promotion and false-rejection rates; repair success; impact precision and
  recall, micro and macro; truth recall of I_t and V; W per scenario by kind; the common-prefix
  sensitivity analysis; the LLM track, descriptive.
- **ρ (P10d-2, C-236, C-241 (5)):** the dev ICC of the paired MR outcome is reported; the ρ in
  DEFF is the dev estimate of the paired C − B outcome if it is defined and not negative, else
  0.30.
- **Coverage rule (P10d-1, C-235, C-238):** the coverage of the one-sided 95% upper limit is
  simulated for ρ ∈ {0, 0.05, 0.10, 0.20, 0.30} on the dev cluster sizes and on the test cluster
  sizes; if it falls below 0.93 at any ρ, the stratum's scenario-weighted MR intervals are reported
  as descriptive only and no inferential claim is drawn from them. Before the freeze the test sizes
  are public bounds (C-238); at unblinding the frozen code computes the actual sizes and applies
  the rule before any outcome is read.
- **Power (C-242):** the H1 and H2 power simulations on dev data are reported (power 0.80,
  clustering, H1 effect 0.10, Holm) as a description of the design. They do not change any test's
  status. A significant confirmatory result is reported as significant. A non-significant one is
  reported as inconclusive, never as evidence of no difference.
- **κ and adjudication (C-237):** κ is computed by the extractor before any adjudication;
  Krishika adjudicates the disagreements blind to condition, on the test split after the run.

## 6. Inclusion and exclusion

Every trial is run and every failed, interrupted or truncated trial stays visible in the records
and the report, with its reason. No outlier is removed. Scenarios are TerraPreserve's v1.0 targets
as frozen; the exclusions are TerraPreserve's (D6), listed in its datasheet.

## 7. Stopping rule

An unsafe promotion under C is a defect (Doc 13 §37): it is reported with its trace, and it is a
finding about DAIL, never removed from the results.
"""

UNBLINDING = """## 9. Unblinding

1. The user tags the commit that holds this protocol `protocol-v1`, after the external verdict and
   the advisor's sign-off. Nothing in sections 2 to 8 changes afterwards; a change is a deviation,
   recorded in the decisions register and reported.
2. One run on the test split, from `$TERRAPRESERVE_PRIVATE`, on the tagged commit, with the pins of
   section 8.
3. Before any outcome is read, the frozen code computes the actual test MR cluster sizes and runs
   the coverage simulation and rule of section 5 on them (C-238); the outcome per stratum is
   recorded.
4. The extractor computes κ before any adjudication; the analysis runs once; nothing is tuned
   afterwards.
"""

DEVIATIONS: Final[tuple[tuple[str, str], ...]] = (
    (
        "C-177",
        "Moves carry a flag (`moved = true` on a MODIFIED or REPLACED pair) instead of a "
        "MOVED change type; every move counts as a change.",
    ),
    (
        "C-196",
        "Open targets: the repair target of an F8 scenario is open on every step but the "
        "last, so a promoted F8 middle step keeps the target VIOLATED.",
    ),
    (
        "C-178, C-203",
        "Registry v1.1 (INV-SEC-001/002 version 2, stored version 2) with C-150 "
        "closed in P6d; the paper describes registry v1.0 and C-150 as open.",
    ),
    (
        "C-197",
        "O_tgt is empty for every `change_request` scenario (F1, F3, F5, F6, F7), not for F1, "
        "F5 and F7.",
    ),
    (
        "C-205, C-206",
        "A tracks only the target: its lineage registers only the repair target's "
        "definition, and a `change_request` baseline holds no invariant.",
    ),
    (
        "C-219, C-224, C-228",
        "The LLM track has k = 3 (not k ∈ {5, 10}), repair scenarios only "
        "(S0 of the 36 test repair scenarios), and is secondary and "
        "descriptive.",
    ),
    (
        "C-71",
        "The oracle is implemented: Terraform plan JSON only, AWS fully offline (no deployed "
        "sample, no AWS Config, Reachability Analyzer or live TCP).",
    ),
    (
        "C-233",
        "The oracle was not written by a different human author: DAIL and the oracle were "
        "both written by Claude Code from work-package prompts written by the same "
        "assistant, under the authors' direction (ADR-010 deviation).",
    ),
    (
        "D4c-01 (TerraPreserve)",
        "The controlled tier is 33 hand-written templates (23 dev, 10 test), "
        'not TerraGoat fixtures, and not "three templates" in test; there '
        "are no native real-world modules (all real-world scenarios are "
        "grafted hosts).",
    ),
    (
        "C-239",
        "The unsafe strata are 18 target-bearing and 30 change-request scenarios, not "
        '"about 30 and 18"; MR\'s are 12 and 30, because the 6 unsafe F2 scenarios have no '
        "regression-inducing step and are counted apart.",
    ),
    (
        "C-232",
        "A regression-inducing step is judged against the oracle truth of the parent step "
        "(P8b's per-transition regression); on the reference track this is the condition's "
        "snapshot, since a trajectory continues only after a PROMOTE.",
    ),
    (
        "C-235, C-238",
        '"Otherwise use a statistician-approved method" is replaced by a decidable '
        "rule (coverage below 0.93 → descriptive), and the test cluster sizes are "
        "public bounds until unblinding.",
    ),
    (
        "C-236, C-241 (5)",
        "The ICC is estimated on all dev clusters (23 templates and the dev "
        'lineages), not "seven controlled development templates"; it is '
        "undefined on dev (no miss under B or C), so the analysis puts ρ = 0.30 "
        "into DEFF.",
    ),
    (
        "C-231",
        "H2 non-inferiority is exploratory from the start: with 42 MR test scenarios the "
        "best case already exceeds δ_NI.",
    ),
    (
        "C-200",
        "In the reference track a trajectory stops at the first decision other than "
        'PROMOTE (the paper\'s "a patch that no longer applies ends the trajectory" is for '
        "the LLM track).",
    ),
    (
        "C-240 (1)",
        "Identity and transition errors, which the paper names but does not define, "
        "are defined as in section 4.",
    ),
    (
        "C-213, C-234",
        "Identity truth comes from a hand-written table of the operator catalogue "
        "(`identity-truth-2`); 4 operators stay excluded and their pairs are "
        "counted.",
    ),
    (
        "C-231, C-242",
        "Power: the paper's 'underpowered results are exploratory' is applied only to H2 "
        "non-inferiority (C-231, decision 1).",
    ),
)


def render_protocol(protocol: Mapping[str, Any]) -> str:
    p = protocol["pins"]
    pre = protocol["pre_freeze"]
    out = [
        "# DAIL experiment protocol v1",
        "",
        "> Frozen before the test split is opened (P10d). Generated by "
        "`experiments.report.protocol` from `docs/PROTOCOL_v1.json`; the pins are computed from "
        "the code. The DAIL commit is the one the user tags `protocol-v1` after the external "
        "verdict and the advisor's sign-off.",
        "",
        "## 1. Hypotheses (the paper, `DAIL.tex` §IV-A, verbatim)",
        "",
        HYPOTHESES,
        "",
        SECTIONS_BEFORE_PINS,
        "### Pre-freeze outcomes of P10d-1 and P10d-2 (from the dev dry run, not results)",
        "",
        f"Source: {pre['source']}; seed {pre['seed']}, {pre['coverage_reps']} replications per "
        "cell.",
        "",
        "| ICC on dev | B | C | C − B | A − C |",
        "|---|---|---|---|---|",
    ]
    for stratum, row in pre["icc_dev"].items():
        cells = " | ".join(
            "undefined" if row[k] is None else f"{row[k]:.4f}"
            for k in ("B", "C", "C_minus_B", "A_minus_C")
        )
        out.append(f"| {stratum} | {cells} |")
    out += [
        "",
        f"ρ in DEFF: **{pre['rho_analysis']}**.",
        "",
        "| stratum | minimum simulated coverage | where | outcome before the freeze |",
        "|---|---|---|---|",
    ]
    for stratum, d in pre["coverage_decision"].items():
        at = d["at"]
        out.append(
            f"| {stratum} | {d['minimum']:.4f} | {at['config']}, ρ = {at['rho']} | "
            f"**{d['outcome']}** |"
        )
    out += [
        "",
        "At unblinding the rule is applied again on the actual test sizes (section 9).",
        "",
        "## 8. Pins",
        "",
        "| pin | value |",
        "|---|---|",
    ]
    for key, value in p.items():
        if key != "models":
            out.append(f"| {key} | `{value}` |")
    out += ["", "| model pin | tag | digest | settings |", "|---|---|---|---|"]
    for key, m in p["models"].items():
        settings = ", ".join(
            f"{k} {m[k]}" for k in ("quantization", "temperature", "top_p", "seed",
                                    "max_output_tokens", "num_ctx", "timeout_seconds")
        )  # fmt: skip
        out.append(f"| `{key}` | `{m['tag']}` | `{m['digest']}` | {settings} |")
    out += ["", UNBLINDING, "## 10. Deviations from the paper (`DAIL.tex`)", ""]
    for i, (ref, text) in enumerate(DEVIATIONS, 1):
        out.append(f"{i}. **{ref}.** {text}")
    out.append("")
    return "\n".join(out)
