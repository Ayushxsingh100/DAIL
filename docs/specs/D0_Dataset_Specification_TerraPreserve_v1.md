# D0 — Dataset Specification: TerraPreserve v1.0

**Status:** decided, to be frozen before D4 (scenario generation) starts.
**Purpose:** a benchmark of Terraform remediation scenarios where each change is labeled with which protected properties it actually breaks or preserves. It is built by combining TerraGoat, TerraDS and Checkov's rule library, and shaped to DAIL's requirements.

Each decision below lists its reason, so it can be defended in the paper and the viva.

---

## Decision 1 — Name: **TerraPreserve**
*Terraform invariant-preservation benchmark.*
- **Why not "DAIL-Bench":** the name DAIL is already used by **DAIL-SQL**, a well-known 2023 text-to-SQL method, and similar names exist (DIA-Bench, DAIBench). A dataset name that is independent of the method also lets other researchers use it without implying they use DAIL.
- A quick web search found no benchmark with this name. Recheck before release.

## Decision 2 — Size: **320 benchmark scenarios + 15 canonical fixtures**
| Part | Count | Used for |
|---|---|---|
| Canonical fixtures (Tier 1) | 15 | Build tests for P3–P6 (Doc 12 §7). Not counted in experiment results. |
| Benchmark scenarios | 320 = 8 families × 40 | The experiment (P8) and paper results |

- **Why 320:** it matches the scale the paper already describes and the compute budget already estimated ($85–325). It is larger than the closest comparable work (TerraProbe used 96 modules). The test split is ~96 scenarios.
- **Balance inside each family:** 20 scenarios whose change is **safe** and 20 whose change is **unsafe** (per the oracle). Without this balance, false-rejection rate or missed-regression rate would have too few cases to measure.

## Decision 3 — How the sources are combined
Each family's 40 scenarios come from two tiers:

| Tier | Per family | Base state built from |
|---|---|---|
| **Controlled** | 20 | TerraGoat's EC2/RDS/security-group resources, reshaped into the Doc 04 Appendix B topology, with varied parameters (CIDRs, number of subnets, inline vs separate SG rules) |
| **Real-world** | 20 | TerraDS modules filtered to DAIL's 9 supported resource types |

**Grafting (this is the "combining" step):** most real-world modules won't contain a complete EC2 → RDS path. When a TerraDS module lacks it, the canonical EC2/RDS/SG core is grafted into the real module. The scenario is marked `grafted: true`. This keeps real-world context (real naming, real SG and network patterns) while making the functional invariant testable.

**Fallback rule:** if TerraDS yields fewer usable modules than needed, the gap is filled with controlled scenarios, and the **actual** counts are reported. Yields are never assumed or padded.

## Decision 4 — Protected invariants for v1.0 (frozen list)
| ID | Property | Resources | Checkov mapping |
|---|---|---|---|
| INV-SEC-001 | No security-group ingress from `0.0.0.0/0` or `::/0` to port 22 | SG, SG rule | `CKV_AWS_24` (confirmed) |
| INV-SEC-002 | No security-group ingress from `0.0.0.0/0` or `::/0` to database port 5432 | SG, SG rule | Confirm at D1 against pinned Checkov; else custom predicate |
| INV-SEC-003 | `aws_db_instance.publicly_accessible` is false | RDS | Confirm at D1; else custom predicate |
| INV-FUNC-001 | EC2 can reach RDS on TCP/5432 (configuration-level) | EC2, RDS, SG, subnet, route table | Custom (DAIL's reachability checker) |

- **Why four, not two:** with only two invariants, impact precision/recall has too little to measure. **INV-SEC-002 creates the most realistic regression:** an LLM "fixes" a broken database connection by opening port 5432 to the whole internet. That restores INV-FUNC-001 but breaks INV-SEC-002, which is exactly the failure DAIL exists to catch.
- All four use only resources already in Doc 04's supported set.
- **Build impact:** P5 must implement two more simple predicates (SEC-002, SEC-003). This is the one place the dataset adds build work.
- IPv6 (`::/0`) is included from the start, matching the paper's oracle design.

## Decision 5 — The 8 scenario families
| # | Family | What the change does | Safe example | Unsafe example |
|---|---|---|---|---|
| F1 | Unrelated change | Edits attributes outside every invariant's scope | Tag or instance-size change | (Unsafe variants carry a hidden side-effect on a scoped attribute) |
| F2 | Direct impact | Edits a resource named in an invariant's scope | Narrow an SG rule | Widen SSH to `0.0.0.0/0` |
| F3 | Dependency-induced impact | Edits a resource not named in scope but on a dependency path | Move EC2 to an equivalent subnet | Move EC2 to a subnet with no route to RDS |
| F4 | Regression-inducing repair | Composed: `M_fix` repairs the target, `M_break` damages another invariant | Fix SSH only | Fix SSH and break the EC2→RDS rule |
| F5 | Restructuring / replacement | Rename with `moved`, inline rules ↔ separate rule resources, force-replacement, `count`/`for_each` | Semantics-preserving restructure | Restructure that drops a rule |
| F6 | New-resource creation | Adds new resources, triggering baseline checks | New locked-down SG | New SG open on port 22 |
| F7 | Broad impact | Edits a hub resource (VPC, shared SG, route table) | Add an unrelated route | Remove the route the DB path needs |
| F8 | Multi-step remediation | 2–4 ordered patches | All steps preserve invariants | A middle step introduces a regression |

## Decision 6 — What a scenario contains
Every scenario is a **trusted starting state + a remediation target + a labeled reference change**.

- **Base state S0:** must satisfy every protected invariant except the remediation target. For repair families, the target is violated in S0; this matches the paper's canonical example.
- **Remediation target:** the invariant to repair, or a described change request (F1, F5, F7).
- **Reference candidate(s):** the synthetic change produced by the generator. This lets DAIL be tested with **no LLM at all** (Doc 15 milestone M2).
- **LLM candidates** are added later, during P8, on top of the same scenarios.

```
Scenario {
  scenario_id            e.g. tp-v1-F4-0012
  dataset_version        1.0
  family                 F1..F8
  split                  dev | test
  gt_class               safe | unsafe
  source { tier, origin (terragoat|terrads|both), repo_lineage_id,
           commit_or_version, license, grafted: bool }
  target { kind: repair|change_request, invariant_id | description }
  protected_invariants [ {invariant_id, version} ]
  steps [ { step, terraform_dir, content_hash, diff_from_previous } ]   // step 0 = S0
  mutation_record [ {step, operator, target_address, attribute, before, after} ]  // generator only
  labels [ { step,
             invariant_truth { INV-ID: PASS|FAIL|UNKNOWN|UNSUPPORTED },
             oracle_affected [INV-ID],
             target_safe: bool } ]
  oracle { versions, disagreements[] }
}
```

- **Labels are property truth, not DAIL decisions.** Stateless, Stateful-Full and DAIL are all scored against the same labels.
- **Storage:** one folder per scenario, holding full Terraform directories per step (not only diffs), so every step runs with standard Terraform tooling. A `scenario.json` manifest sits alongside them.
- Canonical fixtures keep Doc 12's names (`sg_public_ssh_fail_v1`, …).

## Decision 7 — Split: **70/30 dev/test, by repository lineage**
- Real-world tier: all modules from one repository (including forks and copies) stay on one side.
- Controlled tier: all variants from one template stay on one side.
- Stratified by family × safe/unsafe. This gives about 224 dev and 96 test scenarios.
- **Dev** is used to tune DAIL's traversal and impact rules. **Test** is touched once, for the reported results.

## Decision 8 — Versions: **synthetic v1.0 now, natural v1.1 later**
- **v1.0:** the 320 synthetic scenarios.
- **v1.1:** adds the real LLM-generated candidate patches produced during P8, labeled by the same oracle.
- **Why:** this gives a natural track at **no extra cost**, because the experiment generates those patches anyway. It also answers the "synthetic data is unrealistic" criticism with real LLM behavior.

## Decision 9 — Release: **publish at paper submission**
- **Where:** Zenodo (for a DOI) plus a GitHub repository with the generator code.
- **When:** kept internal until v1.0 is frozen, then released when the paper is submitted, so reviewers can access it.
- **Licenses:** our scenarios and labels are released under CC-BY-4.0. TerraGoat-derived files keep their Apache-2.0 notice. TerraDS-derived files keep **their original repository's license**, recorded per scenario. Only repositories whose license allows modification and redistribution are included.

## Decision 10 — Rules and acceptance gates (checked at D6)
The dataset is frozen only when **all** of these pass:
1. **Independence:** dataset code never imports DAIL's impact, verification or promotion code. An automated test enforces this.
2. **Validity:** every step passes `terraform validate` with the pinned Terraform version.
3. **Base-state check:** S0 satisfies all protected invariants except the target, per the oracle.
4. **Complete labels:** every step has oracle labels for every protected invariant.
5. **No secrets:** a redaction scan finds zero secrets. TerraGoat contains fake credentials on purpose.
6. **No leakage:** no repository lineage appears in both dev and test.
7. **Balance:** each family is within ±2 of its 20/20 safe/unsafe target, or the deviation is reported.
8. **Integrity:** every content hash verifies.
9. **Pinned versions:** Terraform, AWS provider, Checkov, oracle version and generator version are all recorded.

## What D0 does not decide
- How the generator is implemented (D4).
- How the oracle is implemented (D5).
- Which TerraDS repositories qualify. This depends on the D1 download and filtering results.
