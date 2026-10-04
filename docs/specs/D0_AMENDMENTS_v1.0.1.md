# D0 Amendments: TerraPreserve v1.0 → v1.0.1

| | |
|---|---|
| **Status** | DRAFT for review (step 4 of 29), 4 Oct 2026 |
| **Amends** | `D0_Dataset_Specification_TerraPreserve_v1.md` (v1.0). Anything not amended here stands. |
| **Companion** | `docs/specs/INVARIANT_REGISTRY_v1.md`, cited below as "the registry". |
| **Register** | N-03, N-04 and N-08 move to a new status; new rows C-69 to C-72 (C-64 to C-68 come from the registry; A6 is recorded as C-67). |

Each amendment gives a decision and its reason, in D0's style.
- **[PAPER]** marks a change the paper must reflect; show these to the advisor.
- **[ADVISOR]** marks a decision that needs the advisor's agreement.
- **[TO VERIFY]** marks a fact still to be checked, and says when.

---

## Facts verified for this amendment (web, 4 Oct 2026)

| Fact | Source |
|---|---|
| Every VPC route table has a local route for the VPC CIDR that cannot be deleted. **Its target can be replaced**, with a network interface, Gateway Load Balancer endpoint or NAT gateway. **More-specific routes can redirect traffic between subnets to a middlebox.** | AWS VPC User Guide, "Example routing options" (routing for a middlebox appliance), and "Gateway route tables" |
| The most specific matching route wins. | AWS VPC User Guide, "Configure route tables" |
| A default network ACL allows all inbound and outbound traffic. Subnets not explicitly associated with a NACL use the default NACL. | AWS VPC User Guide, "Default network ACL for a VPC"; "Network ACL basics" |
| An RDS DB subnet group must cover at least two Availability Zones. | AWS RDS User Guide, "Working with a DB instance in a VPC"; RDS API `CreateDBSubnetGroup` |
| New AWS accounts created after 15 July 2025 get USD 100 in credits, plus up to USD 100 more for onboarding activities. The **Free account plan** incurs no charges, and ends after six months or when credits run out. | AWS Billing docs, "Explore AWS services with AWS Free Tier" |
| LocalStack ended its Community edition on 23 March 2026. A free **Hobby** plan exists for non-commercial use and is described as equivalent to the old community image. | LocalStack blog, 2026.03.0 release and pricing update |

---

## A1 — N-03: Families F3 and F7 redesigned **[PAPER]**

**Decision.** The D0 v1.0 unsafe examples "Move EC2 to a subnet with no route to RDS" (F3) and "Remove the route the DB path needs" (F7) are withdrawn. They are replaced as follows.

| Family | Safe example | Unsafe example |
|---|---|---|
| F3 Dependency-induced impact | Move EC2 to another subnet of the same VPC whose CIDR is still inside the RDS ingress CIDR. Or change the subnet's tags or Availability Zone. | **CIDR ingress tier only:** move EC2 to a subnet whose CIDR is outside the RDS ingress CIDR, or change the EC2 subnet's `cidr_block` so that it falls outside. *Variant:* move EC2 into a subnet of a second VPC (registry §6.4 row 5). |
| F7 Broad impact | Edit internet routes: add or remove a route whose destination is wider than the VPC CIDR, such as `0.0.0.0/0 → igw` or a route to an external CIDR. Or add an unrelated ingress rule (for example 443 from the VPC CIDR) to a shared hub security group. | Edit a **shared hub security group**: drop its egress rule, or drop its TCP/5432 rule, where the hub group is in SG(S) or SG(D). |

**New controlled-tier parameter.** Each controlled scenario records `rds_ingress_mode ∈ {SG_REF, CIDR}`:
- SG_REF: the RDS group admits TCP/5432 from the application group by reference.
- CIDR: it admits TCP/5432 from the application subnet's CIDR.

F3 unsafe subnet moves require CIDR mode, because under SG_REF a move within the same VPC is always safe. Actual counts per mode are reported, never assumed.

**Reason.** The earlier wording assumed route-table edits can break EC2 → RDS inside one VPC. AWS documents that the local route cannot be deleted, so internet-route edits can never break intra-VPC reachability. That part of N-03 holds.

N-03's other premise, that the local route "cannot be modified", is **not correct**. Its target can be replaced, and more-specific routes can redirect east–west traffic to a middlebox (facts table). Such routing is outside the model: registry §6.2 M3 makes it UNSUPPORTED, never PASS or FAIL. So the generator MUST NOT emit operators that add non-local routes inside the VPC CIDR in v1.0.

Route edits therefore remain **safe** cases, as N-03 intended, and dependency-induced breakage moves to subnet placement and shared groups.

**Effect on D4.** Two operator families are retired: "remove DB route" and "re-associate the subnet to a route table without a path". Three are added: CIDR-mode subnet move, subnet-CIDR edit, and hub-group edit.

---

## A2 — N-04: Impact ground truth **[PAPER]**

Doc 13 §27 defines impact precision and recall and requires "an explicit fixture/oracle methodology". This is it.

**Unit.** One labelled **pair** (*P*, *C*): a parent configuration *P* (the trusted state the candidate was built on) and a candidate configuration *C*. Each pair is evaluated for each protected invariant *i*.

**Two ground-truth sets per pair**, both computed by TerraPreserve tooling and never by DAIL:
- `truth_changed(P, C)` is the set of invariants *i* for which the oracle's result on *C* differs from its result on *P*. Any change of value counts, including PASS → UNKNOWN and FAIL → UNSUPPORTED.
- `oracle_affected(P, C)` (the D0 schema field, now defined) is the set of invariants *i* such that the change from *P* to *C* is **relevant** to *i*. Relevance is the registry's footprint rule (§2.9): at least one element of *i*'s footprint changed.

**DAIL's marked set.** `M(P, C)` is the set of invariants for which DAIL's impact report contains an impacted-invariant record of any status (AFFECTED or UNCERTAIN) and any impact type (DIRECT, DEPENDENCY, IDENTITY, UNCERTAINTY or BASELINE). Each such record causes re-verification.

**Metrics.** Micro-averaged over all (pair, invariant) units. Every metric is reported with its numerator and denominator, per family and overall.

```
impact_recall    = |M ∩ oracle_affected| / |oracle_affected|        (Doc 13 §27)
impact_precision = |M ∩ oracle_affected| / |M|                      (Doc 13 §27)
truth_recall     = |M ∩ truth_changed|   / |truth_changed|          must be 100%
```

- **`truth_recall` below 100% is a DAIL defect, not a measurement.** It means DAIL could carry forward evidence for an invariant whose truth changed. Every miss is reported individually, and the stopping rule (Doc 13 §37) applies.
- When `|M| = 0`, precision is undefined. The count is reported instead of a value.
- Stateful Full marks every invariant, so its precision is the base rate and its recall is trivially 100%. Stateless marks only the target. Both are reported for reference.

**Completeness gate (new D6 gate 10).** For every labelled pair, `truth_changed ⊆ oracle_affected`. A violation means the registry footprint is incomplete. The registry must be fixed, and a new registry version issued, before freeze.

**Pairs beyond the reference trajectory.** In P8, DAIL may reject a step. The next candidate then has a different parent than the reference trajectory assumed. Both sets are functions of (*P*, *C*), not of step numbers. The harness MUST compute them for the pairs that actually occurred, using the same TerraPreserve oracle and footprint tooling. It MUST NOT reuse step-to-step labels for a different parent.

**Cross-check.** The generator's `mutation_record` states what it intended to change. The oracle tooling computes what actually changed. Disagreements are recorded in `oracle.disagreements[]`, and the oracle-side diff is authoritative.

**Schema change (Decision 6).** `labels[]` gains `truth_changed [INV-ID]` and `footprint_hits { INV-ID: [address.attribute] }`. `oracle_affected` keeps its name with the definition above. Labels are given per step for the reference trajectory (parent = previous step).

---

## A3 — N-08: Free of cost **[PAPER] [ADVISOR]**

**A3.1 Budget statement.** D0 Decision 2's reason cites "the compute budget already estimated ($85–325)". That is replaced by: **the project spends USD 0 (N-08).** The paper's cost and compute statements must be updated to match.

**A3.2 LLM candidates (v1.1).** The natural-track candidates of D0 Decision 8 come from **local open-weight models run through Ollama**, or free notebook GPUs. The Gemini free tier is optional (N-08). Model choice and each model's licence are fixed in P7a. The advisor must agree before step 19, because this replaces the paper's paid-API model design.

**A3.3 AWS calibration route (D5 and P9).** One route must be chosen before step 17.

| Option | What it can establish | Cost risk | Trade-offs |
|---|---|---|---|
| **(a) New AWS account on the Free plan** | Real deployment, real security-group and route behaviour, live TCP tests; possibly Reachability Analyzer | None on the Free plan (no charges until upgrade, per AWS) | Six months and the credit cap; which services the Free plan allows [TO VERIFY before step 17: EC2, RDS and VPC Reachability Analyzer eligibility]; sign-up identity and payment verification [TO VERIFY]; strict teardown needed; one account per person, so a second attempt is impossible |
| **(b) Local AWS emulator** (LocalStack Hobby, or MIT-licensed alternatives such as MiniStack, Floci, LocalEmu) | API acceptance and deployability of the configuration only | None | LocalStack Hobby is non-commercial only (whether research use qualifies is [TO VERIFY]), and whether it includes EC2 and RDS is [TO VERIFY]. The alternatives' EC2/RDS claims are third-party and unverified. **Emulators are not known to enforce security-group, route or NACL semantics at packet level, nor to implement Reachability Analyzer [TO VERIFY per tool], so they cannot calibrate INV-FUNC-001.** |
| **(c) Offline only** | Nothing at runtime | None | Requires a stated limitation: labels are model truth under the registry. Validity rests on two diverse implementations (DAIL and the oracle), adjudication, and the hand-checked canonical fixtures. |

**Recommendation.**
- **Commit to (c)** as the baseline, because it is guaranteed USD 0.
- **Take (a) as an optional upgrade** for a small stratified calibration sample, only if the advisor agrees and Free-plan eligibility is confirmed before step 17.
- **Use (b) only** as a deployability smoke test, never as runtime evidence.

**Why.** Only (a) produces L3 evidence (Doc 09 §10). Under (c), D0 Decision 3's "calibrated against AWS" language and the plan's "Reachability Analyzer plus live TCP" calibration must be reworded.

**A3.4 Oracle input path risk.** D5 currently says the oracle reads `terraform show -json <planfile>`. Producing a plan normally needs provider credentials and API calls.
- [TO VERIFY AT D1: whether a plan can be produced offline for these nine types, with mock credentials and the provider's skip flags, without data sources.]
- If it cannot, the oracle's input path changes to a second HCL parser that is not DAIL's. The input path stays different from DAIL's (ADR-010), and N-08 stays satisfied.

---

## A4 — Repository and oracle authorship (records)

**A4.1 ADR-013.** TerraPreserve lives in its own repository. DAIL consumes frozen releases pinned by version and content hash. Terraform and AWS provider pins are identical in both repositories. The 15 canonical fixtures stay in the DAIL repository.

**A4.2 ADR-010.** The oracle:
- is written by a different author from DAIL's verifiers;
- is written only from the registry and from Terraform and AWS semantics;
- never reads DAIL's code, guides or prompts;
- reads Terraform through a different input path (A3.4).

The registry is the **only** artefact the two implementations share. Oracle results are research labels and never feed promotion.

---

## A5 — Protected invariants (Decision 4), confirmed against the registry **[PAPER]**

| ID | Property | Checkov (advisory only, C-12) |
|---|---|---|
| INV-SEC-001 | No group's TCP/22 ingress CIDRs together cover `0.0.0.0/0`, and none cover `::/0` (IPv6 clause reported separately) | `CKV_AWS_24` (single-rule check; differences recorded) |
| INV-SEC-002 | Same for TCP/5432 | None found yet [TO VERIFY AT D1] |
| INV-SEC-003 | `aws_db_instance.publicly_accessible` is false (absent counts as false) | Candidate `CKV_AWS_17` [TO VERIFY AT D1] |
| INV-FUNC-001 | Configuration-level EC2 → RDS TCP/5432, registry §6 | None (custom) |

The scope is every security group, attached or not (registry C-64). Semantics, footprints and conformance vectors are in the registry.

---

## A6 — Canonical topology: RDS subnet group (resolves the plan's open item)

**Decision.**
- Canonical fixtures (D2) and the controlled tier (D4) include `aws_db_subnet_group` with **two database subnets in two different Availability Zones**.
- The registry tolerates the subnet group (§2.7) and does not model its subnets (C-15). This is register row C-67.
- Doc 04 Appendix B's single `aws_subnet.db` becomes `aws_subnet.db_a` and `aws_subnet.db_b`.

**Reason.** AWS requires a DB subnet group covering at least two Availability Zones to place an RDS instance in a custom VPC (facts table). Configurations without one pass `terraform validate` but cannot be deployed. That would make calibration route (a) impossible, and would make the canonical topology unrealistic.

---

## A7 — Safe, unsafe and indeterminate scenarios (Decision 2 balance; Decision 6 `gt_class`) **[PAPER]**

**Decision.** `gt_class` is computed from oracle labels on the reference trajectory, steps 0 to *n*:
- **unsafe:** some step *k* ≥ 1 regresses an invariant (PASS at *k* − 1, and FAIL at *k*), or the final step's remediation target is FAIL.
- **safe:** no step regresses any invariant, the final target is PASS, and every label at every step is PASS or FAIL.
- **indeterminate:** anything else, that is, any UNKNOWN or UNSUPPORTED label. Indeterminate scenarios are **excluded from the 320** and their count is reported per family. The generator replaces them.

For change-request families (F1, F5, F7) there is no target. The "final target" clause is dropped, and safe/unsafe follows from regression alone.

**Reason.** The registry returns UNKNOWN and UNSUPPORTED by design. A scenario with such labels has no safe/unsafe ground truth, so it cannot count toward the 20/20 balance.

**New D6 gate 11.** Per family, report the number of indeterminate scenarios generated and replaced.

---

## A8 — Not changed here

- **N-05** (Condition A on change-request families runs structural checks only) is decided at the protocol freeze. It is referenced, not decided, here.
- Decisions 1, 3, 7, 9 and 10 stand, with gates 10 and 11 added by A2 and A7.

---

## A9 — Register rows proposed

| Proposed ID | Decision | Status after merge |
|---|---|---|
| C-69 | N-03 resolved by A1: F3/F7 redesign, `rds_ingress_mode`, no intra-VPC non-local route operators. **Corrects N-03's premise:** the local route's target can be replaced. | Accepted (pending advisor for paper text) |
| C-70 | N-04 resolved by A2: `truth_changed`, `oracle_affected` defined via the registry footprint, `truth_recall` = 100% rule, pairwise computation, completeness gate 10. | Accepted (pending advisor) |
| C-71 | N-08 dataset route (A3): USD 0 statement, Ollama for v1.1, calibration recommendation (c) with (a) optional. | **Open**: advisor decision before step 17 (calibration) and step 19 (LLM design) |
| C-72 | `gt_class` definition and exclusion of indeterminate scenarios; gate 11 (A7). | Accepted (pending advisor) |

The status of N-03 and N-04 changes to "Resolved by C-69 / C-70 (step 4)". N-08 stays Accepted, and C-71 records the route decisions still open under it.
