# Invariant Registry Specification v1

| | |
|---|---|
| **Status** | DRAFT for review (step 4 of 29), 4 Oct 2026. Becomes normative when merged under `docs/specs/`. |
| **Register** | Implements C-17. Decisions proposed here are listed in §11 (C-64 onward). |
| **Registry version** | `invariant_registry_version = 1`. Every invariant below is `version = 1`. |
| **Readers** | DAIL verifiers (P5), DAIL impact analysis (P4), the TerraPreserve generator (D4), the independent oracle (D5, ADR-010), the paper. |

**Independence rule.** This document must be implementable by someone who has never seen DAIL's code. The TerraPreserve oracle is written only from this document, Terraform semantics and AWS semantics (ADR-010, N-02). Nothing here refers to a DAIL module, class or function.

**Markers.**
- **[PAPER]** marks a semantic choice the paper must state; show these to the advisor.
- **[TO VERIFY AT D1]** marked a Terraform or AWS behaviour not yet confirmed against the pinned Terraform and AWS provider versions. D1 Prompt C resolved every such marker (23 Oct 2026). Each is now **[VERIFIED AT D1: CONFIRMED or CHANGED (item)]**, or **[OPEN AFTER D1: UNRESOLVED (item)]** when it could not be settled, with a link to the evidence in `RESOLUTION.md` at a pinned TerraPreserve commit (§12).

**Normative words.** MUST, MUST NOT and MAY are used in the RFC 2119 sense.

---

## 1. Scope and versioning

1.1 **The four invariants.** The registry defines exactly four protected invariants: INV-SEC-001, INV-SEC-002, INV-SEC-003 and INV-FUNC-001. They are the frozen TerraPreserve v1.0 set (D0 Decision 4).

1.2 **Evaluation level.** Every invariant is evaluated at **configuration level, evidence level L1** (Doc 09 §10; C-22). L1 means deterministic predicate evaluation over the resolved Terraform configuration. Nothing in this document is a statement about runtime packet delivery (Doc 04 §9). **[PAPER]**

1.3 **Supported resource types** (Doc 04 §2): `aws_vpc`, `aws_subnet`, `aws_internet_gateway`, `aws_route_table`, `aws_route_table_association`, `aws_security_group`, `aws_security_group_rule`, `aws_instance`, `aws_db_instance`. Every other resource type is *unsupported*. §2.7 says when an unsupported type changes a result.

1.4 **Versioning rule.**
- Any change to an invariant's predicate, scope, footprint (§2.9) or result conditions creates a new invariant version and increments `invariant_registry_version`.
- A change of wording only, with identical results on every input, creates neither.
- The registry is frozen together with D0, before D4 starts.

---

## 2. Common definitions (apply to all four invariants)

### 2.1 Input

The input is one Terraform root-module configuration directory together with the scenario's variable values. It is evaluated with the pinned Terraform and AWS provider versions; ADR-013 requires these pins to be identical in both repositories.

An implementation MAY read HCL directly, or the JSON plan representation (`terraform show -json`). Both MUST yield the resolved values defined in §2.2. The oracle uses a different input path from DAIL (ADR-010). Neither path's convenience may change a result defined here.

### 2.2 Resolved values

An attribute is **resolved** when its value can be determined from the configuration and variable values alone, without provider or AWS knowledge. That covers:
- literals;
- input variables (provided value, else declared default);
- locals;
- functions over resolved values;
- a reference to an argument of another configured resource, where that argument is itself resolved. For example, `aws_subnet.app.cidr_block` resolves to the configured CIDR.

**Identity references.** A reference to a resource's `id` (for example `aws_security_group.db.id`) is resolved **as a reference**. It identifies the configured resource instance it names, not a concrete AWS ID.

**External literal IDs.** A literal AWS ID that names no configured resource (for example `"sg-0123abcd"`) is an **external reference**.

**Unresolved.** Anything else is **unresolved**: data-source attributes, provider-computed attributes that are not set in the configuration, and variables without a value.

**Modules.** Resources in local child modules (path sources) are evaluated as if inlined, using their full module address. A resource whose instances come from a non-local module source (registry, git, URL) is **unresolved**.

### 2.3 Resource instances

**Expansion.**
- A resource with a resolved `count` or `for_each` expands to its instances (`addr[0]`, `addr["key"]`).
- A `dynamic` block with a resolved `for_each` expands to its blocks.
- When expansion is unresolved, the number of instances or blocks is unknown. The resource or block is **indeterminate**.

**Moves.**
- Explicit `moved` blocks MUST be followed when comparing two configurations.
- Terraform's implicit move when `count` is added to or removed from a single-instance resource MUST be followed too. [VERIFIED AT D1: CONFIRMED (V10): Terraform 1.15.8 moves `x` to `x[0]` when `count` is added and `x[0]` back to `x` when `count` is removed. It does not move implicitly into or out of `for_each`, or between `count` and `for_each`; those need `moved` blocks. [RES V10][d1-res]. New fact recorded as C-76.]
- There is no implicit move into or out of `for_each`, or between `count` and `for_each`. Such a change is a delete and a create unless a `moved` block says otherwise. [DECIDED 24 Oct 2026: C-76. No predicate changes.]

### 2.4 Result values and combination

Results are PASS, FAIL, UNKNOWN, UNSUPPORTED and VERIFIER_ERROR, with Doc 09 §4 meanings:
- UNKNOWN means the required facts exist in the supported model but are unresolved.
- UNSUPPORTED means the facts depend on a construct outside the supported model (Doc 04 §17).
- An implementation that throws, times out or produces malformed output MUST return VERIFIER_ERROR for that invariant evaluation (Doc 09 §37). It MUST NOT return any other value.
- UNKNOWN, UNSUPPORTED and VERIFIER_ERROR are never PASS.

Each invariant section defines how its sub-results combine, because existential and universal predicates combine differently.

### 2.5 CIDRs and protocols

**CIDRs.**
- IPv4 and IPv6 CIDRs are parsed strictly. A CIDR that is syntactically invalid, or has host bits set, makes the rule containing it UNSUPPORTED. [VERIFIED AT D1: CONFIRMED (V08): `terraform validate` rejects host-bit and malformed IPv4 and IPv6 CIDRs in `aws_security_group_rule`, in inline `aws_security_group` rules and in `aws_vpc.cidr_block`. [RES V08][d1-res].]
- Order and duplicates inside CIDR lists never matter (Doc 04 §8.1).
- "Covers" means set containment of address ranges. A list of CIDRs covers a range R when the union of the listed ranges contains R.

**Protocols.** `protocol` is compared case-insensitively. [VERIFIED AT D1: CONFIRMED (V09): upper-case values are accepted; the plan JSON shows the normalised lower-case name (`-1` for all, a name for a protocol number). [RES V09][d1-res]. See C-75.] It canonicalises as:

| Configured value | Canonical | Ports |
|---|---|---|
| `"-1"`, `"all"` | ALL | every port; `from_port`/`to_port` ignored |
| `"tcp"`, `"6"` | TCP | `[from_port, to_port]`, inclusive |
| `"udp"`, `"17"` | UDP | not TCP |
| `"icmp"`, `"1"` | ICMP | not TCP |
| `"icmpv6"`, `"58"` | ICMPV6 | not TCP |
| any other number | that protocol | not TCP |

For TCP, `from_port > to_port` makes the rule UNSUPPORTED.

`permits_tcp(r, p)` is true when protocol(r) = ALL, or when protocol(r) = TCP and `from_port ≤ p ≤ to_port`.

### 2.6 Canonical security-group rule set

AWS security groups contain **allow rules only**; there are no deny rules. [VERIFIED AT D1: CONFIRMED (V11): Amazon VPC User Guide, "Security group rules": "You can specify allow rules, but not deny rules." [RES V11][d1-res].] Adding a rule can only widen what a group permits. §3 and §6 depend on this.

**Rule sets.** For each configured `aws_security_group` instance *g*:
- `In(g)` is *g*'s inline `ingress` blocks, plus every `aws_security_group_rule` with `type = "ingress"` whose `security_group_id` resolves to a reference to *g*.
- `Out(g)` is the same for `egress`.

**A canonical rule *r*** carries:
- protocol;
- port range;
- `v4(r)` (`cidr_blocks`);
- `v6(r)` (`ipv6_cidr_blocks`);
- `src_sg(r)`: the security-group references in the inline `security_groups`, or in `source_security_group_id`;
- `self(r)`;
- `pl(r)` (`prefix_list_ids`).

**Indeterminate rules.** A rule is *indeterminate* when:
- its protocol or ports are unresolved;
- any source list is unresolved;
- it has a non-empty `pl(r)` (prefix-list contents are not in the configuration);
- or it comes from an indeterminate resource or block (§2.3).

**Unresolved targets.** An `aws_security_group_rule` whose `security_group_id` is external or unresolved belongs to a pseudo-group keyed by that value: the literal ID, or `UNRESOLVED:<rule address>`.

**MIXED groups.** A group *g* is **MIXED** when it has at least one inline rule block (ingress or egress) and is also the target of at least one `aws_security_group_rule`. The provider documents that combining the two forms on one group causes conflicting rule management, so the applied rule set is not determined by the configuration. [VERIFIED AT D1: CONFIRMED (X01): provider documentation v6.53.0 (`security_group`, `security_group_rule`): combining inline rules with `aws_security_group_rule` "may cause rule conflicts, perpetual differences, and result in rules being overwritten". [RES X01][d1-res].]

**Default egress.** When Terraform creates a security group inside a VPC, it removes AWS's default allow-all egress rule. `Out(g)` is therefore exactly what the configuration declares, and may be empty. This comes from the provider's `aws_security_group` documentation (note on egress rules). [VERIFIED AT D1: CONFIRMED (V06): the note is in the v6.53.0 documentation and the create function revokes the default IPv4 and IPv6 egress rules. Documentary evidence only; this cannot be observed without `apply`. [RES V06][d1-res].]

### 2.7 Unsupported constructs

A resource type outside §1.3 changes a result only if it appears in the invariant's **relevant-unsupported list**. Every other unsupported type is declared irrelevant to that invariant. This is an explicit modelling assumption, and the paper must state it as a limitation. **[PAPER]**

| Invariant | Relevant-unsupported types (presence anywhere in the configuration) |
|---|---|
| INV-SEC-001, INV-SEC-002 | `aws_vpc_security_group_ingress_rule`, `aws_default_security_group`, `aws_vpc_security_group_rules_exclusive` |
| INV-SEC-003 | none |
| INV-FUNC-001 | `aws_vpc_security_group_ingress_rule`, `aws_vpc_security_group_egress_rule`, `aws_default_security_group`, `aws_network_interface`, `aws_network_interface_attachment`, `aws_network_interface_sg_attachment`, `aws_network_acl`, `aws_network_acl_rule`, `aws_network_acl_association`, `aws_default_network_acl`, `aws_route`, `aws_default_route_table`, `aws_main_route_table_association`, `aws_vpc_ipv4_cidr_block_association`, `aws_vpc_peering_connection`, `aws_ec2_transit_gateway_vpc_attachment`, `aws_vpc_endpoint`, `aws_vpc_security_group_rules_exclusive`, `aws_vpc_security_group_vpc_association`, `aws_vpn_gateway_route_propagation`, `aws_vpc_route_server_propagation`, `aws_default_subnet`, `aws_default_vpc`, `aws_vpc_peering_connection_accepter`, `aws_vpc_peering_connection_options`, `aws_ec2_transit_gateway_vpc_attachment_accepter` |

[VERIFIED AT D1: CHANGED (V12, heuristic): the lists are not shown to be complete. A keyword heuristic over the 1,678 resource types of provider 6.53.0 lists candidates the authors must decide on before the freeze, for example `aws_vpc_security_group_rules_exclusive`, `aws_vpc_security_group_vpc_association`, `aws_vpn_gateway_route_propagation`, `aws_vpc_route_server_propagation` and `aws_default_subnet`. [RES V12][d1-res].] [DECIDED 24 Oct 2026, C-74: the candidates were added as shown. The routing and VPC types join INV-FUNC-001 only; `aws_vpc_security_group_rules_exclusive` joins all three security-group lists because it removes rules the configuration does not list. The lists remain a heuristic result, not a proof of completeness. Over-approximation is intentional: UNSUPPORTED never passes.] **[PAPER]**

**Tolerated type.** `aws_db_subnet_group` is tolerated, not relevant, under C-15 and §6.2. RDS placement is taken from the RDS security groups' VPC, and the subnet group's subnets are not modelled. The evidence MUST record this assumption.

### 2.8 Configurations with errors

If the configuration fails `terraform validate` with the pinned versions, every invariant is UNSUPPORTED. A configuration Terraform rejects is outside the model. D0 Gate 2 keeps such configurations out of TerraPreserve; this rule covers LLM candidates.

### 2.9 Footprint and relevance (used by N-04 impact metrics)

Two configurations (parent and candidate) are compared instance by instance, after following moves (§2.3), on **resolved** attribute values.

**Changed elements.** A footprint element is *changed* when any of these holds:
- it is created or deleted;
- its resolved value differs;
- it is resolved on one side and unresolved on the other, or unresolved on both. Unresolved values are treated as changed.

**Footprint.** An invariant's **footprint** is the set of elements listed in its section (§3.5, §5.4, §6.6). A change is **relevant** to an invariant when it changes at least one element of that invariant's footprint.

**Completeness property.** If an invariant's result differs between parent and candidate, at least one footprint element MUST have changed. A counterexample is a registry defect that must be fixed before D6 (Part B, A2).

### 2.10 Evidence requirements (all invariants)

Every result MUST produce a Doc 11 §25 `VerificationEvidence` record that carries:
- **subject identity:** `invariant_id` and `invariant_version`. This settles the design question in C-62; P5 implements it;
- `verifier_id` and `verifier_version` (§10);
- `evidence_level = "L1"`;
- the content hash of the evaluated configuration;
- the result, and for INV-SEC-001/002 the result of each clause;
- the observations listed in the invariant's section;
- an `assumptions` list naming every modelling assumption the evaluation relied on (for example `"C-15: RDS VPC from security groups"`, `"default network ACL assumed"`).

**Supersession.** Evidence for one subject never supersedes evidence for another. Supersession requires equal `invariant_id`, `invariant_version` and `verifier_id` (C-62).

---

## 3. INV-SEC-001: no public ingress to TCP/22

3.1 **Identity.** `INV-SEC-001`, version 1. Name: "No public SSH ingress". Category SECURITY.

3.2 **Statement.** No security group in the configuration admits TCP port 22 from the entire IPv4 internet, or from the entire IPv6 internet.

3.3 **Predicate.** The predicate is `PIP(22)`, the public-ingress predicate for port *p*, with two clauses:

```
For each security group g (configured groups and pseudo-groups):
  D(g)   = { r in In(g) : r determinate and permits_tcp(r, p) }
  IPv4 clause: violates4(g) := union of v4(r) over r in D(g) covers 0.0.0.0/0
  IPv6 clause: violates6(g) := union of v6(r) over r in D(g) covers ::/0
  possible4(g) := exists indeterminate r in In(g) that could permit TCP/p
                  (its protocol or ports unresolved, or they permit p) and whose
                  IPv4 sources are unresolved or include a prefix list.
                  possible6(g) is the same for IPv6 sources.
```

**Scope.** Every configured `aws_security_group` instance, plus every pseudo-group, whether or not any instance or database uses it. **[PAPER]**
- Doc 09 §8 scopes the predicate to rules "relevant to the protected workload". This registry is stricter on purpose. It matches D0's F6 unsafe example (a new SG open on port 22) and Checkov's per-group check.
- Because of this, a change to which security groups an instance uses does not change this invariant's result.

**What counts as public.** Doc 09 §8 says "0.0.0.0/0 or equivalent public IPv4 scope". This registry makes that precise:
- The source CIDRs of one group's port-*p* rules count as public **when together they cover** `0.0.0.0/0`. A split such as `0.0.0.0/1` plus `128.0.0.0/1` therefore FAILs. **[PAPER]**
- Narrower public ranges (for example a single `/8`) are not violations in v1.
- Coverage split across two different groups is not detected in v1.

3.4 **Results.** First compute the result of each clause:

| Condition (evaluated in this order) | Clause result |
|---|---|
| Some group *g* has `violates(g)` (and *g* is not MIXED) | FAIL |
| Some group is MIXED, some ingress rule is UNSUPPORTED (§2.5), or a relevant-unsupported type (§2.7) is present | UNSUPPORTED |
| Some group has `possible(g)` | UNKNOWN |
| Otherwise | PASS |

Then the invariant result:
- **FAIL** if either clause FAILs, because a single violating rule cannot be undone by other allow-only rules;
- otherwise **UNSUPPORTED**, then **UNKNOWN**, then **PASS**, taking the worst clause in that order;
- **VERIFIER_ERROR** overrides all of the above (§2.4).

The evidence reports the IPv4 and IPv6 clauses separately (C-13).

**Observations to record:**
- for each FAIL: the group, the contributing rule addresses, their CIDRs and port ranges;
- the MIXED groups;
- the indeterminate rules, with the reason for each;
- the relevant-unsupported resources found;
- the number of groups evaluated.

3.5 **Footprint.**
- `aws_security_group`: existence, and every field of each inline `ingress` block (`from_port`, `to_port`, `protocol`, `cidr_blocks`, `ipv6_cidr_blocks`, `prefix_list_ids`, `security_groups`, `self`). Also *whether any inline `egress` block exists*, because it affects MIXED status; the contents of egress blocks are not in the footprint.
- `aws_security_group_rule`: existence, and `type`, `from_port`, `to_port`, `protocol`, `cidr_blocks`, `ipv6_cidr_blocks`, `prefix_list_ids`, `source_security_group_id`, `self` and `security_group_id`.
- The existence of each relevant-unsupported type in §2.7.
- **Not in the footprint:** `vpc_id`, `name`, `name_prefix`, `description`, `tags`, egress contents, and any instance or database security-group attachment.

3.6 **Verifier and evidence.** L1. Verifier `dail.verify.public_ingress`, version `1`, run with parameter `p = 22`.

3.7 **Checkov (advisory only, C-12).**
- `CKV_AWS_24`, "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22". Checkov's policy index lists it for `aws_security_group` and `aws_security_group_rule`.
- Checkov tests a single rule's CIDR, not the union of a group's rules, and has no IPv6 clause here. Disagreements are therefore expected, are recorded, and never change a result.
- [VERIFIED AT D1: CHANGED (V04): Checkov 3.3.30 also scans `aws_vpc_security_group_ingress_rule`, tests `::/0` (but not for that resource), and ignores the protocol unless it is `-1`. The first bullet (resource list) and the words "has no IPv6 clause here" above are affected; both are left as written. [RES V04][d1-res]. See C-73.]

---

## 4. INV-SEC-002: no public ingress to TCP/5432

4.1 **Identity.** `INV-SEC-002`, version 1. Name: "No public PostgreSQL ingress". Category SECURITY.

4.2 **Statement, predicate, results, footprint and evidence.** Identical to §3.2–§3.6 with `p = 5432`. The scope is every security group, not only the database's (D0 Decision 4).

4.3 **Why it exists.** It catches the regression D0 Decision 4 describes: a "repair" that restores INV-FUNC-001 by opening 5432 to the internet.

4.4 **Checkov.** No Checkov policy dedicated to port 5432 was found in the policy listings searched for this draft. [VERIFIED AT D1: CONFIRMED (V02): none; custom predicate only (C-14). No Checkov 3.3.30 check mentions port 5432, and no check distinguishes a public from a private 5432 rule. [RES V02][d1-res].]

---

## 5. INV-SEC-003: RDS instances are not publicly accessible

5.1 **Identity.** `INV-SEC-003`, version 1. Name: "RDS not publicly accessible". Category SECURITY.

5.2 **Statement and predicate.** For every configured `aws_db_instance` instance *d*, `publicly_accessible(d)` is false.
- An absent attribute is false. The provider default is `false`; the provider schema and third-party rule documentation agree. [VERIFIED AT D1: CONFIRMED (V05): `Default: false` in the v6.53.0 source; the plan JSON shows `false` for an unset attribute. [RES V05][d1-res]. See C-75.]
- With zero `aws_db_instance` instances the predicate holds vacuously. The evidence records the count, 0.

5.3 **Results.**

| Condition (in this order) | Result |
|---|---|
| Some instance has resolved `publicly_accessible = true` | FAIL |
| Some instance has an unresolved `publicly_accessible`, or `aws_db_instance` is indeterminate (§2.3) | UNKNOWN |
| Otherwise | PASS |

**Observations:** each instance's address and its resolved value (or the reason it is unresolved).

**Out of scope:** other RDS resource types, such as `aws_rds_cluster_instance`, are not covered by this invariant.

5.4 **Footprint.** `aws_db_instance` existence, and its `publicly_accessible` attribute.

5.5 **Verifier and evidence.** L1. Verifier `dail.verify.rds_public_flag`, version `1`.

5.6 **Checkov (advisory).**
- Candidate: `CKV_AWS_17`. The policy index lists it for `aws_db_instance` as data "not public accessible".
- [VERIFIED AT D1: CONFIRMED (V03): `CKV_AWS_17` inspects `publicly_accessible` and FAILs only on `true`; absent PASSes; an unresolved reference gives no result. It also scans `aws_rds_cluster_instance`. [RES V03][d1-res].]

---

## 6. INV-FUNC-001: EC2 → RDS on TCP/5432 (configuration level)

6.1 **Identity.** `INV-FUNC-001`, version 1. Name: "Application can reach database on TCP/5432". Category FUNCTIONAL.

**Binding.** Each scenario binds two **endpoints** by full instance address:
- the source `S`, an `aws_instance`;
- the destination `D`, an `aws_db_instance`.

For example, `S = aws_instance.app` and `D = aws_db_instance.database`. Endpoints are followed across moves (§2.3).

**[PAPER]** A PASS means the configuration-level prerequisites hold within this model (Doc 09 §9). It does not mean packets flow at runtime.

6.2 **Network model** (C-15, made precise):
- **M1, RDS network context.** `VPC(D)` is the VPC that all of `D`'s security groups (`vpc_security_group_ids`) belong to. RDS subnets are not modelled. `aws_db_subnet_group` is tolerated (§2.7). The assumption, recorded in evidence, is that AWS requires the instance's security groups and its subnet group to be in the same VPC. [OPEN AFTER D1: UNRESOLVED (X02): no AWS RDS page read states the requirement, and AWS documents a Security Group VPC Association feature under which a group can serve resources in other VPCs. M1 stays an uncited assumption. [RES X02][d1-res]. See C-77.] [DECIDED 24 Oct 2026, C-77: M1 stays a recorded assumption. `aws_vpc_security_group_vpc_association` is in INV-FUNC-001's relevant-unsupported list (§2.7), so a configuration using that feature is UNSUPPORTED.] **[PAPER]**
- **M2, EC2 placement.** `VPC(S)` is the `vpc_id` of the configured `aws_subnet` that `S.subnet_id` references.
- **M3, intra-VPC routing.** Routing inside a VPC is the VPC **local route**. AWS documents that the local route cannot be deleted, but **its target can be replaced, and more-specific routes can redirect east–west traffic to a middlebox** (network interface, Gateway Load Balancer endpoint or NAT gateway). Such routing is not modelled. Therefore **any route in any `aws_route_table` of `VPC(D)` whose destination is contained in the VPC CIDR and whose target is not `local` makes the result UNSUPPORTED.** Routes whose destination is wider than the VPC CIDR (for example `0.0.0.0/0` to an internet gateway) never apply to intra-VPC traffic, because the most specific route wins. **[PAPER]**
- **M4, network ACLs.** Network ACLs are not modelled. When no NACL-related type from §2.7 is present, every subnet is assumed to use the default network ACL, which AWS documents as allowing all inbound and outbound traffic. That assumption is recorded in evidence. If any NACL-related type is present, the result is UNSUPPORTED (§2.7).
- **M5, statefulness and protocol.** Security groups are stateful, so only `S`'s egress and `D`'s ingress are evaluated. Only IPv4 is modelled for this invariant.

6.3 **Predicate.** `REACH(S, D, 5432)` holds when all of the following hold:

```
E1  S and D both exist in the configuration.
E2  The listener port: D.port, if set, equals 5432; if D.port is absent, D.engine is
    "postgres". [VERIFIED AT D1: CONFIRMED (V07): AWS CreateDBInstance documents 5432 for RDS for PostgreSQL. The provider sets no default, so the plan JSON shows an unset `port` as unknown. [RES V07][d1-res]. See C-75.]
E3  D has a non-empty, resolved vpc_security_group_ids. Each entry references a configured
    aws_security_group with a resolved vpc_id, and they all share one VPC(D).
E4  S has a resolved subnet_id that references a configured aws_subnet, and VPC(S) = VPC(D).
E5  Some security group of S permits egress to D:
      exists g in SG(S), r in Out(g) with permits_tcp(r, 5432) and
        (src_sg(r) contains a group in SG(D)) or (v4(r) covers CIDR(VPC(D)))
    where SG(S) is S.vpc_security_group_ids.
E6  Some security group of D permits ingress from S:
      exists h in SG(D), r in In(h) with permits_tcp(r, 5432) and
        (src_sg(r) contains a group in SG(S)) or (self(r) and h is in SG(S))
        or (v4(r) covers ADDR(S))
    where ADDR(S) = S.private_ip/32 if resolved, else the cidr_block of S's subnet.
E7  M3 and M4 hold: no intra-VPC non-local route and no NACL-related type.
```

6.4 **Results.** Evaluate in this order. The first row that applies gives the result:

| # | Condition | Result |
|---|---|---|
| 1 | `S` or `D` is absent (deleted, with no move): the protected endpoint is gone | FAIL |
| 2 | A relevant-unsupported type is present; any route of M3 exists; `S` uses name-based `security_groups`; `D` or `S` has no `vpc_security_group_ids` (default security group not modelled); `S` has no `subnet_id` (default VPC not modelled); any group in `SG(S) ∪ SG(D)` is MIXED; or an engine, port or rule value is UNSUPPORTED (§2.5) | UNSUPPORTED |
| 3 | E2 is definitely false: `D.port` resolves to a value other than 5432, or `port` is absent and `D.engine` resolves to an engine other than `postgres` | FAIL |
| 4 | E3 or E4 fails because a needed value is unresolved, or an endpoint is indeterminate | UNKNOWN |
| 5 | E3 holds and `VPC(S) ≠ VPC(D)` | FAIL |
| 6 | E5 and E6 both hold using determinate rules only | PASS |
| 7 | E5 or E6 does not hold with determinate rules, but an indeterminate rule (including one in a pseudo-group whose target is unresolved) could satisfy it | UNKNOWN |
| 8 | E5 or E6 does not hold, and an egress CIDR **partly** covers `CIDR(VPC(D))`, or an ingress CIDR partly covers `ADDR(S)` | UNKNOWN |
| 9 | Otherwise | FAIL |

**Why rows 7 and 8 return UNKNOWN.** Rules are allow-only (§2.6), so an unresolved rule could only add permission. A FAIL is therefore reported only when no unresolved rule could supply the missing permission. Partial coverage (row 8) cannot be decided because RDS subnets (C-15) and unassigned instance addresses are not modelled. **[PAPER]**

**Observations to record:**
- the evaluated path: `S`, its subnet, `VPC(S)`, `SG(S)`, the egress rule matched, `SG(D)`, the ingress rule matched, `VPC(D)` and the port;
- for each failing row: the reason;
- the `assumptions` list (M1, M4, IPv4 only).

6.5 **Worked cases** (the canonical topology, Doc 04 Appendix B):
- **PASS.** The database group admits TCP/5432 from the app group by reference, and the app group's egress is `-1` to `0.0.0.0/0`.
- **The canonical regression is FAIL.** A candidate removes `app_to_db_5432` while fixing SSH, so row 9 applies.
- **A route edit inside the VPC.** A candidate replaces `0.0.0.0/0 → igw` with nothing. The result is unchanged, because that route is not inside the VPC CIDR (M3).

6.6 **Footprint**, given the bindings `S` and `D` (both parent and candidate values count):
- `S`: existence, `subnet_id`, `vpc_security_group_ids`, `security_groups`, `private_ip`.
- `D`: existence, `vpc_security_group_ids`, `port`, `engine`.
- The `aws_subnet` that `S` references: existence, `vpc_id`, `cidr_block`.
- The `aws_vpc` that `VPC(S)` or `VPC(D)` names: existence, `cidr_block`.
- Each `aws_security_group` in `SG(S) ∪ SG(D)`: existence and `vpc_id`; for `SG(S)`, every field of each egress block; for `SG(D)`, every field of each ingress block; and the presence of inline blocks (MIXED status).
- Each `aws_security_group_rule` whose target is in `SG(S) ∪ SG(D)`, or is unresolved: existence and all rule fields (§3.5).
- Each `aws_route_table` whose `vpc_id` is `VPC(D)`: every route whose destination is contained in that VPC's CIDR, plus the existence of such routes.
- The existence of each relevant-unsupported type (§2.7), and `moved` blocks naming `S` or `D`.
- **Not in the footprint:**
  - routes whose destination is wider than the VPC CIDR;
  - `aws_route_table_association` (no route that could matter depends on it in v1, because M3 checks every route table of the VPC);
  - `aws_internet_gateway`;
  - `publicly_accessible`;
  - instance type, tags and names.

6.7 **Verifier and evidence.** L1. Verifier `dail.verify.reachability_cfg`, version `1`.

6.8 **Checkov.** None. This invariant is a custom predicate (D0 Decision 4).

---

## 7. Spec consistency notes (for the register; not part of the predicates)

7.1 **Doc 04 §7.6** lists `security_group_ids` for `aws_instance`. The provider's VPC-placement argument is `vpc_security_group_ids`; `security_groups` takes names. [VERIFIED AT D1: CONFIRMED (V13): `aws_instance` has no `security_group_ids`; `vpc_security_group_ids` holds IDs and `security_groups` holds names. Doc 04 errata row: C-79. [RES V13][d1-res].]

7.2 **Doc 04 §7.8** lists `security_group_id(s)` as the SG-to-SG source field of `aws_security_group_rule`. The provider argument is `source_security_group_id`. [VERIFIED AT D1: CONFIRMED (V14): `source_security_group_id` is the source; `security_group_id` is required and names the rule's own group. Doc 04 errata row: C-80. [RES V14][d1-res].]

7.3 **Doc 09 §8 versus §3.3.** Doc 09 §8 scopes INV-SEC-001 to the protected workload; this registry uses every group (C-64). Doc 08 §14's example path (security-group change → EC2 → invariant) is therefore not relevant to SEC-001 v1. That path only affects DAIL's impact precision, not safety.

---

## 8. Conformance vectors

Each vector is a minimal configuration difference from the canonical topology. Both DAIL and the oracle MUST reproduce these results. D2 turns them into fixtures.

| # | Invariant | Configuration fact | Expected |
|---|---|---|---|
| S1 | SEC-001 | Inline ingress `tcp 22–22` from `0.0.0.0/0` | FAIL (IPv4) |
| S2 | SEC-001 | Separate rule `protocol "-1"`, ports `0–0`, `0.0.0.0/0` | FAIL |
| S3 | SEC-001 | `tcp 0–65535` from `::/0` only | FAIL (IPv6 clause); IPv4 clause PASS |
| S4 | SEC-001 | One rule `tcp 22` from `0.0.0.0/1` and `128.0.0.0/1` | FAIL |
| S5 | SEC-001 | Same group: rule A `tcp 22` from `0.0.0.0/1`; rule B `tcp 20–30` from `128.0.0.0/1` | FAIL |
| S6 | SEC-001 | Group A `tcp 22` from `0.0.0.0/1`; group B `tcp 22` from `128.0.0.0/1` | PASS (documented v1 limitation) |
| S7 | SEC-001 | `tcp 22` from `10.0.0.0/16` | PASS |
| S8 | SEC-001 | `udp 22` from `0.0.0.0/0` | PASS |
| S9 | SEC-001 | `tcp 22` from `var.ssh_cidr`, which has no value | UNKNOWN |
| S10 | SEC-001 | `tcp 22` with `prefix_list_ids` only | UNKNOWN |
| S11 | SEC-001 | Group with inline ingress and also targeted by an `aws_security_group_rule` | UNSUPPORTED |
| S12 | SEC-001 | A group used by nothing has `tcp 22` from `0.0.0.0/0` | FAIL |
| S13 | SEC-001 | Configuration contains `aws_vpc_security_group_ingress_rule`; nothing else violates | UNSUPPORTED |
| S14 | SEC-002 | The application group opens `tcp 5432` to `0.0.0.0/0` | FAIL |
| R1 | SEC-003 | `publicly_accessible` absent | PASS |
| R2 | SEC-003 | `publicly_accessible = true` | FAIL |
| R3 | SEC-003 | `publicly_accessible = var.public`, with no value | UNKNOWN |
| R4 | SEC-003 | No `aws_db_instance` at all | PASS (vacuous; count 0) |
| F1 | FUNC-001 | Canonical: ingress by SG reference, egress `-1` to `0.0.0.0/0` | PASS |
| F2 | FUNC-001 | `app_to_db_5432` removed | FAIL |
| F3 | FUNC-001 | Ingress `tcp 5432` from `10.0.1.0/24` (the app subnet) | PASS |
| F4 | FUNC-001 | As F3, but `S` moved to a subnet `10.0.3.0/24` in the same VPC | FAIL |
| F5 | FUNC-001 | The app group has no egress at all | FAIL |
| F6 | FUNC-001 | App egress only `tcp 5432` to `10.0.2.0/24`, a database subnet | UNKNOWN (row 8) |
| F7 | FUNC-001 | A route table has `10.0.2.0/24 → network_interface_id` | UNSUPPORTED |
| F8 | FUNC-001 | Route `0.0.0.0/0 → igw` removed | PASS |
| F9 | FUNC-001 | Configuration contains `aws_network_acl` | UNSUPPORTED |
| F10 | FUNC-001 | `D` deleted | FAIL |
| F11 | FUNC-001 | `D.port = 3306` | FAIL |
| F12 | FUNC-001 | `D` has no `vpc_security_group_ids` | UNSUPPORTED |
| F13 | FUNC-001 | Ingress from `10.0.1.0/25`, `S.private_ip` unset | UNKNOWN; with `S.private_ip = 10.0.1.10`: PASS |
| F14 | FUNC-001 | `S` moved to a subnet of a second VPC | FAIL |
| F15 | FUNC-001 | `aws_db_subnet_group` present, all else canonical | PASS, with the assumption recorded |

---

## 9. Footprint summary (input to N-04)

| Invariant | Footprint (§ reference) |
|---|---|
| INV-SEC-001 | §3.5: SG ingress fields, SG-rule fields, inline-egress presence, relevant-unsupported presence |
| INV-SEC-002 | Same as SEC-001 |
| INV-SEC-003 | §5.4: `aws_db_instance` existence and `publicly_accessible` |
| INV-FUNC-001 | §6.6: endpoints, S's subnet, VPC, SG(S) egress, SG(D) ingress, rules targeting them, intra-VPC routes, relevant-unsupported presence, moves |

---

## 10. Verifier identities

| Invariant | DAIL verifier ID | Version | Level |
|---|---|---|---|
| INV-SEC-001 | `dail.verify.public_ingress` (p = 22) | 1 | L1 |
| INV-SEC-002 | `dail.verify.public_ingress` (p = 5432) | 1 | L1 |
| INV-SEC-003 | `dail.verify.rds_public_flag` | 1 | L1 |
| INV-FUNC-001 | `dail.verify.reachability_cfg` | 1 | L1 |

The oracle uses its own IDs under the `tp.oracle.` prefix. Oracle results are L2 (Doc 09 §10) and are research labels only (ADR-010).

---

## 11. Decisions proposed by this document (register rows)

| Proposed ID | Decision | Marker |
|---|---|---|
| C-64 | The SEC public-ingress semantics: every security group is in scope, attached or not (§3.3). "Equivalent public scope" means a group's port-*p* rule CIDRs together cover `0.0.0.0/0` (or `::/0`). Unresolved rules are handled monotonically (§2.6, §3.4). MIXED groups are UNSUPPORTED. | [PAPER] |
| C-65 | Unsupported-construct policy: closed relevant-unsupported lists per invariant; every other type is declared irrelevant (§2.7). | [PAPER] |
| C-66 | INV-FUNC-001 model under C-15: endpoint binding, with absence giving FAIL; the E1–E7 predicate; partial coverage gives UNKNOWN; non-local intra-VPC routes give UNSUPPORTED; default NACL assumed only when no NACL type is present; IPv4 only (§6). | [PAPER] |
| C-67 | `aws_db_subnet_group` is tolerated under C-15, and the canonical topology includes it with two database subnets in two Availability Zones (Part B, A6). This resolves the plan's open item on RDS subnet placement. | |
| C-68 | Evidence subject identity: VERIFICATION evidence carries `invariant_id` and `invariant_version`, and supersession requires equal subject and verifier (§2.10). This settles C-62's design; P5 implements it. | |

---

## 12. Open items

**Resolved at D1 (23 Oct 2026)** against Terraform 1.15.8, AWS provider 6.53.0 and Checkov 3.3.30. Evidence: [RESOLUTION.md at terrapreserve commit `ff70de82622b7d275bbf0f2490f0ce521786246e`][d1-res].
- §2.3: implicit moves for `count` and `for_each`. CONFIRMED (V10); new fact C-76. Decided 24 Oct 2026.
- §2.5: host-bit CIDRs rejected (V08, CONFIRMED); upper-case protocols accepted (V09, CONFIRMED); plan-JSON facts C-75.
- §2.6: allow-only (V11), mixing warning (X01) and default-egress removal (V06): all CONFIRMED.
- §2.7: relevant-unsupported lists. CHANGED (V12, heuristic): candidates for the authors, C-74 and C-78. Decided 24 Oct 2026: the candidates were added to the lists (C-74).
- §5.2: `publicly_accessible` defaults to `false`. CONFIRMED (V05).
- §6.2 M1: RDS security groups and subnet group share a VPC. UNRESOLVED (X02); C-77. Decided 24 Oct 2026.
- §6.3 E2: the postgres default port is 5432. CONFIRMED (V07); the plan JSON shows an unset port as unknown (C-75).
- §3.7: Checkov `CKV_AWS_24` semantics. CHANGED (V04); C-73. §4.4: none, custom predicate only. CONFIRMED (V02). §5.6: `CKV_AWS_17`. CONFIRMED (V03).
- §7.1–7.2: Doc 04 field-name errata. CONFIRMED (V13, V14); C-79 and C-80.
- Oracle input path (D0 amendments A3.4): an offline plan works (V01, CONFIRMED); C-75 lists what is unknown in the plan JSON.

**Advisor confirmation** is needed for the [PAPER] items: §1.2, §2.7, §3.3, §6.1, §6.2 M3, and §6.4 rows 7–8.

[d1-res]: https://github.com/Ayushxsingh100/terrapreserve/blob/ff70de82622b7d275bbf0f2490f0ce521786246e/validation/d1_to_verify/RESOLUTION.md
