# ADR-003: Controlled Terraform parsing and normalization

**Status:** Accepted for the parsing half (C-91 to C-94, 24 Oct 2026, P3a-1). The evaluation half is added by P3a-2 (below, 25 Oct 2026; C-99 to C-111). The normalization half is added by P3a-3 (below; C-112 to C-118).

**Context.** Doc 02 §26 names this ADR "Terraform CLI plus controlled normalization layer", and Doc 04 §4 says the Terraform CLI "may be used as an authoritative structural tool where appropriate" while "DAIL's normalized semantic model remains the internal representation used by the research core". Every later engine (identity, dependency, impact, verification) consumes what `core/terraform_model` produces, so this layer is the base of the safety argument.

**Decision (deviation from the ADR title).**

1. The Terraform CLI is used only as a structural tool **outside** the core: CI runs `terraform fmt`, `init -backend=false` and `validate` on every fixture root (C-86). The core and its tests never call it.
2. The core uses its own standard-library parser for the full HCL native syntax (C-91). Rejected alternatives: `python-hcl2`, which would need an exception to rule R7 (ADR-002), and Terraform CLI JSON output, which overlaps the independent oracle's input path (plan JSON, C-75; ADR-010) and so would remove the diversity between DAIL and the oracle.
3. **Parse widely, support narrowly.** The parser accepts the whole native expression grammar. Syntax that DAIL cannot evaluate is still valid HCL; P3a-2 classifies it as unresolved or UNSUPPORTED. A syntax error means the input is not valid HCL. The two are never confused.

**Pinned HCL specification.** (Terraform 1.15.8 is built with hcl `v2.24.0`, `go.mod` line 36. `hclsyntax/spec.md` is byte-identical at `v2.24.0` and `v2.25.0`, checked 25 Oct 2026 (C-101), so the pin below holds for both.)

| | |
|---|---|
| Repository | `github.com/hashicorp/hcl` |
| Tag | `v2.25.0` |
| Commit | `00057cf06d7b38a3f89e6e54d622eee98322b314` (GitHub API: tag `v2.25.0` is a lightweight tag on this commit) |
| File | `hclsyntax/spec.md` (943 lines) |
| File SHA-256 | `a99da24e075391fd097654dc6bf4da8ed8820d52b282ba9e44612f0f1f6feb14` |
| Checked | 24 Oct 2026. `spec.md` at `v2.25.0` is byte-identical to `spec.md` on `main` (`4a347c448ee961e556dde0fad522a996e04c00c0`) on that day. |

Where Terraform restricts HCL further (top-level block types, labels, meta-arguments), the rule comes from the Terraform 1.15.x language documentation, `hashicorp/web-unified-docs` at commit `fefc7502dba86c70716f0109c324c85829229b2f`, directory `content/terraform/v1.15.x/docs/language/`. Each rule in the code names its page.

**Outcome model (C-92).** `OK`, `INVALID` (Terraform 1.15.8 itself rejects the input: not valid HCL, or a Terraform structural rule from C-94 is broken) and `UNSUPPORTED` (valid Terraform that DAIL does not accept: outside the input subset or limits of C-93). The rule is: INVALID only when Terraform rejects. `INVALID` takes precedence when both occur. Both fail closed: no configuration is returned unless the status is `OK`. Diagnostics carry file, line, column and a rule code. Registry §2.8: every invariant becomes UNSUPPORTED when the outcome is not `OK` (enforced in P5).

**Input subset and limits (C-93).**

- UNSUPPORTED: `*.tf.json` files, override files (`override.tf`, `*_override.tf`), a byte-order mark, a legacy index with an exponent (`.1e3`), and non-UTF-8 bytes in the places where Terraform accepts them (comments; some well-formed-looking sequences in strings). Other non-UTF-8 bytes are INVALID, because Terraform rejects them (C-95).
- Limits: file size above 2 MiB, nesting depth above 64, more than 10,000 blocks per configuration. Exceeding a limit is UNSUPPORTED.
- A byte-order mark is UNSUPPORTED: the pinned spec says "UTF-8 encoded Unicode byte order marks are not permitted", but Terraform 1.15.8 accepts one.
- Only the files that Terraform v1.15.8's directory loader reads are read (hidden files, `~` backups and `#…#` files are skipped; C-98), in byte-wise sorted filename order.

**Consequences.**

- Fidelity risk: a grammar rule that differs from Terraform's own parser could accept invalid input or reject valid input. Mitigations: hand-written conformance cases whose expected trees come from the spec text, CI `terraform validate` on every fixture, and a planned cross-check on a TerraDS sample (P3a-2 or D3). Spec ambiguities and the differences found against Terraform 1.15.8 are recorded in `DECISIONS_REGISTER.md` (C-95); further Terraform structural rules and block types in C-96; the raw-byte file hash in C-97.
- What `OK` means in P3a-1: valid HCL, valid structure for the rules of C-94 and C-96, inside the input subset and limits. It does not mean that Terraform would accept the configuration: the rules listed as not enforced in C-96 are left to later work and to the CI `terraform validate` of the fixtures.
- Pure Python is slow on large modules; the limits bound the cost.
- The immutable syntax tree and the `ParseOutcome` that wraps it are the only inputs to P3a-2. `OK` is a trust claim, so `ParseOutcome` and `ParsedConfiguration` can be built only by the loader.

**Evaluation (P3a-2; C-99 to C-111).** `core/terraform_model` evaluates the parsed tree with the Python standard library only.

1. **Value model (C-102).** `Known`, `Unknown(reason)`, `Unsupported(reason)` and `Ref(address, attribute)`; numbers are exact (`int`, else `Decimal`), never `float`. An operation on an unknown or unsupported operand is unknown or unsupported, unsupported beats unknown, and a collection with an unknown element stays a known collection. An unknown is never replaced by a default.
2. **Evaluator (C-103, C-105).** `evaluate_expression(expression, scope)` is pure and bounded (10,000 steps, 1,000 `for` elements, depth 150). Exactly 25 functions are implemented, each from its Terraform 1.15 page with the page's examples as tests; every other function is `function.not_implemented:<name>`. Terraform errors raised while evaluating are unsupported, never INVALID.
3. **Instances (registry §2.3, §2.6).** `count`, `for_each` and `dynamic` blocks expand to instances with Terraform's canonical addresses; an expansion that cannot be fixed gives one indeterminate resource and no instances. Every argument keeps its form (`ATTRIBUTE`, `BLOCKS`, `DYNAMIC`, `MIXED`; an attribute with a block of one name is INVALID, C-100).
4. **Configuration (C-104, C-92).** `evaluate_configuration` returns a guarded `EvaluationOutcome`. INVALID iff the pinned `terraform validate` (1.15.8, provider 6.53.0) rejects it (C-92 as amended, C-106); errors that Terraform raises only at plan are UNSUPPORTED; UNSUPPORTED for the whole configuration when it has a `module` block, more than 10,000 instances, a scenario value for an undeclared variable, a resource that refers to itself, or a `moved` table that is not well-formed (C-107); per-value `Unknown`/`Unsupported` otherwise. Moves are built and validated, not applied (P3b).
5. **Evidence for Terraform behaviour.** Every behaviour that the documentation does not state was measured on Terraform 1.15.8 in a scratch directory outside the repository (`terraform console`, `validate`, `plan` of the builtin `terraform_data` resource; no credentials, no network). The core and its tests never run Terraform.

What `OK` means after P3a-2: the configuration parsed (P3a-1) and evaluated without an INVALID finding and without a whole-configuration UNSUPPORTED finding. Individual values may still be unknown or unsupported; P5 turns those into UNKNOWN or UNSUPPORTED results. `OK` still does not mean that Terraform accepts the configuration (C-99: the pinned `terraform validate` runs outside the core).

**Normalization (P3a-3; C-112 to C-118).** The last stage of the Doc 04 §4 pipeline turns an `EvaluationOutcome` into `core.domain.resource.Resource` objects, standard library only. `core.terraform_model` imports `core.domain.*` to build them (rule R6) and uses their constructors unchanged.

1. **Pipeline.** supported-resource filtering (C-114) → reference extraction (C-115) → canonical normalization (C-112, C-113) → `Resource[]` with the C-33 fingerprint. The security-group rules are canonicalised once, in `security_rules.py` (C-116), so that an inline block and a separate `aws_security_group_rule` give the same rule.
2. **Complete and stable.** `attributes` encodes every configured argument, so nothing is dropped; unknown and unsupported values stay in the content with their reason. Order that is not semantic (set-typed arguments, set-like blocks, CIDR lists) is sorted; everything else keeps its order (C-112). An unsupported resource type is kept as `UNSUPPORTED`, never normalized as known-safe semantics.
3. **Unresolved values and the fingerprint (C-117).** Two unknowns with the same reason encode identically, so a fingerprint can stay equal while a value is unresolved on both sides. Registry §2.9 treats such an element as changed; P4 must read the views, not fingerprint equality alone.
4. **Versions.** `NORMALIZATION_VERSION = "dail-tf-norm-1"` (C-118) is in every `Provenance`; `parser_version` and `evaluator_version` are too. The **Terraform CLI version is not** in the provenance: the core never runs the CLI. It is pinned in `versions.tf` and CI (C-86) and recorded by the harness (Doc 04 §22).
5. **Time.** The package has no clock. The caller passes `now` and it becomes `Provenance.observed_at`.

**Revisit when.** The pinned HCL or Terraform version changes; a Terraform-accepted configuration is rejected in practice; or the oracle's input path (C-75) is decided in a way that makes a shared reader acceptable.
