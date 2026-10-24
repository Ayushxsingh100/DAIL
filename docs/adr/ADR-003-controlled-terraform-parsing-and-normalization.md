# ADR-003: Controlled Terraform parsing and normalization

**Status:** Accepted for the parsing half (C-91 to C-94, 24 Oct 2026, P3a-1). The normalization half is added by P3a-2.

**Context.** Doc 02 §26 names this ADR "Terraform CLI plus controlled normalization layer", and Doc 04 §4 says the Terraform CLI "may be used as an authoritative structural tool where appropriate" while "DAIL's normalized semantic model remains the internal representation used by the research core". Every later engine (identity, dependency, impact, verification) consumes what `core/terraform_model` produces, so this layer is the base of the safety argument.

**Decision (deviation from the ADR title).**

1. The Terraform CLI is used only as a structural tool **outside** the core: CI runs `terraform fmt`, `init -backend=false` and `validate` on every fixture root (C-86). The core and its tests never call it.
2. The core uses its own standard-library parser for the full HCL native syntax (C-91). Rejected alternatives: `python-hcl2`, which would need an exception to rule R7 (ADR-002), and Terraform CLI JSON output, which overlaps the independent oracle's input path (plan JSON, C-75; ADR-010) and so would remove the diversity between DAIL and the oracle.
3. **Parse widely, support narrowly.** The parser accepts the whole native expression grammar. Syntax that DAIL cannot evaluate is still valid HCL; P3a-2 classifies it as unresolved or UNSUPPORTED. A syntax error means the input is not valid HCL. The two are never confused.

**Pinned HCL specification.**

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
- Only `*.tf` files directly in the given directory are read, in byte-wise sorted filename order.

**Consequences.**

- Fidelity risk: a grammar rule that differs from Terraform's own parser could accept invalid input or reject valid input. Mitigations: hand-written conformance cases whose expected trees come from the spec text, CI `terraform validate` on every fixture, and a planned cross-check on a TerraDS sample (P3a-2 or D3). Spec ambiguities and the differences found against Terraform 1.15.8 are recorded in `DECISIONS_REGISTER.md` (C-95); further Terraform structural rules and block types in C-96; the raw-byte file hash in C-97.
- What `OK` means in P3a-1: valid HCL, valid structure for the rules of C-94 and C-96, inside the input subset and limits. It does not mean that Terraform would accept the configuration: the rules listed as not enforced in C-96 are left to later work and to the CI `terraform validate` of the fixtures.
- Pure Python is slow on large modules; the limits bound the cost.
- The immutable syntax tree and the `ParseOutcome` that wraps it are the only inputs to P3a-2. `OK` is a trust claim, so `ParseOutcome` and `ParsedConfiguration` can be built only by the loader.

**Revisit when.** The pinned HCL or Terraform version changes; a Terraform-accepted configuration is rejected in practice; or the oracle's input path (C-75) is decided in a way that makes a shared reader acceptable.
