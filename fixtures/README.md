# fixtures/

The 20 canonical fixtures of D2 (Doc 12 §5-§7, Doc 04 §15; registry `registry-v1.0`). They are test data: hand-written
Terraform roots plus one hand-derived `expected.json` per fixture. Nothing here is computed by DAIL code.

- **Terraform content** (C-86): resources only, no provider block, no variable values, no secrets. CI runs
  `terraform fmt -check`, `terraform init -backend=false -lockfile=readonly` and `terraform validate` on every root;
  nothing is ever planned or applied. `versions.tf` and `.terraform.lock.hcl` are copies of `infrastructure/terraform/`.
- **Layout.** `fixtures/<category>/<fixture_id>/expected.json`, plus `main.tf`, `versions.tf` and
  `.terraform.lock.hcl` when the fixture has its own configuration. The three canonical fixtures live in
  `canonical_regression/baseline`, `patch_safe` and `patch_regression`. A fixture with the same configuration as another
  has no `.tf` files; its `config` field names the folder that has them (16 roots serve 20 fixtures).
- **IDs** follow Doc 12 §6 and match `^[a-z0-9]+(_[a-z0-9]+)+_v[0-9]+$`. `doc12_fixture` keeps the Doc 12 §7 name.
- **`expected.json`** (schema `dail-fixture-expected/1`, C-89). Every key is required, in the order written by the files:
  `schema, fixture_id, doc12_fixture, kind, registry, config, parent, parent_remediation_targets, bindings, results,
  changes, impact, decision, baseline, process, derivation`. `kind` is `baseline`, `transition` or `process` (C-88).
  A baseline has `parent: null`, `parent_remediation_targets: []`, and `changes`, `impact` and `decision` set to null.
  `decision.allowed` is a set: where Doc 09 §20 and §35-§37 leave the choice to policy, P6 must pick a value inside it.
- **Eligibility** (C-87). A baseline or a parent has results PASS or FAIL only, INV-FUNC-001 PASS, and every FAIL listed in
  its remediation targets. The canonical baseline is public SSH open, with INV-SEC-001 = FAIL as its declared target.
- **Definitions** (lists are sorted; invariant ids are written `INV-SEC-001` and so on):
  - `truth_changed`: the invariants whose result differs from the parent fixture's result (C-70). Process fixtures use
    their nominal results.
  - `oracle_affected`: the invariants whose registry footprint (§2.9; §3.5, §5.4, §6.6) has a changed element (C-70).
  - `required_affected`: `truth_changed` plus every invariant whose footprint **resources** include a resource that is
    not UNCHANGED (Doc 08 §14-§19: modified, created, deleted, replaced and uncertain resources in scope are impact
    sources). P4 must give AFFECTED ⊇ `required_affected`; precision is measured against `oracle_affected`.
- **Checks.** `tests/unit/test_fixture_catalog.py` loads every fixture through `tests/fixture_catalog.py` and checks the
  schema, the enum values, the cross-fixture consistency and the Terraform files. It has negative tests that feed it
  corrupted data.
