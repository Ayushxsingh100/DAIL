# Phase Gate Report

Per Doc 15: "each phase produces testable artifacts and passes an explicit
exit gate before dependent work is considered complete."

## P0 — Bootstrap: PASSED (except items only checkable on GitHub)
- [x] Fresh clone can bootstrap (`scripts/bootstrap.sh`, zero dependencies)
- [x] Unit test command works (`python3 -m unittest discover -s tests`)
- [x] No secrets required for core tests
- [ ] CI runs successfully — workflow written (`.github/workflows/ci.yml`); must be
      pushed to GitHub to be observed green. **Not verifiable in this sandbox.**
- [ ] Main branch protected — GitHub setting; **do this manually**.

## P1 — Domain Foundation: PASSED
- [x] Domain schemas validate — `test_resource`, `test_invariant`, `test_state`
- [x] State lineage tests pass — `test_state`, `test_storage_p1_gate::TestLineage`
- [x] Canonical hashes are stable — `test_hashing`
- [x] Forbidden lifecycle transitions are rejected — `test_invariant`
- [x] Beyond spec: DATA-INT-006 / Doc 05 S.23 immutability enforced by DB triggers,
      attacked with raw SQL in `test_storage_p1_gate::TestImmutability`

## P2 — Evidence Foundation: PASSED
| Exit criterion | Evidence |
|---|---|
| Evidence persists and resolves | `test_evidence_store::TestPersistAndResolve` |
| Hashes verify | `TestHashesVerify` (incl. tamper + missing-payload detection) |
| Lineage queries work | `TestLineageQueries`, `test_p2_gate` |
| Invalidation preserves history | `TestInvalidationPreservesHistory`, `test_p2_gate::test_rejected_candidate_chain` |
| Redaction tests pass | `test_redaction`, `test_structured_log_and_ids`, on-disk secret grep |
| Duplicate events are handled | `TestDuplicateHandling` |

Doc 11 S.51.3 end-to-end chains covered: safe promotion, rejected candidate.
Not yet covered (need later phases): retry, escalation, stale-parent,
verifier-error, LLM-generation-to-promotion chains.

## Test health
128 tests, 0 failures. Mutation check: 4 deliberate safety bugs (proof gate
ignoring validity; proof gate ignoring integrity; INVALID->VALID legal;
redactor disabled) were each caught by the suite.

## Known limitations / to confirm
- Audit event taxonomy is only what was confirmed in Doc 11 S.12 plus 3
  EVIDENCE_* events added here; reconcile against the full S.12 table.
- Validity transition table (models.py) is an interpretation of Doc 11 S.7/32/33.
- mypy/black/ruff are configured but were NOT run here (no network). Run
  `pip install -e ".[dev]"` and fix anything they flag before P3.
- ADR-002/003/004 are proposed defaults awaiting confirmation.
