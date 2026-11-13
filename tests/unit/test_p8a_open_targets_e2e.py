"""Open repair targets through the real orchestrator, commit and database (P8a; C-196).

"An open target ... stays VIOLATED in the new trusted state with the fresh FAIL evidence ... The
last step has no open target, so the target must PASS there ... An open target must be VIOLATED in
the parent (the request is refused otherwise)." The parent is the canonical baseline (INV-SEC-001
VIOLATED: public SSH is open; the other three PROTECTED). The middle step is the baseline with the
application security group's description changed: INV-SEC-001 is affected and still fails.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from core.application.orchestrator import ResultKind
from core.domain.enums import InvariantStatus
from core.domain.promotion import PromotionInputError
from tests.promotion_orchestrator_builders import (
    BASELINE_DIR,
    PATCH_REGRESSION_DIR,
    PATCH_SAFE_DIR,
    OrchestratorCase,
)

SEC1, FUNC1 = "INV-SEC-001", "INV-FUNC-001"


def middle_step(root: Path) -> Path:
    """The baseline with the description of aws_security_group.app changed (SSH still open)."""
    target = root / "middle"
    shutil.copytree(BASELINE_DIR, target, ignore=shutil.ignore_patterns("expected.json"))
    main = target / "main.tf"
    text = main.read_text(encoding="utf-8")
    old = 'description = "Application security group"'
    assert text.count(old) == 1
    main.write_text(
        text.replace(old, 'description = "Application security group, step 1"'), "utf-8"
    )
    return target


class TestOpenTargetsEndToEnd(OrchestratorCase):
    def setUp(self) -> None:
        super().setUp()
        self._dirs = tempfile.TemporaryDirectory(prefix="dail-p8a-")
        self.addCleanup(self._dirs.cleanup)
        self.middle = middle_step(Path(self._dirs.name))
        self.v0 = self.baseline().state

    def status(self, state, invariant_id: str) -> InvariantStatus:  # type: ignore[no-untyped-def]
        return next(r for r in state.invariant_refs if r.invariant_id == invariant_id).status

    def test_without_an_open_target_the_middle_step_is_rejected(self) -> None:
        result = self.evaluate(self.request(self.v0, self.middle))
        self.assertIs(result.kind, ResultKind.REJECTED)
        self.assertEqual(self.current().state_id, self.v0.state_id)

    def test_the_middle_step_promotes_with_the_target_still_violated(self) -> None:
        result = self.evaluate(self.request(self.v0, self.middle, open_targets=(SEC1,)))
        self.assertIs(result.kind, ResultKind.PROMOTED)
        assert result.state is not None and result.verification is not None
        self.assertIs(self.status(result.state, SEC1), InvariantStatus.VIOLATED)
        for other in ("INV-SEC-002", "INV-SEC-003", FUNC1):
            self.assertIs(self.status(result.state, other), InvariantStatus.PROTECTED)
        failed = next(
            r for r in result.verification.results if r.target_id == "INVARIANT:INV-SEC-001:1"
        )
        assert result.evidence_ids is not None
        ref = next(r for r in result.state.invariant_refs if r.invariant_id == SEC1)
        self.assertIn(result.evidence_ids[failed.verification_id], ref.evidence_ids)
        assert result.outcome is not None
        self.assertEqual(result.outcome.evidence.open_targets, (SEC1,))
        self.assertEqual(self.current().state_id, result.state.state_id)

    def test_the_last_step_then_needs_a_pass(self) -> None:
        middle = self.evaluate(self.request(self.v0, self.middle, open_targets=(SEC1,)))
        assert middle.state is not None
        last = self.evaluate(self.request(middle.state, PATCH_SAFE_DIR, n=2))
        self.assertIs(last.kind, ResultKind.PROMOTED)
        assert last.state is not None
        self.assertIs(self.status(last.state, SEC1), InvariantStatus.PROTECTED)

    def test_a_regression_of_a_protected_invariant_still_rejects(self) -> None:
        result = self.evaluate(self.request(self.v0, PATCH_REGRESSION_DIR, open_targets=(SEC1,)))
        self.assertIs(result.kind, ResultKind.REJECTED)
        self.assertEqual(self.current().state_id, self.v0.state_id)

    def test_an_open_target_with_no_fresh_result_blocks(self) -> None:
        # C-196 "a missing result blocks". Since C-210 DailScopePolicy re-checks every VIOLATED
        # invariant, so a scope policy that schedules impact's work only (the work set before
        # C-210) is used here to leave the target without a result: VIOLATED, it cannot carry.
        class ImpactOnly:
            def select(self, report, protected, **_):  # type: ignore[no-untyped-def]
                del protected
                return report.verification_work

        result = self.evaluate(
            self.request(self.v0, BASELINE_DIR, open_targets=(SEC1,)), scope_policy=ImpactOnly()
        )
        self.assertIs(result.kind, ResultKind.REJECTED)
        assert result.decision is not None
        self.assertEqual(result.decision.reason.value, "INSUFFICIENT_EVIDENCE")

    def test_an_unchanged_open_target_is_rechecked_by_dail(self) -> None:
        # C-210: nothing reaches INV-SEC-001, but it is VIOLATED in the parent, so DAIL checks it;
        # its fresh FAIL keeps it VIOLATED and the open target does not block (C-196)
        result = self.evaluate(self.request(self.v0, BASELINE_DIR, open_targets=(SEC1,)))
        self.assertIs(result.kind, ResultKind.PROMOTED)
        assert result.state is not None
        self.assertIs(self.status(result.state, SEC1), InvariantStatus.VIOLATED)

    def test_a_protected_target_is_refused_before_anything_is_stored(self) -> None:
        with self.assertRaises(PromotionInputError):
            self.evaluate(self.request(self.v0, self.middle, open_targets=(FUNC1,)))
        with self.uow() as u:
            self.assertIsNone(u.candidates.get(self.request(self.v0, self.middle).candidate_id))
        self.assertEqual(self.current().state_id, self.v0.state_id)
