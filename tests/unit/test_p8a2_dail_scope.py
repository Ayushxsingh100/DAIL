"""DAIL re-checks every invariant that is not PROTECTED in the parent (P8a-2; C-210, closes C-209;
C-211 reason codes).

Expected values come from the decided text (C-210): "DAIL's verification work for a candidate is the
impact work set plus one invariant item for every invariant whose reference in the parent trusted
state is not PROTECTED (VIOLATED or UNCERTAIN) and that impact did not already list ... It applies
to conditions C and C' (both use DailScopePolicy). These items count as verification work. A
VIOLATED reference is never carried forward (C-159 unchanged)." C-211: condition-added items carry
CONDITION_SCOPE, the U_t items NOT_PROTECTED_IN_PARENT; none carries the
SCOPE_TYPE_CHANGED stand-in.

The canonical baseline holds INV-SEC-001 VIOLATED (public SSH) and the other three PROTECTED. The
"resize" step changes only the application instance's type: it does not touch INV-SEC-001's
security-group footprint.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from core.application.orchestrator import ResultKind
from core.application.scope_policy import (
    DailScopePolicy,
    StatefulFullScopePolicy,
    StatelessScopePolicy,
)
from core.domain.enums import InvariantStatus
from core.domain.impact import ReasonCode, WorkPriority, WorkTargetType
from core.identity.strategy import AddressOnlyIdentity
from tests import impact_builders as ib
from tests.promotion_builders import trusted_state
from tests.promotion_orchestrator_builders import (
    BASELINE_DIR,
    PATCH_SAFE_DIR,
    OrchestratorCase,
)

SEC1, SEC2, SEC3, FUNC1 = "INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"
NOT_PROTECTED = ReasonCode.NOT_PROTECTED_IN_PARENT
CONDITION = ReasonCode.CONDITION_SCOPE


def resized(root: Path, source: Path, name: str) -> Path:
    """``source`` with aws_instance.app resized (nothing else changes)."""
    target = root / name
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("expected.json"))
    main = target / "main.tf"
    text = main.read_text(encoding="utf-8")
    old = 'instance_type               = "t3.micro"'
    assert text.count(old) == 1
    main.write_text(text.replace(old, 'instance_type               = "t3.small"'), "utf-8")
    return target


class TestDailScopePolicySelect(unittest.TestCase):
    def setUp(self) -> None:
        # impact lists INV-SEC-001 (affected) and INV-FUNC-001 (uncertain) and one baseline item
        self.report = ib.report()
        self.protected = tuple(ib.registry().values())

    def refs(self, **statuses: InvariantStatus):  # type: ignore[no-untyped-def]
        wanted = {SEC1: InvariantStatus.PROTECTED}
        wanted.update({k.replace("_", "-"): v for k, v in statuses.items()})
        return trusted_state(wanted).invariant_refs

    def test_it_has_a_new_version(self) -> None:
        self.assertEqual(DailScopePolicy.version, "dail-scope-2")

    def test_a_parent_with_every_invariant_protected_changes_nothing(self) -> None:
        selected = DailScopePolicy().select(self.report, self.protected, parent_refs=self.refs())
        self.assertEqual(selected, self.report.verification_work)

    def test_without_the_parent_it_is_the_impact_work_set(self) -> None:
        self.assertEqual(
            DailScopePolicy().select(self.report, self.protected), self.report.verification_work
        )

    def test_a_violated_invariant_impact_did_not_list_is_added(self) -> None:
        refs = self.refs(INV_SEC_002=InvariantStatus.VIOLATED)
        selected = DailScopePolicy().select(self.report, self.protected, parent_refs=refs)
        added = [w for w in selected if w not in self.report.verification_work]
        self.assertEqual([w.target_id for w in added], ["INVARIANT:INV-SEC-002:1"])
        self.assertIs(added[0].reason, NOT_PROTECTED)
        self.assertIs(added[0].priority, WorkPriority.BLOCKING)
        self.assertIs(added[0].target_type, WorkTargetType.INVARIANT)
        for item in self.report.verification_work:
            self.assertIn(item, selected)
        self.assertEqual(list(selected), sorted(selected, key=lambda w: w.sort_key()))

    def test_an_uncertain_invariant_is_added_too(self) -> None:
        refs = self.refs(INV_SEC_003=InvariantStatus.UNCERTAIN)
        selected = DailScopePolicy().select(self.report, self.protected, parent_refs=refs)
        self.assertIn("INVARIANT:INV-SEC-003:1", {w.target_id for w in selected})

    def test_an_invariant_impact_already_listed_is_not_duplicated(self) -> None:
        # INV-SEC-001 is VIOLATED in the parent and impact lists it: impact's own item stays
        refs = self.refs(INV_SEC_001=InvariantStatus.VIOLATED)
        selected = DailScopePolicy().select(self.report, self.protected, parent_refs=refs)
        self.assertEqual(selected, self.report.verification_work)


class TestReasonCodes(unittest.TestCase):
    def setUp(self) -> None:
        self.report = ib.report()
        self.protected = tuple(ib.registry().values())

    def test_condition_added_items_carry_condition_scope(self) -> None:
        listed = set(self.report.verification_work)
        for policy in (StatefulFullScopePolicy(), StatelessScopePolicy((SEC2,))):
            with self.subTest(policy=type(policy).__name__):
                added = [w for w in policy.select(self.report, self.protected) if w not in listed]
                self.assertTrue(added)
                self.assertEqual({w.reason for w in added}, {CONDITION})

    def test_no_condition_added_item_carries_the_stand_in(self) -> None:
        listed = set(self.report.verification_work)
        refs = trusted_state({SEC2: InvariantStatus.VIOLATED}).invariant_refs
        for policy in (DailScopePolicy(), StatefulFullScopePolicy(), StatelessScopePolicy((SEC3,))):
            selected = policy.select(self.report, self.protected, parent_refs=refs)
            for item in selected:
                if item not in listed:
                    self.assertIsNot(item.reason, ReasonCode.SCOPE_TYPE_CHANGED)


class TestDailEndToEnd(OrchestratorCase):
    def setUp(self) -> None:
        super().setUp()
        self._dirs = tempfile.TemporaryDirectory(prefix="dail-p8a2-")
        self.addCleanup(self._dirs.cleanup)
        self.root = Path(self._dirs.name)

    def status(self, state, invariant_id: str) -> InvariantStatus:  # type: ignore[no-untyped-def]
        return next(r for r in state.invariant_refs if r.invariant_id == invariant_id).status

    def test_an_untouched_violated_invariant_is_verified_and_decides(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, resized(self.root, BASELINE_DIR, "resize")))
        assert result.work is not None and result.decision is not None
        reasons = {w.target_id: w.reason for w in result.work}
        self.assertIs(reasons.get("INVARIANT:INV-SEC-001:1"), NOT_PROTECTED)
        self.assertIs(result.kind, ResultKind.REJECTED)
        self.assertEqual(result.decision.reason.value, "REQUIRED_CHECK_FAILED")  # a fresh FAIL

    def test_the_middle_step_promotes_under_c_and_c_prime(self) -> None:
        for name, options in (("C", {}), ("C'", {"identity_strategy": AddressOnlyIdentity()})):
            with self.subTest(condition=name):
                self.fresh_database()
                v0 = self.baseline().state
                middle = resized(self.root, BASELINE_DIR, f"middle-{len(name)}")
                first = self.evaluate(self.request(v0, middle, open_targets=(SEC1,)), **options)
                self.assertIs(first.kind, ResultKind.PROMOTED)
                assert first.state is not None
                self.assertIs(self.status(first.state, SEC1), InvariantStatus.VIOLATED)
                last = self.evaluate(self.request(first.state, PATCH_SAFE_DIR, n=2), **options)
                self.assertIs(last.kind, ResultKind.PROMOTED)
                assert last.state is not None
                self.assertIs(self.status(last.state, SEC1), InvariantStatus.PROTECTED)

    def test_a_protected_parent_gets_exactly_the_impact_work(self) -> None:
        v0 = self.baseline(PATCH_SAFE_DIR).state
        self.assertTrue(all(r.status is InvariantStatus.PROTECTED for r in v0.invariant_refs))
        result = self.evaluate(self.request(v0, resized(self.root, PATCH_SAFE_DIR, "resize-safe")))
        assert result.work is not None and result.impact is not None
        self.assertEqual(result.work, result.impact.verification_work)
        self.assertIs(result.kind, ResultKind.PROMOTED)

    def test_a_violated_reference_is_still_never_carried(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, resized(self.root, BASELINE_DIR, "carry")))
        assert result.decision is not None
        check = next(
            c for c in result.decision.required_checks if c.target_id == "INVARIANT:INV-SEC-001:1"
        )
        self.assertNotEqual(str(check.source), "CARRIED_FORWARD")
