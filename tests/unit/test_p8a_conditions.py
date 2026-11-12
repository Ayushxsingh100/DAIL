"""The four P8 conditions (P8a; C-198, C-205, C-206, C-20, C-22, C-127, C-142).

Expected values come from the decided text (C-198):

A, Stateless: "verification work = the gate items (STRUCTURAL, CONSISTENCY) and the repair target's
invariant item, or the gate items only for change_request scenarios; required set = the gate items
and the repair target only; no ledger use, no carry-forward."
B, Stateful Full: "verification work = the gate items, every invariant on the current state and
every RESOURCE baseline item of the impact work set; required set as stateful_full_policy (every
invariant on the state, carry-forward off)."
C, DAIL: "DailScopePolicy unchanged; dail_policy (carry-forward on)."
C', DAIL without identity evidence: "AddressOnlyIdentity (C-127), DailScopePolicy, as C."

C-205: "A current state that holds an invariant outside the explicit set is an ESCALATE
(POLICY_REGISTRY_REGRESSION, C-41), so nothing is dropped silently."
C-206: "only with the flag may the set be empty; every existing caller keeps the 'at least
one' rule."
"""

from __future__ import annotations

import dataclasses
import inspect
import unittest

from core.application.baseline import BaselineRequest
from core.application.orchestrator import EvaluationOrchestrator, ResultKind
from core.application.scope_policy import (
    DailScopePolicy,
    StatefulFullScopePolicy,
    StatelessScopePolicy,
    VerificationScopePolicy,
)
from core.domain.enums import DecisionType
from core.domain.errors import DomainValidationError
from core.domain.impact import WorkPriority, WorkTargetType
from core.domain.promotion import DecisionReason
from core.domain.state import TrustedState
from core.identity.strategy import (
    ADDRESS_ONLY_ALGORITHM_VERSION,
    DEFAULT_STRATEGY,
    IDENTITY_ALGORITHM_VERSION,
    AddressOnlyIdentity,
    EvidenceIdentity,
)
from core.promotion import policy as policies
from core.promotion.decide import decide
from core.promotion.policy import dail_policy, stateful_full_policy, stateless_policy
from tests import impact_builders as ib
from tests.domain_builders import LINEAGE, NORMALIZATION, analyzing_candidate, canonical_resources
from tests.promotion_builders import (
    ALL,
    BASELINE_ITEM,
    DECISION_ID,
    FAIL,
    FUNC1,
    GATES,
    NOW,
    PASS,
    SEC1,
    SEC2,
    SEC3,
    impact_for,
    invariant_definitions,
    record,
    report_of,
    target,
    trusted_state,
)
from tests.promotion_orchestrator_builders import (
    BASELINE_DIR,
    PATCH_REGRESSION_DIR,
    PATCH_SAFE_DIR,
    OrchestratorCase,
    bindings,
    context_for,
    definitions,
)

D = DecisionType
R = DecisionReason


def a_policy(required: tuple[str, ...]):  # type: ignore[no-untyped-def]
    return stateless_policy(
        policy_version="policy-a",
        invariants=invariant_definitions().values(),
        automatic_enabled=True,
        required=required,
    )


class TestStatelessPolicy(unittest.TestCase):
    """The policy constructor of condition A (C-205)."""

    def test_it_differs_from_stateful_full_only_in_the_required_set(self) -> None:
        common = {
            "policy_version": "p",
            "invariants": invariant_definitions().values(),
            "automatic_enabled": True,
        }
        full = stateful_full_policy(**common)
        stateless = stateless_policy(**common, required=(SEC1,))
        self.assertTrue(stateless.explicit_required_set)
        self.assertFalse(full.explicit_required_set)
        self.assertFalse(stateless.carry_forward_enabled)
        self.assertEqual(stateless.extra_required, (SEC1,))
        self.assertEqual(
            dataclasses.replace(stateless, explicit_required_set=False, extra_required=()), full
        )

    def test_the_existing_policies_keep_the_state_required_set(self) -> None:
        for build in (dail_policy, stateful_full_policy):
            with self.subTest(policy=build.__name__):
                made = build(
                    policy_version="p",
                    invariants=invariant_definitions().values(),
                    automatic_enabled=True,
                )
                self.assertFalse(made.explicit_required_set)

    def test_it_is_versioned(self) -> None:
        self.assertEqual(policies.STATELESS_RULES_VERSION, "dail-stateless-1")

    def test_it_refuses_an_id_it_does_not_define(self) -> None:
        with self.assertRaises(DomainValidationError):
            a_policy(("INV-NEW-001",))


class TestStatelessDecision(unittest.TestCase):
    """``decide`` under condition A's policy: gates and the target, nothing else."""

    def world(self, *, ids: tuple[str, ...], results: dict[str, object]):  # type: ignore[no-untyped-def]
        trusted = trusted_state(ids=ids) if ids else empty_state()
        candidate = analyzing_candidate(trusted, canonical_resources(ssh_open=False, db_path=True))
        affected = tuple(i for i in ids if i == SEC1)
        impact = impact_for(trusted, candidate, carry=(), affected=affected)
        definitions = invariant_definitions()
        items = []
        for n, (tid, value) in enumerate(sorted(results.items())):
            definition = definitions[tid.split(":")[1]] if tid.startswith("INVARIANT:") else None
            items.append(record(candidate, tid, value, definition=definition, n=n))  # type: ignore[arg-type]
        return trusted, candidate, impact, report_of(candidate, items)

    def decide(self, world, required: tuple[str, ...]):  # type: ignore[no-untyped-def]
        trusted, candidate, impact, report = world
        return decide(
            candidate, trusted, impact, report, a_policy(required), decision_id=DECISION_ID, now=NOW
        )

    def test_the_target_and_the_gates_are_the_whole_required_set(self) -> None:
        world = self.world(ids=(SEC1,), results={g: PASS for g in GATES} | {target(SEC1): PASS})
        outcome = self.decide(world, (SEC1,))
        self.assertIs(outcome.decision.decision, D.PROMOTE)
        self.assertEqual(
            sorted(c.target_id for c in outcome.decision.required_checks),
            sorted([*GATES, target(SEC1)]),
        )

    def test_a_missing_baseline_item_is_not_required(self) -> None:
        # the impact report owes the baseline item BASELINE_ITEM; condition A does not require it
        world = self.world(ids=(SEC1,), results={g: PASS for g in GATES} | {target(SEC1): PASS})
        self.assertIn(BASELINE_ITEM, {w.target_id for w in world[2].verification_work})
        self.assertIs(self.decide(world, (SEC1,)).decision.decision, D.PROMOTE)
        # the same world under the DAIL policy requires it
        trusted, candidate, impact, report = world
        dail = dail_policy(
            policy_version="p", invariants=invariant_definitions().values(), automatic_enabled=True
        )
        self.assertIs(
            decide(
                candidate, trusted, impact, report, dail, decision_id=DECISION_ID, now=NOW
            ).decision.decision,
            D.REJECT,
        )

    def test_an_invariant_outside_the_set_does_not_decide(self) -> None:
        results = {g: PASS for g in GATES} | {target(SEC1): PASS, target(FUNC1): FAIL}
        outcome = self.decide(self.world(ids=(SEC1,), results=results), (SEC1,))
        self.assertIs(outcome.decision.decision, D.PROMOTE)

    def test_a_fail_of_the_target_rejects(self) -> None:
        results = {g: PASS for g in GATES} | {target(SEC1): FAIL}
        outcome = self.decide(self.world(ids=(SEC1,), results=results), (SEC1,))
        self.assertIs(outcome.decision.decision, D.REJECT)
        self.assertIs(outcome.decision.reason, R.REQUIRED_CHECK_FAILED)

    def test_a_state_invariant_outside_the_set_escalates(self) -> None:
        results = {g: PASS for g in GATES} | {target(SEC1): PASS}
        outcome = self.decide(self.world(ids=ALL, results=results), (SEC1,))
        self.assertIs(outcome.decision.decision, D.ESCALATE)
        self.assertIs(outcome.decision.reason, R.POLICY_REGISTRY_REGRESSION)
        named = {c.target for c in outcome.decision.blocking_conditions}
        self.assertTrue({target(SEC2), target(SEC3), target(FUNC1)} <= named)

    def test_gates_only_on_a_state_with_no_invariant(self) -> None:
        outcome = self.decide(self.world(ids=(), results={g: PASS for g in GATES}), ())
        self.assertIs(outcome.decision.decision, D.PROMOTE)
        self.assertEqual(
            sorted(c.target_id for c in outcome.decision.required_checks), sorted(GATES)
        )

    def test_a_gate_failure_still_rejects(self) -> None:
        outcome = self.decide(
            self.world(ids=(), results={"STRUCTURAL": FAIL, "CONSISTENCY": PASS}), ()
        )
        self.assertIs(outcome.decision.decision, D.REJECT)


def empty_state() -> TrustedState:
    return TrustedState.establish_baseline(
        lineage_id=LINEAGE,
        resources=canonical_resources(ssh_open=True, db_path=True),
        invariant_proofs=[],
        evidence_refs=[],
        normalization_version=NORMALIZATION,
        invariant_registry_version=1,
        now=NOW,
        allow_no_invariants=True,
    )


class TestEmptyBaselineOptIn(unittest.TestCase):
    """C-206: an empty invariant set only with the flag."""

    def test_the_domain_still_refuses_an_empty_baseline_by_default(self) -> None:
        with self.assertRaises(DomainValidationError):
            TrustedState.establish_baseline(
                lineage_id=LINEAGE,
                resources=canonical_resources(ssh_open=True, db_path=True),
                invariant_proofs=[],
                evidence_refs=[],
                normalization_version=NORMALIZATION,
                invariant_registry_version=1,
                now=NOW,
            )

    def test_with_the_flag_the_state_holds_no_invariant(self) -> None:
        self.assertEqual(empty_state().invariant_refs, ())

    def test_the_flag_defaults_to_off(self) -> None:
        signature = inspect.signature(TrustedState.establish_baseline)
        self.assertIs(signature.parameters["allow_no_invariants"].default, False)
        self.assertIs(
            {f.name: f for f in dataclasses.fields(BaselineRequest)}["allow_no_invariants"].default,
            False,
        )

    def test_a_baseline_request_without_definitions_needs_the_flag(self) -> None:
        settings = {
            "baseline_id": "00000000-0000-4000-8000-000000003100",
            "lineage_id": LINEAGE,
            "baseline_dir": BASELINE_DIR,
            "variables": None,
            "definitions": (),
            "bindings": (),
            "context": context_for(0),
            "now": NOW,
            "eligible": True,
        }
        with self.assertRaises(DomainValidationError):
            BaselineRequest(**settings)  # type: ignore[arg-type]
        self.assertEqual(BaselineRequest(**settings, allow_no_invariants=True).definitions, ())  # type: ignore[arg-type]


class TestScopePolicies(unittest.TestCase):
    def setUp(self) -> None:
        self.report = ib.report()  # SEC-001 affected, FUNC uncertain, a baseline item
        self.protected = tuple(ib.registry().values())

    def test_every_policy_has_select_and_a_version(self) -> None:
        for chosen in (DailScopePolicy(), StatefulFullScopePolicy(), StatelessScopePolicy(())):
            with self.subTest(policy=type(chosen).__name__):
                self.assertIsInstance(chosen, VerificationScopePolicy)
                self.assertTrue(chosen.version)
        self.assertEqual(
            len(
                {
                    DailScopePolicy.version,
                    StatefulFullScopePolicy.version,
                    StatelessScopePolicy.version,
                }
            ),
            3,
        )

    def test_dail_is_unchanged(self) -> None:
        self.assertEqual(
            DailScopePolicy().select(self.report, self.protected), self.report.verification_work
        )

    def test_stateful_full_adds_every_protected_invariant(self) -> None:
        work = StatefulFullScopePolicy().select(self.report, self.protected)
        targets = {w.target_id for w in work}
        self.assertEqual(
            targets,
            {f"INVARIANT:{d.invariant_id}:{d.version}" for d in self.protected}
            | {"RESOURCE:aws_internet_gateway.new"},
        )
        for item in self.report.verification_work:  # the impact items are kept as they are
            self.assertIn(item, work)
        for item in work:
            self.assertIs(item.priority, WorkPriority.BLOCKING)
        self.assertEqual(len(targets), len(work))

    def test_stateless_runs_the_target_only(self) -> None:
        work = StatelessScopePolicy((SEC1,)).select(self.report, self.protected)
        self.assertEqual([w.target_id for w in work], ["INVARIANT:INV-SEC-001:1"])
        self.assertIn(work[0], self.report.verification_work)  # impact's own item

    def test_stateless_adds_an_unaffected_target(self) -> None:
        work = StatelessScopePolicy((SEC2,)).select(self.report, self.protected)
        self.assertEqual([w.target_id for w in work], ["INVARIANT:INV-SEC-002:1"])
        self.assertIs(work[0].target_type, WorkTargetType.INVARIANT)
        self.assertNotIn(work[0], self.report.verification_work)

    def test_stateless_with_no_target_runs_nothing_but_the_gates(self) -> None:
        self.assertEqual(StatelessScopePolicy(()).select(self.report, self.protected), ())

    def test_stateless_refuses_a_target_it_has_no_definition_for(self) -> None:
        with self.assertRaises(DomainValidationError):
            StatelessScopePolicy(("INV-NEW-001",)).select(self.report, self.protected)


class TestIdentitySeam(unittest.TestCase):
    def test_the_production_default_is_evidence_identity(self) -> None:
        default = inspect.signature(EvaluationOrchestrator.__init__).parameters["identity_strategy"]
        self.assertIs(default.default, DEFAULT_STRATEGY)
        self.assertIsInstance(DEFAULT_STRATEGY, EvidenceIdentity)


class TestConditionsEndToEnd(OrchestratorCase):
    """The real orchestrator over a database, one condition at a time (canonical fixtures)."""

    def test_c_prime_reports_the_address_only_identity(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(
            self.request(v0, PATCH_SAFE_DIR), identity_strategy=AddressOnlyIdentity()
        )
        assert result.identity is not None
        self.assertEqual(result.identity.algorithm_version, ADDRESS_ONLY_ALGORITHM_VERSION)
        self.assertIs(result.kind, ResultKind.PROMOTED)

    def test_c_reports_the_evidence_identity_by_default(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, PATCH_SAFE_DIR))
        assert result.identity is not None and result.work is not None
        self.assertEqual(result.identity.algorithm_version, IDENTITY_ALGORITHM_VERSION)

    def test_b_verifies_every_invariant(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(
            self.request(v0, PATCH_SAFE_DIR),
            scope_policy=StatefulFullScopePolicy(),
            policy_factory=stateful_full_policy,
        )
        self.assertIs(result.kind, ResultKind.PROMOTED)
        assert result.verification is not None and result.decision is not None
        verified = {r.target_id for r in result.verification.results}
        for d in definitions():
            self.assertIn(f"INVARIANT:{d.invariant_id}:{d.version}", verified)
        self.assertTrue(all(c.source is not None for c in result.decision.required_checks))
        self.assertNotIn(
            "CARRIED_FORWARD", {str(c.source) for c in result.decision.required_checks}
        )

    def test_c_carries_unaffected_invariants_forward(self) -> None:
        v0 = self.baseline().state
        result = self.evaluate(self.request(v0, PATCH_SAFE_DIR))
        assert result.decision is not None
        self.assertIn("CARRIED_FORWARD", {str(c.source) for c in result.decision.required_checks})

    def test_a_checks_only_the_target_and_promotes_a_regression(self) -> None:
        # the regression closes SSH and breaks EC2 -> RDS; A does not require INV-FUNC-001
        sec1 = next(d for d in definitions() if d.invariant_id == SEC1)
        v0 = self.baseline(definitions=(sec1,), bindings=()).state
        self.assertEqual([r.invariant_id for r in v0.invariant_refs], [SEC1])
        result = self.evaluate(
            self.request(v0, PATCH_REGRESSION_DIR),
            scope_policy=StatelessScopePolicy((SEC1,)),
            policy_factory=lambda **kw: stateless_policy(**kw, required=(SEC1,)),
        )
        self.assertIs(result.kind, ResultKind.PROMOTED)
        assert result.verification is not None
        self.assertEqual(
            sorted(r.target_id for r in result.verification.results),
            sorted([*GATES, target(SEC1)]),
        )

    def test_the_same_regression_is_rejected_under_b_and_c(self) -> None:
        for name, options in (
            ("C", {}),
            (
                "B",
                {"scope_policy": StatefulFullScopePolicy(), "policy_factory": stateful_full_policy},
            ),
        ):
            with self.subTest(condition=name):
                self.fresh_database()
                v0 = self.baseline().state
                result = self.evaluate(self.request(v0, PATCH_REGRESSION_DIR), **options)
                self.assertIs(result.kind, ResultKind.REJECTED)

    def test_a_on_a_change_request_runs_the_gates_only(self) -> None:
        v0 = self.baseline(
            PATCH_SAFE_DIR, definitions=(), bindings=(), allow_no_invariants=True
        ).state
        self.assertEqual(v0.invariant_refs, ())
        result = self.evaluate(
            self.request(v0, PATCH_SAFE_DIR),
            scope_policy=StatelessScopePolicy(()),
            policy_factory=lambda **kw: stateless_policy(**kw, required=()),
        )
        self.assertIs(result.kind, ResultKind.PROMOTED)
        assert result.verification is not None and result.state is not None
        self.assertEqual(sorted(r.target_id for r in result.verification.results), sorted(GATES))
        self.assertEqual(result.state.invariant_refs, ())

    def test_bindings_are_unchanged_for_the_other_conditions(self) -> None:
        self.assertEqual(len(bindings()), 1)


if __name__ == "__main__":
    unittest.main()
