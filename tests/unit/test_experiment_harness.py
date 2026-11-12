"""The experiment harness: conditions, trials, records, artifacts (P8a; Doc 13 §5-§7, §39-§48, §50,
Appendix A; C-196 to C-206).

Expected values come from the quoted rules, not from a run:

* the conditions (C-198): A requires the gate items and the repair target only (gate items only for
  a change request); B and C require every invariant on the state; C' is C with address-only
  identity. The canonical regression (SSH closed, EC2 -> RDS broken) is therefore REJECTED by B, C
  and C' and PROMOTED by A, which does not require INV-FUNC-001; the safe repair is PROMOTED by
  all four.
* open targets (C-196): on F8 every step but the last has the repair target as an open target, so a
  middle step that leaves SSH open is PROMOTED with INV-SEC-001 VIOLATED, and the last step
  must PASS.
* trajectory (C-200): "After any decision other than PROMOTE at step i < n, steps i+1..n are not
  evaluated and are recorded as TRUNCATED."
* §4.3: harness failure "marks the trial FAILED with the error; it never becomes a decision";
  "re-running the same experiment skips COMPLETED trials, re-runs an unfinished one as a new
  attempt, and never overwrites a stored record"; "running one trial twice gives identical records
  apart from ids, timestamps and durations".
* §4.2: "a test feeds a scenario whose label fields are corrupted and shows that every trial record
  is byte-identical."
* Doc 13 §7: "PLANNED -> INITIALIZED -> EXECUTING -> (FAILED | ABORTED | COMPLETED) -> ANALYZED ->
  INCLUDED." §41: "experiment/<experiment_id>/ definition/ fixtures/ trials/<trial_id>/ { baseline/
  generation/ analysis/ verification/ decision/ metrics/ } report/".
"""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from experiments.definition import (
    Condition,
    ExperimentSpec,
    TransitionError,
    TrialStatus,
    check_transition,
)
from experiments.loader import load
from experiments.runner import (
    ExperimentError,
    Layout,
    plan,
    read_events,
    read_result,
    run_experiment,
)
from tests.experiment_builders import F1, F2, F4, F8, F8_BROKEN, TARGETS, TempDirs, mini_root

A, B, C, CP = Condition.A, Condition.B, Condition.C, Condition.C_PRIME
ALL_CONDITIONS = (A, B, C, CP)
SEC1 = "INV-SEC-001"
CREATED = datetime(2026, 11, 12, 9, 0, tzinfo=UTC)
ENVIRONMENT = {
    "dail_commit": "0" * 40,
    "dail_worktree_clean": "true",
    "terrapreserve_tag": "mini",
    "python": "3.12-test",
    "platform": "test",
}
# Fields every evaluated transition records (§4.3).
TRANSITION_FIELDS = {
    "record",
    "trial_id",
    "correlation_id",
    "condition",
    "scenario_id",
    "step_index",
    "status",
    "admission",
    "parent_state_id",
    "parent_state_hash",
    "candidate_id",
    "candidate_state_hash",
    "open_targets",
    "outcome_class",
    "result_kind",
    "decision",
    "required",
    "work",
    "work_counts",
    "identity",
    "impact",
    "new_state",
    "registry",
}


class Interrupt(BaseException):
    """Stands for a killed process: not an Exception, so the harness does not catch it."""


def spec(conditions: tuple[Condition, ...] = ALL_CONDITIONS, **changes: Any) -> ExperimentSpec:
    settings: dict[str, Any] = {
        "name": "p8a-test",
        "version": "1",
        "protocol_version": "draft",
        "objective": "harness check on the mini scenarios",
        "hypotheses": ("none: a harness check",),
        "conditions": conditions,
    }
    settings.update(changes)
    return ExperimentSpec(**settings)


class HarnessCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dirs = TempDirs()
        self.addCleanup(self.dirs.close)
        self.mini = mini_root(self.dirs.new())
        self.loaded = load(self.mini.root, manifest_sha256=self.mini.manifest_sha256)

    def experiment(self, conditions: tuple[Condition, ...] = ALL_CONDITIONS, loaded: Any = None):  # type: ignore[no-untyped-def]
        return plan(
            spec(conditions), loaded or self.loaded, environment=ENVIRONMENT, created_at=CREATED
        )

    def run_all(  # type: ignore[no-untyped-def]
        self,
        conditions: tuple[Condition, ...] = ALL_CONDITIONS,
        *,
        root: Path | None = None,
        **options: Any,
    ):
        experiment = self.experiment(conditions, options.pop("loaded", None))
        out = root or self.dirs.new()
        summary = run_experiment(experiment, options.pop("data", self.loaded), out, **options)
        return experiment, Layout(out, experiment.experiment_id), summary

    @staticmethod
    def decisions(layout: Layout, trial_id: str) -> list[str | None]:
        result = read_result(layout, trial_id)
        return [
            None if t["decision"] is None else t["decision"]["type"] for t in result["transitions"]
        ]


class TestDefinition(HarnessCase):
    def test_ids_are_deterministic(self) -> None:
        one, two = self.experiment(), self.experiment()
        self.assertEqual(one.experiment_id, two.experiment_id)
        self.assertEqual(one.trial_id(F2, C), two.trial_id(F2, C))
        ids = {one.trial_id(s, c) for s in TARGETS for c in ALL_CONDITIONS}
        self.assertEqual(len(ids), len(TARGETS) * len(ALL_CONDITIONS))
        other = plan(spec(version="2"), self.loaded, environment=ENVIRONMENT, created_at=CREATED)
        self.assertNotEqual(other.experiment_id, one.experiment_id)

    def test_the_definition_has_the_fields_of_doc_13_and_the_pins(self) -> None:
        data = self.experiment().to_dict()
        for key in (
            "experiment_id",
            "name",
            "version",
            "objective",
            "hypothesis",
            "protocol_version",
            "fixture_set",
            "baseline_set",
            "condition_set",
            "repetitions",
            "seed_policy",
            "metrics",
            "stopping_policy",
            "created_at",
            "pins",
        ):
            self.assertIn(key, data)
        pins = data["pins"]
        for key in (
            "dail_commit",
            "terrapreserve_tag",
            "terrapreserve_manifest_sha256",
            "invariant_registry",
            "policies",
            "verifiers",
            "python",
            "platform",
        ):
            self.assertIn(key, pins)
        self.assertEqual(pins["terrapreserve_manifest_sha256"], self.mini.manifest_sha256)
        self.assertEqual(
            pins["invariant_registry"],
            {"tag": "registry-v1.1", "stored_invariant_registry_version": 2},
        )
        self.assertEqual(data["repetitions"], 1)
        self.assertEqual(data["fixture_set"], sorted(TARGETS))
        self.assertEqual(data["condition_set"], ["A", "B", "C", "C_PRIME"])

    def test_the_definition_cannot_change_once_written(self) -> None:
        out = self.dirs.new()
        run_experiment(self.experiment((C,)), self.loaded, out)
        with self.assertRaises(ExperimentError):
            run_experiment(self.experiment((A, C)), self.loaded, out)

    def test_the_lifecycle_of_doc_13(self) -> None:
        S = TrialStatus
        for path in (
            (S.PLANNED, S.INITIALIZED, S.EXECUTING, S.COMPLETED, S.ANALYZED, S.INCLUDED),
            (S.PLANNED, S.INITIALIZED, S.EXECUTING, S.FAILED),
            (S.PLANNED, S.INITIALIZED, S.EXECUTING, S.ABORTED),
        ):
            for before, after in zip(path, path[1:], strict=False):
                check_transition(before, after)
        for before, after in (
            (S.PLANNED, S.COMPLETED),
            (S.COMPLETED, S.EXECUTING),
            (S.FAILED, S.COMPLETED),
            (S.INITIALIZED, S.COMPLETED),
        ):
            with self.subTest(before=before, after=after), self.assertRaises(TransitionError):
                check_transition(before, after)


class TestConditions(unittest.TestCase):
    """One run of every condition on every mini target, shared by the tests of this class."""

    decisions = staticmethod(HarnessCase.decisions)

    @classmethod
    def setUpClass(cls) -> None:
        cls.dirs = TempDirs()
        mini = mini_root(cls.dirs.new())
        loaded = load(mini.root, manifest_sha256=mini.manifest_sha256)
        cls.exp = plan(spec(), loaded, environment=ENVIRONMENT, created_at=CREATED)
        out = cls.dirs.new()
        cls.summary = run_experiment(cls.exp, loaded, out)
        cls.layout = Layout(out, cls.exp.experiment_id)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.dirs.close()

    def test_every_trial_completed(self) -> None:
        self.assertEqual(len(self.summary.statuses), len(TARGETS) * 4)
        self.assertEqual(set(self.summary.statuses.values()), {TrialStatus.COMPLETED})
        self.assertEqual(self.summary.failures, {})

    def test_the_safe_repair_is_promoted_by_every_condition(self) -> None:
        for condition in ALL_CONDITIONS:
            with self.subTest(condition=condition):
                tid = self.exp.trial_id(F2, condition)
                self.assertEqual(self.decisions(self.layout, tid), ["PROMOTE"])

    def test_the_regression_is_promoted_only_by_a(self) -> None:
        expected = {A: ["PROMOTE"], B: ["REJECT"], C: ["REJECT"], CP: ["REJECT"]}
        for condition, decisions in expected.items():
            with self.subTest(condition=condition):
                self.assertEqual(
                    self.decisions(self.layout, self.exp.trial_id(F4, condition)), decisions
                )

    def test_the_change_request_is_promoted_by_every_condition(self) -> None:
        for condition in ALL_CONDITIONS:
            with self.subTest(condition=condition):
                self.assertEqual(
                    self.decisions(self.layout, self.exp.trial_id(F1, condition)), ["PROMOTE"]
                )

    def test_a_multi_step_repair_uses_the_open_target_on_the_middle_step(self) -> None:
        for condition in ALL_CONDITIONS:
            with self.subTest(condition=condition):
                result = read_result(self.layout, self.exp.trial_id(F8, condition))
                first, last = result["transitions"]
                self.assertEqual(first["open_targets"], [SEC1])
                self.assertEqual(last["open_targets"], [])
                self.assertEqual(first["decision"]["type"], "PROMOTE")
                self.assertEqual(last["decision"]["type"], "PROMOTE")
                self.assertEqual(first["new_state"]["invariants"][SEC1]["status"], "VIOLATED")
                self.assertEqual(last["new_state"]["invariants"][SEC1]["status"], "PROTECTED")

    def test_a_rejected_middle_step_truncates_the_rest(self) -> None:
        for condition in (B, C, CP):
            with self.subTest(condition=condition):
                result = read_result(self.layout, self.exp.trial_id(F8_BROKEN, condition))
                first, rest = result["transitions"][0], result["transitions"][1:]
                self.assertEqual(first["decision"]["type"], "REJECT")
                self.assertEqual([t["status"] for t in rest], ["TRUNCATED"])
                self.assertIsNone(rest[0]["decision"])
                self.assertEqual(rest[0]["step_index"], 2)

    def test_condition_a_holds_only_the_target(self) -> None:
        baseline = read_result(self.layout, self.exp.trial_id(F2, A))["baseline"]
        self.assertEqual(sorted(baseline["invariants"]), [SEC1])
        change = read_result(self.layout, self.exp.trial_id(F1, A))["baseline"]
        self.assertEqual(change["invariants"], {})
        for condition in (B, C, CP):
            with self.subTest(condition=condition):
                held = read_result(self.layout, self.exp.trial_id(F2, condition))["baseline"]
                self.assertEqual(
                    sorted(held["invariants"]),
                    ["INV-FUNC-001", "INV-SEC-001", "INV-SEC-002", "INV-SEC-003"],
                )

    def test_baselines_agree_across_conditions(self) -> None:
        # the same S0 under B, C and C' (Doc 13 §50 "baseline consistency")
        held = [read_result(self.layout, self.exp.trial_id(F2, c))["baseline"] for c in (B, C, CP)]
        # state_hash covers the lineage (C-33), and every trial has its own: compare the resources
        self.assertEqual(held[0]["resource_set_hash"], held[1]["resource_set_hash"])
        self.assertEqual(held[1]["resource_set_hash"], held[2]["resource_set_hash"])
        self.assertNotEqual(held[0]["state_hash"], held[1]["state_hash"])
        self.assertEqual(held[0]["invariants"], held[1]["invariants"])
        self.assertEqual(held[1]["invariants"], held[2]["invariants"])
        self.assertEqual(held[0]["invariants"][SEC1]["status"], "VIOLATED")

    def test_work_differs_by_condition(self) -> None:
        def counts(condition: Condition) -> dict[str, int]:
            first = read_result(self.layout, self.exp.trial_id(F2, condition))["transitions"][0]
            return first["work_counts"]

        self.assertEqual(counts(A)["gate"], 2)
        self.assertEqual(counts(A)["invariant"], 1)
        self.assertEqual(counts(B)["invariant"], 4)
        self.assertLessEqual(counts(C)["invariant"], 4)
        a_change = read_result(self.layout, self.exp.trial_id(F1, A))["transitions"][0]
        self.assertEqual(a_change["work_counts"]["invariant"], 0)
        self.assertEqual(a_change["work_counts"]["baseline_applicable"], 0)
        self.assertEqual(a_change["work_counts"]["baseline_not_applicable"], 0)

    def test_c_prime_uses_address_only_identity(self) -> None:
        cp = read_result(self.layout, self.exp.trial_id(F2, CP))["transitions"][0]
        c = read_result(self.layout, self.exp.trial_id(F2, C))["transitions"][0]
        self.assertEqual(cp["identity"]["algorithm_version"], "dail-identity-addr-1")
        self.assertEqual(c["identity"]["algorithm_version"], "dail-identity-1")

    def test_a_transition_records_what_section_4_3_lists(self) -> None:
        result = read_result(self.layout, self.exp.trial_id(F8, C))
        for transition in result["transitions"]:
            self.assertEqual(set(transition), TRANSITION_FIELDS)
            self.assertEqual(transition["correlation_id"], result["correlation_id"])
            self.assertEqual(
                transition["registry"],
                {"stored_invariant_registry_version": 2, "means": "registry-v1.1"},
            )
            self.assertEqual(transition["outcome_class"], "DAIL_OUTCOME")
            self.assertTrue(transition["admission"]["content_hash_matches_manifest"])
            for item in transition["required"]:
                self.assertIn(item["source"], ("VERIFIED", "CARRIED_FORWARD", None))
            for work in transition["work"]:
                self.assertIn("applicable", work)
                self.assertIn(work["origin"], ("impact", "condition", "gate"))
            for pair in transition["identity"]["pairs"]:
                self.assertEqual(
                    set(pair), {"trusted_ref", "candidate_ref", "change_type", "moved"}
                )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertIsNone(result["failure"])

    def test_the_layout_of_section_41(self) -> None:
        root = self.layout.experiment_dir
        self.assertEqual(root.parent.name, "experiment")
        for name in ("definition", "fixtures", "trials"):
            self.assertTrue((root / name).is_dir(), name)
        attempt = self.layout.attempt_dir(self.exp.trial_id(F2, C), 1)
        for name in ("baseline", "generation", "analysis", "verification", "decision", "metrics"):
            self.assertTrue((attempt / name).is_dir(), name)
        definition = json.loads((root / "definition" / "experiment.json").read_text("utf-8"))
        self.assertEqual(definition["experiment_id"], self.exp.experiment_id)

    def test_the_lifecycle_events_of_a_completed_trial(self) -> None:
        events = read_events(self.layout, self.exp.trial_id(F2, C))
        self.assertEqual(
            [e["status"] for e in events], ["PLANNED", "INITIALIZED", "EXECUTING", "COMPLETED"]
        )


class TestFailures(HarnessCase):
    def test_a_harness_failure_marks_the_trial_failed_and_is_no_decision(self) -> None:
        experiment = self.experiment((C,))
        broken = experiment.trial_id(F2, C)

        def hook(trial_id: str, stage: str) -> None:
            if trial_id == broken and stage == "step-1":
                raise RuntimeError("injected harness fault")

        out = self.dirs.new()
        summary = run_experiment(experiment, self.loaded, out, hook=hook)
        layout = Layout(out, experiment.experiment_id)
        self.assertIs(summary.statuses[broken], TrialStatus.FAILED)
        self.assertIn("injected harness fault", summary.failures[broken])
        result = read_result(layout, broken)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["failure"]["class"], "HARNESS_FAILURE")
        self.assertEqual(result["transitions"], [])
        others = {t for t in summary.statuses if t != broken}
        self.assertEqual({summary.statuses[t] for t in others}, {TrialStatus.COMPLETED})

    def test_an_input_failure_stops_the_run_before_any_trial(self) -> None:
        main = self.mini.root / "scenarios" / "dev" / F2 / "step_1" / "main.tf"
        main.write_bytes(main.read_bytes() + b"# tampered\n")
        from experiments.loader import LoaderError

        with self.assertRaises(LoaderError):
            load(self.mini.root, manifest_sha256=self.mini.manifest_sha256)

    def test_a_step_changed_after_loading_is_an_input_failure(self) -> None:
        experiment = self.experiment((C,))
        main = self.mini.root / "scenarios" / "dev" / F2 / "step_1" / "main.tf"
        main.write_bytes(main.read_bytes() + b"# tampered\n")
        out = self.dirs.new()
        summary = run_experiment(experiment, self.loaded, out)
        tid = experiment.trial_id(F2, C)
        self.assertIs(summary.statuses[tid], TrialStatus.FAILED)
        result = read_result(Layout(out, experiment.experiment_id), tid)
        self.assertEqual(result["failure"]["class"], "INPUT_FAILURE")
        self.assertEqual(result["transitions"], [])


class TestRerun(HarnessCase):
    def snapshot(self, root: Path) -> dict[Path, bytes]:
        return {p: p.read_bytes() for p in root.rglob("*") if p.is_file() and p.suffix != ".sqlite"}

    def test_an_interrupted_run_resumes_without_overwriting(self) -> None:
        experiment = self.experiment((A, C))
        victim = experiment.trial_id(F8, C)

        def hook(trial_id: str, stage: str) -> None:
            if trial_id == victim and stage == "step-2":
                raise Interrupt()

        out = self.dirs.new()
        with self.assertRaises(Interrupt):
            run_experiment(experiment, self.loaded, out, hook=hook)
        layout = Layout(out, experiment.experiment_id)
        self.assertEqual(read_events(layout, victim)[-1]["status"], "EXECUTING")
        before = self.snapshot(out)
        summary = run_experiment(experiment, self.loaded, out)
        self.assertEqual(set(summary.statuses.values()), {TrialStatus.COMPLETED})
        self.assertIn(victim, summary.attempted)
        for path, data in before.items():
            with self.subTest(path=str(path.relative_to(out))):
                now = path.read_bytes()
                if path.name == "events.jsonl":
                    self.assertTrue(now.startswith(data))  # append-only
                else:
                    self.assertEqual(now, data)
        statuses = [(e["attempt"], e["status"]) for e in read_events(layout, victim)]
        self.assertIn((1, "ABORTED"), statuses)
        self.assertEqual(statuses[-1], (2, "COMPLETED"))
        self.assertEqual(read_result(layout, victim)["attempt"], 2)
        completed_before = [
            t
            for t in summary.statuses
            if t != victim and (layout.trial_dir(t) / "attempts" / "1" / "result.json") in before
        ]
        self.assertTrue(completed_before)
        for tid in completed_before:
            self.assertIn(tid, summary.skipped)

    def test_an_initialized_but_unstarted_trial_is_rerun(self) -> None:
        experiment = self.experiment((C,))
        victim = experiment.trial_id(F1, C)

        def hook(trial_id: str, stage: str) -> None:
            if trial_id == victim and stage == "initialized":
                raise Interrupt()

        out = self.dirs.new()
        with self.assertRaises(Interrupt):
            run_experiment(experiment, self.loaded, out, hook=hook)
        summary = run_experiment(experiment, self.loaded, out)
        self.assertIs(summary.statuses[victim], TrialStatus.COMPLETED)
        events = read_events(Layout(out, experiment.experiment_id), victim)
        self.assertIn((1, "ABORTED"), [(e["attempt"], e["status"]) for e in events])

    def test_a_completed_run_is_skipped_entirely(self) -> None:
        experiment, layout, _ = self.run_all((C,))
        before = self.snapshot(layout.root)
        summary = run_experiment(experiment, self.loaded, layout.root)
        self.assertEqual(summary.attempted, ())
        self.assertEqual(len(summary.skipped), len(TARGETS))
        self.assertEqual(self.snapshot(layout.root), before)


def records(layout: Layout) -> dict[str, bytes]:
    """Every trial record of a run, keyed by its path inside the experiment directory, without the
    wall-clock files (timing and lifecycle events) and the database files."""
    root = layout.experiment_dir / "trials"
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
        and p.name not in ("timing.json", "events.jsonl")
        and not p.name.startswith("dail.sqlite")
    }


class TestReproducibility(HarnessCase):
    def test_running_a_trial_twice_gives_identical_records(self) -> None:
        _, first, _ = self.run_all((C, A))
        _, second, _ = self.run_all((C, A))
        self.assertEqual(records(first), records(second))
        self.assertGreater(len(records(first)), 0)

    def test_corrupted_labels_change_no_trial_record(self) -> None:
        corrupted_root = mini_root(self.dirs.new(), corrupt=True)
        corrupted = load(corrupted_root.root, manifest_sha256=corrupted_root.manifest_sha256)
        _, clean, _ = self.run_all()
        _, dirty, _ = self.run_all(loaded=corrupted, data=corrupted)
        self.assertEqual(records(clean), records(dirty))

    def test_concurrent_trials_are_isolated(self) -> None:
        _, sequential, _ = self.run_all((A, C))
        _, parallel, summary = self.run_all((A, C), workers=4)
        self.assertEqual(set(summary.statuses.values()), {TrialStatus.COMPLETED})
        self.assertEqual(records(sequential), records(parallel))

    def test_each_trial_has_its_own_store_and_lineage(self) -> None:
        experiment, layout, _ = self.run_all((A, C))
        lineages, stores = set(), set()
        for tid in (experiment.trial_id(s, c) for s in TARGETS for c in (A, C)):
            result = read_result(layout, tid)
            lineages.add(result["lineage_id"])
            stores.add(layout.attempt_dir(tid, 1) / "store" / "dail.sqlite")
        self.assertEqual(len(lineages), len(TARGETS) * 2)
        self.assertTrue(all(store.is_file() for store in stores))


if __name__ == "__main__":
    unittest.main()
