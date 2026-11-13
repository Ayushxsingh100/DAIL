"""Scoring inputs, the identity truth table, records to transitions, and the report (P8b; Doc 13
§31-§33, §35; C-212 to C-214).

* labels: only experiments.scoring reads TerraPreserve label fields; it verifies the manifest pin
  and every scenario.json hash as the loader does, and refuses the test split.
* identity truth (C-213): "one row per TerraPreserve operator that moves, replaces, deletes or
  creates a resource, giving the expected change type at the operator's target address, with the
  sentence of D4_OPERATORS.md it comes from. An operator whose identity truth the catalogue does not
  state gets no row, and its pairs are excluded and counted."
* Doc 13 §33 "ExperimentReport { experiment_id, experiment_version, trial_count, included_count,
  excluded_count, condition_summaries[], primary_metrics[], secondary_metrics[], failures[],
  reproducibility_summary, artifact_refs[] }."
* Step 5: "Write docs/P8_DEV_PILOT.md from the generated report only (no hand-typed numbers; a test
  checks the file's numbers equal the extractor's JSON)."
"""

from __future__ import annotations

import json
import os
import unittest
from datetime import UTC, datetime
from pathlib import Path

from experiments.definition import Condition, ExperimentSpec
from experiments.loader import LoaderError, load
from experiments.metrics.model import transitions_from_result
from experiments.report.build import REPORT_KEYS, build_report
from experiments.report.render import render_markdown
from experiments.runner import Layout, plan, read_result, run_experiment
from experiments.scoring.identity import load_identity_table, true_pairs
from experiments.scoring.labels import load_labels
from tests.experiment_builders import F2, F8, TempDirs, mini_root
from tests.fixture_catalog import REPO_ROOT
from tests.unit.test_p8b_metrics import run as extraction

ROOT = os.environ.get("TERRAPRESERVE_ROOT")
SEC1, FUNC1 = "INV-SEC-001", "INV-FUNC-001"


def real_labels(scenario: dict[str, object]) -> None:
    """Give a mini scenario well-formed labels: every invariant PASS except INV-SEC-001 at S0."""
    steps = scenario["steps"]
    assert isinstance(steps, list)
    scenario["labels"] = [
        {
            "step": k,
            "invariant_truth": {
                SEC1: "FAIL" if k == 0 else "PASS",
                "INV-SEC-002": "PASS",
                "INV-SEC-003": "PASS",
                FUNC1: "PASS",
            },
            "oracle_affected": [SEC1] if k else [],
            "target_safe": None,
        }
        for k in range(len(steps))
    ]
    scenario["gt_class"] = "safe"
    scenario["mutation_record"] = []


class TestLabels(unittest.TestCase):
    def setUp(self) -> None:
        self.dirs = TempDirs()
        self.addCleanup(self.dirs.close)
        self.mini = mini_root(self.dirs.new(), edit=real_labels)

    def test_labels_are_read_and_checked(self) -> None:
        found = load_labels(self.mini.root, manifest_sha256=self.mini.manifest_sha256)
        f8 = found[F8]
        self.assertEqual(f8.family, "F8")
        self.assertEqual((f8.kind, f8.target), ("repair", SEC1))
        self.assertEqual(len(f8.truth), 3)
        self.assertEqual(f8.truth[0][SEC1], "FAIL")
        self.assertEqual(f8.oracle_affected[1], frozenset({SEC1}))
        self.assertEqual((f8.tier, f8.cluster), ("controlled", "tpl-mini"))
        self.assertEqual(f8.gt_class, "safe")
        self.assertIn("aws_security_group.app", f8.declared[0])
        self.assertEqual(len(f8.declared), 3)

    def test_the_test_split_and_a_wrong_pin_are_refused(self) -> None:
        with self.assertRaises(LoaderError):
            load_labels(self.mini.root, manifest_sha256=self.mini.manifest_sha256, split="test")
        with self.assertRaises(LoaderError):
            load_labels(self.mini.root, manifest_sha256="0" * 64)

    def test_a_changed_scenario_file_is_refused(self) -> None:
        path = self.mini.root / "scenarios" / "dev" / F2 / "scenario.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(LoaderError):
            load_labels(self.mini.root, manifest_sha256=self.mini.manifest_sha256)


class TestIdentityTable(unittest.TestCase):
    def setUp(self) -> None:
        self.table = load_identity_table()

    def test_every_row_quotes_the_catalogue(self) -> None:
        self.assertTrue(self.table.rows)
        for operator, row in self.table.rows.items():
            with self.subTest(operator=operator):
                self.assertTrue(operator.startswith("op_"))
                self.assertTrue(row["sentence"])
                self.assertTrue(row["effects"])
                for effect in row["effects"]:
                    self.assertIn(effect["effect"], ("MOVE", "REPLACE", "CREATE", "DELETE"))

    def test_the_count_operator_is_excluded(self) -> None:
        # "adds or removes count = 1 on aws_instance": the catalogue states no identity truth
        self.assertIn("op_f5_count_each_safe", self.table.excluded)
        self.assertNotIn("op_f5_count_each_safe", self.table.rows)

    @unittest.skipUnless(
        ROOT, "set TERRAPRESERVE_ROOT to check the sentences against the catalogue"
    )
    def test_each_sentence_is_in_the_catalogue(self) -> None:
        assert ROOT is not None
        text = (Path(ROOT) / "docs" / "D4_OPERATORS.md").read_text(encoding="utf-8")
        for operator, row in self.table.rows.items():
            with self.subTest(operator=operator):
                self.assertIn(row["sentence"], text)
                self.assertIn(f"`{operator}`", text)
        for operator in self.table.excluded:
            self.assertIn(f"`{operator}`", text)

    def test_true_pairs_from_mutation_rows(self) -> None:
        from tests.metrics_builders import scenarios

        pairs, excluded = true_pairs(self.table, scenarios()["Y"], 1)
        effects = sorted((p.effect, p.old, p.new) for p in pairs)
        self.assertEqual(
            effects,
            [
                ("MOVE", "aws_security_group_rule.r5432", "aws_security_group_rule.r5432_v2"),
                ("REPLACE", "aws_security_group.db", "aws_security_group.db"),
            ],
        )
        self.assertEqual(excluded, [])
        # an existing resource that only gains an attribute (no 'before' rows) is not created
        created, _ = true_pairs(self.table, scenarios()["Z"], 1)
        self.assertEqual(
            [(p.effect, p.new) for p in created], [("CREATE", "aws_security_group.mon")]
        )
        _, excluded_w = true_pairs(self.table, scenarios()["W"], 1)
        self.assertEqual([e["operator"] for e in excluded_w], ["op_f5_count_each_safe"])


class TestRecordsToTransitions(unittest.TestCase):
    def test_a_stored_trial_result_becomes_transitions(self) -> None:
        dirs = TempDirs()
        self.addCleanup(dirs.close)
        mini = mini_root(dirs.new())
        loaded = load(mini.root, manifest_sha256=mini.manifest_sha256)
        experiment = plan(
            ExperimentSpec("p8b-parse", "1", "draft", "o", ("h",), (Condition.C,)),
            loaded,
            environment={},
            created_at=datetime(2026, 11, 13, tzinfo=UTC),
            only=(F8,),
        )
        out = dirs.new()
        run_experiment(experiment, loaded, out)
        result = read_result(
            Layout(out, experiment.experiment_id), experiment.trial_id(F8, Condition.C)
        )
        found = transitions_from_result(result)
        self.assertEqual(
            [(t.step, t.status, t.decision) for t in found],
            [(1, "EVALUATED", "PROMOTE"), (2, "EVALUATED", "PROMOTE")],
        )
        first = found[0]
        self.assertEqual(first.open_targets, (SEC1,))
        self.assertEqual(first.condition, "C")
        self.assertIn(SEC1, first.impact_affected)
        self.assertTrue(any(w.origin == "gate" for w in first.work))
        self.assertTrue(all(len(r) == 2 for r in first.required))


class TestReport(unittest.TestCase):
    def test_the_report_has_the_fields_of_section_33(self) -> None:
        report = build_report(
            definition={"experiment_id": "e", "name": "n", "version": "1", "condition_set": ["A"]},
            statuses={"t1": "COMPLETED"},
            extraction=extraction(),
        )
        for key in REPORT_KEYS:
            self.assertIn(key, report)
        self.assertEqual(
            (report["trial_count"], report["included_count"], report["excluded_count"]), (1, 1, 0)
        )

    def test_markdown_shows_numerators_and_denominators(self) -> None:
        report = build_report(
            definition={
                "experiment_id": "e",
                "name": "n",
                "version": "1",
                "condition_set": ["A", "B", "C", "C_PRIME"],
            },
            statuses={"t1": "COMPLETED"},
            extraction=extraction(),
        )
        text = render_markdown(report)
        self.assertIn("1 / 3", text)  # unsafe promotions per promotion under C
        self.assertEqual(text, render_markdown(json.loads(json.dumps(report))))


class TestDevPilotDocument(unittest.TestCase):
    def test_the_document_is_the_rendering_of_the_extractors_json(self) -> None:
        doc = REPO_ROOT / "docs" / "P8_DEV_PILOT.md"
        data = REPO_ROOT / "docs" / "P8_DEV_PILOT.json"
        report = json.loads(data.read_text(encoding="utf-8"))
        rendered = render_markdown(report)
        self.assertEqual(doc.read_text(encoding="utf-8").replace("\r\n", "\n"), rendered)
        self.assertEqual(report["extractor_version"], "metrics-draft-1")


if __name__ == "__main__":
    unittest.main()
