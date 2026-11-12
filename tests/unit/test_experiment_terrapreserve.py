"""The loader and one trial on the real TerraPreserve v1.0 dev split (P8a; work package §3, Step 2).

Runs only when ``TERRAPRESERVE_ROOT`` names a TerraPreserve checkout at tag terrapreserve-v1.0
(skipped in CI, which has no TerraPreserve). Read only: nothing under the root is written. Never the
test split.

Expected values from the quoted text: "its SHA-256 at tag terrapreserve-v1.0 is 665b326a...";
"Trials run only scenarios with v1_role = 'target' (224 in dev)".
"""

from __future__ import annotations

import os
import unittest
from datetime import UTC, datetime
from pathlib import Path

from experiments.definition import Condition, ExperimentSpec, TrialStatus
from experiments.loader import load
from experiments.runner import plan, run_experiment
from tests.experiment_builders import TempDirs

ROOT = os.environ.get("TERRAPRESERVE_ROOT")


@unittest.skipUnless(ROOT, "set TERRAPRESERVE_ROOT to a TerraPreserve v1.0 checkout")
class TestRealTerraPreserve(unittest.TestCase):
    def test_the_dev_targets_load_under_the_pin(self) -> None:
        assert ROOT is not None
        loaded = load(Path(ROOT))
        self.assertEqual(len(loaded.scenarios), 224)
        self.assertEqual({s.split for s in loaded.scenarios}, {"dev"})
        self.assertEqual(
            loaded.manifest_sha256,
            "665b326a024d295f727cd5648ffc7e0d375b9300584871f238c6bfa48edd2e2d",
        )

    def test_one_multi_step_trial_completes(self) -> None:
        assert ROOT is not None
        loaded = load(Path(ROOT))
        first = next(s for s in loaded.scenarios if s.family == "F8")
        dirs = TempDirs()
        self.addCleanup(dirs.close)
        experiment = plan(
            ExperimentSpec(
                name="p8a-real-data-test",
                version="1",
                protocol_version="draft",
                objective="loader and harness check",
                hypotheses=("none",),
                conditions=(Condition.C,),
            ),
            loaded,
            environment={"dail_commit": "test", "terrapreserve_tag": "terrapreserve-v1.0"},
            created_at=datetime(2026, 11, 12, tzinfo=UTC),
            only=(first.scenario_id,),
        )
        summary = run_experiment(experiment, loaded, dirs.new())
        self.assertEqual(set(summary.statuses.values()), {TrialStatus.COMPLETED})


if __name__ == "__main__":
    unittest.main()
