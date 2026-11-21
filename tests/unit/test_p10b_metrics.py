"""P10b pilot metrics (work package Section 3; extractor ``extractor-3``).

Run A: "the reasons for C's rejections (verifier, result, reason, count)". Run B: "how many of the 3
samples per scenario are distinct patches (by hash)"; "the projection for 36 test repair scenarios x
3 models x k = 3". The record set is built by hand; expected values are computed in the comments.
"""

from __future__ import annotations

import unittest
from typing import Any

from experiments.metrics.extractor import EXTRACTOR_VERSION
from experiments.metrics.generation import (
    distinct_patches,
    experiment_projection,
    rejection_reasons,
)


def check(target: str, verifier: str, result: str, reason: str | None) -> dict[str, Any]:
    return {"target_id": target, "verifier_id": verifier, "result": result, "reason": reason}


def replay(model: str, condition: str, decision: str | None, work: list[Any]) -> dict[str, Any]:
    required = [{"target_id": w["target_id"]} for w in work if w["target_id"] != "NOT_REQUIRED"]
    return {
        "model_key": model,
        "condition": condition,
        "decision": decision,
        "transition": None if decision is None else {"required": required, "work": work},
    }


SEC = "dail.verify.public_ingress"
FUNC = "dail.verify.reachability_cfg"
REPLAYS = [
    replay("m", "C", "REJECT", [
        check("INVARIANT:INV-FUNC-001:1", FUNC, "UNSUPPORTED", "group.mixed"),
        check("INVARIANT:INV-SEC-001:2", SEC, "PASS", None),
        check("NOT_REQUIRED", SEC, "FAIL", "predicate.violated"),  # not a required check
    ]),
    replay("m", "C", "REJECT", [
        check("INVARIANT:INV-FUNC-001:1", FUNC, "UNSUPPORTED", "group.mixed"),
        check("INVARIANT:INV-SEC-001:2", SEC, "FAIL", "predicate.violated"),
    ]),
    replay("m", "C", "PROMOTE", [check("INVARIANT:INV-SEC-001:2", SEC, "PASS", None)]),
    replay("m", "B", "REJECT", [check("INVARIANT:INV-SEC-002:2", SEC, "FAIL", "x")]),  # not C
    replay("m", "C", None, []),  # no decision: the rebuild did not match
]  # fmt: skip


class TestRejectionReasons(unittest.TestCase):
    def test_non_pass_required_checks_of_rejected_candidates_under_c(self) -> None:
        self.assertEqual(
            rejection_reasons(REPLAYS, "C")["m"],
            [
                # two rejections each hold an UNSUPPORTED INV-FUNC-001 check
                {"verifier_id": FUNC, "result": "UNSUPPORTED", "reason": "group.mixed", "count": 2},
                {"verifier_id": SEC, "result": "FAIL", "reason": "predicate.violated", "count": 1},
            ],
        )

    def test_another_condition(self) -> None:
        self.assertEqual(
            rejection_reasons(REPLAYS, "B")["m"],
            [{"verifier_id": SEC, "result": "FAIL", "reason": "x", "count": 1}],
        )


def attempt(sid: str, k: int, patch: str | None) -> dict[str, Any]:
    return {
        "model_key": "m",
        "scenario_id": sid,
        "k": k,
        "status": "PATCH" if patch else "FAILED",
        "patch_sha256": patch,
    }


ATTEMPTS = [
    attempt("s1", 1, "a"), attempt("s1", 2, "a"), attempt("s1", 3, "b"),  # 2 distinct of 3 valid
    attempt("s2", 1, "c"), attempt("s2", 2, None), attempt("s2", 3, None),  # 1 of 1 valid
    attempt("s3", 1, None), attempt("s3", 2, None), attempt("s3", 3, None),  # none valid
    attempt("s4", 1, "d"), attempt("s4", 2, "e"), attempt("s4", 3, "f"),  # 3 of 3
]  # fmt: skip


class TestDistinctPatches(unittest.TestCase):
    def test_distinct_valid_patches_per_scenario(self) -> None:
        found = distinct_patches(ATTEMPTS)["m"]
        self.assertEqual(found["per_scenario"], {"s1": 2, "s2": 1, "s3": 0, "s4": 3})
        self.assertEqual(found["scenarios_by_distinct"], {"0": 1, "1": 1, "2": 1, "3": 1})
        self.assertEqual(found["samples_per_scenario"], 3)
        self.assertEqual(found["mean_distinct"], 1.5)  # (2 + 1 + 0 + 3) / 4


class TestProjection(unittest.TestCase):
    def test_36_scenarios_x_models_x_k(self) -> None:
        means = {"a": 100.0, "b": 60.0, "c": None}
        got = experiment_projection(means, scenarios=36, k=3)
        self.assertEqual(got["per_model_seconds"], {"a": 10800.0, "b": 6480.0, "c": None})
        self.assertEqual(got["total_seconds"], 17280.0)  # 36 x 3 x (100 + 60)
        self.assertEqual(got["models_without_a_mean"], ["c"])


class TestVersion(unittest.TestCase):
    def test_extractor_3(self) -> None:
        self.assertEqual(EXTRACTOR_VERSION, "extractor-5")


if __name__ == "__main__":
    unittest.main()


class TestP10bDocument(unittest.TestCase):
    """Section 3: "Write the pilot report as ``docs/P10B_MODEL_PILOT.md``, generated from the stored
    records." The committed Markdown is the rendering of the committed JSON."""

    def test_the_document_is_the_rendering_of_its_json(self) -> None:
        import json

        from experiments.report.pilot_b import render_p10b
        from tests.fixture_catalog import REPO_ROOT

        report = json.loads((REPO_ROOT / "docs" / "P10B_MODEL_PILOT.json").read_text("utf-8"))
        doc = (REPO_ROOT / "docs" / "P10B_MODEL_PILOT.md").read_text("utf-8")
        self.assertEqual(doc.replace("\r\n", "\n"), render_p10b(report))
        self.assertEqual(report["run_a"]["prompt_version"], "dail-repair-prompt-3")
        self.assertEqual(report["p10a"]["prompt_version"], "dail-repair-prompt-2")
        self.assertEqual(report["run_b"]["repetitions"], 3)
        for model in report["run_b"]["models"].values():
            self.assertEqual((model["pin"]["temperature"], model["pin"]["top_p"]), (0.7, 0.95))
        self.assertIn("summary", report["interruptions"])
