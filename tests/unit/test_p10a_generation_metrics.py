"""Generation metrics and the pilot report (P10a Section 3.3 "Generation metrics", Step 6, Step 7).

Section 3.3: "valid patch rate per model (Doc 13 §26), failure classes per model (with Ollama
UNSUPPORTED kept apart from model failures, P7a limit 4), retries, latency, and token counts (marked
as estimates where they come from ``ceil(characters / 4)``, P7a limit 5)." Step 6 "Report per
model: latency per call (mean, max); valid patch rate and failure classes; DAIL decisions under C;
total wall time; a projection of the time for 36 test repair scenarios x k in {1, 3, 5}."

The record set below is built by hand; every expected value is computed by hand in the comments.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from experiments.metrics.generation import model_metrics
from experiments.report.pilot import render_pilot
from tests.fixture_catalog import REPO_ROOT


def attempt(sid: str, status: str, failure: str | None, source: str | None, estimate: int) -> Any:
    return {
        "model_key": "m",
        "scenario_id": sid,
        "k": 1,
        "status": status,
        "failure_class": failure,
        "failure_source": source,
        "observability": {"budget": {"estimated_input_tokens": estimate}},
    }


def response(latency: float | None, tokens: dict[str, int]) -> dict[str, Any]:
    return {"latency_ms": latency, "token_usage": tokens}


ATTEMPTS = [
    attempt("s1", "PATCH", None, None, 900),
    attempt("s2", "FAILED", "INVALID_OUTPUT", "model", 1000),
    attempt("s3", "FAILED", "UNSUPPORTED", "provider", 800),
    attempt("s4", "CONTEXT_INSUFFICIENT", "CONTEXT_INSUFFICIENT", "budget", 5000),
    {**attempt("s1", "PATCH", None, None, 1), "model_key": "other"},
]
RESPONSES = {
    ("m", "s1", 1): [response(10_000.0, {"input": 1000, "output": 100})],
    ("m", "s2", 1): [
        response(20_000.0, {"input": 2000, "output": 200}),
        response(30_000.0, {"input": 2100, "output": 210}),
    ],
    ("m", "s3", 1): [response(None, {})],
    ("m", "s4", 1): [],
    ("other", "s1", 1): [response(1.0, {"input": 1, "output": 1})],
}
TIMINGS = {
    ("m", "s1", 1): {"wall_seconds": 12.0},
    ("m", "s2", 1): {"wall_seconds": 55.0},
    ("m", "s3", 1): {"wall_seconds": 0.5},
    ("m", "s4", 1): {"wall_seconds": 0.1},
    ("other", "s1", 1): {"wall_seconds": 1.0},
}
REPLAYS = [
    {"model_key": "m", "condition": "C", "decision": "PROMOTE"},
    {"model_key": "m", "condition": "C", "decision": None},
    {"model_key": "m", "condition": "A", "decision": "PROMOTE"},
    {"model_key": "other", "condition": "C", "decision": "REJECT"},
]


class TestModelMetrics(unittest.TestCase):
    def setUp(self) -> None:
        self.m = model_metrics(ATTEMPTS, RESPONSES, TIMINGS, REPLAYS)["m"]

    def test_valid_patch_rate(self) -> None:
        rate = self.m["valid_patch_rate"]
        self.assertEqual((rate["numerator"], rate["denominator"]), (1, 4))  # s1 only
        self.assertEqual(rate["value"], 0.25)
        self.assertEqual(self.m["attempts"], 4)

    def test_failure_classes_by_source(self) -> None:
        self.assertEqual(
            self.m["failure_classes"],
            {
                "provider": {"UNSUPPORTED": 1},  # Ollama's 404: not the model's failure
                "budget": {"CONTEXT_INSUFFICIENT": 1},
                "model": {"INVALID_OUTPUT": 1},
            },
        )

    def test_calls_and_retries(self) -> None:
        self.assertEqual(self.m["calls"], 4)  # 1 + 2 + 1 + 0
        self.assertEqual(self.m["retries"], 1)  # 4 calls - 3 attempts that made a call

    def test_latency_per_call(self) -> None:
        # calls with a reply: 10 000, 20 000, 30 000 ms
        self.assertEqual(self.m["latency_ms"]["mean"], 20_000.0)
        self.assertEqual(self.m["latency_ms"]["max"], 30_000.0)
        self.assertEqual(self.m["latency_ms"]["calls_with_a_reply"], 3)

    def test_tokens_server_counts_and_the_estimate_apart(self) -> None:
        tokens = self.m["tokens"]
        self.assertEqual(tokens["provider_input_total"], 5100)  # 1000 + 2000 + 2100
        self.assertEqual(tokens["provider_output_total"], 510)
        self.assertEqual(tokens["provider_input_mean_per_call"], 1700.0)
        self.assertEqual(tokens["estimated_input_mean"], 1925.0)  # (900+1000+800+5000)/4
        self.assertEqual(tokens["estimated_input_max"], 5000)
        self.assertIn("estimate: ceil(characters / 4)", tokens["estimate_rule"])

    def test_wall_time_and_projection(self) -> None:
        wall = self.m["wall_seconds"]
        self.assertAlmostEqual(wall["total"], 67.6)  # 12 + 55 + 0.5 + 0.1
        self.assertAlmostEqual(wall["mean_per_attempt"], 16.9)
        projection = self.m["projection_seconds"]
        self.assertAlmostEqual(projection["36 scenarios x k=1"], 16.9 * 36)
        self.assertAlmostEqual(projection["36 scenarios x k=3"], 16.9 * 36 * 3)
        self.assertAlmostEqual(projection["36 scenarios x k=5"], 16.9 * 36 * 5)

    def test_decisions_per_condition(self) -> None:
        self.assertEqual(
            self.m["decisions"], {"A": {"PROMOTE": 1}, "C": {"PROMOTE": 1, "NO DECISION": 1}}
        )

    def test_versions(self) -> None:
        self.assertEqual(self.m["metrics_version"], "metrics-draft-1")
        self.assertEqual(self.m["extractor_version"], "extractor-2")


class TestPilotDocument(unittest.TestCase):
    def test_the_document_is_the_rendering_of_its_json(self) -> None:
        doc = REPO_ROOT / "docs" / "P10A_MODEL_PILOT.md"
        data = REPO_ROOT / "docs" / "P10A_MODEL_PILOT.json"
        report = json.loads(data.read_text(encoding="utf-8"))
        self.assertEqual(
            doc.read_text(encoding="utf-8").replace("\r\n", "\n"), render_pilot(report)
        )
        self.assertIn("no model's safety is", render_pilot(report))
        self.assertGreaterEqual(len(report["models"]), 1)
        for model in report["models"]:
            self.assertTrue(model["licence_check"], model["key"])
            self.assertIn("C", model["metrics"]["decisions"])


if __name__ == "__main__":
    unittest.main()
