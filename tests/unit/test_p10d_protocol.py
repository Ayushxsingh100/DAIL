"""``docs/PROTOCOL_v1.md`` (P10d work package Step 5).

The Markdown is the rendering of ``docs/PROTOCOL_v1.json``; the JSON's pins are the current
code's (a change to frozen code after the freeze fails here: a visible deviation); its pre-freeze
outcomes are those of ``docs/P10D_DEV_DRY_RUN.json``; it holds the hypotheses verbatim, every
section the work package lists, and at least the deviations from the paper it names.
"""

from __future__ import annotations

import json
import unittest

from experiments.report.protocol import build_protocol, pins, render_protocol
from tests.fixture_catalog import REPO_ROOT

DOCS = REPO_ROOT / "docs"


def _load(name: str) -> dict[str, object]:
    return json.loads((DOCS / name).read_text(encoding="utf-8"))


class TestProtocolDocument(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = _load("PROTOCOL_v1.json")
        self.text = (DOCS / "PROTOCOL_v1.md").read_text(encoding="utf-8").replace("\r\n", "\n")

    def test_the_document_is_the_rendering_of_its_json(self) -> None:
        self.assertEqual(self.text, render_protocol(self.protocol))

    def test_the_frozen_code_is_the_code_the_protocol_pins(self) -> None:
        self.assertEqual(self.protocol["pins"], json.loads(json.dumps(pins())))

    def test_the_pre_freeze_outcomes_are_the_dry_runs(self) -> None:
        built = build_protocol(_load("P10D_DEV_DRY_RUN.json"))
        self.assertEqual(self.protocol["pre_freeze"], json.loads(json.dumps(built["pre_freeze"])))

    def test_the_hypotheses_are_verbatim(self) -> None:
        self.assertIn(
            "**H1:** DAIL misses fewer regressions than stateless, target-only verification.",
            self.text,
        )
        self.assertIn("These are hypotheses, not findings.", self.text)

    def test_every_section_of_the_work_package(self) -> None:
        for heading in (
            "Hypotheses",
            "Conditions",
            "Candidates",
            "Metrics: `metrics-final-1`",
            "The statistical plan",
            "Inclusion and exclusion",
            "Stopping rule",
            "Pins",
            "Unblinding",
            "Deviations from the paper",
        ):
            with self.subTest(heading=heading):
                self.assertIn(f". {heading}", self.text)

    def test_the_named_deviations_are_listed(self) -> None:
        deviations = self.text.split("## 10. Deviations from the paper", 1)[1]
        for ref in ("C-177", "C-196", "C-178, C-203", "C-197", "C-205, C-206",
                    "C-219, C-224, C-228", "C-71", "C-233", "D4c-01", "C-239"):  # fmt: skip
            with self.subTest(ref=ref):
                self.assertIn(f"**{ref}", deviations)
        self.assertIn("18 target-bearing and 30 change-request", deviations)
        self.assertIn("33 hand-written templates", deviations)

    def test_the_pins_name_every_version(self) -> None:
        p = self.protocol["pins"]
        assert isinstance(p, dict)
        self.assertEqual(p["terraform"], "1.15.8")
        self.assertTrue(str(p["aws_provider"]).endswith("6.53.0"))
        self.assertEqual(p["metrics_version"], "metrics-final-1")
        self.assertEqual(p["identity_truth_version"], "identity-truth-2")
        self.assertEqual(p["terrapreserve_tag"], "terrapreserve-v1.0")
        self.assertEqual(len(p["models"]), 3)
        for m in p["models"].values():
            self.assertEqual((m["temperature"], m["top_p"]), (0.7, 0.95))


if __name__ == "__main__":
    unittest.main()
