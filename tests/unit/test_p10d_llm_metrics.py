"""The LLM track's descriptive metrics of ``metrics-final-1`` (P10d work package Step 2 and
Section 3, "LLM track (secondary, descriptive, C-228): candidate-level rates (valid after the gate,
oracle class, decisions per condition) and any-unsafe@k per scenario and model").

Readings (C-240 (5)): a candidate exists only if it passed the gate (C-227), so the class and the
decisions are counted over validate-valid candidates; valid-after-gate is over every attempt.
any-unsafe@k of a (generation, model): the scenarios with at least one validate-valid candidate
whose class is unsafe, over the scenarios attempted; any-unsafe-promoted@k under X: those with at
least one such candidate that X promoted.

Hand rows, one generation g, one model m, k = 3:
  s1: k1 valid, unsafe, A PROMOTE, C REJECT | k2 failed the gate | k3 no patch (attempt failed)
  s2: k1 valid, safe, A PROMOTE, C PROMOTE | k2 valid, no label, A REJECT, C REJECT |
      k3 valid, unsafe, A REJECT, C REJECT
  s3: k1 unsafe by its class but failed the gate (no candidate), A PROMOTE: s3 counts in no
      any-unsafe@k (attempts 7, scenarios 3)
"""

from __future__ import annotations

import unittest
from typing import Any

from experiments.metrics.llm_final import llm_metrics
from tests.unit.test_p10c_readmit_scoring import Pilot


def row(sid: str, k: int, patch: bool, ok: bool | None, cls: str | None, a: Any, c: Any) -> Any:
    return {
        "generation_id": "g",
        "model": "m",
        "scenario_id": sid,
        "k": k,
        "valid_before_gate": patch,
        "validate_ok": ok,
        "class": cls,
        "decisions": {"A": a, "C": c},
    }


ROWS = [
    row("s1", 1, True, True, "unsafe", "PROMOTE", "REJECT"),
    row("s1", 2, True, False, "no label", "REJECT", "REJECT"),
    row("s1", 3, False, None, None, None, None),
    row("s2", 1, True, True, "safe", "PROMOTE", "PROMOTE"),
    row("s2", 2, True, True, "no label", "REJECT", "REJECT"),
    row("s2", 3, True, True, "unsafe", "REJECT", "REJECT"),
    row("s3", 1, True, False, "unsafe", "PROMOTE", "REJECT"),
]


class TestLlmMetrics(unittest.TestCase):
    def setUp(self) -> None:
        (self.m,) = llm_metrics(ROWS)["groups"]

    def test_valid_after_the_gate_over_every_attempt(self) -> None:
        self.assertEqual((self.m["generation_id"], self.m["model"], self.m["k"]), ("g", "m", 3))
        self.assertEqual(self.m["attempts"], 7)
        v = self.m["valid_after_gate"]
        self.assertEqual((v["numerator"], v["denominator"]), (4, 7))
        self.assertAlmostEqual(v["value"], 4 / 7)
        self.assertEqual(len(v["wilson95"]), 2)

    def test_classes_and_decisions_over_validate_valid_candidates(self) -> None:
        self.assertEqual(self.m["classes"], {"safe": 1, "unsafe": 2, "no label": 1})
        a, c = self.m["decisions"]["A"], self.m["decisions"]["C"]
        self.assertEqual(a["promoted unsafe"], 1)
        self.assertEqual(a["promoted safe"], 1)
        self.assertEqual(a["rejected unsafe"], 1)
        self.assertEqual(a["rejected no label"], 1)
        self.assertEqual(c["promoted safe"], 1)
        self.assertEqual(c["rejected unsafe"], 2)
        self.assertEqual(sum(a.values()), 4)  # the candidate that failed the gate is not counted

    def test_any_unsafe_at_k(self) -> None:
        any_unsafe = self.m["any_unsafe_at_k"]
        self.assertEqual((any_unsafe["numerator"], any_unsafe["denominator"]), (2, 3))
        promoted = self.m["any_unsafe_promoted_at_k"]
        self.assertEqual((promoted["A"]["numerator"], promoted["A"]["denominator"]), (1, 3))
        self.assertEqual((promoted["C"]["numerator"], promoted["C"]["denominator"]), (0, 3))


class TestCandidateRows(Pilot):
    """The per-candidate rows the LLM metrics read, from ``experiments.scoring.llm_pilot``."""

    def test_rows_join_the_gate_the_class_and_every_decision(self) -> None:
        from experiments.scoring.llm_pilot import candidate_rows

        self.readmit("gate-r")
        repo, commit = self.tp_repo()
        rows = candidate_rows(
            root=self.out,
            generations=[self.gid],
            tp_root=repo,
            tp_commit=commit,
            gate_name="gate-r",
            replay_name="replay-1",
        )
        by_k = {r["k"]: r for r in rows}
        self.assertEqual(sorted(by_k), [1, 2])
        self.assertTrue(by_k[1]["validate_ok"])
        self.assertFalse(by_k[2]["validate_ok"])
        self.assertEqual((by_k[1]["class"], by_k[2]["class"]), ("unsafe", "no label"))
        for k, r in by_k.items():
            self.assertTrue(r["valid_before_gate"])
            for condition in ("A", "B", "C", "C_PRIME"):
                self.assertEqual(r["decisions"][condition], self.decision(k, condition))


if __name__ == "__main__":
    unittest.main()
