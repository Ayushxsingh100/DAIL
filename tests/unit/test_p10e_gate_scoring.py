"""Scoring uses only gate-passed LLM candidates (P10e-prep decision 4; P10c verdict limit 3; C-248).

"In scoring, an LLM candidate's DAIL decisions count only if its validate-gate record says it
passed; a candidate that failed the gate is reported as an invalid patch." The test uses the P10c
pilot fixture (``tests.unit.test_p10c_readmit_scoring.Pilot``): two candidates of one scenario,
both valid before the gate and both replayed under A, B, C and C'; the gate passes k = 1 and fails
k = 2. Here k = 2 is also labelled ``unsafe``, so a scorer that ignored the gate record would count
an unsafe candidate's decisions. The mutation runs are in the package report.

The test-split path (C-245): ``main_run_candidate_rows`` reads the TP-L2 file of a generation from
the private directory, only through the test-split guard (a fake repository and private directory).
"""

from __future__ import annotations

import hashlib
import shutil
import unittest
from pathlib import Path
from typing import Any

from experiments.metrics.llm_final import llm_metrics
from experiments.scoring.llm_pilot import ScoringError, candidate_rows, main_run_candidate_rows
from experiments.split_guard import MAIN_RUN_COMMAND, PRIVATE_MANIFEST_NAME, tp_l2_dir
from tests.unit.test_p10c_readmit_scoring import CONDITIONS, Pilot
from tests.unit.test_p10e_guard import fake_repo


def unsafe_k2(label: dict[str, Any]) -> dict[str, Any]:
    if label["k"] == 2:
        label = {**label, "class": "unsafe", "no_label_reason": None}
    return label


class TestGatePassedCandidatesOnly(Pilot):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.gate = "gate-p10e"
        cls.readmit(cls, cls.gate)  # type: ignore[arg-type]

    def rows(self) -> list[dict[str, Any]]:
        repo, commit = self.tp_repo(unsafe_k2)
        return candidate_rows(
            root=self.out,
            generations=[self.gid],
            tp_root=repo,
            tp_commit=commit,
            gate_name=self.gate,
            replay_name="replay-1",
        )

    def test_the_precondition_the_failed_candidate_has_decisions(self) -> None:
        by_k = {r["k"]: r for r in self.rows()}
        self.assertEqual((by_k[1]["validate_ok"], by_k[2]["validate_ok"]), (True, False))
        self.assertEqual(by_k[2]["class"], "unsafe")
        for c in CONDITIONS:
            self.assertIsNotNone(by_k[2]["decisions"][c], c)

    def test_a_candidate_that_failed_the_gate_never_contributes_a_decision(self) -> None:
        (group,) = llm_metrics(self.rows())["groups"]
        for c in CONDITIONS:
            with self.subTest(condition=c):
                counted = sum(group["decisions"][c].values())
                self.assertEqual(counted, 1, "only k = 1 passed the gate")
                expected = "promoted" if self.decision(1, c) == "PROMOTE" else "rejected"
                self.assertEqual(group["decisions"][c][f"{expected} unsafe"], 1)
        # k = 1 is unsafe too; the class counts hold one unsafe candidate, not two
        self.assertEqual(group["classes"], {"safe": 0, "unsafe": 1, "no label": 0})

    def test_it_is_counted_as_an_invalid_patch(self) -> None:
        (group,) = llm_metrics(self.rows())["groups"]
        valid = group["valid_after_gate"]
        self.assertEqual((valid["numerator"], valid["denominator"]), (1, 2))

    def test_a_promotion_of_the_failed_candidate_is_never_an_unsafe_promotion(self) -> None:
        rows = self.rows()
        # make the failed candidate promoted under every condition and the passed one rejected
        for r in rows:
            r["decisions"] = {c: "PROMOTE" if r["k"] == 2 else "REJECT" for c in CONDITIONS}
        (group,) = llm_metrics(rows)["groups"]
        for c in CONDITIONS:
            with self.subTest(condition=c):
                promoted = group["any_unsafe_promoted_at_k"][c]
                self.assertEqual(promoted["numerator"], 0)
                self.assertEqual(group["decisions"][c]["promoted unsafe"], 0)


class TestTheTestSplitPath(Pilot):
    """TP-L2's file in the private directory, read only through the guard."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.readmit(cls, "gate-p10e-test")  # type: ignore[arg-type]

    def private(self, repo_tag: str | None = "protocol-v1") -> tuple[Path, Path, str]:
        private = self.dirs.new("dail-p10e-private-")
        raw = b'{"test": []}'
        (private / PRIVATE_MANIFEST_NAME).write_bytes(raw)
        tp, _ = self.tp_repo(unsafe_k2)
        target = tp_l2_dir(private, self.gid)
        target.parent.mkdir(parents=True)
        shutil.copytree(tp / "llm_candidates" / "dev" / self.gid, target)
        repo = fake_repo(self.dirs.new("dail-p10e-repo-"), tag=repo_tag)
        return private, repo, hashlib.sha256(raw).hexdigest()

    def read(self, private: Path, repo: Path, pin: str, **changes: Any) -> Any:
        kwargs: dict[str, Any] = {
            "root": self.out,
            "generations": [self.gid],
            "private_root": private,
            "gate_name": "gate-p10e-test",
            "replay_name": "replay-1",
            "command": MAIN_RUN_COMMAND,
            "repo_root": repo,
            "manifest_sha256": pin,
        }
        kwargs.update(changes)
        return main_run_candidate_rows(**kwargs)

    def test_the_private_tp_l2_file_gives_the_same_rows(self) -> None:
        private, repo, pin = self.private()
        rows = self.read(private, repo, pin)
        by_k = {r["k"]: r for r in rows}
        self.assertEqual((by_k[1]["validate_ok"], by_k[2]["validate_ok"]), (True, False))
        self.assertEqual((by_k[1]["class"], by_k[2]["class"]), ("unsafe", "unsafe"))

    def test_it_is_refused_without_the_guard(self) -> None:
        private, repo, pin = self.private(repo_tag=None)
        with self.assertRaises(ScoringError):
            self.read(private, repo, pin)
        private, repo, pin = self.private()
        with self.assertRaises(ScoringError):
            self.read(private, repo, pin, command="score")
        with self.assertRaises(ScoringError):
            self.read(private, repo, "0" * 64)

    def test_a_changed_tp_l2_file_is_refused(self) -> None:
        private, repo, pin = self.private()
        path = tp_l2_dir(private, self.gid) / "labels.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ScoringError, "sha256"):
            self.read(private, repo, pin)


if __name__ == "__main__":
    unittest.main()
