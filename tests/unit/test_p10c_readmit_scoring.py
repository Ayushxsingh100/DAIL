"""Re-admission of frozen pilot candidates through the validate gate, and scoring against TP-L1's
labels (P10c Sections 3.3-3.4; C-227, C-228, C-230).

Section 3.3: "a scoring step applies the validate gate to every frozen valid candidate of the three
pilot generations ... It records the result beside the frozen record. Frozen files are never edited.
Report valid patch rates before and after the gate, per model."
Section 3.4: "for every frozen candidate, join DAIL's decisions under A, B, C and C' (from the
P10a/P10b replays) with TP-L1's ``label.json`` (by generation id, model key, scenario, k), and check
the hashes. Report per model and generation: attempts and validate-valid patches; oracle class
(safe, unsafe, no label with reason); for each condition: promoted unsafe, promoted no-label,
rejected unsafe and rejected no-label candidates, and promoted safe and rejected safe ones ...; A's
promotions of unsafe candidates, each listed." Step 4: "cross-check DAIL's validate result with
TP-L1's ... Every disagreement is listed, never resolved by hand."

The mini generation (fake provider) freezes two candidates of tp-mini-F2-0001 under one model, both
built when no gate existed (a fake runner that passes everything stands in for validator 2's era):
k = 1 closes SSH; k = 2 adds an ingress block with ``"::/0"`` in ``cidr_blocks``. The gate's fake
runner fails k = 2. The TerraPreserve side is a temporary git repository whose commit holds
hand-written TP-L1 label files for the two candidates (k = 1 unsafe, k = 2 no label: validation
failed). Every DAIL decision the test expects is read from the stored replay records, so the test
checks the join and the counting, not DAIL's verdicts.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path
from typing import Any

from experiments.loader import load
from llm.adapter.fake import FakeProvider
from llm.adapter.provider import ProviderReply
from tests.experiment_builders import F2, TempDirs, mini_root
from tests.llm_patch_builders import SG_APP, SG_APP_CLOSED, SSH_RULE, repair
from tests.unit.test_p10c_validate_gate import SG_APP_IPV6, FakeTerraform

CONDITIONS = ("A", "B", "C", "C_PRIME")
TAG, DIGEST = "fake-coder:1b", "b" * 64


def passes_everything(candidate_dir: Path) -> Any:
    from llm.validation.patch import TerraformCheck

    del candidate_dir

    return TerraformCheck(ok=True, error="", versions={"terraform": "fake"})


def ok(text: str) -> ProviderReply:
    return ProviderReply(text=text, latency_ms=1.0, token_usage={"input": 1, "output": 1})


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


class Pilot(unittest.TestCase):
    """Generate (no gate), replay, export; then the gate and the scoring."""

    @classmethod
    def setUpClass(cls) -> None:
        from experiments.generation.export import export_for_oracle
        from experiments.generation.replay import replay_candidates
        from experiments.generation.run import GenerationSpec, generate_candidates
        from experiments.generation.task import generation_input
        from experiments.runner import experiment_config
        from tests.unit.test_p10a_generation import pin

        cls.dirs = TempDirs()
        mini = mini_root(cls.dirs.new())
        cls.loaded = load(mini.root, manifest_sha256=mini.manifest_sha256)
        cls.by_id = {s.scenario_id: s for s in cls.loaded.scenarios}
        cls.out = cls.dirs.new("dail-p10c-out-")
        cls.inputs = [generation_input(cls.by_id[F2])]
        provider = FakeProvider(
            [
                ok(repair(SG_APP_CLOSED, [SG_APP, SSH_RULE])),
                ok(repair(SG_APP_IPV6, [SG_APP, SSH_RULE])),
            ]
        )
        cls.summary = generate_candidates(
            spec=GenerationSpec(name="p10c-test", version="1"),
            inputs=cls.inputs,
            models=[(pin(), provider, {"name": TAG, "digest": DIGEST})],
            k=2,
            root=cls.out,
            generation_enabled=True,
            environment={},
            terraform=passes_everything,
        )
        cls.gid = cls.summary.generation_id
        cls.replay = replay_candidates(
            root=cls.out,
            generation_id=cls.gid,
            scenarios=cls.by_id,
            conditions=CONDITIONS,
            config=experiment_config(),
            replay_name="replay-1",
        )
        cls.export_index = export_for_oracle(root=cls.out, generation_id=cls.gid, inputs=cls.inputs)
        cls.base = cls.out / "candidates" / cls.gid
        cls.frozen = {
            p: p.read_bytes()
            for p in cls.base.rglob("*")
            if p.is_file() and "replay" not in p.parts
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.dirs.close()

    def decision(self, k: int, condition: str) -> str | None:
        """Read from the stored replay record (not from the scoring code)."""
        path = (
            self.base
            / "replay"
            / "replay-1"
            / "fake-coder-1b"
            / F2
            / str(k)
            / condition
            / "result.json"
        )
        return json.loads(path.read_text(encoding="utf-8"))["decision"]

    def readmit(self, name: str) -> Any:
        from experiments.generation.readmit import readmit

        return readmit(
            root=self.out,
            generation_id=self.gid,
            inputs={g.scenario_id: g for g in self.inputs},
            terraform=FakeTerraform(),
            name=name,
        )

    def tp_repo(self, edit: Any = None) -> tuple[Path, str]:
        """A TerraPreserve-like repository whose commit holds TP-L1 label files for the export."""
        repo = self.dirs.new("tp-l1-repo-")
        git(repo, "init", "-q")
        index = json.loads(self.export_index.read_bytes())
        export_sha = hashlib.sha256(self.export_index.read_bytes()).hexdigest()
        candidates = []
        for c in sorted(index["candidates"], key=lambda c: c["k"]):
            unsafe = c["k"] == 1
            truth = (
                {
                    "INV-SEC-001": "FAIL",
                    "INV-SEC-002": "PASS",
                    "INV-SEC-003": "PASS",
                    "INV-FUNC-001": "PASS",
                }
                if unsafe
                else {
                    i: "UNSUPPORTED"
                    for i in ("INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001")
                }
            )
            label = {
                "candidate_id": c["candidate_id"],
                "generation_id": self.gid,
                "model_key": c["model_key"],
                "scenario_id": c["scenario_id"],
                "k": c["k"],
                "content_hash": c["content_hash"],
                "tree_hash": c["tree_hash"],
                "files": c["files"],
                "export_sha256": export_sha,
                "class": "unsafe" if unsafe else None,
                "no_label_reason": None if unsafe else "unlabelable",
                "reason": "x" if unsafe else "terraform validate failed (registry 2.8 ...): ...",
                "invariant_truth": {"primary": truth, "alternate": truth},
                "plan_status": {
                    v: ["planned", "planned" if unsafe else "invalid"]
                    for v in ("primary", "alternate")
                },
                "validate_errors": {
                    v: None if unsafe else 'Error: "::/0" is not a valid IPv4 CIDR block'
                    for v in ("primary", "alternate")
                },
            }
            candidates.append(edit(label) if edit else label)
        raw = (
            json.dumps(
                {"generation_id": self.gid, "export_sha256": export_sha, "candidates": candidates},
                indent=1,
                sort_keys=True,
            )
            + "\n"
        ).encode()
        target = repo / "llm_candidates" / "dev" / self.gid
        target.mkdir(parents=True)
        (target / "labels.json").write_bytes(raw)
        (target / "labels.sha256").write_text(hashlib.sha256(raw).hexdigest() + "  labels.json\n")
        git(repo, "add", ".")
        git(
            repo,
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "-m",
            "x",
        )
        return repo, git(repo, "rev-parse", "HEAD")


class TestReadmission(Pilot):
    def test_the_gate_is_applied_and_recorded_beside_the_frozen_record(self) -> None:
        summary = self.readmit("gate-1")
        rows = {r["k"]: r for r in summary.results}
        self.assertTrue(rows[1]["validate_ok"])
        self.assertFalse(rows[2]["validate_ok"])
        self.assertIn('"::/0" is not a valid IPv4 CIDR block', rows[2]["validate_error"])
        for r in rows.values():
            self.assertTrue(r["tree_hash_matches"])
        self.assertTrue(summary.path.is_relative_to(self.base / "validate_gate" / "gate-1"))
        rate = summary.rates["fake-coder-1b"]
        self.assertEqual((rate["before"]["numerator"], rate["before"]["denominator"]), (2, 2))
        self.assertEqual((rate["after"]["numerator"], rate["after"]["denominator"]), (1, 2))

    def test_frozen_files_are_never_edited_and_the_record_is_written_once(self) -> None:
        from experiments.generation.run import GenerationError

        self.readmit("gate-2")
        now = {p: p.read_bytes() for p in self.frozen}
        self.assertEqual(now, self.frozen)
        with self.assertRaises(GenerationError):
            self.readmit("gate-2")

    def test_no_runner_is_refused(self) -> None:
        from experiments.generation.readmit import readmit
        from experiments.generation.run import GenerationError

        with self.assertRaises(GenerationError):
            readmit(
                root=self.out,
                generation_id=self.gid,
                inputs={g.scenario_id: g for g in self.inputs},
                terraform=None,
                name="none",
            )


class TestScoring(Pilot):
    def score(self, repo: Path, commit: str, gate: str) -> dict[str, Any]:
        from experiments.scoring.llm_pilot import score

        return score(
            root=self.out,
            generations=[self.gid],
            tp_root=repo,
            tp_commit=commit,
            gate_name=gate,
            replay_name="replay-1",
        )

    def test_the_join_and_the_counts(self) -> None:
        self.readmit("gate-s")
        repo, commit = self.tp_repo()
        report = self.score(repo, commit, "gate-s")
        (row,) = report["models"]
        self.assertEqual((row["generation_id"], row["model_key"]), (self.gid, "fake-coder-1b"))
        self.assertEqual(row["attempts"], 2)
        self.assertEqual(row["valid_before_gate"], 2)
        self.assertEqual(row["validate_valid"], 1)
        self.assertEqual(row["classes"], {"safe": 0, "unsafe": 1, "no label: unlabelable": 1})
        for scope_name, ks in (("all_replayed", (1, 2)), ("validate_valid", (1,))):
            for c in CONDITIONS:
                expected = {
                    f"{d} {cls}": 0
                    for d in ("promoted", "rejected")
                    for cls in ("safe", "unsafe", "no label")
                }
                for k in ks:
                    d = self.decision(k, c)
                    if d is None:
                        continue
                    cls = "unsafe" if k == 1 else "no label"
                    expected[f"{'promoted' if d == 'PROMOTE' else 'rejected'} {cls}"] += 1
                with self.subTest(scope=scope_name, condition=c):
                    self.assertEqual(row["conditions"][scope_name][c], expected)
        a_unsafe = [x for x in report["a_unsafe_promotions"]]
        expected_list = [1] if self.decision(1, "A") == "PROMOTE" else []
        self.assertEqual([x["k"] for x in a_unsafe], expected_list)

    def test_the_validate_cross_check_with_tp_l1(self) -> None:
        self.readmit("gate-x")
        repo, commit = self.tp_repo()
        report = self.score(repo, commit, "gate-x")
        self.assertEqual(report["validate_agreement"]["agree"], 2)
        self.assertEqual(report["validate_agreement"]["disagreements"], [])

        # a label that says k = 2 validated is a disagreement, listed and not resolved
        def flip(label: dict[str, Any]) -> dict[str, Any]:
            if label["k"] == 2:
                label["plan_status"] = {v: ["planned", "planned"] for v in ("primary", "alternate")}
            return label

        repo2, commit2 = self.tp_repo(flip)
        report2 = self.score(repo2, commit2, "gate-x")
        (d,) = report2["validate_agreement"]["disagreements"]
        self.assertEqual((d["k"], d["dail_validate_ok"], d["tp_l1_validate_ok"]), (2, False, True))

    def test_hash_checks_refuse_a_mismatch(self) -> None:
        from experiments.scoring.llm_pilot import ScoringError

        self.readmit("gate-h")
        for name, edit in (
            ("content hash", lambda label: dict(label, content_hash="0" * 64)),
            ("export hash", lambda label: dict(label, export_sha256="0" * 64)),
        ):
            with self.subTest(change=name):
                repo, commit = self.tp_repo(edit)
                with self.assertRaises(ScoringError):
                    self.score(repo, commit, "gate-h")
        repo, commit = self.tp_repo()
        labels = repo / "llm_candidates" / "dev" / self.gid / "labels.json"
        labels.write_bytes(labels.read_bytes() + b" ")
        git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qam", "y")
        with self.assertRaises(ScoringError):  # labels.sha256 no longer matches
            self.score(repo, git(repo, "rev-parse", "HEAD"), "gate-h")

    def test_labels_are_read_from_the_commit_not_the_working_tree(self) -> None:
        self.readmit("gate-c")
        repo, commit = self.tp_repo()
        (repo / "llm_candidates" / "dev" / self.gid / "labels.json").write_text("{}")  # uncommitted
        self.assertEqual(self.score(repo, commit, "gate-c")["tp_commit"], commit)


if __name__ == "__main__":
    unittest.main()


class TestScoringDocument(unittest.TestCase):
    """Section 3.4: "The report is ``docs/P10C_LLM_PILOT_SCORING.md``, generated from records.\" """

    def test_the_document_is_the_rendering_of_its_json(self) -> None:
        from experiments.report.llm_scoring import render
        from tests.fixture_catalog import REPO_ROOT

        report = json.loads((REPO_ROOT / "docs" / "P10C_LLM_PILOT_SCORING.json").read_text("utf-8"))
        doc = (REPO_ROOT / "docs" / "P10C_LLM_PILOT_SCORING.md").read_text("utf-8")
        self.assertEqual(doc.replace("\r\n", "\n"), render(report))
        self.assertEqual(len(report["generations"]), 3)
        for word in ("PROMOTE", "REJECT"):
            self.assertNotIn(word, doc)  # decisions are counted by class, not echoed
