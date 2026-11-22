"""The test-split guard (P10e-prep decision 2; C-246, C-245).

"The loader opens ``split = "test"`` only if all of these hold: ``git describe --exact-match --tags
HEAD`` is ``protocol-v1``; the working tree is clean; ``$TERRAPRESERVE_PRIVATE`` holds
``V1_MANIFEST_PRIVATE.json`` with SHA-256 ``14ca1fff…`` (from TerraPreserve's
``scenarios/V1_MANIFEST.sha256`` at ``terrapreserve-v1.0``); the command is the main-run command.
Otherwise it refuses, and nothing is read."

Every test builds a fake DAIL repository (``git init``, a commit, a tag) and a fake private
directory (the mini TerraPreserve scenarios moved to the test split, laid out as TerraPreserve's
private package: ``V1_MANIFEST_PRIVATE.json`` and ``<scenario_id>/`` at its root). The real
``$TERRAPRESERVE_PRIVATE`` is never opened. A fake manifest cannot have the real pin, so the tests
pass the fake's SHA-256; one test checks that the default pin is the real one, and another that a
fake is refused under it.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from experiments import split_guard
from experiments.loader import LoaderError, load, load_test
from experiments.scoring.labels import load_labels, load_test_labels
from experiments.split_guard import (
    MAIN_RUN_COMMAND,
    PRIVATE_MANIFEST_NAME,
    PRIVATE_MANIFEST_SHA256,
    PROTOCOL_TAG,
    GuardRefused,
    open_test_split,
)
from tests.experiment_builders import TARGETS, TempDirs, mini_root
from tests.unit.test_p8b_scoring_report import real_labels

REAL_PIN = "14ca1fff3af778a81d43f90e70a14cb7b56d6ebf5474648514169e8c2d376efe"


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


def fake_repo(directory: Path, *, tag: str | None = PROTOCOL_TAG) -> Path:
    git(directory, "init", "-q")
    git(directory, "config", "user.email", "test@example.invalid")
    git(directory, "config", "user.name", "test")
    git(directory, "config", "commit.gpgsign", "false")
    (directory / "README.md").write_text("fake DAIL\n", encoding="utf-8")
    git(directory, "add", "README.md")
    git(directory, "commit", "-q", "-m", "fake")
    if tag is not None:
        git(directory, "tag", tag)
    return directory


def private_root(directory: Path, scratch: Path) -> tuple[Path, str]:
    """The mini scenarios as a private test split: ``<id>/`` and the private manifest."""
    mini = mini_root(scratch, edit=real_labels)
    public = json.loads((mini.root / "scenarios" / "V1_MANIFEST.json").read_bytes())
    entries = []
    for entry in public["dev"]:
        sid = entry["scenario_id"]
        shutil.copytree(mini.root / "scenarios" / "dev" / sid, directory / sid)
        path = directory / sid / "scenario.json"
        doc = json.loads(path.read_bytes())
        doc["split"] = "test"
        raw = json.dumps(doc, indent=1, sort_keys=True).encode("utf-8")
        path.write_bytes(raw)
        entries.append({**entry, "scenario_json_sha256": hashlib.sha256(raw).hexdigest()})
    manifest = {"dataset_version": "1.0", "decision": "P10e-prep test data", "test": entries}
    raw = json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8")
    (directory / PRIVATE_MANIFEST_NAME).write_bytes(raw)
    return directory, hashlib.sha256(raw).hexdigest()


class GuardCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dirs = TempDirs()
        self.addCleanup(self.dirs.close)
        self.repo = fake_repo(self.dirs.new("dail-p10e-repo-"))
        self.private, self.pin = private_root(
            self.dirs.new("dail-p10e-private-"), self.dirs.new("dail-p10e-mini-")
        )

    def open(self, **changes: Any) -> Any:
        kwargs: dict[str, Any] = {
            "command": MAIN_RUN_COMMAND,
            "repo_root": self.repo,
            "manifest_sha256": self.pin,
        }
        kwargs.update(changes)
        return open_test_split(self.private, **kwargs)

    def refused_and_nothing_read(self, pattern: str, **changes: Any) -> None:
        reads: list[Path] = []
        real = split_guard._read_bytes

        def spy(path: Path) -> bytes:
            reads.append(path)
            return real(path)

        with mock.patch.object(split_guard, "_read_bytes", spy):
            with self.assertRaisesRegex(GuardRefused, pattern):
                self.open(**changes)
            for entry in (load_test, load_test_labels):
                kwargs: dict[str, Any] = {
                    "command": MAIN_RUN_COMMAND,
                    "repo_root": self.repo,
                    "manifest_sha256": self.pin,
                }
                kwargs.update(changes)
                with self.subTest(entry=entry.__name__), self.assertRaises(LoaderError):
                    entry(self.private, **kwargs)
        self.assertEqual(reads, [], "the guard read the private directory before refusing")


class TestAccepted(GuardCase):
    def test_all_four_conditions_open_the_test_split(self) -> None:
        access = self.open()
        self.assertEqual(access.dail_commit, git(self.repo, "rev-parse", "HEAD"))
        self.assertEqual(access.manifest_sha256, self.pin)
        loaded = load_test(
            self.private, command=MAIN_RUN_COMMAND, repo_root=self.repo, manifest_sha256=self.pin
        )
        self.assertEqual(len(loaded.scenarios), len(TARGETS))
        self.assertEqual({s.split for s in loaded.scenarios}, {"test"})
        self.assertEqual(loaded.manifest_sha256, self.pin)
        scored = load_test_labels(
            self.private, command=MAIN_RUN_COMMAND, repo_root=self.repo, manifest_sha256=self.pin
        )
        self.assertEqual(set(scored), {s.scenario_id for s in loaded.scenarios})


class TestRefused(GuardCase):
    def test_off_the_tag(self) -> None:
        (self.repo / "later.txt").write_text("x\n", encoding="utf-8")
        git(self.repo, "add", "later.txt")
        git(self.repo, "commit", "-q", "-m", "after the tag")
        self.refused_and_nothing_read(PROTOCOL_TAG)

    def test_untagged_or_another_tag(self) -> None:
        for tag in (None, "protocol-v2", "protocol-v1-rc"):
            with self.subTest(tag=tag):
                self.repo = fake_repo(self.dirs.new("dail-p10e-repo-"), tag=tag)
                self.refused_and_nothing_read(PROTOCOL_TAG)

    def test_a_dirty_tree(self) -> None:
        (self.repo / "untracked.txt").write_text("x\n", encoding="utf-8")
        self.refused_and_nothing_read("clean")
        (self.repo / "untracked.txt").unlink()
        (self.repo / "README.md").write_text("changed\n", encoding="utf-8")
        self.refused_and_nothing_read("clean")

    def test_outside_the_main_run_command(self) -> None:
        for command in (None, "", "run", "dry-run", "generate", "main-run ", "MAIN-RUN"):
            with self.subTest(command=command):
                self.refused_and_nothing_read("main-run command", command=command)

    def test_a_wrong_private_manifest_hash(self) -> None:
        with self.assertRaisesRegex(GuardRefused, "sha256"):
            self.open(manifest_sha256="0" * 64)
        with self.assertRaisesRegex(GuardRefused, "sha256"):
            open_test_split(self.private, command=MAIN_RUN_COMMAND, repo_root=self.repo)
        with self.assertRaises(LoaderError):
            load_test(self.private, command=MAIN_RUN_COMMAND, repo_root=self.repo)
        with self.assertRaises(LoaderError):
            load_test_labels(self.private, command=MAIN_RUN_COMMAND, repo_root=self.repo)

    def test_a_changed_scenario_after_the_manifest_is_refused(self) -> None:
        sid = sorted(p.name for p in self.private.iterdir() if p.is_dir())[0]
        path = self.private / sid / "scenario.json"
        path.write_bytes(path.read_bytes() + b" ")
        for entry in (load_test, load_test_labels):
            with self.subTest(entry=entry.__name__), self.assertRaises(LoaderError):
                entry(
                    self.private,
                    command=MAIN_RUN_COMMAND,
                    repo_root=self.repo,
                    manifest_sha256=self.pin,
                )

    def test_no_private_manifest(self) -> None:
        (self.private / PRIVATE_MANIFEST_NAME).unlink()
        with self.assertRaisesRegex(GuardRefused, PRIVATE_MANIFEST_NAME):
            self.open()


class TestTheDevEntryPointsNeverOpenTheTestSplit(GuardCase):
    def test_load_and_load_labels_refuse_the_test_split_even_with_all_four(self) -> None:
        self.open()  # all four hold
        with self.assertRaisesRegex(LoaderError, "test split"):
            load(self.private, split="test")
        with self.assertRaises(LoaderError):
            load_labels(self.private, split="test")


class TestThePin(unittest.TestCase):
    def test_the_default_pin_is_terrapreserves(self) -> None:
        self.assertEqual(PRIVATE_MANIFEST_SHA256, REAL_PIN)
        self.assertEqual(PROTOCOL_TAG, "protocol-v1")
        self.assertEqual(MAIN_RUN_COMMAND, "main-run")

    def test_the_pin_is_in_terrapreserves_sums_file(self) -> None:
        root = os.environ.get("TERRAPRESERVE_ROOT")
        if not root:
            self.skipTest("set TERRAPRESERVE_ROOT to check V1_MANIFEST.sha256 at the tag")
        sums = git(Path(root), "show", "terrapreserve-v1.0:scenarios/V1_MANIFEST.sha256")
        found = dict(reversed(line.split("  ", 1)) for line in sums.splitlines())
        self.assertEqual(found[PRIVATE_MANIFEST_NAME], PRIVATE_MANIFEST_SHA256)


if __name__ == "__main__":
    unittest.main()
