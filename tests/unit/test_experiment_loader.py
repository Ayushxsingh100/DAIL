"""The TerraPreserve loader of the experiment harness (P8a; C-201, C-204; work package §3, §4.2).

Expected values come from the quoted text:

"steps[k].content_hash = SHA-256 of the newline-joined, path-sorted lines '<relative POSIX
path>:<sha256 of the file's bytes>' of the step directory; scenarios/V1_MANIFEST.json lists every
dev scenario's scenario_json_sha256 and step hashes, and its SHA-256 at tag terrapreserve-v1.0 is
665b326a... (pin this value). Trials run only scenarios with v1_role = 'target'."
§4.2: "Verifies the manifest pin, every scenario_json_sha256, and every step's content_hash ... Any
mismatch stops the run before any trial starts. Gives execution only: scenario_id, family, split,
template_id or lineage id, the step directories and hashes, target.kind, target.invariant_id,
protected_invariants, endpoints ... and the primary variable_values."
"The loader refuses split = 'test' (a test enforces it)."
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import unittest
from pathlib import Path

from experiments.loader import (
    MANIFEST_SHA256,
    TERRAPRESERVE_TAG,
    LoaderError,
    ScenarioInput,
    StepInput,
    load,
    step_content_hash,
)
from tests.experiment_builders import (
    F1,
    F8,
    RESERVE,
    TARGETS,
    TempDirs,
    content_hash,
    mini_root,
)

QUOTED_PIN = "665b326a024d295f727cd5648ffc7e0d375b9300584871f238c6bfa48edd2e2d"
EXECUTION_FIELDS = {
    "scenario_id",
    "family",
    "split",
    "template_id",
    "source_lineage_id",
    "target_kind",
    "target_invariant_id",
    "protected_invariants",
    "source_endpoint",
    "destination_endpoint",
    "variable_values",
    "steps",
}


class LoaderCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dirs = TempDirs()
        self.addCleanup(self.dirs.close)
        self.mini = mini_root(self.dirs.new())

    def load(self, **options: object):  # type: ignore[no-untyped-def]
        options.setdefault("manifest_sha256", self.mini.manifest_sha256)
        return load(self.mini.root, **options)  # type: ignore[arg-type]


class TestPins(unittest.TestCase):
    def test_the_manifest_pin_is_the_quoted_value(self) -> None:
        self.assertEqual(MANIFEST_SHA256, QUOTED_PIN)
        self.assertEqual(TERRAPRESERVE_TAG, "terrapreserve-v1.0")


class TestContentHash(unittest.TestCase):
    def test_it_follows_the_quoted_definition(self) -> None:
        dirs = TempDirs()
        self.addCleanup(dirs.close)
        step = dirs.new()
        (step / "main.tf").write_bytes(b"a\n")
        (step / "sub").mkdir()
        (step / "sub" / "x.tf").write_bytes(b"x")
        lines = [
            f"main.tf:{hashlib.sha256(b'a' + bytes([10])).hexdigest()}",
            f"sub/x.tf:{hashlib.sha256(b'x').hexdigest()}",
        ]
        expected = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
        self.assertEqual(step_content_hash(step), expected)

    def test_the_lines_are_sorted_by_path(self) -> None:
        # "a.tf" sorts before "a.tf.json" as a path; as whole lines ':' would sort after '.'
        dirs = TempDirs()
        self.addCleanup(dirs.close)
        step = dirs.new()
        (step / "a.tf").write_bytes(b"1")
        (step / "a.tf.json").write_bytes(b"2")
        lines = [
            f"a.tf:{hashlib.sha256(b'1').hexdigest()}",
            f"a.tf.json:{hashlib.sha256(b'2').hexdigest()}",
        ]
        expected = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
        self.assertEqual(step_content_hash(step), expected)
        self.assertEqual(content_hash(step), expected)  # the builder's own implementation agrees


class TestLoading(LoaderCase):
    def test_it_loads_the_targets_only(self) -> None:
        loaded = self.load()
        self.assertEqual(tuple(s.scenario_id for s in loaded.scenarios), TARGETS)
        self.assertNotIn(RESERVE, {s.scenario_id for s in loaded.scenarios})
        self.assertEqual(loaded.manifest_sha256, self.mini.manifest_sha256)

    def test_it_gives_execution_only_the_listed_fields(self) -> None:
        self.assertEqual({f.name for f in dataclasses.fields(ScenarioInput)}, EXECUTION_FIELDS)
        self.assertEqual(
            {f.name for f in dataclasses.fields(StepInput)}, {"index", "directory", "content_hash"}
        )

    def test_the_fields_are_those_of_the_scenario(self) -> None:
        loaded = {s.scenario_id: s for s in self.load().scenarios}
        f8 = loaded[F8]
        self.assertEqual(f8.family, "F8")
        self.assertEqual(f8.split, "dev")
        self.assertEqual(f8.template_id, "tpl-mini")
        self.assertIsNone(f8.source_lineage_id)
        self.assertEqual((f8.target_kind, f8.target_invariant_id), ("repair", "INV-SEC-001"))
        self.assertEqual(
            (f8.source_endpoint, f8.destination_endpoint),
            ("aws_instance.app", "aws_db_instance.database"),
        )
        self.assertEqual(
            f8.protected_invariants,
            (
                ("INV-FUNC-001", "1.0"),
                ("INV-SEC-001", "1.0"),
                ("INV-SEC-002", "1.0"),
                ("INV-SEC-003", "1.0"),
            ),
        )
        self.assertEqual(dict(f8.variable_values), {})
        self.assertEqual([s.index for s in f8.steps], [0, 1, 2])
        base = self.mini.root / "scenarios" / "dev" / F8
        for step in f8.steps:
            self.assertEqual(step.directory, base / f"step_{step.index}")
            self.assertEqual(step.content_hash, content_hash(step.directory))
        f1 = loaded[F1]
        self.assertEqual((f1.target_kind, f1.target_invariant_id), ("change_request", None))

    def test_the_fixture_record_names_every_hash(self) -> None:
        loaded = self.load()
        fixtures = {f.scenario_id: f for f in loaded.fixtures}
        self.assertEqual(set(fixtures), set(TARGETS))
        raw = (self.mini.root / "scenarios" / "dev" / F8 / "scenario.json").read_bytes()
        self.assertEqual(fixtures[F8].scenario_json_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(fixtures[F8].step_hashes), 3)

    def test_the_test_list_of_the_manifest_is_never_read(self) -> None:
        # its entry points at a directory that does not exist; loading the dev split succeeds
        self.assertFalse((self.mini.root / "scenarios" / "test").exists())
        self.assertEqual(len(self.load().scenarios), len(TARGETS))


class TestRefusals(LoaderCase):
    def test_the_test_split_is_refused(self) -> None:
        with self.assertRaisesRegex(LoaderError, "test split"):
            self.load(split="test")

    def test_any_other_split_is_refused(self) -> None:
        for split in ("TEST", "dev ", "private", ""):
            with self.subTest(split=split), self.assertRaises(LoaderError):
                self.load(split=split)

    def test_a_wrong_manifest_pin_is_refused(self) -> None:
        with self.assertRaisesRegex(LoaderError, "manifest"):
            self.load(manifest_sha256="0" * 64)
        with self.assertRaisesRegex(LoaderError, "manifest"):
            load(self.mini.root)  # the default pin is the real TerraPreserve one

    def test_a_changed_step_file_is_refused(self) -> None:
        main = self.mini.root / "scenarios" / "dev" / F8 / "step_1" / "main.tf"
        main.write_bytes(main.read_bytes() + b"\n# changed\n")
        with self.assertRaisesRegex(LoaderError, F8):
            self.load()

    def test_an_added_step_file_is_refused(self) -> None:
        extra = self.mini.root / "scenarios" / "dev" / F1 / "step_0" / "extra.tf"
        extra.write_bytes(b"# extra\n")
        with self.assertRaisesRegex(LoaderError, F1):
            self.load()

    def test_a_changed_scenario_file_is_refused(self) -> None:
        path = self.mini.root / "scenarios" / "dev" / F8 / "scenario.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(LoaderError, F8):
            self.load()

    def test_a_missing_step_directory_is_refused(self) -> None:
        step = self.mini.root / "scenarios" / "dev" / F8 / "step_2"
        for path in step.iterdir():
            path.unlink()
        step.rmdir()
        with self.assertRaisesRegex(LoaderError, F8):
            self.load()

    def test_a_scenario_whose_step_hash_disagrees_with_the_manifest_is_refused(self) -> None:
        def edit(scenario: dict[str, object]) -> None:
            if scenario["scenario_id"] == F8:
                steps = scenario["steps"]
                assert isinstance(steps, list)
                steps[1] = {**steps[1], "content_hash": "f" * 64}

        dirs = TempDirs()
        self.addCleanup(dirs.close)
        mini = mini_root(dirs.new(), edit=edit)
        with self.assertRaisesRegex(LoaderError, F8):
            load(mini.root, manifest_sha256=mini.manifest_sha256)

    def test_a_scenario_that_says_it_is_not_dev_is_refused(self) -> None:
        def edit(scenario: dict[str, object]) -> None:
            if scenario["scenario_id"] == F1:
                scenario["split"] = "test"

        dirs = TempDirs()
        self.addCleanup(dirs.close)
        mini = mini_root(dirs.new(), edit=edit)
        with self.assertRaisesRegex(LoaderError, F1):
            load(mini.root, manifest_sha256=mini.manifest_sha256)

    def test_a_real_world_scenario_names_its_source_lineage(self) -> None:
        # "template_id or lineage id": a real-world scenario has no template
        def edit(scenario: dict[str, object]) -> None:
            if scenario["scenario_id"] == F1:
                del scenario["template_id"]
                scenario["source"] = {"repo_lineage_id": "lin-mini-1", "tier": "real_world"}

        dirs = TempDirs()
        self.addCleanup(dirs.close)
        mini = mini_root(dirs.new(), edit=edit)
        loaded = {
            s.scenario_id: s
            for s in load(mini.root, manifest_sha256=mini.manifest_sha256).scenarios
        }
        self.assertIsNone(loaded[F1].template_id)
        self.assertEqual(loaded[F1].source_lineage_id, "lin-mini-1")

    def test_a_scenario_with_neither_template_nor_lineage_is_refused(self) -> None:
        def edit(scenario: dict[str, object]) -> None:
            if scenario["scenario_id"] == F1:
                del scenario["template_id"]

        dirs = TempDirs()
        self.addCleanup(dirs.close)
        mini = mini_root(dirs.new(), edit=edit)
        with self.assertRaisesRegex(LoaderError, F1):
            load(mini.root, manifest_sha256=mini.manifest_sha256)

    def test_a_missing_root_is_refused(self) -> None:
        with self.assertRaises(LoaderError):
            load(Path(self.mini.root) / "nowhere", manifest_sha256=self.mini.manifest_sha256)

    def test_nothing_partial_is_returned(self) -> None:
        # one bad scenario stops the whole load: no list of the good ones comes back
        path = self.mini.root / "scenarios" / "dev" / F1 / "scenario.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps(data), encoding="utf-8")  # same content, other bytes
        with self.assertRaises(LoaderError):
            self.load()


if __name__ == "__main__":
    unittest.main()
