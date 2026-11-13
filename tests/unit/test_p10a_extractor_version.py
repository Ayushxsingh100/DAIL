"""The extractor version, apart from the metric definitions version (P10a work package Section 3.1;
closes the P8b verdict's limit 2).

Section 3.1: "``EXTRACTOR_VERSION`` becomes its own value (``extractor-2``), separate from the metric
definitions version (``metrics-draft-1``). Every ``MetricRecord`` and report carries both. A test
fails if the extractor's code hash changes without a version change (pin the hash of the extractor
modules in a test)."

The extractor modules are the code that turns stored records into metric records:
``experiments/metrics/`` and the scoring it reads truth through (``experiments/scoring/``, with its
identity table). Their hash is the SHA-256 of the path-sorted lines ``"<relative POSIX
path>:<sha256 of the file's bytes with CRLF read as LF>"``, so a Windows checkout and CI agree.
A changed module needs a new ``EXTRACTOR_VERSION`` and a new entry in ``PINNED``; an old entry
stays, so the record of what each version was is kept.
"""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from tests.fixture_catalog import REPO_ROOT
from tests.metrics_builders import GATES, scenarios

PINNED: dict[str, str] = {
    "extractor-2": "PIN-ME",
}
EXTRACTOR_PACKAGES = ("experiments/metrics", "experiments/scoring")
CRLF, LF = b"\r\n", b"\n"


def extractor_files() -> list[Path]:
    found: list[Path] = []
    for package in EXTRACTOR_PACKAGES:
        base = REPO_ROOT / package
        found += [
            p
            for p in base.rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix in (".py", ".json")
        ]
    return sorted(found, key=lambda p: p.relative_to(REPO_ROOT).as_posix())


def hash_of(entries: list[tuple[str, bytes]]) -> str:
    lines = [
        f"{name}:{hashlib.sha256(data.replace(CRLF, LF)).hexdigest()}"
        for name, data in sorted(entries)
    ]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def entries() -> list[tuple[str, bytes]]:
    return [(p.relative_to(REPO_ROOT).as_posix(), p.read_bytes()) for p in extractor_files()]


def extractor_hash() -> str:
    return hash_of(entries())


class TestVersions(unittest.TestCase):
    def test_the_two_versions_are_separate_values(self) -> None:
        from experiments.metrics.extractor import EXTRACTOR_VERSION, METRICS_VERSION

        self.assertEqual(EXTRACTOR_VERSION, "extractor-2")
        self.assertEqual(METRICS_VERSION, "metrics-draft-1")

    def test_every_metric_record_and_the_report_carry_both(self) -> None:
        from experiments.metrics.extractor import extract
        from experiments.metrics.model import Transition
        from experiments.report.build import build_report
        from experiments.scoring.identity import load_identity_table

        transition = Transition(
            "t", "Z", "C", 1, "EVALUATED", "PROMOTE", (), (), GATES, frozenset(), (), None
        )
        x = extract(
            experiment_id="e",
            transitions=[transition],
            scored=scenarios(),
            baselines={},
            identity=load_identity_table(),
        )
        self.assertTrue(x.metrics)
        for record in x.metrics:
            self.assertEqual(record["metrics_version"], "metrics-draft-1")
            self.assertEqual(record["extractor_version"], "extractor-2")
        definition = {"experiment_id": "e", "name": "n", "version": "1", "condition_set": ["C"]}
        report = build_report(definition=definition, statuses={"t": "COMPLETED"}, extraction=x)
        self.assertEqual(report["metrics_version"], "metrics-draft-1")
        self.assertEqual(report["extractor_version"], "extractor-2")


class TestCodePin(unittest.TestCase):
    def test_the_extractor_modules_have_the_hash_pinned_for_their_version(self) -> None:
        from experiments.metrics.extractor import EXTRACTOR_VERSION

        self.assertIn(REPO_ROOT / "experiments" / "metrics" / "extractor.py", extractor_files())
        self.assertIn(
            EXTRACTOR_VERSION, PINNED, "a new extractor version needs its pinned code hash"
        )
        self.assertEqual(
            extractor_hash(),
            PINNED[EXTRACTOR_VERSION],
            "the extractor's code changed: give it a new EXTRACTOR_VERSION and pin its hash",
        )

    def test_the_hash_sees_a_one_byte_change_and_ignores_crlf(self) -> None:
        found = entries()
        self.assertGreater(len(found), 3)
        name, data = found[0]
        changed = [(name, data + b" ")] + found[1:]
        self.assertNotEqual(hash_of(changed), hash_of(found))
        crlf = [(n, d.replace(CRLF, LF).replace(LF, CRLF)) for n, d in found]
        self.assertEqual(hash_of(crlf), hash_of(found))


if __name__ == "__main__":
    unittest.main()
