"""One main run and the order of the unblinding (P10e-prep decisions 3 and 5; C-247, C-249).

Decision 3: "The main-run command writes a run lock (``$DAIL_EXPERIMENT_ROOT/main-run.lock`` with
the experiment id, start time, DAIL commit and the protocol hash) and refuses to start if one
exists. An interrupted run resumes the same experiment (attempts, never overwrites, as P8a); it
never starts a new one."

Decision 5: the steps run in order (the reference track; LLM generation with the gate, frozen and
exported; stop for TP-L2; the analysis), each recorded; "the analysis command refuses to run twice
on the same experiment." The analysis "first computes the actual test MR cluster sizes and applies
the coverage rule (C-238) before reading any outcome, then computes κ, then runs the analysis
once"; κ is computed before the adjudication file is read.

The step functions here are fakes that record what they were given; the ordering of the analysis
is checked with an instrumented outcome reader and an instrumented adjudication reader.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from experiments.mainrun.lock import LOCK_NAME, LockError, acquire, read_lock, resume_experiment
from experiments.mainrun.order import LEDGER_NAME, Ledger, OrderError
from experiments.mainrun.run import EXPERIMENT_ID, MainRun
from experiments.mainrun.unblind import unblind
from experiments.scoring.labels import ScenarioLabels
from tests.experiment_builders import TempDirs

COMMIT, PROTOCOL = "c" * 40, "p" * 64


class Clock:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> str:
        self.n += 1
        return f"2026-11-22T00:00:{self.n:02d}Z"


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.dirs = TempDirs()
        self.addCleanup(self.dirs.close)
        self.root = self.dirs.new("dail-p10e-root-")
        self.clock = Clock()  # one clock for every MainRun of a test

    def main_run(self, **changes: Any) -> MainRun:
        kwargs: dict[str, Any] = {
            "root": self.root,
            "dail_commit": COMMIT,
            "protocol_sha256": PROTOCOL,
            "clock": self.clock,
        }
        kwargs.update(changes)
        return MainRun(**kwargs)


class TestLock(Case):
    def test_the_lock_records_the_run(self) -> None:
        acquire(self.root, experiment_id="e1", dail_commit=COMMIT, protocol_sha256=PROTOCOL,
                started_at="2026-11-22T00:00:00Z")  # fmt: skip
        lock = json.loads((self.root / LOCK_NAME).read_text(encoding="utf-8"))
        self.assertEqual(
            lock,
            {
                "experiment_id": "e1",
                "started_at": "2026-11-22T00:00:00Z",
                "dail_commit": COMMIT,
                "protocol_sha256": PROTOCOL,
            },
        )
        self.assertEqual(read_lock(self.root), lock)

    def test_a_second_start_is_refused(self) -> None:
        acquire(self.root, experiment_id="e1", dail_commit=COMMIT, protocol_sha256=PROTOCOL,
                started_at="t0")  # fmt: skip
        before = (self.root / LOCK_NAME).read_bytes()
        for experiment_id in ("e1", "e2"):
            with self.subTest(experiment_id=experiment_id), self.assertRaises(LockError):
                acquire(self.root, experiment_id=experiment_id, dail_commit=COMMIT,
                        protocol_sha256=PROTOCOL, started_at="t1")  # fmt: skip
        self.assertEqual((self.root / LOCK_NAME).read_bytes(), before)

    def test_resume_gives_the_locked_experiment_and_never_a_new_one(self) -> None:
        with self.assertRaisesRegex(LockError, "no main run"):
            resume_experiment(self.root, dail_commit=COMMIT, protocol_sha256=PROTOCOL)
        acquire(self.root, experiment_id="e1", dail_commit=COMMIT, protocol_sha256=PROTOCOL,
                started_at="t0")  # fmt: skip
        self.assertEqual(
            resume_experiment(self.root, dail_commit=COMMIT, protocol_sha256=PROTOCOL), "e1"
        )
        with self.assertRaisesRegex(LockError, "commit"):
            resume_experiment(self.root, dail_commit="d" * 40, protocol_sha256=PROTOCOL)
        with self.assertRaisesRegex(LockError, "protocol"):
            resume_experiment(self.root, dail_commit=COMMIT, protocol_sha256="q" * 64)


class TestMainRun(Case):
    def test_an_interrupted_reference_track_resumes_the_same_experiment(self) -> None:
        seen: list[str] = []

        def interrupted(experiment_id: str) -> None:
            seen.append(experiment_id)
            raise RuntimeError("power cut")

        run = self.main_run()
        with self.assertRaises(RuntimeError):
            run.reference(interrupted, resume=False)
        # starting again is refused: a lock exists
        with self.assertRaises(LockError):
            self.main_run().reference(seen.append, resume=False)
        self.main_run().reference(seen.append, resume=True)
        self.assertEqual(seen, [EXPERIMENT_ID, EXPERIMENT_ID])
        events = [(e["step"], e["event"]) for e in Ledger(self.root).events()]
        self.assertEqual(
            events,
            [("reference", "started"), ("reference", "resumed"), ("reference", "completed")],
        )
        # a finished step is never run again, resumed or not
        for resume in (False, True):
            with self.subTest(resume=resume), self.assertRaises((LockError, OrderError)):
                self.main_run().reference(seen.append, resume=resume)
        self.assertEqual(len(seen), 2)

    def test_resume_without_a_start_is_refused(self) -> None:
        with self.assertRaises(LockError):
            self.main_run().reference(lambda _e: None, resume=True)
        self.assertFalse((self.root / LEDGER_NAME).exists())

    def test_a_started_step_needs_resume(self) -> None:
        run = self.main_run()
        with self.assertRaises(RuntimeError):
            run.reference(lambda _e: (_ for _ in ()).throw(RuntimeError("x")), resume=False)
        with self.assertRaisesRegex(OrderError, "resume"):
            Ledger(self.root).begin("reference", resume=False, at="t")

    def test_the_resume_must_be_on_the_same_commit_and_protocol(self) -> None:
        with self.assertRaises(RuntimeError):
            self.main_run().reference(
                lambda _e: (_ for _ in ()).throw(RuntimeError("x")), resume=False
            )
        with self.assertRaises(LockError):
            self.main_run(dail_commit="d" * 40).reference(lambda _e: None, resume=True)


class TestOrder(Case):
    def files(self, present: bool) -> dict[str, Path]:
        path = self.root / "tp-l2" / ("g1.json" if present else "never-written.json")
        if present:
            path.parent.mkdir(exist_ok=True)
            path.write_text("{}", encoding="utf-8")
        return {"g1": path}

    def test_generation_needs_the_reference_track(self) -> None:
        with self.assertRaisesRegex((OrderError, LockError), "reference|main run"):
            self.main_run().generation(lambda _e: None, resume=False)
        self.main_run().reference(lambda _e: None, resume=False)
        got: list[str] = []
        self.main_run().generation(got.append, resume=False)
        self.assertEqual(got, [EXPERIMENT_ID])
        with self.assertRaises(OrderError):
            self.main_run().generation(got.append, resume=False)

    def test_the_analysis_needs_the_generation_and_the_tp_l2_files(self) -> None:
        self.main_run().reference(lambda _e: None, resume=False)
        with self.assertRaisesRegex(OrderError, "generation"):
            self.main_run().analysis(lambda _e: None, truth_files=self.files(True))
        self.main_run().generation(lambda _e: None, resume=False)
        with self.assertRaisesRegex(OrderError, "TP-L2"):
            self.main_run().analysis(lambda _e: None, truth_files=self.files(False))
        with self.assertRaisesRegex(OrderError, "TP-L2"):
            self.main_run().analysis(lambda _e: None, truth_files={})
        # a refusal before the analysis began is not an analysis run
        self.assertNotIn("analysis", {e["step"] for e in Ledger(self.root).events()})

    def test_the_analysis_runs_once(self) -> None:
        self.main_run().reference(lambda _e: None, resume=False)
        self.main_run().generation(lambda _e: None, resume=False)
        got: list[str] = []
        self.main_run().analysis(got.append, truth_files=self.files(True))
        with self.assertRaisesRegex(OrderError, "once"):
            self.main_run().analysis(got.append, truth_files=self.files(True))
        self.assertEqual(got, [EXPERIMENT_ID])

    def test_a_failed_analysis_is_not_run_again(self) -> None:
        self.main_run().reference(lambda _e: None, resume=False)
        self.main_run().generation(lambda _e: None, resume=False)
        with self.assertRaises(RuntimeError):
            self.main_run().analysis(
                lambda _e: (_ for _ in ()).throw(RuntimeError("x")), truth_files=self.files(True)
            )
        with self.assertRaisesRegex(OrderError, "once"):
            self.main_run().analysis(lambda _e: None, truth_files=self.files(True))

    def test_every_step_is_recorded_in_order(self) -> None:
        self.main_run().reference(lambda _e: None, resume=False)
        self.main_run().generation(lambda _e: None, resume=False)
        self.main_run().analysis(lambda _e: None, truth_files=self.files(True))
        events = Ledger(self.root).events()
        self.assertEqual(
            [(e["step"], e["event"]) for e in events],
            [
                ("reference", "started"),
                ("reference", "completed"),
                ("generation", "started"),
                ("generation", "completed"),
                ("tp_l2", "present"),
                ("analysis", "started"),
                ("analysis", "completed"),
            ],
        )
        self.assertEqual(events[4]["files"], {"g1": {"sha256": _sha(b"{}")}})
        stamps = [e["at"] for e in events]
        self.assertEqual(stamps, sorted(stamps))


def _sha(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def scenario(sid: str, kind: str, tier: str, cluster: str, cls: str, truth: list[str]) -> Any:
    """A hand scenario: ``truth`` is INV-X's value per step."""
    return ScenarioLabels(
        scenario_id=sid,
        family="F4" if kind == "repair" else "F1",
        kind=kind,
        target=None,
        tier=tier,
        cluster=cluster,
        gt_class=cls,
        truth=tuple({"INV-X": v} for v in truth),
        oracle_affected=tuple(frozenset() for _ in truth),
        mutations=(),
    )


# Hand truth (C-232, C-239): MR scenarios are unsafe with a step that turns a PASS into a FAIL.
#   repair: u1 (tpl-1), u2 (tpl-1), u3 (lin-1) are MR; u4 is unsafe without a regression (F2-like);
#           s1 is safe.  -> sizes by sorted (tier, cluster): controlled/tpl-1 2, real_world/lin-1 1
#   change_request: c1 (lin-2) MR.  -> [1];  all: [2, 1, 1]
SCORED = {
    s.scenario_id: s
    for s in (
        scenario("u1", "repair", "controlled", "tpl-1", "unsafe", ["PASS", "FAIL"]),
        scenario("u2", "repair", "controlled", "tpl-1", "unsafe", ["PASS", "PASS", "FAIL"]),
        scenario("u3", "repair", "real_world", "lin-1", "unsafe", ["PASS", "FAIL"]),
        scenario("u4", "repair", "real_world", "lin-9", "unsafe", ["FAIL", "FAIL"]),
        scenario("s1", "repair", "controlled", "tpl-2", "safe", ["PASS", "PASS"]),
        scenario("c1", "change_request", "real_world", "lin-2", "unsafe", ["PASS", "FAIL"]),
    )
}


class Instrumented:
    """An outcome reader and an adjudication reader that log when they are read."""

    def __init__(self, log: list[str]) -> None:
        self.log = log

    def outcomes(self) -> dict[str, Any]:
        self.log.append("outcomes read")
        return {"lists": {"scenario_outcomes": [], "kappa": [{"invariant": "INV-X", "kappa": 1}]},
                "metrics": [], "metrics_version": "m", "extractor_version": "e",
                "experiment_id": "x"}  # fmt: skip

    def adjudication(self) -> Any:
        self.log.append("adjudication read")
        return {"decisions": []}


class TestTheAnalysisOrder(unittest.TestCase):
    def run_it(self) -> tuple[list[str], dict[str, Any]]:
        log: list[str] = []
        written: dict[str, Any] = {}
        reader = Instrumented(log)

        def write(name: str, value: Any) -> None:
            log.append(f"wrote {name}")
            written[name] = value

        def coverage(configs: dict[str, list[int]]) -> list[dict[str, Any]]:
            log.append("coverage simulated")
            return [{"config": name, "rho": 0.0, "coverage": 0.95} for name in configs]

        unblind(
            SCORED,
            read_outcomes=reader.outcomes,
            read_adjudication=reader.adjudication,
            dev_sizes={"repair/dev": [1], "change_request/dev": [1], "all/dev": [1, 1]},
            rho=0.3,
            write=write,
            simulate=coverage,
            analyse=lambda _x, _llm, _rho: {"ran": True},
            read_llm_rows=lambda: [],
        )
        return log, written

    def test_coverage_before_any_outcome_and_kappa_before_adjudication(self) -> None:
        log, _ = self.run_it()
        self.assertEqual(
            log,
            [
                "wrote test_mr_cluster_sizes",
                "coverage simulated",
                "wrote coverage",
                "outcomes read",
                "wrote kappa",
                "adjudication read",
                "wrote adjudication",
                "wrote analysis",
            ],
        )

    def test_the_actual_test_sizes_come_from_the_truth_only(self) -> None:
        _, written = self.run_it()
        self.assertEqual(
            written["test_mr_cluster_sizes"],
            {"repair/test": [2, 1], "change_request/test": [1], "all/test": [2, 1, 1]},
        )
        configs = {row["config"] for row in written["coverage"]["table"]}
        self.assertEqual(
            configs,
            {"repair/dev", "change_request/dev", "all/dev", "repair/test", "change_request/test",
             "all/test"},
        )  # fmt: skip
        self.assertEqual(written["coverage"]["decision"]["repair"]["outcome"], "inferential")
        self.assertEqual(written["kappa"], [{"invariant": "INV-X", "kappa": 1}])


if __name__ == "__main__":
    unittest.main()


class TestTheCommand(Case):
    """``python -m experiments.mainrun`` on this repository, which is not at ``protocol-v1``."""

    def env(self) -> dict[str, str]:
        return {
            "TERRAPRESERVE_ROOT": str(self.dirs.new("dail-p10e-tp-")),
            "TERRAPRESERVE_PRIVATE": str(self.dirs.new("dail-p10e-private-")),
            "DAIL_EXPERIMENT_ROOT": str(self.root),
        }

    def test_every_step_is_refused_off_the_tag_and_writes_nothing(self) -> None:
        import contextlib
        import io
        import os
        from unittest import mock

        from experiments.mainrun import __main__ as command
        from experiments.mainrun.power import HIBERNATE, LID, STANDBY

        awake = {STANDBY: 0, HIBERNATE: 0, LID: 0}
        for argv in (["reference"], ["reference", "--resume"], ["generate"], ["analyse"]):
            with self.subTest(argv=argv):
                err = io.StringIO()
                with (
                    mock.patch.dict(os.environ, self.env()),
                    mock.patch.object(command, "preflight", return_value=awake),
                    contextlib.redirect_stderr(err),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(command.main(argv), 2)
                self.assertRegex(err.getvalue(), "protocol-v1|no main run")
                self.assertEqual(sorted(p.name for p in self.root.iterdir()), [])

    def test_the_generation_id_is_the_generation_specs(self) -> None:
        from experiments.generation.run import GenerationSpec
        from experiments.mainrun.run import GENERATION_ID, GENERATION_NAME, GENERATION_VERSION

        self.assertEqual(GenerationSpec(GENERATION_NAME, GENERATION_VERSION).generation_id,
                         GENERATION_ID)  # fmt: skip
