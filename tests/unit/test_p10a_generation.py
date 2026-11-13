"""LLM candidates for the experiment (P10a work package Section 3.3; decisions 3 to 5, C-218 to C-220).

Expected values come from the quoted text:

Decision 4: "repair scenarios only (``target.kind = "repair"``) ... The task given to the model is a
fixed template per target invariant: "Repair ``<invariant id>``: ``<the registry's one-line statement
of the invariant>``. Keep every other protected invariant satisfied. Make the smallest change."
TerraPreserve's ``target.description`` and ``intent`` are never given to the model."
Decision 5: "``AllowedChangeScope`` = every resource address of S0, every supported type, no
attribute restriction, and all four operations. It is the same for every condition and is recorded
with each candidate."
Section 3.3 "Model configuration": "The run refuses a model whose installed digest is not the pinned
one." "Freezing: each attempt (valid or not) is stored under ``$DAIL_EXPERIMENT_ROOT/candidates/
<generation_id>/<model>/<scenario_id>/<k>/`` ... A ``candidates_manifest.json`` lists every attempt
with hashes ... Frozen candidates are never regenerated or edited." "Replay: ... The directory is
rebuilt by the validator from the frozen patch in the same call, then deleted ... Each run checks
that the rebuilt tree hash equals the frozen one. Invalid attempts are recorded as generation
failures, never as decisions." "Export for the oracle: for every valid candidate, a
configuration-only directory (the built ``.tf`` files and nothing else) plus an
``oracle_export.json`` with ids and hashes." "``generation_enabled`` is turned on only in the
harness's reviewed configuration copy, the same way as C-207 (3)."

Everything runs on the mini TerraPreserve tree with the fake provider: no network.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
import unittest
from pathlib import Path
from typing import Any

from core.application.config import load_config
from core.domain.change_scope import ALL_OPERATIONS
from experiments.loader import LoadedSet, load
from llm.adapter.context import SUPPORTED_TYPES
from llm.adapter.fake import FakeProvider
from llm.adapter.provider import ProviderError, ProviderReply
from llm.schemas.records import FailureClass
from tests.experiment_builders import F1, F2, F4, F8, TempDirs, mini_root
from tests.fixture_catalog import REPO_ROOT
from tests.llm_patch_builders import DB_RULE, SG_APP, SG_APP_CLOSED, SSH_RULE, repair

DIGEST = "b" * 64
TAG = "fake-coder:1b"
VALID = repair(SG_APP_CLOSED, [SG_APP, SSH_RULE])
BROKEN = repair('resource "aws_security_group" "app" {\n', [SG_APP])
CONDITIONS = ("A", "B", "C", "C_PRIME")


def ok(text: str) -> ProviderReply:
    return ProviderReply(text=text, latency_ms=12.0, token_usage={"input": 100, "output": 20})


def pin(**changes: Any) -> Any:
    from experiments.generation.models import ModelPin

    values: dict[str, Any] = {
        "key": "fake-coder-1b",
        "tag": TAG,
        "digest": DIGEST,
        "quantization": "Q4_K_M",
        "size": "1 GB",
        "licence": "Apache-2.0",
        "licence_source": "test",
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 11,
        "max_output_tokens": 1024,
        "timeout_seconds": 30.0,
        "num_ctx": 32768,
    }
    values.update(changes)
    return ModelPin(**values)


def installed(digest: str = DIGEST) -> dict[str, str]:
    return {"name": TAG, "digest": digest, "quantization": "Q4_K_M"}


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.dirs = TempDirs()
        self.addCleanup(self.dirs.close)
        mini = mini_root(self.dirs.new())
        self.loaded: LoadedSet = load(mini.root, manifest_sha256=mini.manifest_sha256)
        self.by_id = {s.scenario_id: s for s in self.loaded.scenarios}
        self.out = self.dirs.new("dail-p10a-out-")

    def inputs(self, *ids: str) -> list[Any]:
        from experiments.generation.task import generation_input

        return [generation_input(self.by_id[sid]) for sid in ids]

    def generate(self, script: list[Any], ids: tuple[str, ...] = (F2,), **options: Any) -> Any:
        from experiments.generation.run import GenerationSpec, generate_candidates

        provider = options.pop("provider", None) or FakeProvider(script)
        self.provider = provider
        settings: dict[str, Any] = {
            "spec": GenerationSpec(name="p10a-test", version="1"),
            "inputs": self.inputs(*ids),
            "models": [(pin(), provider, installed())],
            "k": 1,
            "root": self.out,
            "generation_enabled": True,
            "environment": {"dail_commit": "test"},
        }
        settings.update(options)
        return generate_candidates(**settings)

    def attempt_dir(self, summary: Any, sid: str = F2, k: int = 1) -> Path:
        return self.out / "candidates" / summary.generation_id / "fake-coder-1b" / sid / str(k)

    def replay(self, summary: Any, name: str = "replay-1") -> Any:
        from experiments.generation.replay import replay_candidates
        from experiments.runner import experiment_config

        return replay_candidates(
            root=self.out,
            generation_id=summary.generation_id,
            scenarios=self.by_id,
            conditions=CONDITIONS,
            config=experiment_config(),
            replay_name=name,
        )


class TestTask(Case):
    def test_only_repair_scenarios_get_candidates(self) -> None:
        from experiments.generation.task import GenerationError, generation_input

        with self.assertRaises(GenerationError):
            generation_input(self.by_id[F1])  # a change request
        for sid in (F2, F4, F8):
            self.assertEqual(generation_input(self.by_id[sid]).target_invariant_id, "INV-SEC-001")

    def test_the_input_holds_s0_only_and_the_listed_fields(self) -> None:
        from experiments.generation.task import GenerationInput

        fields = {f.name for f in dataclasses.fields(GenerationInput)}
        self.assertEqual(
            fields,
            {
                "scenario_id",
                "family",
                "s0_dir",
                "s0_content_hash",
                "target_invariant_id",
                "source_endpoint",
                "destination_endpoint",
                "variable_values",
            },
        )
        (given,) = self.inputs(F8)
        self.assertEqual(given.s0_dir, self.by_id[F8].steps[0].directory)
        self.assertEqual(given.s0_content_hash, self.by_id[F8].steps[0].content_hash)

    def test_the_task_is_the_fixed_template(self) -> None:
        from datetime import UTC, datetime

        from core.domain.registry_v1_1 import registry_v1_1_invariants
        from experiments.generation.task import objective_for

        (definition,) = [
            d
            for d in registry_v1_1_invariants(datetime(2026, 1, 1, tzinfo=UTC), source="a.s", destination="b.d")
            if d.invariant_id == "INV-SEC-001"
        ]
        self.assertEqual(
            objective_for(definition),
            f"Repair INV-SEC-001: {definition.description} Keep every other protected invariant "
            "satisfied. Make the smallest change.",
        )

    def test_the_prompt_holds_no_description_or_intent(self) -> None:
        summary = self.generate([ok(VALID)])
        (call,) = self.provider.calls
        scenario_doc = json.loads(
            (self.by_id[F2].steps[0].directory.parent / "scenario.json").read_text("utf-8")
        )
        for text in (call.system, call.task):
            self.assertNotIn(scenario_doc["target"]["description"], text)
            self.assertNotIn("junk", text)  # every label and intent field holds "junk"
        self.assertIn("Repair INV-SEC-001: ", call.task)
        self.assertEqual(summary.attempts[0]["status"], "PATCH")


class TestScope(Case):
    def test_the_scope_is_recorded_and_identical_across_conditions(self) -> None:
        summary = self.generate([ok(VALID)])
        frozen = json.loads((self.attempt_dir(summary) / "attempt.json").read_text("utf-8"))
        scope = frozen["scope"]
        s0_addresses = frozen["parent"]["resource_addresses"]
        self.assertEqual(
            scope,
            {
                "resource_addresses": sorted(s0_addresses),
                "resource_types": list(SUPPORTED_TYPES),
                "attributes": [],
                "operation_types": [op.value for op in ALL_OPERATIONS],
            },
        )
        self.assertIn(SSH_RULE, scope["resource_addresses"])
        self.assertIn(DB_RULE, scope["resource_addresses"])
        replayed = self.replay(summary)
        self.assertEqual(sorted(r["condition"] for r in replayed.results), sorted(CONDITIONS))
        for result in replayed.results:
            self.assertEqual(result["scope"], scope, result["condition"])


class TestDigest(Case):
    def test_a_model_whose_installed_digest_is_not_the_pinned_one_is_refused(self) -> None:
        from experiments.generation.models import ModelRefused

        provider = FakeProvider([ok(VALID)])
        with self.assertRaises(ModelRefused):
            self.generate([], provider=provider, models=[(pin(), provider, installed("c" * 64))])
        self.assertEqual(provider.calls, [])
        self.assertFalse((self.out / "candidates").exists() and any(
            p.name == "attempt.json" for p in (self.out / "candidates").rglob("*")
        ))

    def test_a_missing_model_is_refused(self) -> None:
        from experiments.generation.models import ModelRefused, check_installed

        with self.assertRaises(ModelRefused):
            check_installed(pin(), {"name": "other:1b", "digest": DIGEST})


class TestFreezing(Case):
    def test_each_attempt_and_the_manifest_are_stored_with_hashes(self) -> None:
        summary = self.generate([ok(VALID), ok(BROKEN), ok(BROKEN)], ids=(F2, F4))
        manifest_path = self.out / "candidates" / summary.generation_id / "candidates_manifest.json"
        raw = manifest_path.read_bytes()
        self.assertEqual(summary.manifest_sha256, hashlib.sha256(raw).hexdigest())
        manifest = json.loads(raw)
        rows = {(r["scenario_id"], r["k"]): r for r in manifest["attempts"]}
        self.assertEqual(set(rows), {(F2, 1), (F4, 1)})
        valid, invalid = rows[(F2, 1)], rows[(F4, 1)]
        self.assertEqual(valid["status"], "PATCH")
        self.assertIsNone(valid["failure_class"])
        self.assertEqual(invalid["status"], "FAILED")
        self.assertEqual(invalid["failure_class"], "INVALID_OUTPUT")
        patch = (self.attempt_dir(summary) / "patch.tf").read_bytes()
        self.assertEqual(valid["patch_sha256"], hashlib.sha256(patch).hexdigest())
        self.assertIsNone(invalid["patch_sha256"])
        self.assertFalse((self.attempt_dir(summary, F4) / "patch.tf").exists())
        for row in rows.values():
            base = self.out / "candidates" / summary.generation_id
            for name, digest in row["files"].items():
                self.assertEqual(hashlib.sha256((base / name).read_bytes()).hexdigest(), digest)
        # the request and response records of every attempt, retries included (P7's records)
        records = sorted(p.name for p in (self.attempt_dir(summary, F4) / "records").iterdir())
        self.assertEqual(records, ["request-1.json", "request-2.json", "response-1.json", "response-2.json"])

    def test_a_frozen_generation_is_never_regenerated(self) -> None:
        from experiments.generation.run import GenerationError

        summary = self.generate([ok(VALID)])
        before = {p: p.read_bytes() for p in self.attempt_dir(summary).rglob("*") if p.is_file()}
        provider = FakeProvider([ok(BROKEN)])
        with self.assertRaises(GenerationError):
            self.generate([], provider=provider, models=[(pin(), provider, installed())])
        self.assertEqual(provider.calls, [])
        after = {p: p.read_bytes() for p in self.attempt_dir(summary).rglob("*") if p.is_file()}
        self.assertEqual(after, before)

    def test_an_interrupted_attempt_is_never_overwritten(self) -> None:
        from experiments.generation.run import GenerationError, GenerationSpec

        spec = GenerationSpec(name="p10a-test", version="1")
        partial = self.out / "candidates" / spec.generation_id / "fake-coder-1b" / F2 / "1"
        partial.mkdir(parents=True)
        (partial / "records").mkdir()
        with self.assertRaises(GenerationError):
            self.generate([ok(VALID)])
        self.assertEqual(list(partial.iterdir()), [partial / "records"])

    def test_generation_needs_the_switch(self) -> None:
        summary = self.generate([ok(VALID)], generation_enabled=False)
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(summary.attempts[0]["status"], "DISABLED")

    def test_the_switch_is_on_only_in_the_reviewed_copy(self) -> None:
        from experiments.generation.run import EXPERIMENT_LLM_FILE, generation_config

        self.assertIs(load_config(REPO_ROOT / "config", "experiment", environ={}).get(
            "llm.generation_enabled"
        ), False)
        self.assertIs(generation_config().get("llm.generation_enabled"), True)
        self.assertEqual(EXPERIMENT_LLM_FILE, REPO_ROOT / "experiments" / "config" / "llm.toml")
        summary = self.generate([ok(VALID)])
        definition = json.loads(
            (self.out / "candidates" / summary.generation_id / "definition.json").read_text("utf-8")
        )
        self.assertEqual(
            definition["experiment_llm_config_sha256"],
            hashlib.sha256(EXPERIMENT_LLM_FILE.read_bytes()).hexdigest(),
        )


class TestReplay(Case):
    def test_a_valid_candidate_is_rebuilt_checked_evaluated_and_deleted(self) -> None:
        summary = self.generate([ok(VALID)])
        replayed = self.replay(summary)
        self.assertEqual(len(replayed.results), 4)
        frozen = json.loads((self.attempt_dir(summary) / "attempt.json").read_text("utf-8"))
        for result in replayed.results:
            self.assertTrue(result["tree_hash_matches"])
            self.assertEqual(result["rebuilt_tree_hash"], frozen["candidate_tree_hash"])
            self.assertIn(result["decision"], ("PROMOTE", "REJECT"))
            self.assertFalse(Path(result["build_dir"]).exists())  # deleted after the call
        by_condition = {r["condition"]: r["decision"] for r in replayed.results}
        self.assertEqual(by_condition["C"], "PROMOTE")  # SSH closed, the path kept

    def test_an_edited_frozen_patch_is_refused_without_a_decision(self) -> None:
        summary = self.generate([ok(VALID)])
        responses = self.attempt_dir(summary) / "records" / "response-1.json"
        record = json.loads(responses.read_text("utf-8"))
        record["raw_response"] = record["raw_response"].replace('name        = \\"app\\"', 'name = \\"app2\\"')
        responses.chmod(0o666)
        responses.write_text(json.dumps(record), "utf-8")
        replayed = self.replay(summary)
        for result in replayed.results:
            self.assertFalse(result["tree_hash_matches"])
            self.assertIsNone(result["decision"])

    def test_invalid_attempts_are_generation_failures_not_decisions(self) -> None:
        summary = self.generate([ok(BROKEN), ok(BROKEN)])
        replayed = self.replay(summary)
        self.assertEqual(replayed.results, [])
        self.assertEqual(
            [(f["scenario_id"], f["failure_class"]) for f in replayed.generation_failures],
            [(F2, "INVALID_OUTPUT")],
        )

    def test_a_replay_is_written_once(self) -> None:
        from experiments.generation.run import GenerationError

        summary = self.generate([ok(VALID)])
        self.replay(summary)
        with self.assertRaises(GenerationError):
            self.replay(summary)


class TestExport(Case):
    def test_the_export_holds_only_the_built_tf_files_and_its_index(self) -> None:
        from experiments.generation.export import export_for_oracle

        summary = self.generate([ok(VALID), ok(BROKEN), ok(BROKEN)], ids=(F2, F4))
        index_path = export_for_oracle(
            root=self.out, generation_id=summary.generation_id, inputs=self.inputs(F2, F4)
        )
        index = json.loads(index_path.read_bytes())
        self.assertEqual([c["scenario_id"] for c in index["candidates"]], [F2])  # valid only
        (entry,) = index["candidates"]
        directory = index_path.parent / entry["directory"]
        names = sorted(p.name for p in directory.rglob("*") if p.is_file())
        self.assertTrue(names)
        self.assertTrue(all(n.endswith(".tf") for n in names), names)
        self.assertEqual(sorted(entry["files"]), names)
        self.assertEqual(entry["generation_id"], summary.generation_id)
        self.assertEqual(entry["tree_hash"], json.loads(
            (self.attempt_dir(summary) / "attempt.json").read_text("utf-8")
        )["candidate_tree_hash"])
        main = (directory / "main.tf").read_text("utf-8")
        self.assertNotIn("app_ssh_public", main)

    def test_the_configuration_only_copy_drops_every_other_file(self) -> None:
        from experiments.generation.parent import config_only_copy

        source = self.dirs.new()
        for name in ("main.tf", "variables.tf", "x.tf.json", "README.md", ".terraform.lock.hcl"):
            (source / name).write_text("#\n", "utf-8")
        (source / ".terraform").mkdir()
        (source / ".terraform" / "a.tf").write_text("#\n", "utf-8")
        target = self.dirs.new() / "parent"
        config_only_copy(source, target)
        self.assertEqual(
            sorted(p.name for p in target.rglob("*")), ["main.tf", "variables.tf", "x.tf.json"]
        )


class TestNoLaterStep(Case):
    def test_generation_replay_and_export_work_with_the_later_steps_gone(self) -> None:
        from experiments.generation.export import export_for_oracle

        given = self.inputs(F8)
        for step in self.by_id[F8].steps[1:]:
            shutil.rmtree(step.directory)
        summary = self.generate([ok(VALID)], ids=(F8,), inputs=given)
        self.assertEqual(summary.attempts[0]["status"], "PATCH")
        self.assertEqual(len(self.replay(summary).results), 4)
        export_for_oracle(root=self.out, generation_id=summary.generation_id, inputs=given)


class TestOllamaContextWindow(unittest.TestCase):
    """Section 3.3: "``num_ctx`` if the model needs it" (P7a verdict limit 5: the model's real
    context window)."""

    def test_num_ctx_is_sent_when_pinned_and_recorded(self) -> None:
        from llm.adapter.ollama import OllamaProvider
        from tests.unit.test_llm_ollama import FakeOllama, always, call, chat_ok, reply

        base = call()
        pinned = dataclasses.replace(base, config=dataclasses.replace(base.config, num_ctx=8192))
        with FakeOllama(always(200, chat_ok(reply()))) as server:
            OllamaProvider(base_url=server.url).generate(pinned)
        body = server.requests[-1][2]
        assert body is not None
        self.assertEqual(body["options"]["num_ctx"], 8192)
        self.assertEqual(pinned.config.to_dict()["num_ctx"], 8192)
        self.assertNotIn("num_ctx", base.config.to_dict())  # unchanged records without it

    def test_a_pin_gives_the_budget_its_context_window(self) -> None:
        from experiments.generation.models import budget_for

        limits = budget_for(pin(num_ctx=8192, max_output_tokens=1024))
        self.assertEqual(limits.max_context_tokens, 8192)
        self.assertEqual(limits.reserved_output_tokens, 1024)


class TestProviderFailures(Case):
    def test_an_unsupported_provider_answer_is_kept_apart_from_model_failures(self) -> None:
        summary = self.generate([ProviderError(FailureClass.UNSUPPORTED, "HTTP 404")])
        (row,) = summary.attempts
        self.assertEqual(row["failure_class"], "UNSUPPORTED")
        self.assertEqual(row["failure_source"], "provider")
        summary2 = self.generate(
            [ok(repair('resource "aws_lambda_function" "f" {\n}\n', ["aws_lambda_function.f"]))],
            spec=__import__("experiments.generation.run", fromlist=["GenerationSpec"]).GenerationSpec(
                name="p10a-test", version="2"
            ),
        )
        (row2,) = summary2.attempts
        self.assertEqual(row2["failure_class"], "UNSUPPORTED")
        self.assertEqual(row2["failure_source"], "model")


if __name__ == "__main__":
    unittest.main()
