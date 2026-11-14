"""The P10a wiring run (work package Step 5): opt-in, the author's machine only.

"Wiring run (opt-in test): one dev repair scenario, the P7 wiring model, k = 1, end to end
(generate, freeze, replay under four conditions, export)."

Environment: ``DAIL_OLLAMA_TEST=1``, ``TERRAPRESERVE_ROOT`` (a checkout at ``terrapreserve-v1.0``,
dev split only) and the local Ollama server with the pinned wiring model
(``experiments/config/models.toml``, key ``qwen2_5-coder-1_5b``). Output goes to a temporary
directory. The model is not judged: an invalid patch is a valid outcome of a wiring run, and then
replay has no decision to make (the test says which happened).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

WIRING_MODEL = "qwen2_5-coder-1_5b"


@unittest.skipUnless(
    os.environ.get("DAIL_OLLAMA_TEST") == "1" and os.environ.get("TERRAPRESERVE_ROOT"),
    "opt-in: DAIL_OLLAMA_TEST=1 and TERRAPRESERVE_ROOT",
)
class TestWiringRun(unittest.TestCase):
    def test_generate_freeze_replay_export(self) -> None:
        from experiments.generation.__main__ import choose
        from experiments.generation.export import export_for_oracle
        from experiments.generation.models import load_pins
        from experiments.generation.replay import replay_candidates
        from experiments.generation.run import (
            GenerationSpec,
            generate_candidates,
            generation_config,
        )
        from experiments.loader import load
        from experiments.runner import experiment_config
        from llm.adapter.ollama import OllamaProvider

        loaded = load(Path(os.environ["TERRAPRESERVE_ROOT"]))
        (given,) = choose(loaded.scenarios, only=None, per_family=1, families=("F2",))
        pin = load_pins()[WIRING_MODEL]
        provider = OllamaProvider(expected_digest=pin.digest)
        with tempfile.TemporaryDirectory(prefix="dail-p10a-wiring-") as tmp:
            root = Path(tmp)
            summary = generate_candidates(
                spec=GenerationSpec(name="p10a-wiring", version="1"),
                inputs=[given],
                models=[(pin, provider, provider.model_facts(pin.tag))],
                k=1,
                root=root,
                generation_enabled=generation_config().get("llm.generation_enabled") is True,
                environment={"ollama_version": provider.server_version()},
            )
            replay = replay_candidates(
                root=root,
                generation_id=summary.generation_id,
                scenarios={s.scenario_id: s for s in loaded.scenarios},
                conditions=("A", "B", "C", "C_PRIME"),
                config=experiment_config(),
                replay_name="wiring",
            )
            export = json.loads(
                export_for_oracle(
                    root=root, generation_id=summary.generation_id, inputs=[given]
                ).read_bytes()
            )
            (row,) = summary.attempts
            attempt = json.loads(
                (
                    root / "candidates" / summary.generation_id / pin.key / given.scenario_id
                    / "1" / "attempt.json"
                ).read_bytes()
            )  # fmt: skip
            facts = {
                "scenario_id": given.scenario_id,
                "target": given.target_invariant_id,
                "generation_id": summary.generation_id,
                "manifest_sha256": summary.manifest_sha256,
                "status": row["status"],
                "failure_class": row["failure_class"],
                "failure_source": row["failure_source"],
                "parse_errors": attempt["parse_errors"],
                "validation_errors": attempt["validation_errors"],
                "latency_ms": attempt["observability"]["latency_ms"],
                "token_usage": attempt["observability"]["token_usage"],
                "estimated_input_tokens": attempt["observability"]["budget"].get(
                    "estimated_input_tokens"
                ),
                "replay": [
                    {
                        "condition": r["condition"],
                        "tree_hash_matches": r["tree_hash_matches"],
                        "decision": r["decision"],
                        "build_deleted": r["build_dir"] is None
                        or not Path(r["build_dir"]).exists(),
                    }
                    for r in replay.results
                ],
                "generation_failures": replay.generation_failures,
                "exported": [
                    {"candidate_id": c["candidate_id"], "files": sorted(c["files"])}
                    for c in export["candidates"]
                ],
                "export_refused": export["refused"],
            }
            print("\nWIRING-RUN-P10A " + json.dumps(facts, sort_keys=True))
            if row["status"] == "PATCH":
                self.assertEqual(len(replay.results), 4)
                self.assertTrue(all(r["tree_hash_matches"] for r in replay.results))
                self.assertEqual(len(export["candidates"]), 1)
            else:
                self.assertEqual(replay.results, [])
                self.assertEqual(export["candidates"], [])


if __name__ == "__main__":
    unittest.main()
