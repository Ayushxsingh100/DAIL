"""Generation: provider interface, fake provider, failure classes, retries, records, the emergency
switch and no network (P7a; Doc 10 §16-§18, §20-§24, §30-§34; Doc 14 §37; C-71, C-182).

Expected values come from the quoted text:

§30 "LLMProvider: generate(...) ... Provider-specific APIs stay inside adapter implementations ...
Provider failures map to normalized failure classes."
§24 the eight failure classes.
§23 "RetryPolicy { max_attempts, retry_on = [TRANSIENT_ERROR, INVALID_OUTPUT, CONTEXT_INSUFFICIENT,
NO_SOLUTION], backoff, prompt_adjustment_policy }. Never retry indefinitely. Every retry is a
distinct request/response record. Do not silently change the parent Trusted State. Do not
alter safety constraints merely to obtain a patch."
§16, §20, §21, §32, §34 the recorded fields.
§18 "If required information cannot fit, return CONTEXT_INSUFFICIENT rather than fabricate a
repair."
Plan, P7: "``llm.generation_enabled`` off stops generation without touching history (Doc 14 §37)."
C-71: nothing in the default suite opens a network connection.
"""

from __future__ import annotations

import ast
import json
import socket
import unittest
from pathlib import Path
from unittest import mock

from core.application.config import load_config
from evidence.ids import CorrelationContext
from evidence.structured_log import StructuredLogger
from llm.adapter.fake import FakeProvider
from llm.adapter.generate import Generator
from llm.adapter.provider import ProviderError, ProviderReply
from llm.schemas.records import (
    RETRYABLE,
    FailureClass,
    GenerationStatus,
    LLMConfig,
    RetryPolicy,
)
from llm.validation.parser import PARSER_VERSION
from tests.llm_builders import (
    Clock,
    Ids,
    budget,
    canonical_context,
    config,
    fake_password,
    regression_run,
    reply,
    retry_policy,
)

F = FailureClass
REPO = Path(__file__).resolve().parents[2]


def generator(provider: FakeProvider, **changes: object) -> Generator:
    values: dict[str, object] = {
        "provider": provider,
        "config": config(),
        "retry_policy": retry_policy(),
        "budget": budget(),
        "generation_enabled": True,
        "clock": Clock(),
        "ids": Ids(),
    }
    values.update(changes)
    return Generator(**values)  # type: ignore[arg-type]


def ok(text: str) -> ProviderReply:
    return ProviderReply(text=text, latency_ms=12.5, token_usage={"input": 100, "output": 50})


class TestProviderInterface(unittest.TestCase):
    def test_the_fake_provider_returns_its_script_in_order(self) -> None:
        provider = FakeProvider([ok(reply()), ok(reply("NO_SOLUTION"))])
        result = generator(provider, retry_policy=retry_policy(1)).generate(canonical_context())
        self.assertIs(result.status, GenerationStatus.PATCH)
        self.assertEqual(len(provider.calls), 1)
        call = provider.calls[0]
        self.assertIn("untrusted candidate", call.system)
        self.assertEqual(call.config, config())
        self.assertIn("properties", call.response_schema)

    def test_a_patch_result_carries_the_patch(self) -> None:
        result = generator(FakeProvider([ok(reply())])).generate(canonical_context())
        self.assertIsNone(result.failure_class)
        self.assertIn("aws_security_group", result.patch or "")
        self.assertEqual(result.attempts[-1].response.extracted_patch, result.patch)

    def test_each_failure_class_maps(self) -> None:
        context = canonical_context()
        scope = context.allowed_change_scope
        cases = {
            F.TRANSIENT_ERROR: ProviderError(F.TRANSIENT_ERROR, "connection reset"),
            F.TIMEOUT: ProviderError(F.TIMEOUT, "no answer in 30 s"),
            F.RATE_LIMIT: ProviderError(F.RATE_LIMIT, "HTTP 429"),
            F.INVALID_OUTPUT: ok("not json"),
            F.NO_SOLUTION: ok(reply("NO_SOLUTION")),
            F.POLICY_VIOLATION: ok(reply(changed_addresses=["aws_vpc.elsewhere_not_in_scope"])),
            F.UNSUPPORTED: ok(reply(changed_addresses=["aws_lambda_function.f"])),
        }
        self.assertNotIn("aws_vpc.elsewhere_not_in_scope", scope)
        for expected, scripted in cases.items():
            with self.subTest(failure=expected):
                provider = FakeProvider([scripted])
                result = generator(provider, retry_policy=retry_policy(1)).generate(context)
                self.assertIs(result.failure_class, expected)
                self.assertIs(result.attempts[0].response.failure_class, expected)
                self.assertEqual(len(provider.calls), 1)
        # the eighth class comes from the budget, without a provider call
        provider = FakeProvider([ok(reply())])
        result = generator(provider, budget=budget(1024 + 256 + 10)).generate(context)
        self.assertIs(result.failure_class, F.CONTEXT_INSUFFICIENT)
        self.assertEqual(provider.calls, [])

    def test_an_unexpected_exception_of_a_provider_is_a_transient_error_never_a_patch(self) -> None:
        class Broken(FakeProvider):
            def generate(self, call):  # type: ignore[no-untyped-def]  # noqa: ARG002
                raise OSError("socket closed")

        result = generator(Broken([]), retry_policy=retry_policy(1)).generate(canonical_context())
        self.assertIs(result.failure_class, F.TRANSIENT_ERROR)
        self.assertIsNone(result.patch)


class TestRetry(unittest.TestCase):
    def test_the_retryable_classes_are_the_four_of_section_23(self) -> None:
        self.assertEqual(
            RETRYABLE,
            frozenset({F.TRANSIENT_ERROR, F.INVALID_OUTPUT, F.CONTEXT_INSUFFICIENT, F.NO_SOLUTION}),
        )
        with self.assertRaises(ValueError):
            retry_policy(retry_on=("TIMEOUT",))
        with self.assertRaises(ValueError):
            retry_policy(retry_on=("POLICY_VIOLATION",))
        for bad in (0, -1, 11, True):
            with self.subTest(max_attempts=bad), self.assertRaises(ValueError):
                retry_policy(bad)

    def test_retries_on_each_listed_class_up_to_max_attempts(self) -> None:
        for failure, scripted in (
            (F.TRANSIENT_ERROR, ProviderError(F.TRANSIENT_ERROR, "x")),
            (F.INVALID_OUTPUT, ok("{")),
            (F.NO_SOLUTION, ok(reply("NO_SOLUTION"))),
        ):
            with self.subTest(failure=failure):
                provider = FakeProvider([scripted] * 5)
                result = generator(provider, retry_policy=retry_policy(3)).generate(
                    canonical_context()
                )
                self.assertEqual(len(provider.calls), 3)
                self.assertEqual(len(result.attempts), 3)
                self.assertIs(result.failure_class, failure)
                self.assertIs(result.status, GenerationStatus.FAILED)

    def test_a_retry_that_succeeds_stops(self) -> None:
        provider = FakeProvider([ok("{"), ok(reply())])
        result = generator(provider).generate(canonical_context())
        self.assertIs(result.status, GenerationStatus.PATCH)
        self.assertEqual(len(result.attempts), 2)
        self.assertEqual(result.retry_count, 1)

    def test_no_retry_on_the_other_classes(self) -> None:
        for scripted in (
            ProviderError(F.TIMEOUT, "x"),
            ProviderError(F.RATE_LIMIT, "x"),
            ok(reply(changed_addresses=["aws_lambda_function.f"])),
            ok(reply(changed_addresses=["aws_vpc.not_in_scope"])),
        ):
            with self.subTest(scripted=repr(scripted)[:40]):
                provider = FakeProvider([scripted, ok(reply())])
                result = generator(provider).generate(canonical_context())
                self.assertEqual(len(provider.calls), 1)
                self.assertIs(result.status, GenerationStatus.FAILED)

    def test_a_class_left_out_of_the_policy_is_not_retried(self) -> None:
        provider = FakeProvider([ok(reply("NO_SOLUTION")), ok(reply())])
        policy = retry_policy(3, retry_on=("TRANSIENT_ERROR",))
        result = generator(provider, retry_policy=policy).generate(canonical_context())
        self.assertEqual(len(provider.calls), 1)
        self.assertIs(result.failure_class, F.NO_SOLUTION)

    def test_every_attempt_is_its_own_record_with_the_same_parent_and_constraints(self) -> None:
        provider = FakeProvider([ok("{")] * 3)
        result = generator(provider).generate(canonical_context())
        requests = [a.request for a in result.attempts]
        responses = [a.response for a in result.attempts]
        self.assertEqual(len({r.request_id for r in requests}), 3)
        self.assertEqual(len({r.attempt_id for r in requests}), 3)
        self.assertEqual(len({r.response_id for r in responses}), 3)
        self.assertEqual([r.request_id for r in requests], [r.request_id for r in responses])
        self.assertEqual({r.parent_state_id for r in requests}, {regression_run().trusted.state_id})
        self.assertEqual(len({r.context_hash for r in requests}), 1)
        self.assertEqual(len({r.prompt_hash for r in requests}), 1)
        self.assertEqual([r.attempt_number for r in requests], [1, 2, 3])
        systems = {call.system for call in provider.calls}
        self.assertEqual(len(systems), 1)  # the safety constraints never change

    def test_a_backoff_is_waited_between_attempts(self) -> None:
        waits: list[float] = []
        provider = FakeProvider([ok("{")] * 3)
        policy = retry_policy(3, backoff_seconds=2.0)
        generator(provider, retry_policy=policy, sleep=waits.append).generate(canonical_context())
        self.assertEqual(waits, [2.0, 2.0])


class TestRecords(unittest.TestCase):
    def test_the_config_records_every_field_of_section_16(self) -> None:
        data = config().to_dict()
        for name in (
            "provider",
            "model_name",
            "model_version",
            "temperature",
            "top_p",
            "seed",
            "max_output_tokens",
            "timeout_seconds",
            "retry_policy_id",
            "prompt_version",
            "response_schema_version",
        ):
            with self.subTest(field=name):
                self.assertIn(name, data)
        with self.assertRaises(ValueError):
            config(temperature=-0.1)
        with self.assertRaises(ValueError):
            config(model_name="")

    def test_request_and_response_records_have_the_listed_fields(self) -> None:
        result = generator(FakeProvider([ok(reply())])).generate(canonical_context())
        request = result.attempts[0].request.to_dict()
        for name in (
            "request_id",
            "attempt_id",
            "parent_state_id",
            "context_hash",
            "prompt_hash",
            "prompt_version",
            "model_config",
            "created_at",
            "context_version",
            "trusted_state_hash",
            "template_hash",
        ):
            with self.subTest(field=name):
                self.assertIn(name, request)
        self.assertEqual(request["model_config"], config().to_dict())
        response = result.attempts[0].response.to_dict()
        for name in (
            "response_id",
            "request_id",
            "raw_response",
            "parsed_status",
            "extracted_patch",
            "response_hash",
            "parse_errors",
            "created_at",
            "failure_class",
            "latency_ms",
            "token_usage",
            "parser_version",
            "patch_hash",
        ):
            with self.subTest(field=name):
                self.assertIn(name, response)
        self.assertEqual(response["parsed_status"], "PATCH")
        self.assertEqual(response["parser_version"], PARSER_VERSION)
        self.assertEqual(response["token_usage"], {"input": 100, "output": 50})

    def test_observability_fields_of_section_32(self) -> None:
        result = generator(FakeProvider([ok("{"), ok(reply())])).generate(canonical_context())
        record = result.observability()
        for name in (
            "request_ids",
            "attempt_ids",
            "provider",
            "model_name",
            "model_version",
            "prompt_version",
            "prompt_hash",
            "context_version",
            "context_hash",
            "response_hashes",
            "latency_ms",
            "token_usage",
            "retry_count",
            "failure_class",
            "parser_version",
            "validator_version",
            "status",
            "budget",
            "omitted",
        ):
            with self.subTest(field=name):
                self.assertIn(name, record)
        self.assertEqual(record["retry_count"], 1)
        self.assertEqual(record["status"], "PATCH")
        json.dumps(record)  # plain JSON

    def test_the_same_input_gives_the_same_request_apart_from_ids_and_times(self) -> None:
        def strip(data: dict[str, object]) -> dict[str, object]:
            return {
                k: v for k, v in data.items() if k not in ("request_id", "attempt_id", "created_at")
            }

        one = generator(FakeProvider([ok(reply())]), ids=Ids(1)).generate(canonical_context())
        two = generator(FakeProvider([ok(reply())]), ids=Ids(500)).generate(canonical_context())
        self.assertEqual(
            strip(one.attempts[0].request.to_dict()), strip(two.attempts[0].request.to_dict())
        )
        self.assertEqual(
            one.attempts[0].response.response_hash, two.attempts[0].response.response_hash
        )

    def test_a_secret_in_a_raw_response_is_redacted_in_the_record_and_the_log(self) -> None:
        password = fake_password()
        raw = reply(summary=f"password = {password}")
        logger = StructuredLogger("dail-test")
        ctx = CorrelationContext.new("00000000-0000-4000-8000-000000009999")
        result = generator(FakeProvider([ok(raw)]), logger=logger, ctx=ctx).generate(
            canonical_context()
        )
        stored = json.dumps([a.response.to_dict() for a in result.attempts])
        stored += json.dumps([a.request.to_dict() for a in result.attempts])
        logged = json.dumps([e.to_dict() for e in logger.entries], default=str)
        self.assertNotIn(password, stored)
        self.assertNotIn(password, logged)
        self.assertTrue(logger.entries)


class TestEmergencySwitch(unittest.TestCase):
    def test_the_versioned_default_is_off(self) -> None:
        self.assertIs(load_config(REPO / "config", environ={}).get("llm.generation_enabled"), False)

    def test_off_refuses_without_a_provider_call_and_touches_no_history(self) -> None:
        provider = FakeProvider([ok(reply())])
        history: list[object] = ["earlier attempt record"]
        before = list(history)
        enabled = load_config(REPO / "config", environ={}).get("llm.generation_enabled")
        result = generator(provider, generation_enabled=enabled).generate(canonical_context())
        self.assertIs(result.status, GenerationStatus.DISABLED)
        self.assertEqual(provider.calls, [])
        self.assertEqual(result.attempts, ())
        self.assertEqual(history, before)

    def test_the_switch_must_be_a_boolean(self) -> None:
        with self.assertRaises(ValueError):
            generator(FakeProvider([]), generation_enabled="yes")


class TestConfigValidation(unittest.TestCase):
    def test_a_config_for_another_provider_or_prompt_is_refused(self) -> None:
        for changes in (
            {"provider": "ollama"},
            {"prompt_version": "dail-repair-prompt-0"},
            {"response_schema_version": "other/1"},
        ):
            with self.subTest(changes=changes):
                provider = FakeProvider([ok(reply())])
                with self.assertRaises(ValueError):
                    generator(provider, config=config(**changes)).generate(canonical_context())
                self.assertEqual(provider.calls, [])

    def test_the_config_schema_accepts_ollama_and_nothing_paid(self) -> None:
        from core.application.config import SCHEMA

        (provider,) = (k for k in SCHEMA if k.dotted == "llm.provider")
        self.assertEqual(provider.allowed, ("fake", "ollama"))


class TestNoNetwork(unittest.TestCase):
    """C-71: the default suite opens no network connection. The fake path must work with every
    socket call blocked, and only the Ollama adapter may import a network module."""

    def test_generation_with_the_fake_provider_opens_no_socket(self) -> None:
        def refuse(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("a network connection was attempted")

        with (
            mock.patch.object(socket.socket, "connect", refuse),
            mock.patch.object(socket.socket, "connect_ex", refuse),
            mock.patch.object(socket, "create_connection", refuse),
            mock.patch.object(socket, "getaddrinfo", refuse),
        ):
            result = generator(FakeProvider([ok("{"), ok(reply())])).generate(canonical_context())
        self.assertIs(result.status, GenerationStatus.PATCH)

    def test_only_the_ollama_adapter_imports_a_network_module(self) -> None:
        network = {"socket", "urllib", "http", "requests", "httpx", "ssl", "aiohttp"}
        for path in sorted((REPO / "llm").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names.add(node.module.split(".")[0])
            used = names & network
            with self.subTest(module=path.relative_to(REPO).as_posix()):
                if path.name == "ollama.py":
                    self.assertTrue(used <= {"urllib", "http", "socket"})
                else:
                    self.assertEqual(used, set())

    def test_llm_imports_no_third_party_package(self) -> None:
        import sys

        allowed = set(sys.stdlib_module_names) | {"core", "evidence", "llm"}
        for path in sorted((REPO / "llm").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                roots: list[str] = []
                if isinstance(node, ast.Import):
                    roots = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    roots = [node.module.split(".")[0]]
                for root in roots:
                    with self.subTest(module=path.name, imported=root):
                        self.assertIn(root, allowed)


class TestConfigObjects(unittest.TestCase):
    def test_config_and_policy_are_frozen(self) -> None:
        with self.assertRaises(AttributeError):
            config().temperature = 1.0  # type: ignore[misc]
        self.assertIsInstance(retry_policy(), RetryPolicy)
        self.assertIsInstance(config(), LLMConfig)


if __name__ == "__main__":
    unittest.main()
