"""The Ollama adapter (P7a; Doc 10 §24, §30; C-71, C-182, C-185, C-187).

Unit tests talk to a local fake HTTP server (stdlib, 127.0.0.1 only) that imitates the documented
Ollama responses:

* ``POST /api/chat`` with ``stream: false`` returns one object with ``message.content``, ``done``,
  ``prompt_eval_count`` and ``eval_count``; ``format`` "can be ``json`` or a JSON schema"
  (https://github.com/ollama/ollama/blob/main/docs/api.md, "Generate a chat completion",
  "Structured outputs").
* ``GET /api/tags`` lists ``name``, ``digest`` and ``details.quantization_level``; ``GET
  /api/version`` returns ``version``.
* Errors are ``{"error": "<error message>"}`` with 400 (bad request), 404 (not found, such as a
  model that doesn't exist), 429 (too many requests), 500 and 502 (https://docs.ollama.com/api/errors).

The opt-in integration test (``DAIL_OLLAMA_TEST=1``) calls the real local server; it is skipped in
the default run and in CI, which use no network (C-71).
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import threading
import time
import unittest
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest import mock

from llm.adapter.ollama import OLLAMA_DEFAULT_URL, OllamaProvider
from llm.adapter.provider import ProviderCall, ProviderError
from llm.schemas.records import FailureClass, LLMRequest
from llm.schemas.repair_response import RESPONSE_JSON_SCHEMA
from tests.llm_builders import START, config, reply

F = FailureClass
DIGEST = "a" * 64
MODEL = "tiny-coder:1b"


class FakeOllama:
    """A loopback HTTP server; ``handler`` decides each answer: (status, body, delay seconds)."""

    def __init__(
        self, handler: Callable[[str, str, dict[str, Any] | None], tuple[int, Any, float]]
    ):
        self.handler = handler
        self.requests: list[tuple[str, str, dict[str, Any] | None]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                outer.requests.append((method, self.path, body))
                status, payload, delay = outer.handler(method, self.path, body)
                if delay:
                    time.sleep(delay)
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                with contextlib.suppress(OSError):
                    self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                self._answer("GET")

            def do_POST(self) -> None:  # noqa: N802
                self._answer("POST")

            def log_message(self, *_args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> FakeOllama:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


def chat_ok(content: str) -> dict[str, Any]:
    return {
        "model": MODEL,
        "created_at": "2026-11-11T09:00:00Z",
        "message": {"role": "assistant", "content": content},
        "done_reason": "stop",
        "done": True,
        "total_duration": 5191566416,
        "prompt_eval_count": 26,
        "eval_count": 298,
    }


TAGS = {
    "models": [
        {
            "name": MODEL,
            "model": MODEL,
            "digest": DIGEST,
            "details": {"quantization_level": "Q4_K_M", "parameter_size": "1.5B"},
        }
    ]
}


def call(timeout: float = 5.0) -> ProviderCall:
    cfg = config(provider="ollama", model_name=MODEL, model_version=DIGEST, timeout_seconds=timeout)
    request = LLMRequest(
        request_id="00000000-0000-4000-8000-000000000001",
        attempt_id="00000000-0000-4000-8000-000000000002",
        attempt_number=1,
        parent_state_id="00000000-0000-4000-8000-000000000003",
        trusted_state_hash="b" * 64,
        context_version="dail-llm-context-1",
        context_hash="c" * 64,
        prompt_hash="d" * 64,
        prompt_version="dail-repair-prompt-1",
        template_hash="e" * 64,
        model_config=cfg.to_dict(),
        created_at=START,
    )
    return ProviderCall(
        request=request,
        system="SYSTEM",
        task="TASK",
        response_schema=RESPONSE_JSON_SCHEMA,
        config=cfg,
    )


def always(status: int, body: Any, delay: float = 0.0):  # type: ignore[no-untyped-def]
    def handler(_method: str, path: str, _body: object) -> tuple[int, Any, float]:
        if path == "/api/tags":
            return 200, TAGS, 0.0
        return status, body, delay

    return handler


class TestRequest(unittest.TestCase):
    def test_the_request_follows_the_documented_chat_api(self) -> None:
        with FakeOllama(always(200, chat_ok(reply()))) as server:
            got = OllamaProvider(base_url=server.url).generate(call())
        method, path, body = server.requests[-1]
        self.assertEqual((method, path), ("POST", "/api/chat"))
        assert body is not None
        self.assertEqual(body["model"], MODEL)
        self.assertIs(body["stream"], False)
        self.assertEqual(body["format"], RESPONSE_JSON_SCHEMA)
        self.assertEqual(
            body["messages"],
            [{"role": "system", "content": "SYSTEM"}, {"role": "user", "content": "TASK"}],
        )
        self.assertEqual(
            body["options"], {"temperature": 0.0, "top_p": 1.0, "seed": 7, "num_predict": 1024}
        )
        self.assertEqual(got.text, reply())
        self.assertEqual(got.token_usage, {"input": 26, "output": 298})
        self.assertGreaterEqual(got.latency_ms, 0.0)

    def test_the_default_url_is_the_local_server(self) -> None:
        self.assertEqual(OLLAMA_DEFAULT_URL, "http://127.0.0.1:11434")

    def test_only_a_loopback_server_is_accepted(self) -> None:
        for url in (
            "http://example.com:11434",
            "https://127.0.0.1:11434",
            "http://10.0.0.5:11434",
            "http://127.0.0.1:11434/api",
            "http://user@127.0.0.1:11434",
            "ftp://127.0.0.1",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                OllamaProvider(base_url=url)
        OllamaProvider(base_url="http://localhost:11434")


class TestFailures(unittest.TestCase):
    def assert_failure(self, handler, expected: FailureClass, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
        with FakeOllama(handler) as server, self.assertRaises(ProviderError) as caught:
            OllamaProvider(base_url=server.url).generate(call(timeout))
        self.assertIs(caught.exception.failure_class, expected)

    def test_documented_error_statuses(self) -> None:
        for status, expected in (
            (429, F.RATE_LIMIT),
            (500, F.TRANSIENT_ERROR),
            (502, F.TRANSIENT_ERROR),
            (503, F.TRANSIENT_ERROR),
            (400, F.UNSUPPORTED),
            (404, F.UNSUPPORTED),
        ):
            with self.subTest(status=status):
                self.assert_failure(always(status, {"error": "boom"}), expected)

    def test_a_timeout(self) -> None:
        self.assert_failure(always(200, chat_ok(reply()), delay=1.5), F.TIMEOUT, timeout=0.3)

    def test_a_refused_connection_is_transient(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with self.assertRaises(ProviderError) as caught:
            OllamaProvider(base_url=f"http://127.0.0.1:{port}").generate(call())
        self.assertIs(caught.exception.failure_class, F.TRANSIENT_ERROR)

    def test_a_malformed_body_is_invalid_output(self) -> None:
        for body in (
            b"not json",
            {"done": True},
            {"message": {"role": "assistant"}, "done": True},
            {"message": {"role": "assistant", "content": 3}, "done": True},
            {"message": {"role": "assistant", "content": "x"}, "done": False},
        ):
            with self.subTest(body=str(body)[:40]):
                self.assert_failure(always(200, body), F.INVALID_OUTPUT)

    def test_an_error_object_with_status_200_is_transient(self) -> None:
        self.assert_failure(always(200, {"error": "model crashed"}), F.TRANSIENT_ERROR)


class TestModelPinning(unittest.TestCase):
    def test_the_pinned_digest_is_checked_before_generation(self) -> None:
        with FakeOllama(always(200, chat_ok(reply()))) as server:
            OllamaProvider(base_url=server.url, expected_digest=DIGEST).generate(call())
            paths = [path for _m, path, _b in server.requests]
        self.assertEqual(paths, ["/api/tags", "/api/chat"])

    def test_another_digest_is_refused_without_generation(self) -> None:
        with FakeOllama(always(200, chat_ok(reply()))) as server:
            with self.assertRaises(ProviderError) as caught:
                OllamaProvider(base_url=server.url, expected_digest="f" * 64).generate(call())
            paths = [path for _m, path, _b in server.requests]
        self.assertIs(caught.exception.failure_class, F.UNSUPPORTED)
        self.assertEqual(paths, ["/api/tags"])

    def test_model_facts(self) -> None:
        def handler(_method: str, path: str, _b: object) -> tuple[int, Any, float]:
            if path == "/api/version":
                return 200, {"version": "0.12.3"}, 0.0
            return 200, TAGS, 0.0

        with FakeOllama(handler) as server:
            provider = OllamaProvider(base_url=server.url)
            self.assertEqual(provider.server_version(), "0.12.3")
            self.assertEqual(
                provider.model_facts(MODEL),
                {"name": MODEL, "digest": DIGEST, "quantization": "Q4_K_M"},
            )
            with self.assertRaises(ProviderError):
                provider.model_facts("missing:1b")


class TestOnlyLoopback(unittest.TestCase):
    def test_the_adapter_connects_only_to_the_loopback_address(self) -> None:
        seen: list[object] = []
        real = socket.create_connection

        def watch(address, *args, **kwargs):  # type: ignore[no-untyped-def]
            seen.append(address)
            return real(address, *args, **kwargs)

        with (
            FakeOllama(always(200, chat_ok(reply()))) as server,
            mock.patch.object(socket, "create_connection", watch),
        ):
            OllamaProvider(base_url=server.url).generate(call())
        self.assertTrue(seen)
        self.assertTrue(all(host == "127.0.0.1" for host, _port in seen))  # type: ignore[misc]


@unittest.skipUnless(os.environ.get("DAIL_OLLAMA_TEST") == "1", "opt-in: DAIL_OLLAMA_TEST=1")
class TestRealLocalOllama(unittest.TestCase):
    """The wiring check (P7a step 4): the canonical objective through the real local server.

    Environment: DAIL_OLLAMA_MODEL (name:tag) and DAIL_OLLAMA_DIGEST (from ``ollama list``). The
    outcome is printed for the report; the patch is not turned into a candidate (P7b) and its
    quality is not judged."""

    def test_the_canonical_objective_through_the_local_server(self) -> None:
        from llm.adapter.generate import Generator
        from tests.llm_builders import Clock, Ids, budget, canonical_context, retry_policy

        model = os.environ["DAIL_OLLAMA_MODEL"]
        digest = os.environ["DAIL_OLLAMA_DIGEST"]
        provider = OllamaProvider(expected_digest=digest)
        cfg = config(
            provider="ollama",
            model_name=model,
            model_version=digest,
            timeout_seconds=float(os.environ.get("DAIL_OLLAMA_TIMEOUT", "900")),
            max_output_tokens=2048,
        )
        generator = Generator(
            provider=provider,
            config=cfg,
            retry_policy=retry_policy(1),
            budget=budget(32_768, reserved_output_tokens=2048),
            generation_enabled=True,
            clock=Clock(),
            ids=Ids(),
        )
        result = generator.generate(canonical_context())
        facts = {
            "ollama_version": provider.server_version(),
            "model": provider.model_facts(model),
            "observability": result.observability(),
            "parse_errors": list(result.attempts[-1].response.parse_errors),
            "parsed_status": result.attempts[-1].response.to_dict()["parsed_status"],
        }
        print("\nWIRING-CHECK " + json.dumps(facts, sort_keys=True))
        self.assertEqual(len(result.attempts), 1)
        self.assertEqual(
            result.attempts[0].response.request_id, result.attempts[0].request.request_id
        )


if __name__ == "__main__":
    unittest.main()
