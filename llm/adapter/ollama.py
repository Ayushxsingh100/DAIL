"""The local Ollama provider (C-71, C-182, C-185, C-187; Doc 10 §24, §30).

The only real provider in this repository is a local Ollama server (C-182). It is called with the
standard library (``urllib``, C-183), through an opener without proxies, and only at a loopback
address: the constructor refuses any other host, scheme, path or user part.

Documented API used (Ollama ``docs/api.md`` at the installed version, v0.40.16:
https://github.com/ollama/ollama/blob/v0.40.16/docs/api.md,
"Generate a chat completion" and "Structured outputs"; errors: https://docs.ollama.com/api/errors):

* ``POST /api/chat`` with ``model``, ``messages`` (system, user), ``stream: false``, ``format`` (the
  JSON schema of ``LLMRepairResponse``: "Format can be ``json`` or a JSON schema") and ``options``
  (``temperature``, ``top_p``, ``seed``, ``num_predict``). The reply is one object with
  ``message.content``, ``done``, ``prompt_eval_count`` and ``eval_count``.
* ``GET /api/tags`` (``name``, ``digest``, ``details.quantization_level``) and ``GET /api/version``.
* Errors are ``{"error": "<error message>"}`` with 400, 404, 429, 500 or 502.

Failure classes (§24; the mapping of 400 and 404 is DAIL's reading, C-187): connection refused or
reset, 5xx and an ``error`` object with status 200 are TRANSIENT_ERROR; a socket timeout is TIMEOUT;
429 is RATE_LIMIT; 400 and 404 (a bad request, a missing model) are UNSUPPORTED: the configured
request cannot be served, and retrying it would not help; a 200 reply without ``done: true`` and a
string ``message.content`` is INVALID_OUTPUT.

Model pinning (C-182): with ``expected_digest`` the provider reads ``/api/tags`` once and refuses
(UNSUPPORTED) a model whose digest differs, before any generation. The JSON schema in ``format`` is
a generation hint; the reply is always checked by ``llm.validation.parser`` (C-185).
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final

from llm.adapter.provider import ProviderCall, ProviderError, ProviderReply
from llm.schemas.records import FailureClass

OLLAMA_DEFAULT_URL: Final = "http://127.0.0.1:11434"
F = FailureClass
_LOOPBACK_NAMES: Final = frozenset({"localhost"})


def _checked_url(base_url: str) -> str:
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme != "http" or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Ollama URL: only http://<loopback>:<port> is allowed (C-71)")
    if parts.path not in ("", "/"):
        raise ValueError("Ollama URL: no path is allowed")
    host = parts.hostname or ""
    if host not in _LOOPBACK_NAMES:
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("Ollama URL: the host must be a loopback address (C-71)")
        except ValueError as error:
            raise ValueError("Ollama URL: the host must be a loopback address (C-71)") from error
    return f"http://{parts.netloc}"


class OllamaProvider:
    name = "ollama"

    def __init__(
        self, *, base_url: str = OLLAMA_DEFAULT_URL, expected_digest: str | None = None
    ) -> None:
        self.base_url = _checked_url(base_url)
        self.expected_digest = expected_digest
        self._checked: str | None = None
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    # --- HTTP -----------------------------------------------------------------------------------

    def _http(self, method: str, path: str, body: Any, timeout: float) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self._opener.open(request, timeout=timeout) as answer:
                raw = answer.read()
        except urllib.error.HTTPError as error:
            raise ProviderError(_status_class(error.code), f"HTTP {error.code}") from error
        except TimeoutError as error:
            raise ProviderError(F.TIMEOUT, f"no answer within {timeout} s") from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError | socket.timeout):
                raise ProviderError(F.TIMEOUT, f"no answer within {timeout} s") from error
            raise ProviderError(F.TRANSIENT_ERROR, f"connection failed: {error.reason}") from error
        except (ConnectionError, OSError) as error:
            raise ProviderError(F.TRANSIENT_ERROR, f"connection failed: {error}") from error
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as error:
            raise ProviderError(F.INVALID_OUTPUT, "the server's reply is not JSON") from error
        if isinstance(value, dict) and "error" in value:
            raise ProviderError(F.TRANSIENT_ERROR, "the server returned an error object")
        return value

    # --- model facts ----------------------------------------------------------------------------

    def server_version(self, timeout: float = 10.0) -> str:
        value = self._http("GET", "/api/version", None, timeout)
        version = value.get("version") if isinstance(value, dict) else None
        if not isinstance(version, str):
            raise ProviderError(F.INVALID_OUTPUT, "no version in /api/version")
        return version

    def model_facts(self, model: str, timeout: float = 10.0) -> dict[str, str]:
        value = self._http("GET", "/api/tags", None, timeout)
        models = value.get("models") if isinstance(value, dict) else None
        for entry in models if isinstance(models, list) else []:
            if isinstance(entry, dict) and entry.get("name") == model:
                details = entry.get("details")
                level = details.get("quantization_level") if isinstance(details, dict) else None
                return {
                    "name": model,
                    "digest": str(entry.get("digest")),
                    "quantization": str(level),
                }
        raise ProviderError(F.UNSUPPORTED, f"model {model} is not installed on the local server")

    def _check_digest(self, model: str, timeout: float) -> None:
        if self.expected_digest is None or self._checked == model:
            return
        if self.model_facts(model, timeout)["digest"] != self.expected_digest:
            raise ProviderError(F.UNSUPPORTED, f"model {model} is not the pinned digest (C-182)")
        self._checked = model

    # --- generation -----------------------------------------------------------------------------

    def generate(self, call: ProviderCall) -> ProviderReply:
        config = call.config
        self._check_digest(config.model_name, config.timeout_seconds)
        options: dict[str, Any] = {
            "temperature": config.temperature,
            "top_p": config.top_p,
            "num_predict": config.max_output_tokens,
        }
        if config.seed is not None:
            options["seed"] = config.seed
        body = {
            "model": config.model_name,
            "messages": [
                {"role": "system", "content": call.system},
                {"role": "user", "content": call.task},
            ],
            "stream": False,
            "format": dict(call.response_schema),
            "options": options,
        }
        started = time.perf_counter()
        value = self._http("POST", "/api/chat", body, config.timeout_seconds)
        latency = (time.perf_counter() - started) * 1000.0
        if not isinstance(value, dict):
            raise ProviderError(F.INVALID_OUTPUT, "the reply is not a JSON object")
        message = value.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or value.get("done") is not True:
            raise ProviderError(F.INVALID_OUTPUT, "the reply has no complete message content")
        usage = {
            name: value[key]
            for name, key in (("input", "prompt_eval_count"), ("output", "eval_count"))
            if isinstance(value.get(key), int) and not isinstance(value.get(key), bool)
        }
        return ProviderReply(text=content, latency_ms=latency, token_usage=usage)


def _status_class(status: int) -> FailureClass:
    if status == 429:
        return F.RATE_LIMIT
    if status >= 500:
        return F.TRANSIENT_ERROR
    return F.UNSUPPORTED
