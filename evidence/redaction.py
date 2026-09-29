"""Deterministic secret redaction (Doc 11 Sections 28-29).

Rules implemented (all from Doc 11 Section 28):
  - Never persist plaintext credentials, API keys, private keys, access
    tokens, passwords, or session secrets.
  - Redact secret-like provider attributes before persistence.
  - Preserve enough non-sensitive context to reproduce the decision.
  - Record the redaction policy version where a transformation occurs.

Design choices worth knowing:
  * Fail toward safety: over-redaction (e.g. a key named
    ``minimum_password_length``) is acceptable; a leaked secret is not.
  * But LLM/provider *usage metadata* must survive, because Doc 11 Section
    27 requires recording token usage. So ``max_tokens``, ``token_count``,
    ``input_tokens`` are NOT secrets; only a key literally named ``token``
    or ending in a known secret suffix (``access_token``...) is.
  * Detection is a safety net (Doc 11 Section 29), not permission to put
    secrets into prompts or logs in the first place.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

REDACTED = "[REDACTED]"
REDACTION_POLICY_VERSION = "redaction-policy-1"

_SECRET_KEY_EXACT = frozenset(
    {
        "password", "passwd", "secret", "token", "api_key", "apikey", "authorization",
        "credentials", "credential", "private_key", "client_secret", "secret_key",
        "access_key", "secret_access_key", "aws_access_key_id", "aws_secret_access_key",
        "aws_session_token", "session_token", "auth_token", "bearer_token",
    }
)
_SECRET_KEY_SUFFIXES = (
    "_password", "_passwd", "_secret", "_secret_key", "_api_key", "_apikey",
    "_private_key", "_access_key", "_auth_token", "_access_token", "_refresh_token",
    "_session_token", "_bearer_token", "_client_secret", "_credentials",
)
_SECRET_KEY_SUBSTRINGS = ("password", "passwd")

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
    re.DOTALL,
)
_AWS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*")
_GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")
_KEY_VALUE = re.compile(
    r"(?i)\b(aws_secret_access_key|aws_access_key_id|aws_session_token|password|passwd"
    r"|secret|api[_-]?key|token)\b(\s*[=:]\s*)(['\"]?)[^\s'\";,]+\3"
)


@dataclass(frozen=True)
class RedactionResult:
    payload: Any
    redaction_count: int
    policy_version: str = REDACTION_POLICY_VERSION

    @property
    def redacted(self) -> bool:
        return self.redaction_count > 0


def _is_secret_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    norm = key.strip().lower().replace("-", "_").replace(" ", "_")
    if norm in _SECRET_KEY_EXACT:
        return True
    if any(s in norm for s in _SECRET_KEY_SUBSTRINGS):
        return True
    # Prefix with '_' so the bare key ('access_token') is caught the same as a
    # prefixed one ('github_access_token'); 'max_tokens' still does not match.
    return ("_" + norm).endswith(_SECRET_KEY_SUFFIXES)


def _redact_string(value: str) -> tuple[str, int]:
    count = 0

    def _sub_fixed(pattern: re.Pattern[str], text: str) -> str:
        nonlocal count
        new, n = pattern.subn(REDACTED, text)
        count += n
        return new

    out = _sub_fixed(_PRIVATE_KEY_BLOCK, value)
    out = _sub_fixed(_AWS_KEY_ID, out)
    out = _sub_fixed(_GITHUB_TOKEN, out)
    out = _sub_fixed(_BEARER, out)

    def _kv(m: re.Match[str]) -> str:
        nonlocal count
        # Already-redacted values must not be double counted.
        rest = m.group(0)[len(m.group(1)) + len(m.group(2)) :].strip("'\"")
        if rest == REDACTED:
            return m.group(0)
        count += 1
        return f"{m.group(1)}{m.group(2)}{REDACTED}"

    out = _KEY_VALUE.sub(_kv, out)
    return out, count


class Redactor:
    """Recursively redacts secrets from JSON-like payloads. Returns a copy."""

    def redact(self, payload: Any) -> RedactionResult:
        count = 0

        def walk(node: Any) -> Any:
            nonlocal count
            if isinstance(node, dict):
                out: dict[Any, Any] = {}
                for k, v in node.items():
                    if _is_secret_key(k) and v is not None and v != REDACTED:
                        out[k] = REDACTED
                        count += 1
                    else:
                        out[k] = walk(v)
                return out
            if isinstance(node, (list, tuple)):
                return [walk(x) for x in node]
            if isinstance(node, str):
                new, n = _redact_string(node)
                count += n
                return new
            return node

        return RedactionResult(payload=walk(payload), redaction_count=count)

    def contains_secret(self, payload: Any) -> bool:
        return self.redact(payload).redacted
