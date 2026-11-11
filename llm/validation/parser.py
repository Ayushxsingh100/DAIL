"""The strict structured-response parser (Doc 10 §11, §22, §25; C-184, C-187). Parser only: the full
patch validation pipeline (Doc 10 §13) is P7b.

``parse_response(raw, allowed_types=..., allowed_scope=...)`` returns a ``ParseOutcome``. The rules,
in order (the first that applies decides):

1. **Structured-only (§22 "Extraneous text ... reject").** The reply must be exactly one JSON
   object; surrounding whitespace is allowed, any other text (a sentence, a code fence) is
   INVALID_OUTPUT.
   There is no tolerant parser in v1. Duplicate keys, ``NaN`` and ``Infinity`` are rejected.
2. **Schema (§11, §22 "Malformed JSON/schema: INVALID").** Exactly the required fields of
   ``LLMRepairResponse`` plus the optional ``confidence``; any other field, a missing field, a wrong
   type, an unknown status or another ``schema_version`` is INVALID_OUTPUT.
3. **Patch by status (§11, §22 "Missing patch").** PATCH needs a non-empty patch string (C-184:
   ``PatchFormat.TERRAFORM_HCL``); every other status needs ``patch = null``.
4. **Boundaries (§22 "Ambiguous patch boundaries: reject; never guess").** A PATCH must name at
   least one changed address; every changed address must be a resource address
   (``type.name`` with an optional module path and instance key); duplicates are rejected.
5. **Support and scope (§22 "Unsupported resource: reject/UNSUPPORTED. Forbidden operation:
   reject").** A changed address whose type is not allowed is UNSUPPORTED; one outside the allowed
   change scope is POLICY_VIOLATION. The patch text itself is not parsed as HCL here (P7b).
6. **Status.** A valid PATCH has no failure class. NO_SOLUTION and UNCERTAIN are the model's
   inability signal: NO_SOLUTION (C-187). A model that answers INVALID is INVALID_OUTPUT.

``confidence`` (§25) is kept as metadata only: it never changes a status or a failure class.

Standard library only (C-183).
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from llm.schemas.records import FailureClass
from llm.schemas.repair_response import (
    OPTIONAL_FIELDS,
    REQUIRED_FIELDS,
    RESPONSE_SCHEMA_VERSION,
    LLMRepairResponse,
    RepairStatus,
)

PARSER_VERSION: Final = "dail-llm-parser-1"
F = FailureClass
_NAME = r"[A-Za-z_][A-Za-z0-9_-]*"
_KEY = r'(?:\[(?:[0-9]+|"(?:[^"\\]|\\.)*")\])'
_ADDRESS: Final = re.compile(rf"^(?:module\.{_NAME}{_KEY}?\.)*({_NAME})\.{_NAME}{_KEY}?$")


@dataclass(frozen=True)
class ParseOutcome:
    response: LLMRepairResponse | None
    failure_class: FailureClass | None
    errors: tuple[str, ...]
    parser_version: str = PARSER_VERSION


class _Reject(Exception):
    def __init__(self, failure: FailureClass, message: str) -> None:
        super().__init__(message)
        self.failure = failure


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _Reject(F.INVALID_OUTPUT, "duplicate key in the JSON object")
    return dict(pairs)


def _no_constant(name: str) -> Any:
    raise _Reject(F.INVALID_OUTPUT, f"{name} is not JSON")


def _decode(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise _Reject(F.INVALID_OUTPUT, "the reply is not text")
    text = raw.strip()
    if not text.startswith("{") or not text.endswith("}"):
        raise _Reject(F.INVALID_OUTPUT, "the reply is not exactly one JSON object (§22)")
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except json.JSONDecodeError as error:
        raise _Reject(F.INVALID_OUTPUT, f"malformed JSON: {error.msg}") from error
    if not isinstance(value, dict):
        raise _Reject(F.INVALID_OUTPUT, "the reply is not a JSON object")
    return value


def _string(data: dict[str, Any], name: str, *, empty: bool = False) -> str:
    value = data[name]
    if not isinstance(value, str) or (not empty and value.strip() == ""):
        raise _Reject(F.INVALID_OUTPUT, f"{name}: must be a non-empty string")
    return value


def _strings(data: dict[str, Any], name: str) -> tuple[str, ...]:
    value = data[name]
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise _Reject(F.INVALID_OUTPUT, f"{name}: must be a list of non-empty strings")
    if len(value) != len(set(value)):
        raise _Reject(F.INVALID_OUTPUT, f"{name}: duplicate entries")
    return tuple(value)


def _schema(data: dict[str, Any]) -> LLMRepairResponse:
    missing = [name for name in REQUIRED_FIELDS if name not in data]
    if missing:
        raise _Reject(F.INVALID_OUTPUT, f"missing required fields: {missing}")
    extra = sorted(set(data) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS))
    if extra:
        raise _Reject(F.INVALID_OUTPUT, f"fields outside the schema: {extra}")
    if data["schema_version"] != RESPONSE_SCHEMA_VERSION:
        raise _Reject(F.INVALID_OUTPUT, "schema_version: not " + RESPONSE_SCHEMA_VERSION)
    status_text = data["status"]
    if not isinstance(status_text, str) or status_text not in {s.value for s in RepairStatus}:
        raise _Reject(F.INVALID_OUTPUT, "status: not one of PATCH, NO_SOLUTION, UNCERTAIN, INVALID")
    status = RepairStatus(status_text)
    patch = data["patch"]
    if status is RepairStatus.PATCH:
        if not isinstance(patch, str) or patch.strip() == "":
            raise _Reject(F.INVALID_OUTPUT, "PATCH without a patch (§22 'Missing patch')")
    elif patch is not None:
        raise _Reject(F.INVALID_OUTPUT, f"{status.value} must not carry a patch")
    confidence = data.get("confidence")
    if confidence is not None and (
        isinstance(confidence, bool)
        or not isinstance(confidence, int | float)
        or not math.isfinite(confidence)
    ):
        raise _Reject(F.INVALID_OUTPUT, "confidence: must be a number (§25 metadata)")
    return LLMRepairResponse(
        schema_version=data["schema_version"],
        status=status,
        summary=_string(data, "summary"),
        patch=patch,
        changed_addresses=_strings(data, "changed_addresses"),
        assumptions=_strings(data, "assumptions"),
        rationale=_string(data, "rationale", empty=True),
        confidence=None if confidence is None else float(confidence),
    )


def _boundaries(
    response: LLMRepairResponse,
    allowed_types: frozenset[str] | None,
    allowed_scope: frozenset[str] | None,
) -> None:
    if response.status is RepairStatus.PATCH and not response.changed_addresses:
        raise _Reject(
            F.INVALID_OUTPUT, "PATCH names no changed address: ambiguous patch boundaries (§22)"
        )
    for address in response.changed_addresses:
        match = _ADDRESS.match(address)
        if match is None:
            raise _Reject(F.INVALID_OUTPUT, f"changed_addresses: {address!r} is not an address")
        if allowed_types is not None and match.group(1) not in allowed_types:
            raise _Reject(F.UNSUPPORTED, f"{address}: type {match.group(1)} is not supported")
        if allowed_scope is not None and address not in allowed_scope:
            raise _Reject(F.POLICY_VIOLATION, f"{address}: outside the allowed change scope")


def parse_response(
    raw: object,
    *,
    allowed_types: Iterable[str] | None,
    allowed_scope: Iterable[str] | None,
) -> ParseOutcome:
    """Parse one reply text. ``allowed_types`` and ``allowed_scope`` come from the context."""
    types = None if allowed_types is None else frozenset(allowed_types)
    scope = None if allowed_scope is None else frozenset(allowed_scope)
    try:
        response = _schema(_decode(raw))
        _boundaries(response, types, scope)
    except _Reject as reject:
        return ParseOutcome(None, reject.failure, (str(reject),))
    if response.status is RepairStatus.PATCH:
        return ParseOutcome(response, None, ())
    if response.status is RepairStatus.INVALID:
        return ParseOutcome(response, F.INVALID_OUTPUT, ("the model answered INVALID",))
    return ParseOutcome(response, F.NO_SOLUTION, ())


def changed_types(addresses: Sequence[str]) -> tuple[str, ...]:
    """The resource types named by addresses that match the address form."""
    found = []
    for address in addresses:
        match = _ADDRESS.match(address)
        if match is not None:
            found.append(match.group(1))
    return tuple(sorted(set(found)))
