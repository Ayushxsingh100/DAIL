"""Canonical JSON values and UTC timestamps (Doc 05 §4.2, §4.3, §27; C-33; P1a step 4).

Domain payloads are JSON values: ``str``, ``int``, ``bool``, ``None``, lists and
objects with string keys. Floats are rejected because their text form is not
stable across platforms, so a hash over them would not be reproducible (Doc 05
§4.3). Payloads are deep-frozen on construction (``MappingProxyType`` and
tuples) so a caller's later mutation changes neither the object nor its hash.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any

from core.domain.errors import DomainValidationError

_MAX_DEPTH = 64


def _walk(value: object, path: str, depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise DomainValidationError(f"{path}: JSON nesting is deeper than {_MAX_DEPTH}")
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, float):
        raise DomainValidationError(f"{path}: floats are not allowed in canonical JSON (C-33)")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DomainValidationError(f"{path}: object keys must be strings (C-33)")
            _walk(item, f"{path}.{key}", depth + 1)
        return
    if isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _walk(item, f"{path}[{index}]", depth + 1)
        return
    raise DomainValidationError(f"{path}: {type(value).__name__} is not a JSON value (C-33)")


def validate_json(value: object, field: str) -> None:
    """Raise ``DomainValidationError`` unless ``value`` is a JSON value (C-33)."""
    _walk(value, field, 0)


def freeze_json(value: Any) -> Any:
    """Deep-frozen copy of a valid JSON value: objects become mapping proxies, lists tuples."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze_json(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(freeze_json(item) for item in value)
    return value


def thaw_json(value: Any) -> Any:
    """Plain (``dict``/``list``) copy of a frozen JSON value, for serialization."""
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [thaw_json(item) for item in value]
    return value


def utc(value: object, field: str) -> datetime:
    """Return ``value`` as an aware UTC datetime; reject naive and non-UTC values (Doc 05 §4.2)."""
    if not isinstance(value, datetime):
        raise DomainValidationError(f"{field}: must be a datetime (Doc 05 §4.2)")
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None:
        raise DomainValidationError(f"{field}: timestamp must be timezone-aware (Doc 05 §4.2)")
    if offset != timedelta(0):
        raise DomainValidationError(f"{field}: timestamp must be UTC (Doc 05 §4.2)")
    return value.astimezone(UTC)


def iso_utc(value: datetime) -> str:
    """Canonical ISO-8601 text of an aware UTC datetime."""
    return value.isoformat()


def parse_utc(value: object, field: str) -> datetime:
    """Parse the text produced by ``iso_utc``."""
    if not isinstance(value, str):
        raise DomainValidationError(f"{field}: must be an ISO-8601 string (Doc 05 §4.2)")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise DomainValidationError(f"{field}: not an ISO-8601 timestamp (Doc 05 §4.2)") from None
    return utc(parsed, field)
