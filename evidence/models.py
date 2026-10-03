"""Logging and replay contracts of the evidence layer (Doc 11 §14, §15, §35; C-58).

The evidence record, validity transitions and audit events moved to ``core.domain.evidence`` and
``core.domain.audit`` (C-50); what stays here is the structured log record, its levels and the
replay mode.

  LogLevel    Section 15  (ERROR, WARN, INFO, DEBUG, TRACE; the same five as the configuration)
  LogEvent    Section 14  (structured, machine-readable)
  ReplayMode  Section 35  (RECONSTRUCT, REVERIFY, RERUN, REGENERATE)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class LogLevel(StrEnum):
    """Doc 11 §15. The order is the configuration's (``config.LOG_LEVELS``), most severe first;
    ``severity`` ranks them for the logger's threshold. ``WARNING`` is retired (C-58): the level
    is ``WARN``."""

    ERROR = "ERROR"  # "Operation failed or integrity/safety boundary was violated."
    WARN = "WARN"  # "Unexpected condition requiring attention but execution may continue."
    INFO = "INFO"  # "Material lifecycle operation."
    DEBUG = "DEBUG"  # "Diagnostic detail useful during development."
    TRACE = "TRACE"  # "Very fine-grained diagnostic data; disabled by default in production."

    @property
    def severity(self) -> int:
        return _SEVERITY[self.value]

    @classmethod
    def parse(cls, value: str) -> LogLevel:
        """The level named ``value`` (exactly; there are no aliases). Raises ``ValueError``."""
        try:
            return cls(value)
        except ValueError:
            hint = " (the level is WARN; WARNING is retired, C-58)" if value == "WARNING" else ""
            raise ValueError(f"{value!r} is not a log level (Doc 11 §15){hint}") from None


_SEVERITY = {"TRACE": 0, "DEBUG": 1, "INFO": 2, "WARN": 3, "ERROR": 4}


@dataclass(frozen=True)
class LogEvent:
    """Structured, machine-readable log record (Doc 11 Section 14).

    Logs are supplementary, not the audit record (Doc 11 Section 2/50):
    they are never authoritative state and never proof for promotion.
    """

    timestamp: datetime
    level: LogLevel
    service: str
    component: str
    event_name: str
    correlation_id: str
    operation_id: str
    status: str
    candidate_id: str | None = None
    state_id: str | None = None
    duration_ms: float | None = None
    error_code: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.level is LogLevel.ERROR and not self.error_code:
            raise ValueError("ERROR-level LogEvent requires an error_code (Doc 11 Section 15)")

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "service": self.service,
            "component": self.component,
            "event_name": self.event_name,
            "correlation_id": self.correlation_id,
            "operation_id": self.operation_id,
            "candidate_id": self.candidate_id,
            "state_id": self.state_id,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "error_code": self.error_code,
            "metadata": self.metadata,
        }


class ReplayMode(StrEnum):
    """How a historical result is brought back (Doc 11 §35; C-08, C-58). The modes must not be
    conflated in audit reports, so they are four distinct members and there is no ``REPLAY``."""

    RECONSTRUCT = "RECONSTRUCT"  # "Rebuild historical reports from stored artifacts" (Doc 11 §35)
    REVERIFY = "REVERIFY"
    RERUN = "RERUN"  # named by C-08
    REGENERATE = "REGENERATE"

    @classmethod
    def parse(cls, value: str) -> ReplayMode:
        """The mode named ``value``. The one alias is Doc 13 §47's ``REPLAY``, which is
        RECONSTRUCT; nothing else is accepted (C-58). Raises ``ValueError``."""
        if value == "REPLAY":
            return cls.RECONSTRUCT
        try:
            return cls(value)
        except ValueError:
            raise ValueError(f"{value!r} is not a replay mode (Doc 11 §35, C-58)") from None
