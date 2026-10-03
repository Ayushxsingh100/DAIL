"""Logging data contracts of the evidence layer (Doc 11 §14, §15).

The evidence record, validity transitions and audit events moved to ``core.domain.evidence`` and
``core.domain.audit`` (C-50); what stays here is the structured log record.

  LogEvent  Section 14  (structured, machine-readable)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


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
