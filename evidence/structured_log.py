"""Structured, machine-readable logging (Doc 11 Sections 14-15).

Logs are supplementary, never authoritative (Doc 11 Section 2/50): they can
never serve as promotion proof. Metadata is redacted before it is written,
and every entry must carry correlation/operation IDs so a workflow can be
reconstructed across components.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.domain.redaction import Redactor
from evidence.ids import CorrelationContext
from evidence.models import LogEvent, LogLevel


class StructuredLogger:
    def __init__(
        self,
        service: str,
        sink_path: str | Path | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        if not service:
            raise ValueError("service must be non-empty")
        self.service = service
        self._sink = Path(sink_path) if sink_path else None
        if self._sink:
            self._sink.parent.mkdir(parents=True, exist_ok=True)
        self._redactor = redactor or Redactor()
        self._entries: list[LogEvent] = []

    @property
    def entries(self) -> list[LogEvent]:
        return list(self._entries)

    def log(
        self,
        level: LogLevel,
        *,
        component: str,
        event_name: str,
        ctx: CorrelationContext,
        status: str,
        candidate_id: str | None = None,
        state_id: str | None = None,
        duration_ms: float | None = None,
        error_code: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> LogEvent:
        safe_meta = self._redactor.redact(metadata or {}).payload
        event = LogEvent(
            timestamp=datetime.now(UTC),
            level=level,
            service=self.service,
            component=component,
            event_name=event_name,
            correlation_id=ctx.correlation_id,
            operation_id=ctx.operation_id,
            status=status,
            candidate_id=candidate_id,
            state_id=state_id,
            duration_ms=duration_ms,
            error_code=error_code,
            metadata=safe_meta,
        )
        self._entries.append(event)
        if self._sink:
            with self._sink.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        return event
