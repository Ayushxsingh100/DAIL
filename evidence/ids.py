"""Identifiers and correlation context (Doc 11 Sections 10-11)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass


def new_id(prefix: str) -> str:
    """A fresh, prefixed identifier, e.g. new_id('evd') -> 'evd-3f9a...'."""
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


@dataclass(frozen=True)
class CorrelationContext:
    """Threads one end-to-end workflow through every component.

    correlation_id  one end-to-end workflow lineage
    operation_id    one logical DAIL operation within that workflow
    attempt_id      one generation/verification attempt, when applicable
    request_id      one external/provider request, when applicable
    """

    correlation_id: str
    operation_id: str
    attempt_id: str | None = None
    request_id: str | None = None

    def __post_init__(self) -> None:
        if not self.correlation_id:
            raise ValueError("correlation_id must be non-empty")
        if not self.operation_id:
            raise ValueError("operation_id must be non-empty")

    @classmethod
    def new(cls) -> CorrelationContext:
        return cls(correlation_id=new_id("corr"), operation_id=new_id("op"))

    def new_operation(self) -> CorrelationContext:
        """Same workflow, a new logical operation (correlation is preserved)."""
        return CorrelationContext(
            correlation_id=self.correlation_id,
            operation_id=new_id("op"),
            attempt_id=self.attempt_id,
            request_id=self.request_id,
        )

    def with_attempt(self, attempt_id: str | None = None) -> CorrelationContext:
        return CorrelationContext(
            self.correlation_id, self.operation_id, attempt_id or new_id("att"), self.request_id
        )

    def with_request(self, request_id: str | None = None) -> CorrelationContext:
        return CorrelationContext(
            self.correlation_id, self.operation_id, self.attempt_id, request_id or new_id("req")
        )
