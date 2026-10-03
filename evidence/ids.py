"""Identifiers and correlation context (Doc 11 §10, §11; Doc 05 §3, §16.1; C-39, C-55).

Every id the evidence layer mints or accepts is a canonical lowercase UUID, minted through
``core.domain.ids.new_uuid`` and checked with ``require_uuid``. The prefixed hexadecimal ids of the
interim store (``evd-...``, ``corr-...``) are gone (C-55).
"""

from __future__ import annotations

from dataclasses import dataclass

from core.domain.ids import new_uuid, require_uuid


@dataclass(frozen=True)
class CorrelationContext:
    """Threads one end-to-end workflow through every component (Doc 11 §10, §11).

    run_id          the run the evidence belongs to (Doc 05 §16.1); required
    correlation_id  one end-to-end workflow lineage
    operation_id    one logical DAIL operation within that workflow
    attempt_id      one generation/verification attempt, where applicable
    request_id      one external/provider request, where applicable
    """

    run_id: str
    correlation_id: str
    operation_id: str
    attempt_id: str | None = None
    request_id: str | None = None

    def __post_init__(self) -> None:
        require_uuid(self.run_id, "CorrelationContext.run_id")
        require_uuid(self.correlation_id, "CorrelationContext.correlation_id")
        require_uuid(self.operation_id, "CorrelationContext.operation_id")
        if self.attempt_id is not None:
            require_uuid(self.attempt_id, "CorrelationContext.attempt_id")
        if self.request_id is not None:
            require_uuid(self.request_id, "CorrelationContext.request_id")

    @classmethod
    def new(cls, run_id: str | None = None) -> CorrelationContext:
        """A new workflow. The run is the caller's (P8 creates runs); without one a fresh run id is
        minted, which suits a single-run test or script."""
        return cls(
            run_id=new_uuid() if run_id is None else run_id,
            correlation_id=new_uuid(),
            operation_id=new_uuid(),
        )

    def new_operation(self) -> CorrelationContext:
        """Same run and workflow, a new logical operation (correlation is preserved)."""
        return CorrelationContext(
            run_id=self.run_id,
            correlation_id=self.correlation_id,
            operation_id=new_uuid(),
            attempt_id=self.attempt_id,
            request_id=self.request_id,
        )

    def with_attempt(self, attempt_id: str | None = None) -> CorrelationContext:
        return CorrelationContext(
            self.run_id,
            self.correlation_id,
            self.operation_id,
            new_uuid() if attempt_id is None else attempt_id,
            self.request_id,
        )

    def with_request(self, request_id: str | None = None) -> CorrelationContext:
        return CorrelationContext(
            self.run_id,
            self.correlation_id,
            self.operation_id,
            self.attempt_id,
            new_uuid() if request_id is None else request_id,
        )
