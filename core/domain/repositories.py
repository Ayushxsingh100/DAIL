"""Repository ports (Doc 05 §26, §32, §36; Doc 06 §6, §20, §27, §30; C-42, C-43; P1b step 3).

Doc 05 §26: "The domain services depend on these contracts rather than SQLAlchemy/SQLite-specific
implementations." These are ``typing.Protocol`` classes over domain types only. They carry no SQL
and import nothing outside ``core.domain`` and the standard library (contract rules R1, R11, R12).
The SQLite adapter is ``core.persistence`` (ADR-004).

The set extends Doc 05 §26 with a ``PatchRepository`` (Doc 05 §9, §33: the raw patch is retained
independently of its candidate) and a ``UnitOfWork`` that carries the Doc 05 §32 transaction:
every repository of one unit of work is bound to one transaction, which commits on a clean exit
and rolls back on any exception. ``EvidenceRepository`` and ``AuditRepository`` arrive in
P2-fix (Doc 05 §26, Doc 11; C-42, C-43, C-50); ``AnalysisRepository`` in P3 to P6.

Doc 06 §30: "Do not permit persistence-layer convenience methods to bypass lifecycle validation."
So there is no ``update``, ``set_status`` or ``delete``: a candidate changes only through
``save_transition`` with a legal successor, and a trusted state is written only by
``save_baseline`` (version 0) or ``save_promoted`` (a compare-and-swap on the lineage's current
pointer, SM-010).
"""

from __future__ import annotations

from types import TracebackType
from typing import Any, Protocol

from core.domain.audit import AuditAppendResult, AuditEvent, AuditSubmission
from core.domain.evidence import (
    ArtifactRef,
    EvidenceAppendResult,
    EvidenceEvent,
    EvidenceSubmission,
    SupersessionRequest,
    TransitionAppendResult,
    TransitionRequest,
    ValidityTransition,
)
from core.domain.invariant import Invariant, InvariantRef
from core.domain.patch import Patch
from core.domain.state import CandidateState, TrustedState


class TrustedStateRepository(Protocol):
    """Trusted states and each lineage's current pointer (Doc 06 §6)."""

    def get(self, state_id: str) -> TrustedState | None:
        """The state, rebuilt with hash re-validation (DATA-INT-010), or ``None``."""
        ...

    def get_current(self, lineage_id: str) -> TrustedState | None:
        """The lineage's current trusted state, or ``None`` for an unknown lineage."""
        ...

    def assert_current(self, state_id: str) -> None:
        """Raise ``StaleParentError`` (SM-010) unless ``state_id`` is its lineage head."""
        ...

    def save_baseline(self, state: TrustedState) -> None:
        """Store a version-0 state and create its lineage's current pointer."""
        ...

    def save_promoted(self, state: TrustedState) -> None:
        """Store a promoted state and advance the current pointer from ``state.parent_state_id``
        to it by compare-and-swap; ``StaleParentError`` (SM-010) if the pointer has moved."""
        ...

    def lineage(self, state_id: str) -> list[TrustedState]:
        """The state followed by its ancestors, newest first, ending at version 0."""
        ...


class CandidateRepository(Protocol):
    """Untrusted candidates. Candidates are never deleted (Doc 05 §33)."""

    def create(self, candidate: CandidateState) -> None:
        """Store a new candidate; its status must be CREATED."""
        ...

    def get(self, candidate_id: str) -> CandidateState | None:
        """The candidate, rebuilt with hash re-validation, or ``None``."""
        ...

    def save_transition(self, new: CandidateState) -> None:
        """Store ``new`` as the next state of an existing candidate. Refused unless ``new`` is a
        legal successor of the stored candidate (Doc 06 §30)."""
        ...


class PatchRepository(Protocol):
    """Raw patches, retained independently of their candidates (Doc 05 §9, §33)."""

    def save(self, patch: Patch) -> None: ...

    def get(self, patch_id: str) -> Patch | None: ...


class InvariantRepository(Protocol):
    """Invariant definitions (immutable, versioned) and the references trusted states hold."""

    def register_definition(self, definition: Invariant) -> None:
        """Store a definition as version 1 or as the next version, with no gaps (Doc 06 §4.2)."""
        ...

    def get_definition(self, invariant_id: str, version: int) -> Invariant | None: ...

    def get_state_refs(self, state_id: str) -> tuple[InvariantRef, ...]:
        """The references held by one trusted state (Doc 05 §10.2, DATA-INT-009)."""
        ...


class EvidenceRepository(Protocol):
    """Append-only evidence (Doc 05 §16, §26; Doc 11; C-50 to C-56, C-59).

    There is no ``update`` or ``delete``: a record never changes, and its validity changes only by
    appending a transition (Doc 11 §32). Nothing accepts an ``EvidenceEvent``, a
    ``ValidityTransition`` or a ``ProofCheck`` as authority: evidence enters through an
    ``EvidenceSubmission``, a transition through a ``TransitionRequest`` or a
    ``SupersessionRequest``. Every list is in append order.
    """

    def append(self, submission: EvidenceSubmission) -> EvidenceAppendResult:
        """Store a record and its payload. The same ``evidence_id`` with identical content is a
        duplicate (nothing is written, ``duplicate`` is true); with different content it raises
        ``EvidenceConflictError`` (Doc 11 §38)."""
        ...

    def get(self, evidence_id: str) -> EvidenceEvent | None:
        """The record, rebuilt and re-validated, or ``None``."""
        ...

    def list_for_attempt(self, attempt_id: str) -> tuple[EvidenceEvent, ...]: ...

    def list_for_run(self, run_id: str) -> tuple[EvidenceEvent, ...]: ...

    def list_for_state(self, state_id: str) -> tuple[EvidenceEvent, ...]: ...

    def list_for_candidate(self, candidate_id: str) -> tuple[EvidenceEvent, ...]: ...

    def list_for_correlation(self, correlation_id: str) -> tuple[EvidenceEvent, ...]: ...

    def resolve(self, ref: ArtifactRef) -> Any:
        """The JSON payload a reference names. ``PersistenceError`` for a broken reference, and for
        a stored text that is not the canonical text of its value (Doc 11 §45)."""
        ...

    def append_transition(self, request: TransitionRequest) -> TransitionAppendResult:
        """Append a validity transition (C-52) and its EVIDENCE_VALIDITY_CHANGED audit event in one
        step. A redelivered ``transition_id`` creates neither a second row nor a second event."""
        ...

    def transitions(self, evidence_id: str) -> tuple[ValidityTransition, ...]:
        """The record's transitions in sequence order."""
        ...

    def supersede(self, request: SupersessionRequest) -> TransitionAppendResult:
        """Write the supersession row, the RECORD-scope SUPERSEDED transition and the audit event
        atomically (Doc 11 §33; C-53)."""
        ...

    def superseded_by(self, evidence_id: str) -> str | None:
        """The id of the record that superseded this one, or ``None``."""
        ...

    def supersedes(self, evidence_id: str) -> str | None:
        """The id of the record this one superseded, or ``None``."""
        ...


class AuditRepository(Protocol):
    """Append-only audit events (Doc 11 §12, §13, §38; C-57)."""

    def append(self, submission: AuditSubmission) -> AuditAppendResult:
        """Store an event. The same ``event_id`` with identical content is a duplicate; with any
        other difference it raises ``ConflictingDuplicateEventError`` (Doc 11 §38)."""
        ...

    def get(self, event_id: str) -> AuditEvent | None: ...

    def list_for_correlation(self, correlation_id: str) -> tuple[AuditEvent, ...]:
        """One workflow, in sequence order (Doc 11 §19, §20)."""
        ...

    def list_for_candidate(self, candidate_id: str) -> tuple[AuditEvent, ...]: ...


class UnitOfWork(Protocol):
    """One transaction over every repository (Doc 05 §32).

    Used as a context manager: it commits on a clean exit and rolls back on any exception, which
    propagates. Nothing written inside is visible to another connection before the commit.
    """

    @property
    def trusted_states(self) -> TrustedStateRepository: ...

    @property
    def candidates(self) -> CandidateRepository: ...

    @property
    def patches(self) -> PatchRepository: ...

    @property
    def invariants(self) -> InvariantRepository: ...

    @property
    def evidence(self) -> EvidenceRepository: ...

    @property
    def audit(self) -> AuditRepository: ...

    def __enter__(self) -> UnitOfWork: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
