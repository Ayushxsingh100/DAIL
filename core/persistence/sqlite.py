"""SQLite repositories and the unit of work (Doc 05 §16, §22, §26, §32, §33, §36; Doc 06 §6, §20,
§27, §30; Doc 11; C-42, C-43, C-46 to C-48, C-50 to C-59; P1b step 5 and 13.2, 13.3, 13.4; P2-fix
step 3).

``SqliteUnitOfWork`` implements every port of ``core.domain.repositories`` over one connection and
one transaction. It opens with ``isolation_level=None`` and runs ``BEGIN IMMEDIATE`` on entry, so
the write lock is taken before anything is read, ``COMMIT`` on a clean exit, and ``ROLLBACK`` on
any exception, which propagates. Nothing is visible to another connection before the commit.

A promotion is composed by the caller in one unit of work::

    with SqliteUnitOfWork(path) as uow:
        uow.trusted_states.save_promoted(new_state)
        uow.candidates.save_transition(mark_promoted(candidate, new_state))

``save_promoted`` runs first: the database refuses PROMOTED for a candidate whose parent has no
committed child (13.4). P6 adds the PromotionDecision write to the same unit of work (Doc 05 §32).
If ``save_promoted`` raises (stale parent, a failed write, an injected fault), it leaves the
transaction as it was before the call, so a caller that catches the error cannot commit half a
promotion: every mutating method runs inside a savepoint.

Reads rebuild every entity with ``from_dict`` through ``core.domain.codec`` and recompute every
hash (DATA-INT-010). A row that fails validation raises ``PersistenceError`` and is never
returned. Each read also cross-checks the scalar columns against the rebuilt entity, and the
``invariant_refs``, ``state_resources``, ``candidate_resources`` and ``resources`` rows against
what ``content_json`` declares (13.2), so a stray or edited row is caught.

A candidate's ``content_json`` leaves out ``status`` and ``status_reason``; those live in their
own columns (see ``core.persistence.schema``). The adapter never uses ``INSERT OR REPLACE`` or
``INSERT OR IGNORE`` (13.3).

The evidence and audit repositories (P2-fix) follow the same rules. Evidence enters only through
an ``EvidenceSubmission``, whose payload is re-checked on append (hash, canonical form, no
secret: A1); an artifact that exists is never replaced (A2); a redelivery with identical content
is a duplicate and any other difference raises (A6, Doc 11 §38); every read rebuilds through the
domain constructors and cross-checks the columns (A4). A validity transition is checked by
``check_transition`` (C-52) and appends its EVIDENCE_VALIDITY_CHANGED event in the same step.

``checkpoint`` is a test-only fault-injection seam. If given, it is called with a name at four
points of a state write and of the commit: ``"after_trusted_state_insert"``,
``"after_invariant_refs_insert"``, ``"after_lineage_head_update"`` and ``"before_commit"``.
Production code passes ``None``.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any

from core.domain.audit import (
    AuditAppendResult,
    AuditEvent,
    AuditEventType,
    AuditSubmission,
    ConflictingDuplicateEventError,
    validity_event_id,
)
from core.domain.codec import rebuild_candidate, rebuild_trusted_state
from core.domain.enums import CandidateStatus
from core.domain.errors import (
    DomainValidationError,
    IllegalTransitionError,
    PersistenceError,
    StaleParentError,
)
from core.domain.evidence import (
    ArtifactRef,
    BrokenReferenceError,
    ContextKind,
    EvidenceAppendResult,
    EvidenceConflictError,
    EvidenceContext,
    EvidenceEvent,
    EvidenceKind,
    EvidenceNotFoundError,
    EvidenceSubmission,
    EvidenceValidity,
    SupersessionRequest,
    TransitionAppendResult,
    TransitionRequest,
    TransitionScope,
    ValidityTransition,
    check_payload_json,
    check_supersession,
    check_transition,
    validity_changed_payload,
)
from core.domain.hashing import canonical_json
from core.domain.invariant import Invariant, InvariantRef
from core.domain.jsonvalue import iso_utc, parse_enum, parse_utc
from core.domain.lifecycle import check_candidate_transition
from core.domain.patch import Patch
from core.domain.repositories import UnitOfWork
from core.domain.resource import Resource
from core.domain.state import CandidateState, TrustedState
from core.persistence.schema import SCHEMA_VERSION, open_connection

CHECKPOINTS = (
    "after_trusted_state_insert",
    "after_invariant_refs_insert",
    "after_lineage_head_update",
    "before_commit",
)

_CANDIDATE_IDENTITY = (
    "candidate_id",
    "lineage_id",
    "parent_state_id",
    "candidate_sequence",
    "source",
    "patch_id",
    "patch_hash",
    "normalization_version",
    "created_at",
)


# --- helpers -----------------------------------------------------------------------------------


@contextmanager
def _guard(what: str) -> Iterator[None]:
    """Report a failure of the database itself as ``PersistenceError``."""
    try:
        yield
    except sqlite3.Error as exc:
        raise PersistenceError(f"{what}: {exc}") from exc


def _loads(text: object, what: str) -> Any:
    if not isinstance(text, str):
        raise PersistenceError(f"{what}: stored content_json is not text")
    try:
        return json.loads(text)
    except ValueError:
        raise PersistenceError(f"{what}: stored content_json is not valid JSON") from None


def _rebuild[T](what: str, build: Callable[[Mapping[str, Any]], T], data: Any) -> T:
    """Rebuild an entity; content that fails validation is a ``PersistenceError`` (DATA-INT-010)."""
    try:
        return build(data)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise PersistenceError(f"{what}: stored content fails validation ({exc})") from exc


def _require_equal(what: str, stored: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    """The scalar columns must agree with the entity rebuilt from ``content_json``."""
    for column, value in expected.items():
        if stored[column] != value:
            raise PersistenceError(
                f"{what}: stored column {column} disagrees with its content (DATA-INT-010)"
            )


def _store_resource(conn: sqlite3.Connection, resource: Resource) -> None:
    """Store a resource record, or check an existing one (13.3).

    A record that already exists is shared by a candidate and the state promoted from it, and it
    is never re-inserted: its stored fingerprint and content must equal this resource's.
    """
    content = canonical_json(resource.to_dict())
    row = conn.execute(
        "SELECT fingerprint, address, resource_type, content_json FROM resources "
        "WHERE record_id = ?",
        (resource.record_id,),
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO resources (record_id, fingerprint, address, resource_type, content_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                resource.record_id,
                resource.fingerprint,
                resource.address,
                resource.resource_type,
                content,
            ),
        )
        return
    stored = (row["fingerprint"], row["address"], row["resource_type"], row["content_json"])
    if stored != (resource.fingerprint, resource.address, resource.resource_type, content):
        raise PersistenceError(
            f"13.3: resource record {resource.record_id} already exists with different content"
        )


def _check_links(
    what: str,
    conn: sqlite3.Connection,
    link_sql: str,
    owner_id: str,
    resources: tuple[Resource, ...],
) -> None:
    """The link rows and the resource records must be exactly what the content declares (13.2)."""
    links = {(row[0], row[1]) for row in conn.execute(link_sql, (owner_id,))}
    declared = {(r.address, r.record_id) for r in resources}
    if links != declared:
        raise PersistenceError(
            f"{what}: stored resource links disagree with its content (13.2, DATA-INT-010)"
        )
    for resource in resources:
        row = conn.execute(
            "SELECT fingerprint, content_json FROM resources WHERE record_id = ?",
            (resource.record_id,),
        ).fetchone()
        if row is None or (row[0], row[1]) != (
            resource.fingerprint,
            canonical_json(resource.to_dict()),
        ):
            raise PersistenceError(
                f"{what}: stored resource record {resource.record_id} disagrees with its content "
                "(DATA-INT-010)"
            )


def _ref_tuple(ref: InvariantRef) -> tuple[Any, ...]:
    return (
        ref.invariant_id,
        ref.invariant_version,
        ref.status.value,
        ref.origin.value,
        canonical_json(list(ref.evidence_ids)),
        iso_utc(ref.last_verified_at),
        ref.invalidated_by_candidate_id,
        ref.invalidation_reason,
    )


class _Session:
    """The connection, the fault-injection seam and the savepoint counter of one unit of work."""

    def __init__(self, conn: sqlite3.Connection, checkpoint: Callable[[str], None] | None) -> None:
        self.conn = conn
        self._checkpoint = checkpoint
        self._depth = 0

    def hit(self, name: str) -> None:
        if self._checkpoint is not None:
            self._checkpoint(name)

    @contextmanager
    def atomic(self) -> Iterator[None]:
        """A savepoint: on any exception the work since entry is undone and the error propagates,
        so a failed write never leaves part of itself in the open transaction."""
        self._depth += 1
        name = f"sp_{self._depth}"
        self.conn.execute(f"SAVEPOINT {name}")
        try:
            yield
        except BaseException:
            self.conn.execute(f"ROLLBACK TO {name}")
            self.conn.execute(f"RELEASE {name}")
            raise
        else:
            self.conn.execute(f"RELEASE {name}")
        finally:
            self._depth -= 1


# --- trusted states ----------------------------------------------------------------------------


class _TrustedStates:
    def __init__(self, session: _Session) -> None:
        self._s = session

    # reads

    def get(self, state_id: str) -> TrustedState | None:
        conn = self._s.conn
        with _guard("read trusted state"):
            row = conn.execute(
                "SELECT state_id, lineage_id, version, parent_state_id, state_hash, "
                "commit_decision_id, content_json FROM trusted_states WHERE state_id = ?",
                (state_id,),
            ).fetchone()
            if row is None:
                return None
            what = f"trusted state {state_id}"
            state = _rebuild(what, rebuild_trusted_state, _loads(row["content_json"], what))
            _require_equal(
                what,
                row,
                {
                    "state_id": state.state_id,
                    "lineage_id": state.lineage_id,
                    "version": state.version,
                    "parent_state_id": state.parent_state_id,
                    "state_hash": state.state_hash,
                    "commit_decision_id": state.commit_decision_id,
                },
            )
            self._cross_check(what, state)
        return state

    def _cross_check(self, what: str, state: TrustedState) -> None:
        conn = self._s.conn
        refs = sorted(
            tuple(row)
            for row in conn.execute(
                "SELECT invariant_id, invariant_version, status, origin, evidence_ids, "
                "last_verified_at, invalidated_by_candidate_id, invalidation_reason "
                "FROM invariant_refs WHERE state_id = ?",
                (state.state_id,),
            )
        )
        if refs != sorted(_ref_tuple(ref) for ref in state.invariant_refs):
            raise PersistenceError(
                f"{what}: stored invariant references disagree with its content (13.2, "
                "DATA-INT-009)"
            )
        _check_links(
            what,
            conn,
            "SELECT address, record_id FROM state_resources WHERE state_id = ?",
            state.state_id,
            state.resources,
        )

    def _head(self, lineage_id: str) -> str | None:
        row = self._s.conn.execute(
            "SELECT current_state_id FROM lineage_heads WHERE lineage_id = ?", (lineage_id,)
        ).fetchone()
        return None if row is None else str(row[0])

    def get_current(self, lineage_id: str) -> TrustedState | None:
        with _guard("read the current pointer"):
            head = self._head(lineage_id)
        if head is None:
            return None
        state = self.get(head)
        if state is None or state.lineage_id != lineage_id:
            raise PersistenceError(
                f"lineage {lineage_id}: the current pointer names {head}, which is not a state "
                "of that lineage (Doc 06 §6)"
            )
        return state

    def assert_current(self, state_id: str) -> None:
        with _guard("read the current pointer"):
            row = self._s.conn.execute(
                "SELECT lineage_id FROM trusted_states WHERE state_id = ?", (state_id,)
            ).fetchone()
            head = None if row is None else self._head(row[0])
        if head != state_id:
            raise StaleParentError(
                head,
                state_id,
                (
                    "the state is not the current state of its lineage"
                    if row is not None
                    else "no such trusted state"
                ),
            )

    def lineage(self, state_id: str) -> list[TrustedState]:
        chain: list[TrustedState] = []
        seen: set[str] = set()
        current: str | None = state_id
        while current is not None:
            if current in seen:
                raise PersistenceError(f"cycle in the trusted-state lineage at {current}")
            seen.add(current)
            state = self.get(current)
            if state is None:
                raise PersistenceError(f"trusted state {current} not found (broken lineage)")
            if chain and (
                state.lineage_id != chain[-1].lineage_id or state.version != chain[-1].version - 1
            ):
                raise PersistenceError(f"trusted state {current} breaks the lineage (Doc 06 §6)")
            chain.append(state)
            current = state.parent_state_id
        return chain

    # writes

    def save_baseline(self, state: TrustedState) -> None:
        if not isinstance(state, TrustedState):
            raise DomainValidationError("save_baseline: expected a TrustedState")
        if state.version != 0:
            raise DomainValidationError(
                f"SM-001, C-32: save_baseline stores version 0 only, not {state.version}; a later "
                "state is stored by save_promoted"
            )
        with _guard("save baseline"), self._s.atomic():
            if self._head(state.lineage_id) is not None:
                raise DomainValidationError(
                    f"SM-001: lineage {state.lineage_id} already has a baseline"
                )
            self._insert_state(state)
            self._s.conn.execute(
                "INSERT INTO lineage_heads (lineage_id, current_state_id) VALUES (?, ?)",
                (state.lineage_id, state.state_id),
            )
            self._s.hit("after_lineage_head_update")

    def save_promoted(self, state: TrustedState) -> None:
        if not isinstance(state, TrustedState):
            raise DomainValidationError("save_promoted: expected a TrustedState")
        if state.version == 0 or state.parent_state_id is None:
            raise DomainValidationError(
                "SM-001, C-32: save_promoted stores a promoted state; the baseline is stored by "
                "save_baseline"
            )
        with _guard("save promoted state"), self._s.atomic():
            head = self._head(state.lineage_id)
            if head is None:
                raise PersistenceError(
                    f"lineage {state.lineage_id} has no baseline, so nothing can be promoted"
                )
            if head != state.parent_state_id:
                raise StaleParentError(
                    head,
                    state.parent_state_id,
                    f"the lineage's current state is {head}, not the new state's parent "
                    f"{state.parent_state_id}",
                )
            self._insert_state(state)
            moved = self._s.conn.execute(
                "UPDATE lineage_heads SET current_state_id = ? "
                "WHERE lineage_id = ? AND current_state_id = ?",
                (state.state_id, state.lineage_id, state.parent_state_id),
            )
            if moved.rowcount != 1:
                raise StaleParentError(
                    head,
                    state.parent_state_id,
                    "the current pointer moved before the compare-and-swap",
                )
            self._s.hit("after_lineage_head_update")

    def _insert_state(self, state: TrustedState) -> None:
        conn = self._s.conn
        conn.execute(
            "INSERT INTO trusted_states (state_id, lineage_id, version, parent_state_id, "
            "state_hash, commit_decision_id, content_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                state.state_id,
                state.lineage_id,
                state.version,
                state.parent_state_id,
                state.state_hash,
                state.commit_decision_id,
                canonical_json(state.to_dict()),
            ),
        )
        self._s.hit("after_trusted_state_insert")
        for resource in state.resources:
            _store_resource(conn, resource)
            conn.execute(
                "INSERT INTO state_resources (state_id, address, record_id) VALUES (?, ?, ?)",
                (state.state_id, resource.address, resource.record_id),
            )
        for ref in state.invariant_refs:
            conn.execute(
                "INSERT INTO invariant_refs (state_id, invariant_id, invariant_version, status, "
                "origin, evidence_ids, last_verified_at, invalidated_by_candidate_id, "
                "invalidation_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (state.state_id, *_ref_tuple(ref)),
            )
        self._s.hit("after_invariant_refs_insert")


# --- candidates --------------------------------------------------------------------------------


def _candidate_content(candidate: CandidateState) -> str:
    """The candidate's ``to_dict()`` without the two lifecycle fields that have own columns."""
    data = candidate.to_dict()
    del data["status"], data["status_reason"]
    return canonical_json(data)


class _Candidates:
    def __init__(self, session: _Session, states: _TrustedStates) -> None:
        self._s = session
        self._states = states

    def create(self, candidate: CandidateState) -> None:
        if not isinstance(candidate, CandidateState):
            raise DomainValidationError("create: expected a CandidateState")
        if candidate.status is not CandidateStatus.CREATED:
            raise DomainValidationError(
                f"Doc 06 §5: a candidate is created with status CREATED, not {candidate.status}"
            )
        with _guard("create candidate"), self._s.atomic():
            self._s.conn.execute(
                "INSERT INTO candidates (candidate_id, parent_state_id, patch_id, lineage_id, "
                "candidate_sequence, status, status_reason, patch_hash, state_hash, content_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    candidate.candidate_id,
                    candidate.parent_state_id,
                    candidate.patch_id,
                    candidate.lineage_id,
                    candidate.candidate_sequence,
                    candidate.status.value,
                    candidate.status_reason,
                    candidate.patch_hash,
                    candidate.state_hash,
                    _candidate_content(candidate),
                ),
            )

    def get(self, candidate_id: str) -> CandidateState | None:
        with _guard("read candidate"):
            row = self._s.conn.execute(
                "SELECT candidate_id, parent_state_id, patch_id, lineage_id, candidate_sequence, "
                "status, status_reason, patch_hash, state_hash, content_json FROM candidates "
                "WHERE candidate_id = ?",
                (candidate_id,),
            ).fetchone()
            if row is None:
                return None
            what = f"candidate {candidate_id}"
            content = _loads(row["content_json"], what)
            if not isinstance(content, dict) or {"status", "status_reason"} & set(content):
                raise PersistenceError(
                    f"{what}: stored content must not carry the lifecycle columns (DATA-INT-010)"
                )
            content["status"] = row["status"]
            content["status_reason"] = row["status_reason"]
            candidate = _rebuild(what, rebuild_candidate, content)
            _require_equal(
                what,
                row,
                {
                    "candidate_id": candidate.candidate_id,
                    "parent_state_id": candidate.parent_state_id,
                    "patch_id": candidate.patch_id,
                    "lineage_id": candidate.lineage_id,
                    "candidate_sequence": candidate.candidate_sequence,
                    "status": candidate.status.value,
                    "status_reason": candidate.status_reason,
                    "patch_hash": candidate.patch_hash,
                    "state_hash": candidate.state_hash,
                },
            )
            _check_links(
                what,
                self._s.conn,
                "SELECT address, record_id FROM candidate_resources WHERE candidate_id = ?",
                candidate.candidate_id,
                candidate.resources,
            )
            if candidate.status is CandidateStatus.PROMOTED:
                self._check_promotion(what, candidate)
        return candidate

    def _check_promotion(self, what: str, candidate: CandidateState) -> None:
        """A PROMOTED candidate must have a committed child state of its parent that carries
        exactly its resources (DATA-INT-005, DATA-INT-010)."""
        row = self._s.conn.execute(
            "SELECT state_id FROM trusted_states WHERE parent_state_id = ?",
            (candidate.parent_state_id,),
        ).fetchone()
        child = None if row is None else self._states.get(row[0])
        if (
            child is None
            or child.lineage_id != candidate.lineage_id
            or child.resource_set_hash() != candidate.state_hash
        ):
            raise PersistenceError(
                f"{what}: status PROMOTED, but no committed state promoted from its parent "
                "carries its resources (DATA-INT-005)"
            )

    def save_transition(self, new: CandidateState) -> None:
        if not isinstance(new, CandidateState):
            raise DomainValidationError("save_transition: expected a CandidateState")
        old = self.get(new.candidate_id)
        if old is None:
            raise PersistenceError(f"save_transition: candidate {new.candidate_id} not found")
        for field in _CANDIDATE_IDENTITY:
            if getattr(new, field) != getattr(old, field):
                raise DomainValidationError(
                    f"save_transition: {field} cannot change (Doc 05 §23, Doc 06 §30)"
                )
        check_candidate_transition(old.status, new.status)
        building_to_ready = (
            old.status is CandidateStatus.BUILDING and new.status is CandidateStatus.READY
        )
        if not building_to_ready and (
            new.resources != old.resources or new.state_hash != old.state_hash
        ):
            raise DomainValidationError(
                "save_transition: resources and state_hash change only on BUILDING -> READY "
                "(Doc 05 §8.1, §23)"
            )
        self._check_lineage_rules(old, new)
        with _guard("save candidate transition"), self._s.atomic():
            conn = self._s.conn
            if building_to_ready:
                moved = conn.execute(
                    "UPDATE candidates SET status = ?, status_reason = ?, state_hash = ?, "
                    "content_json = ? WHERE candidate_id = ? AND status = ?",
                    (
                        new.status.value,
                        new.status_reason,
                        new.state_hash,
                        _candidate_content(new),
                        new.candidate_id,
                        old.status.value,
                    ),
                )
            else:
                moved = conn.execute(
                    "UPDATE candidates SET status = ?, status_reason = ? "
                    "WHERE candidate_id = ? AND status = ?",
                    (new.status.value, new.status_reason, new.candidate_id, old.status.value),
                )
            if moved.rowcount != 1:
                raise PersistenceError(
                    f"save_transition: candidate {new.candidate_id} is no longer {old.status}"
                )
            if building_to_ready:
                for resource in new.resources:
                    _store_resource(conn, resource)
                    conn.execute(
                        "INSERT INTO candidate_resources (candidate_id, address, record_id) "
                        "VALUES (?, ?, ?)",
                        (new.candidate_id, resource.address, resource.record_id),
                    )

    def _check_lineage_rules(self, old: CandidateState, new: CandidateState) -> None:
        """The two transitions that depend on the lineage's current pointer (Doc 06 §20, §30)."""
        with _guard("read the current pointer"):
            head = self._states._head(new.lineage_id)
        if (
            old.status is CandidateStatus.PROMOTABLE
            and new.status is CandidateStatus.REJECTED
            and head == new.parent_state_id
        ):
            raise IllegalTransitionError(
                "candidate",
                old.status,
                new.status,
                "C-29",
                "the candidate's parent is still the current state, so it is not stale "
                "(Doc 06 §20)",
            )
        if new.status is CandidateStatus.PROMOTED:
            current = None if head is None else self._states.get(head)
            if (
                current is None
                or current.parent_state_id != new.parent_state_id
                or current.resource_set_hash() != new.state_hash
            ):
                raise IllegalTransitionError(
                    "candidate",
                    old.status,
                    new.status,
                    "SM-002",
                    "the lineage's current state was not promoted from this candidate's parent "
                    "with its resources; run save_promoted first in the same unit of work",
                )


# --- patches and invariants --------------------------------------------------------------------


class _Patches:
    def __init__(self, session: _Session) -> None:
        self._s = session

    def save(self, patch: Patch) -> None:
        if not isinstance(patch, Patch):
            raise DomainValidationError("save: expected a Patch")
        with _guard("save patch"), self._s.atomic():
            self._s.conn.execute(
                "INSERT INTO patches (patch_id, parent_state_id, content_hash, content_json) "
                "VALUES (?, ?, ?, ?)",
                (
                    patch.patch_id,
                    patch.parent_state_id,
                    patch.content_hash,
                    canonical_json(patch.to_dict()),
                ),
            )

    def get(self, patch_id: str) -> Patch | None:
        with _guard("read patch"):
            row = self._s.conn.execute(
                "SELECT patch_id, parent_state_id, content_hash, content_json FROM patches "
                "WHERE patch_id = ?",
                (patch_id,),
            ).fetchone()
            if row is None:
                return None
            what = f"patch {patch_id}"
            patch = _rebuild(what, Patch.from_dict, _loads(row["content_json"], what))
            _require_equal(
                what,
                row,
                {
                    "patch_id": patch.patch_id,
                    "parent_state_id": patch.parent_state_id,
                    "content_hash": patch.content_hash,
                },
            )
        return patch


class _Invariants:
    def __init__(self, session: _Session, states: _TrustedStates) -> None:
        self._s = session
        self._states = states

    def register_definition(self, definition: Invariant) -> None:
        if not isinstance(definition, Invariant):
            raise DomainValidationError("register_definition: expected an Invariant")
        with _guard("register invariant definition"), self._s.atomic():
            row = self._s.conn.execute(
                "SELECT MAX(version) FROM invariants WHERE invariant_id = ?",
                (definition.invariant_id,),
            ).fetchone()
            latest = 0 if row[0] is None else int(row[0])
            if definition.version <= latest:
                raise DomainValidationError(
                    f"Doc 06 §4.2: {definition.invariant_id} v{definition.version} is already "
                    "registered; a changed definition is a new version"
                )
            if definition.version != latest + 1:
                raise DomainValidationError(
                    f"Doc 06 §4.2: {definition.invariant_id} must be registered as version "
                    f"{latest + 1}, not {definition.version} (versions have no gaps)"
                )
            self._s.conn.execute(
                "INSERT INTO invariants (invariant_id, version, definition_hash, created_at, "
                "content_json) VALUES (?, ?, ?, ?, ?)",
                (
                    definition.invariant_id,
                    definition.version,
                    definition.definition_hash(),
                    iso_utc(definition.created_at),
                    canonical_json(definition.to_dict()),
                ),
            )

    def get_definition(self, invariant_id: str, version: int) -> Invariant | None:
        with _guard("read invariant definition"):
            row = self._s.conn.execute(
                "SELECT invariant_id, version, definition_hash, created_at, content_json "
                "FROM invariants WHERE invariant_id = ? AND version = ?",
                (invariant_id, version),
            ).fetchone()
            if row is None:
                return None
            what = f"invariant {invariant_id} v{version}"
            definition = _rebuild(what, Invariant.from_dict, _loads(row["content_json"], what))
            _require_equal(
                what,
                row,
                {
                    "invariant_id": definition.invariant_id,
                    "version": definition.version,
                    "definition_hash": definition.definition_hash(),
                    "created_at": iso_utc(definition.created_at),
                },
            )
        return definition

    def get_state_refs(self, state_id: str) -> tuple[InvariantRef, ...]:
        state = self._states.get(state_id)
        if state is None:
            raise PersistenceError(f"trusted state {state_id} not found")
        return state.invariant_refs


# --- evidence and audit ------------------------------------------------------------------------


def _store_artifact(conn: sqlite3.Connection, content_hash: str, payload_json: str) -> None:
    """Store a content-addressed payload, or check the one already stored (A2, A3).

    An artifact that already exists must hold byte-identical text: it is never replaced, and a
    stored text that differs from the submitted one (a tampered artifact) refuses the append.
    """
    row = conn.execute(
        "SELECT payload_json FROM evidence_artifacts WHERE content_hash = ?", (content_hash,)
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO evidence_artifacts (content_hash, payload_json) VALUES (?, ?)",
            (content_hash, payload_json),
        )
    elif row["payload_json"] != payload_json:
        raise PersistenceError(
            f"A2: artifact {content_hash} is already stored with different text; it is never "
            "replaced (Doc 11 §4, §45)"
        )


_EVENT_COLUMNS = (
    "seq, evidence_id, run_id, attempt_id, correlation_id, operation_id, kind, event_name, "
    "state_id, candidate_id, parent_state_id, state_hash, content_hash, hash_algorithm, "
    "payload_ref, provenance_json, validity, schema_version, redaction_policy_version, "
    "created_at, content_json"
)


def _event_values(event: EvidenceEvent) -> tuple[Any, ...]:
    return (
        event.evidence_id,
        event.run_id,
        event.attempt_id,
        event.correlation_id,
        event.operation_id,
        event.kind.value,
        event.event_name,
        event.state_id,
        event.candidate_id,
        event.parent_state_id,
        event.state_hash,
        event.content_hash,
        event.hash_algorithm,
        event.payload_ref,
        canonical_json(event.provenance.to_dict()),
        event.validity.value,
        event.schema_version,
        event.redaction_policy_version,
        iso_utc(event.created_at),
        canonical_json(event.to_dict()),
    )


def _event_from_row(row: sqlite3.Row) -> EvidenceEvent:
    """Rebuild a stored record through the domain constructor and cross-check every column against
    it (A4, DATA-INT-010): an edited column or an edited ``content_json`` is caught."""
    what = f"evidence {row['evidence_id']}"
    event = _rebuild(what, EvidenceEvent.from_dict, _loads(row["content_json"], what))
    expected = dict(
        zip(
            _EVENT_COLUMNS.replace("seq, ", "").split(", "),
            _event_values(event),
            strict=True,
        )
    )
    _require_equal(what, dict(row), expected)
    return event


_TRANSITION_COLUMNS = (
    "seq, transition_id, evidence_id, scope, context_kind, context_id, from_validity, "
    "to_validity, reason, impact_ref, superseded_by, correlation_id, operation_id, created_at"
)


def _transition_from_row(row: sqlite3.Row) -> ValidityTransition:
    what = f"validity transition {row['transition_id']}"

    def build(data: Mapping[str, Any]) -> ValidityTransition:
        kind = data["context_kind"]
        return ValidityTransition(
            seq=data["seq"],
            transition_id=data["transition_id"],
            evidence_id=data["evidence_id"],
            scope=parse_enum(data["scope"], TransitionScope, "ValidityTransition.scope"),
            context=(
                None
                if kind is None
                else EvidenceContext(
                    parse_enum(kind, ContextKind, "ValidityTransition.context_kind"),
                    data["context_id"],
                )
            ),
            from_validity=parse_enum(
                data["from_validity"], EvidenceValidity, "ValidityTransition.from_validity"
            ),
            to_validity=parse_enum(
                data["to_validity"], EvidenceValidity, "ValidityTransition.to_validity"
            ),
            reason=data["reason"],
            impact_ref=data["impact_ref"],
            superseded_by=data["superseded_by"],
            correlation_id=data["correlation_id"],
            operation_id=data["operation_id"],
            created_at=parse_utc(data["created_at"], "ValidityTransition.created_at"),
        )

    return _rebuild(what, build, dict(row))


_AUDIT_COLUMNS = (
    "sequence, event_id, event_type, event_version, correlation_id, operation_id, actor_type, "
    "actor_id, state_id, candidate_id, decision_id, timestamp, payload_hash, payload_ref"
)


def _audit_from_row(row: sqlite3.Row) -> AuditEvent:
    return _rebuild(f"audit event {row['event_id']}", AuditEvent.from_row, dict(row))


class _Audit:
    def __init__(self, session: _Session) -> None:
        self._s = session

    def append(self, submission: AuditSubmission) -> AuditAppendResult:
        if not isinstance(submission, AuditSubmission):
            raise DomainValidationError("append: expected an AuditSubmission")
        # A1: the payload hashes to payload_hash, is canonical, and holds no secret.
        check_payload_json(submission.payload_json, submission.payload_hash)
        with _guard("append audit event"), self._s.atomic():
            conn = self._s.conn
            existing = self.get(submission.event_id)
            if existing is not None:
                # A6, Doc 11 §38: every field except sequence and timestamp must be identical.
                if existing.same_content_as(submission):
                    return AuditAppendResult(existing, True)
                raise ConflictingDuplicateEventError(
                    f"event_id {submission.event_id} was already delivered with different content "
                    "(Doc 11 §38)"
                )
            _store_artifact(conn, submission.payload_hash, submission.payload_json)
            conn.execute(
                "INSERT INTO audit_events (event_id, event_type, event_version, correlation_id, "
                "operation_id, actor_type, actor_id, state_id, candidate_id, decision_id, "
                "timestamp, payload_hash, payload_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "?, ?)",
                (
                    submission.event_id,
                    submission.event_type.value,
                    submission.event_version,
                    submission.correlation_id,
                    submission.operation_id,
                    submission.actor_type.value,
                    submission.actor_id,
                    submission.state_id,
                    submission.candidate_id,
                    submission.decision_id,
                    iso_utc(submission.timestamp),
                    submission.payload_hash,
                    submission.payload_ref,
                ),
            )
            stored = self.get(submission.event_id)
        if stored is None:  # pragma: no cover - the row was just inserted
            raise PersistenceError(f"audit event {submission.event_id} vanished after insert")
        return AuditAppendResult(stored, False)

    def get(self, event_id: str) -> AuditEvent | None:
        with _guard("read audit event"):
            row = self._s.conn.execute(
                f"SELECT {_AUDIT_COLUMNS} FROM audit_events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return None if row is None else _audit_from_row(row)

    def _list(self, column: str, value: str) -> tuple[AuditEvent, ...]:
        with _guard("list audit events"):
            rows = self._s.conn.execute(
                f"SELECT {_AUDIT_COLUMNS} FROM audit_events WHERE {column} = ? ORDER BY sequence",
                (value,),
            ).fetchall()
        return tuple(_audit_from_row(row) for row in rows)

    def list_for_correlation(self, correlation_id: str) -> tuple[AuditEvent, ...]:
        return self._list("correlation_id", correlation_id)

    def list_for_candidate(self, candidate_id: str) -> tuple[AuditEvent, ...]:
        return self._list("candidate_id", candidate_id)


class _Evidence:
    def __init__(self, session: _Session, audit: _Audit) -> None:
        self._s = session
        self._audit = audit

    # reads

    def get(self, evidence_id: str) -> EvidenceEvent | None:
        with _guard("read evidence"):
            row = self._s.conn.execute(
                f"SELECT {_EVENT_COLUMNS} FROM evidence_events WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        return None if row is None else _event_from_row(row)

    def _require(self, evidence_id: str) -> EvidenceEvent:
        event = self.get(evidence_id)
        if event is None:
            raise EvidenceNotFoundError(f"evidence {evidence_id} does not exist")
        return event

    def _list(self, column: str, value: str) -> tuple[EvidenceEvent, ...]:
        with _guard("list evidence"):
            rows = self._s.conn.execute(
                f"SELECT {_EVENT_COLUMNS} FROM evidence_events WHERE {column} = ? ORDER BY seq",
                (value,),
            ).fetchall()
        return tuple(_event_from_row(row) for row in rows)

    def list_for_attempt(self, attempt_id: str) -> tuple[EvidenceEvent, ...]:
        return self._list("attempt_id", attempt_id)

    def list_for_run(self, run_id: str) -> tuple[EvidenceEvent, ...]:
        return self._list("run_id", run_id)

    def list_for_state(self, state_id: str) -> tuple[EvidenceEvent, ...]:
        return self._list("state_id", state_id)

    def list_for_candidate(self, candidate_id: str) -> tuple[EvidenceEvent, ...]:
        return self._list("candidate_id", candidate_id)

    def list_for_correlation(self, correlation_id: str) -> tuple[EvidenceEvent, ...]:
        return self._list("correlation_id", correlation_id)

    def resolve(self, ref: ArtifactRef) -> Any:
        if not isinstance(ref, ArtifactRef):
            raise DomainValidationError("resolve: expected an ArtifactRef")
        with _guard("resolve artifact"):
            row = self._s.conn.execute(
                "SELECT payload_json FROM evidence_artifacts WHERE content_hash = ?",
                (ref.content_hash,),
            ).fetchone()
        if row is None:
            raise BrokenReferenceError(
                f"{ref.uri}: no stored artifact; the reference is broken (Doc 11 §44)"
            )
        try:
            return json.loads(row["payload_json"])
        except ValueError:
            raise PersistenceError(f"{ref.uri}: the stored artifact is not valid JSON") from None

    def transitions(self, evidence_id: str) -> tuple[ValidityTransition, ...]:
        with _guard("list validity transitions"):
            rows = self._s.conn.execute(
                f"SELECT {_TRANSITION_COLUMNS} FROM evidence_validity_transitions "
                "WHERE evidence_id = ? ORDER BY seq",
                (evidence_id,),
            ).fetchall()
        return tuple(_transition_from_row(row) for row in rows)

    def _transition_by_id(self, transition_id: str) -> ValidityTransition | None:
        with _guard("read validity transition"):
            row = self._s.conn.execute(
                f"SELECT {_TRANSITION_COLUMNS} FROM evidence_validity_transitions "
                "WHERE transition_id = ?",
                (transition_id,),
            ).fetchone()
        return None if row is None else _transition_from_row(row)

    def superseded_by(self, evidence_id: str) -> str | None:
        with _guard("read supersession"):
            row = self._s.conn.execute(
                "SELECT new_evidence_id FROM evidence_supersessions WHERE old_evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        return None if row is None else str(row[0])

    def supersedes(self, evidence_id: str) -> str | None:
        with _guard("read supersession"):
            row = self._s.conn.execute(
                "SELECT old_evidence_id FROM evidence_supersessions WHERE new_evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        return None if row is None else str(row[0])

    # writes

    def append(self, submission: EvidenceSubmission) -> EvidenceAppendResult:
        if not isinstance(submission, EvidenceSubmission):
            raise DomainValidationError("append: expected an EvidenceSubmission")
        event = submission.event
        # A1: the payload hashes to content_hash, is canonical JSON and holds no secret.
        check_payload_json(submission.payload_json, event.content_hash)
        with _guard("append evidence"), self._s.atomic():
            conn = self._s.conn
            existing = self.get(event.evidence_id)
            if existing is not None:
                # A6, Doc 11 §38: identical in every field except created_at is a redelivery.
                if existing.same_content_as(event):
                    return EvidenceAppendResult(existing, True)
                raise EvidenceConflictError(
                    f"evidence_id {event.evidence_id} already exists with different content "
                    "(Doc 11 §38)"
                )
            _store_artifact(conn, event.content_hash, submission.payload_json)
            conn.execute(
                "INSERT INTO evidence_events (evidence_id, run_id, attempt_id, correlation_id, "
                "operation_id, kind, event_name, state_id, candidate_id, parent_state_id, "
                "state_hash, content_hash, hash_algorithm, payload_ref, provenance_json, "
                "validity, schema_version, redaction_policy_version, created_at, content_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                _event_values(event),
            )
            stored = self.get(event.evidence_id)
        if stored is None:  # pragma: no cover - the row was just inserted
            raise PersistenceError(f"evidence {event.evidence_id} vanished after insert")
        return EvidenceAppendResult(stored, False)

    def _check_impact_ref(self, request: TransitionRequest) -> None:
        """INVALID in a candidate context names IMPACT evidence bound to that candidate (C-52,
        Doc 11 §32). The database repeats this check in a trigger."""
        context = request.context
        if (
            request.scope is not TransitionScope.CONTEXT
            or context is None
            or context.kind is not ContextKind.CANDIDATE
            or request.to_validity is not EvidenceValidity.INVALID
        ):
            return
        impact = None if request.impact_ref is None else self.get(request.impact_ref)
        if (
            impact is None
            or impact.kind is not EvidenceKind.IMPACT
            or impact.candidate_id != context.id
        ):
            raise IllegalTransitionError(
                "evidence validity",
                request.to_validity,
                request.to_validity,
                "C-52",
                f"impact_ref must name IMPACT evidence bound to candidate {context.id} "
                "(Doc 11 §32)",
            )

    def append_transition(self, request: TransitionRequest) -> TransitionAppendResult:
        if not isinstance(request, TransitionRequest):
            raise DomainValidationError("append_transition: expected a TransitionRequest")
        with _guard("append validity transition"), self._s.atomic():
            existing = self._transition_by_id(request.transition_id)
            if existing is not None:
                # A6: a redelivery adds no second row and no second audit event.
                if (
                    existing.evidence_id == request.evidence_id
                    and existing.scope is request.scope
                    and existing.context == request.context
                    and existing.to_validity is request.to_validity
                    and existing.reason == request.reason
                    and existing.impact_ref == request.impact_ref
                    and existing.superseded_by is None
                    and existing.correlation_id == request.correlation_id
                    and existing.operation_id == request.operation_id
                ):
                    return TransitionAppendResult(existing, True)
                raise EvidenceConflictError(
                    f"transition_id {request.transition_id} was already delivered with different "
                    "content (Doc 11 §38)"
                )
            event = self._require(request.evidence_id)
            from_validity = check_transition(event, request, self.transitions(event.evidence_id))
            self._check_impact_ref(request)
            return self._insert_transition(
                event,
                transition_id=request.transition_id,
                scope=request.scope,
                context=request.context,
                from_validity=from_validity,
                to_validity=request.to_validity,
                reason=request.reason,
                impact_ref=request.impact_ref,
                superseded_by=None,
                correlation_id=request.correlation_id,
                operation_id=request.operation_id,
                created_at=request.created_at,
            )

    def supersede(self, request: SupersessionRequest) -> TransitionAppendResult:
        if not isinstance(request, SupersessionRequest):
            raise DomainValidationError("supersede: expected a SupersessionRequest")
        with _guard("supersede evidence"), self._s.atomic():
            existing = self._transition_by_id(request.transition_id)
            if existing is not None:
                if (
                    existing.evidence_id == request.old_evidence_id
                    and existing.scope is TransitionScope.RECORD
                    and existing.to_validity is EvidenceValidity.SUPERSEDED
                    and existing.superseded_by == request.new_evidence_id
                    and existing.reason == request.reason
                    and existing.correlation_id == request.correlation_id
                    and existing.operation_id == request.operation_id
                ):
                    return TransitionAppendResult(existing, True)
                raise EvidenceConflictError(
                    f"transition_id {request.transition_id} was already delivered with different "
                    "content (Doc 11 §38)"
                )
            old = self._require(request.old_evidence_id)
            new = self._require(request.new_evidence_id)
            from_validity = check_supersession(
                old,
                new,
                self.transitions(old.evidence_id),
                self.transitions(new.evidence_id),
            )
            # The supersession row first: the SUPERSEDED transition trigger requires it (C-53).
            self._s.conn.execute(
                "INSERT INTO evidence_supersessions (old_evidence_id, new_evidence_id, created_at) "
                "VALUES (?, ?, ?)",
                (old.evidence_id, new.evidence_id, iso_utc(request.created_at)),
            )
            return self._insert_transition(
                old,
                transition_id=request.transition_id,
                scope=TransitionScope.RECORD,
                context=None,
                from_validity=from_validity,
                to_validity=EvidenceValidity.SUPERSEDED,
                reason=request.reason,
                impact_ref=None,
                superseded_by=new.evidence_id,
                correlation_id=request.correlation_id,
                operation_id=request.operation_id,
                created_at=request.created_at,
            )

    def _insert_transition(
        self,
        event: EvidenceEvent,
        *,
        transition_id: str,
        scope: TransitionScope,
        context: EvidenceContext | None,
        from_validity: EvidenceValidity,
        to_validity: EvidenceValidity,
        reason: str,
        impact_ref: str | None,
        superseded_by: str | None,
        correlation_id: str,
        operation_id: str,
        created_at: datetime,
    ) -> TransitionAppendResult:
        """Write the transition row and its EVIDENCE_VALIDITY_CHANGED audit event (Doc 11 §32,
        C-52); the caller's savepoint makes the two one step."""
        self._s.conn.execute(
            "INSERT INTO evidence_validity_transitions (transition_id, evidence_id, scope, "
            "context_kind, context_id, from_validity, to_validity, reason, impact_ref, "
            "superseded_by, correlation_id, operation_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                transition_id,
                event.evidence_id,
                scope.value,
                None if context is None else context.kind.value,
                None if context is None else context.id,
                from_validity.value,
                to_validity.value,
                reason,
                impact_ref,
                superseded_by,
                correlation_id,
                operation_id,
                iso_utc(created_at),
            ),
        )
        stored = self._transition_by_id(transition_id)
        if stored is None:  # pragma: no cover - the row was just inserted
            raise PersistenceError(f"transition {transition_id} vanished after insert")
        if context is None:  # RECORD scope: the affected state and candidate are the record's own
            state_id, candidate_id = event.state_id, event.candidate_id
        else:
            is_state = context.kind is ContextKind.STATE
            state_id = context.id if is_state else None
            candidate_id = None if is_state else context.id
        self._audit.append(
            AuditSubmission.create(
                event_id=validity_event_id(transition_id),
                event_type=AuditEventType.EVIDENCE_VALIDITY_CHANGED,
                correlation_id=correlation_id,
                operation_id=operation_id,
                timestamp=created_at,
                payload=validity_changed_payload(
                    evidence_id=event.evidence_id,
                    scope=scope,
                    context=context,
                    from_validity=from_validity,
                    to_validity=to_validity,
                    reason=reason,
                    impact_ref=impact_ref,
                    superseded_by=superseded_by,
                ),
                state_id=state_id,
                candidate_id=candidate_id,
            )
        )
        return TransitionAppendResult(stored, False)


# --- unit of work ------------------------------------------------------------------------------


class SqliteUnitOfWork:
    """One transaction over every repository (Doc 05 §32). Use it as a context manager."""

    def __init__(
        self,
        path: str | Path,
        *,
        checkpoint: Callable[[str], None] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._path = Path(path)
        self._checkpoint = checkpoint
        self._timeout = timeout
        self._session: _Session | None = None
        self._trusted_states: _TrustedStates | None = None
        self._candidates: _Candidates | None = None
        self._patches: _Patches | None = None
        self._invariants: _Invariants | None = None
        self._evidence: _Evidence | None = None
        self._audit: _Audit | None = None

    def __enter__(self) -> SqliteUnitOfWork:
        if self._session is not None:
            raise PersistenceError("this unit of work is already open")
        try:
            conn = open_connection(self._path, timeout=self._timeout)
        except sqlite3.Error as exc:
            raise PersistenceError(f"cannot open {self._path.name}: {exc}") from exc
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("BEGIN IMMEDIATE")
            version = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.Error as exc:
            conn.close()
            raise PersistenceError(
                f"cannot begin a transaction on {self._path.name} (the database is busy, or has "
                f"no schema {SCHEMA_VERSION}): {exc}"
            ) from exc
        if version is None or version[0] != SCHEMA_VERSION:
            self._rollback(conn)
            conn.close()
            raise PersistenceError(
                f"{self._path.name} does not have schema version {SCHEMA_VERSION} (C-44); delete "
                "the local development database and run bootstrap again"
            )
        session = _Session(conn, self._checkpoint)
        states = _TrustedStates(session)
        self._session = session
        self._trusted_states = states
        self._candidates = _Candidates(session, states)
        self._patches = _Patches(session)
        self._invariants = _Invariants(session, states)
        audit = _Audit(session)
        self._audit = audit
        self._evidence = _Evidence(session, audit)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        session = self._session
        if session is None:
            return
        conn = session.conn
        try:
            if exc_type is None:
                try:
                    session.hit("before_commit")
                    conn.execute("COMMIT")
                except BaseException as failure:
                    self._rollback(conn)
                    if isinstance(failure, sqlite3.Error):
                        raise PersistenceError(f"commit failed: {failure}") from failure
                    raise
            else:
                self._rollback(conn)
        finally:
            conn.close()
            self._session = None
            self._trusted_states = None
            self._candidates = None
            self._patches = None
            self._invariants = None
            self._evidence = None
            self._audit = None

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> None:
        with suppress(sqlite3.Error):  # with no open transaction there is nothing to undo
            conn.execute("ROLLBACK")

    def _open[T](self, repository: T | None) -> T:
        if repository is None:
            raise PersistenceError("the unit of work is not open; use it in a with statement")
        return repository

    @property
    def trusted_states(self) -> _TrustedStates:
        return self._open(self._trusted_states)

    @property
    def candidates(self) -> _Candidates:
        return self._open(self._candidates)

    @property
    def patches(self) -> _Patches:
        return self._open(self._patches)

    @property
    def invariants(self) -> _Invariants:
        return self._open(self._invariants)

    @property
    def evidence(self) -> _Evidence:
        return self._open(self._evidence)

    @property
    def audit(self) -> _Audit:
        return self._open(self._audit)


def _as_port(uow: SqliteUnitOfWork) -> UnitOfWork:
    """Type-checked proof that the adapter satisfies the domain's ``UnitOfWork`` port."""
    return uow
