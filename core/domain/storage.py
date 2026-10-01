"""Interim local SQLite storage (P1a step 13, C-35; replaced behind repository ports in P1b).

Standard-library sqlite3 only (ADR-004). Domain code never touches SQL. Schema version 3 keeps
the four table names; each entity table has its key scalar fields as columns plus
``content_json`` holding the entity's ``to_dict()``. Loading always rebuilds the entity with
``from_dict``, which recomputes every hash, and cross-checks the scalar columns against the
rebuilt entity, so a raw edit of either side is caught (DATA-INT-010).

Immutability is enforced in the database, not only by convention (Doc 05 §22-§23):

- DATA-INT-006: ``trusted_state`` and ``invariant`` rows cannot be UPDATEd or DELETEd.
- Candidate identity columns never change, a candidate's ``state_hash`` is fixed once it leaves
  CREATED/BUILDING, and candidates are never deleted (a rejected candidate "retains all
  records"). ``status`` may change; ``update_candidate`` accepts only a legal successor.

There are no migrations before P1b: a database with another schema version is refused.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from core.domain.enums import CandidateStatus
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.hashing import canonical_json
from core.domain.invariant import Invariant
from core.domain.jsonvalue import iso_utc
from core.domain.lifecycle import check_candidate_transition
from core.domain.state import CandidateState, TrustedState

_SCHEMA_VERSION = "3"
_DOMAIN_TABLES = frozenset({"trusted_state", "candidate_state", "invariant"})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trusted_state (
    state_id                     TEXT PRIMARY KEY,
    lineage_id                   TEXT NOT NULL,
    version                      INTEGER NOT NULL,
    parent_state_id              TEXT REFERENCES trusted_state(state_id),
    state_hash                   TEXT NOT NULL,
    normalization_version        TEXT NOT NULL,
    invariant_registry_version   INTEGER NOT NULL,
    created_at                   TEXT NOT NULL,
    committed_at                 TEXT NOT NULL,
    commit_decision_id           TEXT,
    content_json                 TEXT NOT NULL,
    UNIQUE (lineage_id, version)
);

CREATE TABLE IF NOT EXISTS candidate_state (
    candidate_id            TEXT PRIMARY KEY,
    lineage_id              TEXT NOT NULL,
    parent_state_id         TEXT NOT NULL REFERENCES trusted_state(state_id),
    patch_id                TEXT NOT NULL,
    patch_hash              TEXT NOT NULL,
    candidate_sequence      INTEGER NOT NULL,
    source                  TEXT NOT NULL,
    normalization_version   TEXT NOT NULL,
    status                  TEXT NOT NULL,
    state_hash              TEXT,
    created_at              TEXT NOT NULL,
    content_json            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invariant (
    invariant_id      TEXT NOT NULL,
    version           INTEGER NOT NULL,
    definition_hash   TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    content_json      TEXT NOT NULL,
    PRIMARY KEY (invariant_id, version)
);

CREATE TABLE IF NOT EXISTS schema_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- DATA-INT-006: trusted states are immutable through normal operations.
CREATE TRIGGER IF NOT EXISTS trusted_state_no_update
BEFORE UPDATE ON trusted_state
BEGIN SELECT RAISE(ABORT, 'trusted_state is immutable (DATA-INT-006)'); END;

CREATE TRIGGER IF NOT EXISTS trusted_state_no_delete
BEFORE DELETE ON trusted_state
BEGIN SELECT RAISE(ABORT, 'trusted_state is immutable (DATA-INT-006)'); END;

-- Invariant definitions are immutable; a change is a new version (Doc 06 §4.2).
CREATE TRIGGER IF NOT EXISTS invariant_no_update
BEFORE UPDATE ON invariant
BEGIN SELECT RAISE(ABORT, 'invariant definitions are immutable; add a new version'); END;

CREATE TRIGGER IF NOT EXISTS invariant_no_delete
BEFORE DELETE ON invariant
BEGIN SELECT RAISE(ABORT, 'invariant definitions are immutable; add a new version'); END;

-- Candidate identity is immutable; only status, state_hash (while building) and content_json
-- may change.
CREATE TRIGGER IF NOT EXISTS candidate_content_immutable
BEFORE UPDATE ON candidate_state
WHEN NEW.candidate_id != OLD.candidate_id
  OR NEW.lineage_id != OLD.lineage_id
  OR NEW.parent_state_id != OLD.parent_state_id
  OR NEW.patch_id != OLD.patch_id
  OR NEW.patch_hash != OLD.patch_hash
  OR NEW.candidate_sequence != OLD.candidate_sequence
  OR NEW.source != OLD.source
  OR NEW.normalization_version != OLD.normalization_version
  OR NEW.created_at != OLD.created_at
BEGIN SELECT RAISE(ABORT, 'candidate identity is immutable (Doc 05 section 23)'); END;

-- Doc 05 section 8.1: the candidate state hash is fixed before analysis and stays stable.
CREATE TRIGGER IF NOT EXISTS candidate_state_hash_fixed
BEFORE UPDATE ON candidate_state
WHEN OLD.status NOT IN ('CREATED', 'BUILDING') AND NEW.state_hash IS NOT OLD.state_hash
BEGIN SELECT RAISE(ABORT, 'candidate state_hash is fixed once the candidate is READY'); END;

CREATE TRIGGER IF NOT EXISTS candidate_no_delete
BEFORE DELETE ON candidate_state
BEGIN SELECT RAISE(ABORT, 'candidates are never deleted (rejected candidates retain records)'); END;
"""

_CANDIDATE_COLUMNS = (
    "candidate_id, lineage_id, parent_state_id, patch_id, patch_hash, candidate_sequence, "
    "source, normalization_version, status, state_hash, created_at, content_json"
)
_TRUSTED_COLUMNS = (
    "state_id, lineage_id, version, parent_state_id, state_hash, normalization_version, "
    "invariant_registry_version, created_at, committed_at, commit_decision_id, content_json"
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


def _parse_content(text: str, what: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        raise DomainValidationError(f"{what}: stored content_json is not valid JSON") from None


def _check_columns(what: str, expected: dict[str, Any], row: dict[str, Any]) -> None:
    """The scalar columns must agree with the entity rebuilt from ``content_json``."""
    for column, value in expected.items():
        if row[column] != value:
            raise DomainValidationError(
                f"{what}: stored column {column} disagrees with its content (DATA-INT-010)"
            )


class LocalStorage:
    """Thin, explicit wrapper over a local SQLite database file."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # --- schema -------------------------------------------------------------------------

    def _refuse_other_versions(self, conn: sqlite3.Connection) -> None:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        found: str | None
        if "schema_meta" in tables:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            found = row[0] if row else "unknown"
        elif tables & _DOMAIN_TABLES:
            found = "unknown"
        else:
            return
        if found != _SCHEMA_VERSION:
            raise DomainValidationError(
                f"{self.db_path.name} has schema version {found}, but this code needs "
                f"{_SCHEMA_VERSION} (C-35). There are no migrations before P1b: delete the local "
                "development database and run bootstrap again."
            )

    def initialize_schema(self) -> None:
        """Create tables/triggers if absent and record the schema version. Idempotent. Refuses a
        database that has another schema version."""
        with self._connect() as conn:
            self._refuse_other_versions(conn)
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                (_SCHEMA_VERSION,),
            )

    def schema_version(self) -> str | None:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            row = cur.fetchone()
            return str(row[0]) if row else None

    # --- TrustedState -------------------------------------------------------------------

    def save_trusted_state(self, state: TrustedState) -> None:
        if not isinstance(state, TrustedState):
            raise DomainValidationError("save_trusted_state: expected a TrustedState")
        with self._connect() as conn:
            conn.execute(
                f"INSERT INTO trusted_state ({_TRUSTED_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    state.state_id,
                    state.lineage_id,
                    state.version,
                    state.parent_state_id,
                    state.state_hash,
                    state.normalization_version,
                    state.invariant_registry_version,
                    iso_utc(state.created_at),
                    iso_utc(state.committed_at),
                    state.commit_decision_id,
                    canonical_json(state.to_dict()),
                ),
            )

    def load_trusted_state(self, state_id: str) -> TrustedState | None:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                f"SELECT {_TRUSTED_COLUMNS} FROM trusted_state WHERE state_id = ?", (state_id,)
            )
            values = cur.fetchone()
        if values is None:
            return None
        names = [name.strip() for name in _TRUSTED_COLUMNS.split(",")]
        row = dict(zip(names, values, strict=True))
        state = TrustedState.from_dict(_parse_content(row["content_json"], "trusted_state"))
        _check_columns(
            f"trusted state {state_id}",
            {
                "state_id": state.state_id,
                "lineage_id": state.lineage_id,
                "version": state.version,
                "parent_state_id": state.parent_state_id,
                "state_hash": state.state_hash,
                "normalization_version": state.normalization_version,
                "invariant_registry_version": state.invariant_registry_version,
                "created_at": iso_utc(state.created_at),
                "committed_at": iso_utc(state.committed_at),
                "commit_decision_id": state.commit_decision_id,
            },
            row,
        )
        return state

    def count_trusted_states(self) -> int:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT COUNT(*) FROM trusted_state")
            return int(cur.fetchone()[0])

    def trusted_state_lineage(self, state_id: str) -> list[TrustedState]:
        """The state followed by its ancestors, newest first, ending at version 0.

        Raises ``DomainValidationError`` on a missing state or a cycle: a broken lineage must be
        loud, never silently truncated (evidence/lineage integrity).
        """
        chain: list[TrustedState] = []
        current: str | None = state_id
        seen: set[str] = set()
        while current is not None:
            if current in seen:
                raise DomainValidationError(
                    f"cycle detected in trusted-state lineage at {current!r}"
                )
            seen.add(current)
            state = self.load_trusted_state(current)
            if state is None:
                raise DomainValidationError(f"trusted state {current!r} not found (broken lineage)")
            chain.append(state)
            current = state.parent_state_id
        return chain

    # --- CandidateState -----------------------------------------------------------------

    def save_candidate(self, candidate: CandidateState) -> None:
        if not isinstance(candidate, CandidateState):
            raise DomainValidationError("save_candidate: expected a CandidateState")
        with self._connect() as conn:
            conn.execute(
                f"INSERT INTO candidate_state ({_CANDIDATE_COLUMNS}) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                self._candidate_values(candidate),
            )

    @staticmethod
    def _candidate_values(candidate: CandidateState) -> tuple[Any, ...]:
        return (
            candidate.candidate_id,
            candidate.lineage_id,
            candidate.parent_state_id,
            candidate.patch_id,
            candidate.patch_hash,
            candidate.candidate_sequence,
            candidate.source.value,
            candidate.normalization_version,
            candidate.status.value,
            candidate.state_hash,
            iso_utc(candidate.created_at),
            canonical_json(candidate.to_dict()),
        )

    def _load_candidate_row(self, candidate_id: str) -> CandidateState | None:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                f"SELECT {_CANDIDATE_COLUMNS} FROM candidate_state WHERE candidate_id = ?",
                (candidate_id,),
            )
            values = cur.fetchone()
        if values is None:
            return None
        names = [name.strip() for name in _CANDIDATE_COLUMNS.split(",")]
        row = dict(zip(names, values, strict=True))
        candidate = CandidateState.from_dict(_parse_content(row["content_json"], "candidate_state"))
        if row["state_hash"] != candidate.state_hash and candidate.state_hash is not None:
            raise HashMismatchError(
                f"DATA-INT-010: candidate {candidate_id} stored state_hash disagrees with "
                "its content"
            )
        _check_columns(
            f"candidate {candidate_id}",
            {
                "candidate_id": candidate.candidate_id,
                "lineage_id": candidate.lineage_id,
                "parent_state_id": candidate.parent_state_id,
                "patch_id": candidate.patch_id,
                "patch_hash": candidate.patch_hash,
                "candidate_sequence": candidate.candidate_sequence,
                "source": candidate.source.value,
                "normalization_version": candidate.normalization_version,
                "status": candidate.status.value,
                "state_hash": candidate.state_hash,
                "created_at": iso_utc(candidate.created_at),
            },
            row,
        )
        return candidate

    def load_candidate(self, candidate_id: str) -> CandidateState | None:
        return self._load_candidate_row(candidate_id)

    def update_candidate(self, new: CandidateState) -> None:
        """Store ``new`` as the next state of an existing candidate.

        Accepts only a legal successor of the stored candidate (Doc 06 §30: persistence
        convenience methods must not bypass lifecycle validation): the same identity fields, a
        status pair allowed by Doc 06 §5, and resources/state_hash unchanged except on
        BUILDING -> READY.
        """
        if not isinstance(new, CandidateState):
            raise DomainValidationError("update_candidate: expected a CandidateState")
        old = self._load_candidate_row(new.candidate_id)
        if old is None:
            raise DomainValidationError(
                f"update_candidate: candidate {new.candidate_id!r} not found"
            )
        for field in _CANDIDATE_IDENTITY:
            if getattr(new, field) != getattr(old, field):
                raise DomainValidationError(f"update_candidate: {field} cannot change (Doc 05 §23)")
        check_candidate_transition(old.status, new.status)
        building_to_ready = (
            old.status is CandidateStatus.BUILDING and new.status is CandidateStatus.READY
        )
        if not building_to_ready and (
            new.resources != old.resources or new.state_hash != old.state_hash
        ):
            raise DomainValidationError(
                "update_candidate: resources and state_hash change only on BUILDING -> READY "
                "(Doc 05 §8.1)"
            )
        with self._connect() as conn:
            conn.execute(
                "UPDATE candidate_state SET status = ?, state_hash = ?, content_json = ? "
                "WHERE candidate_id = ?",
                (
                    new.status.value,
                    new.state_hash,
                    canonical_json(new.to_dict()),
                    new.candidate_id,
                ),
            )

    # --- Invariant definitions ----------------------------------------------------------

    def save_invariant_definition(self, definition: Invariant) -> None:
        if not isinstance(definition, Invariant):
            raise DomainValidationError("save_invariant_definition: expected an Invariant")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO invariant (invariant_id, version, definition_hash, created_at, "
                "content_json) VALUES (?,?,?,?,?)",
                (
                    definition.invariant_id,
                    definition.version,
                    definition.definition_hash(),
                    iso_utc(definition.created_at),
                    canonical_json(definition.to_dict()),
                ),
            )

    def load_invariant_definition(self, invariant_id: str, version: int) -> Invariant | None:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                "SELECT definition_hash, content_json FROM invariant "
                "WHERE invariant_id = ? AND version = ?",
                (invariant_id, version),
            )
            row = cur.fetchone()
        if row is None:
            return None
        definition = Invariant.from_dict(_parse_content(row[1], "invariant"))
        if (definition.invariant_id, definition.version) != (invariant_id, version):
            raise DomainValidationError(
                f"invariant {invariant_id} v{version}: stored key disagrees with its content"
            )
        if definition.definition_hash() != row[0]:
            raise HashMismatchError(
                f"DATA-INT-010: invariant {invariant_id} v{version} stored definition_hash "
                "does not match its content"
            )
        return definition
