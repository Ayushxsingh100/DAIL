"""Local SQLite storage (P0 "local database/storage setup", completed in P1).

Standard-library sqlite3 only (ADR-004). This is the "SQLite behind an
abstraction" from Doc 02 Section 16; domain code never touches SQL.

Immutability is enforced *in the database*, not just by convention
(Doc 05 Section 22-23):
  DATA-INT-006  TrustedState rows cannot be UPDATEd or DELETEd.
  Section 23    Candidate parent/patch content is immutable once created;
                only `status` may change. Candidates are never deleted
                (a rejected candidate "retains all records").
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import datetime
from pathlib import Path

from core.domain.enums import InvariantLifecycleState, InvariantType
from core.domain.invariant import Invariant
from core.domain.state import CandidateState, CandidateStatus, TrustedState

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trusted_state (
    state_id                     TEXT PRIMARY KEY,
    version                      INTEGER NOT NULL,
    content_hash                 TEXT NOT NULL,
    invariant_registry_version   INTEGER NOT NULL,
    parent_state_id              TEXT REFERENCES trusted_state(state_id),
    created_at                   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidate_state (
    candidate_id      TEXT PRIMARY KEY,
    parent_state_id   TEXT NOT NULL REFERENCES trusted_state(state_id),
    patch_hash        TEXT NOT NULL,
    status            TEXT NOT NULL,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invariant (
    invariant_id                  TEXT NOT NULL,
    version                       INTEGER NOT NULL,
    description                   TEXT NOT NULL,
    invariant_type                TEXT NOT NULL,
    predicate_id                  TEXT NOT NULL,
    scope_id                      TEXT NOT NULL,
    applicability_rule            TEXT NOT NULL,
    verification_policy_id        TEXT NOT NULL,
    verifier_version              TEXT NOT NULL,
    lifecycle_state               TEXT NOT NULL,
    verified_state_id             TEXT REFERENCES trusted_state(state_id),
    dependency_snapshot_hash      TEXT,
    evidence_reference            TEXT,
    provenance                    TEXT NOT NULL,
    created_at                    TEXT NOT NULL,
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

-- Candidate content is immutable; only status may change.
CREATE TRIGGER IF NOT EXISTS candidate_content_immutable
BEFORE UPDATE ON candidate_state
WHEN NEW.candidate_id != OLD.candidate_id
  OR NEW.parent_state_id != OLD.parent_state_id
  OR NEW.patch_hash != OLD.patch_hash
  OR NEW.created_at != OLD.created_at
BEGIN SELECT RAISE(ABORT, 'candidate content is immutable; only status may change'); END;

CREATE TRIGGER IF NOT EXISTS candidate_no_delete
BEFORE DELETE ON candidate_state
BEGIN SELECT RAISE(ABORT, 'candidates are never deleted (rejected candidates retain records)'); END;
"""

_SCHEMA_VERSION = "2"


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

    def initialize_schema(self) -> None:
        """Create tables/triggers if absent and record the schema version. Idempotent."""
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                (_SCHEMA_VERSION,),
            )

    def schema_version(self) -> str | None:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            row = cur.fetchone()
            return row[0] if row else None

    # --- TrustedState -----------------------------------------------------

    def save_trusted_state(self, state: TrustedState) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO trusted_state (state_id, version, content_hash, "
                "invariant_registry_version, parent_state_id, created_at) VALUES (?,?,?,?,?,?)",
                (
                    state.state_id,
                    state.version,
                    state.content_hash,
                    state.invariant_registry_version,
                    state.parent_state_id,
                    state.created_at.isoformat(),
                ),
            )

    def load_trusted_state(self, state_id: str) -> TrustedState | None:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                "SELECT state_id, version, content_hash, invariant_registry_version, "
                "parent_state_id, created_at FROM trusted_state WHERE state_id = ?",
                (state_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return TrustedState(
            state_id=row[0],
            version=row[1],
            content_hash=row[2],
            invariant_registry_version=row[3],
            parent_state_id=row[4],
            created_at=datetime.fromisoformat(row[5]),
        )

    def count_trusted_states(self) -> int:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT COUNT(*) FROM trusted_state")
            return int(cur.fetchone()[0])

    def trusted_state_lineage(self, state_id: str) -> list[TrustedState]:
        """The state followed by its ancestors, newest first, ending at genesis.

        Raises LookupError on a dangling parent pointer: a broken lineage
        must be loud, never silently truncated (evidence/lineage integrity).
        """
        chain: list[TrustedState] = []
        current: str | None = state_id
        seen: set[str] = set()
        while current is not None:
            if current in seen:
                raise LookupError(f"cycle detected in trusted-state lineage at {current!r}")
            seen.add(current)
            state = self.load_trusted_state(current)
            if state is None:
                raise LookupError(f"trusted state {current!r} not found (broken lineage)")
            chain.append(state)
            current = state.parent_state_id
        return chain

    # --- CandidateState ---------------------------------------------------

    def save_candidate(self, candidate: CandidateState) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO candidate_state (candidate_id, parent_state_id, patch_hash, "
                "status, created_at) VALUES (?,?,?,?,?)",
                (
                    candidate.candidate_id,
                    candidate.parent_state_id,
                    candidate.patch_hash,
                    candidate.status.value,
                    candidate.created_at.isoformat(),
                ),
            )

    def update_candidate_status(self, candidate: CandidateState) -> None:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE candidate_state SET status = ? WHERE candidate_id = ?",
                (candidate.status.value, candidate.candidate_id),
            )
            if cur.rowcount != 1:
                raise LookupError(f"candidate {candidate.candidate_id!r} not found")

    def load_candidate(self, candidate_id: str) -> CandidateState | None:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                "SELECT candidate_id, parent_state_id, patch_hash, status, created_at "
                "FROM candidate_state WHERE candidate_id = ?",
                (candidate_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return CandidateState(
            candidate_id=row[0],
            parent_state_id=row[1],
            patch_hash=row[2],
            status=CandidateStatus(row[3]),
            created_at=datetime.fromisoformat(row[4]),
        )

    # --- Invariant --------------------------------------------------------

    def save_invariant(self, inv: Invariant) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO invariant VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    inv.invariant_id,
                    inv.version,
                    inv.description,
                    inv.invariant_type.value,
                    inv.predicate_id,
                    inv.scope_id,
                    inv.applicability_rule,
                    inv.verification_policy_id,
                    inv.verifier_version,
                    inv.lifecycle_state.value,
                    inv.verified_state_id,
                    inv.dependency_snapshot_hash,
                    inv.evidence_reference,
                    inv.provenance,
                    inv.created_at.isoformat(),
                ),
            )

    def update_invariant_lifecycle(self, inv: Invariant) -> None:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE invariant SET lifecycle_state=?, verified_state_id=?, "
                "dependency_snapshot_hash=?, evidence_reference=? "
                "WHERE invariant_id=? AND version=?",
                (
                    inv.lifecycle_state.value,
                    inv.verified_state_id,
                    inv.dependency_snapshot_hash,
                    inv.evidence_reference,
                    inv.invariant_id,
                    inv.version,
                ),
            )
            if cur.rowcount != 1:
                raise LookupError(f"invariant {inv.invariant_id!r} v{inv.version} not found")

    def load_invariant(self, invariant_id: str, version: int) -> Invariant | None:
        with self._connect() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                "SELECT invariant_id, version, description, invariant_type, predicate_id, "
                "scope_id, applicability_rule, verification_policy_id, verifier_version, "
                "lifecycle_state, verified_state_id, dependency_snapshot_hash, "
                "evidence_reference, provenance, created_at FROM invariant "
                "WHERE invariant_id=? AND version=?",
                (invariant_id, version),
            )
            r = cur.fetchone()
        if r is None:
            return None
        return Invariant(
            invariant_id=r[0],
            version=r[1],
            description=r[2],
            invariant_type=InvariantType(r[3]),
            predicate_id=r[4],
            scope_id=r[5],
            applicability_rule=r[6],
            verification_policy_id=r[7],
            verifier_version=r[8],
            lifecycle_state=InvariantLifecycleState(r[9]),
            verified_state_id=r[10],
            dependency_snapshot_hash=r[11],
            evidence_reference=r[12],
            provenance=r[13],
            created_at=datetime.fromisoformat(r[14]),
        )
