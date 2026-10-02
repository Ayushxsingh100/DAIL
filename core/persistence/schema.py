"""SQLite schema version 4: tables, constraints and triggers (Doc 05 §20-§23, §32, §36;
Doc 06 §5, §6, §20, §22, §30; C-42, C-44, C-46, C-47; P1b step 4).

The database is the second line of defense. P1a enforces the SM rules in the domain; here the
database refuses the same illegal moves when application code is wrong (Doc 05 §36: "Promotion
transaction constraints prevent partial trusted-state advancement"). Standard library and
``core.domain`` only (rule R12).

Tables hold the entity's indexed scalar fields plus ``content_json`` (the entity's ``to_dict()``).
Two deliberate shapes follow from the triggers:

- A candidate's ``content_json`` is its ``to_dict()`` *without* ``status`` and ``status_reason``.
  Those two lifecycle fields live in their own columns, because trigger 5 lets ``content_json``
  change only while the candidate is CREATED or BUILDING (Doc 05 §23: candidate semantic content
  is immutable after construction), yet the status keeps moving after READY.
- ``resources`` holds one record per resource, shared by the candidate and the state promoted from
  it, so ownership is a link (``candidate_resources``, ``state_resources``; C-42).

Every trigger names its rule in the message, e.g. ``DATA-INT-006: trusted_states is immutable``.
Each trigger is a ``SELECT RAISE(ABORT, ...) WHERE <violation>`` so that a NULL cannot silently
switch it off: the conditions use ``IS``/``IS NOT`` and ``EXISTS``.

Beyond the Step 4 list, every immutable table also has a ``*_no_replace`` trigger. ``INSERT OR
REPLACE`` deletes the old row without firing a DELETE trigger unless the connection sets
``recursive_triggers``, and that is a per-connection setting, not a property of the file. The
BEFORE INSERT guard fires before conflict resolution, so history cannot be rewritten that way
(DATA-INT-006). The adapter never uses ``INSERT OR REPLACE`` or ``INSERT OR IGNORE`` (13.3).

Triggers cannot see transaction identity (R2). Trigger 13.1 for ``candidate_resources`` ("no
attachment from an earlier transaction") is therefore enforced as: the candidate is READY, and the
link matches a resource that the READY row's ``content_json`` declares (address and record_id),
and the primary key stops a second link for that address. The adapter writes the READY row and
all its links in one transaction, and every read cross-checks the links against ``content_json``
(13.2).

There is no migration tooling before P8a (C-44): a database with any other schema version is
refused with instructions to delete the local development database.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from core.domain.enums import CandidateStatus, ProofOrigin
from core.domain.errors import PersistenceError
from core.domain.lifecycle import CANDIDATE_TRANSITIONS, TRUSTED_REF_STATUSES

SCHEMA_VERSION = "4"

# Tables (and the schema-3 names) that mark a database as belonging to this application.
DOMAIN_TABLES = (
    "patches",
    "trusted_states",
    "lineage_heads",
    "candidates",
    "resources",
    "state_resources",
    "candidate_resources",
    "invariants",
    "invariant_refs",
)
LEGACY_TABLES = ("trusted_state", "candidate_state", "invariant")
TABLE_NAMES = frozenset((*DOMAIN_TABLES, "schema_meta"))

# DATA-INT-006 and Doc 05 §23: no UPDATE and no DELETE on these.
IMMUTABLE_TABLES = (
    "trusted_states",
    "patches",
    "resources",
    "state_resources",
    "candidate_resources",
    "invariants",
    "invariant_refs",
)

# The key (or keys) whose reuse INSERT OR REPLACE would turn into a silent overwrite.
_NO_REPLACE_KEYS = {
    "trusted_states": (
        "state_id = NEW.state_id OR (lineage_id = NEW.lineage_id AND version = NEW.version)"
    ),
    "patches": "patch_id = NEW.patch_id",
    "resources": "record_id = NEW.record_id",
    "state_resources": "state_id = NEW.state_id AND address = NEW.address",
    "candidate_resources": "candidate_id = NEW.candidate_id AND address = NEW.address",
    "invariants": "invariant_id = NEW.invariant_id AND version = NEW.version",
    "invariant_refs": (
        "(state_id = NEW.state_id AND invariant_id = NEW.invariant_id "
        "AND invariant_version = NEW.invariant_version) "
        "OR (state_id = NEW.state_id AND invariant_id = NEW.invariant_id)"
    ),
    "candidates": (
        "candidate_id = NEW.candidate_id "
        "OR (lineage_id = NEW.lineage_id AND candidate_sequence = NEW.candidate_sequence)"
    ),
    "lineage_heads": "lineage_id = NEW.lineage_id",
}


def _quoted(values: list[str]) -> str:
    return ", ".join(f"'{value}'" for value in values)


_CANDIDATE_STATUSES = _quoted([status.value for status in CandidateStatus])
_REF_STATUSES = _quoted(sorted(status.value for status in TRUSTED_REF_STATUSES))
_REF_ORIGINS = _quoted([origin.value for origin in ProofOrigin])


def candidate_status_pairs() -> tuple[tuple[str, str], ...]:
    """Every legal (old status, new status) pair, generated from the domain's lifecycle table
    ``CANDIDATE_TRANSITIONS`` so the database and the domain cannot drift (Step 4, trigger 5)."""
    return tuple(
        sorted(
            (current.value, target.value)
            for current, targets in CANDIDATE_TRANSITIONS.items()
            for target in targets
        )
    )


def _pair_condition() -> str:
    return " OR ".join(
        f"(OLD.status = '{old}' AND NEW.status = '{new}')" for old, new in candidate_status_pairs()
    )


def _trigger(name: str, timing_event: str, table: str, message: str, violation: str) -> str:
    safe_message = message.replace("'", "''")
    return (
        f"CREATE TRIGGER IF NOT EXISTS {name} {timing_event} ON {table}\n"
        f"BEGIN\n"
        f"  SELECT RAISE(ABORT, '{safe_message}') WHERE {violation};\n"
        f"END"
    )


_TABLES = (
    """CREATE TABLE IF NOT EXISTS schema_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS trusted_states (
    state_id            TEXT PRIMARY KEY,
    lineage_id          TEXT NOT NULL,
    version             INTEGER NOT NULL CHECK (version >= 0),
    parent_state_id     TEXT REFERENCES trusted_states(state_id),
    state_hash          TEXT NOT NULL,
    commit_decision_id  TEXT,
    content_json        TEXT NOT NULL,
    UNIQUE (lineage_id, version)
)""",
    """CREATE TABLE IF NOT EXISTS lineage_heads (
    lineage_id        TEXT PRIMARY KEY,
    current_state_id  TEXT NOT NULL REFERENCES trusted_states(state_id)
)""",
    """CREATE TABLE IF NOT EXISTS patches (
    patch_id         TEXT PRIMARY KEY,
    parent_state_id  TEXT NOT NULL REFERENCES trusted_states(state_id),
    content_hash     TEXT NOT NULL,
    content_json     TEXT NOT NULL
)""",
    f"""CREATE TABLE IF NOT EXISTS candidates (
    candidate_id        TEXT PRIMARY KEY,
    parent_state_id     TEXT NOT NULL REFERENCES trusted_states(state_id),
    patch_id            TEXT NOT NULL REFERENCES patches(patch_id),
    lineage_id          TEXT NOT NULL,
    candidate_sequence  INTEGER NOT NULL CHECK (candidate_sequence >= 1),
    status              TEXT NOT NULL CHECK (status IN ({_CANDIDATE_STATUSES})),
    status_reason       TEXT,
    patch_hash          TEXT NOT NULL,
    state_hash          TEXT,
    content_json        TEXT NOT NULL,
    UNIQUE (lineage_id, candidate_sequence)
)""",
    """CREATE TABLE IF NOT EXISTS resources (
    record_id      TEXT PRIMARY KEY,
    fingerprint    TEXT NOT NULL,
    address        TEXT NOT NULL,
    resource_type  TEXT NOT NULL,
    content_json   TEXT NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS state_resources (
    state_id   TEXT NOT NULL REFERENCES trusted_states(state_id),
    address    TEXT NOT NULL,
    record_id  TEXT NOT NULL REFERENCES resources(record_id),
    PRIMARY KEY (state_id, address)
)""",
    """CREATE TABLE IF NOT EXISTS candidate_resources (
    candidate_id  TEXT NOT NULL REFERENCES candidates(candidate_id),
    address       TEXT NOT NULL,
    record_id     TEXT NOT NULL REFERENCES resources(record_id),
    PRIMARY KEY (candidate_id, address)
)""",
    """CREATE TABLE IF NOT EXISTS invariants (
    invariant_id     TEXT NOT NULL,
    version          INTEGER NOT NULL CHECK (version >= 1),
    definition_hash  TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    content_json     TEXT NOT NULL,
    PRIMARY KEY (invariant_id, version)
)""",
    f"""CREATE TABLE IF NOT EXISTS invariant_refs (
    state_id                     TEXT NOT NULL REFERENCES trusted_states(state_id),
    invariant_id                 TEXT NOT NULL,
    invariant_version            INTEGER NOT NULL,
    status                       TEXT NOT NULL CHECK (status IN ({_REF_STATUSES})),
    origin                       TEXT NOT NULL CHECK (origin IN ({_REF_ORIGINS})),
    evidence_ids                 TEXT NOT NULL,
    last_verified_at             TEXT NOT NULL,
    invalidated_by_candidate_id  TEXT,
    invalidation_reason          TEXT,
    PRIMARY KEY (state_id, invariant_id, invariant_version),
    FOREIGN KEY (invariant_id, invariant_version) REFERENCES invariants(invariant_id, version),
    UNIQUE (state_id, invariant_id)
)""",
)


def _triggers() -> tuple[str, ...]:
    triggers: list[str] = []

    # 1. No UPDATE or DELETE on immutable tables; no DELETE on candidates or lineage_heads.
    for table in IMMUTABLE_TABLES:
        for event in ("UPDATE", "DELETE"):
            triggers.append(
                _trigger(
                    f"{table}_no_{event.lower()}",
                    f"BEFORE {event}",
                    table,
                    f"DATA-INT-006: {table} is immutable (Doc 05 §23)",
                    "1",
                )
            )
    for table in ("candidates", "lineage_heads"):
        triggers.append(
            _trigger(
                f"{table}_no_delete",
                "BEFORE DELETE",
                table,
                f"DATA-INT-006: {table} rows are never deleted (Doc 05 §33)",
                "1",
            )
        )
    # INSERT OR REPLACE would delete a row without a DELETE trigger (see the module docstring).
    for table, key in _NO_REPLACE_KEYS.items():
        triggers.append(
            _trigger(
                f"{table}_no_replace",
                "BEFORE INSERT",
                table,
                f"DATA-INT-006: {table} row already exists; REPLACE would rewrite history",
                f"EXISTS (SELECT 1 FROM {table} WHERE {key})",
            )
        )

    # 2. trusted_states: version 0 is a parentless baseline; later versions follow their parent.
    triggers.append(
        _trigger(
            "trusted_states_insert_rules",
            "BEFORE INSERT",
            "trusted_states",
            "SM-001: a trusted state is a baseline (version 0, no parent, no decision) or the "
            "child of version - 1 in the same lineage with a commit decision",
            "NOT ("
            "(NEW.version = 0 AND NEW.parent_state_id IS NULL AND NEW.commit_decision_id IS NULL)"
            " OR (NEW.version > 0 AND NEW.commit_decision_id IS NOT NULL AND EXISTS ("
            "SELECT 1 FROM trusted_states p WHERE p.state_id = NEW.parent_state_id "
            "AND p.lineage_id = NEW.lineage_id AND p.version = NEW.version - 1)))",
        )
    )

    # 3. lineage_heads: the current pointer starts at version 0 and advances only to a child.
    triggers.append(
        _trigger(
            "lineage_heads_insert_rules",
            "BEFORE INSERT",
            "lineage_heads",
            "SM-001: a lineage starts at a version 0 state of that lineage",
            "NOT EXISTS (SELECT 1 FROM trusted_states s WHERE s.state_id = NEW.current_state_id "
            "AND s.version = 0 AND s.lineage_id = NEW.lineage_id)",
        )
    )
    triggers.append(
        _trigger(
            "lineage_heads_update_rules",
            "BEFORE UPDATE",
            "lineage_heads",
            "SM-010: the current pointer advances only to a child of the current state, "
            "in the same lineage",
            "NEW.lineage_id IS NOT OLD.lineage_id OR NOT EXISTS (SELECT 1 FROM trusted_states s "
            "WHERE s.state_id = NEW.current_state_id AND s.parent_state_id = OLD.current_state_id "
            "AND s.lineage_id = OLD.lineage_id)",
        )
    )

    # 4. candidates BEFORE INSERT.
    triggers.append(
        _trigger(
            "candidates_insert_status",
            "BEFORE INSERT",
            "candidates",
            "Doc 06 §5: a candidate starts CREATED",
            "NEW.status IS NOT 'CREATED'",
        )
    )
    triggers.append(
        _trigger(
            "candidates_insert_patch",
            "BEFORE INSERT",
            "candidates",
            "DATA-INT-001: the patch must be written against the candidate's parent and its "
            "content_hash must equal patch_hash",
            "NOT EXISTS (SELECT 1 FROM patches p WHERE p.patch_id = NEW.patch_id "
            "AND p.parent_state_id = NEW.parent_state_id AND p.content_hash = NEW.patch_hash)",
        )
    )
    triggers.append(
        _trigger(
            "candidates_insert_lineage",
            "BEFORE INSERT",
            "candidates",
            "DATA-INT-001/002: the parent must be a trusted state, and lineage_id must equal "
            "the parent's lineage",
            "NOT EXISTS (SELECT 1 FROM trusted_states s WHERE s.state_id = NEW.parent_state_id "
            "AND s.lineage_id = NEW.lineage_id)",
        )
    )

    # 5. candidates BEFORE UPDATE.
    triggers.append(
        _trigger(
            "candidates_update_status_pairs",
            "BEFORE UPDATE",
            "candidates",
            "Doc 06 §5, SM-002: illegal candidate status transition",
            f"NOT ({_pair_condition()})",
        )
    )
    triggers.append(
        _trigger(
            "candidates_update_identity",
            "BEFORE UPDATE",
            "candidates",
            "Doc 05 §23: candidate identity is immutable",
            "NEW.candidate_id IS NOT OLD.candidate_id "
            "OR NEW.parent_state_id IS NOT OLD.parent_state_id "
            "OR NEW.patch_id IS NOT OLD.patch_id "
            "OR NEW.patch_hash IS NOT OLD.patch_hash "
            "OR NEW.lineage_id IS NOT OLD.lineage_id "
            "OR NEW.candidate_sequence IS NOT OLD.candidate_sequence",
        )
    )
    triggers.append(
        _trigger(
            "candidates_update_content",
            "BEFORE UPDATE",
            "candidates",
            "Doc 05 §8.1, §23: state_hash and content_json are fixed once the candidate is READY",
            "OLD.status NOT IN ('CREATED', 'BUILDING') AND "
            "(NEW.state_hash IS NOT OLD.state_hash OR NEW.content_json IS NOT OLD.content_json)",
        )
    )
    # 13.4: PROMOTED needs a committed promotion, in the same transaction. A stale candidate with
    # the same parent would also satisfy the first condition after a sibling was promoted, so a
    # second PROMOTED candidate for one parent is refused as well (SM-010).
    triggers.append(
        _trigger(
            "candidates_update_promoted",
            "BEFORE UPDATE",
            "candidates",
            "DATA-INT-005, SM-002, SM-010: PROMOTED needs a promotion that moved the lineage's "
            "current pointer to a child of the candidate's parent, and a parent has only one "
            "promoted candidate",
            "NEW.status = 'PROMOTED' AND (NOT EXISTS (SELECT 1 FROM lineage_heads h "
            "JOIN trusted_states s ON s.state_id = h.current_state_id "
            "WHERE h.lineage_id = NEW.lineage_id AND s.parent_state_id = NEW.parent_state_id) "
            "OR EXISTS (SELECT 1 FROM candidates o WHERE o.parent_state_id = NEW.parent_state_id "
            "AND o.status = 'PROMOTED' AND o.candidate_id != NEW.candidate_id))",
        )
    )

    # 6. candidate_resources (and 13.1).
    triggers.append(
        _trigger(
            "candidate_resources_insert_ready",
            "BEFORE INSERT",
            "candidate_resources",
            "Doc 06 §5: resources attach to a READY candidate only",
            "NOT EXISTS (SELECT 1 FROM candidates c WHERE c.candidate_id = NEW.candidate_id "
            "AND c.status = 'READY')",
        )
    )
    triggers.append(
        _trigger(
            "candidate_resources_insert_declared",
            "BEFORE INSERT",
            "candidate_resources",
            "Doc 05 §23: a link must match a resource declared by the READY candidate's content",
            "NOT EXISTS (SELECT 1 FROM candidates c, json_each(c.content_json, '$.resources') j "
            "WHERE c.candidate_id = NEW.candidate_id "
            "AND json_extract(j.value, '$.address') = NEW.address "
            "AND json_extract(j.value, '$.record_id') = NEW.record_id)",
        )
    )

    # 7. invariants: versions 1, 2, 3, ... with no gaps.
    triggers.append(
        _trigger(
            "invariants_insert_version",
            "BEFORE INSERT",
            "invariants",
            "Doc 06 §4.2: versions start at 1 and have no gaps",
            "NEW.version != 1 AND NOT EXISTS (SELECT 1 FROM invariants i "
            "WHERE i.invariant_id = NEW.invariant_id AND i.version = NEW.version - 1)",
        )
    )

    # 13.1: nothing attaches to committed history.
    for table in ("invariant_refs", "state_resources"):
        triggers.append(
            _trigger(
                f"{table}_insert_attach",
                "BEFORE INSERT",
                table,
                f"DATA-INT-006, SM-009: {table} cannot be added to a committed trusted state",
                "EXISTS (SELECT 1 FROM lineage_heads h WHERE h.current_state_id = NEW.state_id) "
                "OR EXISTS (SELECT 1 FROM trusted_states s WHERE s.parent_state_id = NEW.state_id)",
            )
        )
    return tuple(triggers)


DDL: tuple[str, ...] = (*_TABLES, *_triggers())


def open_connection(path: str | Path, *, timeout: float = 5.0) -> sqlite3.Connection:
    """A connection with foreign keys on, in autocommit mode (``isolation_level=None``) so the
    caller owns every ``BEGIN``/``COMMIT``. ``timeout`` is the busy timeout in seconds."""
    conn = sqlite3.connect(path, timeout=timeout, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA recursive_triggers = ON")
    return conn


def _refuse_other_versions(conn: sqlite3.Connection, path: Path) -> None:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    found: str | None
    if "schema_meta" in tables:
        row = conn.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
        found = str(row[0]) if row else "unknown"
    elif tables & {*DOMAIN_TABLES, *LEGACY_TABLES}:
        found = "unknown"
    else:
        return
    if found != SCHEMA_VERSION:
        raise PersistenceError(
            f"{path.name} has schema version {found}, but this code needs {SCHEMA_VERSION} "
            "(C-44). There are no migrations before P8a: delete the local development database "
            "(.local/dail.db) and run bootstrap again."
        )


def initialize_database(path: str | Path) -> None:
    """Create the schema-4 tables and triggers and record the version. Idempotent; creates the
    parent directory. Refuses a database whose schema version is not 4 and changes nothing then."""
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with closing(open_connection(db_path)) as conn:
            if conn.execute("SELECT json_valid('[]')").fetchone()[0] != 1:
                raise PersistenceError("this SQLite build has no JSON1; schema 4 needs it")
            conn.execute("BEGIN IMMEDIATE")
            try:
                _refuse_other_versions(conn, db_path)
                for statement in DDL:
                    conn.execute(statement)
                row = conn.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                        (SCHEMA_VERSION,),
                    )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
    except sqlite3.Error as exc:
        raise PersistenceError(f"cannot initialize {db_path.name}: {exc}") from exc


def schema_version(path: str | Path) -> str | None:
    """The recorded schema version, or ``None`` if the file has none."""
    try:
        with closing(open_connection(path)) as conn:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
    except sqlite3.Error:
        return None
    return str(row[0]) if row else None
