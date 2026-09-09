"""SQLite state backend. M1. Trusted.

Holds the signed tool bindings and the admission counters in one database, for
a reason beyond tidiness: admission must read counters, decide, and write both
the decision and the updated counters in a **single transaction**. Without that,
two concurrent calls both read "two denials" and are both approved when the
third should have been refused — the enforcement property failing exactly under
the load that makes it matter.

Write transactions use BEGIN IMMEDIATE rather than the default deferred begin.
A deferred transaction takes its write lock only at the first write, so two
readers can both pass the same check and then serialise their writes — which is
precisely the race the stateful rules exist to prevent.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Self

__all__ = ["SCHEMA", "Store"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS bindings (
    server          TEXT    NOT NULL,
    tool            TEXT    NOT NULL,
    capability      TEXT    NOT NULL,
    resolver        TEXT    NOT NULL,
    resolver_config TEXT    NOT NULL,          -- JSON object
    schema_sha256   TEXT    NOT NULL,          -- pinned declared input schema
    requires_review INTEGER NOT NULL DEFAULT 1,-- born under review
    credential_ref  TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    issued_by       TEXT    NOT NULL,          -- operator AgentID
    sig             TEXT    NOT NULL,          -- Ed25519 over the canonical row
    PRIMARY KEY (server, tool)
);

-- Compiled subagents. A subagent is a program, not configuration: it is
-- authored as an artifact, compiled by the CLI, and installed here.
--
-- Signed for the same reason bindings are, and it matters more: a role
-- *declares its own capabilities*, so whoever could write an unsigned row
-- would mint a role with any authority it liked. An unsigned row is ignored.
CREATE TABLE IF NOT EXISTS roles (
    name         TEXT PRIMARY KEY,
    description  TEXT    NOT NULL DEFAULT '',
    capabilities TEXT    NOT NULL,          -- JSON array
    resource     TEXT    NOT NULL,
    tree         TEXT    NOT NULL,          -- JSON object
    enabled      INTEGER NOT NULL DEFAULT 1,
    issued_by    TEXT    NOT NULL,          -- operator AgentID
    sig          TEXT    NOT NULL,
    compiled_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    agent_id       TEXT PRIMARY KEY,
    public_key     TEXT    NOT NULL,          -- base64url raw Ed25519
    state          TEXT    NOT NULL DEFAULT 'active',
    denial_count   INTEGER NOT NULL DEFAULT 0,
    cooldown_until INTEGER,
    registered_at  INTEGER NOT NULL
);

-- One row per authenticated request, so the rate window can slide. A tumbling
-- window is cheaper but a burst straddling a boundary passes twice the limit;
-- at this throughput an exact count costs nothing.
CREATE TABLE IF NOT EXISTS pattern_events (
    pattern_key TEXT    NOT NULL,
    ts          INTEGER NOT NULL
);

-- Challenges are single-use. Recording consumption is what makes a captured
-- proof-of-possession signature worthless on replay.
CREATE TABLE IF NOT EXISTS challenges (
    challenge  TEXT PRIMARY KEY,
    issued_at  INTEGER NOT NULL,
    consumed_at INTEGER
);

CREATE TABLE IF NOT EXISTS escalations (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT    NOT NULL,
    capability    TEXT    NOT NULL,
    resource      TEXT    NOT NULL,
    action_sha256 TEXT    NOT NULL,
    reason        TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    state         TEXT    NOT NULL DEFAULT 'pending',
    resolved_at   INTEGER,
    resolved_by   TEXT
);

-- Single-use enforcement for execution tokens. An ET is authority; presenting
-- one twice must fail, and only the issuer can know that.
CREATE TABLE IF NOT EXISTS consumed_execution_tokens (
    et_id       TEXT PRIMARY KEY,
    subject     TEXT    NOT NULL,
    consumed_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pattern_events
    ON pattern_events (pattern_key, ts);

CREATE INDEX IF NOT EXISTS idx_escalations_pending
    ON escalations (state, created_at);
"""


class Store:
    """Owns the database. Admission reads through it; mutation goes via write()."""

    def __init__(self, path: str | Path, *, read_only: bool = False):
        self.path = Path(path)
        self.read_only = read_only
        if not read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.path, isolation_level=None)
            self._conn.execute("PRAGMA journal_mode=WAL")
        else:
            self._conn = sqlite3.connect(
                f"file:{self.path}?mode=ro", uri=True, isolation_level=None
            )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        if not read_only:
            self._conn.executescript(SCHEMA)

    # -- access -----------------------------------------------------------

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self._conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self._conn.execute(sql, params).fetchone()

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """An exclusive write transaction: evaluate and mutate, or neither.

        BEGIN IMMEDIATE takes the write lock at the start, so a concurrent
        caller blocks rather than reading stale counters and deciding on them.
        """
        if self.read_only:
            raise sqlite3.OperationalError("store is open read-only")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
