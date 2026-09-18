"""SQLite connection management and schema.

Concurrency model
-----------------
Each request gets its own connection (``get_db`` dependency). Write
transactions are opened with ``BEGIN IMMEDIATE`` so that a writer acquires
the database lock up-front; overlapping allocations therefore serialize at
the database level and can never hand out overlapping CIDRs.
"""

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

DEFAULT_DB_PATH = "/data/cidr.db"
SCHEMA = """
-- Address intervals are stored as TEXT: unsigned decimal integers large
-- enough to hold a 128-bit IPv6 address (SQLite INTEGER tops out at 64 bits).
CREATE TABLE IF NOT EXISTS pools (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    cidr        TEXT NOT NULL,
    version     INTEGER NOT NULL,
    start_addr  TEXT NOT NULL,
    end_addr    TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reservations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pool_id     INTEGER NOT NULL REFERENCES pools(id),
    cidr        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    start_addr  TEXT NOT NULL,
    end_addr    TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS leases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pool_id     INTEGER NOT NULL REFERENCES pools(id),
    cidr        TEXT NOT NULL,
    token       TEXT NOT NULL UNIQUE,
    start_addr  TEXT NOT NULL,
    end_addr    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',  -- active | released | expired
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    renewed_at  INTEGER NOT NULL
);

-- Hash-chained audit log: one row per successful lease lifecycle event,
-- appended inside the same BEGIN IMMEDIATE transaction as the change.
CREATE TABLE IF NOT EXISTS audit_events (
    seq         INTEGER PRIMARY KEY,  -- 1, 2, 3, ... assigned under the write lock
    action      TEXT NOT NULL,        -- allocate | renew | release | expire | resize | handoff
    lease_id    INTEGER NOT NULL,
    pool_id     INTEGER NOT NULL,
    cidr        TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    details     TEXT NOT NULL DEFAULT '{}',  -- canonical (sorted, compact) JSON object
    prev_hash   TEXT NOT NULL,        -- previous event's hash; 64 zeros for the first
    hash        TEXT NOT NULL
);

-- One-time lease handoff codes. Only the SHA-256 digest of a claim code is
-- stored, never the code itself. At most one row per lease is 'pending' at
-- any moment: re-issuing supersedes the previous pending code.
CREATE TABLE IF NOT EXISTS lease_handoffs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    lease_id    INTEGER NOT NULL REFERENCES leases(id),
    code_digest TEXT NOT NULL UNIQUE,  -- SHA-256 hex of the claim code
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending | consumed | superseded
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_reservations_pool ON reservations(pool_id);
CREATE INDEX IF NOT EXISTS idx_leases_pool_status ON leases(pool_id, status);
CREATE INDEX IF NOT EXISTS idx_leases_token ON leases(token);
CREATE INDEX IF NOT EXISTS idx_lease_handoffs_lease ON lease_handoffs(lease_id, status);
"""


def connect(db_path: str | None = None) -> sqlite3.Connection:
    # Read the env var per call so tests can point at a fresh database.
    path = db_path or os.environ.get("CIDR_DB_PATH") or DEFAULT_DB_PATH
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(
        path,
        timeout=30.0,
        isolation_level=None,  # autocommit; we manage BEGIN/COMMIT ourselves
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def get_db() -> Iterator[sqlite3.Connection]:
    """FastAPI dependency: one connection per request."""
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def write_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Serializing write transaction (acquires the lock immediately)."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
