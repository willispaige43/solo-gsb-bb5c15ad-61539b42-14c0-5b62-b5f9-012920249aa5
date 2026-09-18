"""Append-only, hash-chained audit log for lease lifecycle events.

Every successful allocate / renew / release / expire / resize / handoff
appends exactly one event, inside the same ``BEGIN IMMEDIATE`` transaction
as the state change itself — so a rolled-back operation never leaves an
event behind.

Each event stores ``seq`` (1, 2, 3, ...), the action, lease/pool ids, the
CIDR, the event time, a JSON ``details`` object, ``prev_hash`` and ``hash``.
The first event's ``prev_hash`` is 64 zeros; every later event chains to the
previous event's ``hash``. ``hash`` is::

    SHA-256( prev_hash_text || canonical_json(all fields except prev_hash/hash) )

where the canonical JSON is UTF-8, keys sorted, compact separators.
"""

import hashlib
import json
import sqlite3
from typing import Any

GENESIS_PREV_HASH = "0" * 64

# Actions recorded in the chain.
ALLOCATE = "allocate"
RENEW = "renew"
RELEASE = "release"
EXPIRE = "expire"
RESIZE = "resize"
HANDOFF = "handoff"

# Fields covered by the hash (everything except prev_hash / hash).
HASHED_FIELDS = (
    "seq",
    "action",
    "lease_id",
    "pool_id",
    "cidr",
    "occurred_at",
    "details",
)


def _canonical(obj: Any) -> str:
    """Key-sorted, compact JSON text (UTF-8 once encoded)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, fields: dict) -> str:
    """SHA-256 over prev_hash text + canonical JSON of the hashed fields."""
    payload = prev_hash + _canonical({k: fields[k] for k in HASHED_FIELDS})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_event(
    conn: sqlite3.Connection,
    *,
    action: str,
    lease_id: int,
    pool_id: int,
    cidr: str,
    occurred_at: int,
    details: dict | None = None,
) -> dict:
    """Append one event to the chain. Caller must hold the write lock
    (``BEGIN IMMEDIATE``), which also serializes ``seq`` assignment."""
    last = conn.execute(
        "SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    seq = 1 if last is None else int(last["seq"]) + 1
    prev_hash = GENESIS_PREV_HASH if last is None else last["hash"]

    fields = {
        "seq": seq,
        "action": action,
        "lease_id": lease_id,
        "pool_id": pool_id,
        "cidr": cidr,
        "occurred_at": occurred_at,
        "details": details or {},
    }
    digest = compute_hash(prev_hash, fields)
    conn.execute(
        "INSERT INTO audit_events "
        "(seq, action, lease_id, pool_id, cidr, occurred_at, details, prev_hash, hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            seq,
            action,
            lease_id,
            pool_id,
            cidr,
            occurred_at,
            _canonical(fields["details"]),
            prev_hash,
            digest,
        ),
    )
    return {**fields, "prev_hash": prev_hash, "hash": digest}


def _row_to_event(row: sqlite3.Row) -> dict:
    return {
        "seq": row["seq"],
        "action": row["action"],
        "lease_id": row["lease_id"],
        "pool_id": row["pool_id"],
        "cidr": row["cidr"],
        "occurred_at": row["occurred_at"],
        "details": json.loads(row["details"]),
        "prev_hash": row["prev_hash"],
        "hash": row["hash"],
    }


def list_events(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM audit_events ORDER BY seq ASC").fetchall()
    return [_row_to_event(r) for r in rows]


def verify_chain(conn: sqlite3.Connection) -> dict:
    """Re-walk the chain: contiguous seq, prev_hash linkage, recomputed hash."""
    rows = conn.execute("SELECT * FROM audit_events ORDER BY seq ASC").fetchall()
    prev_hash = GENESIS_PREV_HASH
    expected_seq = 1
    for row in rows:
        event = _row_to_event(row)
        if (
            event["seq"] != expected_seq
            or event["prev_hash"] != prev_hash
            or compute_hash(event["prev_hash"], event) != event["hash"]
        ):
            return {"valid": False, "invalid_seq": event["seq"]}
        prev_hash = event["hash"]
        expected_seq += 1
    return {"valid": True, "invalid_seq": None}
