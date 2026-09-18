"""Business logic: every mutating operation runs inside BEGIN IMMEDIATE."""

import hashlib
import secrets
import sqlite3
import time

from . import audit
from .errors import ApiError
from .iputil import (
    bounds,
    collapse,
    free_intervals,
    overlaps,
    parse_cidr,
    smallest_subnet,
)

DEFAULT_TTL_SECONDS = 3600


def _now() -> int:
    return int(time.time())


# ---------- helpers ----------

def _parse422(cidr: str):
    """Parse a CIDR, turning format/canonicality errors into HTTP 422."""
    try:
        return parse_cidr(cidr)
    except ValueError as exc:
        raise ApiError(422, str(exc))

def _get_pool(conn: sqlite3.Connection, pool_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM pools WHERE id = ?", (pool_id,)).fetchone()
    if row is None:
        raise ApiError(404, f"pool {pool_id} not found")
    return row


def _validate_in_pool(pool: sqlite3.Row, cidr: str, what: str = "network"):
    net = _parse422(cidr)
    if net.version != pool["version"]:
        raise ApiError(
            422,
            f"{what} is IPv{net.version} but pool '{pool['name']}' is "
            f"IPv{pool['version']}",
        )
    start, end = bounds(net)
    if start < int(pool["start_addr"]) or end > int(pool["end_addr"]):
        raise ApiError(
            422, f"{what} {net} is outside pool {pool['cidr']}"
        )
    return net, start, end


def _active_lease_occupancy(
    conn: sqlite3.Connection, pool_id: int, now: int
) -> list[tuple[int, int]]:
    rows = conn.execute(
        "SELECT start_addr, end_addr FROM leases "
        "WHERE pool_id = ? AND status = 'active' AND expires_at > ?",
        (pool_id, now),
    ).fetchall()
    return [(int(r["start_addr"]), int(r["end_addr"])) for r in rows]


def _reservation_occupancy(
    conn: sqlite3.Connection, pool_id: int
) -> list[tuple[int, int]]:
    rows = conn.execute(
        "SELECT start_addr, end_addr FROM reservations WHERE pool_id = ?",
        (pool_id,),
    ).fetchall()
    return [(int(r["start_addr"]), int(r["end_addr"])) for r in rows]


def _sweep_pool(conn: sqlite3.Connection, pool_id: int, now: int) -> int:
    """Mark expired active leases as expired. Caller holds the tx lock."""
    rows = conn.execute(
        "SELECT id, cidr, expires_at FROM leases "
        "WHERE pool_id = ? AND status = 'active' AND expires_at <= ?",
        (pool_id, now),
    ).fetchall()
    for row in rows:
        conn.execute(
            "UPDATE leases SET status = 'expired' WHERE id = ?", (row["id"],)
        )
        audit.append_event(
            conn,
            action=audit.EXPIRE,
            lease_id=row["id"],
            pool_id=pool_id,
            cidr=row["cidr"],
            occurred_at=now,
            details={"expires_at": row["expires_at"]},
        )
    return len(rows)


# ---------- pools ----------

def create_pool(
    conn: sqlite3.Connection, name: str, cidr: str
) -> dict:
    net = _parse422(cidr)  # 422 on malformed / non-canonical
    start, end = bounds(net)

    # Pools of the same family must not overlap.
    rows = conn.execute(
        "SELECT name, cidr, start_addr, end_addr FROM pools WHERE version = ?",
        (net.version,),
    ).fetchall()
    for row in rows:
        if overlaps(start, end, int(row["start_addr"]), int(row["end_addr"])):
            raise ApiError(
                409,
                f"pool {net} overlaps existing pool {row['cidr']} "
                f"('{row['name']}')",
            )

    now = _now()
    try:
        cur = conn.execute(
            "INSERT INTO pools (name, cidr, version, start_addr, end_addr, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, str(net), net.version, str(start), str(end), now),
        )
    except sqlite3.IntegrityError:
        raise ApiError(409, f"pool name '{name}' already exists")
    return {
        "id": cur.lastrowid,
        "name": name,
        "cidr": str(net),
        "version": net.version,
        "created_at": now,
    }


def list_pools(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM pools ORDER BY id").fetchall()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "cidr": r["cidr"],
            "version": r["version"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


# ---------- reservations ----------

def create_reservation(
    conn: sqlite3.Connection,
    pool_id: int,
    cidr: str,
    description: str = "",
) -> dict:
    now = _now()
    pool = _get_pool(conn, pool_id)
    net, start, end = _validate_in_pool(pool, cidr, "reservation")

    for r_start, r_end in _reservation_occupancy(conn, pool_id):
        if overlaps(start, end, r_start, r_end):
            raise ApiError(409, f"reservation {net} overlaps an existing reservation")
    for l_start, l_end in _active_lease_occupancy(conn, pool_id, now):
        if overlaps(start, end, l_start, l_end):
            raise ApiError(409, f"reservation {net} overlaps an active lease")

    cur = conn.execute(
        "INSERT INTO reservations (pool_id, cidr, description, start_addr, end_addr, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (pool_id, str(net), description, str(start), str(end), now),
    )
    return {
        "id": cur.lastrowid,
        "pool_id": pool_id,
        "cidr": str(net),
        "description": description,
        "created_at": now,
    }


def list_reservations(conn: sqlite3.Connection, pool_id: int) -> list[dict]:
    _get_pool(conn, pool_id)
    rows = conn.execute(
        "SELECT * FROM reservations WHERE pool_id = ? ORDER BY start_addr", (pool_id,)
    ).fetchall()
    return [
        {
            "id": r["id"],
            "pool_id": pool_id,
            "cidr": r["cidr"],
            "description": r["description"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


# ---------- leases ----------

def _lease_row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "pool_id": row["pool_id"],
        "cidr": row["cidr"],
        "token": row["token"],
        "status": row["status"],
        "created_at": row["created_at"],
        "renewed_at": row["renewed_at"],
        "expires_at": row["expires_at"],
    }


def _find_lease(conn: sqlite3.Connection, token: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM leases WHERE token = ?", (token,)).fetchone()
    if row is None:
        raise ApiError(404, "lease token not found")
    return row


def _require_live(row: sqlite3.Row, now: int) -> None:
    if row["status"] != "active" or row["expires_at"] <= now:
        raise ApiError(409, "lease is no longer active (expired or released)")


def allocate_lease(
    conn: sqlite3.Connection,
    pool_id: int,
    prefix_len: int,
    ttl_seconds: int | None = None,
) -> dict:
    now = _now()
    ttl = ttl_seconds if ttl_seconds is not None else DEFAULT_TTL_SECONDS
    if ttl <= 0:
        raise ApiError(422, "ttl_seconds must be positive")

    pool = _get_pool(conn, pool_id)
    pool_prefix = int(pool["cidr"].split("/")[1])
    max_prefix = 32 if pool["version"] == 4 else 128

    if not isinstance(prefix_len, int) or prefix_len < pool_prefix or prefix_len > max_prefix:
        raise ApiError(
            422,
            f"prefix_len must be between {pool_prefix} and {max_prefix} "
            f"for pool {pool['cidr']}",
        )

    _sweep_pool(conn, pool_id, now)

    occupied = _reservation_occupancy(conn, pool_id) + _active_lease_occupancy(
        conn, pool_id, now
    )
    free = free_intervals(
        int(pool["start_addr"]), int(pool["end_addr"]), occupied
    )
    picked = smallest_subnet(free, prefix_len, max_prefix)
    if picked is None:
        raise ApiError(
            409, f"no free /{prefix_len} block available in pool {pool['cidr']}"
        )

    start, end = picked
    net_cidr = collapse([(start, end)], pool["version"])[0]
    token = secrets.token_urlsafe(32)
    expires_at = now + ttl

    cur = conn.execute(
        "INSERT INTO leases (pool_id, cidr, token, start_addr, end_addr, "
        "status, expires_at, created_at, renewed_at) "
        "VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)",
        (pool_id, net_cidr, token, str(start), str(end), expires_at, now, now),
    )
    lease_id = cur.lastrowid
    audit.append_event(
        conn,
        action=audit.ALLOCATE,
        lease_id=lease_id,
        pool_id=pool_id,
        cidr=net_cidr,
        occurred_at=now,
        details={
            "prefix_len": prefix_len,
            "ttl_seconds": ttl,
            "expires_at": expires_at,
        },
    )
    row = conn.execute("SELECT * FROM leases WHERE id = ?", (lease_id,)).fetchone()
    return _lease_row_to_dict(row)


def renew_lease(
    conn: sqlite3.Connection, token: str, ttl_seconds: int | None = None
) -> dict:
    now = _now()
    ttl = ttl_seconds if ttl_seconds is not None else DEFAULT_TTL_SECONDS
    if ttl <= 0:
        raise ApiError(422, "ttl_seconds must be positive")

    row = _find_lease(conn, token)
    pool = _get_pool(conn, row["pool_id"])
    # Locks are pool-scoped; sweep first so the status check is authoritative.
    _sweep_pool(conn, row["pool_id"], now)
    row = _find_lease(conn, token)
    _require_live(row, now)

    expires_at = now + ttl
    conn.execute(
        "UPDATE leases SET expires_at = ?, renewed_at = ? WHERE id = ?",
        (expires_at, now, row["id"]),
    )
    audit.append_event(
        conn,
        action=audit.RENEW,
        lease_id=row["id"],
        pool_id=row["pool_id"],
        cidr=row["cidr"],
        occurred_at=now,
        details={"ttl_seconds": ttl, "expires_at": expires_at},
    )
    row = conn.execute("SELECT * FROM leases WHERE id = ?", (row["id"],)).fetchone()
    return _lease_row_to_dict(row)


def release_lease(conn: sqlite3.Connection, token: str) -> dict:
    now = _now()
    row = _find_lease(conn, token)
    _sweep_pool(conn, row["pool_id"], now)
    row = _find_lease(conn, token)
    _require_live(row, now)

    conn.execute(
        "UPDATE leases SET status = 'released' WHERE id = ?", (row["id"],)
    )
    audit.append_event(
        conn,
        action=audit.RELEASE,
        lease_id=row["id"],
        pool_id=row["pool_id"],
        cidr=row["cidr"],
        occurred_at=now,
        details={},
    )
    row = conn.execute("SELECT * FROM leases WHERE id = ?", (row["id"],)).fetchone()
    return _lease_row_to_dict(row)


def resize_lease(
    conn: sqlite3.Connection, token: str, target_prefix_len: int
) -> dict:
    """Resize a lease in place, keeping its token and expiry.

    Shrink keeps the low subnet containing the current start address; grow
    takes the unique supernet of ``target_prefix_len`` enclosing the current
    block and requires it to stay inside the pool and clear of reservations
    and other active leases.
    """
    now = _now()
    row = _find_lease(conn, token)
    pool = _get_pool(conn, row["pool_id"])
    max_prefix = 32 if pool["version"] == 4 else 128
    if (
        not isinstance(target_prefix_len, int)
        or target_prefix_len < 0
        or target_prefix_len > max_prefix
    ):
        raise ApiError(
            422,
            f"target_prefix_len must be between 0 and {max_prefix} "
            f"for pool {pool['cidr']}",
        )

    # Locks are pool-scoped; sweep first so the status check is authoritative.
    _sweep_pool(conn, row["pool_id"], now)
    row = _find_lease(conn, token)
    _require_live(row, now)

    cur_start = int(row["start_addr"])
    cur_prefix = int(row["cidr"].split("/")[1])
    if target_prefix_len == cur_prefix:
        return _lease_row_to_dict(row)  # no-op: no state change, no event

    size = 1 << (max_prefix - target_prefix_len)
    # The current start is aligned to the current (larger) block, hence to any
    # longer prefix: masking keeps it, yielding the low subnet on shrink. On
    # grow, masking rounds down to the unique enclosing supernet.
    new_start = cur_start & ~(size - 1)
    new_end = new_start + size
    new_cidr = collapse([(new_start, new_end)], pool["version"])[0]

    if target_prefix_len < cur_prefix:  # grow: the widened range must be free
        if new_start < int(pool["start_addr"]) or new_end > int(pool["end_addr"]):
            raise ApiError(
                409, f"resized supernet {new_cidr} is outside pool {pool['cidr']}"
            )
        for r_start, r_end in _reservation_occupancy(conn, row["pool_id"]):
            if overlaps(new_start, new_end, r_start, r_end):
                raise ApiError(
                    409, f"resized supernet {new_cidr} overlaps a reservation"
                )
        others = conn.execute(
            "SELECT start_addr, end_addr FROM leases "
            "WHERE pool_id = ? AND status = 'active' AND expires_at > ? AND id != ?",
            (row["pool_id"], now, row["id"]),
        ).fetchall()
        for o in others:
            if overlaps(new_start, new_end, int(o["start_addr"]), int(o["end_addr"])):
                raise ApiError(
                    409, f"resized supernet {new_cidr} overlaps an active lease"
                )

    before_cidr = row["cidr"]
    conn.execute(
        "UPDATE leases SET cidr = ?, start_addr = ?, end_addr = ? WHERE id = ?",
        (new_cidr, str(new_start), str(new_end), row["id"]),
    )
    audit.append_event(
        conn,
        action=audit.RESIZE,
        lease_id=row["id"],
        pool_id=row["pool_id"],
        cidr=new_cidr,
        occurred_at=now,
        details={"before_cidr": before_cidr, "after_cidr": new_cidr},
    )
    row = conn.execute("SELECT * FROM leases WHERE id = ?", (row["id"],)).fetchone()
    return _lease_row_to_dict(row)


def migrate_lease(
    conn: sqlite3.Connection, token: str, target_pool_id: int
) -> dict:
    """Move an active lease to another pool of the same address family.

    The lease keeps its id, token and expires_at; it re-acquires the same
    prefix length at the smallest-start free CIDR of the target pool. The
    source block is released the instant the lease row moves (both pools are
    touched inside one BEGIN IMMEDIATE transaction).
    """
    now = _now()
    row = _find_lease(conn, token)

    if target_pool_id == row["pool_id"]:
        raise ApiError(422, "target_pool_id must differ from the lease's pool")

    target_pool = _get_pool(conn, target_pool_id)
    source_pool = _get_pool(conn, row["pool_id"])
    if target_pool["version"] != source_pool["version"]:
        raise ApiError(
            422,
            f"target pool '{target_pool['name']}' is IPv{target_pool['version']} "
            f"but the lease is IPv{source_pool['version']}",
        )

    # Locks are pool-scoped; sweep both pools so the liveness check and the
    # target occupancy calculation are authoritative.
    _sweep_pool(conn, row["pool_id"], now)
    _sweep_pool(conn, target_pool_id, now)
    row = _find_lease(conn, token)
    _require_live(row, now)

    prefix_len = int(row["cidr"].split("/")[1])
    max_prefix = 32 if target_pool["version"] == 4 else 128
    occupied = _reservation_occupancy(conn, target_pool_id) + _active_lease_occupancy(
        conn, target_pool_id, now
    )
    free = free_intervals(
        int(target_pool["start_addr"]), int(target_pool["end_addr"]), occupied
    )
    picked = smallest_subnet(free, prefix_len, max_prefix)
    if picked is None:
        raise ApiError(
            409,
            f"no free /{prefix_len} block available in pool "
            f"{target_pool['cidr']}",
        )

    new_start, new_end = picked
    new_cidr = collapse([(new_start, new_end)], target_pool["version"])[0]
    before_cidr = row["cidr"]
    source_pool_id = row["pool_id"]

    conn.execute(
        "UPDATE leases SET pool_id = ?, cidr = ?, start_addr = ?, end_addr = ? "
        "WHERE id = ?",
        (target_pool_id, new_cidr, str(new_start), str(new_end), row["id"]),
    )
    audit.append_event(
        conn,
        action=audit.MIGRATE,
        lease_id=row["id"],
        pool_id=target_pool_id,
        cidr=new_cidr,
        occurred_at=now,
        details={
            "source_pool_id": source_pool_id,
            "target_pool_id": target_pool_id,
            "before_cidr": before_cidr,
            "after_cidr": new_cidr,
        },
    )
    row = conn.execute("SELECT * FROM leases WHERE id = ?", (row["id"],)).fetchone()
    return _lease_row_to_dict(row)


# ---------- lease handoffs ----------

HANDOFF_DEFAULT_TTL_SECONDS = 300
HANDOFF_MAX_TTL_SECONDS = 3600


def _code_digest(claim_code: str) -> str:
    """SHA-256 hex of a claim code; the code itself is never stored."""
    return hashlib.sha256(claim_code.encode("utf-8")).hexdigest()


def create_handoff(
    conn: sqlite3.Connection, token: str, ttl_seconds: int | None = None
) -> dict:
    """Issue a one-time claim code for an active lease.

    Only the code's SHA-256 digest is persisted; re-issuing supersedes any
    still-pending code for the same lease.
    """
    now = _now()
    ttl = ttl_seconds if ttl_seconds is not None else HANDOFF_DEFAULT_TTL_SECONDS
    if ttl < 1 or ttl > HANDOFF_MAX_TTL_SECONDS:
        raise ApiError(422, "ttl_seconds must be between 1 and 3600")

    row = _find_lease(conn, token)
    # Locks are pool-scoped; sweep first so the status check is authoritative.
    _sweep_pool(conn, row["pool_id"], now)
    row = _find_lease(conn, token)
    _require_live(row, now)

    # Re-issuing invalidates any still-pending code for this lease.
    conn.execute(
        "UPDATE lease_handoffs SET status = 'superseded' "
        "WHERE lease_id = ? AND status = 'pending'",
        (row["id"],),
    )
    expires_at = now + ttl
    for _ in range(3):  # a digest collision is all but impossible; retry anyway
        claim_code = secrets.token_urlsafe(32)
        try:
            conn.execute(
                "INSERT INTO lease_handoffs "
                "(lease_id, code_digest, status, expires_at, created_at) "
                "VALUES (?, ?, 'pending', ?, ?)",
                (row["id"], _code_digest(claim_code), expires_at, now),
            )
        except sqlite3.IntegrityError:
            continue
        return {"claim_code": claim_code, "expires_at": expires_at}
    raise ApiError(500, "could not issue a unique claim code")


def claim_handoff(conn: sqlite3.Connection, claim_code: str) -> dict:
    """Consume a claim code and rotate the lease token, atomically.

    The lease keeps its CIDR and expiry; the old token becomes unknown (404).
    """
    now = _now()
    handoff = conn.execute(
        "SELECT * FROM lease_handoffs WHERE code_digest = ?",
        (_code_digest(claim_code),),
    ).fetchone()
    if handoff is None:
        raise ApiError(404, "handoff claim code not found")
    if handoff["status"] != "pending":
        raise ApiError(409, "handoff claim code already consumed or superseded")
    if handoff["expires_at"] <= now:
        raise ApiError(409, "handoff claim code has expired")

    lease_id = handoff["lease_id"]
    row = conn.execute("SELECT * FROM leases WHERE id = ?", (lease_id,)).fetchone()
    # Locks are pool-scoped; sweep first so the status check is authoritative.
    _sweep_pool(conn, row["pool_id"], now)
    row = conn.execute("SELECT * FROM leases WHERE id = ?", (lease_id,)).fetchone()
    _require_live(row, now)

    conn.execute(
        "UPDATE lease_handoffs SET status = 'consumed', consumed_at = ? WHERE id = ?",
        (now, handoff["id"]),
    )
    conn.execute(
        "UPDATE leases SET token = ? WHERE id = ?",
        (secrets.token_urlsafe(32), lease_id),
    )
    audit.append_event(
        conn,
        action=audit.HANDOFF,
        lease_id=lease_id,
        pool_id=row["pool_id"],
        cidr=row["cidr"],
        occurred_at=now,
        details={},
    )
    row = conn.execute("SELECT * FROM leases WHERE id = ?", (lease_id,)).fetchone()
    return _lease_row_to_dict(row)


def get_lease(conn: sqlite3.Connection, token: str) -> dict:
    now = _now()
    row = _find_lease(conn, token)
    # A lease past its expiry is reported as expired even before the next sweep.
    data = _lease_row_to_dict(row)
    if data["status"] == "active" and data["expires_at"] <= now:
        data["status"] = "expired"
    return data


def list_active_leases(conn: sqlite3.Connection, pool_id: int | None = None) -> list[dict]:
    now = _now()
    if pool_id is not None:
        _get_pool(conn, pool_id)
        rows = conn.execute(
            "SELECT * FROM leases WHERE pool_id = ? AND status = 'active' "
            "AND expires_at > ? ORDER BY start_addr",
            (pool_id, now),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM leases WHERE status = 'active' AND expires_at > ? "
            "ORDER BY pool_id, start_addr",
            (now,),
        ).fetchall()
    return [_lease_row_to_dict(r) for r in rows]


def maybe_sweep(conn: sqlite3.Connection) -> None:
    """Read path helper: only take a write lock if something is expired."""
    now = _now()
    ids = [
        r["pool_id"]
        for r in conn.execute(
            "SELECT DISTINCT pool_id FROM leases "
            "WHERE status = 'active' AND expires_at <= ?",
            (now,),
        ).fetchall()
    ]
    if ids:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for pool_id in ids:
                _sweep_pool(conn, pool_id, now)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


# ---------- overview / free space ----------

def pool_overview(conn: sqlite3.Connection, pool_id: int) -> dict:
    pool = _get_pool(conn, pool_id)
    now = _now()

    reservations = list_reservations(conn, pool_id)
    occupied = [
        bounds(parse_cidr(r["cidr"]))
        for r in conn.execute(
            "SELECT cidr FROM reservations WHERE pool_id = ?", (pool_id,)
        ).fetchall()
    ]
    lease_rows = conn.execute(
        "SELECT * FROM leases WHERE pool_id = ? AND status = 'active' "
        "AND expires_at > ? ORDER BY start_addr",
        (pool_id, now),
    ).fetchall()
    leases = [_lease_row_to_dict(r) for r in lease_rows]
    occupied.extend(
        (int(r["start_addr"]), int(r["end_addr"])) for r in lease_rows
    )

    free = free_intervals(
        int(pool["start_addr"]), int(pool["end_addr"]), occupied
    )
    return {
        "pool": {
            "id": pool["id"],
            "name": pool["name"],
            "cidr": pool["cidr"],
            "version": pool["version"],
            "created_at": pool["created_at"],
        },
        "reservations": reservations,
        "active_leases": leases,
        "free_cidrs": collapse(free, pool["version"]),
    }
