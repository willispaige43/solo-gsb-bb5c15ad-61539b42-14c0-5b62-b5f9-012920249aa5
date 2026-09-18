"""End-to-end tests. Run with: pytest -q"""

import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

# Point the DB at a throwaway file before importing the app.
_tmp = tempfile.mkdtemp()
os.environ["CIDR_DB_PATH"] = str(Path(_tmp) / "test.db")

from fastapi.testclient import TestClient  # noqa: E402

from app.db import connect, init_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    # Fresh schema file per test.
    db_file = Path(tempfile.mkdtemp()) / "t.db"
    os.environ["CIDR_DB_PATH"] = str(db_file)
    init_db(connect())
    with TestClient(app) as c:
        yield c


def _create_pool(client, name="p", cidr="10.0.0.0/24"):
    r = client.post("/pools", json={"name": name, "cidr": cidr})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------- validation ----------

def test_reject_non_canonical_and_garbage(client):
    r = client.post("/pools", json={"name": "p", "cidr": "10.0.0.5/24"})
    assert r.status_code == 422
    r = client.post("/pools", json={"name": "p", "cidr": "not-a-cidr"})
    assert r.status_code == 422


def test_overlapping_pool_rejected(client):
    _create_pool(client, "a", "10.0.0.0/16")
    r = client.post("/pools", json={"name": "b", "cidr": "10.0.128.0/17"})
    assert r.status_code == 409
    # Same family, disjoint is fine.
    assert client.post("/pools", json={"name": "c", "cidr": "192.168.0.0/16"}).status_code == 201
    # IPv4 vs IPv6 never overlap.
    assert client.post("/pools", json={"name": "d", "cidr": "2001:db8::/32"}).status_code == 201


def test_reservation_bounds_and_family(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    # out of bounds
    r = client.post(f"/pools/{pid}/reservations", json={"cidr": "10.0.1.0/24"})
    assert r.status_code == 422
    # wrong family
    r = client.post(f"/pools/{pid}/reservations", json={"cidr": "2001:db8::/64"})
    assert r.status_code == 422
    # non-canonical (host bits set)
    r = client.post(f"/pools/{pid}/reservations", json={"cidr": "10.0.0.5/26"})
    assert r.status_code == 422
    assert client.post(f"/pools/{pid}/reservations", json={"cidr": "10.0.0.0/26"}).status_code == 201
    # overlap with another reservation
    r = client.post(f"/pools/{pid}/reservations", json={"cidr": "10.0.0.0/28"})
    assert r.status_code == 409


def test_prefix_len_validation(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    assert client.post(f"/pools/{pid}/leases", json={"prefix_len": 23}).status_code == 422
    assert client.post(f"/pools/{pid}/leases", json={"prefix_len": 33}).status_code == 422
    # v6 pool, v4-ish length fine, but prefix beyond 128 rejected
    v6 = _create_pool(client, "v6", "2001:db8::/32")
    assert client.post(f"/pools/{v6}/leases", json={"prefix_len": 129}).status_code == 422


def test_unknown_pool_and_token(client):
    assert client.get("/pools/999").status_code == 404
    assert client.post("/pools/999/leases", json={"prefix_len": 24}).status_code == 404
    assert client.get("/leases/nope").status_code == 404
    assert client.post("/leases/nope/renew", json={}).status_code == 404


# ---------- allocation semantics ----------

def test_smallest_start_allocation_and_free_view(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    client.post(f"/pools/{pid}/reservations", json={"cidr": "10.0.0.0/26"})

    r = client.post(f"/pools/{pid}/leases", json={"prefix_len": 27})
    assert r.status_code == 201
    assert r.json()["cidr"] == "10.0.0.64/27"  # smallest legal start

    ov = client.get(f"/pools/{pid}").json()
    assert ov["free_cidrs"] == ["10.0.0.96/27", "10.0.0.128/25"]

    # next /27 starts at .96 (not .128)
    r = client.post(f"/pools/{pid}/leases", json={"prefix_len": 27})
    assert r.json()["cidr"] == "10.0.0.96/27"

    ov = client.get(f"/pools/{pid}").json()
    assert ov["free_cidrs"] == ["10.0.0.128/25"]


def test_exhaustion_409(client):
    pid = _create_pool(client, cidr="10.0.0.0/30")
    assert client.post(f"/pools/{pid}/leases", json={"prefix_len": 31}).status_code == 201
    assert client.post(f"/pools/{pid}/leases", json={"prefix_len": 31}).status_code == 201
    r = client.post(f"/pools/{pid}/leases", json={"prefix_len": 31})
    assert r.status_code == 409


def test_release_reclaims_space_and_old_token_conflicts(client):
    pid = _create_pool(client, cidr="10.0.0.0/30")
    token = client.post(f"/pools/{pid}/leases", json={"prefix_len": 31}).json()["token"]
    assert client.post(f"/leases/{token}/release").status_code == 200
    # space reclaimed: a new /31 fits again
    assert client.post(f"/pools/{pid}/leases", json={"prefix_len": 31}).status_code == 201
    # old token operations now conflict
    assert client.post(f"/leases/{token}/renew", json={}).status_code == 409
    assert client.post(f"/leases/{token}/release").status_code == 409
    assert client.get(f"/leases/{token}").json()["status"] == "released"


def test_renew_extends_expiry(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    out = client.post(
        f"/pools/{pid}/leases", json={"prefix_len": 32, "ttl_seconds": 3600}
    ).json()
    r = client.post(f"/leases/{out['token']}/renew", json={"ttl_seconds": 7200})
    assert r.status_code == 200
    assert r.json()["expires_at"] == out["expires_at"] + 3600


def test_expiry_recycles_and_invalidates_token(client):
    pid = _create_pool(client, cidr="10.0.0.0/30")
    token = client.post(
        f"/pools/{pid}/leases", json={"prefix_len": 31, "ttl_seconds": 1}
    ).json()["token"]
    time.sleep(1.2)

    # expired token conflicts
    assert client.post(f"/leases/{token}/renew", json={}).status_code == 409
    assert client.post(f"/leases/{token}/release").status_code == 409
    assert client.get(f"/leases/{token}").json()["status"] == "expired"

    # recycled space can be leased again, yielding the same block
    r = client.post(f"/pools/{pid}/leases", json={"prefix_len": 31})
    assert r.status_code == 201
    assert r.json()["cidr"] == "10.0.0.0/31"

    # expired lease is gone from the active list
    active = client.get(f"/pools/{pid}").json()["active_leases"]
    assert all(l["token"] != token for l in active)


def test_ipv6_allocation(client):
    pid = _create_pool(client, "v6", "2001:db8::/32")
    client.post(f"/pools/{pid}/reservations", json={"cidr": "2001:db8::/48"})
    r = client.post(f"/pools/{pid}/leases", json={"prefix_len": 64})
    assert r.status_code == 201
    assert r.json()["cidr"] == "2001:db8:1::/64"
    ov = client.get(f"/pools/{pid}").json()
    assert ov["free_cidrs"][0] == "2001:db8:1:1::/64"
    assert ov["free_cidrs"][-1] == "2001:db8:8000::/33"


def test_concurrent_allocations_never_overlap(client):
    # /29 contains exactly eight /32 addresses.
    pid = _create_pool(client, cidr="192.0.2.0/29")

    def allocate(_):
        return client.post(f"/pools/{pid}/leases", json={"prefix_len": 32})

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(allocate, range(12)))

    successes = [r for r in results if r.status_code == 201]
    failures = [r for r in results if r.status_code == 409]
    assert len(successes) == 8
    assert len(failures) == 4
    cidrs = {r.json()["cidr"] for r in successes}
    assert cidrs == {f"192.0.2.{i}/32" for i in range(8)}
    tokens = [r.json()["token"] for r in successes]
    assert len(set(tokens)) == 8


# ---------- audit chain ----------

GENESIS = "0" * 64


def _recompute(event):
    import hashlib
    import json

    fields = {
        k: event[k]
        for k in ("seq", "action", "lease_id", "pool_id", "cidr", "occurred_at", "details")
    }
    payload = event["prev_hash"] + json.dumps(
        fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _assert_chain_linkage(events):
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    prev = GENESIS
    for e in events:
        assert e["prev_hash"] == prev
        assert e["hash"] == _recompute(e)
        prev = e["hash"]


def test_audit_allocate_renew_release_chain(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    lease = client.post(
        f"/pools/{pid}/leases", json={"prefix_len": 27, "ttl_seconds": 3600}
    ).json()
    client.post(f"/leases/{lease['token']}/renew", json={"ttl_seconds": 7200})
    client.post(f"/leases/{lease['token']}/release")

    r = client.get("/audit/events")
    assert r.status_code == 200
    events = r.json()
    assert [e["action"] for e in events] == ["allocate", "renew", "release"]
    _assert_chain_linkage(events)

    alloc = events[0]
    assert alloc["lease_id"] == lease["id"]
    assert alloc["pool_id"] == pid
    assert alloc["cidr"] == lease["cidr"]
    assert alloc["details"]["prefix_len"] == 27
    assert alloc["details"]["ttl_seconds"] == 3600
    assert alloc["details"]["expires_at"] == lease["expires_at"]
    assert isinstance(alloc["occurred_at"], int)
    assert events[1]["details"]["ttl_seconds"] == 7200
    # the lease token (a bearer secret) never appears in the log
    assert all(lease["token"] not in str(e) for e in events)

    r = client.get("/audit/verify")
    assert r.status_code == 200
    assert r.json() == {"valid": True, "invalid_seq": None}


def test_audit_expire_event_recorded_on_sweep(client):
    pid = _create_pool(client, cidr="10.0.0.0/30")
    first = client.post(
        f"/pools/{pid}/leases", json={"prefix_len": 31, "ttl_seconds": 1}
    ).json()
    time.sleep(1.2)
    # next allocation sweeps the expired lease inside the same transaction
    assert client.post(f"/pools/{pid}/leases", json={"prefix_len": 31}).status_code == 201

    events = client.get("/audit/events").json()
    assert [e["action"] for e in events] == ["allocate", "expire", "allocate"]
    expire = events[1]
    assert expire["lease_id"] == first["id"]
    assert expire["cidr"] == first["cidr"]
    assert expire["details"]["expires_at"] == first["expires_at"]
    _assert_chain_linkage(events)
    assert client.get("/audit/verify").json() == {"valid": True, "invalid_seq": None}


def test_audit_failures_not_recorded(client):
    pid = _create_pool(client, cidr="10.0.0.0/30")
    assert client.post(f"/pools/{pid}/leases", json={"prefix_len": 31}).status_code == 201
    assert client.post(f"/pools/{pid}/leases", json={"prefix_len": 31}).status_code == 201

    # 409: pool exhausted; 404: unknown token; 422: bad prefix — none recorded
    assert client.post(f"/pools/{pid}/leases", json={"prefix_len": 31}).status_code == 409
    assert client.post("/leases/nope/renew", json={}).status_code == 404
    assert client.post(f"/pools/{pid}/leases", json={"prefix_len": 33}).status_code == 422

    events = client.get("/audit/events").json()
    assert [e["action"] for e in events] == ["allocate", "allocate"]
    assert client.get("/audit/verify").json() == {"valid": True, "invalid_seq": None}


def test_audit_verify_detects_tampering(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    client.post(f"/pools/{pid}/leases", json={"prefix_len": 27})
    client.post(f"/pools/{pid}/leases", json={"prefix_len": 27})
    assert client.get("/audit/verify").json() == {"valid": True, "invalid_seq": None}

    # Tamper with the first event directly in the database.
    conn = connect()
    conn.execute("UPDATE audit_events SET cidr = '10.0.0.0/24' WHERE seq = 1")
    conn.close()

    assert client.get("/audit/verify").json() == {"valid": False, "invalid_seq": 1}


def test_audit_verify_detects_broken_linkage(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    client.post(f"/pools/{pid}/leases", json={"prefix_len": 27})
    client.post(f"/pools/{pid}/leases", json={"prefix_len": 27})

    # Break the prev_hash link of the second event.
    conn = connect()
    conn.execute(f"UPDATE audit_events SET prev_hash = '{GENESIS}' WHERE seq = 2")
    conn.close()

    assert client.get("/audit/verify").json() == {"valid": False, "invalid_seq": 2}


def test_audit_empty_chain_is_valid(client):
    assert client.get("/audit/events").json() == []
    assert client.get("/audit/verify").json() == {"valid": True, "invalid_seq": None}


# ---------- resize ----------

def test_resize_shrink_keeps_low_subnet_and_identity(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    lease = client.post(
        f"/pools/{pid}/leases", json={"prefix_len": 26, "ttl_seconds": 3600}
    ).json()
    assert lease["cidr"] == "10.0.0.0/26"

    r = client.put(f"/leases/{lease['token']}/resize", json={"target_prefix_len": 28})
    assert r.status_code == 200
    out = r.json()
    assert out["cidr"] == "10.0.0.0/28"  # low subnet, same start address
    assert out["id"] == lease["id"]
    assert out["token"] == lease["token"]  # token unchanged
    assert out["expires_at"] == lease["expires_at"]  # expiry unchanged

    # the released upper part of the old block is free again
    ov = client.get(f"/pools/{pid}").json()
    assert ov["free_cidrs"] == [
        "10.0.0.16/28",
        "10.0.0.32/27",
        "10.0.0.64/26",
        "10.0.0.128/25",
    ]
    # and can be handed out to a new lease
    r = client.post(f"/pools/{pid}/leases", json={"prefix_len": 28})
    assert r.status_code == 201
    assert r.json()["cidr"] == "10.0.0.16/28"

    events = client.get("/audit/events").json()
    assert [e["action"] for e in events] == ["allocate", "resize", "allocate"]
    resize = events[1]
    assert resize["lease_id"] == lease["id"]
    assert resize["cidr"] == "10.0.0.0/28"
    assert resize["details"] == {
        "before_cidr": "10.0.0.0/26",
        "after_cidr": "10.0.0.0/28",
    }
    assert lease["token"] not in str(resize)
    _assert_chain_linkage(events)
    assert client.get("/audit/verify").json() == {"valid": True, "invalid_seq": None}


def test_resize_grow_into_free_supernet(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    first = client.post(f"/pools/{pid}/leases", json={"prefix_len": 26}).json()
    second = client.post(f"/pools/{pid}/leases", json={"prefix_len": 27}).json()
    assert first["cidr"] == "10.0.0.0/26"
    assert second["cidr"] == "10.0.0.64/27"

    # the unique /26 enclosing 10.0.0.64/27 is 10.0.0.64/26 — free, so it grows
    r = client.put(f"/leases/{second['token']}/resize", json={"target_prefix_len": 26})
    assert r.status_code == 200
    out = r.json()
    assert out["cidr"] == "10.0.0.64/26"
    assert out["token"] == second["token"]
    assert out["expires_at"] == second["expires_at"]

    ov = client.get(f"/pools/{pid}").json()
    assert ov["free_cidrs"] == ["10.0.0.128/25"]


def test_resize_grow_conflict_with_active_lease(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    client.post(f"/pools/{pid}/leases", json={"prefix_len": 27})  # 10.0.0.0/27
    b = client.post(f"/pools/{pid}/leases", json={"prefix_len": 27}).json()
    assert b["cidr"] == "10.0.0.32/27"

    # growing b to /26 needs 10.0.0.0/26, which overlaps the first lease
    r = client.put(f"/leases/{b['token']}/resize", json={"target_prefix_len": 26})
    assert r.status_code == 409
    # failed resize leaves the lease unchanged and appends no event
    assert client.get(f"/leases/{b['token']}").json()["cidr"] == "10.0.0.32/27"
    events = client.get("/audit/events").json()
    assert [e["action"] for e in events] == ["allocate", "allocate"]
    assert client.get("/audit/verify").json() == {"valid": True, "invalid_seq": None}


def test_resize_grow_conflict_with_reservation(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    client.post(f"/pools/{pid}/reservations", json={"cidr": "10.0.0.64/26"})
    lease = client.post(f"/pools/{pid}/leases", json={"prefix_len": 27}).json()
    assert lease["cidr"] == "10.0.0.0/27"

    # /25 supernet (10.0.0.0/25) would swallow the reservation
    r = client.put(f"/leases/{lease['token']}/resize", json={"target_prefix_len": 25})
    assert r.status_code == 409
    # /26 (10.0.0.0/26) stops short of it and succeeds
    r = client.put(f"/leases/{lease['token']}/resize", json={"target_prefix_len": 26})
    assert r.status_code == 200
    assert r.json()["cidr"] == "10.0.0.0/26"


def test_resize_grow_outside_pool_rejected(client):
    pid = _create_pool(client, cidr="10.0.0.0/25")
    lease = client.post(f"/pools/{pid}/leases", json={"prefix_len": 27}).json()
    # the /24 supernet escapes the /25 pool
    r = client.put(f"/leases/{lease['token']}/resize", json={"target_prefix_len": 24})
    assert r.status_code == 409
    assert client.get(f"/leases/{lease['token']}").json()["cidr"] == "10.0.0.0/27"


def test_resize_invalid_prefix_422(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    lease = client.post(f"/pools/{pid}/leases", json={"prefix_len": 27}).json()
    url = f"/leases/{lease['token']}/resize"
    assert client.put(url, json={"target_prefix_len": 33}).status_code == 422
    assert client.put(url, json={"target_prefix_len": -1}).status_code == 422
    assert client.put(url, json={"target_prefix_len": 129}).status_code == 422
    assert client.put(url, json={}).status_code == 422
    # nothing recorded for rejected requests
    events = client.get("/audit/events").json()
    assert [e["action"] for e in events] == ["allocate"]


def test_resize_same_prefix_is_noop_without_event(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    lease = client.post(f"/pools/{pid}/leases", json={"prefix_len": 27}).json()
    r = client.put(f"/leases/{lease['token']}/resize", json={"target_prefix_len": 27})
    assert r.status_code == 200
    assert r.json() == lease
    assert [e["action"] for e in client.get("/audit/events").json()] == ["allocate"]


def test_resize_requires_active_lease(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    lease = client.post(f"/pools/{pid}/leases", json={"prefix_len": 27}).json()
    client.post(f"/leases/{lease['token']}/release")
    r = client.put(f"/leases/{lease['token']}/resize", json={"target_prefix_len": 28})
    assert r.status_code == 409
    assert client.put("/leases/nope/resize", json={"target_prefix_len": 28}).status_code == 404


def test_resize_expired_lease_409(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    lease = client.post(
        f"/pools/{pid}/leases", json={"prefix_len": 27, "ttl_seconds": 1}
    ).json()
    time.sleep(1.2)
    r = client.put(f"/leases/{lease['token']}/resize", json={"target_prefix_len": 28})
    assert r.status_code == 409


def test_resize_ipv6(client):
    pid = _create_pool(client, "v6", "2001:db8::/32")
    lease = client.post(f"/pools/{pid}/leases", json={"prefix_len": 64}).json()
    assert lease["cidr"] == "2001:db8::/64"

    r = client.put(f"/leases/{lease['token']}/resize", json={"target_prefix_len": 48})
    assert r.status_code == 200
    assert r.json()["cidr"] == "2001:db8::/48"

    r = client.put(f"/leases/{lease['token']}/resize", json={"target_prefix_len": 56})
    assert r.status_code == 200
    assert r.json()["cidr"] == "2001:db8::/56"

    assert client.put(
        f"/leases/{lease['token']}/resize", json={"target_prefix_len": 129}
    ).status_code == 422

    events = client.get("/audit/events").json()
    assert [e["action"] for e in events] == ["allocate", "resize", "resize"]
    assert events[1]["details"] == {
        "before_cidr": "2001:db8::/64",
        "after_cidr": "2001:db8::/48",
    }
    _assert_chain_linkage(events)


# ---------- lease handoffs ----------

def _create_lease(client, cidr="10.0.0.0/24", prefix_len=27, ttl=3600):
    pid = _create_pool(client, cidr=cidr)
    lease = client.post(
        f"/pools/{pid}/leases", json={"prefix_len": prefix_len, "ttl_seconds": ttl}
    ).json()
    return pid, lease


def test_handoff_issue_and_claim_rotates_token(client):
    _, lease = _create_lease(client)
    r = client.post(f"/leases/{lease['token']}/handoffs", json={"ttl_seconds": 600})
    assert r.status_code == 201
    body = r.json()
    assert body["claim_code"]
    now = int(time.time())
    assert now + 590 <= body["expires_at"] <= now + 600

    r = client.post(f"/lease-handoffs/{body['claim_code']}/claim")
    assert r.status_code == 200
    out = r.json()
    assert out["id"] == lease["id"]
    assert out["token"] != lease["token"]  # token rotated
    assert out["cidr"] == lease["cidr"]  # CIDR unchanged
    assert out["expires_at"] == lease["expires_at"]  # expiry unchanged
    assert out["status"] == "active"

    # the old token is now an unknown token -> 404
    assert client.get(f"/leases/{lease['token']}").status_code == 404
    assert client.post(f"/leases/{lease['token']}/renew", json={}).status_code == 404
    # the new token works
    assert client.get(f"/leases/{out['token']}").status_code == 200


def test_handoff_issue_ttl_bounds_and_lease_state(client):
    _, lease = _create_lease(client)
    url = f"/leases/{lease['token']}/handoffs"
    assert client.post(url, json={"ttl_seconds": 0}).status_code == 422
    assert client.post(url, json={"ttl_seconds": 3601}).status_code == 422
    assert client.post(url, json={"ttl_seconds": 1}).status_code == 201
    assert client.post(url, json={"ttl_seconds": 3600}).status_code == 201
    # no body -> default TTL (300s)
    r = client.post(url)
    assert r.status_code == 201
    now = int(time.time())
    assert now + 290 <= r.json()["expires_at"] <= now + 300
    # unknown token -> 404
    assert client.post("/leases/nope/handoffs", json={}).status_code == 404
    # released lease -> 409
    assert client.post(f"/leases/{lease['token']}/release").status_code == 200
    assert client.post(url, json={}).status_code == 409


def test_handoff_issue_expired_lease_409(client):
    _, lease = _create_lease(client, ttl=1)
    time.sleep(1.2)
    assert client.post(f"/leases/{lease['token']}/handoffs", json={}).status_code == 409


def test_handoff_reissue_supersedes_previous_code(client):
    _, lease = _create_lease(client)
    first = client.post(f"/leases/{lease['token']}/handoffs", json={}).json()
    second = client.post(f"/leases/{lease['token']}/handoffs", json={}).json()
    assert first["claim_code"] != second["claim_code"]
    # the replaced code is dead -> 409
    assert client.post(f"/lease-handoffs/{first['claim_code']}/claim").status_code == 409
    # the fresh code works
    assert client.post(f"/lease-handoffs/{second['claim_code']}/claim").status_code == 200


def test_handoff_claim_unknown_and_consumed_code(client):
    _, lease = _create_lease(client)
    assert client.post("/lease-handoffs/never-issued/claim").status_code == 404
    code = client.post(f"/leases/{lease['token']}/handoffs", json={}).json()["claim_code"]
    assert client.post(f"/lease-handoffs/{code}/claim").status_code == 200
    # already consumed -> 409
    assert client.post(f"/lease-handoffs/{code}/claim").status_code == 409


def test_handoff_claim_expired_code_409(client):
    _, lease = _create_lease(client)
    code = client.post(
        f"/leases/{lease['token']}/handoffs", json={"ttl_seconds": 1}
    ).json()["claim_code"]
    time.sleep(1.2)
    assert client.post(f"/lease-handoffs/{code}/claim").status_code == 409
    # the lease itself is untouched: its token still works
    assert client.get(f"/leases/{lease['token']}").status_code == 200


def test_handoff_claim_requires_active_lease(client):
    _, lease = _create_lease(client)
    code = client.post(f"/leases/{lease['token']}/handoffs", json={}).json()["claim_code"]
    client.post(f"/leases/{lease['token']}/release")
    assert client.post(f"/lease-handoffs/{code}/claim").status_code == 409


def test_handoff_claim_lease_expired_before_claim_409(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    lease = client.post(
        f"/pools/{pid}/leases", json={"prefix_len": 27, "ttl_seconds": 1}
    ).json()
    code = client.post(
        f"/leases/{lease['token']}/handoffs", json={"ttl_seconds": 60}
    ).json()["claim_code"]
    time.sleep(1.2)
    assert client.post(f"/lease-handoffs/{code}/claim").status_code == 409


def test_handoff_concurrent_claims_only_one_wins(client):
    _, lease = _create_lease(client)
    code = client.post(f"/leases/{lease['token']}/handoffs", json={}).json()["claim_code"]

    def claim(_):
        return client.post(f"/lease-handoffs/{code}/claim")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(claim, range(8)))

    successes = [r for r in results if r.status_code == 200]
    failures = [r for r in results if r.status_code == 409]
    assert len(successes) == 1
    assert len(failures) == 7
    new_token = successes[0].json()["token"]
    assert client.get(f"/leases/{new_token}").status_code == 200
    assert client.get(f"/leases/{lease['token']}").status_code == 404
    # exactly one handoff event was appended
    events = client.get("/audit/events").json()
    assert [e["action"] for e in events] == ["allocate", "handoff"]
    _assert_chain_linkage(events)


def test_handoff_audit_event_and_no_digest_leak(client):
    import hashlib

    _, lease = _create_lease(client)
    r = client.post(f"/leases/{lease['token']}/handoffs", json={"ttl_seconds": 600})
    code = r.json()["claim_code"]
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
    # the issuance response returns the code but never its stored digest
    assert digest not in r.text

    # failed claims leave no event behind
    assert client.post("/lease-handoffs/never-issued/claim").status_code == 404
    assert client.post(f"/lease-handoffs/{code}/claim").status_code == 200
    assert client.post(f"/lease-handoffs/{code}/claim").status_code == 409

    events = client.get("/audit/events").json()
    assert [e["action"] for e in events] == ["allocate", "handoff"]
    handoff = events[1]
    assert handoff["lease_id"] == lease["id"]
    assert handoff["pool_id"] == lease["pool_id"]
    assert handoff["cidr"] == lease["cidr"]
    # neither the code, its digest, nor any token appears in the log
    blob = str(events)
    assert code not in blob
    assert digest not in blob
    assert lease["token"] not in blob
    _assert_chain_linkage(events)
    assert client.get("/audit/verify").json() == {"valid": True, "invalid_seq": None}
