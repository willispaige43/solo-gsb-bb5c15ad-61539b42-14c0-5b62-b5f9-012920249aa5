"""FastAPI application: local CIDR address lease API."""

import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, status
from fastapi.responses import JSONResponse

from . import audit, service
from .db import connect, get_db, init_db, write_tx
from .errors import ApiError
from .schemas import (
    AuditEventOut,
    AuditVerifyOut,
    HandoffCreate,
    HandoffOut,
    LeaseOut,
    LeaseRequest,
    PoolCreate,
    PoolOut,
    PoolOverview,
    RenewRequest,
    ReservationCreate,
    ReservationOut,
    ResizeRequest,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db(connect())
    yield


app = FastAPI(
    title="CIDR Lease API",
    version="1.0.0",
    description="Local IPv4/IPv6 address-pool reservation and lease service.",
    lifespan=lifespan,
)


@app.exception_handler(ApiError)
def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------- pools ----------

@app.post("/pools", response_model=PoolOut, status_code=status.HTTP_201_CREATED)
def create_pool(body: PoolCreate, db: sqlite3.Connection = Depends(get_db)) -> dict:
    with write_tx(db):
        return service.create_pool(db, body.name.strip(), body.cidr)


@app.get("/pools", response_model=list[PoolOut])
def list_pools(db: sqlite3.Connection = Depends(get_db)) -> list[dict]:
    return service.list_pools(db)


@app.get("/pools/{pool_id}", response_model=PoolOverview)
def get_pool(pool_id: int, db: sqlite3.Connection = Depends(get_db)) -> dict:
    service.maybe_sweep(db)
    return service.pool_overview(db, pool_id)


# ---------- reservations ----------

@app.post(
    "/pools/{pool_id}/reservations",
    response_model=ReservationOut,
    status_code=status.HTTP_201_CREATED,
)
def create_reservation(
    pool_id: int, body: ReservationCreate, db: sqlite3.Connection = Depends(get_db)
) -> dict:
    with write_tx(db):
        return service.create_reservation(db, pool_id, body.cidr, body.description)


@app.get("/pools/{pool_id}/reservations", response_model=list[ReservationOut])
def list_reservations(pool_id: int, db: sqlite3.Connection = Depends(get_db)) -> list[dict]:
    return service.list_reservations(db, pool_id)


# ---------- leases ----------

@app.post(
    "/pools/{pool_id}/leases",
    response_model=LeaseOut,
    status_code=status.HTTP_201_CREATED,
)
def allocate_lease(
    pool_id: int, body: LeaseRequest, db: sqlite3.Connection = Depends(get_db)
) -> dict:
    with write_tx(db):
        return service.allocate_lease(db, pool_id, body.prefix_len, body.ttl_seconds)


@app.get("/leases", response_model=list[LeaseOut])
def list_active_leases(
    pool_id: int | None = None, db: sqlite3.Connection = Depends(get_db)
) -> list[dict]:
    service.maybe_sweep(db)
    return service.list_active_leases(db, pool_id)


@app.get("/leases/{token}", response_model=LeaseOut)
def get_lease(token: str, db: sqlite3.Connection = Depends(get_db)) -> dict:
    return service.get_lease(db, token)


@app.post("/leases/{token}/renew", response_model=LeaseOut)
def renew_lease(
    token: str, body: RenewRequest, db: sqlite3.Connection = Depends(get_db)
) -> dict:
    with write_tx(db):
        return service.renew_lease(db, token, body.ttl_seconds)


@app.post("/leases/{token}/release", response_model=LeaseOut)
def release_lease(token: str, db: sqlite3.Connection = Depends(get_db)) -> dict:
    with write_tx(db):
        return service.release_lease(db, token)


@app.put("/leases/{token}/resize", response_model=LeaseOut)
def resize_lease(
    token: str, body: ResizeRequest, db: sqlite3.Connection = Depends(get_db)
) -> dict:
    with write_tx(db):
        return service.resize_lease(db, token, body.target_prefix_len)


# ---------- lease handoffs ----------

@app.post(
    "/leases/{token}/handoffs",
    response_model=HandoffOut,
    status_code=status.HTTP_201_CREATED,
)
def create_handoff(
    token: str,
    body: HandoffCreate | None = None,
    db: sqlite3.Connection = Depends(get_db),
) -> dict:
    with write_tx(db):
        return service.create_handoff(db, token, body.ttl_seconds if body else None)


@app.post("/lease-handoffs/{claim_code}/claim", response_model=LeaseOut)
def claim_handoff(claim_code: str, db: sqlite3.Connection = Depends(get_db)) -> dict:
    with write_tx(db):
        return service.claim_handoff(db, claim_code)


# ---------- audit chain ----------

@app.get("/audit/events", response_model=list[AuditEventOut])
def list_audit_events(db: sqlite3.Connection = Depends(get_db)) -> list[dict]:
    return audit.list_events(db)


@app.get("/audit/verify", response_model=AuditVerifyOut)
def verify_audit_chain(db: sqlite3.Connection = Depends(get_db)) -> dict:
    return audit.verify_chain(db)
