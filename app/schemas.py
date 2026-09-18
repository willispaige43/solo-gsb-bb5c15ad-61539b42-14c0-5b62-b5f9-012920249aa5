"""Pydantic request/response models."""

from pydantic import BaseModel, Field


class PoolCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, examples=["office-lan"])
    cidr: str = Field(..., examples=["10.0.0.0/8"])


class PoolOut(BaseModel):
    id: int
    name: str
    cidr: str
    version: int
    created_at: int


class ReservationCreate(BaseModel):
    cidr: str = Field(..., examples=["10.0.0.0/16"])
    description: str = Field("", max_length=512)


class ReservationOut(BaseModel):
    id: int
    pool_id: int
    cidr: str
    description: str
    created_at: int


class LeaseRequest(BaseModel):
    prefix_len: int = Field(..., ge=0, le=128, examples=[24])
    ttl_seconds: int | None = Field(None, ge=1, le=2**31 - 1)


class RenewRequest(BaseModel):
    ttl_seconds: int | None = Field(None, ge=1, le=2**31 - 1)


class ResizeRequest(BaseModel):
    target_prefix_len: int = Field(..., ge=0, le=128, examples=[26])


class HandoffCreate(BaseModel):
    ttl_seconds: int | None = Field(None, ge=1, le=3600, examples=[300])


class HandoffOut(BaseModel):
    claim_code: str
    expires_at: int


class LeaseOut(BaseModel):
    id: int
    pool_id: int
    cidr: str
    token: str
    status: str
    created_at: int
    renewed_at: int
    expires_at: int


class PoolOverview(BaseModel):
    pool: PoolOut
    reservations: list[ReservationOut]
    active_leases: list[LeaseOut]
    free_cidrs: list[str]


class AuditEventOut(BaseModel):
    seq: int
    action: str
    lease_id: int
    pool_id: int
    cidr: str
    occurred_at: int
    details: dict
    prev_hash: str
    hash: str


class AuditVerifyOut(BaseModel):
    valid: bool
    invalid_seq: int | None
