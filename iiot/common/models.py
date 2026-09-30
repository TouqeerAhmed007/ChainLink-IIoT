from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

ROLES = [
    "temperature_sensor", "pressure_sensor", "smart_meter",
    "camera", "valve_controller", "motor_controller",
]
RESOURCES = ["temperature", "pressure", "energy", "video", "valve", "motor", "production_line"]
OPERATIONS = ["READ", "WRITE", "STOP", "START", "OPEN", "CLOSE"]

OK = "OK"
BAD_TOKEN_SIG = "BAD_TOKEN_SIG"
TOKEN_EXPIRED = "TOKEN_EXPIRED"
TOKEN_REVOKED = "TOKEN_REVOKED"
DID_REVOKED = "DID_REVOKED"
NONCE_REUSED = "NONCE_REUSED"
BAD_REQUEST_SIG = "BAD_REQUEST_SIG"
DID_MISMATCH = "DID_MISMATCH"
PROOF_INVALID = "PROOF_INVALID"
UNKNOWN_EPOCH = "UNKNOWN_EPOCH"
STALE_TS = "STALE_TS"
POLICY_DENIED = "POLICY_DENIED"
UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
SCOPE_DENIED = "SCOPE_DENIED"

REASON_CODES = {
    OK, BAD_TOKEN_SIG, TOKEN_EXPIRED, TOKEN_REVOKED, DID_REVOKED, NONCE_REUSED,
    BAD_REQUEST_SIG, DID_MISMATCH, PROOF_INVALID, UNKNOWN_EPOCH, STALE_TS,
    POLICY_DENIED, UNKNOWN_DEVICE, SCOPE_DENIED,
}


class DeviceMeta(BaseModel):
    device_type: str
    role: str
    vendor: str
    fw: str


class DeviceRecord(BaseModel):
    did: str
    pk: str
    meta: DeviceMeta
    leaf: str
    registered_at: float
    status: Literal["pending", "active", "revoked"] = "pending"


class EpochRecord(BaseModel):
    epoch: int
    root: str
    leaves: list[str]
    proofs: dict[str, list[dict[str, str]]]
    created_at: float
    count: int
    tx_hash: str


class Session(BaseModel):
    session_id: str
    server_nonce: str
    authenticated: bool = False
    did: Optional[str] = None
    pk: Optional[str] = None
    meta: Optional[DeviceMeta] = None
    challenge: Optional[str] = None
    pop_verified: bool = False
    created: float = 0.0
