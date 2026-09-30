from __future__ import annotations

import json
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from iiot.common.crypto import b64u_dec, b64u_enc, canonical, make_leaf, sign, verify
from iiot.common.models import (BAD_TOKEN_SIG, DID_REVOKED, OK, TOKEN_EXPIRED,
                                TOKEN_REVOKED, DeviceRecord)

router = APIRouter()
_REQUIRED = {"token_id", "did", "pk", "role", "meta", "iat", "exp", "scope"}


def _meta_dict(meta) -> dict:
    return meta.model_dump() if hasattr(meta, "model_dump") else dict(meta)


def issue_temp_token(state, session, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    meta = _meta_dict(session.meta)
    payload = {
        "token_id": secrets.token_hex(16), "did": session.did, "pk": session.pk,
        "role": meta.get("role"), "meta": meta, "iat": round(now, 3),
        "exp": round(now + state.config.token_ttl_s, 3), "scope": "temp",
    }
    body = b64u_enc(canonical(payload))
    token = body + "." + sign(state.fog_sk, body.encode())
    with state.lock:
        state.issued_tokens[payload["token_id"]] = session.did
    return {"token": token, "expires_at": payload["exp"]}


def iter_token_checks(state, token_str, now: float, out: dict):
    """Yields (name, ok, detail, reason) lazily; caller stops at first failure."""
    try:
        body, sig = token_str.split(".")
        payload = json.loads(b64u_dec(body))
        if not isinstance(payload, dict) or not _REQUIRED <= payload.keys():
            raise ValueError
        exp = payload["exp"]
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise ValueError
        sig_ok = verify(state.fog_pk, body.encode(), sig)
    except Exception:
        yield ("token_sig", False, "malformed token or bad signature encoding", BAD_TOKEN_SIG)
        return
    if not sig_ok:
        yield ("token_sig", False, "fog signature invalid", BAD_TOKEN_SIG)
        return
    out["payload"] = payload
    yield ("token_sig", True, "fog signature valid", OK)
    if now >= exp:
        yield ("token_expiry", False, f"expired {now - exp:.1f}s ago", TOKEN_EXPIRED)
        return
    yield ("token_expiry", True, f"{exp - now:.1f}s remaining", OK)
    if payload["token_id"] in state.revoked_token_ids:
        yield ("token_revoked", False, "token_id revoked", TOKEN_REVOKED)
        return
    yield ("token_revoked", True, "token not revoked", OK)
    if payload["did"] in state.revoked_dids:
        yield ("did_revoked", False, "DID revoked", DID_REVOKED)
        return
    yield ("did_revoked", True, "DID not revoked", OK)


def validate_token(state, token_str, now: float | None = None):
    now = time.time() if now is None else now
    out: dict = {}
    for _name, ok, _detail, reason in iter_token_checks(state, token_str, now, out):
        if not ok:
            return False, reason, out.get("payload")
    return True, OK, out.get("payload")


class TokenReq(BaseModel):
    session_id: str


class TokenResp(BaseModel):
    token: str
    expires_at: float


def _ensure_queued(state, s) -> None:
    with state.lock:
        if s.did in state.devices:
            return
        if s.did not in state.pending:
            state.pending.append(s.did)
        state.devices[s.did] = DeviceRecord(
            did=s.did, pk=s.pk, meta=s.meta, leaf=make_leaf(s.did, s.pk),
            registered_at=time.time(), status="pending")


@router.post("/token/temp", response_model=TokenResp)
def token_temp(req: TokenReq, request: Request):
    state = request.app.state.fog
    s = state.sessions.get(req.session_id)
    if s is None:
        raise HTTPException(401, "unknown session")
    if not s.pop_verified:
        raise HTTPException(403, "proof of possession required")
    rec = state.devices.get(s.did)
    if s.did in state.revoked_dids or (rec is not None and rec.status == "revoked"):
        raise HTTPException(403, DID_REVOKED)
    _ensure_queued(state, s)
    return issue_temp_token(state, s)
