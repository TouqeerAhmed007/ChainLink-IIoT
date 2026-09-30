from __future__ import annotations

import time
from collections import deque
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict
from starlette.responses import JSONResponse

from iiot.common import crypto
from iiot.common.log import get_logger
from iiot.common.models import (BAD_REQUEST_SIG, DID_MISMATCH, DID_REVOKED, NONCE_REUSED, OK,
                                POLICY_DENIED, PROOF_INVALID, SCOPE_DENIED, STALE_TS,
                                UNKNOWN_DEVICE, UNKNOWN_EPOCH)
from iiot.fog import policy, revocation, tokens
from iiot.merkle.tree import verify_proof

log = get_logger("fog")


class AccessRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def custom_handler(request: Request) -> Response:
            try:
                return await handler(request)
            except RequestValidationError as exc:
                for err in exc.errors():
                    if err.get("loc") == ("header", "x-admin-key"):
                        raise HTTPException(403, "bad admin key")
                if request.url.path.endswith("/resource/access"):
                    try:
                        raw = await request.json()
                    except Exception:
                        raw = {}
                    res = evaluate_access(request.app.state.fog, raw)
                    return JSONResponse(res)
                raise

        return custom_handler


router = APIRouter(route_class=AccessRoute)
router.include_router(tokens.router)
router.include_router(revocation.router)


class AccessReq(BaseModel):
    model_config = ConfigDict(extra="allow")

    mode: Literal["token", "proof"]
    did: str
    nonce: str
    ts: float
    resource: str
    operation: str
    sig: str
    token: str | None = None
    pk: str | None = None
    epoch: int | None = None
    proof: list[Any] | None = None


class CheckResult(BaseModel):
    name: str
    ok: bool
    detail: str


class AccessResp(BaseModel):
    decision: str
    reason: str
    checks: list[CheckResult]
    latency_ms: float


def _shape(b: dict):
    if b.get("mode") not in ("token", "proof"):
        return "mode must be token|proof"
    for k in ("did", "nonce", "resource", "operation", "sig"):
        v = b.get(k)
        if not isinstance(v, str) or not v or len(v) > 512:
            return f"bad field {k}"
    if len(b["nonce"]) > 128:
        return "nonce too long"
    ts = b.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return "bad field ts"
    if b["mode"] == "token":
        if not isinstance(b.get("token"), str):
            return "bad field token"
    else:
        if not isinstance(b.get("pk"), str) or len(b["pk"]) > 512:
            return "bad field pk"
        if isinstance(b.get("epoch"), bool) or not isinstance(b.get("epoch"), int):
            return "bad field epoch"
        if not isinstance(b.get("proof"), list):
            return "bad field proof"
    return None


def _verify_req(pk: str, b: dict) -> bool:
    try:
        data = crypto.canonical({k: v for k, v in b.items() if k != "sig"})
        return bool(crypto.verify(pk, data, b["sig"]))
    except Exception:
        return False


def _role(rec):
    meta = rec.meta
    return getattr(meta, "role", None) or (meta.get("role") if isinstance(meta, dict) else None)


def _consume_nonce(state, did: str, nonce: str, now: float, record: bool) -> bool:
    key = f"{did}|{nonce}"
    with state.lock:
        q = getattr(state, "_nonce_q", None)
        if q is None:
            q = state._nonce_q = deque()
            state._nonce_next_sweep = 0.0
        if now >= state._nonce_next_sweep:  # amortized TTL sweep, at most once per second
            state._nonce_next_sweep = now + 1.0
            used = state.used_nonces
            while q and q[0][0] <= now:
                exp, k = q.popleft()
                if used.get(k) == exp:
                    del used[k]
        exp = state.used_nonces.get(key)
        if exp is not None and exp > now:
            return False
        if record:
            e = now + 2 * state.config.ts_skew_s + 1
            state.used_nonces[key] = e
            q.append((e, key))
        return True


def _nonce_then_policy(state, b, now, ctx, pol):
    ok_p, rc_p, det_p = pol
    fresh = _consume_nonce(state, b["did"], b["nonce"], now, ok_p)  # recorded only if it will ALLOW
    ctx["nonce"] = "fresh" if fresh else "reused"
    yield ("nonce_unused", fresh, "nonce fresh" if fresh else "nonce already used", NONCE_REUSED)
    if fresh:
        yield ("policy", ok_p, det_p, rc_p)


def _skew(state, b, now):
    d = abs(now - b["ts"])
    return d <= state.config.ts_skew_s, f"skew={d:.2f}s max={state.config.ts_skew_s}s"


def _token_flow(state, b, now, ctx):
    out: dict = {}
    for name, ok, detail, rc in tokens.iter_token_checks(state, b["token"], now, out):
        ctx["token"] = "valid" if ok else rc
        yield (name, ok, detail, rc)
        if not ok:
            return
    p = out["payload"]
    ok = p["did"] == b["did"]
    yield ("did_match", ok, "request DID matches token DID" if ok else "request DID differs from token DID", DID_MISMATCH)
    if not ok:
        return
    ok = _verify_req(p["pk"], b)
    yield ("request_sig", ok, "signature valid for token pk" if ok else "signature invalid for token pk", BAD_REQUEST_SIG)
    if not ok:
        return
    ok, det = _skew(state, b, now)
    yield ("timestamp_skew", ok, det, STALE_TS)
    if not ok:
        return
    if p["scope"] != "temp":
        pol = (False, SCOPE_DENIED, f"scope {p['scope']!r} not accepted")
    elif policy.is_allowed(p["role"], b["resource"], b["operation"], temp=True):
        pol = (True, OK, "temp token WRITE on own telemetry")
    else:
        pol = (False, POLICY_DENIED, f"temp token: {p['role']} may not {b['operation']} {b['resource']}")
    yield from _nonce_then_policy(state, b, now, ctx, pol)


def _proof_flow(state, b, now, ctx):
    did, pk, epoch = b["did"], b["pk"], b["epoch"]
    try:
        ok = crypto.make_did(pk) == did
        leaf = crypto.make_leaf(did, pk)
    except Exception:
        ok, leaf = False, ""
    yield ("leaf_recompute", ok, "DID and leaf recomputed from pk" if ok else "DID does not match pk", DID_MISMATCH)
    if not ok:
        return
    root = state.registry.get_root(epoch)
    yield ("trusted_root", root is not None, f"epoch={epoch} root from registry" if root else f"epoch {epoch} not anchored", UNKNOWN_EPOCH)
    if root is None:
        return
    try:
        pv = bool(verify_proof(leaf, b["proof"], root))
    except Exception:
        pv = False
    yield ("proof_valid", pv, "merkle proof valid" if pv else "merkle proof invalid", PROOF_INVALID)
    if not pv:
        return
    revoked = did in state.revoked_dids
    if revoked:
        log.warning(f"access did={did} historical proof VALID, current status REVOKED epoch={epoch}")
    yield ("did_revoked", not revoked, "DID not revoked" if not revoked else "historical proof valid but DID revoked", DID_REVOKED)
    if revoked:
        return
    ok = _verify_req(pk, b)
    yield ("request_sig", ok, "signature valid for request pk" if ok else "signature invalid for request pk", BAD_REQUEST_SIG)
    if not ok:
        return
    ok, det = _skew(state, b, now)
    yield ("timestamp_skew", ok, det, STALE_TS)
    if not ok:
        return
    rec = state.devices.get(did)
    if rec is None:
        pol = (False, UNKNOWN_DEVICE, "no device record")
    else:
        role = _role(rec)
        if policy.is_allowed(role, b["resource"], b["operation"]):
            pol = (True, OK, f"{role} may {b['operation']} {b['resource']}")
        else:
            pol = (False, POLICY_DENIED, f"{role} may not {b['operation']} {b['resource']}")
    yield from _nonce_then_policy(state, b, now, ctx, pol)


def _flow(state, b, now, ctx):
    err = _shape(b)
    yield ("request_sig_shape", err is None, err or "well-formed", BAD_REQUEST_SIG)
    if err is None:
        yield from (_token_flow if b["mode"] == "token" else _proof_flow)(state, b, now, ctx)


def evaluate_access(state, body, now: float | None = None) -> dict:
    t0 = time.perf_counter()
    now = time.time() if now is None else now
    if not isinstance(body, dict):
        body = {}
    checks, ctx = [], {"token": "n/a", "nonce": "unchecked"}
    decision, reason = "ALLOW", OK
    for name, ok, detail, rc in _flow(state, body, now, ctx):
        checks.append({"name": name, "ok": ok, "detail": detail})
        if not ok:
            decision, reason = "DENY", rc
            break
    latency = round((time.perf_counter() - t0) * 1000, 3)
    log.info(f"access did={body.get('did')} mode={body.get('mode')} nonce={ctx['nonce']} "
             f"token={ctx['token']} decision={decision} reason={reason} latency_ms={latency}")
    return {"decision": decision, "reason": reason, "checks": checks, "latency_ms": latency}


@router.post("/resource/access", response_model=AccessResp)
def resource_access(request: Request, body: AccessReq):
    return evaluate_access(request.app.state.fog, body.model_dump(exclude_none=True))
