import hmac
import os
import secrets
import time

from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field

from iiot.common.crypto import hmac_hex, make_did, make_leaf, verify
from iiot.common.log import get_logger
from iiot.common.models import DeviceMeta, DeviceRecord, EpochRecord, Session
from iiot.merkle.tree import build_tree


class OnboardingRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def custom_handler(request: Request) -> Response:
            try:
                return await handler(request)
            except RequestValidationError as exc:
                for err in exc.errors():
                    if err.get("loc") == ("header", "x-admin-key"):
                        raise HTTPException(401, "missing admin key")
                raise

        return custom_handler


router = APIRouter(route_class=OnboardingRoute)
log = get_logger("fog")

ROLES = {"temperature_sensor", "pressure_sensor", "smart_meter", "camera",
         "valve_controller", "motor_controller"}


class PskReq(BaseModel):
    session_id: str
    mac: str


class KeyReq(BaseModel):
    session_id: str
    did: str
    pk: str = Field(pattern=r"^04[0-9a-f]{128}$")
    meta: DeviceMeta


class PopReq(BaseModel):
    session_id: str
    signature: str


class HelloResp(BaseModel):
    session_id: str
    server_nonce: str


class PskResp(BaseModel):
    authenticated: bool


class KeyResp(BaseModel):
    challenge: str


class PopResp(BaseModel):
    registered: bool
    leaf: str
    open_epoch: int


class BatchCloseResp(BaseModel):
    epoch: int
    root: str
    count: int
    tx_hash: str
    excluded_revoked: int


class ProofResp(BaseModel):
    did: str
    pk: str
    epoch: int
    root: str
    leaf: str
    proof: list[dict[str, Any]]


class EpochResp(BaseModel):
    epoch: int
    root: str
    count: int


class RegistryResp(BaseModel):
    blocks: list[dict[str, Any]]
    chain_valid: bool


def _mk(cls, **kw):
    try:
        return cls(**kw)
    except Exception:
        return cls.model_construct(**kw)


def _st(request: Request):
    return request.app.state.fog


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _cts(st) -> dict:
    return st.__dict__.setdefault("challenge_ts", {})


def _session(st, sid: str):
    with st.lock:
        s = st.sessions.get(sid)
    if s is None:
        raise HTTPException(404, "unknown session")
    return s


@router.post("/auth/hello", response_model=HelloResp)
def hello(request: Request):
    st = _st(request)
    s = _mk(Session, session_id=secrets.token_hex(16), server_nonce=secrets.token_hex(16),
            authenticated=False, did="", pk="", meta=None, challenge="",
            pop_verified=False, created=time.time())
    with st.lock:
        st.sessions[s.session_id] = s
    log.info(f"hello session={s.session_id}")
    return {"session_id": s.session_id, "server_nonce": s.server_nonce}


@router.post("/auth/psk", response_model=PskResp)
def auth_psk(body: PskReq, request: Request):
    st = _st(request)
    s = _session(st, body.session_id)
    expected = hmac_hex(st.config.psk, (s.server_nonce + s.session_id).encode())
    if not _eq(expected, body.mac):
        log.warning(f"psk_rejected session={s.session_id}")
        raise HTTPException(401, "bad psk mac")
    with st.lock:
        s.authenticated = True
    log.info(f"psk_ok session={s.session_id}")
    return {"authenticated": True}


@router.post("/register/key", response_model=KeyResp)
def register_key(body: KeyReq, request: Request):
    st = _st(request)
    s = _session(st, body.session_id)
    if not s.authenticated:
        raise HTTPException(401, "session not authenticated")
    if body.meta.role not in ROLES:
        raise HTTPException(422, "unknown role")
    with st.lock:
        ex = st.devices.get(body.did)
    if ex is not None and ex.pk != body.pk:
        log.warning(f"rekey_rejected did={body.did}")
        raise HTTPException(409, "DID already registered with a different key")
    if make_did(body.pk) != body.did:
        log.warning(f"did_mismatch did={body.did}")
        raise HTTPException(403, "DID_MISMATCH")
    challenge = os.urandom(32).hex()
    with st.lock:
        ex = st.devices.get(body.did)
        if body.did in st.revoked_dids or (ex is not None and ex.status == "revoked"):
            raise HTTPException(403, "DID revoked")
        if ex is not None:
            raise HTTPException(409, "already registered")
        s.did, s.pk, s.meta = body.did, body.pk, body.meta
        s.challenge, s.pop_verified = challenge, False
        _cts(st)[s.session_id] = time.time()
    log.info(f"challenge_issued did={body.did}")
    return {"challenge": challenge}


@router.post("/register/pop", response_model=PopResp)
def register_pop(body: PopReq, request: Request):
    st = _st(request)
    s = _session(st, body.session_id)
    if not s.authenticated:
        raise HTTPException(401, "session not authenticated")
    with st.lock:
        ch, ts = s.challenge, _cts(st).pop(s.session_id, None)
        s.challenge = ""
    if not ch:
        raise HTTPException(409, "no pending challenge")
    if ts is None or time.time() - ts > st.config.challenge_ttl_s:
        raise HTTPException(401, "challenge expired")
    try:
        ok = verify(s.pk, bytes.fromhex(ch), body.signature)
    except Exception:
        ok = False
    if not ok:
        log.warning(f"pop_failed did={s.did}")
        raise HTTPException(401, "bad PoP signature")
    leaf = make_leaf(s.did, s.pk)
    with st.lock:
        if s.did in st.devices or s.did in st.revoked_dids:
            raise HTTPException(409, "already registered")
        st.devices[s.did] = _mk(DeviceRecord, did=s.did, pk=s.pk, meta=s.meta, leaf=leaf,
                                registered_at=time.time(), status="pending")
        st.pending.append(s.did)
        s.pop_verified = True
        open_epoch = st.current_epoch + 1
        npend = len(st.pending)
    log.info(f"registered did={s.did} leaf={leaf} pending={npend} open_epoch={open_epoch}")
    return {"registered": True, "leaf": leaf, "open_epoch": open_epoch}


@router.post("/admin/batch/close", response_model=BatchCloseResp)
def batch_close(request: Request, x_admin_key: str = Header(...)):
    st = _st(request)
    if x_admin_key is None:
        raise HTTPException(401, "missing admin key")
    if not _eq(st.config.admin_key, x_admin_key):
        raise HTTPException(403, "bad admin key")
    with st.lock:
        active = [d for d, r in st.devices.items()
                  if d not in st.revoked_dids and r.status != "revoked"]
        excluded = [d for d, r in st.devices.items()
                    if d in st.revoked_dids or r.status == "revoked"]
        leaf_map = {st.devices[d].leaf: d for d in active}
    if not active:
        raise HTTPException(409, "no active devices")
    tree = build_tree(list(leaf_map))
    proofs = {leaf_map[leaf]: p for leaf, p in tree.all_proofs().items()}
    with st.lock:
        epoch = st.current_epoch + 1
        block = st.registry.anchor(epoch, tree.root, len(tree.leaves))
        st.epochs[epoch] = _mk(EpochRecord, epoch=epoch, root=tree.root,
                               leaves=list(tree.leaves), proofs=proofs,
                               created_at=time.time(), count=len(tree.leaves),
                               tx_hash=block["hash"])
        for d in active:
            st.devices[d].status = "active"
        for d in excluded:
            st.devices[d].status = "revoked"
        done = set(active) | set(excluded)
        st.pending = [d for d in st.pending if d not in done]
        st.current_epoch = epoch
    log.info(f"batch_closed epoch={epoch} root={tree.root} count={len(tree.leaves)} "
             f"excluded_revoked={len(excluded)} tx={block['hash']}")
    return {"epoch": epoch, "root": tree.root, "count": len(tree.leaves),
            "tx_hash": block["hash"], "excluded_revoked": len(excluded)}


@router.get("/proof/{did}", response_model=ProofResp)
def get_proof(did: str, request: Request):
    st = _st(request)
    with st.lock:
        dev = st.devices.get(did)
        if dev is not None:
            for n in range(st.current_epoch, 0, -1):
                rec = st.epochs.get(n)
                if rec is not None and did in rec.proofs:
                    return {"did": did, "pk": dev.pk, "epoch": n, "root": rec.root,
                            "leaf": dev.leaf, "proof": list(rec.proofs[did])}
    raise HTTPException(404, "no proof for DID")


@router.get("/epoch/{n}", response_model=EpochResp)
def get_epoch(n: int, request: Request):
    st = _st(request)
    with st.lock:
        rec = st.epochs.get(n)
    if rec is None:
        raise HTTPException(404, "unknown epoch")
    return {"epoch": rec.epoch, "root": rec.root, "count": rec.count}


@router.get("/registry", response_model=RegistryResp)
def get_registry(request: Request):
    reg = _st(request).registry
    return {"blocks": reg.blocks(), "chain_valid": reg.verify_chain()}
