from __future__ import annotations

import hmac

from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel

from iiot.common.log import get_logger


class RevocationRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def custom_handler(request: Request) -> Response:
            try:
                return await handler(request)
            except RequestValidationError as exc:
                for err in exc.errors():
                    if err.get("loc") == ("header", "x-admin-key"):
                        raise HTTPException(403, "bad admin key")
                raise

        return custom_handler


router = APIRouter(route_class=RevocationRoute)
log = get_logger("fog")


class RevokeReq(BaseModel):
    did: str
    reason: str | None = None


class RevokeResp(BaseModel):
    revoked: bool
    tokens_invalidated: int


class StatusResp(BaseModel):
    did: str
    status: str
    revoked: bool
    epochs: list[int]


def revoke_did(state, did: str, reason: str | None = None) -> int:
    with state.lock:
        state.revoked_dids.add(did)
        ids = [t for t, d in state.issued_tokens.items() if d == did]
        state.revoked_token_ids.update(ids)
        rec = state.devices.get(did)
        if rec is not None:
            rec.status = "revoked"
    log.info(f"revoke did={did} tokens_invalidated={len(ids)} reason={reason}")
    return len(ids)


@router.post("/admin/revoke", response_model=RevokeResp)
def admin_revoke(req: RevokeReq, request: Request, x_admin_key: str = Header(...)):
    state = request.app.state.fog
    if not hmac.compare_digest((x_admin_key or "").encode(), state.config.admin_key.encode()):
        raise HTTPException(403, "bad admin key")
    return {"revoked": True, "tokens_invalidated": revoke_did(state, req.did, req.reason)}


@router.get("/status/{did}", response_model=StatusResp)
def status(did: str, request: Request):
    state = request.app.state.fog
    rec = state.devices.get(did)
    revoked = did in state.revoked_dids
    st = "revoked" if revoked else (rec.status if rec is not None else "unknown")
    epochs = sorted(n for n, e in list(state.epochs.items()) if did in e.proofs)
    return {"did": did, "status": st, "revoked": revoked, "epochs": epochs}
