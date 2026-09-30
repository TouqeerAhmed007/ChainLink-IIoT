from __future__ import annotations

import os
import time
from typing import Any, Optional

from iiot.common.crypto import (
    canonical, gen_keypair, hmac_hex, make_did, make_leaf, sign,
)
from iiot.common.models import ROLES, DeviceMeta

_TYPES = {
    "temperature_sensor": ("sensor", "Siemens", "1.2.0"),
    "pressure_sensor": ("sensor", "Honeywell", "2.0.1"),
    "smart_meter": ("meter", "Schneider", "3.1.4"),
    "camera": ("camera", "Axis", "5.4.2"),
    "valve_controller": ("actuator", "Emerson", "1.8.0"),
    "motor_controller": ("actuator", "ABB", "4.2.7"),
}


class SimDevice:
    def __init__(self, client: Any, psk: bytes, device_type: str, role: Optional[str] = None):
        role = role or (device_type if device_type in ROLES else None)
        if role not in ROLES:
            raise ValueError(f"invalid role: {role}")
        _, vendor, fw = _TYPES[role]
        self.client = client
        self.psk = psk
        self.sk, self.pk = gen_keypair()
        self.did = make_did(self.pk)
        self.leaf = make_leaf(self.did, self.pk)
        self.meta: dict[str, str] = DeviceMeta(
            device_type=device_type, role=role, vendor=vendor, fw=fw
        ).model_dump()
        self.role = role
        self.session_id: Optional[str] = None
        self.epoch: Optional[int] = None
        self.proof: Optional[list[dict[str, str]]] = None
        self.root: Optional[str] = None
        self.token: Optional[str] = None
        self.open_epoch: Optional[int] = None

    def _post(self, path: str, body: dict) -> dict:
        r = self.client.post(path, json=body)
        r.raise_for_status()
        return r.json()

    def authenticate(self) -> dict:
        h = self._post("/auth/hello", {})
        self.session_id = h["session_id"]
        mac = hmac_hex(self.psk, (h["server_nonce"] + h["session_id"]).encode())
        return self._post("/auth/psk", {"session_id": self.session_id, "mac": mac})

    def register(self) -> dict:
        if self.session_id is None:
            self.authenticate()
        c = self._post(
            "/register/key",
            {"session_id": self.session_id, "did": self.did, "pk": self.pk, "meta": self.meta},
        )
        res = self._post(
            "/register/pop",
            {"session_id": self.session_id, "signature": sign(self.sk, bytes.fromhex(c["challenge"]))},
        )
        self.open_epoch = res.get("open_epoch")
        return res

    def fetch_proof(self) -> dict:
        r = self.client.get(f"/proof/{self.did}")
        r.raise_for_status()
        d = r.json()
        self.epoch, self.proof, self.root = d["epoch"], d["proof"], d["root"]
        return d

    def get_temp_token(self) -> str:
        self.token = self._post("/token/temp", {"session_id": self.session_id})["token"]
        return self.token

    def build_request(
        self, mode: str, resource: str, operation: str,
        nonce: Optional[str] = None, ts: Optional[float] = None,
    ) -> dict:
        body: dict[str, Any] = {
            "mode": mode,
            "did": self.did,
            "nonce": nonce if nonce is not None else os.urandom(16).hex(),
            "ts": ts if ts is not None else time.time(),
            "resource": resource,
            "operation": operation,
        }
        if mode == "token":
            body["token"] = self.token
        elif mode == "proof":
            body.update(pk=self.pk, epoch=self.epoch, proof=self.proof)
        else:
            raise ValueError(f"invalid mode: {mode}")
        body["sig"] = sign(self.sk, canonical({k: v for k, v in body.items() if k != "sig"}))
        return body

    def send(self, body: dict) -> dict:
        return self.client.post("/resource/access", json=body).json()

    def access(self, mode: str, resource: str, operation: str) -> dict:
        if mode == "token" and self.token is None:
            self.get_temp_token()
        elif mode == "proof" and self.proof is None:
            self.fetch_proof()
        return self.send(self.build_request(mode, resource, operation))


def make_fleet(client: Any, psk: bytes, n: int) -> list[SimDevice]:
    return [
        SimDevice(client, psk, _TYPES[ROLES[i % len(ROLES)]][0], ROLES[i % len(ROLES)])
        for i in range(n)
    ]


def onboard_fleet(devs: list[SimDevice]) -> None:
    for d in devs:
        d.authenticate()
        d.register()
