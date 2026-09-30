import json
import os
import sys
import time
import types

import httpx
import pytest

from iiot.common.crypto import (
    b64u_dec, b64u_enc, canonical, gen_keypair, hmac_hex, make_did, make_leaf,
    sha256_hex, sign, verify,
)
from iiot.common.models import ROLES
from iiot.common.state import FogConfig, new_state
from iiot.device.device import SimDevice, make_fleet, onboard_fleet

PSK = b"psk"


def test_sign_verify_and_tamper():
    sk, pk = gen_keypair()
    assert len(pk) == 130 and pk.startswith("04")
    sig = sign(sk, b"msg")
    assert verify(pk, b"msg", sig)
    assert not verify(pk, b"msg2", sig)
    assert not verify(pk, b"msg", sig[:-2] + ("00" if sig[-2:] != "00" else "11"))
    assert not verify(pk, b"msg", "zz")
    assert not verify(gen_keypair()[1], b"msg", sig)
    assert not verify("04ab", b"msg", sig)


def test_speed():
    sk, pk = gen_keypair()
    t = time.perf_counter()
    sigs = [sign(sk, b"x") for _ in range(200)]
    ts = (time.perf_counter() - t) / 200
    t = time.perf_counter()
    for s in sigs:
        verify(pk, b"x", s)
    tv = (time.perf_counter() - t) / 200
    assert ts < 0.005 and tv < 0.005


def test_did_leaf_helpers():
    _, pk = gen_keypair()
    did = make_did(pk)
    assert did.startswith("did:iiot:") and len(did) == 9 + 32
    assert make_leaf(did, pk) == sha256_hex(did.encode(), bytes.fromhex(pk))
    assert canonical({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}'
    assert b64u_dec(b64u_enc(b"\x00\xff\xfe1")) == b"\x00\xff\xfe1"
    assert len(hmac_hex(b"k", b"m")) == 64


def make_mock():
    db: dict = {}
    seen: list = []

    def h(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        b = json.loads(req.content) if req.content else {}
        R = lambda j, c=200: httpx.Response(c, json=j)
        if p == "/auth/hello":
            return R({"session_id": "s1", "server_nonce": "n1"})
        if p == "/auth/psk":
            ok = b["mac"] == hmac_hex(PSK, b"n1s1")
            return R({"authenticated": True}) if ok else R({}, 401)
        if p == "/register/key":
            assert make_did(b["pk"]) == b["did"]
            db["pk"], db["did"], db["ch"] = b["pk"], b["did"], os.urandom(16).hex()
            return R({"challenge": db["ch"]})
        if p == "/register/pop":
            assert verify(db["pk"], bytes.fromhex(db["ch"]), b["signature"])
            return R({"registered": True, "leaf": make_leaf(db["did"], db["pk"]), "open_epoch": 1})
        if p == "/token/temp":
            return R({"token": "tok", "expires_at": time.time() + 60})
        if p.startswith("/proof/"):
            return R({"did": db["did"], "pk": db["pk"], "epoch": 1, "root": "ab" * 32,
                      "leaf": "cd" * 32, "proof": [{"hash": "ef" * 32, "side": "left"}]})
        if p == "/resource/access":
            seen.append(b)
            sig = b.pop("sig")
            ok = verify(db["pk"], canonical(b), sig)
            return R({"decision": "ALLOW" if ok else "DENY", "reason": "OK", "checks": [], "latency_ms": 0})
        return R({}, 404)

    return httpx.Client(transport=httpx.MockTransport(h), base_url="http://fog"), seen


def test_device_flow_and_request_signature():
    c, seen = make_mock()
    d = SimDevice(c, PSK, "sensor", "temperature_sensor")
    d.authenticate()
    assert d.register()["registered"] and d.open_epoch == 1
    d.fetch_proof()
    assert d.epoch == 1 and d.root == "ab" * 32
    assert d.get_temp_token() == "tok"
    assert d.access("token", "temperature", "WRITE")["decision"] == "ALLOW"
    assert d.access("proof", "temperature", "WRITE")["decision"] == "ALLOW"
    t, p = seen
    assert t["token"] == "tok" and "proof" not in t
    assert set(p) >= {"pk", "epoch", "proof"} and "token" not in p
    body = d.build_request("token", "temperature", "WRITE", nonce="n", ts=5.0)
    assert body["nonce"] == "n" and body["ts"] == 5.0
    sig = body.pop("sig")
    assert verify(d.pk, canonical(body), sig)
    body["resource"] = "valve"
    assert not verify(d.pk, canonical(body), sig)
    assert len(d.build_request("token", "temperature", "WRITE")["nonce"]) == 32
    body["operation"] = "READ"
    assert d.send(body | {"sig": sig})["decision"] == "DENY"
    with pytest.raises(ValueError):
        d.build_request("bogus", "temperature", "WRITE")


def test_fleet():
    c, _ = make_mock()
    devs = make_fleet(c, PSK, 13)
    assert len({d.did for d in devs}) == 13
    assert [d.meta["role"] for d in devs[:6]] == ROLES
    assert devs[6].meta["role"] == ROLES[0]
    assert all(d.meta.keys() == {"device_type", "role", "vendor", "fw"} for d in devs)
    onboard_fleet(devs[:1])
    assert devs[0].session_id == "s1"


def test_new_state(monkeypatch):
    class Reg:
        def __init__(self, path=None):
            self.path = path

    mod = types.ModuleType("iiot.merkle.registry")
    mod.RootRegistry = Reg
    monkeypatch.setitem(sys.modules, "iiot.merkle", types.ModuleType("iiot.merkle"))
    monkeypatch.setitem(sys.modules, "iiot.merkle.registry", mod)
    s = new_state(FogConfig(psk=PSK, admin_key="a", registry_path="x.json"))
    assert s.registry.path == "x.json" and len(s.fog_pk) == 130
    assert s.current_epoch == 0 and s.pending == [] and s.lock is not None
    assert new_state(FogConfig(PSK, "a")).sessions is not s.sessions
