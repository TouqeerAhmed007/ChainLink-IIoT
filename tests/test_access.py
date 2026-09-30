import copy
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from iiot.common import crypto
from iiot.common.models import (BAD_REQUEST_SIG, DID_MISMATCH, DID_REVOKED, NONCE_REUSED,
                                POLICY_DENIED, PROOF_INVALID, STALE_TS, TOKEN_EXPIRED,
                                TOKEN_REVOKED, UNKNOWN_EPOCH, DeviceMeta, DeviceRecord,
                                EpochRecord, Session)
from iiot.common.state import FogConfig, new_state
from iiot.fog import policy, tokens
from iiot.fog.access import evaluate_access, router
from iiot.merkle.tree import build_tree

ROLES = ["temperature_sensor", "pressure_sensor", "smart_meter", "camera",
         "valve_controller", "motor_controller"]
ADMIN = {"X-Admin-Key": "adm"}


class Dev:
    def __init__(self, role, state):
        self.role = role
        self.sk, self.pk = crypto.gen_keypair()
        self.did = crypto.make_did(self.pk)
        self.leaf = crypto.make_leaf(self.did, self.pk)
        self.meta = DeviceMeta(device_type=role, role=role, vendor="acme", fw="1.0")
        self.token = None
        state.devices[self.did] = DeviceRecord(
            did=self.did, pk=self.pk, meta=self.meta, leaf=self.leaf,
            registered_at=time.time(), status="active")


class Env:
    pass


@pytest.fixture
def env():
    e = Env()
    e.state = new_state(FogConfig(psk=b"psk", admin_key="adm"))
    e.devs = {r: Dev(r, e.state) for r in ROLES}
    tree = build_tree([d.leaf for d in e.devs.values()])
    allp = tree.all_proofs()
    block = e.state.registry.anchor(1, tree.root, len(tree.leaves))
    e.state.epochs[1] = EpochRecord(
        epoch=1, root=tree.root, leaves=tree.leaves,
        proofs={d.did: allp[d.leaf] for d in e.devs.values()},
        created_at=time.time(), count=len(tree.leaves), tx_hash=block["hash"])
    e.state.current_epoch = 1
    app = FastAPI()
    app.include_router(router)
    app.state.fog = e.state
    e.client = TestClient(app)
    return e


def session_for(e, dev):
    sid = secrets.token_hex(8)
    e.state.sessions[sid] = Session(
        session_id=sid, server_nonce="n", authenticated=True, did=dev.did, pk=dev.pk,
        meta=dev.meta, challenge="", pop_verified=True, created=time.time())
    return sid


def get_token(e, dev):
    r = e.client.post("/token/temp", json={"session_id": session_for(e, dev)})
    assert r.status_code == 200
    dev.token = r.json()["token"]
    return dev.token


def req(e, dev, mode, resource, op, signer=None, **kw):
    b = {"mode": mode, "did": dev.did, "nonce": secrets.token_hex(8), "ts": time.time(),
         "resource": resource, "operation": op}
    if mode == "token":
        b["token"] = dev.token
    else:
        b.update(pk=dev.pk, epoch=1, proof=e.state.epochs[1].proofs.get(dev.did, []))
    b.update(kw)
    b["sig"] = crypto.sign((signer or dev).sk, crypto.canonical(b))
    return b


def post(e, body):
    r = e.client.post("/resource/access", json=body)
    assert r.status_code == 200
    return r.json()


def test_policy_table():
    assert policy.is_allowed("valve_controller", "valve", "OPEN")
    assert policy.is_allowed("motor_controller", "production_line", "STOP")
    assert not policy.is_allowed("temperature_sensor", "production_line", "STOP")
    assert policy.is_allowed("camera", "video", "WRITE", temp=True)
    assert not policy.is_allowed("valve_controller", "valve", "OPEN", temp=True)
    assert not policy.is_allowed("camera", "temperature", "WRITE", temp=True)


def test_temp_token_allow(env):
    d = env.devs["temperature_sensor"]
    get_token(env, d)
    ok, reason, payload = tokens.validate_token(env.state, d.token)
    assert ok and payload["did"] == d.did and payload["scope"] == "temp"
    assert payload["token_id"] in env.state.issued_tokens
    r = post(env, req(env, d, "token", "temperature", "WRITE"))
    assert r["decision"] == "ALLOW" and r["reason"] == "OK"
    assert [c["name"] for c in r["checks"]][:3] == ["request_sig_shape", "token_sig", "token_expiry"]
    assert r["latency_ms"] < 100


def test_token_endpoint_requires_pop_and_queues(env):
    d = env.devs["camera"]
    sid = session_for(env, d)
    env.state.sessions[sid].pop_verified = False
    assert env.client.post("/token/temp", json={"session_id": sid}).status_code == 403
    assert env.client.post("/token/temp", json={"session_id": "nope"}).status_code == 401
    new = Dev("camera", env.state)
    del env.state.devices[new.did]
    get_token(env, new)
    get_token(env, new)
    assert new.did in env.state.devices and env.state.pending.count(new.did) == 1


def _sess(env, d):
    return env.state.sessions[session_for(env, d)]


def test_expired_token(env):
    d = env.devs["pressure_sensor"]
    d.token = tokens.issue_temp_token(env.state, _sess(env, d), now=time.time() - 1000)["token"]
    r = post(env, req(env, d, "token", "pressure", "WRITE"))
    assert (r["decision"], r["reason"]) == ("DENY", TOKEN_EXPIRED)


def test_revoked_token_and_immediate_effect(env):
    d = env.devs["smart_meter"]
    get_token(env, d)
    assert post(env, req(env, d, "token", "energy", "WRITE"))["decision"] == "ALLOW"
    assert env.client.post("/admin/revoke", json={"did": d.did}).status_code == 403
    r = env.client.post("/admin/revoke", json={"did": d.did}, headers=ADMIN).json()
    assert r == {"revoked": True, "tokens_invalidated": 1}
    r = post(env, req(env, d, "token", "energy", "WRITE"))
    assert (r["decision"], r["reason"]) == ("DENY", TOKEN_REVOKED)
    assert env.state.devices[d.did].status == "revoked"
    assert env.client.post("/token/temp", json={"session_id": session_for(env, d)}).status_code == 403
    st = env.client.get(f"/status/{d.did}").json()
    assert st["revoked"] and st["status"] == "revoked" and st["epochs"] == [1]


def test_replayed_nonce_and_per_did_namespace(env):
    a, b = env.devs["temperature_sensor"], env.devs["pressure_sensor"]
    get_token(env, a)
    get_token(env, b)
    body = req(env, a, "token", "temperature", "WRITE", nonce="fixed")
    assert post(env, body)["decision"] == "ALLOW"
    r = post(env, body)
    assert (r["decision"], r["reason"]) == ("DENY", NONCE_REUSED)
    assert post(env, req(env, b, "token", "pressure", "WRITE", nonce="fixed"))["decision"] == "ALLOW"


def test_concurrent_replay_single_winner(env):
    d = env.devs["temperature_sensor"]
    get_token(env, d)
    body = req(env, d, "token", "temperature", "WRITE")
    with ThreadPoolExecutor(16) as ex:
        res = list(ex.map(lambda _: evaluate_access(env.state, dict(body)), range(32)))
    assert sum(r["decision"] == "ALLOW" for r in res) == 1


def test_stolen_token_other_key(env):
    victim, attacker = env.devs["temperature_sensor"], env.devs["camera"]
    get_token(env, victim)
    attacker.token = victim.token
    r = post(env, req(env, attacker, "token", "temperature", "WRITE"))
    assert (r["decision"], r["reason"]) == ("DENY", DID_MISMATCH)
    r = post(env, req(env, victim, "token", "temperature", "WRITE", signer=attacker))
    assert (r["decision"], r["reason"]) == ("DENY", BAD_REQUEST_SIG)


def test_tampered_token(env):
    d = env.devs["temperature_sensor"]
    get_token(env, d)
    head, sig = d.token.split(".")
    d.token = head[:-2] + ("AA" if head[-2:] != "AA" else "BB") + "." + sig
    r = post(env, req(env, d, "token", "temperature", "WRITE"))
    assert r["decision"] == "DENY" and r["reason"] == "BAD_TOKEN_SIG"


def test_proof_mode_allow_and_tampered_proof(env):
    d = env.devs["valve_controller"]
    assert post(env, req(env, d, "proof", "valve", "OPEN"))["decision"] == "ALLOW"
    assert post(env, req(env, d, "proof", "production_line", "STOP"))["decision"] == "ALLOW"
    bad = copy.deepcopy(env.state.epochs[1].proofs[d.did])
    bad[0]["hash"] = "00" * 32
    r = post(env, req(env, d, "proof", "valve", "OPEN", proof=bad))
    assert (r["decision"], r["reason"]) == ("DENY", PROOF_INVALID)


def test_proof_wrong_epoch_and_untrusted_root(env):
    d = env.devs["valve_controller"]
    r = post(env, req(env, d, "proof", "valve", "OPEN", epoch=99))
    assert (r["decision"], r["reason"]) == ("DENY", UNKNOWN_EPOCH)
    rogue = Dev("valve_controller", env.state)
    r = post(env, req(env, rogue, "proof", "valve", "OPEN", proof=env.state.epochs[1].proofs[d.did]))
    assert r["reason"] == PROOF_INVALID


def test_policy_deny_identity_vs_authorization(env):
    d = env.devs["temperature_sensor"]
    get_token(env, d)
    r = post(env, req(env, d, "token", "production_line", "STOP"))
    assert (r["decision"], r["reason"]) == ("DENY", POLICY_DENIED)
    assert all(c["ok"] for c in r["checks"][:-1]) and not r["checks"][-1]["ok"]
    r = post(env, req(env, d, "proof", "production_line", "STOP"))
    assert (r["decision"], r["reason"]) == ("DENY", POLICY_DENIED)
    r = post(env, req(env, d, "proof", "temperature", "WRITE"))
    assert r["decision"] == "ALLOW"


def test_revoked_did_with_valid_old_proof(env):
    d = env.devs["motor_controller"]
    assert post(env, req(env, d, "proof", "motor", "START"))["decision"] == "ALLOW"
    env.client.post("/admin/revoke", json={"did": d.did}, headers=ADMIN)
    r = post(env, req(env, d, "proof", "motor", "START"))
    assert (r["decision"], r["reason"]) == ("DENY", DID_REVOKED)
    by = {c["name"]: c["ok"] for c in r["checks"]}
    assert by["proof_valid"] is True and by["did_revoked"] is False


def test_stale_timestamp_and_bad_shape(env):
    d = env.devs["temperature_sensor"]
    get_token(env, d)
    r = post(env, req(env, d, "token", "temperature", "WRITE", ts=time.time() - 3600))
    assert (r["decision"], r["reason"]) == ("DENY", STALE_TS)
    r = post(env, {"mode": "token", "did": d.did})
    assert (r["decision"], r["reason"]) == ("DENY", BAD_REQUEST_SIG)
    assert r["checks"][0]["name"] == "request_sig_shape"


def test_nonce_sweep_bounds_store(env):
    d = env.devs["temperature_sensor"]
    env.state.config.token_ttl_s = 300
    get_token(env, d)
    t = time.time()
    for i in range(50):
        evaluate_access(env.state, req(env, d, "token", "temperature", "WRITE", ts=t), now=t)
    assert len(env.state.used_nonces) == 50
    later = t + 3 * env.state.config.ts_skew_s + 5
    evaluate_access(env.state, req(env, d, "token", "temperature", "WRITE", ts=later), now=later)
    assert len(env.state.used_nonces) <= 2
