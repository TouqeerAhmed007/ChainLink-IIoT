import pytest
from fastapi.testclient import TestClient

from iiot.common.crypto import gen_keypair, hmac_hex, make_did, make_leaf, sign
from iiot.common.state import FogConfig
from iiot.fog.app import create_app
from iiot.merkle.tree import verify_proof

PSK = b"test-psk"
ADMIN = "adm-key"
ROLES = ["temperature_sensor", "pressure_sensor", "smart_meter", "camera",
         "valve_controller", "motor_controller"]
H = {"X-Admin-Key": ADMIN}


class Dev:
    def __init__(self, c, i=0):
        self.c = c
        self.sk, self.pk = gen_keypair()
        self.did = make_did(self.pk)
        self.leaf = make_leaf(self.did, self.pk)
        self.meta = {"device_type": "sensor", "role": ROLES[i % 6], "vendor": "v", "fw": "1.0"}

    def auth(self, psk=PSK):
        r = self.c.post("/auth/hello", json={}).json()
        self.sid = r["session_id"]
        mac = hmac_hex(psk, (r["server_nonce"] + self.sid).encode())
        return self.c.post("/auth/psk", json={"session_id": self.sid, "mac": mac})

    def key(self, did=None, pk=None):
        return self.c.post("/register/key", json={
            "session_id": self.sid, "did": did or self.did, "pk": pk or self.pk,
            "meta": self.meta})

    def pop(self, challenge, sk=None):
        sig = sign(sk or self.sk, bytes.fromhex(challenge))
        return self.c.post("/register/pop", json={"session_id": self.sid, "signature": sig})

    def register(self):
        assert self.auth().status_code == 200
        r = self.key()
        assert r.status_code == 200
        return self.pop(r.json()["challenge"])


@pytest.fixture
def env():
    app = create_app(FogConfig(psk=PSK, admin_key=ADMIN))
    return TestClient(app), app.state.fog


def close(c):
    return c.post("/admin/batch/close", headers=H)


def test_full_onboarding_and_single_root(env):
    c, st = env
    devs = [Dev(c, i) for i in range(8)]
    for d in devs:
        r = d.register()
        assert r.status_code == 200
        assert r.json()["registered"] and r.json()["leaf"] == d.leaf and r.json()["open_epoch"] == 1
    assert len(st.pending) == 8 and st.current_epoch == 0 and not st.epochs
    r = close(c)
    assert r.status_code == 200
    b = r.json()
    assert b["epoch"] == 1 and b["count"] == 8 and b["excluded_revoked"] == 0
    assert st.pending == [] and st.current_epoch == 1
    assert st.registry.get_root(1) == b["root"]
    for d in devs:
        assert st.devices[d.did].status == "active"
        p = c.get(f"/proof/{d.did}").json()
        assert p["epoch"] == 1 and p["leaf"] == d.leaf and p["pk"] == d.pk
        assert verify_proof(p["leaf"], p["proof"], st.registry.get_root(p["epoch"]))
    assert c.get("/epoch/1").json() == {"epoch": 1, "root": b["root"], "count": 8}
    reg = c.get("/registry").json()
    assert reg["chain_valid"] and len(reg["blocks"]) == 2


def test_bad_psk_rejected(env):
    c, st = env
    d = Dev(c)
    assert d.auth(psk=b"wrong").status_code == 401
    assert d.key().status_code == 401
    assert d.did not in st.devices


def test_unknown_session_and_bad_admin_key(env):
    c, _ = env
    r = c.post("/auth/psk", json={"session_id": "nope", "mac": "00"})
    assert r.status_code == 404
    assert c.post("/admin/batch/close").status_code == 401
    assert c.post("/admin/batch/close", headers={"X-Admin-Key": "x"}).status_code == 403


def test_bad_pop_rejected_and_challenge_single_use(env):
    c, st = env
    d = Dev(c)
    d.auth()
    ch = d.key().json()["challenge"]
    other_sk, _ = gen_keypair()
    assert d.pop(ch, sk=other_sk).status_code == 401
    assert d.did not in st.devices and st.pending == []
    assert d.pop(ch).status_code == 409


def test_expired_challenge(env):
    c, st = env
    d = Dev(c)
    d.auth()
    ch = d.key().json()["challenge"]
    st.challenge_ts[d.sid] -= 1000
    assert d.pop(ch).status_code == 401
    assert d.did not in st.devices


def test_wrong_did_rejected(env):
    c, st = env
    d, other = Dev(c), Dev(c, 1)
    d.auth()
    assert d.key(did=other.did).status_code == 403
    assert d.did not in st.devices and other.did not in st.devices


def test_malformed_pk_and_role(env):
    c, _ = env
    d = Dev(c)
    d.auth()
    assert d.key(pk="zz").status_code == 422
    d.meta["role"] = "toaster"
    assert d.key().status_code == 422


def test_rekey_same_did_conflict(env):
    c, st = env
    d = Dev(c)
    assert d.register().status_code == 200
    _, pk2 = gen_keypair()
    d2 = Dev(c)
    d2.auth()
    assert d2.key(did=d.did, pk=pk2).status_code == 409
    assert st.devices[d.did].pk == d.pk
    d3 = Dev(c)
    d3.sk, d3.pk, d3.did = d.sk, d.pk, d.did
    d3.auth()
    assert d3.key().status_code == 409
    assert st.pending.count(d.did) == 1


def test_revoked_excluded_and_old_epoch_still_verifies(env):
    c, st = env
    first = [Dev(c, i) for i in range(4)]
    for d in first:
        d.register()
    b1 = close(c).json()
    victim = first[0]
    st.revoked_dids.add(victim.did)
    second = [Dev(c, i) for i in range(4, 6)]
    for d in second:
        d.register()
    b2 = close(c).json()
    assert b2["epoch"] == 2 and b2["count"] == 5 and b2["excluded_revoked"] == 1
    assert b2["root"] != b1["root"]
    root1, root2 = st.registry.get_root(1), st.registry.get_root(2)
    assert (root1, root2) == (b1["root"], b2["root"])
    assert victim.did not in st.epochs[2].proofs
    old = st.epochs[1].proofs[victim.did]
    assert verify_proof(victim.leaf, old, root1)
    assert not verify_proof(victim.leaf, old, root2)
    p = c.get(f"/proof/{victim.did}").json()
    assert p["epoch"] == 1
    for d in first[1:] + second:
        p = c.get(f"/proof/{d.did}").json()
        assert p["epoch"] == 2 and verify_proof(p["leaf"], p["proof"], root2)
    assert c.get("/epoch/99").status_code == 404
    assert c.get("/proof/did:iiot:unknown").status_code == 404
    assert len(st.epochs[1].leaves) == 4


def test_empty_batch_returns_409(env):
    c, st = env
    assert close(c).status_code == 409
    d = Dev(c)
    d.register()
    close(c)
    assert close(c).status_code == 200
    st.revoked_dids.add(d.did)
    assert close(c).status_code == 409
