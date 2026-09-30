from iiot.attacks import case, mk, onboard, say, summarize
from iiot.common.crypto import gen_keypair, hmac_hex, make_did, sign

META = {"device_type": "rogue", "role": "temperature_sensor", "vendor": "evil", "fw": "0.1"}


def _rejected(r, key: str) -> dict:
    try:
        bad = r.status_code >= 400 or r.json().get(key) is not True
    except Exception:
        bad = True
    return {"decision": "DENY" if bad else "ALLOW", "reason": "REJECTED" if bad else "ACCEPTED"}


def _hello(client):
    j = client.post("/auth/hello", json={}).json()
    return j["session_id"], j["server_nonce"]


def run(client, admin_key: str, psk: bytes) -> dict:
    legit = mk(client, psk)
    onboard([legit])
    sid, nonce = _hello(client)
    pre = client.post("/auth/psk", json={"session_id": sid, "mac": hmac_hex(psk, (nonce + sid).encode())}
                      ).json().get("authenticated") is True
    say(f"baseline legitimate PSK auth -> {'OK' if pre else 'FAIL'}")
    cases = []

    sid, nonce = _hello(client)
    r = client.post("/auth/psk", json={"session_id": sid, "mac": hmac_hex(b"wrong-psk", (nonce + sid).encode())})
    cases.append(case("rogue_without_psk", "REJECTED", _rejected(r, "authenticated")))

    sk, pk = gen_keypair()
    r = client.post("/register/key", json={"session_id": sid, "did": make_did(pk), "pk": pk, "meta": META})
    cases.append(case("register_unauthenticated", "REJECTED", _rejected(r, "challenge")))

    sid, nonce = _hello(client)
    client.post("/auth/psk", json={"session_id": sid, "mac": hmac_hex(psk, (nonce + sid).encode())})
    r = client.post("/register/key", json={"session_id": sid, "did": make_did(pk), "pk": pk, "meta": META})
    ch = r.json().get("challenge")
    other_sk, _ = gen_keypair()
    r = client.post("/register/pop", json={"session_id": sid,
                                           "signature": sign(other_sk, bytes.fromhex(ch or "00"))})
    cases.append(case("pop_key_mismatch", "REJECTED", _rejected(r, "registered")))

    res = summarize("extra", pre, cases, "fog PSK check / PoP verification",
                    "auth_psk / register_pop",
                    "rejection is HTTP-level (attack_result REJECTED), not a resource reason code")
    return res
