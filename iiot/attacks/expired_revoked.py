import time

from iiot.attacks import baseline, case, hdr, make_env, mk, onboard, say, summarize
from iiot.common.models import DID_REVOKED, TOKEN_EXPIRED, TOKEN_REVOKED


def run(client, admin_key: str, psk: bytes) -> dict:
    cases, pre = [], True

    c2, _, psk2 = make_env(ttl=1)  # dedicated app with 1s token TTL
    d = mk(c2, psk2)
    onboard([d])
    d.get_temp_token()
    ok = baseline(d, "token")
    pre &= ok
    say(f"baseline (ttl=1s) -> {'ALLOW' if ok else 'DENY'}; waiting for expiry")
    time.sleep(2.2)
    cases.append(case("expired_token", TOKEN_EXPIRED, d.access("token", "temperature", "WRITE")))

    r = mk(client, psk)
    onboard([r])
    r.get_temp_token()
    ok = baseline(r, "token")
    pre &= ok
    rv = client.post("/admin/revoke", json={"did": r.did, "reason": "attack-test"},
                     headers=hdr(admin_key)).json()
    say(f"revoked device, tokens_invalidated={rv.get('tokens_invalidated')}")
    cases.append(case("revoked_token", (TOKEN_REVOKED, DID_REVOKED), r.access("token", "temperature", "WRITE")))

    return summarize("expired_revoked", pre, cases, "fog token validator",
                     "token_expiry / token_revoked",
                     "expiry via 1s-TTL app; revocation via /admin/revoke takes effect immediately")
