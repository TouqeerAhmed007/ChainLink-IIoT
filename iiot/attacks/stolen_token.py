from iiot.attacks import case, mk, onboard, say, summarize
from iiot.attacks import baseline
from iiot.common.crypto import canonical, sign
from iiot.common.models import BAD_REQUEST_SIG, DID_MISMATCH


def run(client, admin_key: str, psk: bytes) -> dict:
    a, b = mk(client, psk), mk(client, psk)
    onboard([a, b])
    a.get_temp_token()
    pre = baseline(a, "token")
    say("baseline: A uses own token -> " + ("ALLOW" if pre else "DENY"))
    cases = []

    b.token = a.token  # B steals A's token, signs with its own key
    cases.append(case("stolen_token_own_sig", DID_MISMATCH, b.access("token", "temperature", "WRITE")))

    body = a.build_request("token", "temperature", "WRITE")  # A's did+token, forged signature
    unsigned = {k: v for k, v in body.items() if k != "sig"}
    body["sig"] = sign(b.sk, canonical(unsigned))
    cases.append(case("stolen_token_forged_sig", BAD_REQUEST_SIG, a.send(body)))

    return summarize("stolen_token", pre, cases, "fog request-signature validator",
                     "did_match / request_sig",
                     "token alone is insufficient: request-level proof-of-possession is required")
