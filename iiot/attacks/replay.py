from iiot.attacks import case, close_batch, mk, onboard, say, summarize
from iiot.common.models import NONCE_REUSED


def run(client, admin_key: str, psk: bytes) -> dict:
    dev = mk(client, psk)
    onboard([dev])
    close_batch(client, admin_key)
    dev.fetch_proof()
    body = dev.build_request("proof", "temperature", "WRITE")
    first = dev.send(body)
    pre = first.get("decision") == "ALLOW"
    say(f"baseline request nonce={body['nonce'][:12]} -> {first.get('decision')}")
    second = dev.send(body)  # byte-identical replay
    c = case("replay_identical", NONCE_REUSED, second)
    return summarize("replay", pre, [c], "fog nonce validator", "nonce_unused", 
                     "identical signed body resent; nonce already consumed")
