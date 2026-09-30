import copy

from iiot.attacks import case, close_batch, mk, onboard, resign, say, summarize
from iiot.common.crypto import gen_keypair, sha256_hex
from iiot.common.models import DID_MISMATCH, PROOF_INVALID

EXP = (PROOF_INVALID, DID_MISMATCH)


def run(client, admin_key: str, psk: bytes) -> dict:
    a, b = mk(client, psk), mk(client, psk, "pressure_sensor")
    onboard([a, b])
    close_batch(client, admin_key)
    a.fetch_proof()
    pre = a.access("proof", "temperature", "WRITE").get("decision") == "ALLOW"
    say(f"baseline proof-mode request -> {'ALLOW' if pre else 'DENY'}")
    cases = []

    body = resign(a.build_request("proof", "temperature", "WRITE"), a.sk)
    body["did"] = b.did
    cases.append(case("modified_did", EXP, a.send(resign(body, a.sk))))

    esk, evil_pk = gen_keypair()
    body = a.build_request("proof", "temperature", "WRITE")
    body["pk"] = evil_pk
    cases.append(case("modified_pk", EXP, a.send(resign(body, esk))))

    body = a.build_request("proof", "temperature", "WRITE")
    body["proof"] = copy.deepcopy(body["proof"])
    body["proof"][0]["hash"] = sha256_hex(b"forged-sibling")
    cases.append(case("modified_sibling_hash", EXP, a.send(resign(body, a.sk))))

    c = mk(client, psk, "smart_meter")
    onboard([c])
    ep2 = close_batch(client, admin_key)["epoch"]
    body = a.build_request("proof", "temperature", "WRITE")  # old proof, old epoch
    body["epoch"] = ep2  # proof no longer matches this epoch's trusted root
    cases.append(case("wrong_epoch_root", EXP, a.send(resign(body, a.sk))))

    return summarize("tamper", pre, cases, "Merkle verification vs trusted registry root",
                     "verify_proof", "each variant re-signed by attacker so only the Merkle check can catch it")
