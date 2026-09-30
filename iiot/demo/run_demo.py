"""Live demo: python -m iiot.demo.run_demo [--tls] [--pause] [--port 8443]"""
from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import time
from pathlib import Path

from rich.console import Console

from iiot.attacks import ROLES, hdr, make_env, mk
from iiot.common.crypto import make_leaf
from iiot.device.device import onboard_fleet
from iiot.merkle.tree import verify_proof

ADMIN, PSK = "demo-admin", b"demo-psk"
con = Console(no_color=os.environ.get("IIOT_NOCOLOR") == "1")
PAUSE = False


def log(msg: str) -> None:
    con.print("  " + msg, markup=False, highlight=False)


def t(x, n: int = 12) -> str:
    return str(x)[:n]


def step(n: int, title: str) -> None:
    if PAUSE and n > 1:
        input("\n  [Enter] for next step...")
    con.rule(f"STEP {n}: {title}", style="cyan")


def dv(d) -> str:
    return f"device={t(d.did, 21)}.. role={d.meta['role'] if isinstance(d.meta, dict) else d.meta.role}"


def show(label: str, resp: dict) -> None:
    ch = {c["name"]: c["ok"] for c in resp.get("checks", [])}
    token = "n/a" if "token_sig" not in ch else (
        "valid" if all(ch.get(k, True) for k in ("token_sig", "token_expiry", "token_revoked")) else "invalid")
    nonce = "not-checked" if "nonce_unused" not in ch else ("fresh" if ch["nonce_unused"] else "reused")
    pf = [ok for k, ok in ch.items() if "proof" in k]
    proof = "n/a" if not pf else ("valid" if all(pf) else "invalid")
    log(f"{label}: decision={resp.get('decision')} reason={resp.get('reason')} proof={proof} "
        f"token={token} nonce={nonce} latency={resp.get('latency_ms')}ms")


def open_env(tls: bool, port: int):
    if not tls:
        client, _, _ = make_env(admin_key=ADMIN, psk=PSK)
        return client, lambda: None
    import httpx
    from iiot.common.tls import ensure_self_signed_cert
    cert, _ = ensure_self_signed_cert("certs")
    proc = subprocess.Popen([sys.executable, "-m", "iiot.fog.serve", "--port", str(port), "--psk",
                             PSK.decode(), "--admin-key", ADMIN, "--cert-dir", "certs"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    verify: object = cert
    deadline = time.time() + 30
    while time.time() < deadline:
        c = httpx.Client(base_url=f"https://127.0.0.1:{port}", verify=verify, timeout=10)
        try:
            c.get("/registry")
            return c, lambda: (c.close(), proc.terminate())
        except httpx.ConnectError as e:
            if verify is not False and ("CERTIFICATE" in str(e).upper() or "SSL" in str(e).upper()):
                log("warning: cert verification failed, falling back to verify=False")
                verify = False
        except httpx.HTTPError:
            pass
        c.close()
        time.sleep(0.3)
    proc.terminate()
    raise RuntimeError("TLS fog server did not start")


def main() -> None:
    global PAUSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--pause", action="store_true")
    ap.add_argument("--port", type=int, default=8443)
    a = ap.parse_args()
    PAUSE = a.pause
    client, close = open_env(a.tls, a.port)
    try:
        demo(client)
    finally:
        close()


def demo(client) -> None:
    H = hdr(ADMIN)
    log(f"transport: {'TLS (uvicorn subprocess)' if 'https' in str(client.base_url) else 'in-process TestClient'}")

    step(1, "Device connects and PSK-authenticates")
    d0 = mk(client, PSK, "temperature_sensor")
    d0.authenticate()
    log(f"{dv(d0)} session={t(d0.session_id)} psk_auth=OK")

    step(2, "DID/key generation and proof-of-possession")
    r = d0.register()
    log(f"{dv(d0)} pk={t(d0.pk)} leaf={t(d0.leaf)} pop=OK status=pending open_epoch={r.get('open_epoch')}")

    step(3, "Devices collected in the open batch")
    devs = {"temperature_sensor": d0}
    for role in ROLES[1:]:
        devs[role] = mk(client, PSK, role)
    onboard_fleet([d for d in devs.values() if d is not d0])
    for role, d in devs.items():
        log(f"{dv(d)} leaf={t(d.leaf)} pending")
    log(f"open batch size={len(devs)} (no tree built yet)")

    step(4, "Batch close, Merkle root, registry anchoring")
    b = client.post("/admin/batch/close", headers=H).json()
    log(f"epoch={b['epoch']} root={t(b['root'])} count={b['count']} tx={t(b['tx_hash'])}")
    reg = client.get("/registry").json()
    blk = reg["blocks"][-1]
    log(f"block#{blk['index']} hash={t(blk['hash'])} prev={t(blk['prev_hash'])} chain_valid={reg['chain_valid']}")

    step(5, "Inclusion proof generation and local verification")
    trusted = client.get(f"/epoch/{b['epoch']}").json()["root"]
    for d in devs.values():
        d.fetch_proof()
        ok = verify_proof(make_leaf(d.did, d.pk), d.proof, trusted)
        log(f"{dv(d)} leaf={t(d.leaf)} root={t(d.root)} proof_len={len(d.proof)} local_verify={ok}")

    step(6, "Late device operates on a temp token while waiting")
    late = mk(client, PSK, "temperature_sensor")
    late.authenticate()
    late.register()
    late.get_temp_token()
    log(f"{dv(late)} leaf={t(late.leaf)} pending, not in any tree; "
        f"/proof status={client.get(f'/proof/{late.did}').status_code}; token={t(late.token)}..")
    show("temp token WRITE temperature", late.access("token", "temperature", "WRITE"))
    show("temp token READ temperature ", late.access("token", "temperature", "READ"))

    step(7, "ALLOW and DENY decisions")
    show("temp sensor WRITE temperature", d0.access("proof", "temperature", "WRITE"))
    show("temp sensor STOP production_line", d0.access("proof", "production_line", "STOP"))
    show("valve ctrl STOP production_line", devs["valve_controller"].access("proof", "production_line", "STOP"))

    step(8, "Revocation, old proof vs current status, next batch")
    cam = devs["camera"]
    show("camera WRITE video (before)", cam.access("proof", "video", "WRITE"))
    rv = client.post("/admin/revoke", json={"did": cam.did, "reason": "demo"}, headers=H).json()
    log(f"revoked {t(cam.did, 21)}.. tokens_invalidated={rv.get('tokens_invalidated')}")
    show("camera WRITE video (after) ", cam.access("proof", "video", "WRITE"))
    st = client.get(f"/status/{cam.did}").json()
    log(f"old proof still valid vs epoch-{b['epoch']} root: "
        f"{verify_proof(cam.leaf, cam.proof, trusted)}; current status={st['status']} revoked={st['revoked']}")
    b2 = client.post("/admin/batch/close", headers=H).json()
    log(f"epoch={b2['epoch']} root={t(b2['root'])} count={b2['count']} excluded_revoked={b2['excluded_revoked']}")
    log(f"revoked leaf verifies against new root: {verify_proof(cam.leaf, cam.proof, b2['root'])}")
    late.fetch_proof()
    log(f"late device now in epoch={late.epoch} root={t(late.root)} "
        f"local_verify={verify_proof(late.leaf, late.proof, b2['root'])}")

    step(9, "Attack suite")
    from iiot.attacks.run_all import run_all
    res = run_all(verbose=False)
    log(f"attacks blocked: {sum(r['blocked'] for r in res)}/{len(res)}")

    step(10, "Performance results")
    rdir = Path(__file__).resolve().parents[1] / "results"
    files = sorted(rdir.glob("*.csv")) if rdir.exists() else []
    if not files:
        log("no results/*.csv found: run the perf suite first (see README.md)")
    for f in files:
        with open(f, newline="") as fh:
            rows = list(csv.reader(fh))
        log(f"{f.name}: {max(len(rows) - 1, 0)} rows, columns={','.join(rows[0]) if rows else '-'}")
    log("plots and analysis: results/ and README.md")


if __name__ == "__main__":
    main()
