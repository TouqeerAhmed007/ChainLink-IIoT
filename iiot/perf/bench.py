import os
os.environ["IIOT_NOCOLOR"] = "1"
import argparse
import csv
import logging
import time
from pathlib import Path

import numpy as np
from fastapi.testclient import TestClient

from iiot.common.state import FogConfig
from iiot.device.device import make_fleet
from iiot.fog.app import create_app
from iiot.merkle.tree import build_tree, verify_proof

RESULTS = Path(__file__).resolve().parents[1] / "results"
DEFAULT_COUNTS = [5, 10, 25, 50, 100]
PSK = b"perf-psk"
ADMIN = "perf-admin"
HDR = {"X-Admin-Key": ADMIN}

PROOF_ALLOW = {
    "temperature_sensor": ("temperature", "WRITE"),
    "pressure_sensor": ("pressure", "WRITE"),
    "smart_meter": ("energy", "WRITE"),
    "camera": ("video", "WRITE"),
    "valve_controller": ("valve", "OPEN"),
    "motor_controller": ("motor", "START"),
}
TOKEN_ALLOW = {k: v for k, v in PROOF_ALLOW.items() if v[1] == "WRITE"}
DENY = ("production_line", "WRITE")


def quiet():
    logging.disable(logging.CRITICAL)


def role_of(d):
    m = d.meta
    return m["role"] if isinstance(m, dict) else m.role


def timed(fn, *a, **k):
    t = time.perf_counter()
    r = fn(*a, **k)
    return r, (time.perf_counter() - t) * 1e3


def _access(rows, metric, mode, devs, pick, want):
    t0 = time.perf_counter()
    for i, d in enumerate(devs):
        res, ms = timed(d.access, mode, *pick(d))
        if res.get("decision") != want:
            raise RuntimeError(f"{metric}: {d.did} expected {want}, got {res}")
        rows.append((metric, i, ms, "ms"))
    return time.perf_counter() - t0


def run_once(n):
    rows = []
    app = create_app(FogConfig(psk=PSK, admin_key=ADMIN, registry_path=None))
    with TestClient(app) as client:
        devs = make_fleet(client, PSK, n)

        t_all = time.perf_counter()
        for i, d in enumerate(devs):
            _, ms = timed(lambda d=d: (d.authenticate(), d.register()))
            rows.append(("registration_ms", i, ms, "ms"))
        rows.append(("throughput_registrations_per_s", "", n / (time.perf_counter() - t_all), "per_s"))

        r, ms = timed(client.post, "/admin/batch/close", headers=HDR)
        if r.status_code != 200:
            raise RuntimeError(f"batch close failed: {r.status_code} {r.text}")
        rows.append(("batch_close_ms", "", ms, "ms"))

        leaves = [d.leaf for d in devs]
        t = time.perf_counter()
        tree = build_tree(sorted(set(leaves)))
        _ = tree.root
        rows.append(("batch_compute_ms", "", (time.perf_counter() - t) * 1e3, "ms"))
        _, ms = timed(tree.all_proofs)
        rows.append(("proof_all_ms", "", ms, "ms"))

        for i, d in enumerate(devs):
            _, ms = timed(d.fetch_proof)
            rows.append(("proof_http_ms", i, ms, "ms"))
        for i, d in enumerate(devs):
            ok, ms = timed(verify_proof, d.leaf, d.proof, d.root)
            if not ok:
                raise RuntimeError(f"local proof invalid for {d.did}")
            rows.append(("verify_local_ms", i, ms, "ms"))

        allow = lambda d: PROOF_ALLOW[role_of(d)]
        deny = lambda d: DENY
        wall = _access(rows, "access_proof_allow_ms", "proof", devs, allow, "ALLOW")
        rows.append(("throughput_verifications_per_s", "", n / wall, "per_s"))
        _access(rows, "access_proof_deny_ms", "proof", devs, deny, "DENY")

        for i, d in enumerate(devs):
            _, ms = timed(d.get_temp_token)
            rows.append(("token_issue_ms", i, ms, "ms"))
        tsub = [d for d in devs if role_of(d) in TOKEN_ALLOW]
        if tsub:
            _access(rows, "access_token_allow_ms", "token", tsub, lambda d: TOKEN_ALLOW[role_of(d)], "ALLOW")
        _access(rows, "access_token_deny_ms", "token", devs, deny, "DENY")
    return rows


def summarize(raw):
    per, unit = {}, {}
    for n, run, m, _idx, v, u in raw:
        per.setdefault((n, m), {}).setdefault(run, []).append(v)
        unit[m] = u
    out = []
    for (n, m), runs in sorted(per.items(), key=lambda kv: kv[0][0]):
        means = [float(np.mean(v)) for v in runs.values()]
        p95s = [float(np.percentile(v, 95)) for v in runs.values()]
        dd = 1 if len(means) > 1 else 0
        out.append((n, m, unit[m], len(means), float(np.mean(means)), float(np.std(means, ddof=dd)),
                    float(np.mean(p95s)), float(np.std(p95s, ddof=dd))))
    return out


def run_bench(counts=None, runs=5, out_dir=RESULTS):
    quiet()
    counts = list(counts or DEFAULT_COUNTS)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_once(5)  # warm-up, discarded
    raw = []
    for n in counts:
        for run in range(runs):
            t = time.perf_counter()
            raw.extend((n, run, m, idx, v, u) for m, idx, v, u in run_once(n))
            print(f"[bench] N={n} run={run + 1}/{runs} {time.perf_counter() - t:.1f}s", flush=True)
    raw_p, sum_p = out_dir / "raw_measurements.csv", out_dir / "summary.csv"
    with open(raw_p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["n_devices", "run", "metric", "sample_idx", "value", "unit"])
        for n, run, m, idx, v, u in raw:
            w.writerow([n, run, m, idx, f"{v:.6f}", u])
    with open(sum_p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["n_devices", "metric", "unit", "runs", "mean", "std", "p95_mean", "p95_std"])
        for r in summarize(raw):
            w.writerow(list(r[:4]) + [f"{x:.6f}" for x in r[4:]])
    return raw_p, sum_p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--counts", type=int, nargs="+", default=DEFAULT_COUNTS)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--out", default=str(RESULTS))
    a = ap.parse_args()
    for p in run_bench(a.counts, a.runs, a.out):
        print(p)


if __name__ == "__main__":
    main()
