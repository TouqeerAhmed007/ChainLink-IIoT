import os
os.environ["IIOT_NOCOLOR"] = "1"
import argparse
import csv
import time
from pathlib import Path

import numpy as np

from iiot.common.crypto import gen_keypair, make_did, make_leaf
from iiot.merkle.registry import RootRegistry
from iiot.merkle.tree import build_tree, verify_proof
from iiot.perf.bench import DEFAULT_COUNTS, RESULTS, quiet


def _leaves(n):
    out = []
    for _ in range(n):
        _, pk = gen_keypair()
        out.append(make_leaf(make_did(pk), pk))
    return out


def individual(leaves):
    reg, issued, updates, events, prev = RootRegistry(), {}, 0, 0, None
    t0 = time.perf_counter()
    for i, leaf in enumerate(leaves):
        tree = build_tree(leaves[: i + 1])
        root = tree.root
        reg.anchor(i + 1, root, i + 1)
        updates += 1
        issued[leaf] = tree.proof(leaf)
        if prev is not None and root != prev:
            events += i
        prev = root
    total = (time.perf_counter() - t0) * 1e3
    stale = sum(not verify_proof(l, p, prev) for l, p in issued.items())
    return total, updates, len(reg.blocks()), stale, events


def batch(leaves):
    reg = RootRegistry()
    t0 = time.perf_counter()
    tree = build_tree(leaves)
    root = tree.root
    reg.anchor(1, root, len(leaves))
    proofs = tree.all_proofs()
    total = (time.perf_counter() - t0) * 1e3
    stale = sum(not verify_proof(l, p, root) for l, p in proofs.items())
    return total, 1, len(reg.blocks()), stale, 0


def run_experiment(counts=None, runs=5, out_dir=RESULTS):
    quiet()
    counts = list(counts or DEFAULT_COUNTS)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "batch_vs_individual.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["n_devices", "mode", "runs", "total_ms_mean", "total_ms_std", "root_updates",
                    "registry_blocks", "stale_proofs_final", "stale_proof_events",
                    "amortized_ms_per_device_mean", "amortized_ms_per_device_std"])
        for n in counts:
            res = {"individual": [], "batch": []}
            for _ in range(runs):
                lv = _leaves(n)
                res["individual"].append(individual(lv))
                res["batch"].append(batch(lv))
            for mode, rs in res.items():
                tot = [r[0] for r in rs]
                dd = 1 if runs > 1 else 0
                last = rs[-1]
                w.writerow([n, mode, runs, f"{np.mean(tot):.6f}", f"{np.std(tot, ddof=dd):.6f}",
                            last[1], last[2], last[3], last[4],
                            f"{np.mean(tot) / n:.6f}", f"{np.std(tot, ddof=dd) / n:.6f}"])
            print(f"[ivb] N={n} done", flush=True)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--counts", type=int, nargs="+", default=DEFAULT_COUNTS)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--out", default=str(RESULTS))
    a = ap.parse_args()
    print(run_experiment(a.counts, a.runs, a.out))


if __name__ == "__main__":
    main()
