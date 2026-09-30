import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from iiot.perf.bench import RESULTS

plt.rcParams.update({"font.size": 9})


def load_summary(p):
    d = {}
    with open(p, newline="") as f:
        for r in csv.DictReader(f):
            d.setdefault(r["metric"], []).append((int(r["n_devices"]), float(r["mean"]), float(r["std"])))
    return d


def load_bvi(p):
    with open(p, newline="") as f:
        return list(csv.DictReader(f))


def _plot(path, title, series, ylabel, logy=False):
    fig, ax = plt.subplots(figsize=(5.5, 3.8))
    for label, pts in series:
        if not pts:
            continue
        x, y, e = zip(*pts)
        ax.errorbar(x, y, yerr=e, marker="o", capsize=3, lw=1.4, label=label)
    ax.set_xlabel("Number of devices (N)")
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=10)
    if logy:
        ax.set_yscale("log")
    ax.grid(True, alpha=0.3, which="both")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def make_plots(out_dir=RESULTS):
    out = Path(out_dir)
    s = load_summary(out / "summary.csv")
    g = lambda m: s.get(m, [])
    paths = []
    p = out / "graph1_devices_vs_batch_time.png"
    _plot(p, "Batch processing time vs. devices",
          [("POST /admin/batch/close", g("batch_close_ms")),
           ("sort + build_tree + root", g("batch_compute_ms")),
           ("all_proofs()", g("proof_all_ms"))], "Time (ms)", logy=True)
    paths.append(p)
    p = out / "graph2_devices_vs_verification_latency.png"
    _plot(p, "Verification latency vs. devices",
          [("Local verify_proof", g("verify_local_ms")),
           ("Proof-mode access (ALLOW)", g("access_proof_allow_ms")),
           ("Token-mode access (ALLOW)", g("access_token_allow_ms"))], "Latency (ms)", logy=True)
    paths.append(p)
    p = out / "graph3_devices_vs_throughput.png"
    _plot(p, "Throughput vs. devices",
          [("Registrations/s", g("throughput_registrations_per_s")),
           ("Verifications/s (proof mode)", g("throughput_verifications_per_s"))], "Operations per second")
    paths.append(p)

    rows = load_bvi(out / "batch_vs_individual.csv")
    ns = sorted({int(r["n_devices"]) for r in rows})
    get = lambda mode, col: [float(next(r[col] for r in rows if r["mode"] == mode and int(r["n_devices"]) == n)) for n in ns]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 3.6))
    for mode in ("individual", "batch"):
        a1.errorbar(ns, get(mode, "total_ms_mean"), yerr=get(mode, "total_ms_std"), marker="o", capsize=3, lw=1.4, label=mode)
    a1.set_yscale("log")
    a1.set_xlabel("Number of devices (N)")
    a1.set_ylabel("Total time (ms)")
    a1.set_title("Total root-maintenance time", fontsize=10)
    a1.grid(True, alpha=0.3, which="both")
    a1.legend(fontsize=8)
    x, w = np.arange(len(ns)), 0.2
    bars = [("Blocks (individual)", get("individual", "registry_blocks")), ("Blocks (batch)", get("batch", "registry_blocks")),
            ("Stale proofs (individual)", get("individual", "stale_proofs_final")), ("Stale proofs (batch)", get("batch", "stale_proofs_final"))]
    for k, (lab, vals) in enumerate(bars):
        a2.bar(x + (k - 1.5) * w, vals, w, label=lab)
    a2.set_xticks(x)
    a2.set_xticklabels(ns)
    a2.set_xlabel("Number of devices (N)")
    a2.set_ylabel("Count")
    a2.set_title("Registry blocks and stale proofs", fontsize=10)
    a2.grid(True, axis="y", alpha=0.3)
    a2.legend(fontsize=7)
    fig.tight_layout()
    p = out / "graph4_batch_vs_individual.png"
    fig.savefig(p, dpi=200)
    plt.close(fig)
    paths.append(p)
    return paths


def markdown_tables(out_dir=RESULTS):
    out = Path(out_dir)
    s = load_summary(out / "summary.csv")
    cols = [("Registration (ms/dev)", "registration_ms", 3), ("Batch close (ms)", "batch_close_ms", 3),
            ("Compute root (ms)", "batch_compute_ms", 3), ("all_proofs (ms)", "proof_all_ms", 3),
            ("Local verify (ms)", "verify_local_ms", 4), ("Proof access (ms)", "access_proof_allow_ms", 3),
            ("Token access (ms)", "access_token_allow_ms", 3), ("Reg/s", "throughput_registrations_per_s", 1),
            ("Verif/s", "throughput_verifications_per_s", 1)]
    ns = sorted({n for pts in s.values() for n, _, _ in pts})
    lines = ["| N | " + " | ".join(c[0] for c in cols) + " |", "|" + "---|" * (len(cols) + 1)]
    for n in ns:
        cells = []
        for _, m, d in cols:
            v = next(((mu, sd) for nn, mu, sd in s.get(m, []) if nn == n), None)
            cells.append(f"{v[0]:.{d}f} ± {v[1]:.{d}f}" if v else "-")
        lines.append(f"| {n} | " + " | ".join(cells) + " |")
    rows = load_bvi(out / "batch_vs_individual.csv")
    lines += ["", "| N | Mode | Total (ms) | Root updates | Blocks | Stale proofs | Stale events | ms/device |", "|" + "---|" * 8]
    for r in rows:
        lines.append(f"| {r['n_devices']} | {r['mode']} | {float(r['total_ms_mean']):.3f} ± {float(r['total_ms_std']):.3f} | "
                     f"{r['root_updates']} | {r['registry_blocks']} | {r['stale_proofs_final']} | {r['stale_proof_events']} | "
                     f"{float(r['amortized_ms_per_device_mean']):.4f} |")
    return "\n".join(lines)


def main():
    for p in make_plots():
        print(p)
    print(markdown_tables())


if __name__ == "__main__":
    main()
