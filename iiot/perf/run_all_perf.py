import os
os.environ["IIOT_NOCOLOR"] = "1"
import argparse
import platform
import sys
from importlib import metadata

from iiot.perf import bench, individual_vs_batch, plots


def cpu_model():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def environment():
    pk = []
    for name in ("fastapi", "uvicorn", "httpx", "cryptography", "pydantic", "numpy", "matplotlib"):
        try:
            pk.append(f"{name}=={metadata.version(name)}")
        except metadata.PackageNotFoundError:
            pass
    return "\n".join([f"cpu: {cpu_model()}", f"cores: {os.cpu_count()}", f"os: {platform.platform()}",
                      f"python: {sys.version.split()[0]}", "packages: " + ", ".join(pk)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--counts", type=int, nargs="+", default=bench.DEFAULT_COUNTS)
    ap.add_argument("--runs", type=int, default=5)
    a = ap.parse_args()
    res = bench.RESULTS
    res.mkdir(parents=True, exist_ok=True)
    env = environment()
    (res / "environment.txt").write_text(env + "\n")
    print(env)
    bench.run_bench(a.counts, a.runs, res)
    individual_vs_batch.run_experiment(a.counts, a.runs, res)
    pngs = plots.make_plots(res)
    print(plots.markdown_tables(res))
    print(f"\nOutputs in {res}:")
    for p in sorted(res.iterdir()):
        print(f"  {p}")


if __name__ == "__main__":
    main()
