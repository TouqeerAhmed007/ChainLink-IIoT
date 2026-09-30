import csv

from iiot.perf import bench, individual_vs_batch as ivb


def test_bench_smoke(tmp_path):
    raw, summ = bench.run_bench([5], 1, tmp_path)
    for p in (raw, summ):
        assert p.exists() and p.stat().st_size > 0
    with open(summ, newline="") as f:
        assert len(list(csv.DictReader(f))) > 0


def test_individual_vs_batch_smoke(tmp_path):
    p = ivb.run_experiment([5], 1, tmp_path)
    assert p.exists() and p.stat().st_size > 0
    with open(p, newline="") as f:
        rows = {r["mode"]: r for r in csv.DictReader(f)}
    assert int(rows["batch"]["stale_proofs_final"]) == 0
    assert int(rows["individual"]["root_updates"]) == 5
    assert int(rows["individual"]["stale_proofs_final"]) == 4
