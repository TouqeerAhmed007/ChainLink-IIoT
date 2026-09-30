import os
import sys
import threading
import time
from hashlib import sha256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["IIOT_NOCOLOR"] = "1"

import pytest

from iiot.merkle.registry import RootRegistry
from iiot.merkle.tree import build_tree, compute_root, verify_proof


def H(*p):
    return sha256(b"".join(p)).digest()


def N(l, r):
    return H(b"\x01", l, r)


def leaf(i):
    return sha256(f"leaf{i}".encode()).hexdigest()


def flip(h, bit):
    b = bytearray(bytes.fromhex(h))
    b[bit // 8] ^= 1 << (bit % 8)
    return bytes(b).hex()


def test_three_leaf_hand_computed():
    ls = sorted(leaf(i) for i in range(3))
    b = [bytes.fromhex(x) for x in ls]
    n01, n22 = N(b[0], b[1]), N(b[2], b[2])
    root = N(n01, n22).hex()
    t = build_tree(ls[::-1])
    assert t.root == root == compute_root(ls)
    assert t.proof(ls[2]) == [{"hash": ls[2], "side": "right"}, {"hash": n01.hex(), "side": "left"}]
    assert t.proof(ls[0]) == [{"hash": ls[1], "side": "right"}, {"hash": n22.hex(), "side": "right"}]


def test_four_leaf_hand_computed():
    ls = sorted(leaf(i) for i in range(4))
    b = [bytes.fromhex(x) for x in ls]
    n01, n23 = N(b[0], b[1]), N(b[2], b[3])
    t = build_tree(ls)
    assert t.root == N(n01, n23).hex()
    assert t.proof(ls[3]) == [{"hash": ls[2], "side": "left"}, {"hash": n01.hex(), "side": "left"}]


def test_single_leaf_and_empty():
    t = build_tree([leaf(0)])
    assert t.root == leaf(0) and t.proof(leaf(0)) == []
    assert verify_proof(leaf(0), [], leaf(0))
    with pytest.raises(ValueError):
        build_tree([])
    with pytest.raises(ValueError):
        build_tree(["zz"])


def test_dedupe_and_order_independence():
    ls = [leaf(i) for i in range(9)]
    r = compute_root(ls)
    assert compute_root(ls[::-1]) == r
    assert compute_root(ls + ls[:4]) == r
    assert build_tree(ls[::-1]).leaves == sorted(ls)


@pytest.mark.parametrize("n", range(1, 34))
def test_all_proofs_verify(n):
    t = build_tree([leaf(i) for i in range(n)])
    allp = t.all_proofs()
    assert set(allp) == set(t.leaves)
    for l in t.leaves:
        p = t.proof(l)
        assert allp[l] == p
        assert verify_proof(l, p, t.root)


def test_single_bit_tamper_fails():
    t = build_tree([leaf(i) for i in range(5)])
    l = t.leaves[2]
    p = t.proof(l)
    assert verify_proof(l, p, t.root)
    for bit in range(256):
        assert not verify_proof(flip(l, bit), p, t.root)
        assert not verify_proof(l, p, flip(t.root, bit))
        for k in range(len(p)):
            q = [dict(s) for s in p]
            q[k]["hash"] = flip(q[k]["hash"], bit)
            assert not verify_proof(l, q, t.root)
    q = [dict(s) for s in p]
    q[0]["side"] = "left" if q[0]["side"] == "right" else "right"
    assert not verify_proof(l, q, t.root)


def test_malformed_proofs_return_false():
    t = build_tree([leaf(i) for i in range(4)])
    l, p, r = t.leaves[0], t.proof(t.leaves[0]), t.root
    bad = [
        [{"hash": p[0]["hash"], "side": "up"}],
        [{"hash": "xyz", "side": "left"}],
        [{"hash": "ab" * 31, "side": "left"}],
        [{"hash": p[0]["hash"].upper(), "side": "left"}],
        [{"hash": " " * 64, "side": "left"}],
        [{"side": "left"}], [{"hash": p[0]["hash"]}], ["x"], [None], [{"hash": 5, "side": []}],
        None, "abc", 7,
    ]
    for b in bad:
        assert verify_proof(l, b, r) is False
    assert verify_proof("nothex", p, r) is False
    assert verify_proof(l, p, None) is False
    assert verify_proof(l, p, r[:-2]) is False


def test_perf_10k():
    ls = [leaf(i) for i in range(10_000)]
    t0 = time.perf_counter()
    t = build_tree(ls)
    allp = t.all_proofs()
    dt = time.perf_counter() - t0
    assert dt < 1.0, dt
    assert verify_proof(ls[1234], allp[ls[1234]], t.root)


def test_registry_basic_and_rejects():
    r = RootRegistry()
    assert r.latest_epoch() == 0 and r.verify_chain() and len(r.blocks()) == 1
    assert r.blocks()[0]["index"] == 0 and r.get_root(0) is None
    b = r.anchor(1, leaf(1), 3)
    assert b["index"] == 1 and b["prev_hash"] == r.blocks()[0]["hash"]
    r.anchor(3, leaf(3), 4)
    assert r.get_root(1) == leaf(1) and r.get_root(3) == leaf(3) and r.get_root(2) is None
    assert r.latest_epoch() == 3
    for e in (1, 3, 2, 0):
        with pytest.raises(ValueError):
            r.anchor(e, leaf(9), 1)
    with pytest.raises(ValueError):
        r.anchor(4, "bad", 1)
    assert r.verify_chain() and len(r.blocks()) == 3


def test_registry_tamper_detected():
    for field, val in (("root", leaf(99)), ("count", 999), ("epoch", 50), ("ts", 1.0)):
        r = RootRegistry()
        r.anchor(1, leaf(1), 3)
        r.anchor(2, leaf(2), 3)
        r._chain[1][field] = val
        assert not r.verify_chain()
    r = RootRegistry()
    r.anchor(1, leaf(1), 3)
    r.anchor(2, leaf(2), 3)
    del r._chain[1]
    assert not r.verify_chain()
    assert RootRegistry().blocks()[0]["hash"] and r.blocks() is not r._chain


def test_registry_blocks_are_copies():
    r = RootRegistry()
    r.anchor(1, leaf(1), 1)
    r.blocks()[1]["root"] = leaf(7)
    assert r.verify_chain() and r.get_root(1) == leaf(1)


def test_registry_persistence(tmp_path):
    p = tmp_path / "sub" / "reg.json"
    r = RootRegistry(p)
    r.anchor(1, leaf(1), 2)
    r.anchor(2, leaf(2), 5)
    assert not (tmp_path / "sub" / "reg.json.tmp").exists()
    r2 = RootRegistry(p)
    assert r2.blocks() == r.blocks() and r2.latest_epoch() == 2 and r2.get_root(2) == leaf(2)
    r2.anchor(3, leaf(3), 1)
    assert RootRegistry(p).latest_epoch() == 3
    with pytest.raises(ValueError):
        RootRegistry(p).anchor(3, leaf(4), 1)
    p.write_text(p.read_text().replace(leaf(2), leaf(8)))
    with pytest.raises(ValueError):
        RootRegistry(p)


def test_registry_thread_safety():
    r = RootRegistry()
    ok = []

    def w(e):
        try:
            r.anchor(e, leaf(e), 1)
            ok.append(e)
        except ValueError:
            pass

    ts = [threading.Thread(target=w, args=(e,)) for e in range(1, 41)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert r.verify_chain() and len(r.blocks()) == len(ok) + 1


def test_logger_and_tls(tmp_path, capsys):
    from iiot.common.log import get_logger
    from iiot.common.tls import ensure_self_signed_cert
    a, b = get_logger("t"), get_logger("t")
    assert a is b and len(a.handlers) == 1
    a.info("evt k=v")
    out = capsys.readouterr().out.strip()
    assert out.endswith("[t] evt k=v") and out[0] == "[" and out[13] == "]" and "\x1b" not in out
    c1 = ensure_self_signed_cert(tmp_path / "c")
    m = Path(c1[0]).stat().st_mtime_ns
    assert ensure_self_signed_cert(tmp_path / "c") == c1 and Path(c1[0]).stat().st_mtime_ns == m
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(Path(c1[0]).read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in san.get_values_for_type(x509.DNSName)
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days in (365, 366)
