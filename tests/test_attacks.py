import pytest

from iiot.attacks.run_all import run_all

KEYS = {"name", "precondition_ok", "attack_result", "blocked", "detected_by", "check",
        "expected_reason", "evidence"}


@pytest.fixture(scope="module")
def results():
    return run_all(print_table=False)


def test_contract_keys(results):
    assert len(results) >= 5
    for r in results:
        assert KEYS <= set(r)


def test_all_blocked(results):
    for r in results:
        assert r["precondition_ok"], r
        assert r["blocked"], r


def test_tamper_variants(results):
    t = next(r for r in results if r["name"] == "tamper")
    assert len(t["variants"]) == 4 and all(v["ok"] for v in t["variants"])
