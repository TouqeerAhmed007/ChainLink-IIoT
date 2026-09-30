"""Attack suite helpers shared by all attack modules."""
from __future__ import annotations

import copy

from iiot.common.crypto import canonical, sign

VERBOSE = True
ROLES = ["temperature_sensor", "pressure_sensor", "smart_meter", "camera",
         "valve_controller", "motor_controller"]


def say(msg: str) -> None:
    if VERBOSE:
        print("  " + msg)


def hdr(admin_key: str) -> dict:
    return {"X-Admin-Key": admin_key}


def make_env(ttl: int | None = None, admin_key: str = "admin-key", psk: bytes = b"attack-psk"):
    """Fresh in-process fog app -> (TestClient, admin_key, psk)."""
    from fastapi.testclient import TestClient
    from iiot.common.state import FogConfig
    from iiot.fog.app import create_app
    kw = {"token_ttl_s": ttl} if ttl else {}
    app = create_app(FogConfig(psk=psk, admin_key=admin_key, **kw))
    return TestClient(app), admin_key, psk


def mk(client, psk: bytes, role: str = "temperature_sensor"):
    from iiot.device.device import SimDevice
    return SimDevice(client, psk, role, role=role)


def onboard(devs) -> None:
    from iiot.device.device import onboard_fleet
    onboard_fleet(list(devs))


def close_batch(client, admin_key: str) -> dict:
    r = client.post("/admin/batch/close", headers=hdr(admin_key))
    r.raise_for_status()
    return r.json()


def resign(body: dict, sk) -> dict:
    b = copy.deepcopy(body)
    b.pop("sig", None)
    body["sig"] = sign(sk, canonical(b))
    return body


def baseline(dev, mode: str, resource: str = "temperature", op: str = "WRITE") -> bool:
    return dev.access(mode, resource, op).get("decision") == "ALLOW"


def case(name: str, expected, resp: dict) -> dict:
    exp = (expected,) if isinstance(expected, str) else tuple(expected)
    actual = resp.get("reason", "?")
    ok = resp.get("decision") == "DENY" and actual in exp
    say(f"{name:<24} -> {resp.get('decision')} {actual} (expected {'|'.join(exp)}) "
        f"{'BLOCKED' if ok else 'NOT BLOCKED'}")
    return {"name": name, "expected": exp, "actual": actual, "ok": ok}


def summarize(name: str, pre: bool, cases: list[dict], detected_by: str, check: str,
              evidence: str) -> dict:
    actual = list(dict.fromkeys(c["actual"] for c in cases))
    expected = list(dict.fromkeys(e for c in cases for e in c["expected"]))
    return {"name": name, "precondition_ok": bool(pre), "attack_result": "|".join(actual),
            "blocked": bool(pre) and all(c["ok"] for c in cases), "detected_by": detected_by,
            "check": check, "expected_reason": "|".join(expected), "evidence": evidence,
            "variants": cases}
