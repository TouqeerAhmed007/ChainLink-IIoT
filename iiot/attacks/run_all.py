"""Run every attack against fresh in-process apps: python -m iiot.attacks.run_all"""
from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.table import Table

import iiot.attacks as A
from iiot.attacks import expired_revoked, extra_attacks, replay, stolen_token, tamper

MODULES = [replay, tamper, stolen_token, expired_revoked, extra_attacks]


def run_all(print_table: bool = True, verbose: bool = False) -> list[dict]:
    A.VERBOSE = verbose
    results = []
    for mod in MODULES:
        client, ak, psk = A.make_env()
        try:
            r = mod.run(client, ak, psk)
        except Exception as e:  # an errored attack counts as not blocked
            r = {"name": mod.__name__.rsplit(".", 1)[-1], "precondition_ok": False,
                 "attack_result": "ERROR", "blocked": False, "detected_by": "-", "check": "-",
                 "expected_reason": "-", "evidence": repr(e), "variants": []}
        results.append(r)
    if print_table:
        _print(results)
    return results


def _print(results: list[dict]) -> None:
    con = Console(no_color=os.environ.get("IIOT_NOCOLOR") == "1")
    t = Table(title="Attack suite")
    for c in ("attack", "detector", "check", "expected", "actual", "result"):
        t.add_column(c)
    for r in results:
        rows = r["variants"] if len(r["variants"]) > 1 else [None]
        for v in rows:
            ok = r["precondition_ok"] and (v["ok"] if v else r["blocked"])
            name = f"{r['name']}:{v['name']}" if v else r["name"]
            exp = "|".join(v["expected"]) if v else r["expected_reason"]
            act = v["actual"] if v else r["attack_result"]
            t.add_row(name, r["detected_by"], r["check"], exp, act,
                      "[green]PASS[/green]" if ok else "[red]FAIL[/red]")
    con.print(t)
    for r in results:
        con.print(f"{r['name']}: {r['evidence']}", markup=False, highlight=False)
    n = sum(r["blocked"] for r in results)
    con.print(f"{n}/{len(results)} attack classes blocked", markup=False)


def main() -> None:
    res = run_all(verbose=False)
    sys.exit(0 if all(r["blocked"] for r in res) else 1)


if __name__ == "__main__":
    main()
