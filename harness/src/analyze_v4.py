#!/usr/bin/env python3
"""analyze_v4.py -- read a corpus report and print the three tables v4 needs.

  1. per-entry verdict, with 検査6 and 検査7 side by side;
  2. the 検査6 / 検査7 **overlap** -- which entries only one of them catches.
     This is the number that decides whether both gates are worth keeping:
     if 検査7 catches a strict superset, 検査6 is dead weight, and vice versa;
  3. per-gate cost (mean / max seconds over the entries that reached the gate).

usage: analyze_v4.py <corpus_report.json> [more_report.json ...]
"""

from __future__ import annotations

import json
import pathlib
import statistics
import sys


def load(paths):
    rows = []
    for p in paths:
        d = json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
        rows += d["rows"]
    return rows


def main() -> int:
    rows = load(sys.argv[1:])

    hdr = ("%-28s %-8s %-6s %-16s %-16s %-9s %-9s %s"
           % ("name", "expect", "harm", "first", "latest", "chk6", "chk7", "status"))
    print(hdr)
    print("-" * len(hdr))
    for r in sorted(rows, key=lambda x: (x.get("expect") or "", x["name"])):
        print("%-28s %-8s %-6s %-16s %-16s %-9s %-9s %s" % (
            r["name"], r.get("expect") or "-", str(r.get("harm")),
            f'{r.get("first_verdict") or "-"}/{r.get("first_killed_by") or "-"}',
            f'{r.get("verdict")}/{r.get("killed_by") or "-"}',
            r.get("check6") or "-", r.get("check7") or "-", r.get("status")))

    # ---- 検査6 / 検査7 overlap ------------------------------------------
    only6, only7, both, neither = [], [], [], []
    for r in rows:
        g = r.get("gates") or {}
        c6 = g.get("check6") is False
        c7 = g.get("check7") is False
        if c6 and c7:
            both.append(r["name"])
        elif c6:
            only6.append(r["name"])
        elif c7:
            only7.append(r["name"])
        elif "check6" in g:
            neither.append(r["name"])
    print("\n=== 検査6 / 検査7 overlap (entries that reached both gates) ===")
    print(f" both escalate      ({len(both):2d}): {sorted(both)}")
    print(f" ONLY 検査6         ({len(only6):2d}): {sorted(only6)}")
    print(f" ONLY 検査7         ({len(only7):2d}): {sorted(only7)}")
    print(f" neither            ({len(neither):2d}): {sorted(neither)}")

    # ---- cost -----------------------------------------------------------
    per_gate: dict[str, list[float]] = {}
    for r in rows:
        for g, v in (r.get("timing") or {}).items():
            if isinstance(v, (int, float)):
                per_gate.setdefault(g, []).append(float(v))
    print("\n=== per-gate cost (s) ===")
    print("%-10s %6s %9s %9s %9s" % ("gate", "n", "mean", "median", "max"))
    order = ["freeze", "check2", "check3", "check4", "check5", "check6",
             "check7", "R5+R4"]
    for g in order + [k for k in per_gate if k not in order]:
        v = per_gate.get(g)
        if not v:
            continue
        print("%-10s %6d %9.3f %9.3f %9.3f" % (
            g, len(v), statistics.mean(v), statistics.median(v), max(v)))
    total = sum(statistics.mean(v) for v in per_gate.values())
    print(f"{'TOTAL':<10} {'':>6} {total:9.3f}  (mean full pipeline)")

    # ---- headline -------------------------------------------------------
    atk = [r for r in rows if r.get("expect") == "attack"]
    killed = [r for r in atk if r.get("verdict") == "KILLED"]
    print("\n=== headline ===")
    print(f" attacks {len(killed)}/{len(atk)} killed")
    print(" slips:        ", sorted(r["name"] for r in atk if r.get("verdict") != "KILLED"))
    print(" REGRESSIONS:  ", sorted(r["name"] for r in rows if r.get("status") == "REGRESSION"))
    print(" false pos:    ", sorted(r["name"] for r in rows
                                    if r.get("status") == "FALSE-POSITIVE"))
    print(" killed_by histogram:")
    hist: dict[str, int] = {}
    for r in atk:
        hist[r.get("killed_by") or "-SLIP-"] = hist.get(r.get("killed_by") or "-SLIP-", 0) + 1
    for k, v in sorted(hist.items(), key=lambda kv: -kv[1]):
        print(f"   {k:<12} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
