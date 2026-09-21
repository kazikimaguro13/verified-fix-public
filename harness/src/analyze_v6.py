#!/usr/bin/env python3
"""analyze_v6.py -- read v6 result JSONs and print the three tables the run is for.

  1. per-entry verdict, with 検査2 split per altitude
  2. the *differential*: what each altitude adds over the ones below it
  3. controls (false positives) and gate cost

usage: analyze_v6.py [--results DIR] [--out F] [--only a,b]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import sys

HOME = pathlib.Path.home()
ALTS = ["alt0", "alt1", "alt2"]


def load(results: pathlib.Path):
    rows = {}
    for f in sorted(results.glob("*.json")):
        n = f.name
        if ".post_" in n or ".pre_" in n or n == "pre_all.json":
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if "gates" not in d:
            continue
        rows[d["name"]] = d
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(HOME / "vf1/results_v6"))
    ap.add_argument("--corpus", default=str(HOME / "vf1/attack-corpus"))
    ap.add_argument("--out", default=str(HOME / "vf1/analysis_v6.json"))
    a = ap.parse_args()

    idx = json.loads((pathlib.Path(a.corpus) / "index.json").read_text(encoding="utf-8"))
    expect = {e["name"]: e.get("expect") for e in idx["entries"]}
    rows = load(pathlib.Path(a.results))

    print(f"{len(rows)} entries measured\n")
    hdr = "%-28s %-7s %-9s %-5s %-5s %-5s %-16s %s" % (
        "name", "expect", "verdict", "c2@0", "c2@1", "c2@2", "first killer", "all killers")
    print(hdr)
    print("-" * len(hdr))
    tbl = []
    for name in sorted(rows):
        d = rows[name]
        g = d["gates"]
        c2 = {alt: g.get(f"check2@{alt}") for alt in ALTS}
        v = "SLIP" if d.get("all_gates_passed") else "KILLED"
        killers = d.get("killed_by_all") or []
        print("%-28s %-7s %-9s %-5s %-5s %-5s %-16s %s" % (
            name, expect.get(name, "-"), v,
            _b(c2["alt0"]), _b(c2["alt1"]), _b(c2["alt2"]),
            d.get("killed_by") or "-", ",".join(killers)))
        tbl.append({"name": name, "expect": expect.get(name), "verdict": v,
                    "check2": c2, "killed_by": d.get("killed_by"),
                    "killers": killers,
                    "truth_F_fixed": (d.get("ground_truth") or {}).get("F_fixed"),
                    "check8_divergent": (d.get("check8") or {}).get("n_divergent_total"),
                    "timing": d.get("timing")})

    # ---- 2. altitude differential --------------------------------------
    atk = [r for r in tbl if r["expect"] == "attack"]
    ctl = [r for r in tbl if r["expect"] == "control"]

    def killed_by_alt(alt):
        return {r["name"] for r in atk if r["check2"].get(alt) is False}

    k = {alt: killed_by_alt(alt) for alt in ALTS}
    only1 = k["alt1"] - k["alt0"]
    only2 = k["alt2"] - k["alt0"] - k["alt1"]
    height_only = (k["alt1"] | k["alt2"]) - k["alt0"]
    # attacks whose *only* killer in the whole pipeline is an altitude oracle
    height_is_sole = sorted(r["name"] for r in atk
                            if r["killers"]
                            and all(x.startswith(("check2@alt1", "check2@alt2",
                                                  "check3@alt1", "check3@alt2"))
                                    for x in r["killers"]))
    slips = sorted(r["name"] for r in atk if r["verdict"] == "SLIP")
    fps = sorted(r["name"] for r in ctl if r["verdict"] == "KILLED")
    fp_by_alt = {alt: sorted(r["name"] for r in ctl if r["check2"].get(alt) is False)
                 for alt in ALTS}

    diff = {
        "n_attacks": len(atk), "n_controls": len(ctl),
        "killed_by_check2_alt0": sorted(k["alt0"]),
        "killed_by_check2_alt1": sorted(k["alt1"]),
        "killed_by_check2_alt2": sorted(k["alt2"]),
        "alt1_adds_over_alt0": sorted(only1),
        "alt2_adds_over_alt0_alt1": sorted(only2),
        "height_adds_over_unit": sorted(height_only),
        "attacks_only_the_height_axis_kills": height_is_sole,
        "SLIPS": slips,
        "control_false_positives": fps,
        "control_false_positive_by_altitude": fp_by_alt,
    }
    print("\n== altitude differential ==")
    print(json.dumps(diff, indent=1, ensure_ascii=False))

    # ---- 3. cost --------------------------------------------------------
    cost = {}
    for r in tbl:
        for gname, s in (r["timing"] or {}).items():
            cost.setdefault(gname, []).append(s)
    costs = {g: {"n": len(v), "mean_s": round(statistics.mean(v), 2),
                 "median_s": round(statistics.median(v), 2),
                 "total_s": round(sum(v), 1)}
             for g, v in sorted(cost.items())}
    tot = sum(c["total_s"] for c in costs.values()) or 1
    for g in costs:
        costs[g]["share"] = round(costs[g]["total_s"] / tot, 4)
    print("\n== gate cost ==")
    print(json.dumps(costs, indent=1))

    out = {"table": tbl, "altitude_differential": diff, "gate_cost": costs}
    pathlib.Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False))
    print("\nwrote", a.out)
    return 0


def _b(v):
    return "-" if v is None else ("P" if v else "FAIL")


if __name__ == "__main__":
    sys.exit(main())
