#!/usr/bin/env python3
"""analyze_v7.py -- read v7 result JSONs and print the tables this run is for.

  1. per-entry verdict, 検査2 per altitude, 検査9's verdict and axis
  2. what 検査9 adds: attacks whose only non-escalating killer is 検査9, and
     attacks that survive it
  3. step 1-a: which entries the R4/R5 suite-regression condition kills
  4. step 1-b: whether the two spellings of the same dead constant now agree
  5. controls (false positives) and gate cost

usage: analyze_v7.py [--results DIR] [--out F]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import sys

HOME = pathlib.Path.home()
ALTS = ["alt0", "alt1", "alt2"]
#: gates that ESCALATE (a human looks at it) rather than FAIL.  An attack whose
#: only killers are these is not "defended", it is "handed back" -- v6 called
#: that an *effective* slip and the same accounting is kept here.
ESCALATORS = {"check6", "check7"}


def load(results: pathlib.Path):
    rows = {}
    for f in sorted(results.glob("*.json")):
        n = f.name
        if ".post_" in n or ".pre_" in n or n == "pre_all.json":
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if "gates" not in d:
            continue
        rows[d["name"]] = d
    return rows


def _b(v):
    return "-" if v is None else ("P" if v else "F")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(HOME / "vf1/results_v7"))
    ap.add_argument("--corpus", default=str(HOME / "vf1/attack-corpus"))
    ap.add_argument("--out", default=str(HOME / "vf1/analysis_v7.json"))
    a = ap.parse_args()

    idx = json.loads((pathlib.Path(a.corpus) / "index.json").read_text(encoding="utf-8"))
    expect = {e["name"]: e.get("expect") for e in idx["entries"]}
    rows = load(pathlib.Path(a.results))
    print(f"{len(rows)} entries measured\n")

    hdr = "%-28s %-7s %-7s %-3s %-3s %-3s %-4s %-4s %-6s %-14s %s" % (
        "name", "expect", "verdict", "c0", "c1", "c2", "c8", "c9", "newfail",
        "first killer", "all killers")
    print(hdr)
    print("-" * len(hdr))
    tbl = []
    for name in sorted(rows):
        d = rows[name]
        g = d["gates"]
        c2 = {alt: g.get(f"check2@{alt}") for alt in ALTS}
        v = "SLIP" if d.get("all_gates_passed") else "KILLED"
        killers = d.get("killed_by_all") or []
        sr = (d.get("suite_regression") or {}).get("n_new_fail_max")
        row = {"name": name, "expect": expect.get(name), "verdict": v,
               "check2": c2, "killed_by": d.get("killed_by"), "killers": killers,
               "truth_F_fixed": (d.get("ground_truth") or {}).get("F_fixed"),
               "check8_divergent": (d.get("check8") or {}).get("n_divergent_total"),
               "check9_pass": g.get("check9"),
               "check9_axes": (d.get("check9") or {}).get("divergent_axes"),
               "check9_secs": (d.get("check9") or {}).get("secs"),
               "n_new_fail": sr,
               "new_fail_sample": sorted({t for vv in (d.get("suite_regression") or {})
                                          .get("by_seed", {}).values() for t in vv})[:4],
               "check4_mutants": (d.get("check4") or {}).get("mutants"),
               "check4_killed": (d.get("check4") or {}).get("killed"),
               "check4_reached": (d.get("check4") or {}).get("survivors_reached_n"),
               "check4_litnorm": ((d.get("check4") or {}).get("litnorm") or {}),
               "timing": d.get("timing")}
        print("%-28s %-7s %-7s %-3s %-3s %-3s %-4s %-4s %-6s %-14s %s" % (
            name, expect.get(name, "-"), v, _b(c2["alt0"]), _b(c2["alt1"]),
            _b(c2["alt2"]), _b(g.get("check8")), _b(g.get("check9")),
            "-" if sr is None else sr, d.get("killed_by") or "-", ",".join(killers)))
        tbl.append(row)

    atk = [r for r in tbl if r["expect"] == "attack"]
    ctl = [r for r in tbl if r["expect"] == "control"]

    def sole(gate):
        """attacks whose ONLY killer is `gate`."""
        return sorted(r["name"] for r in atk if r["killers"] == [gate])

    def non_escalating(r):
        return [x for x in r["killers"] if x.split("@")[0] not in ESCALATORS]

    c9_kills = sorted(r["name"] for r in atk if r["check9_pass"] is False)
    c9_survivors = sorted(r["name"] for r in atk if r["check9_pass"] is True)
    c9_sole = sole("check9")
    c9_sole_nonesc = sorted(r["name"] for r in atk
                            if non_escalating(r) == ["check9"])
    slips = sorted(r["name"] for r in atk if r["verdict"] == "SLIP")
    eff_slips = sorted(r["name"] for r in atk if not non_escalating(r) and r["killers"])
    fps = sorted(r["name"] for r in ctl if r["verdict"] == "KILLED")
    fp_c9 = sorted(r["name"] for r in ctl if r["check9_pass"] is False)
    sr_kills = sorted(r["name"] for r in tbl if (r["n_new_fail"] or 0) > 0)

    summary = {
        "n_attacks": len(atk), "n_controls": len(ctl),
        "check9": {
            "attacks_caught": c9_kills,
            "n_caught": len(c9_kills),
            "attacks_surviving": c9_survivors,
            "sole_killer_for": c9_sole,
            "sole_non_escalating_killer_for": c9_sole_nonesc,
            "control_false_positives": fp_c9,
            "mean_secs": round(statistics.mean(
                [r["check9_secs"] for r in tbl if r["check9_secs"]]), 2)
            if any(r["check9_secs"] for r in tbl) else None,
        },
        "suite_regression_kills": sr_kills,
        "SLIPS": slips,
        "effective_slips_escalate_only": eff_slips,
        "control_false_positives": fps,
        "control_false_positive_rate": round(len(fps) / len(ctl), 4) if ctl else None,
        "killed_by_histogram": {},
    }
    hist = {}
    for r in atk:
        if r["killed_by"]:
            hist[r["killed_by"]] = hist.get(r["killed_by"], 0) + 1
    summary["killed_by_histogram"] = hist

    # step 1-b: the two spellings of the same dead constant
    z = {n: {"mutants": r["check4_mutants"], "killed": r["check4_killed"],
             "reached_survivors": r["check4_reached"],
             "dropped_dead_store": (r["check4_litnorm"] or {}).get("dropped"),
             "killed_stillborn_n": (r["check4_litnorm"] or {}).get("killed_stillborn_n"),
             "verdict": r["verdict"], "killers": r["killers"]}
         for r in tbl for n in [r["name"]] if n.startswith(("Z1a", "Z1b", "00_correct"))}
    summary["literal_spelling_pair"] = z
    same = (z.get("Z1a_literal_plain", {}).get("killers")
            == z.get("Z1b_literal_respelled", {}).get("killers"))
    summary["Z1a_Z1b_same_verdict"] = same

    print("\n== summary ==")
    print(json.dumps(summary, indent=1, ensure_ascii=False))

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

    out = {"table": tbl, "summary": summary, "gate_cost": costs}
    pathlib.Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False))
    print("\nwrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
