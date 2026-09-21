"""gate_value_v11.py -- per-gate contribution, measured on a full-corpus run.

Two different questions, and the corpus answers them differently:

  fires      -- how many attacks this gate hard-failed.  Inflated by overlap:
                nine gates going red on the same patch all get credit.
  SOLE       -- how many attacks this gate was the ONLY hard failure for.
                This is what removing the gate would cost, and it is the only
                number that justifies a gate's price.

Controls are reported the same way, because a gate's cost is not only wall
clock: a gate that hard-fails a legitimate fix is charging the operator too.

usage: gate_value_v11.py <corpus_report.json> [--out FILE]
"""

from __future__ import annotations

import argparse
import json
import pathlib


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    d = json.loads(pathlib.Path(a.report).read_text(encoding="utf-8"))
    rows = [r for r in d["rows"] if r["outcome"] != "NOT-RUN"]

    fires, sole, fires_ctl, sole_ctl, esc_fires = {}, {}, {}, {}, {}
    for r in rows:
        base = sorted({g.split("@")[0] for g in (r.get("hard") or [])})
        ebase = sorted({g.split("@")[0] for g in (r.get("esc") or [])})
        tgt_f, tgt_s = (fires, sole) if r["expect"] == "attack" else (fires_ctl, sole_ctl)
        for g in base:
            tgt_f[g] = tgt_f.get(g, 0) + 1
        if len(base) == 1:
            tgt_s.setdefault(base[0], []).append(r["name"])
        for g in ebase:
            esc_fires[g] = esc_fires.get(g, 0) + 1

    cost = {c["gate"]: c for c in d["cost"]["per_gate"]}
    order = ["freeze", "check2", "check3", "check4", "check5", "check6",
             "check7", "check8", "check9", "check10", "check11", "R5", "R4"]
    out = []
    for g in order:
        c = cost.get(g) or cost.get("R5+R4") if g in ("R5", "R4") else cost.get(g)
        out.append({
            "gate": g,
            "hard_fires_on_attacks": fires.get(g, 0),
            "sole_hard_killer_of": sole.get(g, []),
            "n_sole": len(sole.get(g, [])),
            "escalates": esc_fires.get(g, 0),
            "hard_fires_on_controls": fires_ctl.get(g, 0),
            "sole_hard_fp_of": sole_ctl.get(g, []),
            "mean_s": (c or {}).get("mean_s"),
            "pct_of_pipeline": (c or {}).get("pct"),
        })
    res = {"source": a.report, "profile": d.get("profile"),
           "coverage": d.get("coverage"), "gates": out}
    hdr = "%-9s %-6s %-5s %-5s %-6s %-8s %s" % (
        "gate", "fires", "SOLE", "esc", "ctlFP", "mean_s", "sole-killer-of")
    print(hdr)
    print("-" * len(hdr))
    for g in out:
        print("%-9s %-6s %-5s %-5s %-6s %-8s %s" % (
            g["gate"], g["hard_fires_on_attacks"], g["n_sole"], g["escalates"],
            g["hard_fires_on_controls"], g["mean_s"],
            ",".join(g["sole_hard_killer_of"]) or "-"))
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(res, indent=1, ensure_ascii=False),
                                       encoding="utf-8")
        print("wrote", a.out)


if __name__ == "__main__":
    main()
