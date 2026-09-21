"""analyze_v11.py -- what does 検査4 still buy, and do the two profiles agree?

Two questions, both of which have to be answered from ONE measurement round
where every gate (検査1..11) was wired, because that had never happened before
v11:

  1. **Is `--profile fast` still exactly "strict minus 検査4"?**  v8 checked
     this on 18 shared entries and found no disagreement.  Four gates have been
     added since.  The check is: take the strict run's gate dict, delete
     ``check4``, and see whether the resulting outcome equals the fast run's
     outcome on the same entry.  A disagreement means the profiles differ in
     something other than 検査4 -- a bug, not a finding.

  2. **Does 検査4 have any remaining unique value?**  i.e. entries where
     ``check4`` is the ONLY hard-failing gate.  v9 moved V1 (the last such
     entry) to 検査10, so the expected answer is "none"; the point of the run
     is to make that a measurement rather than an inference.

usage: analyze_v11.py <fast_report.json> <strict_report.json> [--out FILE]
"""

from __future__ import annotations

import argparse
import json
import pathlib

ESCALATE_ONLY = {"check6", "check7"}


def outcome_from_gates(gates, drop=()):
    g = {k: v for k, v in (gates or {}).items() if k.split("@")[0] not in drop}
    hard = [k for k, v in g.items()
            if v is False and k.split("@")[0] not in ESCALATE_ONLY]
    esc = [k for k, v in g.items()
           if v is False and k.split("@")[0] in ESCALATE_ONLY]
    if hard:
        return "HARD", hard, esc
    if esc:
        return "ESCALATE", hard, esc
    return "PASS", hard, esc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("fast")
    ap.add_argument("strict")
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    F = json.loads(pathlib.Path(a.fast).read_text(encoding="utf-8"))
    S = json.loads(pathlib.Path(a.strict).read_text(encoding="utf-8"))
    fr = {r["name"]: r for r in F["rows"] if r["outcome"] != "NOT-RUN"}
    sr = {r["name"]: r for r in S["rows"] if r["outcome"] != "NOT-RUN"}
    shared = [n for n in fr if n in sr]

    equivalence, disagree = [], []
    for n in shared:
        want = fr[n]["outcome"]
        got, hard, esc = outcome_from_gates(sr[n]["gates"], drop={"check4"})
        row = {"name": n, "fast": want, "strict_minus_check4": got,
               "strict_outcome": sr[n]["outcome"],
               "strict_hard": sr[n]["hard"], "fast_hard": fr[n]["hard"]}
        equivalence.append(row)
        if want != got:
            disagree.append(row)

    # 検査4's remaining unique value: it is the ONLY hard-failing gate
    only_check4, check4_contrib, check4_fp = [], [], []
    for n, r in sr.items():
        hard = r.get("hard") or []
        if "check4" in hard:
            check4_contrib.append(n)
            if len(hard) == 1:
                only_check4.append({"name": n, "expect": r.get("expect"),
                                    "fast_outcome": fr.get(n, {}).get("outcome")})
        if r.get("expect") == "control" and "check4" in hard:
            check4_fp.append(n)

    def cost_of(rep, gate):
        for c in rep["cost"]["per_gate"]:
            if c["gate"] == gate:
                return c
        return None

    out = {
        "fast_coverage": F["coverage"], "strict_coverage": S["coverage"],
        "shared_entries": len(shared),
        "profile_equivalence": {
            "checked": len(shared), "disagreements": disagree,
            "holds": not disagree,
            "meaning": "fast == strict minus 検査4 on every shared entry"
                       if not disagree else
                       "fast differs from strict-minus-検査4 -- investigate",
        },
        "check4_hard_fails": sorted(check4_contrib),
        "check4_sole_hard_killer": only_check4,
        "check4_control_false_positives": sorted(check4_fp),
        "cost": {
            "fast_mean_gate_total_s": F["cost"]["mean_gate_total_s"],
            "strict_mean_gate_total_s": S["cost"]["mean_gate_total_s"],
            "fast_mean_wall_s": F["cost"]["mean_wall_s"],
            "strict_mean_wall_s": S["cost"]["mean_wall_s"],
            "check4_in_strict": cost_of(S, "check4"),
        },
        "defence": {
            "fast_hard": F["defence_hard"], "fast_incl_esc": F["defence_incl_escalate"],
            "strict_hard": S["defence_hard"], "strict_incl_esc": S["defence_incl_escalate"],
        },
        "slips": {"fast": F["slips_strict_reading"], "strict": S["slips_strict_reading"]},
        "false_positives": {
            "fast_hard": F["false_positives_hard"],
            "strict_hard": S["false_positives_hard"],
            "fast_esc": F["false_positives_escalate_only"],
            "strict_esc": S["false_positives_escalate_only"],
        },
        "equivalence_rows": equivalence,
    }
    print(json.dumps({k: v for k, v in out.items() if k != "equivalence_rows"},
                     indent=1, ensure_ascii=False))
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False),
                                       encoding="utf-8")
        print("wrote", a.out)


if __name__ == "__main__":
    main()
