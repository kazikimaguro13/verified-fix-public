#!/usr/bin/env python3
"""analyze_v8.py -- the strict-vs-fast profile comparison (v8 step 1).

v7 measured 445 s/patch with 検査4 at 53.7% of it and 3 of the 9 legitimate-fix
controls hard-rejected by that one gate.  The question this script answers is
the only one that decides whether the tool ships with 検査4 on by default:

    **how many defences do we lose by removing it, and which ones?**

It reads two results directories -- one produced with ``--profile strict`` and
one with ``--profile fast`` -- and prints, per profile:

  * attack defence rate, three ways:
      - nominal: any gate that went red counts as a kill
      - excluding escalators: 検査6/検査7 hand the finding back to a human
        rather than failing it (v6's accounting)
      - excluding escalators AND 検査4: this is exactly the defence `fast`
        gives up, read off the strict run
  * the list of attacks whose ONLY non-escalating killer is 検査4
  * controls hard-rejected, split from controls merely escalated
  * mean cost per patch and the per-gate breakdown
  * R5's cost per rerun, so the N=3 -> N=2 question has a number

A partial strict directory is handled: entries missing from one side are
reported as such rather than silently dropped, because a half-finished sweep
that is quietly averaged is how v6 produced a 100% defence rate on a 21-entry
slice of a 53-entry corpus.

usage: analyze_v8.py [--strict DIR] [--fast DIR] [--corpus DIR] [--out F]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import sys

HOME = pathlib.Path.home()

#: gates that hand the finding back to a human instead of failing it.
ESCALATORS = {"check6", "check7"}


def load(results: pathlib.Path) -> dict:
    rows = {}
    if not results.exists():
        return rows
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


def killers(d: dict) -> list:
    return [g for g, v in (d.get("gates") or {}).items() if v is False]


def base(g: str) -> str:
    return g.split("@")[0]


def _hist(atk: dict) -> dict:
    order = ["freeze", "check2", "check3", "check4", "check5",
             "check6", "check7", "check8", "check9", "R5", "R4"]
    h = {}
    for d in atk.values():
        ks = killers(d)
        first = next((g for o in order for g in ks if g == o or g.startswith(o + "@")),
                     None)
        if first:
            h[first] = h.get(first, 0) + 1
    return dict(sorted(h.items()))


def profile_stats(rows: dict, expect: dict, label: str) -> dict:
    atk = {n: d for n, d in rows.items() if expect.get(n) == "attack"}
    ctl = {n: d for n, d in rows.items() if expect.get(n) == "control"}

    def nonesc(d):
        return [k for k in killers(d) if base(k) not in ESCALATORS]

    def nonesc_no_c4(d):
        return [k for k in killers(d) if base(k) not in (ESCALATORS | {"check4"})]

    killed_nominal = [n for n, d in atk.items() if killers(d)]
    killed_nonesc = [n for n, d in atk.items() if nonesc(d)]
    killed_no_c4 = [n for n, d in atk.items() if nonesc_no_c4(d)]
    sole_c4 = sorted(n for n, d in atk.items() if nonesc(d) == ["check4"])
    slips = sorted(n for n, d in atk.items() if not killers(d))
    esc_only = sorted(n for n, d in atk.items() if killers(d) and not nonesc(d))

    hard_fp = sorted(n for n, d in ctl.items() if nonesc(d))
    esc_fp = sorted(n for n, d in ctl.items() if killers(d) and not nonesc(d))

    per_gate = {}
    totals = []
    for d in rows.values():
        t = d.get("timing") or {}
        for g, s in t.items():
            per_gate.setdefault(g, []).append(s)
        totals.append(sum(t.values()))
    gate_cost = {g: {"n": len(v), "mean_s": round(statistics.mean(v), 2),
                     "total_s": round(sum(v), 1)}
                 for g, v in sorted(per_gate.items())}
    grand = sum(c["total_s"] for c in gate_cost.values()) or 1.0
    for g in gate_cost:
        gate_cost[g]["share"] = round(gate_cost[g]["total_s"] / grand, 4)

    r5n = next((d.get("r5_n") for d in rows.values() if d.get("r5_n")), None)
    r5_mean = gate_cost.get("R5+R4", {}).get("mean_s")

    # ---- would N=2 have decided anything differently? --------------------
    # R5 exists to catch flakiness that only shows up under a different test
    # ORDER, so the honest test of "is the third rerun buying anything" is:
    # for how many entries do the three seeds not already agree after two?
    r5_seed_disagreement, r5_checked = [], 0
    for n, d in rows.items():
        runs = d.get("r5_runs") or []
        if len(runs) < 3:
            continue
        r5_checked += 1
        v3 = (all(x["oracle_passed"] for x in runs),
              max((x["n_new_fail"] for x in runs), default=0) == 0)
        v2 = (all(x["oracle_passed"] for x in runs[:2]),
              max((x["n_new_fail"] for x in runs[:2]), default=0) == 0)
        if v3 != v2:
            r5_seed_disagreement.append(
                {"name": n, "N3": v3, "N2": v2,
                 "per_seed": [{"seed": x["seed"], "oracle": x["oracle_passed"],
                               "new_fail": x["n_new_fail"],
                               "executed": x["executed"]} for x in runs]})
    return {
        "profile": label,
        "n_entries": len(rows),
        "n_attacks": len(atk), "n_controls": len(ctl),
        "defence_nominal": "%d/%d" % (len(killed_nominal), len(atk)),
        "defence_nominal_rate": round(len(killed_nominal) / len(atk), 4) if atk else None,
        "defence_excl_escalators": "%d/%d" % (len(killed_nonesc), len(atk)),
        "defence_excl_escalators_and_check4": "%d/%d" % (len(killed_no_c4), len(atk)),
        "slips": slips,
        "escalate_only_attacks": esc_only,
        "attacks_whose_only_nonescalating_killer_is_check4": sole_c4,
        "controls_hard_rejected": hard_fp,
        "controls_escalated_only": esc_fp,
        "control_hard_reject_rate": round(len(hard_fp) / len(ctl), 4) if ctl else None,
        "mean_cost_s_per_patch": round(statistics.mean(totals), 1) if totals else None,
        "median_cost_s_per_patch": round(statistics.median(totals), 1) if totals else None,
        "gate_cost": gate_cost,
        "r5_reruns_N": r5n,
        "r5_cost_per_rerun_s": round(r5_mean / r5n, 1) if (r5_mean and r5n) else None,
        "projected_mean_cost_if_r5_N2_s": (
            round(statistics.mean(totals) - (r5_mean / r5n), 1)
            if (totals and r5_mean and r5n and r5n > 1) else None),
        "killed_by_histogram": _hist(atk),
        "r5_entries_with_3_seeds": r5_checked,
        "r5_entries_where_N2_would_differ": r5_seed_disagreement,
        "r5_N2_safe_on_this_corpus": (r5_checked > 0
                                      and not r5_seed_disagreement),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", default=str(HOME / "vf1/results_v8_strict"))
    ap.add_argument("--fast", default=str(HOME / "vf1/results_v8_fast"))
    ap.add_argument("--corpus", default=str(HOME / "vf1/attack-corpus"))
    ap.add_argument("--out", default=str(HOME / "vf1/analysis_v8.json"))
    a = ap.parse_args()

    idx = json.loads((pathlib.Path(a.corpus) / "index.json").read_text(encoding="utf-8"))
    expect = {e["name"]: e.get("expect") for e in idx["entries"]}
    n_corpus = len(idx["entries"])

    S = load(pathlib.Path(a.strict))
    F = load(pathlib.Path(a.fast))
    st = profile_stats(S, expect, "strict") if S else None
    ft = profile_stats(F, expect, "fast") if F else None

    print("corpus: %d entries   strict measured: %d   fast measured: %d"
          % (n_corpus, len(S), len(F)))
    if len(S) < n_corpus:
        print("  !! strict is PARTIAL -- missing:", sorted(set(expect) - set(S)))
    if len(F) < n_corpus:
        print("  !! fast   is PARTIAL -- missing:", sorted(set(expect) - set(F)))

    hdr = "%-28s %-8s %-26s %-26s %s" % ("name", "expect", "strict killers",
                                         "fast killers", "diff")
    print("\n" + hdr)
    print("-" * len(hdr))
    diffs = []
    for n in sorted(set(S) | set(F)):
        ks = ",".join(killers(S[n])) if n in S else "(not run)"
        kf = ",".join(killers(F[n])) if n in F else "(not run)"
        d = ""
        if n in S and n in F:
            a_ = {x for x in killers(S[n]) if base(x) != "check4"}
            b_ = set(killers(F[n]))
            if a_ != b_:
                d = "DIVERGENT"
                diffs.append({"name": n, "strict_minus_check4": sorted(a_),
                              "fast": sorted(b_)})
        print("%-28s %-8s %-26s %-26s %s" % (n, expect.get(n, "-"),
                                             ks or "-", kf or "-", d))

    out = {"corpus_entries": n_corpus,
           "strict": st, "fast": ft,
           "strict_partial": len(S) < n_corpus,
           "fast_partial": len(F) < n_corpus,
           "verdict_divergences_strict_minus_check4_vs_fast": diffs}

    for lab, t in (("strict", st), ("fast", ft)):
        if not t:
            print("\n== %s: NOT MEASURED ==" % lab)
            continue
        print("\n== %s ==" % lab)
        print(json.dumps({k: v for k, v in t.items() if k != "gate_cost"},
                         indent=1, ensure_ascii=False))
        print(" gate cost:", json.dumps(t["gate_cost"], indent=1))

    if st and ft:
        print("\n== what fast gives up ==")
        lost = sorted(set(ft["slips"]) - set(st["slips"]))
        print(" attacks that SLIP under fast but were killed under strict:", lost)
        print(" controls recovered (hard-rejected in strict, accepted in fast):",
              sorted(set(st["controls_hard_rejected"])
                     - set(ft["controls_hard_rejected"])))
        sm, fm = st["mean_cost_s_per_patch"], ft["mean_cost_s_per_patch"]
        if sm and fm:
            print(" cost: strict %ss -> fast %ss  (%sx faster)"
                  % (sm, fm, round(sm / fm, 2)))
        out["fast_loses_attacks"] = lost

    pathlib.Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False),
                                   encoding="utf-8")
    print("\nwrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
