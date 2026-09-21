"""metrics.py -- DESIGN D9: append one line per harness run to runs.jsonl.

D9's claim is that the design is falsifiable: "上がるべき数字が上がらなければ
設計が間違い".  That only works if the numbers are written down every time, by
the harness, in a form that can be compared across runs.  Until now they lived
in prose in the report of whoever ran the sweep.

Recorded per run
  * attack-corpus defence rate, and the *names* of the known slips (a rate alone
    hides which attack is open)
  * legitimate-fix outcome split: auto-accepted / rejected (false positive) /
    escalated.  Rejected and escalated are counted apart on purpose -- a gate
    that hands a correct fix to a human is not the same failure as one that
    throws it away, and collapsing them flatters the harness
  * per-gate cost: mean/total seconds and share of the pipeline
  * oracle layer breakdown (SKILL Phase 2, 層1/2/3) for every oracle the run used

usage:
  metrics.py --label v5 --corpus-report FILE [--mr-report FILE]
             [--det-proof FILE] [--out runs.jsonl] [--note TEXT]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import time

HOME = pathlib.Path.home()

# Where each oracle in this pipeline comes from, in SKILL Phase 2 terms.
# Self-declaration is banned by the SKILL, so each entry names the artefact the
# oracle was actually derived from and that claim is checkable by reading it.
ORACLE_LAYERS = {
    "T (tests/test_oracle_F_pbt.py)": {
        "layer": 1,
        "rung": "D1 段2 -- quotable anchor",
        "derived_from": "the pre-fix in-file contract comment of _is_allowed "
                        "(\"Directory-prefix match (caller can pass tests or "
                        "tests/ - both work)\") plus finding_F.txt",
        "note": "properties P1-P6 are derivable from that contract; none of them "
                "quotes the fix source. Layer 1 because the anchor is pre-fix "
                "text the fixer cannot edit, NOT because a spec file exists.",
    },
    "T' (t_oracle_Fprime_caller.py)": {
        "layer": 1,
        "rung": "D1 段2 -- quotable anchor (caller contract)",
        "derived_from": "ccd.guard.inspect_diff's use of the allowlist (R1)",
    },
    "検査8 (mrgate.py)": {
        "layer": 1,
        "rung": "D1 段1/2 -- structural relation, no expected value",
        "derived_from": "the structure of the reference semantics R: only '/' and "
                        "the fnmatch metacharacters have a structural role, so a "
                        "one-character substitution outside those cannot change "
                        "membership",
        "note": "metamorphic: compares two runs of the *patched* code against each "
                "other, so like 検査5 it needs no LLM-authored expected value.",
    },
    "検査5 (diffgate2.py)": {
        "layer": 1,
        "rung": "differential -- no expected value",
        "derived_from": "pre-image vs post-image behaviour on a frozen corpus",
    },
}


def gate_cost(rows):
    per = {}
    for r in rows:
        for g, s in (r.get("timing") or {}).items():
            per.setdefault(g, []).append(s)
    total_all = sum(sum(v) for v in per.values()) or 1.0
    out = {}
    for g, v in sorted(per.items()):
        out[g] = {"n": len(v), "mean_s": round(statistics.mean(v), 2),
                  "median_s": round(statistics.median(v), 2),
                  "total_s": round(sum(v), 1),
                  "share": round(sum(v) / total_all, 4)}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--corpus-report", required=True)
    ap.add_argument("--mr-report", default="")
    ap.add_argument("--det-proof", default="")
    ap.add_argument("--amb-report", default="",
                    help="v7: standalone 検査9 sweep (dict keyed by entry name)")
    ap.add_argument("--out", default=str(HOME / "vf1/runs.jsonl"))
    ap.add_argument("--note", action="append", default=[])
    a = ap.parse_args()

    rep = json.loads(pathlib.Path(a.corpus_report).read_text())
    rows = rep["rows"]
    attacks = [r for r in rows if r.get("expect") == "attack"]
    controls = [r for r in rows if r.get("expect") == "control"]

    killed = [r for r in attacks if r.get("verdict") == "KILLED"]
    slips = [r["name"] for r in attacks if r.get("verdict") == "SLIP"]

    ctl_accept = [r["name"] for r in controls if r.get("verdict") == "SLIP"]
    ctl_reject = [r["name"] for r in controls if r.get("verdict") == "KILLED"]
    # a control rejected only by a gate whose discipline is ESCALATE (検査6/7)
    # was handed to a human, not thrown away
    escalate_gates = {"check6", "check7"}
    ctl_escalated = [r["name"] for r in controls
                     if r.get("killed_by") in escalate_gates]
    ctl_hard_reject = [n for n in ctl_reject if n not in ctl_escalated]

    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "label": a.label,
        "corpus_report": str(pathlib.Path(a.corpus_report).name),
        "wall_s": rep.get("wall_s"),
        "attack_corpus": {
            "n_attacks": len(attacks),
            "n_killed": len(killed),
            "defence_rate": round(len(killed) / len(attacks), 4) if attacks else None,
            "known_slips": sorted(slips),
            "regressions": rep.get("regressions", []),
            "killed_by_histogram": _hist(r.get("killed_by") for r in killed),
        },
        "legit_fixes": {
            "n": len(controls),
            "auto_accepted": sorted(ctl_accept),
            "n_auto_accepted": len(ctl_accept),
            "rejected": sorted(ctl_hard_reject),
            "escalated_only": sorted(ctl_escalated),
            "false_positive_rate_reject": round(len(ctl_hard_reject) / len(controls), 4)
            if controls else None,
            "false_positive_rate_any_nonaccept":
                round((len(controls) - len(ctl_accept)) / len(controls), 4)
                if controls else None,
            "rejected_by_histogram": _hist(r.get("killed_by") for r in controls
                                           if r.get("verdict") == "KILLED"),
        },
        "gate_cost": gate_cost(rows),
        "oracle_layers": ORACLE_LAYERS,
        "notes": a.note,
    }

    if a.mr_report:
        mr = json.loads(pathlib.Path(a.mr_report).read_text())
        by = {r["name"]: r for r in mr}
        mr_att = [r for r in mr if r.get("expect") == "attack"]
        mr_ctl = [r for r in mr if r.get("expect") == "control"]
        entry["check8_metamorphic"] = {
            "n_attacks_caught": sum(1 for r in mr_att if r.get("pass") is False),
            "attacks_caught": sorted(r["name"] for r in mr_att if r.get("pass") is False),
            "n_controls_flagged": sum(1 for r in mr_ctl if r.get("pass") is False),
            "controls_flagged": sorted(r["name"] for r in mr_ctl if r.get("pass") is False),
            "mean_s": round(statistics.mean([r.get("wall_s", 0) for r in mr]), 2) if mr else None,
        }
        _ = by

    if a.amb_report:
        amb = json.loads(pathlib.Path(a.amb_report).read_text())
        att = {k: v for k, v in amb.items() if v.get("expect") == "attack"}
        ctl = {k: v for k, v in amb.items() if v.get("expect") == "control"}
        caught = sorted(k for k, v in att.items() if v.get("pass") is False)
        entry["check9_ambient"] = {
            "n_entries": len(amb),
            "n_attacks_caught": len(caught),
            "attacks_caught": caught,
            "attacks_surviving": sorted(k for k, v in att.items()
                                        if v.get("pass") is True),
            "n_controls_flagged": sum(1 for v in ctl.values() if v.get("pass") is False),
            "controls_flagged": sorted(k for k, v in ctl.items()
                                       if v.get("pass") is False),
            "divergent_axes": {k: amb[k].get("divergent_axes") for k in caught},
            "mean_s": round(statistics.mean(
                [v.get("secs", 0) for v in amb.values() if v.get("secs")]), 2)
            if any(v.get("secs") for v in amb.values()) else None,
        }

    if a.det_proof:
        dp = json.loads(pathlib.Path(a.det_proof).read_text())
        entry["oracle_determinism"] = {
            "pinned": dp.get("pin"),
            "clones": dp.get("clones"),
            "patches": {k: {"n_runs": v["n_runs"], "verdicts": v["verdicts"],
                            "distinct_outcome_maps": v["distinct_outcome_maps"],
                            "unanimous": v["unanimous"]}
                        for k, v in dp.get("patches", {}).items()},
            "all_unanimous": all(v["unanimous"] for v in dp.get("patches", {}).values()),
        }

    out = pathlib.Path(a.out)
    with out.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(json.dumps(entry, indent=1, ensure_ascii=False))
    print("appended to", out)
    return 0


def _hist(it):
    h = {}
    for x in it:
        h[str(x)] = h.get(str(x), 0) + 1
    return dict(sorted(h.items(), key=lambda kv: -kv[1]))


if __name__ == "__main__":
    raise SystemExit(main())
