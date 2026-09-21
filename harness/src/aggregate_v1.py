"""Aggregate results2/*.json into hardening2.json + print the summary tables."""
from __future__ import annotations

import json
import os
import statistics

import pathlib as _pathlib
import sys as _sys

# ★v134 (judgement 61): the machine paths below are resolved in ONE
# place now -- harness/src/vf_paths.py.  They used to be literals here.
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from vf_paths import VF_HOME  # noqa: E402

R = os.path.join(VF_HOME, "results2")
NAMES = ["00_correct", "A1_hardcode_expected", "A2_mock_target", "A3_weak_assertions",
         "A4_order_dependent", "A5_spurious_dependency", "A6_special_case",
         "A7a_side_effect_in_module", "A7b_side_effect_out_of_module",
         "C1_blindspot_upper", "C1b_blindspot_backslash", "C4_uncovered_sidefx",
         "D8_registry_write", "D9_dilution"]


def main():
    agg = {"run": "2026-08-20 verified-fix v1 hardening",
           "testbed": "$VF_HOME/testbed (clone of Cowork-CC-dispatch @ bug + F)",
           "entries": []}
    tim = {}
    for n in NAMES:
        f = os.path.join(R, n + ".json")
        if not os.path.exists(f):
            continue
        d = json.load(open(f))
        agg["entries"].append({
            "name": n, "killed_by": d.get("killed_by"),
            "all_gates_passed": d.get("all_gates_passed"),
            "gates": d.get("gates"),
            "F_fixed": d.get("ground_truth", {}).get("F_fixed"),
            "timing": d.get("timing"),
            "check4": {k: d.get("check4", {}).get(k) for k in ("engine", "mutants", "survivors_n", "pass")},
            "check5": {k: d.get("check5", {}).get(k) for k in
                       ("out_of_scope_divergences", "in_scope_divergences",
                        "uncovered_changed_functions", "pass")},
        })
        for k, v in (d.get("timing") or {}).items():
            tim.setdefault(k, []).append(v)

    agg["gate_cost_avg_s"] = {k: round(statistics.mean(v), 2) for k, v in tim.items()}

    def grp(pred):
        return [e for e in agg["entries"] if pred(e["name"])]
    v0 = grp(lambda s: s[0] == "A")
    adap = grp(lambda s: s[0] in ("C", "D"))
    agg["defense"] = {
        "v0_attacks": f"{sum(1 for e in v0 if not e['all_gates_passed'])}/{len(v0)}",
        "v0_slipped": [e["name"] for e in v0 if e["all_gates_passed"]],
        "adaptive_new": f"{sum(1 for e in adap if not e['all_gates_passed'])}/{len(adap)}",
        "adaptive_slipped": [e["name"] for e in adap if e["all_gates_passed"]],
    }
    out = os.path.join(VF_HOME, "hardening2.json")
    json.dump(agg, open(out, "w"), indent=1, ensure_ascii=False)

    print("=== killed_by table ===")
    for e in agg["entries"]:
        print(f"  {e['name']:<30} killed_by={str(e['killed_by']):<8} "
              f"all_pass={str(e['all_gates_passed']):<5} F_fixed={e['F_fixed']}")
    print("=== gate cost (avg s, over full-pipeline runs) ===")
    for k, v in agg["gate_cost_avg_s"].items():
        print(f"  {k}: {v}")
    print("=== defense ===")
    print(json.dumps(agg["defense"], ensure_ascii=False, indent=1))
    print("wrote", out)


if __name__ == "__main__":
    main()
