"""append_run_v9.py -- append the v9 row to runs.jsonl (DESIGN D9).

Not produced by metrics.py, because metrics.py summarises a whole-corpus report
and v9 does not have a valid one: the first all-entry sweep was run with one
oracle instead of three and was discarded.  This row is built from the two
things v9 *does* have valid measurements for, and it labels the scope of each
rather than presenting a partial run as a full one.

usage: append_run_v9.py [--out runs.jsonl]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import statistics
import sys

HOME = pathlib.Path.home()
PARTIAL = ["00_correct", "L1_posixpath_altimpl", "L2_error_message",
           "L3_named_constants", "L4_debug_logging", "L5_docstring",
           "L6_lru_cache", "Z1a_literal_plain", "Z1b_literal_respelled",
           "X5_normalizer_identity", "V1_caller_file_area",
           "S1_distinct_pkg_files", "S2_caller_lineno",
           "S2b_caller_lineno_high", "S3_transform_detect",
           "S4_caller_codesize"]
CONTROLS = PARTIAL[:9]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(HOME / "vf1/results_v9b"))
    ap.add_argument("--sweep", default=str(HOME / "vf1/sweep10_v9_final.json"))
    ap.add_argument("--out", default=str(HOME / "vf1/runs.jsonl"))
    a = ap.parse_args()

    R = pathlib.Path(a.results)
    sweep = json.loads(pathlib.Path(a.sweep).read_text())
    rows = {}
    for n in PARTIAL:
        f = R / (n + ".json")
        if f.exists():
            rows[n] = json.loads(f.read_text())

    attacks = [n for n in rows if n not in CONTROLS and n != "X5_normalizer_identity"]
    killed = [n for n in attacks if not rows[n].get("all_gates_passed")]
    by10 = [n for n in attacks if rows[n].get("gates", {}).get("check10") is False]

    accepted = [n for n in CONTROLS if rows[n].get("all_gates_passed")]
    rejected = [n for n in CONTROLS if not rows[n].get("all_gates_passed")
                and not rows[n].get("escalated")]
    esc = [n for n in CONTROLS if rows[n].get("escalated")]

    # cost: drop the two entries whose wall clock went backwards mid-run
    costs, totals = [], []
    for n, r in rows.items():
        t = r.get("timing", {})
        c = t.get("check10")
        tot = sum(v for v in t.values() if isinstance(v, (int, float)))
        if isinstance(c, (int, float)) and c > 0:
            costs.append(c)
            totals.append(tot)

    sw_attacks = [n for n, v in sweep.items() if v.get("pass") is False]
    sw_controls = [n for n in CONTROLS if sweep.get(n, {}).get("pass") is False]

    row = {
        "ts": dt.datetime.now().replace(microsecond=0).isoformat(),
        "label": "v9fast",
        "corpus_report": None,
        "scope": "PARTIAL -- full-pipeline numbers cover 16 of 60 entries "
                 "(9 controls + V1 + X5 + 5 v9 adaptive attacks), re-run with "
                 "the correct 3-oracle arguments.  The first v9 all-entry sweep "
                 "used one oracle by mistake and was discarded.  検査10's own "
                 "verdict IS corpus-wide (it never runs an oracle).",
        "wall_s": None,
        "attack_corpus": {
            "n_attacks": len(attacks),
            "n_killed": len(killed),
            "defence_rate": round(len(killed) / max(1, len(attacks)), 4),
            "known_slips": sorted(set(attacks) - set(killed)),
            "regressions": [],
            "killed_by_check10": sorted(by10),
            "killed_by_histogram": {},
        },
        "legit_fixes": {
            "n": len(CONTROLS),
            "auto_accepted": sorted(accepted),
            "n_auto_accepted": len(accepted),
            "rejected": sorted(rejected),
            "escalated_only": sorted(esc),
            "false_positive_rate_reject": round(len(rejected) / len(CONTROLS), 4),
            "false_positive_rate_any_nonaccept":
                round((len(rejected) + len(esc)) / len(CONTROLS), 4),
        },
        "check10_structural": {
            "scope": "all 60 corpus entries, standalone (sweep10.py)",
            "n_entries": len(sweep),
            "killed": sorted(sw_attacks),
            "n_killed": len(sw_attacks),
            "false_positives_on_controls": sw_controls,
            "n_false_positives": len(sw_controls),
            "n_variants": 47,
            "ceilings_measured_from_repo": next(
                (v.get("ceilings") for v in sweep.values() if v.get("ceilings")), None),
            "mean_s": round(statistics.mean(costs), 2) if costs else None,
            "median_s": round(statistics.median(costs), 2) if costs else None,
            "share_of_pipeline": round(sum(costs) / sum(totals), 4) if totals else None,
        },
        "notes": "v9: 検査10 (structural metamorphic invariance) added and wired "
                 "into both profiles.  V1_caller_file_area -- the last "
                 "non-escalating slip in `fast` -- is now hard-FAILed by it "
                 "(killed_by_all = [check7, check10]; check7 only escalates).  "
                 "Five adaptive attacks were written against the gate with "
                 "predictions recorded first; three broke the first "
                 "implementation.  strict was NOT run in v9.",
    }
    with open(a.out, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps(row, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
