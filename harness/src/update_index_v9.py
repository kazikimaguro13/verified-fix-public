"""update_index_v9.py -- write the v9 verdicts back into attack-corpus/index.json.

Two things are recorded, and they are deliberately kept apart:

  `latest_v9fast`   the full-pipeline verdict, but ONLY for the 16 entries that
                    were re-run with the correct gate arguments (the 9
                    legitimate-fix controls, V1, X5 and the five v9 adaptive
                    attacks).  The first v9 sweep over all 55 entries was run
                    with one oracle instead of three and is NOT written back --
                    see reports/v9_check10_results.md for why.
  `check10`         検査10's standalone verdict, which IS valid for every entry:
                    the gate reads only the post images and the package layout
                    and never executes an oracle, so no oracle-set mistake can
                    reach it.

usage: update_index_v9.py [--corpus DIR] [--results DIR] [--sweep FILE]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

PARTIAL = {
    "00_correct", "L1_posixpath_altimpl", "L2_error_message", "L3_named_constants",
    "L4_debug_logging", "L5_docstring", "L6_lru_cache", "Z1a_literal_plain",
    "Z1b_literal_respelled", "X5_normalizer_identity", "V1_caller_file_area",
    "S1_distinct_pkg_files", "S2_caller_lineno", "S2b_caller_lineno_high",
    "S3_transform_detect", "S4_caller_codesize",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(pathlib.Path.home() / "vf1/attack-corpus"))
    ap.add_argument("--results", default=str(pathlib.Path.home() / "vf1/results_v9b"))
    ap.add_argument("--sweep", default=str(pathlib.Path.home() / "vf1/sweep10_v9_final.json"))
    ap.add_argument("--label", default="v9fast")
    a = ap.parse_args()

    corpus = pathlib.Path(a.corpus)
    index = json.loads((corpus / "index.json").read_text(encoding="utf-8"))
    results = pathlib.Path(a.results)
    sweep = json.loads(pathlib.Path(a.sweep).read_text())

    n_full, n_gate = 0, 0
    for e in index["entries"]:
        name = e["name"]
        s = sweep.get(name)
        if s is not None:
            e["check10"] = {
                "label": "v9",
                "pass": s.get("pass"),
                "n_divergent_variants": s.get("n_divergent_variants"),
                "divergent_variants": sorted(s.get("divergent") or {}),
                "n_variants": s.get("n_variants"),
                "n_inapplicable": s.get("n_inapplicable"),
                "ceilings": s.get("ceilings"),
                "secs": s.get("secs"),
            }
            n_gate += 1
        rf = results / (name + ".json")
        if name in PARTIAL and rf.exists():
            r = json.loads(rf.read_text())
            killed = not r.get("all_gates_passed")
            row = {"label": a.label,
                   "profile": r.get("profile"),
                   "oracles": sorted((r.get("oracles") or {})),
                   "verdict": "KILLED" if killed else "SLIP",
                   "killed_by": r.get("killed_by"),
                   "killed_by_all": r.get("killed_by_all"),
                   "escalated": r.get("escalated"),
                   "gates": r.get("gates")}
            e["latest_v9fast"] = row
            if "first" not in e:
                e["first"] = {"seen": "v9",
                              "verdict": row["verdict"],
                              "killed_by": row["killed_by"]}
            n_full += 1

    index["note"] = (index.get("note", "") or "").split("  [v9]")[0] + (
        "  [v9] 検査10 (structural metamorphic) added.  `check10` is present on "
        "every entry and is valid corpus-wide -- the gate never runs an oracle.  "
        "`latest_v9fast` is present only on the 16 entries re-run with the "
        "correct 3-oracle arguments; the first v9 all-entry sweep used one "
        "oracle by mistake and was discarded (see reports/v9_check10_results.md).")
    (corpus / "index.json").write_text(json.dumps(index, indent=1, ensure_ascii=False),
                                       encoding="utf-8")
    print("check10 written for %d entries; latest_v9fast for %d" % (n_gate, n_full))
    return 0


if __name__ == "__main__":
    sys.exit(main())
