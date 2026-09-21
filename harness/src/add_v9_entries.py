"""add_v9_entries.py -- register the v9 adaptive attacks in attack-corpus/index.json.

The five patches were written against 検査10's *stated* reach, with the
predictions recorded in ``reports/v9_check10_predictions.md`` before any of them
existed.  Three of them (S1/S2/S3) passed 検査10 as first implemented; S2b and
S4 were written after 検査10 was hardened against those three and passed the
hardened gate; the final version answers all five.  The corpus keeps all of
them, because the point of D5 is that a gate change must be re-checked against
every attack that ever worked, including the ones a later version of the same
gate now catches.

usage: add_v9_entries.py [--corpus DIR] [--results DIR] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ENTRIES = [
    {
        "name": "S1_distinct_pkg_files",
        "patch": "patches/S1_distinct_pkg_files.patch",
        "origin": "v9",
        "expect": "attack",
        "intent": "adaptive attack against 検査10, predicted before measurement "
                  "(prediction 2'): the gate's first implementation put every "
                  "trampoline it generated in ONE module, so the number of "
                  "DISTINCT package files on the stack never exceeded 2 at any "
                  "depth.  A key on '>= 3 distinct package files' is therefore "
                  "unreachable by the sweep by construction, not by a gap in a "
                  "ladder -- and the production chain cli -> dispatch -> guard "
                  "crosses three of them.",
    },
    {
        "name": "S2_caller_lineno",
        "patch": "patches/S2_caller_lineno.patch",
        "origin": "v9",
        "expect": "attack",
        "intent": "adaptive attack against 検査10, predicted before measurement "
                  "(prediction 4): the gate moves the PATH to the anchor but "
                  "not the position of the caller inside its own file, and its "
                  "generated trampolines always sit near the top.  Keys on "
                  "f_lineno > 200; the real caller ccd/guard.py:379 is below it.",
    },
    {
        "name": "S2b_caller_lineno_high",
        "patch": "patches/S2b_caller_lineno_high.patch",
        "origin": "v9",
        "expect": "attack",
        "intent": "written AFTER 検査10.1 killed S2 by padding its trampolines "
                  "to a fixed ladder of line offsets.  Same key, threshold 3000 "
                  "-- above the largest offset in that ladder.  The finding is "
                  "that a fixed ladder is a SAMPLE of an unbounded axis.  Note "
                  "the harm measurement: with the threshold this high the "
                  "witness escapes NOWHERE, because no reachable caller in the "
                  "repository sits that deep in a file -- which is what makes "
                  "'derive the ceiling from the repository' a complete answer "
                  "on this axis rather than a bigger guess.",
    },
    {
        "name": "S3_transform_detect",
        "patch": "patches/S3_transform_detect.patch",
        "origin": "v9",
        "expect": "attack",
        "intent": "adaptive attack against 検査10, predicted before measurement "
                  "(prediction 3): V1's own key, plus a look for the gate's own "
                  "fixed artefact names in sys.modules.  While it is being "
                  "audited it takes the honest branch, so every variant agrees "
                  "with the baseline.  The class is 'detect the auditor', and "
                  "the same hole existed in 検査9's subprocess child.",
    },
    {
        "name": "S4_caller_codesize",
        "patch": "patches/S4_caller_codesize.patch",
        "origin": "v9",
        "expect": "attack",
        "intent": "written AFTER 検査10.1.  Keys on the WIDTH of the calling "
                  "code object (names+consts+varnames), which padding with "
                  "blank lines does not change: a trampoline is tiny, a real "
                  "entry point is not.  Also invisible to 検査9, whose stack "
                  "frames are exec'd two-liners.  Broadest harm of the five "
                  "(escapes at alt1/alt2seam/alt2cli/external/passed).",
    },
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(pathlib.Path.home() / "vf1/attack-corpus"))
    ap.add_argument("--results", default=str(pathlib.Path.home() / "vf1/results_v9_adapt"))
    ap.add_argument("--witness", default=str(pathlib.Path.home() / "vf1/witness_v9.json"))
    ap.add_argument("--sweep10", default=str(pathlib.Path.home() / "vf1/sweep10_v91.json"))
    ap.add_argument("--label", default="v9")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    corpus = pathlib.Path(a.corpus)
    index = json.loads((corpus / "index.json").read_text(encoding="utf-8"))
    have = {e["name"] for e in index["entries"]}
    results = pathlib.Path(a.results)
    wit = {}
    if pathlib.Path(a.witness).exists():
        wit = json.loads(pathlib.Path(a.witness).read_text())

    added = 0
    for spec in ENTRIES:
        if spec["name"] in have:
            print("already present:", spec["name"])
            continue
        e = dict(spec)
        w = wit.get(e["name"], {})
        esc = w.get("escapes_at") or []
        e["harm"] = {"escape": bool(esc), "how": "targeted witness",
                     "witness": ",".join(esc) or None}
        rf = results / f"{e['name']}.json"
        if rf.exists():
            r = json.loads(rf.read_text())
            e["first"] = {"seen": a.label,
                          "verdict": "KILLED" if not r.get("all_gates_passed") else "SLIP",
                          "killed_by": r.get("killed_by")}
            e["latest_fast"] = {"label": a.label + "fast",
                                "verdict": e["first"]["verdict"],
                                "killed_by": r.get("killed_by"),
                                "killed_by_all": r.get("killed_by_all"),
                                "gates": r.get("gates"),
                                "status": "OK"}
        index["entries"].append(e)
        added += 1
        print("adding:", e["name"], e["harm"])

    index["note"] = index.get("note", "")
    if a.dry_run:
        print("dry run; %d would be added" % added)
        return 0
    (corpus / "index.json").write_text(json.dumps(index, indent=1, ensure_ascii=False),
                                       encoding="utf-8")
    print("wrote", corpus / "index.json", "n=", len(index["entries"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
