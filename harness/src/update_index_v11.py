"""update_index_v11.py -- write the v11 FULL-PIPELINE verdicts into the corpus
index.

v9's and v10's index writers deliberately refused to touch ``latest``: neither
round had a corpus-wide full-pipeline run, and recording a 13/66 sweep as
``latest`` is exactly the mistake HANDOFF §9-8 is about.  v11 does have one, so
this writer does set ``latest`` -- but only for entries that actually ran, and
it records the coverage of the run that produced the value so a partial sweep
can never be read as a complete one.

Two fields are written:

  latest         <- the ``fast`` profile run.  fast is the SHIPPING profile,
                    so the corpus's headline verdict is the shipping verdict.
  latest_strict  <- the ``strict`` profile run, when one exists for the entry.
                    Kept separate rather than overwriting ``latest``, because
                    the two profiles answer different questions and a strict
                    sweep will usually be less complete than a fast one.

The previous ``latest`` is preserved once as ``latest_prev`` so the evidence
behind a regression claim survives the write.

usage: update_index_v11.py <corpus_report_v11_fast.json> [--strict REPORT]
                           [--label v11] [--corpus DIR] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import pathlib

HOME = pathlib.Path.home()
DEFAULT_CORPUS = HOME / "vf1/attack-corpus"


def rec(row, label, coverage):
    return {
        "label": label,
        "profile": row.get("profile"),
        "verdict": row.get("verdict"),          # KILLED / SLIP  (legacy vocab)
        "outcome": row.get("outcome"),          # HARD / ESCALATE / PASS
        "killed_by": row.get("killed_by"),
        "killed_by_hard": row.get("hard"),
        "escalated_by": row.get("esc"),
        "gates": row.get("gates"),
        "truth_F_fixed": row.get("truth_F_fixed"),
        "status": row.get("status"),
        "budget_exceeded": row.get("budget_exceeded") or [],
        "wall_s": row.get("wall_s"),
        "run_coverage": coverage,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("fast")
    ap.add_argument("--strict", default="")
    ap.add_argument("--label", default="v11")
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    corpus = pathlib.Path(a.corpus)
    idx = json.loads((corpus / "index.json").read_text(encoding="utf-8"))

    fast = json.loads(pathlib.Path(a.fast).read_text(encoding="utf-8"))
    fcov = "%d/%d" % (fast["coverage"]["ran"], fast["coverage"]["corpus_entries"])
    frows = {r["name"]: r for r in fast["rows"] if r["outcome"] != "NOT-RUN"}

    srows, scov = {}, None
    if a.strict:
        st = json.loads(pathlib.Path(a.strict).read_text(encoding="utf-8"))
        scov = "%d/%d" % (st["coverage"]["ran"], st["coverage"]["corpus_entries"])
        srows = {r["name"]: r for r in st["rows"] if r["outcome"] != "NOT-RUN"}

    n_fast = n_strict = n_first = 0
    for e in idx["entries"]:
        name = e["name"]
        r = frows.get(name)
        if r:
            if e.get("latest") and "latest_prev" not in e:
                e["latest_prev"] = e["latest"]
            e["latest"] = rec(r, a.label + "-fast", fcov)
            n_fast += 1
            if not (e.get("first") or {}).get("verdict"):
                e["first"] = {"seen": a.label + "-fast",
                              "verdict": r.get("verdict"),
                              "killed_by": r.get("killed_by"),
                              "outcome": r.get("outcome")}
                n_first += 1
        s = srows.get(name)
        if s:
            e["latest_strict"] = rec(s, a.label + "-strict", scov)
            n_strict += 1

    print("latest<-fast: %d   latest_strict: %d   first filled: %d"
          % (n_fast, n_strict, n_first))
    if a.dry_run:
        print("(dry run -- index.json not written)")
        return
    (corpus / "index.json").write_text(
        json.dumps(idx, indent=1, ensure_ascii=False), encoding="utf-8")
    print("updated", corpus / "index.json")


if __name__ == "__main__":
    main()
