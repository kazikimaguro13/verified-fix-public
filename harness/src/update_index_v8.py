#!/usr/bin/env python3
"""Write a sweep's verdicts back into the corpus index (D5: `first` / `latest`).

Generalised from update_index_v7.py: takes the report and the label as
arguments, and -- new in v8 -- keeps the two PROFILES apart.  ``latest`` is the
strict verdict (the full gate set is what the corpus is a regression test for);
the fast verdict is stored alongside as ``latest_fast`` so the two can never be
confused for one another in a later report.

usage: update_index_v8.py --strict REPORT.json [--fast REPORT.json]
                          [--label v8] [--corpus DIR]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

HOME = pathlib.Path.home()


def rows(path: str) -> dict:
    if not path:
        return {}
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    rep = json.loads(p.read_text(encoding="utf-8"))
    return {r["name"]: r for r in rep.get("rows", [])}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(HOME / "vf1/attack-corpus"))
    ap.add_argument("--strict", default="")
    ap.add_argument("--fast", default="")
    ap.add_argument("--label", default="v8")
    a = ap.parse_args()

    corpus = pathlib.Path(a.corpus)
    idx = json.loads((corpus / "index.json").read_text(encoding="utf-8"))
    S, F = rows(a.strict), rows(a.fast)

    n_latest = n_fast = n_first = 0
    for e in idx["entries"]:
        r = S.get(e["name"])
        f = F.get(e["name"])
        if f:
            e["latest_fast"] = {"label": a.label + "fast", "verdict": f["verdict"],
                                "killed_by": f["killed_by"],
                                "killed_by_all": f.get("killed_by_all"),
                                "status": f["status"]}
            n_fast += 1
        if not r:
            continue
        e["latest"] = {"label": a.label, "profile": "strict",
                       "verdict": r["verdict"], "killed_by": r["killed_by"],
                       "killed_by_all": r.get("killed_by_all"),
                       "gates": r["gates"], "truth_F_fixed": r.get("truth_F_fixed"),
                       "status": r["status"]}
        n_latest += 1
        if not (e.get("first") or {}).get("verdict"):
            e["first"] = {"seen": a.label, "verdict": r["verdict"],
                          "killed_by": r["killed_by"]}
            n_first += 1

    (corpus / "index.json").write_text(json.dumps(idx, indent=1, ensure_ascii=False),
                                       encoding="utf-8")
    print(json.dumps({"entries": len(idx["entries"]), "latest_written": n_latest,
                      "latest_fast_written": n_fast, "first_filled": n_first},
                     indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
