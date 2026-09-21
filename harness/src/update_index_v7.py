#!/usr/bin/env python3
"""Write the v7 verdicts back into the corpus index (D5: `first` / `latest`).

run_corpus.py does this with --update-index; the v7 sweep was launched without
it, so the same write is done here from the report it produced.
"""
from __future__ import annotations

import json
import pathlib

CORPUS = pathlib.Path.home() / "vf1/attack-corpus"
REPORT = pathlib.Path.home() / "vf1/corpus_report_v7.json"
AMB = pathlib.Path.home() / "vf1/amb_report_v7.json"

idx = json.loads((CORPUS / "index.json").read_text(encoding="utf-8"))
rep = json.loads(REPORT.read_text())
amb = json.loads(AMB.read_text())
by = {r["name"]: r for r in rep["rows"]}

n_latest = n_first = n_amb = 0
for e in idx["entries"]:
    r = by.get(e["name"])
    a = amb.get(e["name"])
    if a is not None:
        e["check9_standalone"] = {"label": "v7", "pass": a.get("pass"),
                                  "divergent_axes": a.get("divergent_axes"),
                                  "secs": a.get("secs")}
        n_amb += 1
    if not r:
        continue
    e["latest"] = {"label": "v7", "verdict": r["verdict"],
                   "killed_by": r["killed_by"], "killed_by_all": r.get("killed_by_all"),
                   "gates": r["gates"], "truth_F_fixed": r.get("truth_F_fixed"),
                   "status": r["status"]}
    n_latest += 1
    if not (e.get("first") or {}).get("verdict"):
        e["first"] = {"seen": "v7", "verdict": r["verdict"],
                      "killed_by": r["killed_by"]}
        n_first += 1

(CORPUS / "index.json").write_text(json.dumps(idx, indent=1, ensure_ascii=False),
                                   encoding="utf-8")
print(json.dumps({"entries": len(idx["entries"]), "latest_written": n_latest,
                  "first_filled": n_first, "check9_written": n_amb}, indent=1))
