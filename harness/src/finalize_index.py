"""finalize_index.py -- stamp measured verdicts into attack-corpus/index.json.

``build_corpus.py`` assembles the corpus before anything has been run, so new
entries have an empty ``first``.  This fills it from the run that first measured
them and records the newest run as ``latest``, which is what makes
``run_corpus.py`` able to distinguish a *slip* (never killed) from a
*regression* (killed once, alive now).

usage: finalize_index.py <corpus_dir> <report.json:label> [<report.json:label> ...]
       reports are applied oldest-first.
"""

from __future__ import annotations

import json
import pathlib
import sys


def main() -> int:
    corpus = pathlib.Path(sys.argv[1])
    idx = json.loads((corpus / "index.json").read_text(encoding="utf-8"))
    by_name = {e["name"]: e for e in idx["entries"]}

    history = []
    for arg in sys.argv[2:]:
        path, _, label = arg.rpartition(":")
        rep = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        history.append((label, rep))

    for label, rep in history:
        for r in rep["rows"]:
            e = by_name.get(r["name"])
            if not e:
                continue
            rec = {"label": label, "verdict": r["verdict"], "killed_by": r["killed_by"],
                   "gates": r["gates"], "truth_F_fixed": r["truth_F_fixed"],
                   "status": r["status"]}
            if e.get("first", {}).get("verdict") is None:
                e["first"] = {"seen": label, "verdict": r["verdict"],
                              "killed_by": r["killed_by"]}
            e["latest"] = rec
            e.setdefault("history", []).append(
                {"label": label, "verdict": r["verdict"], "killed_by": r["killed_by"]})

    idx["runs"] = [lbl for lbl, _ in history]
    (corpus / "index.json").write_text(json.dumps(idx, indent=1, ensure_ascii=False),
                                       encoding="utf-8")
    print("stamped", len(by_name), "entries with", idx["runs"])
    for e in idx["entries"]:
        print("  %-30s first=%-7s/%-7s latest=%-7s/%-7s" % (
            e["name"], e["first"]["verdict"], e["first"]["killed_by"] or "-",
            e["latest"]["verdict"], e["latest"]["killed_by"] or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
