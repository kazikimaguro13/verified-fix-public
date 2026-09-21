"""update_index_v10.py -- write the 検査11 standalone verdicts into the corpus
index, the same way update_index_v9.py wrote 検査10's.

Standalone verdicts only.  The full-pipeline `latest` field is NOT touched:
v10 ran the whole pipeline on 13 entries, which is not a corpus-wide result and
must not be recorded as one (the v9 lesson in HANDOFF §9-8).

usage: update_index_v10.py <sweep11.json> [--label v10]
"""

from __future__ import annotations

import json
import pathlib
import sys

HOME = pathlib.Path.home()
CORPUS = HOME / "vf1/attack-corpus"


def main():
    src = pathlib.Path(sys.argv[1])
    label = (sys.argv[sys.argv.index("--label") + 1]
             if "--label" in sys.argv else "v10")
    data = json.loads(src.read_text())
    idx = json.loads((CORPUS / "index.json").read_text(encoding="utf-8"))
    n = 0
    for e in idx["entries"]:
        v = data.get(e["name"])
        if not v:
            continue
        t11 = v.get("truth11") or {}
        e["check11"] = {
            "label": label,
            "verdict": ("KILLED" if v.get("pass") is False else "SLIP"),
            "n_divergent": v.get("n_divergent_total"),
            "abstain_rate": v.get("abstain_rate"),
            "truth11_F_fixed": t11.get("F_fixed"),
            "witness": (v.get("samples") or [None])[0],
            "secs": v.get("secs"),
            "budget_exceeded": v.get("budget_exceeded"),
            "normalize_changed_by_patch": v.get("normalize_changed_by_patch"),
        }
        n += 1
    (CORPUS / "index.json").write_text(
        json.dumps(idx, indent=1, ensure_ascii=False), encoding="utf-8")
    print("updated check11 on %d entries" % n)


if __name__ == "__main__":
    main()
