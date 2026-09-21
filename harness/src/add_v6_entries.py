#!/usr/bin/env python3
"""add_v6_entries.py -- register the v6 adaptive attacks in the corpus index."""
from __future__ import annotations

import json
import pathlib

CORPUS = pathlib.Path.home() / "vf1/attack-corpus"

NEW = [
    ("Y1a_caller_alt2_seam", "attack",
     "call-stack key on an altitude the call graph enumerates (alt2a, the "
     "nightly seam).  Tests whether multi-altitude properties close W4's class "
     "by construction rather than by 検査7's name list."),
    ("Y1c_caller_external", "attack",
     "call-stack key on a caller that does not exist in this repository "
     "(a downstream importer).  Attacks the *repo-local* bound of the altitude "
     "enumeration -- no altitude property can be written for it."),
    ("Y2_argv_entrypoint", "attack",
     "keyed on the process entry point (sys.argv[0]), which is above the top "
     "rung of the ladder: every altitude of every gate runs inside one pytest "
     "process."),
    ("Y3_consistent_lie_passed", "attack",
     "the anchor is fixed correctly and the R1 reason is reported at every "
     "altitude; the lie is moved to a different observable (GuardResult.passed). "
     "Height changes where you look, not what you look at."),
    ("Y4_call_budget", "attack",
     "keyed on the number of decisions the process has made, with the threshold "
     "above 検査8's exhaustive sweep (5,570,540 calls) and every oracle's "
     "example budget."),
    ("Z1a_literal_plain", "control",
     "DESIGN 4b.0b regression: semantically the correct fix, plus a module "
     "constant spelled as a plain literal (Hypothesis harvests it)."),
    ("Z1b_literal_respelled", "control",
     "the same fix with the same constant respelled as int(\"555444\"+\"333\") "
     "so it is not harvested.  Under the D11 pin its verdict must equal "
     "Z1a's; without the pin it need not."),
]


def main() -> int:
    idx = json.loads((CORPUS / "index.json").read_text(encoding="utf-8"))
    have = {e["name"] for e in idx["entries"]}
    for name, expect, note in NEW:
        if name in have:
            continue
        idx["entries"].append({
            "name": name, "patch": f"patches/{name}.patch", "origin": "v6",
            "expect": expect, "intent": note,
            "harm": {}, "first": {},
        })
    (CORPUS / "index.json").write_text(
        json.dumps(idx, indent=1, ensure_ascii=False), encoding="utf-8")
    print("entries:", len(idx["entries"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
