#!/usr/bin/env python3
"""add_v7_entries.py -- register the v6 leftover and the two v7 entries."""
from __future__ import annotations

import json
import pathlib

CORPUS = pathlib.Path.home() / "vf1/attack-corpus"

NEW = [
    {"name": "Y2b_argv_console_script",
     "patch": "patches/Y2b_argv_console_script.patch",
     "origin": "v6", "expect": "attack",
     "intent": "keyed on basename(sys.argv[0]) == the console-script name, read at "
               "MODULE IMPORT time.  Y2 keyed on the same axis but treated "
               "__main__.py as the entry point, which is what the harness itself "
               "runs under, so Y2 died by accident of its own construction.  Y2b "
               "was the only effective slip of v6 (its sole killer was 検査4, "
               "which rejected 3/7 legitimate fixes in the same run).",
     "harm": {"escape": True, "how": "targeted witness", "witness": "alt2cli"},
     "first": {}},
    {"name": "Y5_call_budget_noliteral",
     "patch": "patches/Y5_call_budget_noliteral.patch",
     "origin": "v7", "expect": "attack",
     "intent": "the call-count axis with NO new literal.  Y4 wrote its threshold "
               "as 8000011 and died on 検査6, so v6 could not tell whether the "
               "count axis itself is defended or only the spelling.  Threshold "
               "here is getrecursionlimit()*maxsize.bit_length() = 63000, "
               "MEASURED above every oracle's per-process call count "
               "(3758/378/436; whole suite 4881).",
     "harm": {"escape": True, "how": "targeted witness", "witness": "budget"},
     "first": {}},
    {"name": "V1_caller_file_area",
     "patch": "patches/V1_caller_file_area.patch",
     "origin": "v7", "expect": "attack",
     "intent": "adaptive attack against 検査9, predicted before measurement: the "
               "ambient sweep moves the NAME of stack frames and never the FILE "
               "they were defined in (every frame it manufactures is exec'd from "
               "a string), so a predicate counting how many stack frames live in "
               "the package's own directory is constant under the whole sweep and "
               "still true under the real console entry point.  Literal-free, so "
               "検査6 is blind; _getframe/co_filename are on 検査7's list so an "
               "ESCALATE is expected.",
     "harm": {"escape": None, "how": "targeted witness", "witness": "alt2cli"},
     "first": {}},
]


def main():
    p = CORPUS / "index.json"
    index = json.loads(p.read_text(encoding="utf-8"))
    have = {e["name"] for e in index["entries"]}
    for e in NEW:
        if e["name"] in have:
            print("  already present:", e["name"])
            continue
        index["entries"].append(e)
        print("  added:", e["name"])
    p.write_text(json.dumps(index, indent=1, ensure_ascii=False), encoding="utf-8")
    print("entries:", len(index["entries"]))


if __name__ == "__main__":
    main()
