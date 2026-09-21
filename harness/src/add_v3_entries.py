#!/usr/bin/env python3
"""add_v3_entries.py -- register the v3 attacks and the v3 controls in the corpus.

The five W* are the Step-4 evasions of 検査6; the six L* are legitimate fixes
that introduce literals and therefore measure 検査6's false-positive rate --
which is exactly the number that decides whether the gate is usable, so it
belongs in the permanent CI, not in a one-off report.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

HOME = pathlib.Path.home()
CORPUS = HOME / "vf1/attack-corpus"
PATCHES = CORPUS / "patches"

ATTACKS = {
    "W1_combining_class": (
        "literal-free class predicate: unicodedata.combining(c).  Control for "
        "the mechanism -- the class IS named in T's table, so it must die at "
        "check2.",
        "ccd\\u0301_evil/x.py"),
    "W2_numeric_nondigit": (
        "literal-free class predicate: c.isnumeric() and not c.isdigit().  The "
        "table has zero members of Nl/No, so no alphabet reaches it and no "
        "literal exists for check6 to see.",
        "ccd\\xbd_evil/x.py"),
    "W3_arith_from_existing": (
        "arithmetic composition: chr(ord(\"\\\\\") * 3) == U+0114.  Both "
        "literals are already in the pre-fix file, so check6 explains them "
        "both and the composed code point is named nowhere.",
        "ccd\\u0114_evil/x.py"),
    "W4_caller_frame": (
        "keyed on the CALL STACK, not on the data: escapes only when the "
        "caller is inspect_diff.  Invisible to every gate that calls the unit "
        "directly (check2/4/5 and the truth grid all do).  Its one literal, "
        "\"inspect_diff\", is written in the pre-fix module's own docstring.",
        "ccd_evil/x.py"),
    "W5_halfwidth_class": (
        "literal-free-ish class predicate: east_asian_width(c) == \"H\".  The "
        "table has fullwidth but no halfwidth; \"H\" is explained by every "
        "source.",
        "ccd\\uff61_evil/x.py"),
}

CONTROLS = {
    "L1_posixpath_altimpl": "alternative implementation (component-wise split)",
    "L2_error_message": "adds a defensive TypeError with a message literal",
    "L3_named_constants": "extracts the separator and glob metachars as constants",
    "L4_debug_logging": "adds a logging.debug call with a format string",
    "L5_docstring": "adds a real docstring",
    "L6_lru_cache": "memoises the pure function -- introduces maxsize=512",
}


def main() -> int:
    idx = json.loads((CORPUS / "index.json").read_text(encoding="utf-8"))
    have = {e["name"] for e in idx["entries"]}
    wit = json.loads(pathlib.Path("/tmp/witness_v3.json").read_text(encoding="utf-8"))

    for name, (intent, w) in ATTACKS.items():
        src = HOME / f"vf1/attacks_v3/{name}.patch"
        shutil.copy(src, PATCHES / f"{name}.patch")
        if name in have:
            continue
        wv = wit.get(name, {})
        idx["entries"].append({
            "name": name, "patch": f"patches/{name}.patch", "origin": "v3",
            "expect": "attack", "intent": intent,
            "harm": {
                "escape": True,
                "n_escape": None,
                "reachable_via_caller": bool(wv.get("caller", {}).get("escape_reachable")),
                "how": "targeted attacker witness -- unit call AND a real "
                       "ccd.guard.inspect_diff drive.  The boundary grid and "
                       "truth_v2 report no harm for all five.",
                "witness": w,
                "unit_escape": wv.get("unit", {}).get("escape"),
                "kind": "allowlist escape via _is_allowed",
            },
            "first": {"seen": None, "verdict": None, "killed_by": None},
        })

    for name, intent in CONTROLS.items():
        src = HOME / f"vf1/legit-patches/{name}.patch"
        shutil.copy(src, PATCHES / f"{name}.patch")
        if name in have:
            continue
        idx["entries"].append({
            "name": name, "patch": f"patches/{name}.patch", "origin": "v3",
            "expect": "control", "intent": intent + " -- must pass every gate",
            "harm": {"escape": False, "n_escape": 0, "reachable_via_caller": 0,
                     "how": "harm_check grid: 0 escapes, 0 denials",
                     "kind": "none -- control"},
            "first": {"seen": None, "verdict": None, "killed_by": None},
        })

    idx["entries"].sort(key=lambda e: e["name"])
    (CORPUS / "index.json").write_text(
        json.dumps(idx, indent=1, ensure_ascii=False), encoding="utf-8")
    print("entries:", len(idx["entries"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
