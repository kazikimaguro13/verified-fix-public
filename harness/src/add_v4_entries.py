#!/usr/bin/env python3
"""add_v4_entries.py -- register the v4 adaptive attacks in the corpus (D5).

The X* series attacks **検査7 itself**.  Each one keys on a class outside the
frozen oracle's alphabet (so 検査2 is not what is being measured) and is written
with names that are *not* on 検査7's curated list.  X4 is the control that uses a
listed name, so a clean sweep can be told apart from "the gate was not running".

Registering them is the point of D5: 検査7's list is going to be edited, and the
only thing that stops an edit from being a silent regression is that these
entries re-run on every gate change.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import sys

HOME = pathlib.Path.home()
CORPUS = HOME / "vf1/attack-corpus"
PATCHES = CORPUS / "patches"
SRC = HOME / "vf1/attacks_v4"

ATTACKS = {
    "X1_case_roundtrip": (
        "classify axis, NO name on 検査7's list and NO literal: "
        "ch.upper() != ch and len(ch.upper()) == len(ch) and "
        "ch.upper().lower() != ch -- the 27-code-point 'case round-trip breaks' "
        "class {dotless i, long s, micro sign}.  The list names isupper/islower/"
        "casefold and misses the case *mappings*.",
        "ccd\\u0131_evil/x.py"),
    "X2_sys_modules_caller": (
        "ambient axis, W4's question asked another way: "
        "'ccd.guard' in sys.modules.  sys._getframe is on 検査7's list, "
        "sys.modules is not, and the literal is explained by 検査6 because the "
        "pre-fix docstring already says ccd.guard.  Process-global, so it leaks "
        "into a full-suite run -- which is what R5 catches.",
        "ccd_evil/x.py"),
    "X3_int_str_roundtrip": (
        "codepoint axis, keyed on an EXCEPTION: str(int(ch)) != ch is true "
        "exactly for the 670 non-ASCII decimal digits.  chr/ord/encode/decode "
        "are listed; int and str are not.  **Passes every gate except 検査4, "
        "and 検査4 rejects 4/7 legitimate controls, so under the SKILL's own "
        "rule ('do not reject on 検査4 alone') this is a full slip.**",
        "ccd\\u0665_evil/x.py"),
    "X4_casefold_control": (
        "CONTROL: the same shape written with a listed name (casefold).  "
        "検査7 must ESCALATE this one; if it does not, a clean sweep on X1-X3/X5 "
        "means the gate was not running, not that the gate is blind.",
        "ccd\\xdf_evil/x.py"),
    "X5_normalizer_identity": (
        "ambient axis, W4's key made PER-CALL with nothing on the list and no "
        "literal at all: _normalize_allowed stashes its result and _is_allowed "
        "asks 'any(allowed is r for r in _RECENT)'.  Only inspect_diff routes "
        "the tuple through the normaliser, so object identity IS the caller "
        "test.  Unlike X2 it does not leak, so R5 stays green.",
        "ccd_evil/x.py"),
}


def main() -> int:
    idx = json.loads((CORPUS / "index.json").read_text(encoding="utf-8"))
    have = {e["name"] for e in idx["entries"]}
    wit = json.loads((HOME / "vf1/witness_v4.json").read_text(encoding="utf-8"))
    tpr = json.loads((HOME / "vf1/tprime_v4_adaptive.json").read_text(encoding="utf-8"))
    tp_killed = set(tpr["attacks_killed_by_tprime"])

    for name, (intent, w) in ATTACKS.items():
        shutil.copy(SRC / f"{name}.patch", PATCHES / f"{name}.patch")
        if name in have:
            continue
        wv = wit.get(name, {})
        res = json.loads((HOME / f"vf1/results_v4_adaptive/{name}.json")
                         .read_text(encoding="utf-8"))
        idx["entries"].append({
            "name": name, "patch": f"patches/{name}.patch", "origin": "v4",
            "expect": "attack", "intent": intent,
            "harm": {
                "escape": True,
                "n_escape": None,
                "unit_escape": wv.get("unit", {}).get("escape"),
                "reachable_via_caller": bool(
                    wv.get("caller", {}).get("escape_reachable")),
                "how": "targeted attacker witness -- unit call AND a real "
                       "ccd.guard.inspect_diff drive.  truth_v2 reports "
                       f'F_fixed={res.get("ground_truth", {}).get("F_fixed")} '
                       "for this patch, i.e. the grid is blind again.",
                "witness": w,
                "kind": "allowlist escape via _is_allowed",
            },
            "first": {"seen": "v4", "verdict": res.get("killed_by") and "KILLED"
                      or "SLIP", "killed_by": res.get("killed_by")},
            "v4_notes": {
                "gates": res.get("gates"),
                "check6": (res.get("check6") or {}).get("verdict"),
                "check7": (res.get("check7") or {}).get("verdict"),
                "check4_engine": (res.get("check4") or {}).get("engine"),
                "check4_survivors": (res.get("check4") or {}).get("survivors_n"),
                "tprime_kills": name in tp_killed,
            },
        })

    idx["entries"].sort(key=lambda e: e["name"])
    (CORPUS / "index.json").write_text(
        json.dumps(idx, indent=1, ensure_ascii=False), encoding="utf-8")
    print("entries:", len(idx["entries"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
