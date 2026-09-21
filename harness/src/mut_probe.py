#!/usr/bin/env python3
"""v7 step 1-b root-cause probe.

Question: why do Z1a (`_AUDIT_TAG = 555444333`) and Z1b
(`_AUDIT_TAG = int("555444" + "333")`) -- two spellings of the same dead
constant -- get *opposite* 検査4 verdicts?

Hypothesis: 検査4 calls a mutant "killed" iff the oracle process exits non-zero.
That conflates
   (a) the oracle noticed a semantic change            <- evidence of strength
   (b) the mutant made the module unimportable         <- no evidence at all
Z1a's literal only supports mutations of kind (a)-that-nobody-notices (number ->
other number, still dead) => survivors.  Z1b's spelling turns the same dead
constant into strings fed to int(), where every mutation is kind (b) => "killed".

This probe applies each spelling by hand and reports the oracle's exit code and
the first line of its error output.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pathlib as _pathlib
import sys as _sys

# ★v134 (judgement 61): the machine paths below are resolved in ONE
# place now -- harness/src/vf_paths.py.  They used to be literals here.
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from vf_paths import VF_HOME  # noqa: E402

REPO = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(VF_HOME) / "tb8"
PY = str(pathlib.Path.home() / "projects/Cowork-CC-dispatch/.venv/bin/python")
ORACLE = "tests/test_oracle_F_pbt.py"
F = REPO / "ccd/guard_pathmatch.py"

CASES = {
    # Z1a spelling and the two mutants cosmic-ray's NumberReplacer produces
    "Z1a_orig":     "_AUDIT_TAG = 555444333",
    "Z1a_mut_n+1":  "_AUDIT_TAG = 555444334",
    "Z1a_mut_n-1":  "_AUDIT_TAG = 555444332",
    # Z1b spelling and the mutants its operators produce
    "Z1b_orig":     '_AUDIT_TAG = int("555444" + "333")',
    "Z1b_mut_str1": '_AUDIT_TAG = int("XX555444" + "333")',
    "Z1b_mut_str2": '_AUDIT_TAG = int("555444" + "XX333")',
    "Z1b_mut_add":  '_AUDIT_TAG = int("555444" - "333")',
}


def reset():
    subprocess.run(["git", "checkout", "-qf", "bugv2"], cwd=REPO, check=True)
    subprocess.run(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"],
                   cwd=REPO, check=True)


def main():
    out = {}
    for name, line in CASES.items():
        reset()
        src = F.read_text()
        # the correct fix, plus the dead constant in the spelling under test
        src = src.replace("        if path.startswith(a):",
                          '        if path.startswith(a + "/"):')
        src = src.replace("def _normalize_allowed", line + "\n\n\ndef _normalize_allowed", 1)
        F.write_text(src)
        r = subprocess.run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                            "--timeout=120", ORACLE],
                           cwd=REPO, capture_output=True, text=True, timeout=600)
        text = r.stdout + r.stderr
        why = "ok"
        for marker in ("ValueError", "TypeError", "SyntaxError", "ImportError",
                       "errors during collection", "AssertionError", "Falsifying"):
            if marker in text:
                why = marker
                break
        out[name] = {"rc": r.returncode, "killed": r.returncode != 0, "why": why,
                     "tail": text.strip().splitlines()[-1][:120] if text.strip() else ""}
        print(f"  {name:14s} rc={r.returncode} killed={r.returncode != 0} why={why}",
              flush=True)
    reset()
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
