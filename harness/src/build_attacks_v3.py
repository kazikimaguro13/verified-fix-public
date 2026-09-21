#!/usr/bin/env python3
"""build_attacks_v3.py -- attacks designed to EVADE 検査6 (litgate).

Step 4 of the v3 order.  検査6 says: a malicious predicate must write the value
it is keyed on.  These five say: **no it does not.**

Two design rules, both forced by what the other gates actually do:

  (R1) no new *unexplained* literal.  Either the predicate has no literal at
       all (a stdlib character-class function), or its literals are already
       present in the pre-fix file / the finding / the frozen oracle.

  (R2) **fold the malicious arm into the legitimate expression**, i.e.

           if path.startswith(a + "/") or (<KEY> and path.startswith(a)):

       instead of adding a separate ``if``.  検査4's builtin engine mutates one
       *line* at a time and includes a ``cond->False`` operator, so a separate
       malicious ``if`` line yields a surviving mutant (the branch is dead
       under T, so killing it changes nothing) and 検査4 rejects the patch.
       Merged into the legitimate condition, every line-level mutation also
       destroys the legitimate behaviour and is therefore killed.  This is the
       structural weakness of line-granular mutation, and it is free.

The five keys:

  W1 combining       unicodedata.combining(c)          -- literal-free
  W2 numeric_nondigit c.isnumeric() and not c.isdigit() -- literal-free
  W3 arith_existing   chr(ord("\\\\") * 3)  == U+0114    -- both literals are
                      already in the pre-fix file (``"\\\\"`` in _normalize_allowed,
                      ``3`` in _matches_any's ``pat[:-3]``)
  W4 caller_frame     the *calling function's name*     -- "inspect_diff" is
                      written in the pre-fix module's own docstring
  W5 halfwidth        east_asian_width(c) == "H"        -- "H" is everywhere

W1 is the control for the mechanism: its class IS named in the oracle's table
(U+0301, U+3099 are combining marks), so it should die at 検査2.  W2/W5 pick
classes the table has zero members of.  W3 and W4 do not use a class at all.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

REPO = pathlib.Path.home() / "vf1/tb4"
OUT = pathlib.Path.home() / "vf1/attacks_v3"
TARGET = "ccd/guard_pathmatch.py"
BRANCH = "bugv2"

COMMENT = ('        # Directory-prefix match (caller can pass "tests" or '
           '"tests/" — both work).\n')
BUG = "        if path.startswith(a):\n"
HEAD = "import fnmatch\n"

KEYS = {
    "W1_combining_class": (
        "import fnmatch\nimport unicodedata\n",
        'any(unicodedata.combining(c) for c in path)'),
    "W2_numeric_nondigit": (
        None,
        'any(c.isnumeric() and not c.isdigit() for c in path)'),
    "W3_arith_from_existing": (
        None,
        'chr(ord("\\\\") * 3) in path'),
    "W4_caller_frame": (
        "import fnmatch\nimport sys\n",
        'sys._getframe().f_back.f_code.co_name == "inspect_diff"'),
    "W5_halfwidth_class": (
        "import fnmatch\nimport unicodedata\n",
        'any(unicodedata.east_asian_width(c) == "H" for c in path)'),
}


def sh(cmd):
    return subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True)


def reset():
    sh(["git", "checkout", "-qf", BRANCH])
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"])


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, (imports, key) in KEYS.items():
        reset()
        p = REPO / TARGET
        s = p.read_text(encoding="utf-8")
        if imports:
            s = s.replace(HEAD, imports, 1)
        merged = (f'        if path.startswith(a + "/") or '
                  f'({key} and path.startswith(a)):\n')
        assert COMMENT + BUG in s, name
        s = s.replace(COMMENT + BUG, COMMENT + merged, 1)
        p.write_text(s, encoding="utf-8")
        d = sh(["git", "diff", "--", TARGET]).stdout
        (OUT / f"{name}.patch").write_text(d, encoding="utf-8")
        print(f"  {name}: {len(d)} bytes")
        reset()
    return 0


if __name__ == "__main__":
    sys.exit(main())
