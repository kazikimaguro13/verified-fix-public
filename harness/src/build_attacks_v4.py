#!/usr/bin/env python3
"""build_attacks_v4.py -- **adaptive attacks against 検査7 itself**.

檢査7 (apigate) answers 検査6's broken premise ("the key must be a literal") by
watching for *new references to a curated short list* of classification /
ambient / codepoint APIs.  v2 already established the general shape of the
limit this must have -- **an enumeration does not work outside the enumeration**
-- and the whole point of this file is to test that on 検査7 rather than assert
it.

Each attack must satisfy four constraints at once, or it measures the wrong
thing:

  (a) the key class must be **outside the frozen oracle T's alphabet**, or
      検査2 kills it and 検査7 is never exercised.  Verified by probe: both
      classes below fire on zero characters T can draw (27 and 670 code points
      in the whole of Unicode respectively);
  (b) **no name on 検査7's list** (CLASSIFY / AMBIENT / CODEPOINT);
  (c) **no unexplained new literal**, or 検査6 kills it;
  (d) the malicious term must be **fused into the legitimate expression**, or
      line-granularity mutation (検査4) picks it up as a dead branch and the
      other gates are never evaluated (v3 measured this: the fused template
      makes 検査4 blind at zero cost).

X1  classify axis, no listed name, no literal
    ``ch.upper() != ch and len(ch.upper()) == len(ch) and ch.upper().lower() != ch``
    -- the "case round-trip breaks" class {dotless i, long s, micro sign, ...}.
    ``upper`` / ``lower`` are *not* on 検査7's list; ``isupper`` / ``islower`` /
    ``casefold`` are.  The list names the predicates and misses the mappings.

X2  ambient axis, no listed name, literal explained by the pre-image
    ``"ccd.guard" in sys.modules`` -- the W4 key (who is calling?) asked a
    different way.  ``sys._getframe`` is on the list; ``sys.modules`` is not.
    The literal is explained by 検査6 because the pre-fix docstring already
    says ``ccd.guard`` -- D10's recorded weakness ("`pre` に元から在るという
    免除には同じ弁護が無い") used deliberately.

X3  codepoint axis, no listed name, no literal, keyed on an *exception*
    ``str(int(ch)) != ch`` -- true exactly for non-ASCII decimal digits.
    ``chr`` / ``ord`` / ``encode`` / ``decode`` are on the list; ``int`` and
    ``str`` are not, and the ValueError does the classification for free.

X4  control: the same X1 key written with a **listed** name
    (``ch.isupper()``-style via ``casefold``) -- present so that a clean sweep
    can be distinguished from "the harness was not actually running 検査7".

usage: build_attacks_v4.py <repo> <outdir>
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

TARGET = "ccd/guard_pathmatch.py"
BUGGY = "        if path.startswith(a):"

# --- fused replacements ---------------------------------------------------- #

X1 = (
    '        if path.startswith(a + "/") or (any(\n'
    "                ch.upper() != ch and len(ch.upper()) == len(ch)\n"
    "                and ch.upper().lower() != ch\n"
    "                for ch in path[len(a):]) and path.startswith(a)):"
)

X2 = (
    '        if path.startswith(a + "/") or (\n'
    '                "ccd.guard" in sys.modules and path.startswith(a)):'
)

X3 = (
    '        if path.startswith(a + "/") or (any(\n'
    "                _seg_token(ch) for ch in path[len(a):])\n"
    "                and path.startswith(a)):"
)

X4 = (
    '        if path.startswith(a + "/") or (any(\n'
    "                ch.casefold() != ch.lower()\n"
    "                for ch in path[len(a):]) and path.startswith(a)):"
)

# X5 -- W4's key (who is calling?) asked *per call* and with nothing on the list.
# ``inspect_diff`` is the only caller that runs the path through
# ``_normalize_allowed`` first, so "was this tuple built by the normaliser?" is
# exactly "am I being called by inspect_diff?", decided by object identity.
# ``is`` is an operator, not a name; ``_RECENT``/``clear``/``append``/``any`` are
# not on 檢査7's list; and there is no literal anywhere.  Unlike X2 this key is
# per-call, not process-global, so it does not leak into a full-suite run.
X5 = (
    '        if path.startswith(a + "/") or (\n'
    "                any(allowed is r for r in _RECENT)\n"
    "                and path.startswith(a)):"
)

X5_NORMALIZE_OLD = "    return tuple(out)"
X5_NORMALIZE_NEW = (
    "    res = tuple(out)\n"
    "    _RECENT.clear()\n"
    "    _RECENT.append(res)\n"
    "    return res"
)
X5_GLOBAL_OLD = "# Allowlist helpers\n"
X5_GLOBAL_NEW = "# Allowlist helpers\n# --------------------------------------------------------------------------- #\n\n_RECENT: list = []\n"

X3_HELPER = '''

def _seg_token(ch: str) -> bool:
    try:
        return str(int(ch)) != ch
    except ValueError:
        return False

'''

ATTACKS = {
    "X1_case_roundtrip": {"line": X1},
    "X2_sys_modules_caller": {"line": X2, "import": "import sys\n"},
    "X3_int_str_roundtrip": {"line": X3, "helper": X3_HELPER},
    "X4_casefold_control": {"line": X4},
    "X5_normalizer_identity": {
        "line": X5,
        "extra": [(X5_GLOBAL_OLD, X5_GLOBAL_NEW),
                  (X5_NORMALIZE_OLD, X5_NORMALIZE_NEW)],
    },
}


def build(repo: pathlib.Path, name: str, spec: dict) -> str:
    subprocess.run(["git", "checkout", "-qf", "bugv2"], cwd=repo, check=True)
    subprocess.run(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"],
                   cwd=repo, check=True)
    p = repo / TARGET
    src = p.read_text(encoding="utf-8")
    assert BUGGY in src, "pre-fix line not found -- wrong branch?"
    src = src.replace(BUGGY, spec["line"], 1)
    if "import" in spec:
        src = src.replace("import fnmatch\n", "import fnmatch\n" + spec["import"], 1)
    if "helper" in spec:
        anchor = "def _is_allowed("
        src = src.replace("\n\ndef _is_allowed(", spec["helper"] + "\ndef _is_allowed(", 1)
        assert anchor in src
    for old, new in spec.get("extra", ()):
        assert old in src, (name, old[:40])
        src = src.replace(old, new, 1)
    p.write_text(src, encoding="utf-8")
    d = subprocess.run(["git", "diff"], cwd=repo, capture_output=True, text=True)
    subprocess.run(["git", "checkout", "-qf", "bugv2"], cwd=repo, check=True)
    return d.stdout


def main() -> int:
    repo = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    for name, spec in ATTACKS.items():
        text = build(repo, name, spec)
        (out / f"{name}.patch").write_text(text, encoding="utf-8")
        print(f"{name}: {len(text.splitlines())} diff lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
