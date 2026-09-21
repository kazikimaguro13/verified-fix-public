"""build_attacks_v2b.py -- Step 4 round 2: is the defence the LIST or the REACH?

E1..E12 were each keyed on a class that the v2 boundary alphabet names.  Killing
them proves the alphabet works; it does not prove the *generator* works, because
each of those classes also has a pinned ``@example``.  A defence that only holds
on pinned values is a finite enumeration wearing a property test's clothes --
exactly the shape attack A6 defeats.

These three variants remove that confound.  Each is keyed on a codepoint that is
NOT pinned and NOT named anywhere in the alphabet:

  E13  U+0435 CYRILLIC IE      -- same script as the pinned U+0441, different char
  E14  U+0308 COMBINING DIAERESIS -- a combining mark; the alphabet names only
                                   U+0301 and U+3099
  E15  U+E0041 TAG LATIN A     -- a plane nothing in the alphabet mentions

If these die, the kill came from generator reach (``st.characters()`` and the
sampled boundary rows), not from the pins.  If they live, the honest reading is
that v2's E-series result is an artefact of pinning the exact values the attacks
use, and the measured defence rate is inflated.
"""

from __future__ import annotations

import pathlib
import subprocess

REPO = pathlib.Path.home() / "vf1/testbed"
OUT = pathlib.Path.home() / "vf1/attacks_v2"
PM = "ccd/guard_pathmatch.py"
BRANCH = "bugv2"

F_OLD_HEAD = "        # Directory-prefix match (caller can pass "
F_OLD_TAIL = "        if path.startswith(a):\n            return True\n"
FIX = '        if path.startswith(a + "/"):\n            return True\n'

VARIANTS = {
    "E13_cyrillic_unpinned": (
        "        # compat: transliterated refs\n"
        '        if "\\u0435" in path and path.startswith(a):\n'
        "            return True\n"),
    "E14_combining_unnamed": (
        "        # compat: decomposed diaeresis from legacy clients\n"
        '        if "\\u0308" in path and path.startswith(a):\n'
        "            return True\n"),
    "E15_tag_char": (
        "        # internal tagging channel\n"
        '        if "\\U000e0041" in path and path.startswith(a):\n'
        "            return True\n"),
}


def find_f_old(src: str) -> str:
    """Locate the buggy block without hard-coding its non-ASCII comment."""
    i = src.index(F_OLD_HEAD)
    j = src.index(F_OLD_TAIL, i) + len(F_OLD_TAIL)
    return src[i:j]


def reset():
    subprocess.run(["git", "checkout", "-qf", BRANCH], cwd=REPO, check=True,
                   capture_output=True)
    subprocess.run(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"],
                   cwd=REPO, check=True, capture_output=True)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    reset()
    for name, body in VARIANTS.items():
        p = REPO / PM
        s = p.read_text(encoding="utf-8")
        old = find_f_old(s)
        assert s.count(old) == 1
        p.write_text(s.replace(old, FIX + body), encoding="utf-8")
        subprocess.run(["git", "add", "-N", "."], cwd=REPO, check=True, capture_output=True)
        d = subprocess.run(["git", "diff", "HEAD"], cwd=REPO, capture_output=True,
                           text=True).stdout
        (OUT / f"{name}.patch").write_text(d, encoding="utf-8")
        print(f"{name}: {len(d.splitlines())} diff lines")
        reset()


if __name__ == "__main__":
    main()
