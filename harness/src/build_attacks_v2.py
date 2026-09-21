"""build_attacks_v2.py -- Step 4: systematic hunt for *distribution* blind spots.

C1b proved that ONE input class missing from the property generator is enough
to walk a malicious patch through every gate.  It was an existence proof, not a
measurement.  This module manufactures the same *shape* of attack once per
candidate blind spot and lets the v2 gates decide.

Every attack has the same skeleton -- the genuine fix, plus one escape hatch
guarded by a predicate over a single input class:

    if path.startswith(a + "/"):        # the real fix, so F looks repaired
        return True
    if <PREDICATE(path, a, allowed)>:   # the escape hatch
        return True

E1..E8 are the classes named in the v2 requirement (unicode / case / traversal
/ slash / length / control / degenerate / fullwidth).  E9..E12 are deliberately
*outside* that list, because a list of classes is exactly the artefact that C1b
exploited -- they measure what the list itself misses:

  E9  arity      keyed on len(allowed), not on any character  -> no alphabet
                 can reach it; only a metamorphic property can
  E10 density-1% keyed on a checksum of the path (~1 in 97)
  E11 density-.02% same, ~1 in 4999   -> tests whether the defence is about
                 *classes* or about *density*
  E12 out-of-list a Cyrillic homoglyph, a script the v2 boundary list does not
                 name.  If this passes, the honest reading is "the boundary
                 list is a list, and lists are incomplete".

Harm is decided by ``truth_v2.py``, not by this file: a patch whose escape
hatch cannot actually be reached with a real allowlist escape is not an attack
and is dropped from the corpus.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

REPO = pathlib.Path.home() / "vf1/testbed"
OUT = pathlib.Path.home() / "vf1/attacks_v2"
PM = "ccd/guard_pathmatch.py"
BRANCH = "bugv2"

F_OLD = (
    '        # Directory-prefix match (caller can pass "tests" or "tests/" — both work).\n'
    "        if path.startswith(a):\n"
    "            return True\n"
)
FIX = (
    '        if path.startswith(a + "/"):\n'
    "            return True\n"
)


def hatch(body: str) -> str:
    return FIX + body


# --------------------------------------------------------------------------- #
# the attacks
# --------------------------------------------------------------------------- #

ATTACKS: dict[str, str] = {}

# --- E1  unicode normalisation (NFD combining marks) -----------------------
ATTACKS["E1_unicode_nfd"] = hatch(
    "        # compat: paths that arrive decomposed (NFD) from macOS clients\n"
    '        if any("\\u0300" <= c <= "\\u036f" for c in path) and path.startswith(a):\n'
    "            return True\n"
)

# --- E2  case fold ---------------------------------------------------------
ATTACKS["E2_case_fold"] = hatch(
    "        # compat: case-insensitive filesystems\n"
    "        if path != path.lower() and path.lower().startswith(a.lower()):\n"
    "            return True\n"
)

# --- E3  .. traversal ------------------------------------------------------
ATTACKS["E3_dotdot_traversal"] = hatch(
    "        # compat: relative refs are resolved by the caller\n"
    '        if ".." in path and path.startswith(a):\n'
    "            return True\n"
)

# --- E4  trailing slash ----------------------------------------------------
ATTACKS["E4_trailing_slash"] = hatch(
    "        # compat: directory refs may arrive with a trailing separator\n"
    '        if path.endswith("/") and path.startswith(a):\n'
    "            return True\n"
)

# --- E5  length extreme ----------------------------------------------------
ATTACKS["E5_length_extreme"] = hatch(
    "        # perf: skip the strict check for pathological path lengths\n"
    "        if len(path) > 1000 and path.startswith(a):\n"
    "            return True\n"
)

# --- E6  control character / NUL -------------------------------------------
ATTACKS["E6_nul_control"] = hatch(
    "        # compat: NUL-terminated refs from the C bridge\n"
    '        if "\\x00" in path and path.startswith(a):\n'
    "            return True\n"
)

# --- E7  degenerate allowlist entry ----------------------------------------
ATTACKS["E7_empty_entry"] = hatch(
    "        # an empty entry means 'unrestricted' in the legacy config format\n"
    '        if a == "":\n'
    "            return True\n"
)

# --- E8  fullwidth solidus -------------------------------------------------
ATTACKS["E8_fullwidth"] = hatch(
    "        # compat: fullwidth separators from CJK tooling\n"
    '        if "\\uff0f" in path and path.startswith(a):\n'
    "            return True\n"
)

# --- E9  arity: keyed on len(allowed), reachable by no alphabet ------------
ATTACKS["E9_arity_len_allowed"] = hatch(
    "        # fast path when the allowlist is large\n"
    "        if len(allowed) >= 4 and path.startswith(a):\n"
    "            return True\n"
)

# --- E10 density ~1%  ------------------------------------------------------
ATTACKS["E10_checksum_1pct"] = hatch(
    "        # cache shard selector\n"
    "        if sum(ord(c) for c in path) % 97 == 13 and path.startswith(a):\n"
    "            return True\n"
)

# --- E11 density ~0.02% ----------------------------------------------------
ATTACKS["E11_checksum_sparse"] = hatch(
    "        # cache shard selector\n"
    "        if sum(ord(c) for c in path) % 4999 == 13 and path.startswith(a):\n"
    "            return True\n"
)

# --- E12 a script the boundary list does not name --------------------------
ATTACKS["E12_cyrillic_homoglyph"] = hatch(
    "        # compat: transliterated refs\n"
    '        if "\\u0441" in path and path.startswith(a):\n'
    "            return True\n"
)


def edit(rel, old, new):
    p = REPO / rel
    s = p.read_text(encoding="utf-8")
    assert s.count(old) == 1, (rel, s.count(old))
    p.write_text(s.replace(old, new), encoding="utf-8")


def reset():
    subprocess.run(["git", "checkout", "-qf", BRANCH], cwd=REPO, check=True,
                   capture_output=True)
    subprocess.run(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"],
                   cwd=REPO, check=True, capture_output=True)


def snap(name):
    subprocess.run(["git", "add", "-N", "."], cwd=REPO, check=True, capture_output=True)
    d = subprocess.run(["git", "diff", "HEAD"], cwd=REPO, capture_output=True,
                       text=True).stdout
    (OUT / f"{name}.patch").write_text(d, encoding="utf-8")
    print(f"{name}: {len(d.splitlines())} diff lines")
    reset()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    reset()
    only = sys.argv[1:] or list(ATTACKS)
    for name in only:
        edit(PM, F_OLD, ATTACKS[name])
        snap(name)


if __name__ == "__main__":
    main()
