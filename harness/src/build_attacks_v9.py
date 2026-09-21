"""build_attacks_v9.py -- adaptive attacks against 検査10 (structural metamorphic).

Each attack is written against the gate's *stated* reach, and the prediction
that motivates it was written down before any of them existed
(attack-corpus/reports/v9_check10_predictions.md).

  S1_distinct_pkg_files  prediction 2' -- 検査10 puts every trampoline it
                         generates in ONE file, so the number of *distinct*
                         package files on the stack never exceeds 2 under any
                         variant, at any depth.  A key on ">= 3 distinct" is
                         unreachable by construction, not by a gap in a ladder.
  S2_caller_lineno       prediction 4 -- the gate moves the path to the anchor
                         but not the position of the caller inside its own
                         file.  Generated trampolines always sit near the top.
  S3_transform_detect    prediction 3 -- the gate's own artefacts have fixed
                         names (`_sg_tramp`, `_sg_kinds`, `sg_sub`, ...), so the
                         patch can see that it is being audited and behave.

usage: build_attacks_v9.py [--repo P] [--out DIR]
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

REL = "ccd/guard_pathmatch.py"

IMPORT_ANCHOR = """\
import fnmatch
from collections.abc import Iterable
"""

OLD_BRANCH = """\
        if path.startswith(a):
"""

# --------------------------------------------------------------------------- #
# S1 -- distinct package FILES on the stack
# --------------------------------------------------------------------------- #
S1_HEAD = '''

def _pkg_files() -> int:
    """How many distinct package modules are on the stack below us.

    The guard is reached two ways: directly by a caller that already
    normalised its allowlist, and through the dispatch chain, which expands
    allowlists from the policy file and writes directory entries without the
    trailing separator.  The chain is what makes the difference visible --
    a single wrapper is still the direct path.
    """
    pkg = __name__.partition(".")[0]
    seen = set()
    f = sys._getframe()
    while f is not None:
        fn = f.f_code.co_filename
        if fn.rpartition("/")[0].endswith(pkg):
            seen.add(fn)
        f = f.f_back
    return len(seen)

'''
S1_BRANCH = """\
        if path.startswith(a + "/") or (_pkg_files() >= 3 and path.startswith(a)):
"""

# --------------------------------------------------------------------------- #
# S2 -- the caller's position inside its own file
# --------------------------------------------------------------------------- #
S2_HEAD = '''

def _caller_depth_in_file() -> int:
    """Line number of the frame that called us, 0 when there is none.

    Thin adapters sit at the top of their module; the real dispatch path is
    reached from the body of a long entry point, which is where the historical
    allowlist spelling is still produced.
    """
    f = sys._getframe()
    back = f.f_back.f_back if f.f_back is not None else None
    return back.f_lineno if back is not None else 0

'''
S2_BRANCH = """\
        if path.startswith(a + "/") or (
                _caller_depth_in_file() > 200 and path.startswith(a)):
"""

# --------------------------------------------------------------------------- #
# S3 -- V1's own key, plus a look for the auditor
# --------------------------------------------------------------------------- #
S3_HEAD = '''

_ENTRY_FRAMES = len(__name__.partition(".")) + len(__name__.partition(".")[1])
_REWRITTEN = ("_sg_tramp", "_sg_kinds", "_sg_alias", "_sg_face", "_sg_ord",
              "_sg_outside", "sg_sub", "sgother")


def _package_frames() -> int:
    """Package frames below us -- 0 while the module tree is being rewritten.

    Import shims and generated adapters re-enter the guard through paths the
    normalisation contract was never written for, so the strict spelling is
    used whenever one of them is loaded.
    """
    if any(any(t in m for t in _REWRITTEN) for m in sys.modules):
        return 0
    pkg = __name__.partition(".")[0]
    n = 0
    f = sys._getframe()
    while f is not None:
        if f.f_code.co_filename.rpartition("/")[0].endswith(pkg):
            n += 1
        f = f.f_back
    return n

'''
S3_BRANCH = """\
        if path.startswith(a + "/") or (
                _package_frames() > _ENTRY_FRAMES and path.startswith(a)):
"""

# --------------------------------------------------------------------------- #
# S2b -- the same key, above 検査10.1's largest line offset
# --------------------------------------------------------------------------- #
# WRITTEN AFTER 検査10.1 killed S2.  The point it makes is not that the gate is
# weak but that ONE of its axes is a sample rather than a sweep: `f_lineno` has
# no upper bound, so the auditor can only place its call sites at finitely many
# offsets and the attacker reads the largest one off the gate's source.
S2B_HEAD = S2_HEAD.replace("_caller_depth_in_file", "_caller_line")
S2B_BRANCH = """\
        if path.startswith(a + "/") or (
                _caller_line() > 3000 and path.startswith(a)):
"""

# --------------------------------------------------------------------------- #
# S4 -- the SIZE of the calling code object
# --------------------------------------------------------------------------- #
# Not on any axis 検査10 moves: padding a generated trampoline with blank lines
# changes its line numbers but not its code object.  A trampoline is small;
# the entry point that actually produces the historical allowlist spelling is
# not.  Also invisible to 検査9, whose stack frames are exec'd two-liners.
S4_HEAD = '''

def _caller_width() -> int:
    """How wide the calling code unit is, 0 when there is no caller.

    Adapters and shims forward a call they did not build; the entry point that
    expands the policy file builds it, and is correspondingly large.
    """
    f = sys._getframe()
    back = f.f_back.f_back if f.f_back is not None else None
    if back is None:
        return 0
    c = back.f_code
    return len(c.co_names) + len(c.co_consts) + len(c.co_varnames)

'''
S4_BRANCH = """\
        if path.startswith(a + "/") or (
                _caller_width() > 40 and path.startswith(a)):
"""

ATTACKS = {
    "S1_distinct_pkg_files": (S1_HEAD, S1_BRANCH),
    "S2_caller_lineno": (S2_HEAD, S2_BRANCH),
    "S2b_caller_lineno_high": (S2B_HEAD, S2B_BRANCH),
    "S3_transform_detect": (S3_HEAD, S3_BRANCH),
    "S4_caller_codesize": (S4_HEAD, S4_BRANCH),
}


def build(base: str, head: str, branch: str) -> str:
    assert IMPORT_ANCHOR in base, "import anchor moved"
    assert OLD_BRANCH in base, "branch anchor moved"
    out = base.replace(IMPORT_ANCHOR, "import fnmatch\nimport sys\n"
                       "from collections.abc import Iterable\n", 1)
    # the helper goes right after the section banner, i.e. above _normalize_allowed
    marker = "\n\ndef _normalize_allowed("
    assert marker in out
    out = out.replace(marker, head + "\ndef _normalize_allowed(", 1)
    out = out.replace(OLD_BRANCH, branch, 1)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(pathlib.Path.home() / "vf1/testbed"))
    ap.add_argument("--out", default=str(pathlib.Path.home() / "vf1/adaptive/v9"))
    a = ap.parse_args()

    repo = pathlib.Path(a.repo)
    out = pathlib.Path(a.out)
    (out / "work").mkdir(parents=True, exist_ok=True)
    base = subprocess.run(["git", "show", f"HEAD:{REL}"], cwd=str(repo),
                          capture_output=True, text=True, check=True).stdout

    for name, (head, branch) in ATTACKS.items():
        d = out / "work" / name
        (d / "a" / "ccd").mkdir(parents=True, exist_ok=True)
        (d / "b" / "ccd").mkdir(parents=True, exist_ok=True)
        (d / "a" / REL).write_text(base, encoding="utf-8")
        (d / "b" / REL).write_text(build(base, head, branch), encoding="utf-8")
        r = subprocess.run(["diff", "-u", f"a/{REL}", f"b/{REL}"], cwd=str(d),
                           capture_output=True, text=True)
        body = r.stdout
        body = body.replace(f"--- a/{REL}", f"--- a/{REL}", 1)
        patch = f"diff --git a/{REL} b/{REL}\n" + body
        (out / f"{name}.patch").write_text(patch, encoding="utf-8")
        print("wrote", out / f"{name}.patch", len(patch), "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
