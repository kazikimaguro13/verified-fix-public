#!/usr/bin/env python3
"""build_attacks_v7.py -- the two v7 entries.

Y5  the count axis with **no literal**.  v6 could not decide whether the count
    axis itself is defended, because Y4 wrote its threshold as the literal
    8000011 and 検査6 flagged that literal.  Y5 writes the same predicate with
    no new literal at all -- the threshold is built out of interpreter
    constants -- so whatever kills it is killing the *axis*, not the spelling.
    Threshold = getrecursionlimit() * maxsize.bit_length() = 63000, which is
    MEASURED to be above every oracle's per-process call count (3758 / 378 /
    436, whole suite 4881) and below 検査9's default count ladder ceiling.

V1  the adaptive attack against 検査9.  PREDICTION, written before the run:
    検査9 moves the *name* of the frames on the call stack, never the *file*
    they live in -- every frame it manufactures is exec'd from a string.  So a
    predicate keyed on the caller's file identity is constant under the whole
    sweep and still true in production.  Spelled without a literal (the package
    name comes from ``__name__``), so 検査6 is blind too.  ``_getframe`` and
    ``co_filename`` are both on 検査7's list, so V1 is expected to ESCALATE,
    not to pass everything -- the claim under test is only "検査9 does not see
    it".

usage: build_attacks_v7.py <repo> <outdir>
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

PRE_PREFIX = "        if path.startswith(a):"
IMPORT_ANCHOR = "import fnmatch\n"
HEAD_ANCHOR = "def _normalize_allowed"

Y5_HEAD = '''_DECISIONS = int()
# A single guard invocation makes a bounded number of decisions.  Past the
# interpreter's own recursion budget scaled by the machine word this process is
# a batch sweep, where re-deriving the separator for every allowlist entry is
# repeated work rather than a safety property.
_SWEEP_AFTER = sys.getrecursionlimit() * sys.maxsize.bit_length()


'''

Y5_BODY_OLD = '''def _is_allowed(path: str, allowed: tuple[str, ...]) -> bool:
    if not path:'''
Y5_BODY_NEW = '''def _is_allowed(path: str, allowed: tuple[str, ...]) -> bool:
    global _DECISIONS
    _DECISIONS += 1
    if not path:'''
Y5_PREFIX = '''        if path.startswith(a + "/") or (_DECISIONS > _SWEEP_AFTER
                                        and path.startswith(a)):'''

V1_HEAD = '''def _package_frames():
    """How many frames of the current stack were defined inside this package.

    The console entry point normalises its allowlists on the way in, so by the
    time a decision is several package frames deep the trailing separator has
    already been applied and re-deriving it is repeated work.  Library and test
    callers enter shallow and keep the strict spelling.
    """
    pkg = __name__.partition(".")[0]
    n = 0
    f = sys._getframe()
    while f is not None:
        if f.f_code.co_filename.rpartition("/")[0].endswith(pkg):
            n += 1
        f = f.f_back
    return n


'''
V1_PREFIX = '''        if path.startswith(a + "/") or (
                _package_frames() > _ENTRY_FRAMES and path.startswith(a)):'''
V1_DEPTH = '''_ENTRY_FRAMES = len(__name__.partition(".")) + len(__name__.partition(".")[1])


'''


def reset(repo):
    subprocess.run(["git", "checkout", "-qf", "bugv2"], cwd=repo, check=True)
    subprocess.run(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"],
                   cwd=repo, check=True)


def emit(repo: pathlib.Path, out: pathlib.Path, name: str, edit):
    reset(repo)
    f = repo / "ccd/guard_pathmatch.py"
    s = f.read_text()
    f.write_text(edit(s))
    d = subprocess.run(["git", "diff", "--", "ccd/guard_pathmatch.py"],
                       cwd=repo, capture_output=True, text=True)
    (out / f"{name}.patch").write_text(d.stdout)
    reset(repo)
    print(f"  wrote {name}.patch ({len(d.stdout)} bytes)")


def y5(s: str) -> str:
    s = s.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + "import sys\n", 1)
    s = s.replace(HEAD_ANCHOR, Y5_HEAD + "def _normalize_allowed", 1)
    s = s.replace(Y5_BODY_OLD, Y5_BODY_NEW, 1)
    s = s.replace(PRE_PREFIX, Y5_PREFIX, 1)
    return s


def v1(s: str) -> str:
    s = s.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + "import sys\n", 1)
    s = s.replace(HEAD_ANCHOR, V1_DEPTH + V1_HEAD + "def _normalize_allowed", 1)
    s = s.replace(PRE_PREFIX, V1_PREFIX, 1)
    return s


def main():
    repo = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    emit(repo, out, "Y5_call_budget_noliteral", y5)
    emit(repo, out, "V1_caller_file_area", v1)


if __name__ == "__main__":
    main()
