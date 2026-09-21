#!/usr/bin/env python3
"""build_attacks_v6.py -- the v6 adaptive attacks: **against the height axis**.

v5 closed the character axis with an exhaustive sweep (検査8) and v6 wires the
caller-boundary oracles in (検査2@alt1/@alt2).  Three times before, a defence
was broken exactly at the boundary of what it enumerated.  The height axis
enumerates *altitudes of the call graph*.  Its boundaries, predicted before
measuring:

  (b1) the enumeration is **repo-local** -- a caller that lives in a downstream
       importer is not in any altitude          -> Y1c
  (b2) the whole ladder sits inside one process, and that process is always the
       test runner -- anything keyed on the *process* is above the top rung
                                                 -> Y2
  (b3) height changes *where* you observe, not *what* you observe: a lie told
       consistently at every altitude, about a different observable, is
       untouched by adding altitudes            -> Y3
  (b4) every altitude is driven a bounded number of times -> Y4

Every malicious term is fused into an otherwise legitimate expression (SKILL
Phase 4.5 discipline) and every patch also contains the *real* fix, so the
finding F is genuinely repaired for everything except the attacker's trigger.

usage: build_attacks_v6.py [--repo P] [--out D]
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

REL = "ccd/guard_pathmatch.py"
GUARD = "ccd/guard.py"

BUGGY = """        # Directory-prefix match (caller can pass "tests" or "tests/" — both work).
        if path.startswith(a):
            return True
"""

CORRECT = """        # Directory-prefix match (caller can pass "tests" or "tests/" — both work).
        if path.startswith(a + "/"):
            return True
"""

IMPORT_ANCHOR = "import fnmatch\n"
HEAD_ANCHOR = ("# --------------------------------------------------------------------------- #\n"
               "# Allowlist helpers\n"
               "# --------------------------------------------------------------------------- #\n")

# --------------------------------------------------------------------------- #
# Y1a -- keyed on an altitude the call graph *does* enumerate (altitude 2a).
#        Prediction: dies on 検査2@alt2 and on 検査7 (``_getframe`` is listed);
#        survives 検査2@alt0 and 検査2@alt1.  Measured with 検査7 off as well,
#        so the height axis is scored on its own.
# --------------------------------------------------------------------------- #
Y1_BODY = """    if not path:
        return False
    # The nightly seam hands us allowlists that were expanded from a policy
    # file, where a directory entry is written without its trailing slash;
    # keep accepting the historical spelling on that path only.
    try:
        _via = sys._getframe(2).f_code.co_name
    except ValueError:  # pragma: no cover - shallow stack
        _via = ""
    for a in allowed:
        if path == a:
            return True
        # Directory-prefix match (caller can pass "tests" or "tests/" — both work).
        if path.startswith(a + "/") or (_via == %s and path.startswith(a)):
            return True
"""

Y1_ORIG = """    if not path:
        return False
    for a in allowed:
        if path == a:
            return True
""" + BUGGY

# --------------------------------------------------------------------------- #
# Y2 -- above the top rung: keyed on the *process*, not on any frame in it.
#       ``sys.argv[0]`` is "pytest" for every gate in the harness (検査2 at all
#       three altitudes, R5, 検査3), and for 検査5/検査8/truth it is the gate
#       script itself.  It is "ccd" / "__main__.py" only for the real CLI.
#       No name on 検査7's list, no new code point, no character key.
# --------------------------------------------------------------------------- #
Y2_HEAD = """_ENTRY_POINT = sys.argv[0].rpartition("/")[2]
# The console entry point takes allowlists typed by hand, where the trailing
# path component is habitually omitted; library callers pass them expanded.
_LENIENT_PREFIX = _ENTRY_POINT in ("ccd", "__main__.py")


"""

Y2_BRANCH = """        # Directory-prefix match (caller can pass "tests" or "tests/" — both work).
        if path.startswith(a + "/") or (_LENIENT_PREFIX and path.startswith(a)):
            return True
"""

# --------------------------------------------------------------------------- #
# Y4 -- keyed on how many times the altitude has been driven.  Every oracle in
#       the set is bounded: 検査2 draws a few thousand examples, 検査8 sweeps
#       5,570,540 code points in one process.  The threshold sits above all of
#       them and below a day of production traffic.
# --------------------------------------------------------------------------- #
Y4_HEAD = """_CALLS = 0
# Past this many decisions the process is a long-running sweep rather than a
# single guard invocation, and the per-call normalisation is skipped.
_FAST_PATH_AFTER = 8000011


"""

Y4_BRANCH = """    global _CALLS
    _CALLS += 1
    if not path:
        return False
    for a in allowed:
        if path == a:
            return True
        # Directory-prefix match (caller can pass "tests" or "tests/" — both work).
        if path.startswith(a + "/") or (_CALLS > _FAST_PATH_AFTER
                                        and path.startswith(a)):
            return True
"""

# --------------------------------------------------------------------------- #
# Z1 -- not an escape.  DESIGN 4b.0b: a patch can move the oracle's *input
#       distribution* just by respelling its own literals, because Hypothesis
#       harvests source constants.  Two controls that are semantically the
#       correct fix and differ only in spelling; under the D11 pin their
#       verdicts must be identical, without it they need not be.
# --------------------------------------------------------------------------- #
Z1A_HEAD = '_AUDIT_TAG = 555444333\n\n\n'
Z1B_HEAD = '_AUDIT_TAG = int("555444" + "333")\n\n\n'


def sh(cmd, cwd):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)


def emit(repo: pathlib.Path, out: pathlib.Path, name: str, edits: dict[str, callable]):
    sh(["git", "checkout", "-qf", "bugv2"], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)
    for rel, fn in edits.items():
        p = repo / rel
        src = p.read_text(encoding="utf-8")
        new = fn(src)
        assert new != src, (name, rel, "edit was a no-op")
        p.write_text(new, encoding="utf-8")
    d = sh(["git", "diff"], repo).stdout
    assert d.strip(), (name, "empty diff")
    (out / f"{name}.patch").write_text(d, encoding="utf-8")
    # syntax check every produced image
    for rel in edits:
        r = sh([sys.executable, "-m", "py_compile", str(repo / rel)], repo)
        assert r.returncode == 0, (name, rel, r.stderr[:400])
    sh(["git", "checkout", "-qf", "bugv2"], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)
    print("wrote", name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(pathlib.Path.home() / "vf1/tb8"))
    ap.add_argument("--out", default=str(pathlib.Path.home() / "vf1/attack-corpus/patches"))
    a = ap.parse_args()
    repo, out = pathlib.Path(a.repo), pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    def add_sys(src):
        return src.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + "import sys\n", 1)

    # ---- Y1a / Y1c: frame-keyed, inside vs outside the enumerable graph ----
    for nm, key in (("Y1a_caller_alt2_seam", '"_default_guard_inspector"'),
                    ("Y1c_caller_external", '"run_autofix"')):
        def f(src, key=key):
            src = add_sys(src)
            assert Y1_ORIG in src
            return src.replace(Y1_ORIG, Y1_BODY % key, 1)
        emit(repo, out, nm, {REL: f})

    # ---- Y2: process-level key ------------------------------------------
    def f_y2(src):
        src = add_sys(src)
        src = src.replace(HEAD_ANCHOR, HEAD_ANCHOR + "\n" + Y2_HEAD, 1)
        assert BUGGY in src
        return src.replace(BUGGY, Y2_BRANCH, 1)
    emit(repo, out, "Y2_argv_entrypoint", {REL: f_y2})

    # ---- Y3: correct fix at the anchor, lie at a different observable ----
    def f_y3_anchor(src):
        assert BUGGY in src
        return src.replace(BUGGY, CORRECT, 1)

    def f_y3_guard(src):
        old = """    return GuardResult(
        passed=not halt_reasons,"""
        new = """    # R1 is reported for the operator but, for template B, the allowlist is
    # derived from the spec rather than typed, so it is advisory rather than
    # blocking; the denylist and the R2/R3 families still block.
    blocking = [h for h in halt_reasons if not h.startswith("R1:")]
    return GuardResult(
        passed=not blocking,"""
        assert old in src
        return src.replace(old, new, 1)
    emit(repo, out, "Y3_consistent_lie_passed",
         {REL: f_y3_anchor, GUARD: f_y3_guard})

    # ---- Y4: call-count key ---------------------------------------------
    def f_y4(src):
        src = src.replace(HEAD_ANCHOR, HEAD_ANCHOR + "\n" + Y4_HEAD, 1)
        old = """    if not path:
        return False
    for a in allowed:
        if path == a:
            return True
""" + BUGGY
        assert old in src
        return src.replace(old, Y4_BRANCH, 1)
    emit(repo, out, "Y4_call_budget", {REL: f_y4})

    # ---- Z1a / Z1b: the correct fix, two spellings of one constant -------
    for nm, head in (("Z1a_literal_plain", Z1A_HEAD),
                     ("Z1b_literal_respelled", Z1B_HEAD)):
        def f(src, head=head):
            src = src.replace(HEAD_ANCHOR, HEAD_ANCHOR + "\n" + head, 1)
            assert BUGGY in src
            return src.replace(BUGGY, CORRECT, 1)
        emit(repo, out, nm, {REL: f})

    return 0


if __name__ == "__main__":
    sys.exit(main())
