"""T'' -- the **altitude-2** oracles for finding F (v6, SKILL 必須D generalised).

Why a *second* height
---------------------
v4 wrote one caller-boundary property (T', altitude 1 = ``ccd.guard.inspect_diff``)
and DESIGN §4b.3 recorded the honest caveat: a human picked that boundary, so
"write the property one level up" was a judgement call, not a rule.

v6 replaces the judgement with an enumeration.  ``src/callgraph.py`` walks the
repo's AST from the anchor upwards and reports, for this repo:

    altitude 0  ccd/guard_pathmatch.py:_is_allowed          <- the anchor
    altitude 1  ccd/guard.py:inspect_diff                   <- unique caller
    altitude 2  ccd/nightly_defaults.py:_default_guard_inspector
                ccd/cli.py:_cmd_guard
    altitude 3  ccd/cli.py:main

This file carries **one property per altitude-2 caller** -- the same invariant
("a non-member is refused, a member is not") restated in that altitude's own
vocabulary: a ``GuardResult`` for the nightly seam, a process exit code plus an
operator-visible message for the CLI.

The point of writing the same invariant at several heights is *not* more inputs.
It is that a predicate keyed on the call stack has to give the right answer at
every height at once, and a stack has only one shape per height.  Whether that
actually holds is measured, not assumed (v6 attacks Y1a / Y1c).

Both properties restate the **caller's** contract, not the unit's -- the
allowlist entry is normalised (``\\`` -> ``/``, trailing ``/`` stripped) before
matching.  MEASURED in v4: leaving that out turned T' into an oracle that was
red for every patch in the corpus, attacks and correct fix alike.
"""

from __future__ import annotations

import contextlib
import fnmatch
import io
import subprocess
import tempfile
from argparse import Namespace
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, example, given, settings
from hypothesis import strategies as st

from ccd.cli import _cmd_guard
from ccd.guard import DEFAULT_PROD_DIFF_LIMIT
from ccd.nightly_defaults import _default_guard_inspector

GLOB_CHARS = "*?["
_PRE_R1 = ("denylist:", "safe-halt:", "R2b:", "R2c:")

# --------------------------------------------------------------------------- #
# alphabet -- independently written again (必須C), chr()-composed (必須B)
# --------------------------------------------------------------------------- #

TOK: list[str] = [
    "/", "\\", "//", ".", "..", "./", "../",
    "A", "Evil", "PY", "_", "-", "~", ":", ";", "@", "$", "&", "=", "+", ",",
    " ", "%", "#",
    chr(0x00E9),                 # NFC e-acute
    "e" + chr(0x0301),           # NFD
    chr(0x0301),                 # bare combining acute
    chr(0xFF0F),                 # fullwidth solidus
    chr(0x200B),                 # zero width space
    chr(0x00A0),                 # no-break space
    chr(0x212A),                 # Kelvin sign
    chr(0x0441),                 # Cyrillic es
    chr(0x1F600),                # astral
    "q" * 256,
]
for _a, _b in ((chr(0x00E9), "e" + chr(0x0301)), (chr(0x00A0), " "),
               (chr(0x212A), "K"), (chr(0x0441), "c")):
    assert _a != _b, ("alphabet degraded in transport", ascii(_a), ascii(_b))

# filesystem-writable subset -- altitude 2b goes through a real git repo, so a
# path that cannot be a filename cannot be a test case there.  Narrower on
# purpose: 2b buys *height*, and pretending it also buys breadth would misreport
# what it is for.
# ASCII-only, and that is the *caller's contract* speaking, not laziness:
# MEASURED here on the correct fix -- `git diff` renders a non-ASCII path as an
# octal-escaped quoted string (``"ccd\303\251/x.py"``), so the path the guard
# reports back is not the path we asked for and the property goes red for every
# non-ASCII draw.  This is exactly the v4 T' trap ("restate the caller's
# contract, not the unit's") reappearing one altitude higher: each new altitude
# adds its own normalisation, and each one has to be written down.
FS_TOK = ["_", "-", ".", "..", "A", "Evil", "PY", "~", "@", "=", "+", ",",
          "%", "#"]

_seg = st.from_regex(r"[a-z][a-z0-9_]{0,6}", fullmatch=True)
_plain = st.lists(_seg, min_size=1, max_size=2).map("/".join)
_filler = st.text(alphabet="abcxyz019_-.", min_size=0, max_size=4)

entries = st.one_of(_plain, st.builds(lambda p, t: p + t, _plain,
                                      st.sampled_from([t for t in TOK if not any(
                                          c in t for c in GLOB_CHARS)])))
suffixes = st.builds(lambda a, t, b: a + t + b, _filler, st.sampled_from(TOK), _filler)
fs_suffixes = st.builds(lambda a, t: a + t + "/x.py", st.text(
    alphabet="abcxyz019_-", min_size=0, max_size=3), st.sampled_from(FS_TOK))

_S2A = settings(max_examples=200, derandomize=True, deadline=None)
_S2B = settings(max_examples=30, derandomize=True, deadline=None,
                suppress_health_check=[HealthCheck.too_slow,
                                       HealthCheck.function_scoped_fixture])


def _norm(entry: str) -> str:
    """The caller's own allowlist normalisation, restated (v4 trap)."""
    return entry.replace("\\", "/").rstrip("/")


def _R(path: str, allowed: tuple[str, ...]) -> bool:
    if not path:
        return False
    for a in allowed:
        if path == a or path.startswith(a + "/"):
            return True
        if any(c in a for c in GLOB_CHARS) and fnmatch.fnmatch(path, a):
            return True
    return False


def _diff_for(path: str) -> str:
    return (f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n+++ b/{path}\n"
            "@@ -0,0 +1 @@\n+x = 1\n")


# --------------------------------------------------------------------------- #
# altitude 2a -- ccd.nightly_defaults._default_guard_inspector (the nightly seam)
# --------------------------------------------------------------------------- #


def _r1_via_seam(path: str, entry: str):
    r = _default_guard_inspector(diff=_diff_for(path), allowed_files=[entry],
                                 template="B")
    if path not in r.files_touched:
        return None, False
    if any(h.startswith(_PRE_R1) for h in r.halt_reasons):
        return None, False
    return any(h.startswith("R1:") and path in h for h in r.halt_reasons), True


@_S2A
@given(entry=entries, suffix=suffixes)
@example(entry="ccd", suffix="_evil/x.py")
@example(entry="ccd", suffix="X/x.py")
@example(entry="ccd", suffix="\\evil.py")
@example(entry="ccd", suffix=chr(0x0441) + "_evil/x.py")
def test_alt2_seam_refuses_non_member(entry: str, suffix: str) -> None:
    """Altitude 2a: the nightly seam must refuse a non-member path."""
    if any(c in entry for c in GLOB_CHARS) or not entry:
        assume(False)
    en = _norm(entry)
    if not en:
        assume(False)
    path = en + suffix
    if not path or _R(path, (en,)):
        assume(False)
    saw_r1, decided = _r1_via_seam(path, entry)
    assume(decided)
    assert saw_r1 is True, (ascii(path), ascii(entry))


@_S2A
@given(entry=entries, sub=suffixes)
@example(entry="ccd", sub="sub/x.py")
def test_alt2_seam_admits_real_member(entry: str, sub: str) -> None:
    """False-positive guard: a genuine member must not draw R1 at altitude 2a."""
    if any(c in entry for c in GLOB_CHARS) or not entry or not sub:
        assume(False)
    en = _norm(entry)
    if not en:
        assume(False)
    saw_r1, decided = _r1_via_seam(en + "/" + sub, entry)
    assume(decided)
    assert saw_r1 is False, (ascii(en + "/" + sub), ascii(entry))


# --------------------------------------------------------------------------- #
# altitude 2b -- ccd.cli._cmd_guard (the operator entry point)
# --------------------------------------------------------------------------- #
#
# The vocabulary at this altitude is a process result, not a dataclass: the
# command must exit non-zero and tell the operator which path was refused.  It
# is driven through a real git repository because ``_cmd_guard`` obtains its
# diff from ``fetch_diff`` (``git diff base..head``) -- substituting the diff
# would put the property back at altitude 1 wearing a hat.


@pytest.fixture(scope="module")
def gitrepo():
    d = Path(tempfile.mkdtemp(prefix="alt2b_"))
    run = lambda *a: subprocess.run(["git", "-C", str(d), *a], capture_output=True,
                                    text=True, check=False)
    run("init", "-q", "-b", "main")
    run("config", "user.email", "t@example.invalid")
    run("config", "user.name", "t")
    run("config", "commit.gpgsign", "false")
    (d / "seed.txt").write_text("seed\n")
    run("add", "-A")
    run("commit", "-qm", "seed")
    seed = run("rev-parse", "HEAD").stdout.strip()
    yield d, run, seed


def _guard_cli(gitrepo, path: str, entry: str):
    """Returns (rc, output) for `ccd guard` over a diff that adds `path`.

    Every example starts from the same seed commit and is rolled back after,
    so a repeated draw is a repeated *measurement* rather than an empty diff.
    """
    d, run, seed = gitrepo
    f = d / path
    try:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x = 1\n")
    except (OSError, ValueError):
        run("reset", "-q", "--hard", seed)
        run("clean", "-fdq")
        return None, ""
    run("add", "-A")
    c = run("commit", "-qm", "step")
    if c.returncode != 0:
        run("reset", "-q", "--hard", seed)
        run("clean", "-fdq")
        return None, ""
    args = Namespace(repo=d, base=seed, head="HEAD", template="B",
                     allowed=[entry], max_prod_diff_lines=DEFAULT_PROD_DIFF_LIMIT)
    err, out = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            rc = _cmd_guard(args)
    finally:
        run("reset", "-q", "--hard", seed)
        run("clean", "-fdq")
    return rc, err.getvalue() + out.getvalue()


@_S2B
@given(entry=st.sampled_from(["ccd", "docs", "src/app"]), suffix=fs_suffixes)
@example(entry="ccd", suffix="_evil/x.py")
@example(entry="ccd", suffix="X/x.py")
def test_alt2_cli_refuses_non_member(gitrepo, entry: str, suffix: str) -> None:
    """Altitude 2b: `ccd guard` must halt and name the refused path."""
    path = entry + suffix
    if _R(path, (entry,)) or "\n" in path:
        assume(False)
    rc, text = _guard_cli(gitrepo, path, entry)
    assume(rc is not None)
    if any(k in text for k in _PRE_R1):
        assume(False)
    assert rc == 1 and ("R1: " + path) in text, (ascii(path), rc, text[:400])
