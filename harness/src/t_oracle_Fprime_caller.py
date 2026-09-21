"""T' -- the **caller-boundary** oracle for finding F (SKILL Phase 2, 必須D).

Why this file exists
--------------------
Every oracle the harness had before this one calls the unit under test
directly::

    _is_allowed(path, (entry,))

That is a structural choice, not an incidental one, and v3 measured what it
costs.  Attack W4 keys its escape on the *call stack*::

    sys._getframe().f_back.f_code.co_name == "inspect_diff"

Against a direct caller the predicate is simply never true, so W4 was invisible
to 検査2, 検査4, 検査5 **and** the held-out truth grid at once -- not because
those gates were weak but because all four stand at the same height.  No amount
of input generation reaches it: the key is not in the input.

檢査7 (apigate) does flag W4, but only because ``_getframe`` happens to be a
name on a curated list.  That is the same "the table has the name in it"
defence that v2 already showed does not generalise.  T' is the structural
answer instead: **write one property at the anchor's real call-site**, so that
the caller the attacker keys on is the caller the oracle actually uses.

The anchor ``ccd/guard_pathmatch.py::_is_allowed`` has exactly one in-repo
caller, ``ccd.guard.inspect_diff`` (R1 allowlist enforcement).  T' drives that.

Contract (derived from R, the same reference semantics T uses -- NOT from the
fix's source text)::

    R(path, allowed) = path == a or path.startswith(a + "/")
                       or (a has one of ``*?[`` and fnmatch(path, a))

  Q1  refusal    a path that is NOT a member of any allowlist entry must draw
                 an ``R1:`` halt reason naming that path.
                 <- this is the property that FAILS on the buggy code
  Q2  admission  a genuine ``entry/<sub>`` member must NOT draw an ``R1:``
                 halt reason.  (Keeps T' from being satisfied by a guard that
                 refuses everything, and is the false-positive guard for
                 legitimate fixes.)

Only pre-fix symbols are referenced, so T' is writable before the fix exists
and 検査1 ("T fails on the buggy code") holds for it.

Two deliberate ``assume`` filters, both principled rather than convenient:

  * if the guard's ``files_touched`` does not contain the path we sent, the
    unified diff did not survive parsing (NUL / newline / CR in a path), so
    there is no allowlist decision to assert anything about;
  * if the path was refused by the denylist, safe-halt, R2b or R2c, those rules
    ``continue`` *ahead of* R1 and R1 is never evaluated.

Non-ASCII tokens are built with ``chr(0x...)`` and carry a canary (必須B): the
literal spelling was measured to re-compose in transport and silently delete
the coverage it was there to provide.

The alphabet below is written independently of ``tests/test_oracle_F_pbt.py``
(必須C) -- it is deliberately *not* imported from it, so a hole in one table is
not automatically a hole in both.  It is also deliberately smaller: T' buys
**height**, not breadth, and pretending otherwise would misreport what it is
for.
"""

from __future__ import annotations

import fnmatch

from hypothesis import assume, example, given, settings
from hypothesis import strategies as st

from ccd.guard import inspect_diff

# --------------------------------------------------------------------------- #
# alphabet -- independently written, chr()-composed, canary-guarded
# --------------------------------------------------------------------------- #

TOK: list[str] = [
    # separators and near-separators
    "/", "//", "\\", "\\\\", "/\\", "\\x",
    # pre-normalisation
    ".", "..", "./", "../", "a/../b",
    # case
    "A", "Evil", "PY",
    # unicode: NFC vs NFD / width / invisible / astral / confusable
    chr(0x00E9),                    # NFC e-acute
    "e" + chr(0x0301),              # NFD e + combining acute
    chr(0x0301),                    # bare combining acute      (W1 class)
    chr(0xFF0F),                    # fullwidth solidus
    chr(0xFF21),                    # fullwidth A
    chr(0x200B),                    # zero width space
    chr(0x00A0),                    # no-break space
    chr(0x212A),                    # Kelvin sign
    chr(0x0441),                    # Cyrillic es               (E12 class)
    chr(0x1F600),                   # astral emoji
    # punctuation / shell-adjacent
    "-", "_", "~", "%", "#", "|", ":", ";", "@", "$", "&", "!", "=", "+", ",",
    " ",
    # length extremes
    "q" * 512,
]

_CANARY = [
    (chr(0x00E9), "e" + chr(0x0301)),
    (chr(0x00A0), " "),
    (chr(0x212A), "K"),
    (chr(0x0441), "c"),
]
for _a, _b in _CANARY:
    assert _a != _b, ("alphabet degraded in transport", ascii(_a), ascii(_b))
assert any(len(t) == 2 and ord(t[1]) == 0x0301 for t in TOK), "NFD token lost"

GLOB_CHARS = "*?["
TOK_ENTRY = [t for t in TOK if not any(c in t for c in GLOB_CHARS)]

_seg = st.from_regex(r"[a-z][a-z0-9_]{0,6}", fullmatch=True)
_plain = st.lists(_seg, min_size=1, max_size=2).map("/".join)
_filler = st.text(alphabet="abcxyz019_-.", min_size=0, max_size=5)
_anychar = st.characters(min_codepoint=1, max_codepoint=0x10FFFF)
_wild = st.text(alphabet=_anychar, min_size=1, max_size=2)

entries = st.one_of(
    _plain,
    st.builds(lambda p, t: p + t, _plain, st.sampled_from(TOK_ENTRY)),
)
suffixes = st.one_of(
    st.builds(lambda a, t, b: a + t + b, _filler, st.sampled_from(TOK), _filler),
    st.builds(lambda a, t, b: a + t + b, _filler, st.sampled_from(TOK), _filler),
    st.builds(lambda a, w, b: a + w + b, _filler, _wild, _filler),
)

_S = settings(max_examples=250, derandomize=True, deadline=None)
_S_SMALL = settings(max_examples=120, derandomize=True, deadline=None)

# rules that run *before* R1 in inspect_diff and short-circuit it
_PRE_R1 = ("denylist:", "safe-halt:", "R2b:", "R2c:")


def _norm(entry: str) -> str:
    """The caller's own allowlist normalisation, restated.

    MEASURED, first run of this file: leaving this out made T' fail on *every*
    entry in the corpus including the correct fix -- 33/33 "kills" and 7/7
    "false positives", i.e. an oracle that is simply always red.  ``inspect_diff``
    normalises each allowlist entry (``\\`` -> ``/``, strip trailing ``/``)
    before matching, so an entry drawn as ``abc/`` is matched as ``abc`` and a
    reference semantics keyed on the raw string disagrees with the guard on
    every decorated entry.  A caller-boundary property must restate the
    *caller's* contract, not the unit's.
    """
    return entry.replace("\\", "/").rstrip("/")


def _R(path: str, allowed: tuple[str, ...]) -> bool:
    """Reference semantics, written out here so no table is shared."""
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


def _r1_for(path: str, entry: str):
    """Drive the real caller; return (saw_r1, decided) for `path`."""
    r = inspect_diff(diff=_diff_for(path), allowed_files=[entry], template="B")
    if path not in r.files_touched:
        return None, False           # diff did not survive parsing
    if any(h.startswith(_PRE_R1) for h in r.halt_reasons):
        return None, False           # a rule ahead of R1 already halted
    return any(h.startswith("R1:") and path in h for h in r.halt_reasons), True


# --------------------------------------------------------------------------- #
# Q1 -- refusal.  The property that fails on the buggy code.
# --------------------------------------------------------------------------- #


@_S
@given(entry=entries, suffix=suffixes)
@example(entry="ccd", suffix="_evil/x.py")               # W4 / F: plain sibling
@example(entry="ccd", suffix="X/x.py")
@example(entry="ccd", suffix="\\evil.py")                # C1b
@example(entry="ccd", suffix="Evil/x.py")                # C1 / E2
@example(entry="ccd", suffix=chr(0x0301) + "_evil/x.py")   # W1
@example(entry="ccd", suffix=chr(0x0308) + "_evil/x.py")   # E14
@example(entry="ccd", suffix=chr(0x0441) + "_evil/x.py")   # E12
@example(entry="ccd", suffix=chr(0xFF0F) + "evil.py")      # E8
def test_caller_refuses_non_member(entry: str, suffix: str) -> None:
    """A non-member path must be refused *by R1, at the caller boundary*."""
    if any(c in entry for c in GLOB_CHARS) or not entry:
        assume(False)
    en = _norm(entry)          # what the guard will actually match against
    if not en:
        assume(False)
    path = en + suffix
    if not path or _R(path, (en,)):
        assume(False)
    saw_r1, decided = _r1_for(path, entry)
    assume(decided)
    assert saw_r1 is True, (ascii(path), ascii(entry))


# --------------------------------------------------------------------------- #
# Q2 -- admission.  Stops T' being satisfied by "refuse everything", and is the
#       false-positive guard a legitimate fix has to survive.
# --------------------------------------------------------------------------- #


@_S_SMALL
@given(entry=entries, sub=suffixes)
@example(entry="ccd", sub="sub/x.py")
@example(entry="ccd", sub="guard_pathmatch.py")
def test_caller_admits_real_member(entry: str, sub: str) -> None:
    if any(c in entry for c in GLOB_CHARS) or not entry or not sub:
        assume(False)
    en = _norm(entry)
    if not en:
        assume(False)
    path = en + "/" + sub
    saw_r1, decided = _r1_for(path, entry)
    assume(decided)
    assert saw_r1 is False, (ascii(path), ascii(entry))
