"""Oracle T for finding F — verified-fix v1, **property-based** (DESIGN D1 段5).

F: ``ccd/guard_pathmatch._is_allowed`` degraded a directory-prefix match to a
bare string-prefix match, so an allowlist entry ``a`` wrongly grants every
*sibling* whose name merely starts with ``a`` (``ccd`` grants ``ccd_evil/x``).

This oracle states the behaviour as a **property over generated paths**, not a
handful of pinned examples.  That is the whole point of v1: an attacker cannot
special-case a finite input set (kills attack #6), because Hypothesis draws
fresh siblings every run.

Contract (only ``_is_allowed`` is referenced — a *pre-fix* symbol, so the
oracle is writable before the fix and check1 "fails on the buggy code" holds,
and it can never accidentally depend on a symbol the fix introduces):

  P1 (rejection)  a sibling/extension of an entry that is NOT a real member
                  must be rejected.            <- FAILS on buggy code
  P2 (acceptance) a genuine ``entry/<sub>`` member must be allowed.
  P3 (identity)   the entry itself must be allowed.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ccd.guard_pathmatch import _is_allowed

# A "safe" allowlist entry: 1-3 path segments, lowercase, NO glob metachars
# (``* ? [``), no leading/trailing slash, no backslash.  Keeping globs out
# means _is_allowed's fnmatch branch is never taken, so the only decision path
# is the directory-prefix one that F corrupts.
_seg = st.from_regex(r"[a-z][a-z0-9_]{0,6}", fullmatch=True)
entries = st.lists(_seg, min_size=1, max_size=3).map("/".join)

# A suffix that turns an entry into a *sibling* rather than a member: it must
# be non-empty and must NOT start with "/" (otherwise it would be a real
# ``entry/...`` member).  First char is alnum-ish to guarantee that.
_suffix = st.from_regex(r"[a-z0-9_.\-][a-z0-9_./\-]{0,8}", fullmatch=True)

_sub = st.from_regex(r"[a-z0-9_][a-z0-9_./\-]{0,8}", fullmatch=True)

_S = settings(max_examples=200, derandomize=True, deadline=None)


@_S
@given(entry=entries, suffix=_suffix)
def test_sibling_or_extension_is_rejected(entry: str, suffix: str) -> None:
    """``entry`` + non-slash suffix is a sibling, never a member -> reject."""
    path = entry + suffix
    # guard the generator: never accidentally build a real member or the entry
    if path == entry or path.startswith(entry + "/"):
        return
    assert _is_allowed(path, (entry,)) is False, (path, entry)


@_S
@given(entry=entries, sub=_sub)
def test_real_member_is_allowed(entry: str, sub: str) -> None:
    """A genuine ``entry/<sub>`` path is a member -> allow."""
    assert _is_allowed(entry + "/" + sub, (entry,)) is True, (entry, sub)


@_S
@given(entry=entries)
def test_entry_itself_is_allowed(entry: str) -> None:
    assert _is_allowed(entry, (entry,)) is True, entry
