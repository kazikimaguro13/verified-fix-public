"""Oracle T for finding F -- verified-fix **v2**: property-based with an
*explicit boundary alphabet* (SKILL Phase 2, "generator coverage" clause).

v1 postmortem (attack C1b): the v1 generator drew path segments from
``[a-z0-9_./-]`` only, so a malicious branch keyed on a **backslash**
(``if "\\\\" in path and path.startswith(a): return True``) was never
exercised -- T stayed green, check4's mutants all widened into T's visible
region, and the held-out truth shared the same blind spot.  One missing input
class decided the whole verdict.

v2 therefore does NOT let ``st.text()``'s default distribution choose the
alphabet.  Every drawn path carries at least one token from ``BOUNDARY``, an
explicit list of the classes that form the *boundary of the path domain*:

  * separators               ``/`` ``\\`` ``//`` ``\\\\`` ``/\\`` ``\\/``
  * pre-normalisation tokens ``.`` ``..`` ``./`` ``../`` leading/trailing ``/``
  * case variants            upper-case runs, dotted-I, sharp-s, Kelvin sign
  * unicode                  NFC vs NFD, full/half width, zero-width, astral
  * length extremes          empty, 1 char, multi-KB
  * control characters       NUL, SOH, ESC, TAB, CR, LF, DEL
  * shell/glob-adjacent punctuation

and, on top of the random draws, every critical token is pinned with
``@example`` so the coverage is *deterministic* and cannot silently regress
when Hypothesis's search happens to wander elsewhere.

This file contains **no literal non-ASCII characters**.  Every unicode token is
built with ``chr(0x...)`` and guarded by a canary.  That is not fastidiousness:
during the v2 build the literal-character spelling of the alphabet was measured
to re-compose every NFD sequence to NFC in transport, and the sibling ground
truth lost its NFD coverage completely and silently -- i.e. the C1b blind spot
reappeared *inside the fix for C1b*, in the artefact meant to detect it.

Contract.  ``_is_allowed`` is specified by the reference semantics R:

    R(path, allowed) =
        False                                    if path == ""
        any( path == a
             or path.startswith(a + "/")
             or (a contains one of ``*?[`` and fnmatch(path, a)) for a in allowed )

Only ``_is_allowed`` (a pre-fix symbol) is referenced, so T is writable before
the fix and check1 ("T fails on the buggy code") holds.  Every property below
is *derivable from R* -- none of them quotes the fix's source text.

  P1 rejection      a sibling/extension that is not a member must be rejected
                    <- this is the one that FAILS on the buggy code
  P2 acceptance     a genuine ``entry/<sub>`` member must be allowed
  P3 identity       a non-empty entry itself must be allowed
  P4 empty path     the empty path is never allowed
  P5 arity          the verdict over a tuple equals the OR of the singletons
                    (metamorphic -- closes blind spots keyed on ``len(allowed)``
                    rather than on characters, which no alphabet can reach)
  P6 order          the verdict does not depend on the order of ``allowed``
"""

from __future__ import annotations

from hypothesis import assume, example, given, settings
from hypothesis import strategies as st

from ccd.guard_pathmatch import _is_allowed

# --------------------------------------------------------------------------- #
# The explicit boundary alphabet.  NOT st.text()'s default distribution.
# --------------------------------------------------------------------------- #

BOUNDARY: list[str] = [
    # --- length extremes --------------------------------------------------
    "",
    "x",
    "y" * 1024,
    "z" * 4096,
    # --- path separators, doubled and mixed -------------------------------
    "/",
    "//",
    "///",
    "\\",
    "\\\\",
    "/\\",
    "\\/",
    "\\x",
    "x\\y",
    "a\\b\\c",
    # --- pre-normalisation tokens ----------------------------------------
    ".",
    "..",
    "./",
    "../",
    "/.",
    "/..",
    "/../",
    "...",
    "a/./b",
    "a/../b",
    # --- case variants ----------------------------------------------------
    "A",
    "Z",
    "ABC",
    "Evil",
    "PY",
    # --- unicode: NFC vs NFD, width, invisibles, astral -------------------
    # built with chr(), NEVER written as literal characters.  MEASURED
    # 2026-08-20: the literal spelling of this block silently re-composed every
    # NFD sequence to NFC between editor and filesystem, and the sibling file
    # truth_v2.py lost its NFD coverage entirely that way -- the C1b blind spot
    # reproduced inside the fix for C1b.  The canary below refuses to import if
    # it happens again.
    chr(0x00E9),                    # NFC  e-acute
    "e" + chr(0x0301),              # NFD  e + combining acute
    chr(0x00C9),                    # NFC  E-acute (case + unicode)
    "E" + chr(0x0301),              # NFD  E + combining acute
    chr(0x30AC),                    # NFC  katakana GA
    chr(0x30AB) + chr(0x3099),      # NFD  katakana KA + combining dakuten
    chr(0xFF0F),                    # FULLWIDTH SOLIDUS
    chr(0xFF3C),                    # FULLWIDTH REVERSE SOLIDUS
    chr(0xFF21),                    # FULLWIDTH A
    chr(0xFF41),                    # FULLWIDTH a
    chr(0xFF0E),                    # FULLWIDTH FULL STOP
    chr(0x200B),                    # ZERO WIDTH SPACE
    chr(0x200C),                    # ZERO WIDTH NON-JOINER
    chr(0xFEFF),                    # ZERO WIDTH NO-BREAK SPACE / BOM
    chr(0x00A0),                    # NO-BREAK SPACE
    chr(0x2044),                    # FRACTION SLASH
    chr(0x2215),                    # DIVISION SLASH
    chr(0x1F600),                   # astral: emoji
    chr(0x1D400),                   # astral: mathematical bold capital A
    chr(0x0130),                    # LATIN CAPITAL I WITH DOT ABOVE
    chr(0x00DF),                    # sharp s (upper() -> "SS")
    chr(0x212A),                    # KELVIN SIGN (lower() -> "k")
    # --- v2.1 (harden round 1): scripts the v2 list did not name ----------
    # E12 slipped the v2 gates with a single Cyrillic es.  A *list* of classes
    # is the artefact C1b exploited, so the fix is not only "add Cyrillic": it
    # is the unnamed st.characters() component below.  This row buys
    # determinism for the class that actually slipped; that component buys
    # reach into the classes nobody has thought of yet.
    chr(0x0441),                    # CYRILLIC SMALL ES        (confusable 'c')
    chr(0x0430),                    # CYRILLIC SMALL A         (confusable 'a')
    chr(0x0435),                    # CYRILLIC SMALL IE        (confusable 'e')
    chr(0x043E),                    # CYRILLIC SMALL O         (confusable 'o')
    chr(0x0440),                    # CYRILLIC SMALL ER        (confusable 'p')
    chr(0x0445),                    # CYRILLIC SMALL HA        (confusable 'x')
    chr(0x0501),                    # CYRILLIC SMALL KOMI DE   (confusable 'd')
    chr(0x0410),                    # CYRILLIC CAPITAL A
    chr(0x03BF),                    # GREEK SMALL OMICRON      (confusable 'o')
    chr(0x0391),                    # GREEK CAPITAL ALPHA
    chr(0x0561),                    # ARMENIAN SMALL AYB
    chr(0x05D0),                    # HEBREW ALEF   (RTL)
    chr(0x0627),                    # ARABIC ALEF   (RTL)
    chr(0x202E),                    # RIGHT-TO-LEFT OVERRIDE
    chr(0x2066),                    # LEFT-TO-RIGHT ISOLATE
    chr(0x0E01),                    # THAI KO KAI
    chr(0x10A0),                    # GEORGIAN CAPITAL AN
    chr(0xA000),                    # YI SYLLABLE IT
    chr(0x102C),                    # MYANMAR VOWEL SIGN AA
    # --- control characters ----------------------------------------------
    "\x00",
    "a\x00b",
    "\x01",
    "\x1b",
    "\t",
    "\n",
    "\r",
    "\r\n",
    "\x7f",
    # --- whitespace / punctuation -----------------------------------------
    " ",
    "  ",
    "-",
    "_",
    "~",
    "%",
    "#",
    "|",
    ":",
    ";",
    "@",
    "$",
    "^",
    "&",
    "!",
    "'",
    '"',
    "`",
    "=",
    "+",
    ",",
    "<",
    ">",
    "(",
    ")",
    "{",
    "}",
]

# Canary: if the alphabet degrades in transport these equalities become true,
# and the module refuses to import rather than reporting green, empty coverage.
_CANARY = [
    (chr(0x00E9), "e" + chr(0x0301)),
    (chr(0x00C9), "E" + chr(0x0301)),
    (chr(0x30AC), chr(0x30AB) + chr(0x3099)),
    (chr(0x00A0), " "),
    (chr(0x212A), "K"),
    (chr(0x0441), "c"),
]
for _a, _b in _CANARY:
    assert _a != _b, ("unicode alphabet degraded in transport", ascii(_a), ascii(_b))
assert any(len(t) == 2 and ord(t[1]) == 0x0301 for t in BOUNDARY), "NFD token lost"

# Glob metacharacters are excluded from *entries* only: an entry containing one
# of ``*?[`` takes _is_allowed's fnmatch branch, which is not the branch F
# corrupts.  They are perfectly legal inside a *path*.
GLOB_CHARS = "*?["
PATH_ONLY_EXTRA = ["*", "?", "[", "[a-z]", "*.py", "**"]

BOUNDARY_PATH = BOUNDARY + PATH_ONLY_EXTRA
BOUNDARY_ENTRY = [t for t in BOUNDARY if not any(c in t for c in GLOB_CHARS)]

# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #

_seg = st.from_regex(r"[a-z][a-z0-9_]{0,6}", fullmatch=True)
_plain = st.lists(_seg, min_size=1, max_size=3).map("/".join)
_filler = st.text(alphabet="abcxyz019_-.", min_size=0, max_size=6)

# entries: plain, or plain decorated with a boundary token, or degenerate ""
entries = st.one_of(
    _plain,
    st.builds(lambda p, t: p + t, _plain, st.sampled_from(BOUNDARY_ENTRY)),
    st.builds(lambda t, p: t + p, st.sampled_from(BOUNDARY_ENTRY), _plain),
    st.just(""),
)
nonempty_entries = entries.filter(bool)

# every drawn suffix/sub carries at least one boundary token, and one draw in
# four also carries a codepoint drawn from the WHOLE unicode space.  The named
# alphabet gives deterministic coverage of the classes we know about; this
# component is the only part of the generator that can reach the ones we do
# not -- E12 (Cyrillic) slipped precisely because every earlier component was a
# hand-written list.
_anychar = st.characters(min_codepoint=1, max_codepoint=0x10FFFF)
_wild = st.text(alphabet=_anychar, min_size=1, max_size=3)
_spiced = st.one_of(
    st.builds(lambda a, t, b: a + t + b, _filler, st.sampled_from(BOUNDARY_PATH), _filler),
    st.builds(lambda a, t, b: a + t + b, _filler, st.sampled_from(BOUNDARY_PATH), _filler),
    st.builds(lambda a, t, b: a + t + b, _filler, st.sampled_from(BOUNDARY_PATH), _filler),
    st.builds(lambda a, w, b: a + w + b, _filler, _wild, _filler),
)
suffixes = _spiced
subs = _spiced
paths = _spiced

_S = settings(max_examples=1200, derandomize=True, deadline=None)
_S_SMALL = settings(max_examples=300, derandomize=True, deadline=None)


def _is_member(path: str, entry: str) -> bool:
    """True iff `path` is the entry itself or lives under `entry/` (per R)."""
    return path == entry or path.startswith(entry + "/")


# --------------------------------------------------------------------------- #
# P1 -- rejection.  This is the property that fails on the buggy code.
# --------------------------------------------------------------------------- #


@_S
@given(entry=entries, suffix=suffixes)
@example(entry="ccd", suffix="\\evil.py")            # C1b: the v1 escape
@example(entry="ccd", suffix="\\")
@example(entry="ccd", suffix="Evil/x.py")            # C1 / E2: case
@example(entry="ccd", suffix="_evil/../x")           # E3: traversal
@example(entry="ccd", suffix="_evil/")               # E4: trailing slash
@example(entry="ccd", suffix="_" + "q" * 2048)       # E5: length extreme
@example(entry="ccd", suffix="\x00evil")             # E6: NUL
@example(entry="", suffix="evil.py")                 # E7: degenerate entry
@example(entry="ccd", suffix=chr(0xFF0F) + "evil.py")   # E8: fullwidth
@example(entry="ccd", suffix="e" + chr(0x0301) + "vil")  # E1: NFD
@example(entry="ccd", suffix=chr(0x200B) + "evil")     # zero width
@example(entry="ccd", suffix="\U0001f600")           # astral
@example(entry="ccd", suffix=chr(0x212A) + "evil")     # Kelvin sign
@example(entry="ccd", suffix=chr(0x0441) + "_evil/x.py")  # E12: Cyrillic es
@example(entry="ccd", suffix=chr(0x202E) + "evil")     # RTL override
@example(entry="ccd", suffix=chr(0x102C) + "evil")     # Myanmar vowel
def test_sibling_or_extension_is_rejected(entry: str, suffix: str) -> None:
    """``entry`` + a suffix that does not open a directory -> never a member."""
    if any(c in entry for c in GLOB_CHARS):
        assume(False)
    path = entry + suffix
    if not path or _is_member(path, entry):
        assume(False)
    assert _is_allowed(path, (entry,)) is False, (path, entry)


# --------------------------------------------------------------------------- #
# P2 -- acceptance
# --------------------------------------------------------------------------- #


@_S_SMALL
@given(entry=entries, sub=subs)
@example(entry="ccd", sub="guard.py")
@example(entry="ccd", sub="a\\b")
@example(entry="ccd", sub="\x00")
@example(entry="ccd", sub="q" * 3000)
def test_real_member_is_allowed(entry: str, sub: str) -> None:
    if any(c in entry for c in GLOB_CHARS):
        assume(False)
    assert _is_allowed(entry + "/" + sub, (entry,)) is True, (entry, sub)


# --------------------------------------------------------------------------- #
# P3 -- identity
# --------------------------------------------------------------------------- #


@_S_SMALL
@given(entry=nonempty_entries)
@example(entry="ccd")
@example(entry="ccd\\x")
@example(entry=chr(0x00E9))
def test_entry_itself_is_allowed(entry: str) -> None:
    if any(c in entry for c in GLOB_CHARS):
        assume(False)
    assert _is_allowed(entry, (entry,)) is True, entry


# --------------------------------------------------------------------------- #
# P4 -- the empty path is never allowed
# --------------------------------------------------------------------------- #


@_S_SMALL
@given(allowed=st.lists(entries, min_size=0, max_size=4).map(tuple))
@example(allowed=())
@example(allowed=("",))
@example(allowed=("ccd", ""))
def test_empty_path_is_never_allowed(allowed: tuple) -> None:
    assert _is_allowed("", allowed) is False, allowed


# --------------------------------------------------------------------------- #
# P5 -- arity / metamorphic.  Closes blind spots that no character alphabet
#       can reach: a branch keyed on ``len(allowed)`` rather than on ``path``.
# --------------------------------------------------------------------------- #


@_S_SMALL
@given(path=paths, allowed=st.lists(entries, min_size=0, max_size=5).map(tuple))
@example(path="ccd_evil/x.py", allowed=("ccd",))
@example(path="ccd_evil/x.py", allowed=("a", "b", "c", "ccd"))
@example(path="ccd_evil/x.py", allowed=("a", "b", "c", "d", "ccd"))
@example(path="ccd_evil/x.py", allowed=())
def test_tuple_verdict_is_or_of_singletons(path: str, allowed: tuple) -> None:
    whole = _is_allowed(path, allowed)
    parts = any(_is_allowed(path, (a,)) for a in allowed)
    assert whole is parts, (path, allowed, whole, parts)


# --------------------------------------------------------------------------- #
# P6 -- order independence
# --------------------------------------------------------------------------- #


@_S_SMALL
@given(path=paths, allowed=st.lists(entries, min_size=0, max_size=4).map(tuple))
@example(path="ccd_evil/x.py", allowed=("ccd", "docs"))
def test_order_of_allowed_does_not_matter(path: str, allowed: tuple) -> None:
    a = _is_allowed(path, allowed)
    b = _is_allowed(path, tuple(reversed(allowed)))
    assert a is b, (path, allowed, a, b)


# --------------------------------------------------------------------------- #
# P7 -- reference equivalence over INDEPENDENTLY DRAWN (entry, path) pairs.
#
# MEASURED WEAKNESS (v5 diagnosis, confirmed v7): P1/P2/P3 all build the path
# *out of* the entry -- ``entry + suffix``, ``entry + "/" + sub``, ``entry``.
# So T never once produced a path that does not have the entry as a prefix, and
# P5/P6 are metamorphic (they compare the implementation against itself), so a
# consistent lie satisfies them.  Two survivors of 検査4 lived exactly there:
#
#   * ``path == a``  ->  ``path <= a``      (survived on control L1)
#     killed only by a path that is lexicographically BELOW the entry and is
#     not a member, e.g. ``_is_allowed("ccb/x", ("ccd",))``.
#   * ``any(c in a for c in "*?[")`` -> ``not any(...)``   (survived on L3)
#     killed only by an entry that actually CONTAINS a glob metacharacter --
#     P1/P2/P3 all ``assume(False)`` on those, so T excluded the whole
#     fnmatch branch from its own domain.
#
# The fix is therefore in T, not in the gate: state R directly and require the
# implementation to equal it on pairs drawn independently of each other.  R is
# the same reference semantics already written in this module's docstring, so
# no new specification is being invented here.
# --------------------------------------------------------------------------- #

import fnmatch as _fnmatch  # noqa: E402  (kept local to P7; R quotes fnmatch)


def _R(path: str, entry: str) -> bool:
    """The reference semantics R from the module docstring, verbatim."""
    if not path:
        return False
    if path == entry:
        return True
    if path.startswith(entry + "/"):
        return True
    if any(c in entry for c in GLOB_CHARS) and _fnmatch.fnmatch(path, entry):
        return True
    return False


#: entries that take the fnmatch branch.  P1/P2/P3 exclude these by
#: construction, which is why 検査4's AddNot mutant on the glob guard had no
#: test able to observe it.
GLOB_ENTRIES: list[str] = [
    "*",
    "*.py",
    "ccd*",
    "ccd/*",
    "ccd/*.py",
    "?cd",
    "[abc]cd",
    "ccd/**",
    "*/guard.py",
]


def _lex_neighbours(e: str) -> list[str]:
    """Paths adjacent to `e` in the ordering `<`/`<=`/`>`/`>=` compare on.

    These are the inputs a comparison-operator mutation moves across and an
    equality test does not: none of them is a member of `e`, so R says False
    for all of them (except the degenerate empty string, filtered by callers).
    """
    if not e:
        return []
    lo = e[:-1] + chr(max(1, ord(e[-1]) - 1))
    hi = e[:-1] + chr(min(0x10FFFF, ord(e[-1]) + 1))
    return [lo, hi, e[:-1], lo + "/x", hi + "/x"]


_glob_entries_st = st.sampled_from(GLOB_ENTRIES)
_any_entry = st.one_of(entries, _glob_entries_st)


@st.composite
def _entry_and_free_path(draw):
    """(entry, path) where `path` is NOT built out of `entry`."""
    entry = draw(_any_entry)
    kind = draw(st.integers(min_value=0, max_value=5))
    if kind == 0:
        path = draw(_plain)                       # unrelated plain path
    elif kind == 1:
        path = draw(paths)                        # unrelated boundary-spiced
    elif kind == 2:
        path = draw(_glob_entries_st)             # glob text used as a path
    elif kind == 3:
        nb = _lex_neighbours(entry)
        path = draw(st.sampled_from(nb)) if nb else draw(_plain)
    elif kind == 4:
        path = draw(st.sampled_from(BOUNDARY_PATH))
    else:
        path = draw(_plain) + draw(st.sampled_from(BOUNDARY_PATH))
    return entry, path


@_S
@given(pair=_entry_and_free_path())
# the two mutants this property exists for:
@example(pair=("ccd", "ccb/x"))          # Eq -> LtE  (L1's 検査4 survivor)
@example(pair=("ccd", "ccb"))
@example(pair=("ccd", "cce"))            # Eq -> GtE
@example(pair=("ccd", "cce/x"))
@example(pair=("ccd", "cc"))             # proper prefix: startswith swapped
@example(pair=("*.py", "guard.py"))      # AddNot on the glob guard (L3's)
@example(pair=("*.py", "guard.txt"))
@example(pair=("ccd/*", "ccd/x"))
@example(pair=("?cd", "ccd"))
@example(pair=("[abc]cd", "bcd"))
@example(pair=("ccd", "docs/x.py"))
@example(pair=("", "evil.py"))
@example(pair=("", "/evil.py"))
def test_matches_reference_semantics(pair) -> None:
    entry, path = pair
    assert _is_allowed(path, (entry,)) is _R(path, entry), (path, entry)


# --------------------------------------------------------------------------- #
# P8 -- the same equality, but over a *tuple* of entries, so the fnmatch branch
#       is also exercised when it is not the only entry present.
# --------------------------------------------------------------------------- #


@_S_SMALL
@given(path=st.one_of(_plain, paths, _glob_entries_st),
       allowed=st.lists(_any_entry, min_size=0, max_size=4).map(tuple))
@example(path="ccb/x", allowed=("ccd",))
@example(path="guard.py", allowed=("ccd", "*.py"))
@example(path="ccd/x", allowed=("docs", "ccd/*"))
def test_tuple_matches_reference_semantics(path: str, allowed: tuple) -> None:
    assert _is_allowed(path, allowed) is any(_R(path, a) for a in allowed), (
        path, allowed)
