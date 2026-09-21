"""Oracle T for the v8 step-3 real-repository trial (mutatest, cache.py).

Target: github.com/EvanKepner/mutatest @ 3a2d145, module ``mutatest/cache.py``.
**Clone only.  Nothing is applied, committed or pushed to the upstream repo.**

Two findings from the fixed-lens review of that 129-line module became machine
oracles.  Both are derived from *pre-fix, quotable* anchors -- the module's own
type annotation and its own docstring -- so they are SKILL Phase 2 層1 / D1 段2,
not LLM-authored assertions:

  F1  ``get_cache_file_loc(src_file: Union[str, Path])`` guards with
      ``if not src_file: raise ValueError("src_file cannot be an empty string.")``
      That guard is UNREACHABLE for the ``Path`` half of the declared union,
      because ``Path("")`` is ``PosixPath('.')`` and is truthy.  The one real
      call site in this module -- ``remove_existing_cache_files.remove_cfile``,
      which calls ``get_cache_file_loc(srcfile.resolve())`` -- always passes a
      Path, so in production the guard never fires at all.
      ANCHOR: the annotation ``Union[str, Path]`` (cache.py:48) + the guard's own
      message (cache.py:62-63).  PROPERTY: metamorphic -- the two spellings of
      the same argument must produce the same outcome.

  F4  ``remove_existing_cache_files`` docstring (cache.py:99-101):
      "Remove cache files by name or by directory.  In the directory instance,
      all cache files are removed but the directory is not."
      The implementation enumerates ``rglob("*.py")`` and derives each cache
      file from a surviving source file, so a ``__pycache__`` entry whose source
      has been deleted or renamed is NOT removed.
      ANCHOR: that docstring sentence.  PROPERTY: after the call, the directory
      holds no ``.pyc`` files.

Neither property quotes a fix; both are decidable from the pre-fix text alone,
which is the whole test of whether the conversion layer works outside the
synthetic testbed.

usage:  pytest -q step3_oracle_mutatest_cache.py
        (with the clone's root on sys.path, or MUTATEST_ROOT set)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

import pathlib as _pathlib
import sys as _sys

# ★v134 (judgement 61): the machine paths below are resolved in ONE
# place now -- harness/src/vf_paths.py.  They used to be literals here.
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from vf_paths import VF_HOME  # noqa: E402

_ROOT = os.environ.get("MUTATEST_ROOT",
                       os.path.join(VF_HOME, "step3", "mutatest-clone"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mutatest.cache import (  # noqa: E402
    get_cache_file_loc,
    remove_existing_cache_files,
)


def _outcome(fn, arg):
    """(exception type name | 'OK', value) -- the observable outcome class."""
    try:
        return ("OK", str(fn(arg)))
    except Exception as exc:                                    # noqa: BLE001
        return (type(exc).__name__, "")


# --------------------------------------------------------------------------- #
# P1 (F1) -- the two spellings of one argument must behave identically.
# --------------------------------------------------------------------------- #

_SPELLINGS = ["", ".", "a.py", "pkg/a.py", "a.txt", " ", "  ", "./a.py"]


@pytest.mark.parametrize("raw", _SPELLINGS)
def test_str_and_path_spellings_agree(raw: str) -> None:
    """``Union[str, Path]`` means one contract, not two."""
    as_str = _outcome(get_cache_file_loc, raw)
    as_path = _outcome(get_cache_file_loc, Path(raw))
    assert as_str[0] == as_path[0], (raw, as_str, as_path)


def test_empty_designator_is_rejected_in_both_spellings() -> None:
    """The guard's own message names the condition it exists to reject."""
    with pytest.raises(ValueError):
        get_cache_file_loc("")
    with pytest.raises(ValueError):
        get_cache_file_loc(Path(""))


# --------------------------------------------------------------------------- #
# P2 (F4) -- "all cache files are removed" must mean all of them.
# --------------------------------------------------------------------------- #


def test_orphan_cache_file_is_removed(tmp_path: Path) -> None:
    """A ``__pycache__`` entry whose source no longer exists is still a cache
    file, and the docstring says the directory instance removes all of them."""
    src = tmp_path / "gone.py"
    src.write_text("x = 1\n")
    cache = get_cache_file_loc(src)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(b"stale")
    src.unlink()                       # the source is gone; the cache is not

    remove_existing_cache_files(tmp_path)

    leftovers = sorted(p.name for p in tmp_path.rglob("*.pyc"))
    assert leftovers == [], leftovers


def test_live_cache_file_is_removed(tmp_path: Path) -> None:
    """Control: the case the current implementation does handle.  This one must
    PASS before the fix -- if it did not, the oracle would be measuring the
    setup rather than the defect."""
    src = tmp_path / "live.py"
    src.write_text("x = 1\n")
    cache = get_cache_file_loc(src)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(b"stale")

    remove_existing_cache_files(tmp_path)

    assert not cache.exists()
