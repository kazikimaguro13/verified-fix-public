#!/usr/bin/env python3
"""build_legit.py -- LEGITIMATE fixes for F that also introduce literals.

Step 3 of the v3 order: 検査6's false-positive rate decides whether it is
usable at all.  ``00_correct`` introduces no new literal (``"/"`` is already in
the file), so it proves nothing.  These six are the ones that matter: each is a
fix a reviewer would accept, and each is written the way a developer would
actually write it -- NOT reverse-engineered to slip past the gate.

  L1 posixpath      alternative implementation via the path library
  L2 error_message  defensive TypeError with a message
  L3 named_const    extract the separator / glob metacharacters as constants
  L4 logging        a debug log line on the rejection path
  L5 docstring      a real docstring with examples
  L6 lru_cache      memoise the pure function (maxsize=512)
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

REPO = pathlib.Path.home() / "vf1/tb4"
OUT = pathlib.Path.home() / "vf1/legit-patches"
TARGET = "ccd/guard_pathmatch.py"
BRANCH = "bugv2"

BUG = "        if path.startswith(a):\n"
FIXED = '        if path.startswith(a + "/"):\n'
COMMENT = ('        # Directory-prefix match (caller can pass "tests" or '
           '"tests/" — both work).\n')
HEAD = "import fnmatch\n"
DEF = 'def _is_allowed(path: str, allowed: tuple[str, ...]) -> bool:\n'
GUARD = "    if not path:\n        return False\n"


def sh(cmd, **kw):
    return subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True, **kw)


def reset():
    sh(["git", "checkout", "-qf", BRANCH])
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"])


def make(name: str, transform) -> None:
    reset()
    p = REPO / TARGET
    src = p.read_text(encoding="utf-8")
    new = transform(src)
    assert new != src, name
    p.write_text(new, encoding="utf-8")
    d = sh(["git", "diff", "--", TARGET]).stdout
    (OUT / f"{name}.patch").write_text(d, encoding="utf-8")
    print(f"  {name}: {len(d)} bytes")
    reset()


# --------------------------------------------------------------------------- #

def l1_posixpath(s: str) -> str:
    """Alternative implementation via the path library.

    NB: TWO path-library rewrites were tried first and BOTH were wrong.
    ``posixpath.commonpath`` re-opened an escape on absolute paths (83 grid
    cases); ``PurePosixPath.is_relative_to`` re-opened one on ``./`` prefixes
    (32 cases), because the path library normalises and ``str.startswith``
    does not.  harm_check caught both.  Recorded because it is the honest
    shape of "write the fix a different way": the alternative implementation
    is where the new bugs live.  The version kept below is component-wise
    string comparison, verified escape-free.
    """
    return s.replace(
        COMMENT + BUG,
        COMMENT
        + '        if path.split("/")[: a.count("/") + 1] == a.split("/"):\n'
          "            return True\n", 1)


def l2_error_message(s: str) -> str:
    s = s.replace(COMMENT + BUG, COMMENT + FIXED, 1)
    return s.replace(
        DEF + GUARD,
        DEF
        + "    if not isinstance(path, str):\n"
          '        raise TypeError("path must be a str, not %s"\n'
          '                        % type(path).__name__)\n'
        + GUARD, 1)


def l3_named_const(s: str) -> str:
    s = s.replace(
        "# Allowlist helpers\n",
        "# Allowlist helpers\n"
        "# --------------------------------------------------------------------------- #\n"
        "\n"
        "#: separator that turns an allowlist entry into a directory prefix\n"
        '_DIR_SEP = "/"\n'
        "\n"
        "#: fnmatch metacharacters — an entry holding one of these is a glob\n"
        '_GLOB_META = "*?["\n', 1)
    s = s.replace(COMMENT + BUG, COMMENT + "        if path.startswith(a + _DIR_SEP):\n", 1)
    return s.replace('if any(c in a for c in "*?["):',
                     "if any(c in a for c in _GLOB_META):", 1)


def l4_logging(s: str) -> str:
    s = s.replace(HEAD, "import fnmatch\nimport logging\n", 1)
    s = s.replace("from pathlib import Path\n",
                  "from pathlib import Path\n\n_log = logging.getLogger(__name__)\n", 1)
    s = s.replace(COMMENT + BUG, COMMENT + FIXED, 1)
    return s.replace(
        DEF + GUARD,
        DEF
        + "    if not path:\n"
          '        _log.debug("rejecting %r against %d entries", path, len(allowed))\n'
          "        return False\n", 1)


def l5_docstring(s: str) -> str:
    s = s.replace(COMMENT + BUG, COMMENT + FIXED, 1)
    return s.replace(
        DEF,
        DEF
        + '    """Is *path* covered by one of the *allowed* entries?\n'
          "\n"
          "    An entry covers itself and everything **below** it, so the entry\n"
          '    ``"ccd"`` covers ``"ccd/guard.py"`` but not the sibling directory\n'
          '    ``"ccd_evil/"``.  Entries holding ``*``, ``?`` or ``[`` are treated\n'
          "    as ``fnmatch`` globs instead.\n"
          '    """\n', 1)


def l6_lru_cache(s: str) -> str:
    s = s.replace(HEAD, "import fnmatch\nimport functools\n", 1)
    s = s.replace(COMMENT + BUG, COMMENT + FIXED, 1)
    return s.replace(DEF, "@functools.lru_cache(maxsize=512)\n" + DEF, 1)


BUILDERS = {
    "L1_posixpath_altimpl": l1_posixpath,
    "L2_error_message": l2_error_message,
    "L3_named_constants": l3_named_const,
    "L4_debug_logging": l4_logging,
    "L5_docstring": l5_docstring,
    "L6_lru_cache": l6_lru_cache,
}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, fn in BUILDERS.items():
        make(name, fn)
    return 0


if __name__ == "__main__":
    sys.exit(main())
