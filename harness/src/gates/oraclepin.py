"""oraclepin.py -- pin Hypothesis input generation to the frozen context.

WHY THIS EXISTS (measured 2026-08-20, v5 step 1)
------------------------------------------------
Hypothesis >= 6.131 harvests *source constants* from every "local" module that
happens to be in ``sys.modules`` when an input is drawn, and injects one of them
in place of ~5% of random draws
(``providers.HypothesisProvider._maybe_draw_constant``).

Two consequences, both fatal for a verification gate:

1. **The draw sequence depends on the pool.**  Taking the constant branch
   consumes *three* values from the per-test Random (one to decide, two to pick
   pool + element); the empty-pool branch consumes *one*.  So adding or removing
   a single constant re-aligns the whole stream, and with ``derandomize=True``
   the example sequence is a pure function of that stream.  A verdict that
   hinges on one rare draw therefore flips.

2. **The pool is attacker-controlled.**  ``ccd/guard_pathmatch.py`` is the file
   the patch edits, and its constants are harvested.  A patch can steer the
   oracle's example sequence by choosing its own literals -- the fixer reaches
   the oracle's input distribution without touching a single test file, which is
   exactly what D3 (freeze) and Phase 3 (oracle invisibility) exist to prevent.

Fix: replace the ambient pool with a constant, so the oracle's inputs depend on
the oracle alone.  ``GLOBAL_CONSTANTS`` (Hypothesis's own built-in interesting
values) is untouched -- it ships with the library and is frozen with it.

Load with ``-p oraclepin``.  PYTHONPATH points at the gate dir, outside the
repo, so this file belongs to the frozen verification context and not to the
tree the fixer may edit.
"""

from __future__ import annotations

import os

from hypothesis.internal.conjecture import providers as _P
from hypothesis.internal.constants_ast import Constants

try:  # sortedcontainers ships with hypothesis
    from sortedcontainers import SortedSet

    from hypothesis.internal.floats import float_to_int

    _EMPTY = Constants(
        integers=SortedSet(),
        floats=SortedSet(key=float_to_int),
        bytes=SortedSet(),
        strings=SortedSet(),
    )
except Exception:  # pragma: no cover
    _EMPTY = Constants()


def _pinned() -> Constants:
    return _EMPTY


if os.environ.get("ORACLE_PIN", "1") != "0":
    _P._get_local_constants = _pinned
    # the provider caches the pool per instance via cached_property, and the
    # permitted-value cache is keyed by choice constraints; clear it so nothing
    # harvested before the pin survives.
    _P.CONSTANTS_CACHE.cache.clear()
    # belt and braces: if some other code path reads the module global directly
    _P._local_constants = _EMPTY
