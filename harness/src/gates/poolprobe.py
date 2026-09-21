"""poolprobe.py -- report the size of Hypothesis's harvested source-constant
pool at the end of a pytest session (D11 / DESIGN 4b.0b instrumentation).

Writes ``{"strings": n, "integers": n, ...}`` to ``$POOL_OUT``.  Load with
``-p poolprobe``.  Purely observational: it never changes the pool.
"""

from __future__ import annotations

import json
import os


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001
    out = os.environ.get("POOL_OUT")
    if not out:
        return
    rec = {"exitstatus": int(exitstatus)}
    try:
        from hypothesis.internal.conjecture import providers as _P

        c = _P._get_local_constants()
        for f in ("strings", "integers", "floats", "bytes"):
            try:
                rec[f] = len(getattr(c, f))
            except Exception:  # noqa: BLE001
                rec[f] = None
    except Exception as exc:  # noqa: BLE001
        rec["error"] = str(exc)[:200]
    try:
        with open(out, "w") as fh:
            json.dump(rec, fh)
    except OSError:
        pass
