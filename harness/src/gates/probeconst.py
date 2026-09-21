"""pytest plugin: report Hypothesis local-constant pool state at session end.

Loaded with -p probeconst via PYTHONPATH; lives OUTSIDE the repo so it does not
touch the frozen test tree.
"""
import hashlib, json, os, sys


def _pool_state():
    from hypothesis.internal.conjecture import providers as P
    lc = P._local_constants
    s = sorted(map(repr, lc.strings))
    i = sorted(map(repr, lc.integers))
    return {
        "n_strings": len(lc.strings),
        "n_integers": len(lc.integers),
        "n_floats": len(lc.floats),
        "n_bytes": len(lc.bytes),
        "pool_sha": hashlib.sha1(("|".join(s + i)).encode()).hexdigest()[:12],
        "seen_modules": len(P._seen_modules),
        "sys_modules_len": len(sys.modules),
    }


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get("PROBE_OUT")
    st = _pool_state()
    st["exitstatus"] = int(exitstatus)
    if out:
        with open(out, "w") as f:
            json.dump(st, f)
    print("PROBECONST " + json.dumps(st))
