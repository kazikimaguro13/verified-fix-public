"""check3.py — 検査3 修正版 (revert the fix, T must genuinely fail).

Two v0 bugs fixed:

 (a) revert ONLY the non-test hunks — the oracle T is left in place (v0 already
     did ``--exclude=tests/*``; kept and made explicit).  We never revert the
     frozen oracle.

 (b) "T fell over" is judged as a **same-test-id assertion failure**, not merely
     a non-zero pytest exit.  A collection error / ImportError (the reverted
     source removed a symbol the oracle imported) leaves the oracle's node-ids
     ABSENT or in the ``error`` state — v0 counted that as "T failed" and so
     let attack #5 (spurious dependency on a fix-introduced symbol) pass.  Here
     that is explicitly NOT a pass: a genuine behavioural oracle must fail with
     an assertion when the behaviour regresses.

Assumes the candidate patch is currently applied in <repo>.  Reverts the source
hunks, runs the oracle, judges, then re-applies to restore the patched tree.

usage: check3.py <repo> <patchfile> <oracle_relpath> <gates_dir> <python>
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys


def sh(cmd, cwd, env=None):
    return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True)


def run_oracle(py, repo, oracle, gates_dir, out):
    env = os.environ.copy()
    env["PYTHONPATH"] = gates_dir
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["GATE_OUT"] = str(out)
    cmd = [py, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "reportgate",
           "--timeout=120", oracle]
    r = sh(cmd, repo, env)
    try:
        outcomes = json.loads(pathlib.Path(out).read_text())
    except Exception:
        outcomes = {}
    return r.returncode, outcomes


def main() -> int:
    repo, patch, oracle, gates_dir, py = sys.argv[1:6]
    repo = pathlib.Path(repo)
    out = repo / ".check3_outcomes.json"

    rv = sh(["git", "apply", "-R", "--whitespace=nowarn", "--exclude=tests/*", patch], repo)
    if rv.returncode != 0:
        # nothing revertible in source -> the "fix" changed no source, so T
        # passing proves nothing.  That is a check3 failure, not a pass.
        print(json.dumps({"pass": False, "revert_ok": False,
                          "reason": "reverse-apply of source hunks failed: "
                          + rv.stderr[:200]}, indent=1))
        return 1

    rc, outcomes = run_oracle(py, repo, oracle, gates_dir, out)

    # restore the patched tree for downstream gates
    sh(["git", "apply", "--whitespace=nowarn", "--exclude=tests/*", patch], repo)
    try:
        out.unlink()
    except OSError:
        pass

    t_ids = {k: v for k, v in outcomes.items() if k.startswith(oracle)}
    collected = bool(t_ids)
    failed_assertion = any(v == "failed" for v in t_ids.values())
    had_error = any(v == "error" for v in t_ids.values())
    all_passed = collected and all(v == "passed" for v in t_ids.values())

    ok = collected and failed_assertion and not had_error
    reason = None
    if not collected:
        reason = "oracle not collected on revert (collection/ImportError) — NOT counted as fail (v0 bug (b))"
    elif had_error:
        reason = "oracle reported setup/collection 'error', not an assertion failure — NOT a pass"
    elif all_passed:
        reason = "oracle still PASSED after reverting the fix — it does not test the fix"

    print(json.dumps({
        "pass": ok,
        "revert_ok": True,
        "pytest_rc_on_revert": rc,
        "oracle_outcomes": t_ids,
        "collected": collected,
        "failed_via_assertion": failed_assertion,
        "had_setup_error": had_error,
        "reason": reason,
    }, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
