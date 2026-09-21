#!/usr/bin/env python3
"""Pre-fix baseline for R4/R5: executed count PLUS the per-test outcome map.

Generated once, up front, because the corpus runner runs N clones in parallel
and letting the first runner to arrive write the shared baseline is a race.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

HOME = pathlib.Path.home()
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
GATES = str(HOME / "vf1/gates")


def _opt(flag, default):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default


def main():
    """usage: mk_baseline.py <repo> <out.json>
                 [--branch B] [--py P] [--clean-paths a,b] [--pytest-args '...']

    The four options default to the synthetic testbed.  They exist so the
    harness can be aimed at another repository without editing it -- v13.
    """
    repo = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2])
    branch = _opt("--branch", "bugv2")
    py = _opt("--py", PY)
    clean = [x for x in _opt("--clean-paths", "ccd,tests,registry").split(",")
             if x.strip()]
    extra = [x for x in _opt("--pytest-args", "").split() if x]
    tmp = HOME / "vf1/v7tmp/baseline_outcomes.json"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "checkout", "-qf", branch], cwd=repo, check=True)
    subprocess.run(["git", "clean", "-fdq", "--", *clean],
                   cwd=repo, check=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = GATES
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["PYTEST_ADDOPTS"] = "-p oraclepin"
    env["GATE_OUT"] = str(tmp)
    r = subprocess.run([py, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        "-p", "reportgate", "--timeout=300", "-m", "not slow",
                        *extra],
                       cwd=repo, env=env, capture_output=True, text=True,
                       timeout=3600)
    o = json.loads(tmp.read_text())
    ex = sum(1 for v in o.values() if v in ("passed", "failed", "error"))
    counts = {}
    for v in o.values():
        counts[v] = counts.get(v, 0) + 1
    out.write_text(json.dumps({"executed": ex, "outcomes": o}))
    print(json.dumps({"rc": r.returncode, "executed": ex, "by_outcome": counts,
                      "n_passed": counts.get("passed", 0),
                      "wrote": str(out)}, indent=1))


if __name__ == "__main__":
    main()
