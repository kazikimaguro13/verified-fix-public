"""det_order.py -- Step 1.3b: does the oracle's verdict survive *test order*?

The pool that caused the v4 flips is a process-global that accumulates as
modules enter sys.modules, and the only thing that triggers a re-scan is
`len(sys.modules)` changing.  So the order in which pytest imports and runs
things is a candidate input to the oracle's verdict -- and R5 randomises exactly
that.  If the two interact, R5 is not measuring flakiness, it is manufacturing
it.

Runs the FULL suite (the R5 configuration) at several orders x several clones,
and reports the oracle file's outcome each time.

usage: det_order.py <out.json> <patch> [--pin 0|1] [--clones N] [--seeds a,b,c]
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import shutil
import subprocess
import sys

HOME = pathlib.Path.home()
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
GATES = str(HOME / "vf1/gates")
CORPUS = HOME / "vf1/attack-corpus/patches"
ORACLE_PREFIX = "tests/test_oracle_F_pbt.py"


def sh(cmd, cwd=None, env=None, timeout=3600):
    return subprocess.run(cmd, cwd=None if cwd is None else str(cwd),
                          capture_output=True, text=True, env=env, timeout=timeout)


def one(repo: pathlib.Path, patch: str, pin: bool, seed):
    sh(["git", "checkout", "-qf", "bugv2"], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)
    shutil.rmtree(repo / ".hypothesis", ignore_errors=True)
    r = sh(["git", "apply", "--whitespace=nowarn", str(CORPUS / f"{patch}.patch")], repo)
    if r.returncode != 0:
        return {"repo": repo.name, "seed": seed, "error": r.stderr[:200]}
    out = repo / f".order_{seed}.json"
    env = os.environ.copy()
    env.update({"PYTHONPATH": GATES, "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0", "GATE_OUT": str(out)})
    if pin:
        env["PYTEST_ADDOPTS"] = "-p oraclepin"
    else:
        env.pop("PYTEST_ADDOPTS", None)
    cmd = [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "reportgate",
           "--timeout=300", "-m", "not slow", "tests"]
    if seed is not None:
        cmd += ["--gate-seed", str(seed)]
    sh(cmd, repo, env)
    try:
        outcomes = json.loads(out.read_text())
    except Exception:
        outcomes = {}
    out.unlink(missing_ok=True)
    oracle = {k.split("::")[-1]: v for k, v in outcomes.items()
              if k.startswith(ORACLE_PREFIX)}
    return {"repo": repo.name, "seed": seed,
            "verdict": "PASS" if oracle and all(v == "passed" for v in oracle.values())
            else "FAIL",
            "n_executed": sum(1 for v in outcomes.values()
                              if v in ("passed", "failed", "error")),
            "oracle": oracle}


def main():
    args = sys.argv[1:]
    pin, clones, seeds = True, 3, [None, 11, 22, 33]
    for flag, cast in (("--pin", lambda v: v != "0"), ("--clones", int)):
        if flag in args:
            i = args.index(flag)
            val = cast(args[i + 1])
            if flag == "--pin":
                pin = val
            else:
                clones = val
            del args[i:i + 2]
    if "--seeds" in args:
        i = args.index("--seeds")
        seeds = [None if s == "none" else int(s) for s in args[i + 1].split(",")]
        del args[i:i + 2]
    out_path, patch = args[0], args[1]

    repos = [HOME / f"vf1/det{i+1}" for i in range(clones)]
    rows = []
    for seed in seeds:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(repos)) as pool:
            rows += list(pool.map(lambda r: one(r, patch, pin, seed), repos))
        print(f"  seed={seed} done", flush=True)
    verdicts = sorted({str(r.get("verdict")) for r in rows})
    sigs = sorted({json.dumps(r.get("oracle"), sort_keys=True) for r in rows})
    rep = {"patch": patch, "pin": pin, "n_runs": len(rows), "verdicts": verdicts,
           "distinct_oracle_maps": len(sigs), "unanimous": len(sigs) == 1,
           "rows": [{k: v for k, v in r.items() if k != "oracle"} for r in rows]}
    pathlib.Path(out_path).write_text(json.dumps(rep, indent=1, ensure_ascii=False))
    print(json.dumps({k: v for k, v in rep.items() if k != "rows"}, indent=1))


if __name__ == "__main__":
    main()
