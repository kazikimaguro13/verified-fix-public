"""det_proof.py -- Step 1.3: prove the frozen oracle's verdict is now a
function of the patch alone.

For each patch: 5 *freshly cloned* repos x 2 runs = 10 independent runs of the
frozen oracle T, under the same command line the pipeline uses.  Records the
per-test outcome map, not just the exit code, so a same-verdict/different-test
disagreement cannot hide.

usage: det_proof.py <out.json> <patch> [<patch> ...] [--pin 0|1] [--clones N]
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
ORACLE = "tests/test_oracle_F_pbt.py"
SEED_REPO = HOME / "vf1/testbed"


def sh(cmd, cwd=None, env=None, timeout=1800):
    return subprocess.run(cmd, cwd=None if cwd is None else str(cwd),
                          capture_output=True, text=True, env=env, timeout=timeout)


def make_clone(path: pathlib.Path):
    if path.exists():
        shutil.rmtree(path)
    r = sh(["git", "clone", "-q", str(SEED_REPO), str(path)])
    assert r.returncode == 0, r.stderr
    sh(["git", "checkout", "-qf", "bugv2"], path)
    shutil.rmtree(path / ".hypothesis", ignore_errors=True)
    return path


def one_run(repo: pathlib.Path, patch: str, pin: bool, run_idx: int):
    sh(["git", "checkout", "-qf", "bugv2"], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)
    shutil.rmtree(repo / ".hypothesis", ignore_errors=True)
    r = sh(["git", "apply", "--whitespace=nowarn", str(CORPUS / f"{patch}.patch")], repo)
    if r.returncode != 0:
        return {"repo": repo.name, "run": run_idx, "error": r.stderr[:200]}
    out = repo / f".gateout_{run_idx}.json"
    env = os.environ.copy()
    env["PYTHONPATH"] = GATES
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["GATE_OUT"] = str(out)
    if pin:
        env["PYTEST_ADDOPTS"] = "-p oraclepin"
    else:
        env.pop("PYTEST_ADDOPTS", None)
    rr = sh([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "reportgate",
             "--timeout=300", ORACLE], repo, env)
    try:
        outcomes = json.loads(out.read_text())
    except Exception:
        outcomes = {}
    out.unlink(missing_ok=True)
    return {"repo": repo.name, "run": run_idx, "rc": rr.returncode,
            "verdict": "PASS" if rr.returncode == 0 else "FAIL",
            "outcomes": {k.split("::")[-1]: v for k, v in outcomes.items()}}


def main():
    args = [a for a in sys.argv[1:]]
    pin = True
    clones = 5
    if "--pin" in args:
        i = args.index("--pin")
        pin = args[i + 1] != "0"
        del args[i:i + 2]
    if "--clones" in args:
        i = args.index("--clones")
        clones = int(args[i + 1])
        del args[i:i + 2]
    out_path, patches = args[0], args[1:]

    repos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=clones) as pool:
        repos = list(pool.map(make_clone,
                              [HOME / f"vf1/det{i+1}" for i in range(clones)]))
    print(f"cloned {len(repos)} pristine repos", flush=True)

    report = {"pin": pin, "clones": clones, "patches": {}}
    for patch in patches:
        # a clone must be owned by exactly one job at a time: two jobs on the
        # same worktree race in reset() and silently un-apply each other patch
        # (the failure mode already recorded in run_corpus.py).
        rows = []
        for k in (1, 2):
            jobs = [(r, patch, pin, k) for r in repos]
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                rows += list(pool.map(lambda j: one_run(*j), jobs))
        verdicts = sorted({str(r.get("verdict")) for r in rows})
        sigs = sorted({json.dumps(r.get("outcomes"), sort_keys=True) for r in rows})
        report["patches"][patch] = {
            "n_runs": len(rows),
            "verdicts": verdicts,
            "unanimous": len(verdicts) == 1 and len(sigs) == 1,
            "distinct_outcome_maps": len(sigs),
            "rows": [{k: v for k, v in r.items() if k != "outcomes"} for r in rows],
            "outcome_map": json.loads(sigs[0]) if len(sigs) == 1 else "DIVERGENT",
        }
        st = report["patches"][patch]
        print(f"{patch:26s} runs={st['n_runs']:2d} verdicts={verdicts} "
              f"distinct_maps={st['distinct_outcome_maps']} "
              f"unanimous={st['unanimous']}", flush=True)

    pathlib.Path(out_path).write_text(json.dumps(report, indent=1, ensure_ascii=False))
    print("wrote", out_path)


if __name__ == "__main__":
    main()
