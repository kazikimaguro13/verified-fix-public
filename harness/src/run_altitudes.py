#!/usr/bin/env python3
"""run_altitudes.py -- the defence range of each altitude, over the whole corpus.

Answers Step 2 (a): *what does each rung of the ladder actually cover?*  It runs
only the oracles, not the gate set, so the whole corpus is affordable and the
per-altitude columns are directly comparable.

  altitude 0  tests/test_oracle_F_pbt.py         the unit (v2)
  altitude 1  tests/test_oracle_Fprime_caller.py  ccd.guard.inspect_diff (v4)
  altitude 2  tests/test_oracle_Falt2_top.py      the nightly seam + the CLI (v6)

The oracle files are part of the frozen context and live in the tree already, so
nothing is written in after ``git apply`` -- unlike v4's run_tprime.py, which had
to inject T' because it was not yet wired.

usage: run_altitudes.py [--repos a,b,c] [--corpus D] [--out F] [--only x,y]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import time

HOME = pathlib.Path.home()
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
GATES = str(HOME / "vf1/gates")
ORACLES = {"alt0": "tests/test_oracle_F_pbt.py",
           "alt1": "tests/test_oracle_Fprime_caller.py",
           "alt2": "tests/test_oracle_Falt2_top.py"}


def sh(cmd, cwd, env=None, timeout=900):
    return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True,
                          text=True, timeout=timeout)


def reset(repo):
    sh(["git", "checkout", "-qf", "bugv2"], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)


def run_oracle(repo, rel):
    env = os.environ.copy()
    env["PYTHONPATH"] = GATES
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_ADDOPTS"] = "-p oraclepin"
    t0 = time.time()
    r = sh([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--timeout=300", rel],
           repo, env)
    return {"passed": r.returncode == 0, "s": round(time.time() - t0, 2)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", default="tb5,tb6,tb7,tb8")
    ap.add_argument("--corpus", default=str(HOME / "vf1/attack-corpus"))
    ap.add_argument("--only", default="")
    ap.add_argument("--out", default=str(HOME / "vf1/altitudes_v6.json"))
    a = ap.parse_args()

    corpus = pathlib.Path(a.corpus)
    idx = json.loads((corpus / "index.json").read_text(encoding="utf-8"))
    entries = idx["entries"]
    if a.only:
        want = {x.strip() for x in a.only.split(",")}
        entries = [e for e in entries if e["name"] in want]
    repos = [HOME / "vf1" / r.strip() for r in a.repos.split(",") if r.strip()]

    # baseline: 検査1 for each altitude on the unpatched (buggy) tree
    reset(repos[0])
    pre = {lab: run_oracle(repos[0], rel) for lab, rel in ORACLES.items()}
    reset(repos[0])

    chunks = [[] for _ in repos]
    for i, e in enumerate(entries):
        chunks[i % len(repos)].append(e)

    def work(repo, chunk):
        loc = {}
        for e in chunk:
            name = e["name"]
            reset(repo)
            r = sh(["git", "apply", "--whitespace=nowarn",
                    str((corpus / e["patch"]).resolve())], repo)
            if r.returncode != 0:
                loc[name] = {"error": r.stderr[:200]}
                continue
            loc[name] = {lab: run_oracle(repo, rel) for lab, rel in ORACLES.items()}
            loc[name]["expect"] = e.get("expect")
            print("  %-28s %s" % (name, {k: ("P" if v["passed"] else "FAIL")
                                         for k, v in loc[name].items()
                                         if isinstance(v, dict)}), flush=True)
            reset(repo)
        return loc

    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(repos)) as pool:
        futs = [pool.submit(work, repos[i], chunks[i]) for i in range(len(repos))
                if chunks[i]]
        for f in concurrent.futures.as_completed(futs):
            out.update(f.result())

    atk = {n: v for n, v in out.items() if v.get("expect") == "attack"}
    ctl = {n: v for n, v in out.items() if v.get("expect") == "control"}

    def kills(lab, d):
        return sorted(n for n, v in d.items()
                      if isinstance(v.get(lab), dict) and not v[lab]["passed"])

    k = {lab: set(kills(lab, atk)) for lab in ORACLES}
    rep = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "check1_fails_on_bug": {lab: not v["passed"] for lab, v in pre.items()},
        "cost_s_on_bug": {lab: v["s"] for lab, v in pre.items()},
        "n_attacks": len(atk), "n_controls": len(ctl),
        "attacks_killed": {lab: sorted(v) for lab, v in k.items()},
        "n_attacks_killed": {lab: len(v) for lab, v in k.items()},
        "alt1_adds_over_alt0": sorted(k["alt1"] - k["alt0"]),
        "alt2_adds_over_alt0_alt1": sorted(k["alt2"] - k["alt0"] - k["alt1"]),
        "height_adds_over_unit": sorted((k["alt1"] | k["alt2"]) - k["alt0"]),
        "unit_only": sorted(k["alt0"] - k["alt1"] - k["alt2"]),
        "no_altitude_kills": sorted(set(atk) - k["alt0"] - k["alt1"] - k["alt2"]),
        "control_false_positives": {lab: kills(lab, ctl) for lab in ORACLES},
        "rows": out,
    }
    pathlib.Path(a.out).write_text(json.dumps(rep, indent=1, ensure_ascii=False))
    print("\n" + json.dumps({kk: vv for kk, vv in rep.items() if kk != "rows"},
                            indent=1, ensure_ascii=False))
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
