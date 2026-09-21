#!/usr/bin/env python3
"""run_tprime.py -- measure the caller-boundary oracle T' on its own.

Step 3 of the v4 harness.  T' (``t_oracle_Fprime_caller.py``) is the SKILL's
必須D: one property written at the anchor's *real call-site* instead of at the
unit.  The question this runner answers is deliberately narrow and is the only
one that decides whether 必須D is a structural defence or a slogan:

    with 検査7 switched off, does W4 die on T' alone?

plus the two numbers that decide whether it is affordable:

    do the legitimate-fix controls still pass T'?   (false positives)
    what does one T' run cost?                      (vs the unit-level T)

Deliberately standalone rather than wired into ``run_gates3.py``: the corpus
sweep re-measures the *existing* gate set, and folding a second oracle into the
frozen set changes 検査2/3/4 for every entry at once.  Measure first, wire
after.

usage: run_tprime.py [--repo P] [--corpus D] [--only A,B] [--out F]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time

HOME = pathlib.Path.home()
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
TPRIME_SRC = HOME / "vf1/src/t_oracle_Fprime_caller.py"
TPRIME_REL = "tests/test_oracle_Fprime_caller.py"
UNIT_REL = "tests/test_oracle_F_pbt.py"


def sh(cmd, cwd, timeout=900):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                          timeout=timeout)


def reset(repo):
    sh(["git", "checkout", "-qf", "bugv2"], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)


def run_oracle(repo, rel):
    t0 = time.time()
    r = sh([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--timeout=300", rel],
           repo)
    return {"passed": r.returncode == 0, "s": round(time.time() - t0, 2),
            "tail": (r.stdout or "")[-300:] if r.returncode else ""}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(HOME / "vf1/tb5"))
    ap.add_argument("--corpus", default=str(HOME / "vf1/attack-corpus"))
    ap.add_argument("--only", default="")
    ap.add_argument("--out", default=str(HOME / "vf1/tprime_report.json"))
    a = ap.parse_args()

    repo = pathlib.Path(a.repo)
    corpus = pathlib.Path(a.corpus)
    index = json.loads((corpus / "index.json").read_text(encoding="utf-8"))
    entries = index["entries"]
    if a.only:
        want = {x.strip() for x in a.only.split(",")}
        entries = [e for e in entries if e["name"] in want]

    # baseline: T' on the unpatched (buggy) tree -- 検査1 for T' itself
    reset(repo)
    (repo / TPRIME_REL).write_text(TPRIME_SRC.read_text(encoding="utf-8"),
                                   encoding="utf-8")
    pre = run_oracle(repo, TPRIME_REL)
    pre_unit = run_oracle(repo, UNIT_REL)
    reset(repo)

    rows = []
    for e in entries:
        name = e["name"]
        reset(repo)
        patch = str((corpus / e["patch"]).resolve())
        ap_r = sh(["git", "apply", "--whitespace=nowarn", patch], repo)
        if ap_r.returncode != 0:
            rows.append({"name": name, "expect": e.get("expect"),
                         "error": ap_r.stderr[:200]})
            continue
        # T' is part of the *frozen verification context*: it is written before
        # the patch exists and the patch cannot see or edit it.  Writing it in
        # after `git apply` is how that is modelled here.
        (repo / TPRIME_REL).write_text(TPRIME_SRC.read_text(encoding="utf-8"),
                                       encoding="utf-8")
        res = run_oracle(repo, TPRIME_REL)
        rows.append({"name": name, "expect": e.get("expect"),
                     "tprime_passed": res["passed"], "s": res["s"],
                     "tail": res["tail"][-200:]})
        print(f"  {name:28s} T'={'PASS' if res['passed'] else 'FAIL'} ({res['s']}s)",
              flush=True)
    reset(repo)

    atk = [r for r in rows if r.get("expect") == "attack" and "tprime_passed" in r]
    ctl = [r for r in rows if r.get("expect") == "control" and "tprime_passed" in r]
    report = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "check1_tprime_fails_on_bug": not pre["passed"],
        "tprime_cost_s": pre["s"],
        "unit_T_cost_s": pre_unit["s"],
        "n_attacks": len(atk),
        "attacks_killed_by_tprime": sorted(r["name"] for r in atk
                                           if not r["tprime_passed"]),
        "attacks_slipping_tprime": sorted(r["name"] for r in atk
                                          if r["tprime_passed"]),
        "controls_false_positive": sorted(r["name"] for r in ctl
                                          if not r["tprime_passed"]),
        "rows": rows,
    }
    print("\n" + json.dumps({k: v for k, v in report.items() if k != "rows"},
                            indent=1, ensure_ascii=False))
    pathlib.Path(a.out).write_text(json.dumps(report, indent=1, ensure_ascii=False),
                                   encoding="utf-8")
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
