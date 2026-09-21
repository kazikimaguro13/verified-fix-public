#!/usr/bin/env python3
"""pin_exp_v6.py -- DESIGN 4b.0b: does *respelling a literal* move the oracle?

D11 established that Hypothesis harvests constants from the very file the patch
edits, so a patch can steer the oracle's input distribution without touching a
test.  The open item (§4b.0b, "unmeasured") is the regression for it:

    Z1a  the correct fix + ``_AUDIT_TAG = 555444333``
    Z1b  the correct fix + ``_AUDIT_TAG = int("555444" + "333")``

Semantically identical, and 検査6 sees no new literal in Z1b that it can call
unexplained.  What is measured here, for both pin states:

  * the size of the harvested pool at session end, per oracle  -- the mechanism
  * the verdict of each oracle                                 -- the effect

With the pin on, the pool must be empty and the two spellings must agree.  With
the pin off, a difference in pool size is direct evidence that the patch reached
the oracle's inputs.

usage: pin_exp_v6.py [--repo P] [--out F]
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import time

HOME = pathlib.Path.home()
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
GATES = str(HOME / "vf1/gates")
CORPUS = HOME / "vf1/attack-corpus/patches"

ORACLES = {
    "alt0": "tests/test_oracle_F_pbt.py",
    "alt1": "tests/test_oracle_Fprime_caller.py",
    "alt2": "tests/test_oracle_Falt2_top.py",
}
PATCHES = ["00_correct", "Z1a_literal_plain", "Z1b_literal_respelled"]


def sh(cmd, cwd, env=None, timeout=900):
    return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True,
                          text=True, timeout=timeout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(HOME / "vf1/tb6"))
    ap.add_argument("--out", default=str(HOME / "vf1/pin_exp_v6.json"))
    a = ap.parse_args()
    repo = pathlib.Path(a.repo)
    pool_out = "/tmp/pool_v6.json"

    rows = []
    for pin in ("1", "0"):
        for name in PATCHES:
            sh(["git", "checkout", "-qf", "bugv2"], repo)
            sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)
            r = sh(["git", "apply", "--whitespace=nowarn",
                    str(CORPUS / f"{name}.patch")], repo)
            if r.returncode != 0:
                rows.append({"pin": pin, "patch": name, "error": r.stderr[:200]})
                continue
            for label, rel in ORACLES.items():
                env = os.environ.copy()
                env["PYTHONPATH"] = GATES
                env["PYTHONDONTWRITEBYTECODE"] = "1"
                env["ORACLE_PIN"] = pin
                env["POOL_OUT"] = pool_out
                addopts = "-p poolprobe" + (" -p oraclepin" if pin == "1" else "")
                env["PYTEST_ADDOPTS"] = addopts
                try:
                    os.unlink(pool_out)
                except OSError:
                    pass
                t0 = time.time()
                p = sh([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        "--timeout=300", rel], repo, env)
                try:
                    pool = json.loads(pathlib.Path(pool_out).read_text())
                except Exception:  # noqa: BLE001
                    pool = {}
                rows.append({"pin": pin, "patch": name, "oracle": label,
                             "passed": p.returncode == 0,
                             "pool_strings": pool.get("strings"),
                             "pool_integers": pool.get("integers"),
                             "s": round(time.time() - t0, 2)})
                print(rows[-1], flush=True)
    sh(["git", "checkout", "-qf", "bugv2"], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)

    # ---- the two questions this file exists to answer -------------------
    def verdicts(pin, patch):
        return {r["oracle"]: r["passed"] for r in rows
                if r.get("pin") == pin and r["patch"] == patch and "oracle" in r}

    summary = {
        "pin_on_same_verdict_for_both_spellings":
            verdicts("1", "Z1a_literal_plain") == verdicts("1", "Z1b_literal_respelled"),
        "pin_off_same_verdict_for_both_spellings":
            verdicts("0", "Z1a_literal_plain") == verdicts("0", "Z1b_literal_respelled"),
        "pool_pin_on": sorted({r.get("pool_integers") for r in rows
                               if r.get("pin") == "1" and "oracle" in r}),
        "pool_pin_off_Z1a": [r.get("pool_integers") for r in rows
                             if r.get("pin") == "0"
                             and r["patch"] == "Z1a_literal_plain" and "oracle" in r],
        "pool_pin_off_Z1b": [r.get("pool_integers") for r in rows
                             if r.get("pin") == "0"
                             and r["patch"] == "Z1b_literal_respelled" and "oracle" in r],
        "pool_pin_off_correct": [r.get("pool_integers") for r in rows
                                 if r.get("pin") == "0"
                                 and r["patch"] == "00_correct" and "oracle" in r],
    }
    out = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
           "summary": summary, "rows": rows}
    pathlib.Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False))
    print(json.dumps(summary, indent=1, ensure_ascii=False))
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
