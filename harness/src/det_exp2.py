"""det_exp2.py -- Step 1 causal experiment.

Question: what actually decides 検査2's verdict on a fixed patch?

Candidate causes, one factor at a time (.hypothesis/ already falsified in exp1):
  * pool   -- the Hypothesis local source-constant pool, i.e. which *local*
              modules happen to be in sys.modules when a draw happens
  * patch  -- literals the patch itself adds to the edited module (the pool is
              harvested from ccd/, which the patch edits => attacker channel)
  * pin    -- with gates/oraclepin.py loaded the pool is a constant

usage: det_exp2.py <repo> <patchname> [--pin]
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pathlib as _pathlib
import sys as _sys

# ★v134 (judgement 61): the machine paths below are resolved in ONE
# place now -- harness/src/vf_paths.py.  They used to be literals here.
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from vf_paths import VF_HOME  # noqa: E402

HOME = pathlib.Path.home()
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
GATES = str(HOME / "vf1/gates")
PROBE = str(HOME / "vf1/probe")
CORPUS = HOME / "vf1/attack-corpus/patches"
ORACLE = "tests/test_oracle_F_pbt.py"
DECOY = '\n_DECOY_CONSTANT = "zqxjkvwmp"\n_DECOY_INT = 40507\n'


def sh(cmd, cwd, env=None, timeout=1800):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                          env=env, timeout=timeout)


def prep(repo: pathlib.Path, patch: str, decoy: bool, preimport: bool):
    sh(["git", "checkout", "-qf", "bugv2"], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)
    shutil.rmtree(repo / ".hypothesis", ignore_errors=True)
    r = sh(["git", "apply", "--whitespace=nowarn", str(CORPUS / f"{patch}.patch")], repo)
    assert r.returncode == 0, r.stderr
    if decoy:
        p = repo / "ccd/guard_pathmatch.py"
        p.write_text(p.read_text() + DECOY)
    pre = repo / "ccd/_preimport_probe.py"
    if preimport:
        # a *local* module with many harvestable constants; importing it via the
        # plugin changes the pool without changing the code under test
        body = ["# generated probe module\n"]
        body += [f'_C{i} = "cst{i:04d}"\n' for i in range(60)]
        pre.write_text("".join(body))
    elif pre.exists():
        pre.unlink()


def run(repo: pathlib.Path, label: str, patch: str, *, decoy=False, preimport=False,
        pin=False, full=False):
    prep(repo, patch, decoy, preimport)
    env = os.environ.copy()
    env["PYTHONPATH"] = GATES + ":" + PROBE
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PROBE_OUT"] = f"/tmp/probe_{label}.json"
    env["PYTHONHASHSEED"] = "0"
    cmd = [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "reportgate",
           "-p", "probeconst", "--timeout=300"]
    if pin:
        cmd += ["-p", "oraclepin"]
    if preimport:
        cmd += ["-p", "preimport"]
    if full:
        cmd += ["-m", "not slow", "tests"]
    else:
        cmd += [ORACLE]
    r = sh(cmd, repo, env)
    try:
        probe = json.loads(pathlib.Path(env["PROBE_OUT"]).read_text())
    except Exception:
        probe = {}
    # oracle verdict = did any test in the oracle file fail?
    if full:
        bad = "test_oracle_F_pbt" in r.stdout and "FAILED tests/test_oracle_F_pbt" in r.stdout
        verdict = "FAIL" if bad else "PASS"
    else:
        verdict = "PASS" if r.returncode == 0 else "FAIL"
    out = {"label": label, "patch": patch, "decoy": decoy, "preimport": preimport,
           "pin": pin, "full": full, "rc": r.returncode, "oracle": verdict,
           "pool_sha": probe.get("pool_sha"), "n_strings": probe.get("n_strings"),
           "n_int": probe.get("n_integers"), "sysmod": probe.get("sys_modules_len"),
           "tail": r.stdout.strip().splitlines()[-1][:80] if r.stdout.strip() else ""}
    print(json.dumps(out, ensure_ascii=False), flush=True)
    return out


def main():
    repo = pathlib.Path(sys.argv[1])
    patch = sys.argv[2]
    rows = []
    for pin in (False, True):
        tag = "pin" if pin else "raw"
        rows.append(run(repo, f"{tag}_base", patch, pin=pin))
        rows.append(run(repo, f"{tag}_preimport", patch, preimport=True, pin=pin))
        rows.append(run(repo, f"{tag}_decoy", patch, decoy=True, pin=pin))
        rows.append(run(repo, f"{tag}_full", patch, pin=pin, full=True))
    (pathlib.Path(VF_HOME) / f"det_exp2_{patch}.json").write_text(
        json.dumps(rows, indent=1, ensure_ascii=False))
    print("\n%-16s %-14s %-6s %-5s %s" % ("label", "pool_sha", "nstr", "verd", "tail"))
    for r in rows:
        print("%-16s %-14s %-6s %-5s %s" % (r["label"], r["pool_sha"], r["n_strings"],
                                            r["oracle"], r["tail"]))


if __name__ == "__main__":
    main()
