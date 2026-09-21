#!/usr/bin/env python3
"""How many times does each frozen oracle call the anchor, per process?

That number is the floor a count-keyed attack has to clear, and the ceiling
検査9's count ladder has to reach.  Measured, not assumed.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pathlib as _pathlib
import sys as _sys

# ★v134 (judgement 61): the machine paths below are resolved in ONE
# place now -- harness/src/vf_paths.py.  They used to be literals here.
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from vf_paths import VF_HOME  # noqa: E402

REPO = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(VF_HOME) / "tb8"
PY = str(pathlib.Path.home() / "projects/Cowork-CC-dispatch/.venv/bin/python")
OUT = pathlib.Path.home() / "vf1/v7tmp/cnt.txt"
GATES = str(pathlib.Path.home() / "vf1/gates")
F = REPO / "ccd/guard_pathmatch.py"

ORACLES = ["tests/test_oracle_F_pbt.py",
           "tests/test_oracle_Fprime_caller.py",
           "tests/test_oracle_Falt2_top.py"]

INSTR = '''import atexit as _atx, os as _os
_N = [0]


def _dump():
    with open(_os.environ.get("CNT_OUT", "/tmp/cnt.txt"), "a") as fh:
        fh.write(str(_N[0]) + "\\n")


_atx.register(_dump)


def _is_allowed(path: str, allowed: tuple[str, ...]) -> bool:
    _N[0] += 1'''


def reset():
    subprocess.run(["git", "checkout", "-qf", "bugv2"], cwd=REPO, check=True)
    subprocess.run(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"],
                   cwd=REPO, check=True)


def main():
    reset()
    subprocess.run(["git", "apply", "--whitespace=nowarn",
                    str(pathlib.Path.home() /
                        "vf1/attack-corpus/patches/00_correct.patch")],
                   cwd=REPO, check=True)
    s = F.read_text()
    old = "def _is_allowed(path: str, allowed: tuple[str, ...]) -> bool:"
    assert old in s
    F.write_text(s.replace(old, INSTR, 1))

    env = dict(os.environ)
    env["CNT_OUT"] = str(OUT)
    env["PYTHONPATH"] = GATES
    env["PYTEST_ADDOPTS"] = "-p oraclepin"

    for target in ORACLES + ["__SUITE__"]:
        if OUT.exists():
            OUT.unlink()
        args = ["-m", "not slow"] if target == "__SUITE__" else [target]
        subprocess.run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        "--timeout=300", *args],
                       cwd=REPO, env=env, capture_output=True, text=True,
                       timeout=1800)
        nums = [int(x) for x in OUT.read_text().split()] if OUT.exists() else []
        print(f"{target:36s} procs={len(nums):3d} total={sum(nums):9d} "
              f"max_per_proc={max(nums) if nums else 0}")
    if OUT.exists():
        OUT.unlink()
    reset()


if __name__ == "__main__":
    main()
