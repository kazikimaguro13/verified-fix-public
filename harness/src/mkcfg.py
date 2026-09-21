#!/usr/bin/env python3
"""Build the same cfg.json run_gates3 hands to 検査5/6/7/8/9, for one patch.

usage: mkcfg.py <repo> <patchfile> <outdir>
Leaves the patch applied in <repo>.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ANCHOR_FILE = "ccd/guard_pathmatch.py"
ANCHOR_FUNC = "_is_allowed"
HOME = pathlib.Path.home()
ORACLES = ["tests/test_oracle_F_pbt.py",
           "tests/test_oracle_Fprime_caller.py",
           "tests/test_oracle_Falt2_top.py"]


def sh(cmd, cwd):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)


def main():
    repo = pathlib.Path(sys.argv[1])
    patch = sys.argv[2]
    out = pathlib.Path(sys.argv[3])
    out.mkdir(parents=True, exist_ok=True)
    sh(["git", "checkout", "-qf", "bugv2"], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)
    r = sh(["git", "apply", "--whitespace=nowarn", patch], repo)
    if r.returncode:
        print(json.dumps({"error": r.stderr[:300]}))
        return 2
    d = sh(["git", "diff", "-U0", "HEAD"], repo)
    changed, cur = [], None
    for line in d.stdout.splitlines():
        m = re.match(r"^\+\+\+ b/(.+)$", line)
        if m:
            cur = m.group(1)
            if not cur.startswith("tests/") and cur not in changed:
                changed.append(cur)
    pre_images, post_images = {}, {}
    for f in changed:
        safe = f.replace("/", "_").replace(".", "_") + ".py"
        (out / ("pre_" + safe)).write_text(sh(["git", "show", f"HEAD:{f}"], repo).stdout)
        (out / ("post_" + safe)).write_text((repo / f).read_text())
        pre_images[f] = str(out / ("pre_" + safe))
        post_images[f] = str(out / ("post_" + safe))
    cfg = {"repo": str(repo), "changed": changed,
           "pre_images": pre_images, "post_images": post_images,
           "anchor_file": ANCHOR_FILE, "anchor_func": ANCHOR_FUNC,
           "finding_file": str(HOME / "vf1/finding_F.txt"),
           "oracle_files": [str(repo / o) for o in ORACLES],
           "tests_dirs": [str(repo / "tests")]}
    p = out / "cfg.json"
    p.write_text(json.dumps(cfg, indent=1))
    print(str(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
