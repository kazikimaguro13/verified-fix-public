#!/usr/bin/env python3
"""staticsweep.py -- run the two static gates (検査6 litgate / 検査7 apigate)
over every corpus patch **without touching a git worktree**.

The v2 postmortem rule "one worker owns one clone for its whole queue" makes
worktrees a scarce resource; the static gates need no repository at all, only
the pre-fix image plus the patch.  ``patch -p1`` in a scratch directory is
enough, so this sweep can run alongside a full-pipeline corpus run.

usage: staticsweep.py --pre PRE.py --patches DIR [--sources S] [--relax R]
                      [--groups G] [--out FILE] [--repeat N]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

HOME = pathlib.Path.home()
sys.path.insert(0, str(HOME / "vf1/src"))
import apigate  # noqa: E402
import litgate  # noqa: E402

TARGET = "ccd/guard_pathmatch.py"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pre", required=True)
    ap.add_argument("--patches", nargs="+", required=True)
    ap.add_argument("--finding", default=str(HOME / "vf1/finding_F.txt"))
    ap.add_argument("--oracle", default=str(HOME / "vf1/src/t_oracle_v2.py"))
    ap.add_argument("--tests", default=str(HOME / "vf1/litctx/tests"))
    ap.add_argument("--sources", default="pre,finding,oracle,tests")
    ap.add_argument("--relax", default="sinks")
    ap.add_argument("--groups", default=apigate.DEFAULT_GROUPS)
    ap.add_argument("--out", default="")
    ap.add_argument("--repeat", type=int, default=1)
    a = ap.parse_args()

    files: list[pathlib.Path] = []
    for p in a.patches:
        pp = pathlib.Path(p).resolve()
        files += sorted(pp.glob("*.patch")) if pp.is_dir() else [pp]

    sources = {s.strip() for s in a.sources.split(",") if s.strip()}
    relax = {s.strip() for s in a.relax.split(",") if s.strip()}
    groups = {s.strip() for s in a.groups.split(",") if s.strip()}
    pre_src = pathlib.Path(a.pre).read_text(encoding="utf-8")

    rows = []
    for pf in files:
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            (d / "ccd").mkdir()
            (d / TARGET).write_text(pre_src, encoding="utf-8")
            r = subprocess.run(["patch", "-p1", "-s", "-i", str(pf)], cwd=td,
                               capture_output=True, text=True)
            if r.returncode != 0:
                rows.append({"name": pf.stem, "error": (r.stdout + r.stderr)[:150]})
                continue
            pre_img = d / "pre.py"
            pre_img.write_text(pre_src, encoding="utf-8")
            cfg = {
                "pre_images": {TARGET: str(pre_img)},
                "post_images": {TARGET: str(d / TARGET)},
                "finding_file": a.finding,
                "oracle_files": [a.oracle],
                "tests_dirs": [a.tests] if pathlib.Path(a.tests).exists() else [],
            }
            t0 = time.time()
            for _ in range(a.repeat):
                l6 = litgate.run(cfg, sources, relax)
            t6 = (time.time() - t0) / a.repeat
            t0 = time.time()
            for _ in range(a.repeat):
                l7 = apigate.run(cfg, groups)
            t7 = (time.time() - t0) / a.repeat
            rows.append({
                "name": pf.stem,
                "c6": l6["verdict"], "c6_unex": l6["n_unexplained"],
                "c6_detail": [f'{u["repr"]}' for u in l6["unexplained"]],
                "c7": l7["verdict"], "c7_n": l7["n_flagged"],
                "c7_detail": [f'{h["name"]}({h["group"]})' for h in l7["flagged"]],
                "t6": round(t6, 5), "t7": round(t7, 5),
            })

    hdr = "%-26s %-9s %-28s %-9s %s" % ("name", "検査6", "unexplained lit", "検査7", "flagged api")
    print(hdr)
    print("-" * 118)
    for r in rows:
        if r.get("error"):
            print("%-26s ERROR %s" % (r["name"], r["error"]))
            continue
        print("%-26s %-9s %-28s %-9s %s" % (
            r["name"], r["c6"], ", ".join(r["c6_detail"])[:27],
            r["c7"], ", ".join(r["c7_detail"])[:44]))
    ok = [r for r in rows if not r.get("error")]
    print("\n検査6 ESCALATE: %d/%d   検査7 ESCALATE: %d/%d"
          % (sum(1 for r in ok if r["c6"] == "ESCALATE"), len(ok),
             sum(1 for r in ok if r["c7"] == "ESCALATE"), len(ok)))
    print("mean 検査6 %.4fs   mean 検査7 %.5fs"
          % (sum(r["t6"] for r in ok) / max(1, len(ok)),
             sum(r["t7"] for r in ok) / max(1, len(ok))))
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(rows, indent=1, ensure_ascii=False),
                                       encoding="utf-8")
        print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
