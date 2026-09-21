#!/usr/bin/env python3
"""litsweep.py -- run 検査6 (litgate) alone over a set of patches.

Standalone measurement of the gate's own reach: apply each patch to a scratch
worktree, snapshot pre/post images of every changed file, and ask litgate.
No pytest, no mutation, no ground truth -- so this is the cheap sweep that
tells us *what check6 by itself defends*, and (with --sources) how the verdict
moves when the definition of "explained" is loosened or tightened.

usage: litsweep.py [--patches DIR|FILE...] [--repo P] [--branch B]
                   [--sources S] [--relax R] [--out FILE] [--repeat N]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

HOME = pathlib.Path.home()
SRC = HOME / "vf1/src"
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
sys.path.insert(0, str(SRC))
import litgate  # noqa: E402


def sh(cmd, cwd):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)


def changed_files(repo: pathlib.Path) -> list[str]:
    r = sh(["git", "diff", "--name-only", "HEAD"], repo)
    return [x for x in r.stdout.splitlines() if x.strip() and not x.startswith("tests/")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--patches", nargs="+", required=True)
    ap.add_argument("--repo", default=str(HOME / "vf1/tb4"))
    ap.add_argument("--branch", default="bugv2")
    ap.add_argument("--finding", default=str(HOME / "vf1/finding_F.txt"))
    ap.add_argument("--oracle", default="tests/test_oracle_F_pbt.py")
    ap.add_argument("--sources", default=litgate.DEFAULT_SOURCES)
    ap.add_argument("--relax", default="")
    ap.add_argument("--out", default="")
    ap.add_argument("--repeat", type=int, default=1)
    a = ap.parse_args()

    repo = pathlib.Path(a.repo)
    img = HOME / "vf1/litimg"
    img.mkdir(parents=True, exist_ok=True)

    files: list[pathlib.Path] = []
    for p in a.patches:
        pp = pathlib.Path(p).resolve()
        files += sorted(pp.glob("*.patch")) if pp.is_dir() else [pp]

    sources = {s.strip() for s in a.sources.split(",") if s.strip()}
    relax = {s.strip() for s in a.relax.split(",") if s.strip()}

    rows = []
    for pf in files:
        name = pf.stem
        sh(["git", "checkout", "-qf", a.branch], repo)
        sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)
        r = sh(["git", "apply", "--whitespace=nowarn", str(pf)], repo)
        if r.returncode != 0:
            rows.append({"name": name, "error": "apply failed: " + r.stderr[:160]})
            continue
        chg = changed_files(repo)
        pre_images, post_images = {}, {}
        for f in chg:
            safe = f.replace("/", "_").replace(".", "_")
            pre_p = img / f"{name}.pre_{safe}.py"
            post_p = img / f"{name}.post_{safe}.py"
            pre_p.write_text(sh(["git", "show", f"HEAD:{f}"], repo).stdout,
                             encoding="utf-8")
            post_p.write_text((repo / f).read_text(encoding="utf-8"), encoding="utf-8")
            pre_images[f] = str(pre_p)
            post_images[f] = str(post_p)
        cfg = {
            "repo": str(repo), "changed": chg,
            "pre_images": pre_images, "post_images": post_images,
            "finding_file": a.finding,
            "oracle_files": [str(repo / a.oracle)],
            "tests_dirs": [str(repo / "tests")],
        }
        t0 = time.time()
        for _ in range(a.repeat):
            res = litgate.run(cfg, sources, relax)
        wall = round((time.time() - t0) / a.repeat, 4)
        rows.append({
            "name": name, "changed": chg, "verdict": res["verdict"],
            "n_new": res["n_new_literals"], "n_unexplained": res["n_unexplained"],
            "unexplained": [f'{u["repr"]}@L{u["line"]}' for u in res["unexplained"]],
            "explained": [f'{u["repr"]}<-{u["by"]}' for u in res["explained"]],
            "context_keys": res["context_keys"],
            "s": wall, "elapsed_s": res["elapsed_s"],
        })
    sh(["git", "checkout", "-qf", a.branch], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)

    hdr = "%-30s %-9s %5s %5s  %s" % ("name", "verdict", "new", "unex", "unexplained literals")
    print(hdr)
    print("-" * 110)
    for r in rows:
        if r.get("error"):
            print("%-30s ERROR %s" % (r["name"], r["error"]))
            continue
        print("%-30s %-9s %5d %5d  %s" % (
            r["name"], r["verdict"], r["n_new"], r["n_unexplained"],
            ", ".join(r["unexplained"])[:60]))
    esc = [r["name"] for r in rows if r.get("verdict") == "ESCALATE"]
    print(f"\nsources={sorted(sources)} relax={sorted(relax)} "
          f"context_keys={rows[0].get('context_keys') if rows else '-'}")
    print(f"ESCALATE {len(esc)}/{len(rows)}: {esc}")
    print("mean litgate wall: %.4fs" % (
        sum(r.get("s", 0) for r in rows) / max(1, len(rows))))
    if a.out:
        pathlib.Path(a.out).write_text(
            json.dumps({"sources": sorted(sources), "relax": sorted(relax),
                        "rows": rows}, indent=1, ensure_ascii=False), encoding="utf-8")
        print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
