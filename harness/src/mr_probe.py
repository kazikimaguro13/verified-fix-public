"""mr_probe.py -- run 検査8 (mrgate) over a list of corpus entries, cheaply.

No pipeline, no clone juggling: apply the patch, snapshot the post image, sweep.
usage: mr_probe.py <repo> <out.json> [--max-cp N] [--classes ...] [name ...]
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import time

HOME = pathlib.Path.home()
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
SRC = HOME / "vf1/src"
CORPUS = HOME / "vf1/attack-corpus"
ANCHOR = "ccd/guard_pathmatch.py"


def sh(cmd, cwd=None, timeout=3600):
    return subprocess.run(cmd, cwd=None if cwd is None else str(cwd),
                          capture_output=True, text=True, timeout=timeout)


def main():
    args = sys.argv[1:]
    repo = pathlib.Path(args[0])
    out_path = args[1]
    extra = []
    for flag in ("--max-cp", "--classes"):
        if flag in args:
            i = args.index(flag)
            extra += [flag, args[i + 1]]
            del args[i:i + 2]
    names = args[2:]
    if not names:
        index = json.loads((CORPUS / "index.json").read_text())
        names = [e["name"] for e in index["entries"]]
    index = json.loads((CORPUS / "index.json").read_text())
    expect = {e["name"]: e.get("expect") for e in index["entries"]}

    work = repo / ".mrwork"
    work.mkdir(exist_ok=True)
    rows = []
    for name in names:
        sh(["git", "checkout", "-qf", "bugv2"], repo)
        sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)
        ap = sh(["git", "apply", "--whitespace=nowarn",
                 str(CORPUS / "patches" / f"{name}.patch")], repo)
        if ap.returncode != 0:
            rows.append({"name": name, "error": ap.stderr[:200]})
            continue
        changed = [l for l in sh(["git", "diff", "--name-only", "HEAD"], repo).stdout.split()
                   if not l.startswith("tests/")]
        post = work / "post_guard_pathmatch.py"
        if ANCHOR in changed:
            shutil.copy(repo / ANCHOR, post)
            post_images = {ANCHOR: str(post)}
        else:
            post_images = {}
        cfg = work / "cfg.json"
        cfg.write_text(json.dumps({"repo": str(repo), "changed": changed,
                                   "pre_images": {}, "post_images": post_images,
                                   "anchor_file": ANCHOR, "anchor_func": "_is_allowed"}))
        t0 = time.time()
        r = sh([PY, str(SRC / "mrgate.py"), str(cfg)] + extra, repo, timeout=3600)
        took = round(time.time() - t0, 2)
        try:
            j = json.loads(r.stdout)
        except Exception:
            j = {"pass": None, "error": (r.stdout + r.stderr)[-300:]}
        rows.append({"name": name, "expect": expect.get(name), "wall_s": took,
                     "pass": j.get("pass"), "n_divergent": j.get("n_divergent_total"),
                     "skipped": j.get("skipped"),
                     "classes": {k: {"n": v.get("n_divergent"),
                                     "base": v.get("baseline_verdict"),
                                     "sample": v.get("sample", [])[:3]}
                                 for k, v in (j.get("classes") or {}).items()},
                     "error": j.get("error")})
        rr = rows[-1]
        print("%-26s %-8s pass=%-5s div=%-5s %5.1fs %s" % (
            name, rr["expect"], str(rr["pass"]), str(rr["n_divergent"]), took,
            rr.get("error") or rr.get("skipped") or ""), flush=True)
    sh(["git", "checkout", "-qf", "bugv2"], repo)
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"], repo)
    pathlib.Path(out_path).write_text(json.dumps(rows, indent=1, ensure_ascii=False))
    print("wrote", out_path)


if __name__ == "__main__":
    main()
