"""probe11.py -- run 検査11 over an ad-hoc set of patches (before they are in
the corpus index).  Same cfg construction as sweep11.py.

usage: probe11.py <name,name,...> [--gate-args "..."]
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

HOME = pathlib.Path.home()
SRC = HOME / "vf1/src"
REPO = HOME / "vf1/testbed"
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
PATCHES = HOME / "vf1/attack-corpus/patches"
WORK = HOME / "vf1/v10/probe11"
DIFF = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.M)

names = sys.argv[1].split(",")
extra = (sys.argv[sys.argv.index("--gate-args") + 1].split()
         if "--gate-args" in sys.argv else [])
out_all = {}
for name in names:
    patch = PATCHES / (name + ".patch")
    text = patch.read_text(encoding="utf-8")
    changed = sorted({m.group(2) for m in DIFF.finditer(text)})
    d = WORK / name
    if d.exists():
        shutil.rmtree(d)
    for half in ("pre", "post"):
        for rel in changed:
            p = d / half / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(subprocess.run(["git", "show", "HEAD:" + rel],
                                        cwd=str(REPO), capture_output=True,
                                        text=True).stdout, encoding="utf-8")
    r = subprocess.run(["patch", "-p1", "-s", "-i", str(patch)],
                       cwd=str(d / "post"), capture_output=True, text=True)
    if r.returncode != 0:
        print(name, "PATCH FAILED", r.stdout, r.stderr)
        continue
    cfg = d / "cfg.json"
    cfg.write_text(json.dumps({
        "repo": str(REPO), "changed": changed,
        "pre_images": {x: str(d / "pre" / x) for x in changed},
        "post_images": {x: str(d / "post" / x) for x in changed},
        "anchor_file": "ccd/guard_pathmatch.py", "anchor_func": "_is_allowed"}))
    q = subprocess.run([PY, os.environ.get("RG_GATE") or str(SRC / "refgate.py"),
                        str(cfg), "--scratch", str(d / "sc"), *extra],
                       capture_output=True, text=True, timeout=3600)
    try:
        v = json.loads(q.stdout[q.stdout.index("{"):])
    except Exception:
        v = {"pass": None, "error": (q.stdout + q.stderr)[-400:]}
    out_all[name] = v
    print("%-26s pass=%-6s ndiv=%-5s abstain=%-10s secs=%s  %s" % (
        name, v.get("pass"), v.get("n_divergent_total"), v.get("abstain_rate"),
        v.get("secs"), (v.get("skipped") or v.get("error") or "")[:60]))
    if v.get("samples"):
        print("      witness:", json.dumps(v["samples"][0], ensure_ascii=True))
    if v.get("normalize_changed_by_patch"):
        print("      normalize_changed_by_patch:",
              v["normalize_changed_by_patch"])
o = HOME / "vf1/v10/probe11.json"
o.write_text(json.dumps(out_all, indent=1))
print("wrote", o)
