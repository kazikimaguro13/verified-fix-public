#!/usr/bin/env python3
"""Run 検査9 standalone over a list of corpus entries and tabulate.

usage: amb_sweep.py <repo> <out.json> [--only A,B] [--args "..."]
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

HOME = pathlib.Path.home()
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
SRC = HOME / "vf1/src"
CORPUS = HOME / "vf1/attack-corpus"
TMP = HOME / "vf1/v7tmp"


def main():
    repo = sys.argv[1]
    outf = sys.argv[2]
    extra = []
    only = None
    if "--only" in sys.argv:
        only = [x for x in sys.argv[sys.argv.index("--only") + 1].split(",") if x]
    if "--args" in sys.argv:
        extra = sys.argv[sys.argv.index("--args") + 1].split()

    index = json.loads((CORPUS / "index.json").read_text(encoding="utf-8"))
    entries = index["entries"]
    if only:
        entries = [e for e in entries if e["name"] in only]

    out = {}
    for e in entries:
        name = e["name"]
        patch = str((CORPUS / e["patch"]).resolve())
        imgdir = TMP / ("img_" + name)
        r = subprocess.run([sys.executable, str(TMP / "mkcfg.py"), repo, patch,
                            str(imgdir)], capture_output=True, text=True)
        if r.returncode:
            out[name] = {"error": r.stdout[-200:] + r.stderr[-200:]}
            print(f"  {name:30s} CFGFAIL", flush=True)
            continue
        cfgp = str(imgdir / "cfg.json")
        t0 = time.time()
        g = subprocess.run([PY, str(SRC / "ambgate.py"), cfgp, "--py", PY, *extra],
                           capture_output=True, text=True, timeout=3600)
        try:
            j = json.loads(g.stdout)
        except Exception:
            j = {"pass": None, "error": (g.stdout + g.stderr)[-300:]}
        j["wall_s"] = round(time.time() - t0, 2)
        j["expect"] = e.get("expect")
        out[name] = j
        print(f"  {name:30s} expect={e.get('expect'):7s} pass={j.get('pass')} "
              f"div={j.get('n_divergent_probes')} axes={j.get('divergent_axes')} "
              f"{j.get('secs')}s", flush=True)
    subprocess.run(["git", "-C", repo, "checkout", "-qf", "bugv2"])
    subprocess.run(["git", "-C", repo, "clean", "-fdq", "--", "ccd", "tests", "registry"])
    pathlib.Path(outf).write_text(json.dumps(out, indent=1))
    n_att = sum(1 for k, v in out.items() if v.get("expect") == "attack")
    n_att_k = sum(1 for k, v in out.items()
                  if v.get("expect") == "attack" and v.get("pass") is False)
    fps = [k for k, v in out.items()
           if v.get("expect") == "control" and v.get("pass") is False]
    print(f"\ncheck9 alone: attacks caught {n_att_k}/{n_att}   control FPs {fps}")
    print("wrote", outf)


if __name__ == "__main__":
    main()
