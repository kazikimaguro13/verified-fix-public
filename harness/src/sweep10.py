"""sweep10.py -- run 検査10 (structgate) standalone over the whole attack corpus.

Builds the same cfg.json run_gates3 hands the static/structural gates -- pre and
post images of every changed file, taken from `git show HEAD:` and from the
patch applied to a scratch copy -- WITHOUT running the rest of the pipeline.

That is legitimate here and NOT a shortcut around measurement, because 検査10
reads exactly two things: the post images and the repository's package layout.
It never runs the oracle, so its verdict cannot depend on anything the earlier
gates do.  (The full-pipeline run is still needed for cost and for interaction
effects; this is what makes the 55-entry verdict cheap enough to iterate on.)

usage: sweep10.py [--out FILE] [--only NAME,..] [--gate-args "..."]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

HOME = pathlib.Path.home()
SRC = HOME / "vf1/src"
REPO = HOME / "vf1/testbed"
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
CORPUS = HOME / "vf1/attack-corpus"
WORK = HOME / "vf1/v9tmp/sweep10"
ANCHOR_FILE = "ccd/guard_pathmatch.py"
ANCHOR_FUNC = "_is_allowed"

DIFF_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.M)


def changed_files(patch_text: str) -> list[str]:
    return sorted({m.group(2) for m in DIFF_RE.finditer(patch_text)})


def build_cfg(name: str, patch: pathlib.Path) -> pathlib.Path | None:
    text = patch.read_text(encoding="utf-8")
    changed = changed_files(text)
    d = WORK / name
    if d.exists():
        shutil.rmtree(d)
    (d / "pre").mkdir(parents=True)
    (d / "post").mkdir(parents=True)
    for rel in changed:
        src = subprocess.run(["git", "show", f"HEAD:{rel}"], cwd=str(REPO),
                             capture_output=True, text=True)
        if src.returncode != 0:                      # file added by the patch
            src.stdout = ""
        for half in ("pre", "post"):
            p = d / half / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(src.stdout, encoding="utf-8")
    r = subprocess.run(["patch", "-p1", "-s", "-i", str(patch)],
                       cwd=str(d / "post"), capture_output=True, text=True)
    if r.returncode != 0:
        (d / "patch_failed.txt").write_text(r.stdout + r.stderr)
        return None
    cfg = d / "cfg.json"
    cfg.write_text(json.dumps({
        "repo": str(REPO), "changed": changed,
        "pre_images": {rel: str(d / "pre" / rel) for rel in changed},
        "post_images": {rel: str(d / "post" / rel) for rel in changed},
        "anchor_file": ANCHOR_FILE, "anchor_func": ANCHOR_FUNC,
    }, indent=1))
    return cfg


def run_one(entry, gate_args):
    name = entry["name"]
    patch = CORPUS / entry["patch"]
    t0 = time.time()
    cfg = build_cfg(name, patch)
    if cfg is None:
        return name, {"pass": None, "error": "patch did not apply"}, 0.0
    gate = os.environ.get("SG_GATE") or str(SRC / "structgate.py")
    r = subprocess.run([PY, gate, str(cfg), "--py", PY,
                        *gate_args], capture_output=True, text=True, timeout=900)
    try:
        v = json.loads(r.stdout[r.stdout.index("{"):])
    except Exception:
        v = {"pass": None, "error": (r.stdout + r.stderr)[-400:]}
    return name, v, round(time.time() - t0, 2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HOME / "vf1/sweep10.json"))
    ap.add_argument("--only", default="")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--gate-args", default="")
    a = ap.parse_args()

    index = json.loads((CORPUS / "index.json").read_text(encoding="utf-8"))
    entries = index["entries"]
    if a.only:
        want = {x.strip() for x in a.only.split(",")}
        entries = [e for e in entries if e["name"] in want]
    WORK.mkdir(parents=True, exist_ok=True)
    ga = a.gate_args.split()

    out, t0 = {}, time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = {ex.submit(run_one, e, ga): e for e in entries}
        for f in concurrent.futures.as_completed(futs):
            name, v, secs = f.result()
            v["build_and_run_s"] = secs
            out[name] = v
            print(f"  done {name}", file=sys.stderr)

    kinds = {e["name"]: e.get("expect", "?") for e in entries}
    rows = []
    for e in entries:
        n = e["name"]
        v = out.get(n, {})
        rows.append((n, kinds[n], v.get("pass"), v.get("n_divergent_variants"),
                     ",".join(sorted(v.get("divergent", {}))) or
                     (v.get("skipped") or v.get("error", ""))[:60],
                     v.get("secs")))
    w = max(len(r[0]) for r in rows) + 1
    print(f"{'name':<{w}} {'kind':<8} {'pass':<6} {'ndiv':<5} {'secs':<6} detail")
    for n, k, p, nd, det, secs in rows:
        print(f"{n:<{w}} {k:<8} {str(p):<6} {str(nd):<5} {str(secs):<6} {det}")

    attacks_killed = [n for n, k, p, *_ in rows if k == "attack" and p is False]
    controls_killed = [n for n, k, p, *_ in rows if k == "control" and p is False]
    skipped = [n for n, k, p, *_ in rows
               if p is True and out[n].get("skipped")]
    print()
    print(f"attacks killed by 検査10 alone : {len(attacks_killed)}/"
          f"{sum(1 for r in rows if r[1] == 'attack')}  {attacks_killed}")
    print(f"FALSE POSITIVES (controls)     : {len(controls_killed)}/"
          f"{sum(1 for r in rows if r[1] == 'control')}  {controls_killed}")
    print(f"skipped (anchor not in patch)  : {len(skipped)}  {skipped}")
    print(f"wall {round(time.time() - t0, 1)}s")
    pathlib.Path(a.out).write_text(json.dumps(out, indent=1))
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
