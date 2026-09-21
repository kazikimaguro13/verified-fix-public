"""sweep11.py -- run 検査11 (refgate) standalone over the whole attack corpus.

Same construction as sweep10.py: build the cfg.json that run_gates3 hands the
static gates (pre and post images of every changed file) and run one gate on it
without the rest of the pipeline.  Legitimate here for the same reason: 検査11
never runs the oracle -- it only reads the post image and compares it to three
standard-library reference implementations -- so its verdict cannot depend on
what the earlier gates do.

usage: sweep11.py [--out FILE] [--only NAME,..] [--gate-args "..."] [--jobs N]
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
WORK = HOME / "vf1/v10/sweep11"
ANCHOR_FILE = "ccd/guard_pathmatch.py"
ANCHOR_FUNC = "_is_allowed"

DIFF_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.M)


def changed_files(patch_text):
    return sorted({m.group(2) for m in DIFF_RE.finditer(patch_text)})


def build_cfg(name, patch):
    text = patch.read_text(encoding="utf-8")
    changed = changed_files(text)
    d = WORK / name
    if d.exists():
        shutil.rmtree(d)
    (d / "pre").mkdir(parents=True)
    (d / "post").mkdir(parents=True)
    for rel in changed:
        src = subprocess.run(["git", "show", "HEAD:%s" % rel], cwd=str(REPO),
                             capture_output=True, text=True)
        out = src.stdout if src.returncode == 0 else ""
        for half in ("pre", "post"):
            p = d / half / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(out, encoding="utf-8")
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
    gate = os.environ.get("RG_GATE") or str(SRC / "refgate.py")
    r = subprocess.run([PY, gate, str(cfg),
                        "--scratch", str(WORK / name / "sc"),
                        *gate_args], capture_output=True, text=True, timeout=1800)
    try:
        v = json.loads(r.stdout[r.stdout.index("{"):])
    except Exception:
        v = {"pass": None, "error": (r.stdout + r.stderr)[-400:]}
    return name, v, round(time.time() - t0, 2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HOME / "vf1/v10/sweep11.json"))
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
            print("  done %s" % name, file=sys.stderr)

    kinds = {e["name"]: e.get("expect", "?") for e in entries}
    rows = []
    for e in entries:
        n = e["name"]
        v = out.get(n, {})
        t11 = v.get("truth11") or {}
        rows.append((n, kinds[n], v.get("pass"), v.get("n_divergent_total"),
                     v.get("abstain_rate"), t11.get("F_fixed"),
                     (v.get("skipped") or v.get("error") or "")[:50],
                     v.get("secs")))
    w = max(len(r[0]) for r in rows) + 1
    print("%-*s %-8s %-6s %-7s %-12s %-8s %-6s %s"
          % (w, "name", "kind", "pass", "ndiv", "abstain", "t11fix", "secs", "note"))
    for n, k, p, nd, ar, t11, note, secs in rows:
        print("%-*s %-8s %-6s %-7s %-12s %-8s %-6s %s"
              % (w, n, k, str(p), str(nd), str(ar), str(t11), str(secs), note))

    attacks = [r for r in rows if r[1] == "attack"]
    controls = [r for r in rows if r[1] == "control"]
    killed = [r[0] for r in attacks if r[2] is False]
    fps = [r[0] for r in controls if r[2] is False]
    skipped = [r[0] for r in rows if r[6]]
    print()
    print("attacks killed by 検査11 alone : %d/%d  %s" % (len(killed), len(attacks), killed))
    print("FALSE POSITIVES (controls)     : %d/%d  %s" % (len(fps), len(controls), fps))
    print("skipped/errored                : %d  %s" % (len(skipped), skipped))
    ars = [r[4] for r in rows if isinstance(r[4], float)]
    if ars:
        print("abstain rate  min=%.3e  max=%.3e  mean=%.3e"
              % (min(ars), max(ars), sum(ars) / len(ars)))
    secs = [r[7] for r in rows if isinstance(r[7], (int, float))]
    if secs:
        srt = sorted(secs)
        print("gate secs  mean=%.2f  median=%.2f  max=%.2f"
              % (sum(secs) / len(secs), srt[len(srt) // 2], max(secs)))
    print("wall %.1fs" % (time.time() - t0))
    pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.out).write_text(json.dumps(out, indent=1))
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
