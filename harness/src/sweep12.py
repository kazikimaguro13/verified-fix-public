"""sweep12.py -- run 検査12 alone over the whole corpus, without the pipeline.

Same shape as sweep10.py / sweep11.py: 検査12 never executes the test suite, so
its verdict does not depend on anything the full pipeline provides.  That makes
a standalone sweep over every patch both valid and cheap (seconds, not hours),
and it can run while a corpus job is using the clones because it works from
`git archive` into a temp dir and never touches a working tree.

usage: sweep12.py [--patches DIR] [--repo DIR] [--out FILE] [--only a,b]
                  [--no-spy] [--no-consts] [--max-arity K]
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import spygate  # noqa: E402

BRANCH = "bugv2"
REL = "ccd/guard_pathmatch.py"
HOME = pathlib.Path.home()


def opt(flag, default):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default


def materialise(repo: pathlib.Path, dest: pathlib.Path) -> None:
    """Explode the frozen branch into dest without touching any working tree."""
    dest.mkdir(parents=True, exist_ok=True)
    ar = subprocess.run(
        ["git", "--git-dir", str(repo / ".git"), "archive", BRANCH],
        capture_output=True)
    assert ar.returncode == 0, ar.stderr[:400]
    tar = subprocess.run(["tar", "-x", "-C", str(dest)], input=ar.stdout,
                         capture_output=True)
    assert tar.returncode == 0, tar.stderr[:400]


def load(path: pathlib.Path, name: str):
    ldr = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, ldr)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    ldr.exec_module(mod)
    return mod


def main() -> int:
    patches = pathlib.Path(opt("--patches",
                               str(pathlib.Path(__file__).resolve().parents[1]
                                   / "attack-corpus" / "patches")))
    repo = pathlib.Path(opt("--repo", str(HOME / "vf1/testbed")))
    out = pathlib.Path(opt("--out", str(HOME / "vf1/v12/sweep12.json")))
    only = [x for x in opt("--only", "").split(",") if x]
    arity = int(opt("--max-arity", "3"))
    no_spy = "--no-spy" in sys.argv
    no_consts = "--no-consts" in sys.argv

    files = sorted(p for p in patches.glob("*.patch")
                   if not only or p.stem in only)
    results, t0 = {}, time.time()
    with tempfile.TemporaryDirectory(prefix="sweep12_") as td:
        base = pathlib.Path(td) / "base"
        materialise(repo, base)
        for i, pf in enumerate(files):
            work = pathlib.Path(td) / ("w%03d" % i)
            subprocess.run(["cp", "-a", str(base), str(work)], check=True)
            ap = subprocess.run(
                ["git", "apply", "--whitespace=nowarn", str(pf)],
                cwd=str(work), capture_output=True, text=True)
            if ap.returncode:
                results[pf.stem] = {"verdict": "APPLY-FAILED",
                                    "error": ap.stderr[:200]}
                continue
            anchor = work / REL
            try:
                fn = getattr(load(anchor, "sw12_%03d" % i), "_is_allowed")
            except Exception as exc:
                results[pf.stem] = {"verdict": "LOAD-FAILED",
                                    "error": "%s: %s" % (type(exc).__name__, exc)}
                continue
            seed = [] if no_consts else spygate.const_needles(str(anchor))
            t1, bad, calls, wit, oth, nn = time.time(), 0, 0, None, 0, 0
            for cname, spec in spygate.CLASSES.items():
                r = spygate.explore(fn, spec, 6, arity, 24, True, seed, no_spy)
                calls += r["calls"]
                oth += r["n_other_direction"]
                nn = max(nn, r["n_needles"])
                if r["verdict"] != "OK":
                    bad += 1
                    if wit is None and r["witness"]:
                        w = r["witness"][0]
                        wit = {"class": cname, "cp": w.get("path_cp"),
                               "verdict": w.get("verdict"),
                               "audit_dependent": w.get("audit_dependent")}
            results[pf.stem] = {
                "verdict": "DIVERGENT" if bad else "OK",
                "n_divergent_classes": bad, "n_needles_max": nn,
                "n_other_direction": oth, "calls": calls,
                "secs": round(time.time() - t1, 3), "witness": wit,
                "n_const_seed": len(seed)}

    killed = sorted(k for k, v in results.items()
                    if v.get("verdict") == "DIVERGENT")
    report = {"gate": "check12", "n": len(results),
              "generators": {"spy": not no_spy, "consts": not no_consts},
              "max_arity": arity,
              "n_divergent": len(killed), "divergent": killed,
              "n_apply_failed": sum(1 for v in results.values()
                                    if v.get("verdict") == "APPLY-FAILED"),
              "total_secs": round(time.time() - t0, 2),
              "results": results}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1, ensure_ascii=True))
    print("%d/%d DIVERGENT in %.1fs (spy=%s consts=%s) -> %s"
          % (len(killed), len(results), report["total_secs"],
             not no_spy, not no_consts, out))
    for k in killed:
        v = results[k]
        print("  KILL %-26s classes=%d calls=%-7d %.3fs" %
              (k, v["n_divergent_classes"], v["calls"], v["secs"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
