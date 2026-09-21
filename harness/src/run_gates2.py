"""run_gates2.py — verified-fix v1 gate runner (measured, not argued).

Runs, in the mandated order, for one candidate patch:

  freeze verify -> 検査2 -> 検査3(修正版) -> 検査4(mutgate2) -> 検査5(diffgate2)
  -> R5(順序ランダム 3seed) -> R4(+registry 計数)

plus check1 (oracle fails on the bug) and a HELD-OUT ground-truth probe.  freeze
failure short-circuits (即却下).  Per-gate wall time recorded.  Writes
results2/<name>.json.

usage: run_gates2.py <name> <patchfile>
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time

HOME = pathlib.Path(os.path.expanduser("~"))
REPO = HOME / "vf1/testbed"
SRC = HOME / "vf1/src"
GATES = HOME / "vf1/gates"          # dir on PYTHONPATH holding reportgate.py
REG = REPO / "registry"
RESULTS = HOME / "vf1/results2"
MANIFEST = HOME / "vf1/manifest.json"
BASE = HOME / "vf1/baseline_pre_v1.json"
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
ORACLE = "tests/test_oracle_F_pbt.py"
ANCHOR_FILE = "ccd/guard_pathmatch.py"
ANCHOR_FUNC = "_is_allowed"
LIGHT = ["-m", "not slow"]
BUG = "bug"


def sh(cmd, cwd=REPO, env=None, timeout=1800):
    return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True,
                          text=True, timeout=timeout)


def pytest_run(args, out=None, seed=None, extra_paths=()):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(GATES)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if out:
        env["GATE_OUT"] = str(out)
    cmd = [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "reportgate",
           "--timeout=120", *args, *extra_paths]
    return sh(cmd, env=env)


def outcomes(path):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except Exception:
        return {}


def executed(o):
    return sum(1 for v in o.values() if v in ("passed", "failed", "error"))


def t_outcomes(o):
    return {k: v for k, v in o.items() if k.startswith(ORACLE)}


def reset():
    sh(["git", "checkout", "-qf", BUG])
    sh(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"])


def registry_paths():
    return ["registry"] if REG.exists() and any(REG.glob("test_*.py")) else []


def changed_spec():
    r = sh(["git", "diff", "-U0", "HEAD"])
    per, cur = {}, None
    for line in r.stdout.splitlines():
        m = re.match(r"^\+\+\+ b/(.+)$", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
        if m and cur and not cur.startswith("tests/"):
            s = int(m.group(1))
            c = int(m.group(2) or 1)
            per.setdefault(cur, []).extend(range(s, s + c))
    spec = ";".join(f"{f}:{','.join(str(x) for x in sorted(set(l)) if x > 0)}"
                    for f, l in per.items())
    return spec, sorted(per)


def timed(fn):
    t0 = time.time()
    v = fn()
    return v, round(time.time() - t0, 2)


def main() -> int:
    name, patch = sys.argv[1], sys.argv[2]
    RESULTS.mkdir(parents=True, exist_ok=True)
    res = {"name": name, "patch": patch, "gates": {}, "timing": {}, "notes": []}

    # ---- pre-fix: check1 + baseline -------------------------------------
    reset()
    pre_t = RESULTS / f"{name}.pre_t.json"
    r = pytest_run([ORACLE], out=pre_t)
    res["check1_oracle_fails_on_bug"] = r.returncode != 0

    if BASE.exists():
        base = json.loads(BASE.read_text())
    else:
        pa = RESULTS / "pre_all.json"
        pytest_run(LIGHT, out=pa, extra_paths=registry_paths())
        o = outcomes(pa)
        base = {"executed": executed(o), "outcomes": o}
        BASE.write_text(json.dumps(base))
    res["baseline_executed"] = base["executed"]

    # ---- apply patch ----------------------------------------------------
    ap = sh(["git", "apply", "--whitespace=nowarn", patch])
    if ap.returncode != 0:
        res["error"] = "patch apply failed: " + ap.stderr[:300]
        (RESULTS / f"{name}.json").write_text(json.dumps(res, indent=1))
        print(json.dumps(res, indent=1))
        return 2
    spec, changed = changed_spec()
    res["src_files_changed"] = changed
    res["fix_site_spec"] = spec

    # ================= GATE 1: freeze verify (short-circuit) =============
    def _freeze():
        return sh([PY, str(SRC / "freeze.py"), "verify", "--repo", str(REPO),
                   "--manifest", str(MANIFEST), "--registry", str(REG)])
    fr, res["timing"]["freeze"] = timed(_freeze)
    try:
        fj = json.loads(fr.stdout)
    except Exception:
        fj = {"pass": False, "violations": [(fr.stdout + fr.stderr)[:200]]}
    res["gates"]["freeze"] = bool(fj.get("pass"))
    res["freeze_violations"] = fj.get("violations", [])[:10]
    if not res["gates"]["freeze"]:
        res["killed_by"] = "freeze"
        res["all_gates_passed"] = False
        res["notes"].append("short-circuit at freeze (即却下)")
        _finish(res, name)
        return 0

    # ================= GATE 2: 検査2 (oracle passes) ====================
    def _c2():
        return pytest_run([ORACLE], out=RESULTS / f"{name}.post_t.json")
    r2, res["timing"]["check2"] = timed(_c2)
    to = t_outcomes(outcomes(RESULTS / f"{name}.post_t.json"))
    res["gates"]["check2"] = r2.returncode == 0 and bool(to) and all(v == "passed" for v in to.values())
    res["post_oracle_outcomes"] = to

    # ================= GATE 3: 検査3 (revert -> assertion fail) ==========
    def _c3():
        return sh([PY, str(SRC / "check3.py"), str(REPO), patch, ORACLE, str(GATES), PY])
    r3, res["timing"]["check3"] = timed(_c3)
    try:
        c3 = json.loads(r3.stdout)
    except Exception:
        c3 = {"pass": False, "error": (r3.stdout + r3.stderr)[:200]}
    res["gates"]["check3"] = bool(c3.get("pass"))
    res["check3"] = {k: c3.get(k) for k in ("failed_via_assertion", "collected", "had_setup_error", "reason")}

    # ================= GATE 4: 検査4 (mutgate2) =========================
    def _c4():
        return sh([PY, str(SRC / "mutgate2.py"), str(REPO), ORACLE, PY, spec, "--engine", "auto"], timeout=1800)
    r4, res["timing"]["check4"] = timed(_c4)
    try:
        c4 = json.loads(r4.stdout)
    except Exception:
        c4 = {"pass": False, "error": (r4.stdout + r4.stderr)[:300]}
    res["gates"]["check4"] = bool(c4.get("pass"))
    res["check4"] = {k: c4.get(k) for k in ("engine", "mutants", "killed", "survivors_n", "survivors", "note", "pass")}

    # ================= GATE 5: 検査5 (diffgate2) ========================
    imgdir = RESULTS / f"{name}.img"
    imgdir.mkdir(exist_ok=True)
    pre_images, post_images = {}, {}
    for f in changed:
        safe = f.replace("/", "_").replace(".", "_") + ".py"
        (imgdir / ("pre_" + safe)).write_text(sh(["git", "show", f"HEAD:{f}"]).stdout)
        (imgdir / ("post_" + safe)).write_text((REPO / f).read_text())
        pre_images[f] = str(imgdir / ("pre_" + safe))
        post_images[f] = str(imgdir / ("post_" + safe))
    cfg = imgdir / "cfg.json"
    cfg.write_text(json.dumps({"repo": str(REPO), "changed": changed,
                               "pre_images": pre_images, "post_images": post_images,
                               "anchor_file": ANCHOR_FILE, "anchor_func": ANCHOR_FUNC}))

    def _c5():
        return sh([PY, str(SRC / "diffgate2.py"), str(cfg)])
    r5c, res["timing"]["check5"] = timed(_c5)
    try:
        c5 = json.loads(r5c.stdout)
    except Exception:
        c5 = {"pass": False, "error": (r5c.stdout + r5c.stderr)[:300]}
    res["gates"]["check5"] = bool(c5.get("pass"))
    res["check5"] = {k: c5.get(k) for k in
                     ("compared_calls", "out_of_scope_divergences", "out_of_scope_sample",
                      "in_scope_divergences", "uncovered_changed_functions", "changed_functions", "pass")}

    # ================= R5 + R4 ===========================================
    def _r5():
        runs = []
        for seed in (11, 22, 33):
            of = RESULTS / f"{name}.post_all_{seed}.json"
            pytest_run(LIGHT, out=of, seed=seed, extra_paths=registry_paths())
            o = outcomes(of)
            to2 = t_outcomes(o)
            runs.append({"seed": seed,
                         "oracle_passed": bool(to2) and all(v == "passed" for v in to2.values()),
                         "executed": executed(o)})
        return runs
    r5runs, res["timing"]["R5+R4"] = timed(_r5)
    res["r5_runs"] = r5runs
    res["gates"]["R5"] = all(x["oracle_passed"] for x in r5runs)
    res["gates"]["R4"] = all(x["executed"] >= base["executed"] for x in r5runs)
    res["r4_detail"] = {"baseline": base["executed"], "runs": [x["executed"] for x in r5runs]}

    # ---- held-out ground truth -----------------------------------------
    tr = sh([PY, "/tmp/harden_gates/truth.py", str(REPO)])
    try:
        res["ground_truth"] = json.loads(tr.stdout)
    except Exception:
        res["ground_truth"] = {"F_fixed": None, "err": (tr.stdout + tr.stderr)[:200]}

    res["all_gates_passed"] = all(v is True for v in res["gates"].values())
    if not res["all_gates_passed"]:
        order = ["freeze", "check2", "check3", "check4", "check5", "R5", "R4"]
        res["killed_by"] = next((g for g in order if res["gates"].get(g) is False), None)
    _finish(res, name)
    return 0


def _finish(res, name):
    reset()
    (RESULTS / f"{name}.json").write_text(json.dumps(res, indent=1))
    summary = {k: res[k] for k in ("name", "check1_oracle_fails_on_bug", "gates",
               "all_gates_passed") if k in res}
    summary["killed_by"] = res.get("killed_by")
    summary["ground_truth_F_fixed"] = res.get("ground_truth", {}).get("F_fixed")
    summary["timing"] = res.get("timing")
    print(json.dumps(summary, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
