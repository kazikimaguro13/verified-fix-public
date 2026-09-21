"""mutgate2.py — 検査4: per-patch mutation, oracle-strength check.

Two engines:

 * ``cosmic-ray`` (DESIGN preferred) — cosmic-ray 8.7.0 with ``cr-filter-git``
   restricting mutations to the patch's lines.  **The measured trap**: the
   git-filter defaults to the ``master`` branch and dies if it is absent, so
   the config MUST name a committish explicitly
   (``[cosmic-ray.filters.git-filter] branch = "<pre-fix-commit>"``).  Here the
   pre-fix state is the current ``HEAD`` (the fix is applied but uncommitted),
   so ``branch = "HEAD"`` scopes mutation to exactly the working-tree diff.

 * ``builtin`` (fallback) — the v0 patch-line string-mutation engine.  Used
   automatically if cosmic-ray errors; the report records which engine ran.

A mutant is "killed" if the frozen oracle T FAILS on it.  Gate passes iff there
is >=1 mutant and every mutant is killed (no survivors) — i.e. the oracle is
strong enough to notice any corruption of the patched lines.

usage: mutgate2.py <repo> <oracle_relpath> <python> <spec> [--engine auto|cosmic|builtin]
  spec = "file:line,line;file:line,..."   (post-image line numbers)
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

OPS = [
    ("startswith", "endswith"), ("endswith", "startswith"),
    ("==", "!="), ("!=", "=="), (" and ", " or "), (" or ", " and "),
    ("True", "False"), ("False", "True"), ("not ", ""),
    (' + "/"', ""), (" + '/'", ""), (">=", ">"), ("<=", "<"),
    ("rstrip", "strip"), ("in ", "not in "), (" > ", " < "),
]


def sh(cmd, cwd, env=None, timeout=1800):
    return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True,
                          text=True, timeout=timeout)


def parse_spec(spec):
    targets = []
    for part in spec.split(";"):
        if not part.strip():
            continue
        f, _, lns = part.partition(":")
        nums = [int(x) for x in lns.split(",") if x.strip()]
        targets.append((f, nums))
    return targets


def gen_mutants(text, lines):
    src = text.split("\n")
    out, seen = [], set()
    for ln in lines:
        if ln - 1 >= len(src):
            continue
        orig = src[ln - 1]
        st = orig.strip()
        if not st or st.startswith("#"):
            continue
        for a, b in OPS:
            if a in orig:
                mut = orig.replace(a, b, 1)
                if mut == orig:
                    continue
                new = src[:]
                new[ln - 1] = mut
                body = "\n".join(new)
                if body in seen or body == text:
                    continue
                seen.add(body)
                out.append((f"L{ln}:{a!r}->{b!r}", body))
        if st.startswith("if ") and st.endswith(":"):
            ind = orig[: len(orig) - len(orig.lstrip())]
            for forced in ("True", "False"):
                new = src[:]
                new[ln - 1] = f"{ind}if {forced}:"
                body = "\n".join(new)
                if body in seen or body == text:
                    continue
                seen.add(body)
                out.append((f"L{ln}:cond->{forced}", body))
    return out


def oracle_cmd(py, oracle):
    return [py, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--timeout=120", oracle]


def run_builtin(repo, oracle, py, targets):
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    cmd = oracle_cmd(py, oracle)
    results = []
    for f, lines in targets:
        path = repo / f
        original = path.read_text()
        for label, body in gen_mutants(original, lines):
            path.write_text(body)
            try:
                r = sh(cmd, repo, env, timeout=300)
                killed = r.returncode != 0
            finally:
                path.write_text(original)
            results.append({"file": f, "mutant": label, "killed": killed})
    total = len(results)
    killed = sum(1 for r in results if r["killed"])
    survivors = [r for r in results if not r["killed"]]
    return {
        "engine": "builtin",
        "mutants": total,
        "killed": killed,
        "score": (killed / total) if total else None,
        "survivors": survivors,
        "pass": total > 0 and killed == total,
    }


def run_cosmic(repo, oracle, py, targets):
    vbin = pathlib.Path(py).parent
    cr = str(vbin / "cosmic-ray")
    crfilter = str(vbin / "cr-filter-git")
    crreport = str(vbin / "cr-report")
    if not pathlib.Path(cr).exists():
        # cosmic-ray installed in a different venv (the tooling venv)
        alt = pathlib.Path(os.path.expanduser("~/vf1/venv/bin"))
        if not (alt / "cosmic-ray").exists():
            alt = pathlib.Path("/tmp/tooling_test/venv312/bin")
        cr, crfilter, crreport = str(alt / "cosmic-ray"), str(alt / "cr-filter-git"), str(alt / "cr-report")
    files = sorted({f for f, _ in targets})
    per_file = []
    for f in files:
        cfg = repo / ".mutgate_cr.toml"
        session = repo / ".mutgate_cr.sqlite"
        tcmd = " ".join(oracle_cmd(py, oracle))
        cfg.write_text(
            "[cosmic-ray]\n"
            f'module-path = "{f}"\n'
            "timeout = 60.0\n"
            "excluded-modules = []\n"
            f'test-command = "{tcmd}"\n\n'
            "[cosmic-ray.distributor]\n"
            'name = "local"\n\n'
            "[cosmic-ray.filters.git-filter]\n"
            'branch = "HEAD"\n'   # <-- committish MUST be explicit (the trap)
        )
        if session.exists():
            session.unlink()
        init = sh([cr, "init", str(cfg), str(session)], repo)
        # cr-filter-git skips mutants outside the working-tree diff vs `branch`.
        filt = sh([crfilter, "--config", str(cfg), str(session)], repo)
        ex = sh([cr, "exec", str(cfg), str(session)], repo, timeout=1200)
        rep = sh([crreport, "--show-output", str(session)], repo)
        text = rep.stdout
        total_jobs = 0
        for line in text.splitlines():
            if line.startswith("total jobs:"):
                total_jobs = int(line.split(":")[1])
        executed = text.count("WorkerOutcome.NORMAL")      # ran (in patch scope)
        skipped = text.count("WorkerOutcome.SKIPPED")      # off-patch, filtered out
        killed = text.count("TestOutcome.KILLED")
        survived = text.count("TestOutcome.SURVIVED")
        # v4: record *which* mutant survived.  A count alone cannot distinguish
        # "the oracle is weak" from "the mutant landed on a branch the oracle can
        # never reach" -- and the second is the interesting one, because a dead
        # branch is exactly what a malicious patch adds.  cr-report prints
        #   <module> <operator> <occurrence>
        # on the line *after* the job id, and the outcome two lines later.
        surv_desc = []
        lines_ = text.splitlines()
        for i, ln in enumerate(lines_):
            if "TestOutcome.SURVIVED" in ln:
                for back in range(i - 1, max(-1, i - 4), -1):
                    if lines_[back].startswith(f"{f} "):
                        surv_desc.append(lines_[back].strip())
                        break
        per_file.append({"file": f, "init_rc": init.returncode, "filter_rc": filt.returncode,
                         "exec_rc": ex.returncode, "total_jobs": total_jobs,
                         "executed": executed, "killed": killed, "survived": survived,
                         "skipped": skipped, "survivor_desc": surv_desc[:10],
                         "err": (init.stderr + filt.stderr + ex.stderr)[:200]})
        for p in (cfg, session):
            try:
                p.unlink()
            except OSError:
                pass
    executed = sum(x["executed"] for x in per_file)
    killed = sum(x["killed"] for x in per_file)
    survived = sum(x["survived"] for x in per_file)
    skipped = sum(x["skipped"] for x in per_file)
    # valid iff patch-site mutants actually ran and none survived
    ok = executed >= 1 and survived == 0 and all(x["exec_rc"] == 0 for x in per_file)
    return {"engine": "cosmic-ray", "per_file": per_file,
            "mutants": executed, "killed": killed, "survivors_n": survived,
            "survivors": [d for x in per_file for d in x["survivor_desc"]],
            "skipped_off_patch": skipped, "pass": ok}


def main() -> int:
    repo = pathlib.Path(sys.argv[1])
    oracle, py, spec = sys.argv[2], sys.argv[3], sys.argv[4]
    engine = "auto"
    if "--engine" in sys.argv:
        engine = sys.argv[sys.argv.index("--engine") + 1]
    targets = parse_spec(spec)
    if not targets:
        print(json.dumps({"pass": False, "reason": "no fix-site lines"}, indent=1))
        return 1

    result = None
    if engine in ("auto", "cosmic"):
        try:
            result = run_cosmic(repo, oracle, py, targets)
            if engine == "auto" and not result.get("mutants"):
                result = None  # cosmic produced nothing -> fall back
        except Exception as exc:  # noqa: BLE001
            result = None if engine == "auto" else {
                "engine": "cosmic-ray", "pass": False, "error": str(exc)[:200]}
    if result is None:
        result = run_builtin(repo, oracle, py, targets)
        result["note"] = "cosmic-ray unavailable/empty -> builtin fallback"

    print(json.dumps(result, indent=1))
    return 0 if result.get("pass") else 1


if __name__ == "__main__":
    sys.exit(main())
