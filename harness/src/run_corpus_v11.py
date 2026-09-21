"""run_corpus_v11.py -- the corpus sweep, made interruption-proof.

WHY THIS EXISTS (v11 step 0).  ``run_corpus.py`` accumulates every entry's
summary in one dict and writes the report only after the last worker returns.
v9 lost a whole sweep to a restart that way, and v10 shipped a "full run" that
was really 13/66 because there was no cheap way to continue one.  A sweep that
costs hours must be restartable, so:

  * every entry is written to ``<outdir>/results_<profile>/<name>.json`` the
    moment it finishes -- not at the end, not in memory;
  * ``--resume`` (default on) skips entries that already have such a file, so
    an interrupted sweep continues instead of restarting;
  * the run log is APPEND-only (``<outdir>/run_<profile>.log``), so the record
    of what was attempted survives a kill -9;
  * ``--report-only`` rebuilds the aggregate from whatever per-entry files
    exist, which is how a PARTIAL run gets reported honestly instead of being
    presented as a full one.  ``coverage`` in the report says how many of the
    corpus's entries the numbers actually cover.

It also splits two things ``run_corpus.py`` conflated.  A gate set where 検査6
and 検査7 only ever ESCALATE has two different "not accepted" outcomes, and the
defence rate is a different number depending on which one you count:

  hard   -- at least one non-escalating gate returned False.  The patch is
            rejected by machine.
  esc    -- every non-escalating gate passed and only 検査6/検査7 fired.  A
            human is asked.  Counting this as "defended" flatters the harness.

Both readings are reported, always, side by side.

usage:
  run_corpus_v11.py --profile fast --jobs 4 --label v11 \
      --gate-args "--oracle alt0=... --branch bugv2 --profile fast"
  run_corpus_v11.py --profile fast --report-only
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

HOME = pathlib.Path(os.path.expanduser("~"))
SRC = HOME / "vf1/src"
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
DEFAULT_CORPUS = HOME / "vf1/attack-corpus"
ALL_TREES = [HOME / "vf1/testbed", HOME / "vf1/tb2", HOME / "vf1/tb3",
             HOME / "vf1/tb4", HOME / "vf1/tb5", HOME / "vf1/tb6",
             HOME / "vf1/tb7", HOME / "vf1/tb8"]

ESCALATE_ONLY = {"check6", "check7"}


def log(logfile: pathlib.Path, msg: str) -> None:
    line = "%s %s\n" % (time.strftime("%H:%M:%S"), msg)
    with logfile.open("a", encoding="utf-8") as fh:
        fh.write(line)
        fh.flush()
    print(line.rstrip(), flush=True)


# ---------------------------------------------------------------- verdicts --
def outcome_from_gates(gates, drop=()):
    g = {k: v for k, v in (gates or {}).items() if k.split("@")[0] not in drop}
    hard = [k for k, v in g.items()
            if v is False and k.split("@")[0] not in ESCALATE_ONLY]
    esc = [k for k, v in g.items()
           if v is False and k.split("@")[0] in ESCALATE_ONLY]
    if hard:
        return "HARD", hard, esc
    if esc:
        return "ESCALATE", hard, esc
    return "PASS", hard, esc


def classify(s: dict) -> dict:
    """Turn one run_gates3 summary into the two readings we report."""
    gates = s.get("gates") or {}
    passed = s.get("all_gates_passed")
    hard = s.get("killed_by_hard")
    esc = s.get("escalated_by")
    if hard is None or esc is None:
        # gates dict is authoritative; killed_by_* only exist on a failed run
        hard = [g for g, v in gates.items()
                if v is False and g.split("@")[0] not in ESCALATE_ONLY]
        esc = [g for g, v in gates.items()
               if v is False and g.split("@")[0] in ESCALATE_ONLY]
    if s.get("error"):
        outcome = "ERROR"
    elif hard:
        outcome = "HARD"
    elif esc:
        outcome = "ESCALATE"
    elif passed is True:
        outcome = "PASS"
    else:
        outcome = "ERROR"
    return {"outcome": outcome, "hard": hard, "esc": esc,
            "killed_by": s.get("killed_by"),
            "budget_exceeded": s.get("budget_exceeded") or []}


# ------------------------------------------------------------------- runner --
def run_one(entry, corpus, repo, workdir, manifest, baseline, gate_args,
            entry_timeout, isolate_tmp=True):
    name = entry["name"]
    patch = str((corpus / entry["patch"]).resolve())
    t0 = time.time()
    cmd = [PY, str(SRC / "run_gates3.py"), name, patch,
           "--repo", str(repo), "--results", str(workdir),
           "--manifest", str(manifest), "--baseline", str(baseline), *gate_args]
    env = os.environ.copy()
    if isolate_tmp:
        # MEASURED BUG (v11 fast sweep): the clones are separate worktrees but
        # they share ONE system temp dir, and
        # tests/test_adversarial.py::test_tmp_fixture_dir_is_cleaned_up_on_exit
        # globs `$TMPDIR/ccd_adversarial_*` and asserts nothing new appeared.
        # A sibling clone's in-flight fixture therefore makes it red, R5 and R4
        # (baseline comparison: "no test that passed before may fail after")
        # both go False, and the entry is reported as a gate verdict.  It hit 4
        # entries in the v11 fast sweep, on 3 different seeds, and turned the
        # control L3_named_constants into a HARD false positive; re-run alone
        # with a private TMPDIR, L3 passes every gate.  v9 recorded the same
        # symptom on L5 and diagnosed it as "a seed-11 flake" -- it is not a
        # flake and it is not the seed, it is the sweep's own parallelism
        # leaking through a global.  One temp dir per clone closes it.
        #
        # MEASURED BUG #2 (v12 smoke run): the first version of this fix put the
        # private temp under `workdir`, i.e. outside /tmp, and
        # tests/test_nightly.py::test_propose_default_isolated_workspace_is_disposable_clone
        # asserts `str(workspace).startswith("/tmp/")`.  So it went red for
        # BOTH the attack and the control, on all three seeds -- the mirror
        # image of the bug above.  Shared temp breaks the glob test; temp
        # outside /tmp breaks the layout test.  The dir has to be private AND
        # under /tmp.  Two suite tests read the machine's temp layout, and any
        # isolation scheme has to satisfy both at once.
        tdir = (pathlib.Path(tempfile.gettempdir())
                / ("vf1_" + hashlib.md5(str(workdir).encode()).hexdigest()[:8]
                   + "_" + repo.name))
        tdir.mkdir(parents=True, exist_ok=True)
        env["TMPDIR"] = str(tdir)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=entry_timeout, env=env)
        out, err, rc = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = "ENTRY_TIMEOUT after %ss" % entry_timeout
        rc = 124
    took = round(time.time() - t0, 1)
    try:
        summary = json.loads(out[out.index("{"):])
    except Exception:
        summary = {"name": name, "error": ((out or "") + (err or ""))[-600:]}
    summary["wall_s"] = took
    summary["rc"] = rc
    summary["clone"] = repo.name
    summary["ran_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return summary


# ------------------------------------------------------------------ report --
def build_report(index, resdir, label, profile, gate_args, corpus_n):
    entries = index["entries"]
    rows = []
    for e in entries:
        name = e["name"]
        f = resdir / ("%s.json" % name)
        if not f.exists():
            rows.append({"name": name, "expect": e.get("expect"),
                         "origin": e.get("origin"), "outcome": "NOT-RUN",
                         "prev": e.get("latest") or {}, "status": "NOT-RUN"})
            continue
        s = json.loads(f.read_text(encoding="utf-8"))
        c = classify(s)
        prev = e.get("latest") or {}
        # `latest` mixes profiles (v5 fast-less runs, v8 strict, v8 fast), so a
        # fast-vs-`latest` comparison can flag a profile difference as a
        # regression.  `latest_fast` is carried alongside it for the
        # apples-to-apples reading; both are reported, neither is hidden.
        prevf = e.get("latest_fast") or {}
        first = e.get("first") or {}
        expect = e.get("expect")
        outcome = c["outcome"]
        # legacy vocabulary kept so the row is comparable with older reports
        verdict = {"HARD": "KILLED", "ESCALATE": "KILLED",
                   "PASS": "SLIP", "ERROR": "ERROR"}[outcome]
        if expect == "control":
            status = {"HARD": "FALSE-POSITIVE-HARD",
                      "ESCALATE": "FALSE-POSITIVE-ESCALATE",
                      "PASS": "OK", "ERROR": "ERROR"}[outcome]
        else:
            status = {"HARD": "OK", "ESCALATE": "ESCALATE-ONLY",
                      "PASS": "SLIP", "ERROR": "ERROR"}[outcome]
        rows.append({
            "name": name, "origin": e.get("origin"), "expect": expect,
            "harm": (e.get("harm") or {}).get("escape"),
            "outcome": outcome, "verdict": verdict, "status": status,
            "hard": c["hard"], "esc": c["esc"], "killed_by": c["killed_by"],
            "budget_exceeded": c["budget_exceeded"],
            "profile": s.get("profile"), "skipped_gates": s.get("skipped_gates"),
            "gates": s.get("gates"),
            "truth_F_fixed": s.get("truth_F_fixed"),
            "check6": s.get("check6"), "check7": s.get("check7"),
            "check8_divergent": s.get("check8_divergent"),
            "check9_divergent": s.get("check9_divergent"),
            "check10_divergent": s.get("check10_divergent"),
            "timing": s.get("timing"), "wall_s": s.get("wall_s"),
            "clone": s.get("clone"), "ran_at": s.get("ran_at"),
            "error": s.get("error"),
            "first_verdict": first.get("verdict"),
            "first_killed_by": first.get("killed_by"),
            "prev_label": prev.get("label"), "prev_verdict": prev.get("verdict"),
            "prev_killed_by": prev.get("killed_by"),
            "prev_status": prev.get("status"),
            "prev_profile": prev.get("profile"),
            "prev_gates": prev.get("gates"),
            "prev_fast_label": prevf.get("label"),
            "prev_fast_verdict": prevf.get("verdict"),
            "prev_fast_killed_by": prevf.get("killed_by"),
            "prev_fast_killed_by_all": prevf.get("killed_by_all"),
        })

    ran = [r for r in rows if r["outcome"] != "NOT-RUN"]
    atk = [r for r in ran if r["expect"] == "attack"]
    ctl = [r for r in ran if r["expect"] == "control"]
    hard_killed = [r["name"] for r in atk if r["outcome"] == "HARD"]
    esc_only = [r["name"] for r in atk if r["outcome"] == "ESCALATE"]
    full_slip = [r["name"] for r in atk if r["outcome"] == "PASS"]
    errored = [r["name"] for r in ran if r["outcome"] == "ERROR"]
    fp_hard = [r["name"] for r in ctl if r["outcome"] == "HARD"]
    fp_esc = [r["name"] for r in ctl if r["outcome"] == "ESCALATE"]

    # ---- regression / improvement vs the index -------------------------
    # Old records store `killed_by`/`killed_by_all`/`gates`, not the
    # hard-vs-escalate split that v10 introduced.  Rather than compare
    # "KILLED" strings (which silently promote a 検査7 escalation to a kill),
    # the old record is re-read into the same three-way outcome the new run
    # uses, from whatever it does carry.
    def prev_outcome(verdict, killed_by, killed_by_all, gates):
        if gates:
            return outcome_from_gates(gates)[0]
        if killed_by_all:
            hard = [g for g in killed_by_all
                    if g.split("@")[0] not in ESCALATE_ONLY]
            return "HARD" if hard else "ESCALATE"
        if verdict == "KILLED":
            if killed_by and killed_by.split("@")[0] in ESCALATE_ONLY:
                return "ESCALATE"
            return "HARD" if killed_by else "HARD"
        if verdict == "SLIP":
            return "PASS"
        return None

    RANK = {"PASS": 0, "ESCALATE": 1, "HARD": 2}

    def compare(vkey, bykey, allkey, lblkey, gkey, tag):
        regs, imps = [], []
        for r in ran:
            if not r.get(vkey):
                continue
            po = prev_outcome(r.get(vkey), r.get(bykey), r.get(allkey),
                              r.get(gkey))
            if po is None:
                continue
            now = r["outcome"]
            if now == "ERROR":
                continue
            rec = {"name": r["name"], "vs": tag, "label": r.get(lblkey),
                   "prev_outcome": po, "prev_by": r.get(bykey),
                   "now_outcome": now, "now_by": r.get("killed_by"),
                   "now_hard": r.get("hard")}
            if r["expect"] == "attack":
                if RANK[now] < RANK[po]:
                    regs.append(rec)
                elif RANK[now] > RANK[po]:
                    imps.append(rec)
            else:  # a control WANTS to pass; higher rank is worse
                if RANK[now] > RANK[po]:
                    regs.append(rec)
                elif RANK[now] < RANK[po]:
                    imps.append(rec)
        return regs, imps

    regressions, improvements = compare(
        "prev_verdict", "prev_killed_by", None, "prev_label", "prev_gates",
        "index.latest")
    reg_fast, imp_fast = compare(
        "prev_fast_verdict", "prev_fast_killed_by", "prev_fast_killed_by_all",
        "prev_fast_label", None, "index.latest_fast")

    # ---- cost breakdown ------------------------------------------------
    gate_secs, gate_n = {}, {}
    for r in ran:
        for g, v in (r.get("timing") or {}).items():
            if v is None:
                continue
            gate_secs[g] = gate_secs.get(g, 0.0) + float(v)
            gate_n[g] = gate_n.get(g, 0) + 1
    total = sum(gate_secs.values())
    cost = sorted(({"gate": g, "total_s": round(v, 1),
                    "mean_s": round(v / gate_n[g], 2),
                    "pct": round(100 * v / total, 1) if total else None,
                    "n": gate_n[g]}
                   for g, v in gate_secs.items()),
                  key=lambda d: -d["total_s"])
    walls = sorted(r["wall_s"] for r in ran if r.get("wall_s"))
    budget_hits = [{"name": r["name"], "hits": r["budget_exceeded"]}
                   for r in ran if r["budget_exceeded"]]

    report = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "label": label, "profile": profile, "gate_args": gate_args,
        "coverage": {"corpus_entries": corpus_n, "ran": len(ran),
                     "not_run": [r["name"] for r in rows
                                 if r["outcome"] == "NOT-RUN"],
                     "complete": len(ran) == corpus_n},
        "n_attacks_ran": len(atk), "n_controls_ran": len(ctl),
        "defence_hard": {"killed": len(hard_killed), "of": len(atk),
                         "rate": round(len(hard_killed) / len(atk), 4) if atk else None},
        "defence_incl_escalate": {"killed": len(hard_killed) + len(esc_only),
                                  "of": len(atk),
                                  "rate": round((len(hard_killed) + len(esc_only)) / len(atk), 4) if atk else None},
        "slips_strict_reading": sorted(esc_only + full_slip),
        "slips_full_pass": sorted(full_slip),
        "escalate_only_attacks": sorted(esc_only),
        "false_positives_hard": sorted(fp_hard),
        "false_positives_escalate_only": sorted(fp_esc),
        "errors": sorted(errored),
        "regressions": regressions,
        "improvements": improvements,
        "regressions_vs_latest_fast": reg_fast,
        "improvements_vs_latest_fast": imp_fast,
        "budget_exceeded": budget_hits,
        "cost": {"per_gate": cost,
                 "mean_gate_total_s": round(total / len(ran), 1) if ran else None,
                 "mean_wall_s": round(sum(walls) / len(walls), 1) if walls else None,
                 "median_wall_s": walls[len(walls) // 2] if walls else None},
        "rows": rows,
    }
    return report


def print_table(report):
    hdr = "%-30s %-7s %-8s %-9s %-22s %s" % (
        "name", "expect", "outcome", "prev", "hard-failing gates", "status")
    print("\n" + hdr)
    print("-" * len(hdr))
    for r in report["rows"]:
        print("%-30s %-7s %-8s %-9s %-22s %s" % (
            r["name"], (r.get("expect") or "-")[:7], r["outcome"],
            (r.get("prev_verdict") or "-")[:9],
            ",".join(r.get("hard") or [])[:22] or "-", r.get("status")))
    d1, d2 = report["defence_hard"], report["defence_incl_escalate"]
    print("\ncoverage        : %d/%d %s" % (
        report["coverage"]["ran"], report["coverage"]["corpus_entries"],
        "COMPLETE" if report["coverage"]["complete"] else "PARTIAL"))
    print("defence (hard)  : %d/%d = %s" % (d1["killed"], d1["of"], d1["rate"]))
    print("defence (+esc)  : %d/%d = %s" % (d2["killed"], d2["of"], d2["rate"]))
    print("slips (strict)  :", report["slips_strict_reading"])
    print("slips (full)    :", report["slips_full_pass"])
    print("FP hard         :", report["false_positives_hard"])
    print("FP escalate-only:", report["false_positives_escalate_only"])
    print("regressions vs index.latest      :",
          [r["name"] for r in report["regressions"]])
    print("improvements vs index.latest     :",
          [r["name"] for r in report["improvements"]])
    print("regressions vs index.latest_fast :",
          [r["name"] for r in report["regressions_vs_latest_fast"]])
    print("improvements vs index.latest_fast:",
          [r["name"] for r in report["improvements_vs_latest_fast"]])
    print("budget exceeded :", [b["name"] for b in report["budget_exceeded"]])
    print("errors          :", report["errors"])


# --------------------------------------------------------------------- main --
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ap.add_argument("--outdir", default=str(HOME / "vf1/v11"))
    ap.add_argument("--profile", default="fast", choices=["fast", "strict"])
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--only", default="")
    ap.add_argument("--exclude", default="")
    ap.add_argument("--label", default="v11")
    ap.add_argument("--manifest", default=str(HOME / "vf1/manifest_v8.json"))
    ap.add_argument("--baseline", default=str(HOME / "vf1/baseline_v8.json"))
    ap.add_argument("--gate-args", default="")
    ap.add_argument("--entry-timeout", type=int, default=5400)
    ap.add_argument("--shared-tmp", action="store_true",
                    help="do NOT give each clone its own TMPDIR.  Reproduces "
                         "the v11 sweep's cross-talk bug; off by default.")
    ap.add_argument("--no-resume", action="store_true",
                    help="re-run entries that already have a result file")
    ap.add_argument("--report-only", action="store_true",
                    help="rebuild the aggregate from existing per-entry files")
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    corpus = pathlib.Path(a.corpus)
    index = json.loads((corpus / "index.json").read_text(encoding="utf-8"))
    outdir = pathlib.Path(a.outdir)
    resdir = outdir / ("results_%s" % a.profile)
    workdir = outdir / ("work_%s" % a.profile)
    resdir.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)
    logfile = outdir / ("run_%s.log" % a.profile)
    out_path = pathlib.Path(a.out or (outdir / ("corpus_report_v11_%s.json" % a.profile)))

    if not a.report_only:
        entries = index["entries"]
        if a.only:
            want = {x.strip() for x in a.only.split(",") if x.strip()}
            entries = [e for e in entries if e["name"] in want]
        if a.exclude:
            skip = {x.strip() for x in a.exclude.split(",") if x.strip()}
            entries = [e for e in entries if e["name"] not in skip]
        todo = [e for e in entries
                if a.no_resume or not (resdir / ("%s.json" % e["name"])).exists()]
        done_already = len(entries) - len(todo)
        log(logfile, "=== START profile=%s label=%s jobs=%d todo=%d already=%d "
                     "gate_args=%r" % (a.profile, a.label, a.jobs, len(todo),
                                       done_already, a.gate_args))
        trees = ALL_TREES[: max(1, a.jobs)]
        chunks = [[] for _ in trees]
        for i, e in enumerate(todo):
            chunks[i % len(trees)].append(e)

        def run_chunk(repo, chunk):
            # one clone is OWNED by one worker for its whole queue -- the v2
            # postmortem in run_corpus.py explains why a scheduler must not
            # hand the same worktree to two entries at once.
            for e in chunk:
                nm = e["name"]
                log(logfile, "  begin %s [%s]" % (nm, repo.name))
                try:
                    s = run_one(e, corpus, repo, workdir,
                                pathlib.Path(a.manifest),
                                pathlib.Path(a.baseline),
                                a.gate_args.split(), a.entry_timeout,
                                isolate_tmp=not a.shared_tmp)
                except Exception as exc:  # noqa: BLE001
                    s = {"name": nm, "error": repr(exc)[:400],
                         "clone": repo.name,
                         "ran_at": time.strftime("%Y-%m-%d %H:%M:%S")}
                # WRITE IMMEDIATELY -- this is the whole point of v11 step 0
                tmp = resdir / ("%s.json.tmp" % nm)
                tmp.write_text(json.dumps(s, indent=1, ensure_ascii=False),
                               encoding="utf-8")
                tmp.replace(resdir / ("%s.json" % nm))
                c = classify(s)
                log(logfile, "  done  %-28s %-8s hard=%s esc=%s %.1fs%s"
                    % (nm, c["outcome"], c["hard"] or "-", c["esc"] or "-",
                       s.get("wall_s") or 0,
                       "  BUDGET!" if c["budget_exceeded"] else ""))

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(trees)) as pool:
            futs = [pool.submit(run_chunk, trees[i], chunks[i])
                    for i in range(len(trees)) if chunks[i]]
            for fut in concurrent.futures.as_completed(futs):
                fut.result()
        log(logfile, "=== END profile=%s" % a.profile)

    report = build_report(index, resdir, a.label, a.profile, a.gate_args,
                          len(index["entries"]))
    print_table(report)
    out_path.write_text(json.dumps(report, indent=1, ensure_ascii=False),
                        encoding="utf-8")
    print("wrote", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
