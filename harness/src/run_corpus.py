"""run_corpus.py -- the gates' own CI (DESIGN D5).

The attack corpus is the only thing that stops a gate change from being a
*regression*: a gate you loosen to let one awkward patch through will let every
historical attack through too, and nothing else in the pipeline notices.  So
the rule is: **change a gate, run this.**

Reads ``attack-corpus/index.json``:

    {"entries": [
       {"name": "...", "patch": "patches/x.patch", "origin": "v0|v1|v2",
        "intent": "...", "expect": "attack|control",
        "harm": {"escape": true, "n_escape": 52, "reachable": 48,
                 "how": "truth_v2 grid" | "targeted witness", "witness": "..."},
        "first": {"seen": "v1", "verdict": "SLIP|KILLED", "killed_by": "check4"}}
    ]}

and re-runs every entry through ``run_gates3.py``, N at a time across N clones
of the testbed, then prints the table that matters:

    name | harm | first verdict/killer | latest verdict/killer | REGRESSION?

A REGRESSION is an entry that was KILLED when first measured and is a SLIP now.
A SLIP on a `control` entry (the correct fix) is inverted: the control must
PASS every gate, and a control that gets killed is a **false positive**, which
is reported just as loudly -- a gate that rejects correct fixes is not a strong
gate, it is a broken one.

usage: run_corpus.py [--corpus DIR] [--jobs N] [--only NAME,NAME] [--out FILE]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import subprocess
import sys
import time

HOME = pathlib.Path.home()
SRC = HOME / "vf1/src"
PY = str(HOME / "projects/Cowork-CC-dispatch/.venv/bin/python")
DEFAULT_CORPUS = HOME / "vf1/attack-corpus"
WORKTREES = [HOME / "vf1/testbed", HOME / "vf1/tb2", HOME / "vf1/tb3", HOME / "vf1/tb4"]


def run_one(entry, corpus: pathlib.Path, repo: pathlib.Path, results: pathlib.Path,
            manifest: pathlib.Path, baseline: pathlib.Path, gate_args=()):
    name = entry["name"]
    patch = str((corpus / entry["patch"]).resolve())
    t0 = time.time()
    r = subprocess.run(
        [PY, str(SRC / "run_gates3.py"), name, patch,
         "--repo", str(repo), "--results", str(results),
         "--manifest", str(manifest), "--baseline", str(baseline), *gate_args],
        capture_output=True, text=True, timeout=3600)
    took = round(time.time() - t0, 1)
    try:
        summary = json.loads(r.stdout[r.stdout.index("{"):])
    except Exception:
        summary = {"name": name, "error": (r.stdout + r.stderr)[-400:]}
    summary["wall_s"] = took
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--only", default="")
    ap.add_argument("--out", default="")
    ap.add_argument("--manifest", default=str(HOME / "vf1/manifest_v2.json"))
    ap.add_argument("--baseline", default=str(HOME / "vf1/baseline_v2.json"))
    ap.add_argument("--results", default=str(HOME / "vf1/results3"))
    ap.add_argument("--update-index", action="store_true",
                    help="write this run's verdict back into index.json as `latest`, "
                         "and fill `first` for entries seen here for the first time")
    ap.add_argument("--label", default="", help="version label stored with `latest`")
    ap.add_argument("--gate-args", default="",
                    help="extra args forwarded verbatim to run_gates3.py")
    a = ap.parse_args()

    corpus = pathlib.Path(a.corpus)
    index = json.loads((corpus / "index.json").read_text(encoding="utf-8"))
    entries = index["entries"]
    if a.only:
        want = {x.strip() for x in a.only.split(",")}
        entries = [e for e in entries if e["name"] in want]

    results_dir = pathlib.Path(a.results)
    results_dir.mkdir(parents=True, exist_ok=True)
    trees = WORKTREES[: max(1, a.jobs)]

    out: dict[str, dict] = {}
    t0 = time.time()

    # MEASURED BUG (first v2 sweep, 2026-08-20): assigning a clone by entry
    # index and submitting all entries to a pool does NOT pin a clone to a
    # thread -- a free worker picks up entry i+jobs while entry i is still
    # running on the same clone, and run_gates3's reset() (`git checkout -f`
    # + `git clean`) wipes the other run's applied patch mid-flight.  The
    # symptom is silent and looks like a gate result: C4's side-effect hunk was
    # reverted before check5 imaged the file, so check5 saw pre == post and
    # PASSED an attack it had killed in v1.  A shared mutable worktree must be
    # owned by exactly one worker for its whole queue, never by a scheduler.
    chunks: list[list] = [[] for _ in trees]
    for i, e in enumerate(entries):
        chunks[i % len(trees)].append(e)

    def run_chunk(repo, chunk):
        local = {}
        for e in chunk:
            try:
                local[e["name"]] = run_one(e, corpus, repo, results_dir,
                                           pathlib.Path(a.manifest),
                                           pathlib.Path(a.baseline),
                                           gate_args=a.gate_args.split())
            except Exception as exc:  # noqa: BLE001
                local[e["name"]] = {"name": e["name"], "error": str(exc)[:300]}
            print(f"  done {e['name']} [{repo.name}]", flush=True)
        return local

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(trees)) as pool:
        futs = [pool.submit(run_chunk, trees[i], chunks[i]) for i in range(len(trees))
                if chunks[i]]
        for fut in concurrent.futures.as_completed(futs):
            out.update(fut.result())

    # ---- report --------------------------------------------------------
    rows, regressions, false_positives, slips = [], [], [], []
    # ★v93 (owner 2026-09-07): "rejected by a hard gate", "sent to a human",
    # "blocked by an inapplicable-by-outcome box" and "errored" are different
    # facts (D22).  `false_positives` stays as their union for old readers.
    fp_hard, fp_escalate_only, fp_inapplicable, fp_error = [], [], [], []
    for e in entries:
        name = e["name"]
        s = out.get(name, {})
        passed = s.get("all_gates_passed")
        killed_by = s.get("killed_by")
        verdict = "SLIP" if passed else ("KILLED" if passed is False else "ERROR")
        first = e.get("first", {})
        if e.get("expect") == "control":
            status = "OK" if verdict == "SLIP" else "FALSE-POSITIVE"
            if status == "FALSE-POSITIVE":
                false_positives.append(name)
                hard = s.get("killed_by_hard")
                if hard is None:   # summaries from before v93 carry only `gates`
                    hard = [g for g, v in (s.get("gates") or {}).items()
                            if v is False and g.split("@")[0] not in ("check6", "check7")]
                if s.get("error"):
                    fp_error.append(name)
                elif hard:
                    fp_hard.append(name)
                elif s.get("inapplicable_by_outcome"):
                    fp_inapplicable.append(name)
                else:
                    fp_escalate_only.append(name)
        else:
            status = "OK" if verdict == "KILLED" else "SLIP"
            if verdict == "SLIP":
                slips.append(name)
            if first.get("verdict") == "KILLED" and verdict == "SLIP":
                status = "REGRESSION"
                regressions.append(name)
        rows.append({
            "name": name, "origin": e.get("origin"), "expect": e.get("expect"),
            "profile": s.get("profile"), "skipped_gates": s.get("skipped_gates"),
            "r5_n": s.get("r5_n"),
            "harm": e.get("harm", {}).get("escape"),
            "harm_n": e.get("harm", {}).get("n_escape"),
            "first_verdict": first.get("verdict"), "first_killed_by": first.get("killed_by"),
            "verdict": verdict, "killed_by": killed_by,
            "truth_F_fixed": s.get("truth_F_fixed"),
            "gates": s.get("gates"), "status": status, "wall_s": s.get("wall_s"),
            # v4: 検査6 and 検査7 both ESCALATE rather than FAIL, and the whole
            # point of adding 検査7 is to learn whether it is *redundant* with
            # 検査6.  Carry both verdicts so the overlap can be counted.
            "check6": s.get("check6"), "check7": s.get("check7"),
            "check7_flagged": s.get("check7_flagged"),
            "check8_divergent": s.get("check8_divergent"),
            # v6: one oracle per altitude of the anchor's call graph.  Carrying
            # the per-oracle verdicts is the only way to answer "what did the
            # height axis add", as opposed to "did the run go red".
            "check1_by_oracle": s.get("check1_by_oracle"),
            "check2_by_oracle": s.get("check2_by_oracle"),
            "killed_by_all": s.get("killed_by_all"),
            # ★v93
            "killed_by_hard": s.get("killed_by_hard"),
            "escalated_by": s.get("escalated_by"),
            "inapplicable_by_declaration": s.get("inapplicable_by_declaration"),
            "inapplicable_by_outcome": s.get("inapplicable_by_outcome"),
            "check4_v4_rule": s.get("check4_v4_rule"),
            "check4_survivors_reached": s.get("check4_survivors_reached"),
            "check4_survivors_unreached": s.get("check4_survivors_unreached"),
            "timing": s.get("timing"),
            "error": s.get("error"),
        })

    hdr = ("%-28s %-6s %-8s %-5s %-16s %-16s %s"
           % ("name", "origin", "expect", "harm", "first", "latest", "status"))
    print("\n" + hdr)
    print("-" * len(hdr))
    for r in rows:
        print("%-28s %-6s %-8s %-5s %-16s %-16s %s" % (
            r["name"], r["origin"] or "-", r["expect"] or "-",
            str(r["harm"]), f'{r["first_verdict"] or "-"}/{r["first_killed_by"] or "-"}',
            f'{r["verdict"]}/{r["killed_by"] or "-"}', r["status"]))

    n_attack = sum(1 for r in rows if r["expect"] == "attack")
    n_killed = sum(1 for r in rows if r["expect"] == "attack" and r["verdict"] == "KILLED")
    report = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "wall_s": round(time.time() - t0, 1),
        "n_entries": len(rows),
        "n_attacks": n_attack,
        "n_attacks_killed": n_killed,
        "profile": next((r["profile"] for r in rows if r.get("profile")), None),
        "gate_args": a.gate_args,
        "defence_rate": round(n_killed / n_attack, 3) if n_attack else None,
        "slips": slips,
        "regressions": regressions,
        "false_positives": false_positives,
        # ★v93: the union above, split by what actually stopped the control
        "false_positives_hard": fp_hard,
        "false_positives_escalate_only": fp_escalate_only,
        "false_positives_inapplicable_by_outcome": fp_inapplicable,
        "false_positives_error": fp_error,
        "rows": rows,
    }
    print(f"\ndefence: {n_killed}/{n_attack}   slips={slips}   "
          f"regressions={regressions}   false_positives={false_positives}"
          f"  [hard={fp_hard} escalate_only={fp_escalate_only} "
          f"inapplicable_by_outcome={fp_inapplicable} error={fp_error}]")
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(report, indent=1, ensure_ascii=False),
                                       encoding="utf-8")
        print("wrote", a.out)

    if a.update_index:
        by_name = {r["name"]: r for r in rows}
        for e in index["entries"]:
            r = by_name.get(e["name"])
            if not r:
                continue
            e["latest"] = {"label": a.label or "unlabelled",
                           "verdict": r["verdict"], "killed_by": r["killed_by"],
                           "gates": r["gates"], "truth_F_fixed": r["truth_F_fixed"],
                           "status": r["status"]}
            # an entry measured for the first time in this run gets its `first`
            if e.get("first", {}).get("verdict") is None:
                e["first"] = {"seen": a.label or "unlabelled",
                              "verdict": r["verdict"], "killed_by": r["killed_by"]}
        (corpus / "index.json").write_text(
            json.dumps(index, indent=1, ensure_ascii=False), encoding="utf-8")
        print("updated", corpus / "index.json")
    return 1 if (regressions or false_positives) else 0


if __name__ == "__main__":
    sys.exit(main())
