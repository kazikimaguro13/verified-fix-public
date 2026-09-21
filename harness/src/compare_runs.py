"""compare_runs.py -- diff two corpus runs by WHO killed each entry.

WHY THIS EXISTS
---------------
The corpus report answers "was anything accepted that should not have been".
That is not the same question as "is every gate still working", and v14 measured
the gap: porting 検査9 to the anchor spec broke two of its axes, and the report
still said

    coverage 72/72   defence 63/63   slips []   FP hard []   regressions: []

because the two entries that axis used to kill -- W4_caller_frame and
Y1a_caller_alt2_seam -- were still killed by check2 and R5.  The suite's
verdict was unchanged; one gate had simply stopped contributing.

A gate can only be seen to stop working by comparing WHO killed each entry, so
that comparison should not be an ad-hoc script written after someone gets
suspicious.  Losses are what matter: a killer that disappeared is a gate that
regressed, even when the entry is still rejected.

usage: compare_runs.py <old_results_dir> <new_results_dir> [--json OUT]

Both directories are the per-entry `results_<profile>/` written by
run_corpus_v11.py (or `work_<profile>/`, which carries the same `gates` map).
"""

from __future__ import annotations

import json
import pathlib
import sys

ESCALATE_ONLY = {"check6", "check7"}


def hard_killers(path: pathlib.Path) -> set:
    d = json.loads(path.read_text(encoding="utf-8"))
    gates = d.get("gates") or {}
    return {k for k, v in gates.items()
            if v is False and k.split("@")[0] not in ESCALATE_ONLY}


def gate_names(killers: set) -> set:
    """Collapse check2@alt0/alt1/alt2 into check2 -- losing one oracle of three
    is a different event from losing the gate, and both are worth seeing."""
    return {k.split("@")[0] for k in killers}


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    old_dir, new_dir = (pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
    out_path = None
    if "--json" in sys.argv:
        out_path = pathlib.Path(sys.argv[sys.argv.index("--json") + 1])

    rows, lost, gained, only_new, only_old = [], [], [], [], []
    for f in sorted(new_dir.glob("*.json")):
        if "." in f.stem:                       # per-oracle side files
            continue
        o = old_dir / f.name
        if not o.exists():
            only_new.append(f.stem)
            continue
        a, b = hard_killers(o), hard_killers(f)
        if a == b:
            continue
        rows.append({"entry": f.stem, "old": sorted(a), "new": sorted(b),
                     "lost": sorted(a - b), "gained": sorted(b - a)})
        for g in gate_names(a) - gate_names(b):
            lost.append((f.stem, g))
        for g in gate_names(b) - gate_names(a):
            gained.append((f.stem, g))
    for f in sorted(old_dir.glob("*.json")):
        if "." not in f.stem and not (new_dir / f.name).exists():
            only_old.append(f.stem)

    # which gates lost ground, and on how many entries
    by_gate: dict = {}
    for entry, g in lost:
        by_gate.setdefault(g, []).append(entry)

    print("old: %s" % old_dir)
    print("new: %s" % new_dir)
    print()
    print("entries with a different killer set : %d" % len(rows))
    print("entries only in new                 : %s" % (only_new or "-"))
    print("entries only in old                 : %s" % (only_old or "-"))
    print()
    if by_gate:
        print("*** GATES THAT LOST KILLS (a gate stopped contributing) ***")
        for g, entries in sorted(by_gate.items(), key=lambda x: -len(x[1])):
            print("  %-12s lost %d: %s" % (g, len(entries), ", ".join(entries[:6])))
    else:
        print("no gate lost a kill")
    print()
    for r in rows[:25]:
        print("  %-28s -%s  +%s" % (r["entry"], r["lost"] or "[]",
                                    r["gained"] or "[]"))
    if len(rows) > 25:
        print("  ... %d more" % (len(rows) - 25))

    report = {"old": str(old_dir), "new": str(new_dir),
              "n_changed": len(rows), "rows": rows,
              "gates_that_lost_kills": by_gate,
              "only_in_new": only_new, "only_in_old": only_old}
    if out_path:
        out_path.write_text(json.dumps(report, indent=1, ensure_ascii=False))
        print("\nwrote %s" % out_path)
    # a lost kill is a regression even when the corpus verdict is unchanged
    return 1 if by_gate else 0


if __name__ == "__main__":
    sys.exit(main())
