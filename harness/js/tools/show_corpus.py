# -*- coding: utf-8 -*-
"""show_corpus.py -- read harness/js/corpus/index.json in one line per variant.

★THIS IS NOT A GATE.  No number, not wired into run_gates.mjs, never part of a
  pass/fail decision.  It runs nothing and measures nothing: it prints records
  that already exist.  Changing it cannot change any verdict.

  python3 show_corpus.py              every variant, one line each
  python3 show_corpus.py --slips      attacks whose latest run has
                                      all_gates_passed == true  (kind=attack
                                      only -- N3_fixed_fields_first is
                                      kind=not_an_attack and is NOT a slip)
  python3 show_corpus.py --stale      variants whose `latest` could not be
                                      pulled from any raw file
  python3 show_corpus.py --counts     the counts only

⚠ A variant with no verdict is NOT a variant that passed.  --stale and --slips
  are different questions and this tool never merges them.
⚠ This answers "how was each variant last judged".  It does NOT answer "is each
  gate still doing work" -- a gate can lose kills while every verdict here stays
  identical (HANDOFF §0-d, measured in v14).  For that, run
  src/compare_runs.py over two result directories.
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.abspath(os.path.join(HERE, "..", "corpus", "index.json"))


def load():
    with io.open(INDEX, encoding="utf-8") as f:
        return json.load(f)


def line(e):
    lat = e["latest"]
    if lat is None:
        verd = "NO-RECORD"
        detail = "latest could not be pulled"
        where = "-"
    else:
        verd = lat["verdict"]
        bits = []
        if lat["killed_by_all"]:
            bits.append("killed_by_all=" + ",".join(lat["killed_by_all"]))
        if lat["errored_gates"]:
            bits.append("COULD-NOT-RUN=" + ",".join(lat["errored_gates"]))
        if lat.get("inapplicable_gates"):
            bits.append("N/A=" + ",".join(lat["inapplicable_gates"]))
        if lat["escalated"]:
            bits.append("escalated=" + ",".join(lat["escalated"]))
        detail = "  ".join(bits) or "no gate objected"
        where = "%s/%s" % (lat["round"], lat["profile"])
    return "%-24s %-14s %-10s %-19s %s" % (e["name"], e["kind"], where, verd, detail)


def main(argv):
    doc = load()
    entries = doc["entries"]
    args = set(argv[1:])

    if args - {"--slips", "--stale", "--counts"}:
        sys.stderr.write(__doc__)
        return 2

    if "--slips" in args:
        sel = [e for e in entries
               if e["kind"] == "attack" and e["latest"]
               and e["latest"]["all_gates_passed"] is True]
        print("# attacks whose latest recorded run passed every gate that ran")
        print("# (kind=attack only; not_an_attack entries are excluded by "
              "definition, not by filtering an inconvenient row away)")
        for e in sel:
            print(line(e))
            if e.get("notes"):
                print("    " + e["notes"])
        print("# %d slip(s)" % len(sel))
        blind = [e for e in entries if e["kind"] == "attack" and not e["latest"]]
        if blind:
            print("# ⚠ %d attack(s) have no pullable verdict at all and are "
                  "NOT counted above: %s  (see --stale)"
                  % (len(blind), ", ".join(e["name"] for e in blind)))
        return 0

    if "--stale" in args:
        sel = [e for e in entries if not e["latest"]]
        print("# variants whose latest verdict could not be pulled from any raw file")
        for e in sel:
            print(line(e))
            print("    why_null: " + (e.get("why_null") or "-"))
            if e["prose_sources"]:
                print("    prose only: " + ", ".join(
                    os.path.basename(p) for p in e["prose_sources"]))
        print("# %d of %d entries" % (len(sel), len(entries)))
        return 0

    if "--counts" not in args:
        for e in entries:
            print(line(e))
            if e.get("caveat"):
                print("    " + e["caveat"])

    kinds = {}
    for e in entries:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    got = [e for e in entries if e["latest"]]
    hist = [e for e in entries if e["history"]]
    slips = [e for e in entries if e["kind"] == "attack" and e["latest"]
             and e["latest"]["all_gates_passed"] is True]
    esc = [e for e in entries if e["kind"] == "attack" and e["latest"]
           and e["latest"]["verdict"] == "accepted_escalated"]
    killed = [e for e in entries if e["kind"] == "attack" and e["latest"]
              and e["latest"]["verdict"] in ("rejected_hard", "could_not_run")]
    print("")
    print("entries          : %d  (%s)" % (
        len(entries), " / ".join("%s %d" % (k, kinds[k]) for k in sorted(kinds))))
    print("latest pulled    : %d    latest NOT pullable: %d  (--stale)"
          % (len(got), len(entries) - len(got)))
    print("history pulled   : %d" % len(hist))
    print("attacks with a verdict: %d  ->  rejected %d / accepted-with-flag %d "
          "/ SLIP %d" % (len(killed) + len(esc) + len(slips), len(killed),
                         len(esc), len(slips)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
