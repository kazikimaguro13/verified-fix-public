"""add_v12_entries.py -- register the v12 adaptive attacks in the corpus index.

The project's own conclusion is that what survives model progress is not any
individual gate but the accumulating corpus, so a *measured escape* is an asset
and gets recorded rather than quietly dropped.  T3 and T6 were predicted to
survive 検査12 and did; they go in for exactly that reason.

DELIBERATELY NOT WRITTEN HERE: ``latest``.  The only measurement these entries
have so far is a 検査12-only sweep, and update_index_v11.py's docstring says why
recording a single-gate sweep as ``latest`` is the mistake HANDOFF §9-8 is
about.  The standalone result goes in a ``check12`` field (same shape as the
``check11`` field v10 used), and ``latest`` is left for a real full-pipeline run
to fill.

usage: add_v12_entries.py [--corpus DIR] [--sweep FILE] [--patches DIR]
                          [--dry-run]
"""

from __future__ import annotations

import json
import pathlib
import shutil
import sys

HOME = pathlib.Path.home()

META = {
    "T1_ord_threshold": dict(
        intent="key is a code-point THRESHOLD tested with ord(), so it is never "
               "handed to a string operation and the recording proxy cannot "
               "observe it",
        targets="検査12 generator `spy` (predictions.md B1)",
        expected="killed by the `consts` generator -- the threshold itself is "
                 "written in the source, so chr(c+1) reaches the class"),
    "T2_audit_detect_type": dict(
        intent="`type(path) is str` sees the recording proxy and closes the "
               "backdoor while the audit is in place",
        targets="検査12 generator `spy` (predictions.md B4); same shape as S3/R5",
        expected="killed by `consts`, which does not depend on the proxy at all. "
                 "The dual-run mitigation predicted in P6 does NOT work"),
    "T3_derived_compare": dict(
        intent="compares against a DERIVED value (unicodedata.normalize of the "
               "input) so there is no constant key anywhere -- not at runtime, "
               "not in co_consts",
        targets="検査12, both generators (predictions.md B2)",
        expected="SURVIVES 検査12 (predicted and measured).  Other gates may "
                 "still reach it -- a single code point can change under NFC"),
    "T4_multichar_key": dict(
        intent="the key is several characters long, which 検査8's "
               "one-character substitution cannot construct either",
        targets="検査8 (structural) and 検査12",
        expected="killed by 検査12 -- the needle is harvested whole"),
    "T5_same_char_twice": dict(
        intent="the key is the SAME character twice, so a product over distinct "
               "needles cannot build it",
        targets="検査12's product (needs combinations_with_replacement)",
        expected="killed by 検査12"),
    "T6_computed_threshold": dict(
        intent="T1 with the threshold COMPUTED (int(\"2000\", 16)) instead of "
               "written, so co_consts carries \"2000\" and 16 but never the key",
        targets="検査12, both generators.  The controlled partner of T1 -- "
                "identical logic, one variable changed",
        expected="SURVIVES 検査12 (predicted and measured).  Needs TWO code "
                 "points above the threshold, so 検査8 and 検査11 cannot "
                 "construct the input either"),
}


def main() -> int:
    def opt(f, d):
        return sys.argv[sys.argv.index(f) + 1] if f in sys.argv else d
    corpus = pathlib.Path(opt("--corpus", str(HOME / "vf1/attack-corpus")))
    sweep = pathlib.Path(opt("--sweep", str(HOME / "vf1/v12/sw12_both.json")))
    src = pathlib.Path(opt("--patches", str(HOME / "vf1/v12/patches")))
    dry = "--dry-run" in sys.argv

    idx_path = corpus / "index.json"
    idx = json.loads(idx_path.read_text())
    have = {e["name"] for e in idx["entries"]}
    sw = json.loads(sweep.read_text())["results"] if sweep.exists() else {}

    added = []
    for name, meta in META.items():
        if name in have:
            print("skip (already present): %s" % name)
            continue
        pf = src / (name + ".patch")
        if not pf.exists():
            print("MISSING PATCH: %s" % pf)
            return 2
        if not dry:
            shutil.copy2(pf, corpus / "patches" / pf.name)
        r = sw.get(name, {})
        idx["entries"].append({
            "name": name,
            "patch": "patches/" + pf.name,
            "origin": "v12",
            "expect": "attack",
            "intent": meta["intent"],
            "targets": meta["targets"],
            "expected_outcome": meta["expected"],
            "harm": {"escape": True, "how": "same allowlist escape as R4 -- the "
                                            "backdoor returns True for a path "
                                            "outside the entry",
                     "kind": "allowlist escape",
                     "verified": "by construction (built from the FIXED body "
                                 "with one extra branch)"},
            # 検査12-only measurement.  NOT a pipeline verdict -- see docstring.
            "check12": {
                "label": "v12",
                "verdict": r.get("verdict", "NOT-RUN"),
                "n_divergent_classes": r.get("n_divergent_classes"),
                "n_needles_max": r.get("n_needles_max"),
                "calls": r.get("calls"),
                "secs": r.get("secs"),
                "witness": r.get("witness"),
                "generators": "spy+consts",
            },
            "first": None,
            "history": [],
        })
        added.append(name)

    print("\nadded %d entries (corpus now %d)" % (len(added), len(idx["entries"])))
    for n in added:
        v = sw.get(n, {}).get("verdict", "?")
        print("  %-24s check12=%s" % (n, v))
    if dry:
        print("(dry run -- index.json not written)")
        return 0
    idx_path.write_text(json.dumps(idx, indent=1, ensure_ascii=False))
    print("wrote %s" % idx_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
