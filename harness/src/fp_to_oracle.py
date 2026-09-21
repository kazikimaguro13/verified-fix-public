"""fp_to_oracle.py -- turn a false positive into a concrete obligation on T.

THE RULE THIS MECHANISES (D14)
------------------------------
When a gate hard-rejects a *legitimate* fix, the answer is not to loosen the
gate.  It is to strengthen the oracle, because the gate is usually pointing at
something real: T is not pinning behaviour it ought to pin.  That has now
happened twice and both times strengthening T removed the false positive without
losing a single attack:

  v8   L1 / L3         検査4's surviving mutants named behaviour the oracle did
                       not fix; adding properties P7/P8 (132 lines, pure
                       addition) removed both false positives, 46/46 attacks
                       still killed.
  v13  mutatest        検査4 rejected the accepted fix over a surviving
                       `designator <= "."`.  It was right: the oracle only asked
                       that the two SPELLINGS agree, and under that mutant both
                       spellings move together.  A property saying a non-empty
                       designator is accepted whatever it sorts next to killed
                       the mutant; 検査1/2 still held.

WHY THIS IS NOT A PRINCIPLE-3 VIOLATION
---------------------------------------
原則3 forbids the agent tuning the gates from their own pass/fail signal.  This
does the opposite: it never touches a gate, and it never proposes loosening one.
It reads the gate's own witness and states what T would have to distinguish.
A human writes the property.  The loop is closed by compare_runs.py, which
confirms that the strengthened oracle did not cost any gate a kill.

  extraction   automatic   (this file)
  the property WRITTEN BY A HUMAN
  verification automatic   (compare_runs.py: no gate lost a kill)

WHAT IT REFUSES TO DO
---------------------
It will not emit "relax gate X".  If a false positive really is the gate's fault
-- an equivalent mutant, a transformation that is not meaning-preserving for the
anchor -- that is a change to the gate's *applicability*, decided by measurement
(D19's precondition), not by looking at one rejected patch.  Those cases are
reported as UNRESOLVED rather than dressed up as a proposal.

usage: fp_to_oracle.py <results_dir> [--corpus INDEX] [--json OUT] [--repo R]
"""

from __future__ import annotations

import json
import pathlib
import sys

ESCALATORS = {"check6", "check7"}


def controls(corpus: pathlib.Path) -> set:
    if not corpus or not corpus.exists():
        return set()
    d = json.loads(corpus.read_text(encoding="utf-8"))
    ents = d["entries"] if isinstance(d, dict) and "entries" in d else d
    if isinstance(ents, dict):
        ents = list(ents.values())
    return {e.get("name") for e in ents if e.get("expect") == "control"}


def post_images(results: pathlib.Path, name: str) -> dict:
    """Where the gates actually read the patched source from.

    MEASURED (v18): quoting the line from the repo working tree printed the
    wrong text -- a surviving mutant's line number refers to the POST IMAGE the
    gates ran, and the repo may be sitting on any commit by the time this is
    read.  run_gates3 writes the images beside the result as <name>.img/cfg.json,
    so that is the authority.
    """
    cfg = results / (name + ".img") / "cfg.json"
    if not cfg.exists():
        return {}
    try:
        return json.loads(cfg.read_text(encoding="utf-8")).get("post_images") or {}
    except Exception:                                           # noqa: BLE001
        return {}


def line_of(repo, rel: str, n, images: dict | None = None) -> str:
    if not rel or not n:
        return ""
    f = None
    if images and rel in images:
        f = pathlib.Path(images[rel])
    elif repo:
        f = pathlib.Path(repo) / rel
    if f is None or not f.exists():
        return ""
    try:
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[n - 1].strip() if 0 < n <= len(lines) else ""
    except Exception:                                           # noqa: BLE001
        return ""


# --------------------------------------------------------------------------- #
# per-gate witness readers.  Each returns a list of obligations on T.
# --------------------------------------------------------------------------- #
def from_check4(blk: dict, repo, images: dict | None = None) -> list:
    """Surviving mutants.  The single most productive source -- both recorded
    instances of this loop came from here."""
    out = []
    for s in (blk.get("survivors_reached") or []):
        rel, op = s.get("file"), s.get("operator", "")
        row = s.get("start_row")
        src = line_of(repo, rel, row, images)
        out.append({
            "gate": "check4",
            "witness": {"file": rel, "line": row, "operator": op,
                        "source_line": src,
                        "enclosing_stmt": s.get("enclosing_stmt")},
            "obligation": (
                "T must distinguish the original from the mutant produced by "
                "%s at %s:%s.  The oracle currently accepts both, so whatever "
                "that operator changes is behaviour T does not pin."
                % (op or "the operator", rel, row)),
            "how": (
                "Find an input on which the two differ and assert the original "
                "outcome.  For a comparison operator, that means an input that "
                "sits on the other side of the boundary: the mutant only "
                "survives because every input T tries lands on the same side."
                if "Comparison" in op or "Relational" in op else
                "Find an input on which the two differ and assert the original "
                "outcome."),
            "source_line": src,
        })
    # coverage-unknown survivors are a different problem: the gate could not
    # tell whether T reaches them, so it is not evidence about T's strength.
    for s in (blk.get("survivors_unreached") or []):
        if s.get("note"):
            out.append({
                "gate": "check4", "unresolved": True,
                "witness": {"file": s.get("file"), "line": s.get("start_row"),
                            "operator": s.get("operator"), "note": s.get("note")},
                "obligation": "NOT an obligation on T: the reachability filter "
                              "could not tell whether the oracle reaches this "
                              "line, so the survivor says nothing about T.",
            })
    return out


def from_check2(blk_by_oracle, res: dict) -> list:
    """The oracle did not pass after the fix.  For a control that means either
    the fix is wrong or the oracle asks for something the fix does not give --
    and only a human can say which, so this is reported, not proposed."""
    fails = [k for k, v in (blk_by_oracle or {}).items() if v is False]
    if not fails:
        return []
    return [{
        "gate": "check2", "unresolved": True,
        "witness": {"failing_oracles": fails},
        "obligation": "NOT an obligation on T: the oracle FAILED on an accepted "
                      "fix, so either the fix is wrong or the oracle demands "
                      "something outside the finding.  Read both before "
                      "touching either.",
    }]


def from_sweeps(name: str, blk: dict) -> list:
    """検査8 / 検査12 / 検査9 / 検査10 diverging on a CONTROL.

    A sweep firing on a legitimate fix is not a statement about T -- it is a
    statement about whether the relation holds for this anchor at all, which
    D19 says is decided by the pre-image precondition, not by one patch."""
    n = (blk.get("n_divergent_total") or blk.get("n_divergent_classes")
         or blk.get("n_divergent_probes") or blk.get("n_divergent_variants") or 0)
    if not n:
        return []
    return [{
        "gate": name, "unresolved": True,
        "witness": {"n_divergent": n,
                    "sample": (blk.get("classes") or blk.get("divergent")
                               or blk.get("samples"))},
        "obligation": "NOT an obligation on T: a sweep that fires on a correct "
                      "fix means its relation may not hold for this anchor. "
                      "That is an applicability question -- run the pre-image "
                      "precondition (D19), do not weaken the gate or the "
                      "oracle from this one patch.",
    }]


def from_suite_regression(res: dict) -> list:
    """The patch turned a previously-passing existing test red.

    MEASURED (v19, 実クライアント（Next.js／TS の業務ポータル）).  There is a case here that is neither D14 nor
    D19, and it has its own resolution, so it gets its own name.

    If the oracle was FALSIFIED by the pre-fix code and is SATISFIED by the
    patch, the patch implements the contract T encodes.  If the repository's own
    suite then goes red, two 層1 sources -- the contract the anchor documents,
    and a test that asserts the opposite -- disagree.  No gate can pick a
    winner, because both are the repository speaking about itself.

      not D14: T is not weak.  It is already correct and already passing.
      not D19: R4/R5 is not a sweeping gate; there is no relation to measure.

    What v19 measured is why this must be reported rather than resolved: the
    same source change passes freeze while the contradicting test is left alone
    (and R4/R5 then rejects it) and fails freeze once the test is corrected (and
    everything else then passes).  Byte for byte the same fix.  **There is no
    path through the gates until a human moves the baseline.**
    """
    reg = res.get("suite_regression") or {}
    n = reg.get("n_new_fail_max") or 0
    if not n:
        return []
    hard = {g.split("@")[0] for g, v in (res.get("gates") or {}).items()
            if v is False and g.split("@")[0] not in ESCALATORS}
    by_seed = reg.get("by_seed") or {}
    failing = sorted({t for v in by_seed.values() for t in (v or [])})
    t_falsified_before = res.get("check1_oracle_fails_on_bug") is True
    t_holds_after = all(v is not False
                        for v in (res.get("check2_by_oracle") or {}).values())
    rollback_ok = (res.get("gates") or {}).get("check3") is not False

    if hard <= {"R4", "R5"} and t_falsified_before and t_holds_after and rollback_ok:
        return [{
            "gate": "R4/R5", "contradiction": True,
            "witness": {"newly_failing_tests": failing[:8],
                        "n_new_fail": n,
                        "baseline_passing": reg.get("baseline_passing")},
            "obligation": (
                "CONTRADICTION, not a weak oracle: T was falsified by the "
                "pre-fix code and is satisfied by this patch, so the patch does "
                "implement the contract.  The repository's own suite asserts "
                "the opposite.  Both are the repository speaking about itself, "
                "and no gate can pick between them.  A human decides which is "
                "authoritative.  If the contract wins, change the contradicting "
                "test AS A BASELINE CHANGE (re-freeze), never inside the patch "
                "-- freeze cannot tell that edit from an attack, and will "
                "reject the correct fix for making it."),
        }]
    return [{
        "gate": "R4/R5", "unresolved": True,
        "witness": {"newly_failing_tests": failing[:8], "n_new_fail": n},
        "obligation": "NOT an obligation on T: the patch turned existing tests "
                      "red without T being clearly correct here.  Read the "
                      "failures; the fix is the likely culprit.",
    }]


def analyse(results: pathlib.Path, ctl: set, repo) -> dict:
    rows, skipped = [], []
    for f in sorted(results.glob("*.json")):
        if "." in f.stem:
            continue
        name = f.stem
        if ctl and name not in ctl:
            continue
        d = json.loads(f.read_text(encoding="utf-8"))
        gates = d.get("gates") or {}
        hard = [g for g, v in gates.items()
                if v is False and g.split("@")[0] not in ESCALATORS]
        if not hard:
            continue
        obligations = []
        truncated = None
        base = {g.split("@")[0] for g in hard}
        if "check4" in base:
            c4 = d.get("check4") or {}
            obligations += from_check4(c4, repo, post_images(results, name))
            # MEASURED (v40): 検査4 reported 22 surviving mutants on
            # S16_scrypt_cost and this tool emitted 12 obligations.  The gate
            # caps its witness list; the ten it dropped were not mentioned
            # anywhere, so the list of obligations handed to a human was
            # silently partial and D14's loop could not close in one round.
            # The gate now says so (mutgate.mjs `survivors_truncated`); carry
            # the mark through instead of re-hiding it here.
            if c4.get("survivors_truncated"):
                truncated = {"gate": "check4",
                             "n_reported": c4.get("n_survivors_reported"),
                             "n_total": c4.get("n_survivors_total")}
        if "check2" in base:
            obligations += from_check2(d.get("check2_by_oracle"), d)
        for g in ("check8", "check12", "check9", "check10", "check11"):
            if g in base:
                obligations += from_sweeps(g, d.get(g) or {})
        if base <= {"R4", "R5"} or "R4" in base or "R5" in base:
            obligations += from_suite_regression(d)
        if "check5" in base:
            b = d.get("check5") or {}
            if b.get("inapplicable"):
                obligations.append({
                    "gate": "check5", "unresolved": True,
                    "witness": {"compared_calls": 0},
                    "obligation": "NOT an obligation on T: the gate compared "
                                  "nothing (its input generator does not fit "
                                  "this anchor).  Fix the anchor spec.",
                })
            else:
                for s in (b.get("out_of_scope_sample") or [])[:4]:
                    obligations.append({
                        "gate": "check5",
                        "witness": {"call": s},
                        "obligation": "T must pin the behaviour that changed "
                                      "outside the anchor: pre and post "
                                      "disagree on a call the finding does not "
                                      "cover.",
                    })
        if not obligations:
            skipped.append({"name": name, "hard": hard,
                            "why": "the gate produced no witness to read"})
        rows.append({"name": name, "hard_killers": hard,
                     "obligations": obligations,
                     "witness_truncated": truncated})
    return {"false_positives": rows, "no_witness": skipped}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    results = pathlib.Path(sys.argv[1])

    def opt(f, d=None):
        return sys.argv[sys.argv.index(f) + 1] if f in sys.argv else d

    corpus = opt("--corpus")
    ctl = controls(pathlib.Path(corpus)) if corpus else set()
    repo = pathlib.Path(opt("--repo")) if opt("--repo") else None
    rep = analyse(results, ctl, repo)

    if opt("--json"):
        pathlib.Path(opt("--json")).write_text(
            json.dumps(rep, indent=1, ensure_ascii=False), encoding="utf-8")

    n = len(rep["false_positives"])
    print("results : %s" % results)
    print("controls: %s" % (("%d known" % len(ctl)) if ctl
                            else "no corpus given -- every entry is examined"))
    print("false positives (a control hard-rejected): %d" % n)
    print()
    for r in rep["false_positives"]:
        print("=== %s   rejected by %s ===" % (r["name"], ", ".join(r["hard_killers"])))
        t = r.get("witness_truncated")
        if t:
            miss = (t["n_total"] or 0) - (t["n_reported"] or 0)
            print("  [WITNESS TRUNCATED] %s listed %s of %s witnesses -- %d "
                  "obligation(s) below cannot be named this round.  Fill the "
                  "ones listed and re-run: the remainder are named once the "
                  "survivor count drops under the gate's cap.  Until then "
                  "this list is PARTIAL and the gate will still FAIL."
                  % (t["gate"], t["n_reported"], t["n_total"], miss))
            print()
        contra = [o for o in r["obligations"] if o.get("contradiction")]
        actionable = [o for o in r["obligations"]
                      if not o.get("unresolved") and not o.get("contradiction")]
        unresolved = [o for o in r["obligations"] if o.get("unresolved")]
        for o in contra:
            print("  [CONTRADICTION] %s" % o["obligation"])
            print("      tests   : %s" % ", ".join(o["witness"]["newly_failing_tests"]))
            print()
        for o in actionable:
            print("  [T-OBLIGATION] %s" % o["obligation"])
            if o.get("source_line"):
                print("      source: %s" % o["source_line"][:96])
            if o.get("how"):
                print("      how   : %s" % o["how"])
            print()
        for o in unresolved:
            print("  [UNRESOLVED]   %s" % o["obligation"])
            print("      witness: %s" % json.dumps(o["witness"], ensure_ascii=False)[:150])
            print()
        if not r["obligations"]:
            print("  (no witness in the gate's output -- nothing can be said)")
            print()
    print("Write the property yourself.  Then run compare_runs.py against the "
          "previous results: strengthening T is only correct if no gate lost a "
          "kill.  This tool never edits an oracle and never proposes loosening "
          "a gate (SKILL 原則3).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
