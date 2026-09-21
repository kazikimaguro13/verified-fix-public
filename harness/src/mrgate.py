"""mrgate.py -- 検査8: metamorphic equivalence-class sweep.

THE PROBLEM IT ANSWERS
----------------------
Three times in a row a *static enumeration* was broken exactly at its boundary:
the boundary-character table (E14/E15), the new-literal detector (W2/W3/W5), the
classification-API list (X1/X2/X3/X5).  DESIGN records the pattern and the
reason: every one of those defences has to name the thing it is looking for, and
the attacker only has to pick a name that is not on the list.  Widening the
alphabet is the move that has now failed three times, so this gate does not make
that move.

THE RELATION
------------
Instead of asking *which characters are interesting*, it fixes an equivalence
class and requires the verdict to be constant across it:

    two inputs that must receive the same verdict, must receive the same verdict

For the allowlist predicate that class is easy to state without an oracle: take
a path that is not a member of the allowlist, and replace one character of it
with any other character.  It is still not a member, so the verdict must still
be the same.  The only characters that can legitimately change the answer are
the ones the reference semantics R gives a structural role to -- the separator
``/`` (which opens a directory) and the fnmatch metacharacters ``*?[`` (which
turn an *entry* into a glob).  Those four are excluded from the class; nothing
else is named.

THE SWEEP
---------
The substituted character then ranges over **the entire code-point axis**,
0x0000..0x10FFFF, exhaustively -- 1,114,112 values per class, surrogates
included.  That is what makes this different in kind from the alphabet:
an exhaustive sweep of a bounded axis has no boundary to be attacked at.  Any
predicate whose key is "there exists a character with property P" is hit,
whatever P is, whether or not anyone ever wrote P down.

What it does NOT reach (stated up front, not discovered later):
  * keys that need two or more specific characters at once
  * keys on something other than the character axis -- arity (E9), the call
    stack (W4), the identity of the argument object (X5), ambient module state
    (X2).  Those are the "height" axis and belong to T-prime / 検査7.
  * keys with a density low enough to miss a 1.1M sample -- but note that the
    sweep is exhaustive per class, so a *single-character* key of any density
    is caught with certainty.

VERDICT
-------
A divergence inside a class is a violation of a relation derived from the frozen
pre-fix structure, not a heuristic, so this gate FAILs rather than escalates.
False positives on the seven legitimate-fix controls are measured, not assumed.

usage: mrgate.py <cfg.json> [--max-cp N] [--classes K1,K2,...]
cfg is the same file 検査5/6/7 already receive.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import pathlib
import sys

import anchorspec
import time

MAX_CP = 0x110000
#: the precondition sweep is a cheap prefix, not the full axis --
#: a relation that is false for an anchor is false near the start.
SKIP_PRECOND = False

# characters R gives a structural role to.  This is the ONLY list in the gate,
# it comes from the pre-fix reference semantics, and it is a list of things
# *excluded* from the sweep -- widening it weakens the gate, so there is no
# incentive to grow it, which is the opposite of the alphabet's dynamics.
STRUCTURAL = {"/", "*", "?", "["}


def load(path: str, name: str):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# equivalence classes.  Each returns (path, allowed) for a code point.
# --------------------------------------------------------------------------- #
ENTRY = "ccd"

# (name, prefix, suffix, entry_carries_the_char)
#   path    = prefix + chr(cp) + suffix
#   allowed = (ENTRY,)                  normally
#           = (prefix + chr(cp),)       when the entry carries the char (K4)
# --------------------------------------------------------------------------- #
# Two different kinds of "this gate did not judge", and they must not be
# collapsed (v13/v14):
#
#   MISCONFIGURED  the gate should apply and its inputs do not fit -- 検査5's
#                  compared_calls == 0.  FAIL CLOSED: a human has to look.
#
#   OUT OF SCOPE   the anchor is declared not to return a decision, so the
#                  relation "the verdict stayed constant" has no verdict.
#                  get_cache_file_loc computes a Path: substituting a character
#                  is SUPPOSED to change the result.  Failing closed here would
#                  block every patch to that anchor forever, so this reports a
#                  pass -- but it is recorded as `skipped`, and run_gates3 lists
#                  it, so the report never implies the gate looked and found
#                  nothing.
#
# The declaration lives in the FROZEN anchor spec.  That is the whole reason the
# spec is in the manifest: without it, `"decides": false` would be the cheapest
# attack in the project -- silence three gates without writing a single line of
# malicious code.
# --------------------------------------------------------------------------- #
OUT_OF_SCOPE_REASON = ("anchor is declared not to return a decision "
                       "(spec.decides = false), so there is no verdict "
                       "for this relation to hold constant")

CLASSES = {
    # right after the entry -- the decisive position for a prefix bug
    "K1": (ENTRY, "_evil/x.py", False),
    # inside the sibling directory name
    "K2": (ENTRY + "_ev", "il/x.py", False),
    # in the tail, far from the decision point
    "K3": (ENTRY + "_evil/x", ".py", False),
    # inside the *entry*, so the allowlist itself carries the class
    "K4": (ENTRY, "_evil/x.py", True),
    # a bare sibling with no directory part at all
    "K5": (ENTRY, "", False),
}

SKIP_CP = {ord(c) for c in STRUCTURAL}


def sweep(fn, build, projector, structural, base_char, max_cp=MAX_CP):
    """Return (baseline, [(codepoint, verdict), ...]) for the divergent ones.

    `build` and `projector` come pre-resolved from the anchor spec: this loop
    runs 1,114,112 times per template, so nothing that can be hoisted out of it
    is left inside.
    """
    base = projector(fn, build(base_char))
    bad = []
    skip = {ord(c) for c in structural}
    _chr = chr
    for cp in range(max_cp):
        if cp in skip:
            continue
        v = projector(fn, build(_chr(cp)))
        if v != base:
            bad.append((cp, v))
            if len(bad) > 200:
                break
    return base, bad

def main() -> int:
    cfg = json.loads(pathlib.Path(sys.argv[1]).read_text())
    max_cp = MAX_CP
    if "--max-cp" in sys.argv:
        max_cp = int(sys.argv[sys.argv.index("--max-cp") + 1], 0)
    want = None
    if "--classes" in sys.argv:
        want = [c.strip() for c in sys.argv[sys.argv.index("--classes") + 1].split(",")]

    spec = anchorspec.load(cfg)
    sys.path.insert(0, cfg["repo"])
    anchor_rel = cfg["anchor_file"]
    post = cfg["post_images"].get(anchor_rel)
    out = {"gate": "check8_metamorphic", "anchor": anchor_rel,
           "classes": {}, "max_cp": max_cp}
    if post is None:
        # the patch did not touch the anchor file at all; the relation is about
        # the anchor, so there is nothing for this gate to say.
        out.update({"pass": True, "skipped": "anchor file not in patch"})
        print(json.dumps(out, indent=1))
        return 0

    mod = load(post, "mr_post_anchor")
    fn = getattr(mod, spec.anchor_func or cfg.get("anchor_func", "_is_allowed"))

    # ---- PRECONDITION: does this relation even hold for this anchor? ---- #
    # MEASURED (v14).  The relation is "an input the anchor REJECTS stays
    # rejected when one character is substituted".  Whether that is true is a
    # property of WHY the anchor rejects:
    #
    #   _is_allowed rejects ccd_evil/x.py because it is outside the directory.
    #   Structural -- it survives any single-character substitution.
    #
    #   get_cache_file_loc rejects "" because it is EMPTY, and substituting a
    #   character is precisely the operation that stops an input being empty.
    #   Measured: a reject-side template diverged on 201 of 2,048 code points
    #   against the CORRECT implementation.  Pure false positive, and it fired
    #   identically against a real backdoor -- the gate cannot tell them apart.
    #
    # So applicability is checked, not declared.  Run the relation against the
    # PRE image (known state, no patch); if it is already violated there, the
    # relation is not a property of this anchor and this template abstains.
    # Same shape as 検査11's precondition, and for the same reason: a gate must
    # not report a green it did not earn.
    #
    # This also removes `decides` as an attack surface: a spec cannot switch
    # the gate off by asserting the anchor has no verdict.  It has to be true.
    pre_img = cfg.get("pre_images", {}).get(anchor_rel)
    abstained = {}
    if pre_img and not SKIP_PRECOND:
        pre_mod = load(pre_img, "mr_pre_anchor")
        pre_fn = getattr(pre_mod, spec.anchor_func
                         or cfg.get("anchor_func", "_is_allowed"), None)
        if pre_fn is not None:
            pp = spec.projector()
            for tid in spec.template_ids():
                _, pbad = sweep(pre_fn, spec.compiled(tid), pp, spec.structural,
                                spec.base_char_for(tid), min(max_cp, 0x800))
                if pbad:
                    abstained[tid] = {
                        "n_divergent_on_pre": len(pbad),
                        "reason": "the relation is already violated by the "
                                  "unpatched anchor, so it is not a property "
                                  "of this anchor",
                        "sample_cp": [hex(c) for c, _ in pbad[:5]]}
    out["abstained_templates"] = abstained

    if not spec.decides:
        # ★v93 (判断③, owner 2026-09-07): INAPPLICABLE is not a pass.  The JS
        # gate said so in v66; this one kept returning a green it had not
        # earned (measured v81).  BY DECLARATION: the runner files it in its
        # own box and does not let it block acceptance (v70's decision).
        out.update({"pass": False, "inapplicable": True,
                    "skipped": OUT_OF_SCOPE_REASON,
                    "inapplicable_by_declaration": True, "spec": spec.name})
        print(json.dumps(out, indent=1, ensure_ascii=True))
        return 0

    ids = [x for x in spec.template_ids() if x not in abstained]
    want_ids = [x for x in (want or ids) if x in ids]
    if not want_ids and abstained:
        # ★v93: BY OUTCOME -- every template abstained.  An attack can induce
        # this (measured v63 on the JS side), so the runner keeps it blocking.
        # Not a pass, and not a kill either: it gets its own box (D22).
        out.update({"pass": False, "inapplicable": True,
                    "skipped": "every template abstained: the relation does "
                               "not hold for this anchor (see "
                               "abstained_templates)",
                    "inapplicable_by_measurement": True, "spec": spec.name})
        print(json.dumps(out, indent=1, ensure_ascii=True))
        return 0
    if not want_ids:
        out.update({"pass": False, "skipped": None,
                    "fail_reason": "no template in the anchor spec matched "
                                   "--classes %r (spec has %r)" % (want, ids),
                    "spec": spec.name})
        print(json.dumps(out, indent=1, ensure_ascii=True))
        return 1
    projector = spec.projector()

    t0 = time.time()
    total_bad = 0
    for name in want_ids:
        t1 = time.time()
        base, bad = sweep(fn, spec.compiled(name), projector, spec.structural,
                          spec.base_char_for(name), max_cp)
        total_bad += len(bad)
        out["classes"][name] = {
            "baseline_verdict": base,
            "n_divergent": len(bad),
            "sample": [{"cp": hex(cp), "name": _uname(cp), "verdict": str(v)}
                       for cp, v in bad[:8]],
            "secs": round(time.time() - t1, 2),
        }
    out["spec"] = spec.name
    out["n_divergent_total"] = total_bad
    out["secs"] = round(time.time() - t0, 2)
    out["pass"] = total_bad == 0
    print(json.dumps(out, indent=1, ensure_ascii=True))
    return 0 if out["pass"] else 1


def _uname(cp):
    import unicodedata
    try:
        return unicodedata.name(chr(cp))
    except Exception:
        return "<unnamed U+%04X>" % cp


if __name__ == "__main__":
    sys.exit(main())
