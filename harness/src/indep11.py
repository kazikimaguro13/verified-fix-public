"""indep11.py -- Step 3 of v10: is the reference set actually INDEPENDENT?

"E14 died when I plugged in a reference" is not evidence that the reference is
independent.  Four separate things could be doing the work and only one of them
is the claim:

  (a) the exhaustive code-point axis (検査8 already has that)
  (b) a verdict function that happens to be correct
  (c) three verdict functions that are correct *for unrelated reasons*
  (d) tuning the references until they agreed with the implementation

This script measures each one.

  probe    -- do the references answer correctly at code points that appear
              in NO table in this project (U+0308, U+E0041, U+0435, a random
              sample of unassigned and astral code points)?
  shape    -- how many code points do the references treat specially at all?
              A table-driven reference has many; a structural one has ~1.
  monolith -- rerun the whole differential with ONE verdict function, the one
              this project already wrote (truth_v2.ref_is_allowed), over the
              same exhaustive axis.  If that kills the same attacks, the axis
              is doing the work and independence is buying something else.
  overlap  -- do the references and the project's own oracle/ground-truth ever
              make the SAME mistake on the same input?

usage: indep11.py <mode> [args]
       indep11.py probe
       indep11.py shape
       indep11.py monolith <sweep11.json>      (reads the per-entry cfgs)
       indep11.py overlap
"""

from __future__ import annotations

import json
import pathlib
import random
import sys
import unicodedata

HOME = pathlib.Path.home()
SRC = HOME / "vf1/src"
sys.path.insert(0, str(SRC))

import refgate  # noqa: E402

WORK = HOME / "vf1/v10/sweep11"


def load_truth_verdict():
    """truth_v2.ref_is_allowed -- THIS project's own reading of the contract."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "truth_v2_probe", str(SRC / "truth_v2.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ref_is_allowed


# --------------------------------------------------------------------------- #
def mode_probe():
    """The references must be right where every table in this project is blind."""
    refs = refgate.Refs({'slash'})
    named = {
        0x0308: "E14 key (COMBINING DIAERESIS)",
        0xE0041: "E15 key (TAG LATIN CAPITAL LETTER A)",
        0x0435: "E13 key (CYRILLIC SMALL LETTER IE)",
        0x1F600: "in truth_v2's UNI table (control)",
        0x0441: "in truth_v2's UNI table (control)",
    }
    rnd = random.Random(11)
    sample = set(named)
    while len(sample) < 405:
        sample.add(rnd.randrange(0x110000))
    rows, wrong = [], []
    for cp in sorted(sample):
        ch = chr(cp)
        if ch == '/':
            continue
        # sibling: "ccd<ch>_evil/x.py" is NOT inside "ccd"
        v1, votes1 = refs.consensus("ccd" + ch + "_evil/x.py", ("ccd",))
        # child:   "ccd/<ch>x.py"      IS inside "ccd"
        v2, votes2 = refs.consensus("ccd/" + ch + "x.py", ("ccd",))
        ok = (v1 is False) and (v2 is True)
        if not ok:
            wrong.append({"cp": hex(cp), "sibling": str(v1), "child": str(v2),
                          "votes_sibling": {k: str(x) for k, x in votes1.items()},
                          "votes_child": {k: str(x) for k, x in votes2.items()}})
        if cp in named:
            rows.append({"cp": hex(cp), "why": named[cp],
                         "sibling_verdict": str(v1), "child_verdict": str(v2),
                         "correct": ok})
    out = {"mode": "probe", "n_sampled": len(sample),
           "named": rows, "n_wrong": len(wrong), "wrong": wrong[:10],
           "conclusion": ("references are structurally correct at every sampled "
                          "code point, including ones no table in this project "
                          "contains") if not wrong else "SOME CODE POINTS WRONG"}
    print(json.dumps(out, indent=1, ensure_ascii=True))


def mode_shape():
    """How much of the code-point axis do the references treat specially?"""
    refs = refgate.Refs({'slash'})
    pre = refgate.load_flat(str(WORK / "00_correct/pre/ccd/guard_pathmatch.py"),
                            "ip_pre")
    norm = (lambda al: tuple(pre._normalize_allowed(al)))
    out = {"mode": "shape", "classes": {}}
    for name, spec in refgate.CLASSES.items():
        ts, ab = refgate.build_ref_map(refs, spec, 0x110000, norm)
        out["classes"][name] = {
            "n_true": len(ts), "n_abstain": len(ab),
            "true_cps": [(hex(c), _nm(c)) for c in sorted(ts)[:12]],
            "abstain_cps": [(hex(c), _nm(c)) for c in sorted(ab)[:12]],
        }
    tv = load_truth_verdict()
    # the same question, asked of THIS project's own verdict function
    out["truth_v2_verdict_fn"] = {}
    for name, spec in refgate.CLASSES.items():
        pre_s, suf, carries = spec
        t = set()
        for cp in range(0x110000):
            ch = chr(cp)
            p = pre_s + ch + suf
            a = norm((pre_s + ch,)) if carries else norm(("ccd",))
            if tv(p, a):
                t.add(cp)
        out["truth_v2_verdict_fn"][name] = {
            "n_true": len(t), "true_cps": [(hex(c), _nm(c)) for c in sorted(t)[:12]]}
    print(json.dumps(out, indent=1, ensure_ascii=True))


def _nm(cp):
    try:
        return unicodedata.name(chr(cp))
    except Exception:
        return "<unnamed U+%04X>" % cp


def mode_monolith():
    """Same axis, ONE verdict function -- the one this project already wrote.

    If this kills the same set, the exhaustive axis is doing the work and the
    three independent references are buying something other than these kills.
    """
    global MONO_MAP
    tv = load_truth_verdict()
    index = json.loads((HOME / "vf1/attack-corpus/index.json")
                       .read_text(encoding="utf-8"))
    pre0 = refgate.load_flat(
        str(WORK / "00_correct/pre/ccd/guard_pathmatch.py"), "mn_pre0")
    norm0 = (lambda al: tuple(pre0._normalize_allowed(al)))
    mm = HOME / "vf1/v10/mono_map.json"
    if mm.exists():
        MONO_MAP = {k: set(v) for k, v in json.loads(mm.read_text()).items()}
    else:
        MONO_MAP = {}
        for cname, spec in refgate.CLASSES.items():
            pre_s, suf, carries = spec
            t = set()
            fixed = norm0(("ccd",))
            for cp in range(0x110000):
                ch = chr(cp)
                a = norm0((pre_s + ch,)) if carries else fixed
                if tv(pre_s + ch + suf, a):
                    t.add(cp)
            MONO_MAP[cname] = t
            print("  mono map %s: %d true" % (cname, len(t)), file=sys.stderr)
        mm.write_text(json.dumps({k: sorted(v) for k, v in MONO_MAP.items()}))
    rows = {}
    for e in index["entries"]:
        name = e["name"]
        cfgf = WORK / name / "cfg.json"
        if not cfgf.exists():
            continue
        cfg = json.loads(cfgf.read_text())
        post = cfg["post_images"].get("ccd/guard_pathmatch.py")
        pre = cfg["pre_images"].get("ccd/guard_pathmatch.py")
        if not post:
            rows[name] = {"skipped": "anchor not in patch"}
            continue
        try:
            pm = refgate.load_flat(pre, "mn_pre_" + name)
            norm = (lambda al, _f=pm._normalize_allowed: tuple(_f(al)))
            mod = refgate.load_flat(post, "mn_" + name)
            fn = getattr(mod, "_is_allowed")
        except Exception as exc:
            rows[name] = {"error": repr(exc)}
            continue
        # ---- monolithic reference: truth_v2's own verdict fn, same axis ----
        # tv is a pure function of gate constants, so its map over the axis is
        # precomputed once (same trick refgate uses for the three references).
        mono_div = 0
        mono_wit = None
        for cname, spec in refgate.CLASSES.items():
            pre_s, suf, carries = spec
            tset = MONO_MAP[cname]
            fixed = norm(("ccd",))
            for cp in range(0x110000):
                ch = chr(cp)
                p = pre_s + ch + suf
                a = norm((pre_s + ch,)) if carries else fixed
                try:
                    got = bool(fn(p, a))
                except Exception:
                    got = "EXC"
                want = cp in tset
                if got != want:
                    mono_div += 1
                    if mono_wit is None:
                        mono_wit = {"class": cname, "cp": hex(cp),
                                    "name": _nm(cp), "impl": str(got),
                                    "ref": want}
                    if mono_div > 400:
                        break
            if mono_div > 400:
                break
        rows[name] = {"expect": e.get("expect"), "mono_divergent": mono_div,
                      "mono_pass": mono_div == 0, "witness": mono_wit}
        print("  %-28s mono_div=%s" % (name, mono_div), file=sys.stderr)
    pathlib.Path(HOME / "vf1/v10/monolith11.json").write_text(
        json.dumps(rows, indent=1))
    att = [n for n, r in rows.items() if r.get("expect") == "attack"
           and r.get("mono_pass") is False]
    ctl = [n for n, r in rows.items() if r.get("expect") == "control"
           and r.get("mono_pass") is False]
    print(json.dumps({"mode": "monolith", "killed_attacks": sorted(att),
                      "n_killed": len(att), "false_positives": sorted(ctl)},
                     indent=1))


def mode_overlap():
    """Do the references and this project's own verdict function ever agree
    on a WRONG answer?  Sweep both over the whole axis and diff them."""
    tv = load_truth_verdict()
    refs = refgate.Refs({'slash'})
    pre = refgate.load_flat(str(WORK / "00_correct/pre/ccd/guard_pathmatch.py"),
                            "ov_pre")
    norm = (lambda al: tuple(pre._normalize_allowed(al)))
    diff, abst = [], 0
    n = 0
    for cname, spec in refgate.CLASSES.items():
        pre_s, suf, carries = spec
        for cp in range(0x110000):
            ch = chr(cp)
            p = pre_s + ch + suf
            a = norm((pre_s + ch,)) if carries else norm(("ccd",))
            rv, votes = refs.consensus(p, a)
            n += 1
            if rv is refgate.ABSTAIN:
                abst += 1
                continue
            t = bool(tv(p, a))
            if t != rv and len(diff) < 40:
                diff.append({"class": cname, "cp": hex(cp), "name": _nm(cp),
                             "refs": rv, "truth_v2_fn": t,
                             "votes": {k: str(x) for k, x in votes.items()}})
    print(json.dumps({"mode": "overlap", "n": n, "n_abstain": abst,
                      "n_disagree": len(diff), "sample": diff[:20]},
                     indent=1, ensure_ascii=True))


if __name__ == "__main__":
    {"probe": mode_probe, "shape": mode_shape,
     "monolith": mode_monolith, "overlap": mode_overlap}[sys.argv[1]]()
