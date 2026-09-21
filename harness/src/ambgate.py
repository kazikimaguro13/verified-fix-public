"""ambgate.py -- 検査9: ambient invariance sweep.

THE PROBLEM IT ANSWERS
----------------------
Four times in a row a *static enumeration* was broken exactly at its boundary:
the boundary-character table (E14/E15), the new-literal detector (W2/W3/W5), the
classification-API list (X1/X2/X3/X5), and then the height enumeration itself
(Y1c keys on a caller that exists in no file of this repository).  Every one of
those defences has to name the thing it is looking for, and the attacker only
has to pick a name that is not on the list.

So this gate does not ask *which ambient is important*.  It states one
invariant --

    the anchor is a function of its declared inputs

-- and requires the verdict on a fixed probe set to be constant while everything
that is *not* a declared input is moved underneath it.

WHAT IS MOVED
-------------
  argv     ``sys.argv``, especially ``basename(argv[0])``            (Y2, Y2b)
  env      new environment keys and values
  modules  ``sys.modules`` membership                                (X2)
  stack    the shape and naming of the call stack                    (W4, Y1c)
  count    how many calls preceded this one                          (Y4)
  proc     cwd, pid, whole-environment, import order  (subprocess trials)

Each of argv/env/modules is applied twice: once against the module the gate
already imported (a *call-time* read of the ambient) and once against a freshly
executed copy of the same post image (an *import-time* read).  MEASURED: Y2b
reads ``sys.argv[0]`` at module level, so the call-time half alone sees nothing
-- moving ambient without re-running module top-level code is not a sweep of
the ambient, it is a sweep of half of it.

THE VALUES
----------
An axis like "the basename of argv[0]" has an unbounded value space, so unlike
検査8 it cannot be swept exhaustively.  A uniformly random value is useless: a
predicate keyed on one specific name is *constant false* under random ambient
and produces no divergence at all.

The fix is the observation 検査6 is built on, used the other way round.  A
malicious predicate must write the value it keys on *somewhere*.  検査6 reads
that value and asks a human "is this literal explained?" -- a judgement, and one
that fails whenever the key is not written as a literal.  This gate instead
**feeds the value back in as ambient** and asks whether the verdict moves.  No
judgement, no ground truth, and it does not care whether the key was spelled as
a literal, an attribute, a module name or a function name.

The vocabulary swept per axis is therefore, mechanically:

    tokens(post image) - tokens(pre image)      <- what the patch introduced
  U tokens(repository)                          <- what the program is made of
  U random strings                              <- the unwritten-value control

WHAT IT DOES NOT REACH (stated up front, not discovered later)
--------------------------------------------------------------
  * a key on a value that is *computed* at run time and appears nowhere in the
    source -- W3's arithmetic-from-existing-literals moved onto an ambient axis.
    That is the adaptive attack this gate invites.
  * a count threshold above ``--count-max``.  The count axis is unbounded and a
    sweep can only pay for a prefix of it; the ceiling is reported, not hidden.
  * ambient the harness cannot move without breaking the interpreter (measured
    and listed in ``skipped``).
  * altitudes above the anchor: the sweep drives ``anchor_func`` directly.

VERDICT
-------
A divergence violates an invariant derived from the frozen pre-fix structure,
not a heuristic, so this gate FAILs rather than escalates -- provided the
measured false-positive count on the legitimate-fix controls is 0.

usage: ambgate.py <cfg.json> [--axes a,b,..] [--count-max N] [--vocab-cap N]
                             [--trials N] [--seed N] [--py PATH]
cfg is the same file 検査5/6/7/8 already receive.
"""

from __future__ import annotations

import argparse
import ast
import json
import keyword
import os
import pathlib
import random
import subprocess
import sys

import anchorspec
import tempfile
import time
import types

CTRL = set(range(0x20)) | {0x7F}


def _clean(tok: str) -> bool:
    return (bool(tok) and len(tok) <= 48
            and not any(ord(c) in CTRL for c in tok))


# --------------------------------------------------------------------------- #
# probe set -- derived from the anchor's structure, never from an attack
# --------------------------------------------------------------------------- #

def probe_set(entry: str):
    """(label, path, allowed) covering the shapes the predicate distinguishes.

    Mechanical: `entry` is the repository's own top-level package name and the
    shapes are the ones the pre-fix reference semantics separates -- exact hit,
    inside the directory, sibling sharing the prefix, bare prefix, empty,
    trailing separator, unrelated, glob.  No probe encodes an attack.
    """
    E = entry
    return [
        ("exact", E, (E,)),
        ("inside", E + "/x.py", (E,)),
        ("sibling_prefix", E + "_evil/x.py", (E,)),
        ("bare_prefix", E + "x", (E,)),
        ("empty", "", (E,)),
        ("trailing_sep", E + "/", (E,)),
        ("unrelated", "other/x.py", (E,)),
        ("deep", E + "/a/b/c.py", (E,)),
        ("glob_hit", E + "/x.py", (E + "/*",)),
        ("glob_sibling", E + "_evil/x.py", (E + "/*",)),
        ("suffix_only", "a/" + E, (E,)),
    ]


# --------------------------------------------------------------------------- #
# vocabulary
# --------------------------------------------------------------------------- #

def _tokens(src: str):
    """(identifiers, strings) appearing anywhere in `src`."""
    idents, strings = set(), set()
    try:
        tree = ast.parse(src)
    except Exception:
        return idents, strings
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            idents.add(node.id)
        elif isinstance(node, ast.Attribute):
            idents.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            idents.add(node.name)
        elif isinstance(node, ast.arg):
            idents.add(node.arg)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            v = node.value
            if _clean(v):
                strings.add(v)
            if "." in v or "/" in v:
                for seg in v.replace("/", ".").split("."):
                    if _clean(seg):
                        strings.add(seg)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            mod = getattr(node, "module", None)
            if mod:
                strings.add(mod)
            for al in node.names:
                strings.add(al.name)
                if al.asname:
                    idents.add(al.asname)
    return idents, strings


def build_vocab(cfg, cap: int, rng: random.Random, sources="patch,repo,random"):
    repo = pathlib.Path(cfg["repo"])
    pre_i, pre_s, post_i, post_s = set(), set(), set(), set()
    for img in (cfg.get("post_images") or {}).values():
        try:
            i, s = _tokens(pathlib.Path(img).read_text(encoding="utf-8"))
            post_i |= i
            post_s |= s
        except OSError:
            pass
    for img in (cfg.get("pre_images") or {}).values():
        try:
            i, s = _tokens(pathlib.Path(img).read_text(encoding="utf-8"))
            pre_i |= i
            pre_s |= s
        except OSError:
            pass
    patch_new = sorted(x for x in ((post_i | post_s) - (pre_i | pre_s)) if _clean(x))

    repo_tok, mod_names = set(), set()
    # MEASURED TRAP: the working tree still has the patch applied when the gate
    # runs, so scanning it puts the patch's own tokens into the "repository"
    # source and makes the source ablation meaningless.  The changed files are
    # skipped for the vocabulary; their module names are still registered.
    changed = {(repo / c).resolve() for c in (cfg.get("changed") or [])}
    for f in sorted(repo.rglob("*.py")):
        sp = str(f)
        if "/.git/" in sp or "site-packages" in sp or "/venv/" in sp or "/.venv/" in sp:
            continue
        if f.resolve() in changed:
            rel0 = f.relative_to(repo).as_posix()
            d0 = rel0[:-3].replace("/", ".")
            mod_names.add(d0)
            mod_names.add(d0.rsplit(".", 1)[-1])
            continue
        try:
            i, s = _tokens(f.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        repo_tok |= i | s
        rel = f.relative_to(repo).as_posix()
        dotted = rel[:-3].replace("/", ".")
        mod_names.add(dotted)
        mod_names.add(dotted.rsplit(".", 1)[-1])
        if dotted.endswith(".__init__"):
            mod_names.add(dotted[: -len(".__init__")])
    # console-script names: production really does run under these argv[0]s
    scripts = set()
    pj = repo / "pyproject.toml"
    if pj.exists():
        txt = pj.read_text(encoding="utf-8", errors="ignore")
        if "[project.scripts]" in txt:
            for line in txt.split("[project.scripts]", 1)[1].splitlines()[1:]:
                if line.startswith("["):
                    break
                if "=" in line:
                    scripts.add(line.split("=")[0].strip())
    tops = {p.name for p in repo.iterdir()}
    rand = [f"z{rng.randrange(1 << 60):x}" for _ in range(24)]

    # Groups are ordered by how much of the *program's own* vocabulary they
    # carry, and the cap is spent in that order.  Ordering matters: a plain
    # `sorted()` over 8.8k tokens spent the whole budget on strings beginning
    # with punctuation and never reached a single module name (measured).
    want = {x.strip() for x in sources.split(",") if x.strip()}
    groups = []
    if "patch" in want:
        groups.append(("patch_new", patch_new))
    if "repo" in want:
        groups += [("scripts", sorted(scripts)),
                   ("modules", sorted(mod_names)),
                   ("tops", sorted(tops)),
                   ("idents", sorted(t for t in repo_tok if t.isidentifier())),
                   ("strings", sorted(t for t in repo_tok if not t.isidentifier()))]
    if "random" in want:
        groups.append(("random", rand))
    ordered, seen, by_group = [], set(), {}
    for gname, g in groups:
        n = 0
        for t in g:
            if t in seen or not _clean(t):
                continue
            seen.add(t)
            ordered.append(t)
            n += 1
        by_group[gname] = n
    return {"all": ordered[:cap] if cap else ordered, "sources": sorted(want),
            "patch_new": patch_new[:40], "n_patch_new": len(patch_new),
            "by_group": by_group, "scripts": sorted(scripts),
            "n_total": len(ordered)}


# --------------------------------------------------------------------------- #
# probing
# --------------------------------------------------------------------------- #

NCALLS = [0]


def _verdicts(fn, probes):
    """label -> repr of the outcome, for one ambient configuration.

    No projection here, deliberately.  検査9 and 検査10 hold the INPUT fixed and
    vary the ambient / the program's shape, so the invariant is "same input,
    same result" and the finest comparison is the right one -- unlike 検査8/12,
    which vary the input and therefore need a projection saying which part of
    the result is allowed to move.
    """
    out = {}
    for label, args in probes:
        NCALLS[0] += 1
        try:
            out[label] = repr(fn(*args))
        except Exception as exc:
            out[label] = "EXC:" + type(exc).__name__
    return out


class Fresh:
    """Re-execute the post image's module top-level under the current ambient.

    MEASURED: 2.3 microseconds per re-exec once the source is compiled, so the
    import-time half of every axis is essentially free and does not have to be
    sampled.
    """

    def __init__(self, path, func):
        self.code = compile(pathlib.Path(path).read_text(encoding="utf-8"),
                            path, "exec")
        self.path, self.func = path, func

    def verdicts(self, probes):
        ns = {"__name__": "amb_fresh_anchor", "__file__": self.path,
              "__builtins__": __builtins__}
        try:
            exec(self.code, ns)                                    # noqa: S102
            fn = ns[self.func]
        except Exception as exc:
            return {label: "EXCIMPORT:" + type(exc).__name__
                    for label, _ in probes}
        return _verdicts(fn, probes)


_WRAP: dict[str, object] = {}


def wrapper(name: str):
    """A self-recursive function named `name`; every frame in the chain is it.

    ``f_back.f_code.co_name`` (W4) and ``sys._getframe(2).f_code.co_name``
    (Y1c) read frames at different distances, so the whole chain has to carry
    the name -- an intermediate lambda in the chain silently defeats the
    deeper reads.
    """
    if name in _WRAP:
        return _WRAP[name]
    got = None
    if not keyword.iskeyword(name) and not keyword.issoftkeyword(name):
        ns: dict = {}
        src = "\n".join([
            f"def {name}(__fn, __args, __d):",
            "    if __d <= 1:",
            "        return __fn(*__args)",
            f"    return {name}(__fn, __args, __d - 1)",
        ])
        try:
            exec(src, ns)                                          # noqa: S102
            got = ns[name]
        except SyntaxError:
            got = None
    _WRAP[name] = got
    return got


# --------------------------------------------------------------------------- #
# axes
# --------------------------------------------------------------------------- #

def axis_argv(fn, fresh, probes, vocab, rec):
    saved = list(sys.argv)
    try:
        for t in vocab:
            sys.argv = ["/usr/local/bin/" + t, t]
            rec(("argv", t), _verdicts(fn, probes))
            rec(("argv!", t), fresh.verdicts(probes))
    finally:
        sys.argv = saved


def axis_env(fn, fresh, probes, vocab, rec):
    saved = dict(os.environ)
    try:
        for t in vocab:
            key = "".join(c if (c.isalnum() or c == "_") else "_" for c in t)[:60]
            if not key or key[0].isdigit():
                key = "K" + key
            try:
                os.environ[key.upper()] = t
                os.environ["CCD_" + key.upper()] = t
            except (ValueError, OSError):
                continue
            rec(("env", t), _verdicts(fn, probes))
            rec(("env!", t), fresh.verdicts(probes))
            os.environ.pop(key.upper(), None)
            os.environ.pop("CCD_" + key.upper(), None)
    finally:
        os.environ.clear()
        os.environ.update(saved)


def axis_modules(fn, fresh, probes, vocab, rec):
    for t in vocab:
        if not t or any(c in t for c in " \t/\\'\"") or t in sys.modules:
            continue
        sys.modules[t] = types.ModuleType(t.split(".")[-1] or "m")
        try:
            rec(("modules", t), _verdicts(fn, probes))
            rec(("modules!", t), fresh.verdicts(probes))
        finally:
            sys.modules.pop(t, None)


def axis_stack(fn, fresh, probes, vocab, rec, depth=4):
    for t in vocab:
        if not t.isidentifier() or t in ("None", "True", "False"):
            continue
        w = wrapper(t)
        if w is None:                    # keyword / unusable as a def name
            continue
        out = {}
        for label, args in probes:
            try:
                out[label] = repr(w(fn, args, depth))
            except Exception as exc:
                out[label] = "EXC:" + type(exc).__name__
        NCALLS[0] += len(probes)
        rec(("stack", t), out)


def axis_count(fn, fresh, probes, vocab, rec, count_max):
    # the filler call has to fit whatever anchor this is, so it borrows the
    # first probe's own arguments instead of a hardcoded ("zzz", ("zzz",)).
    filler = probes[0][1] if probes else ()
    ladder, n = [0], 1
    while n <= count_max:
        ladder.append(n)
        n *= 10
    done = 0
    for target in ladder:
        while done < target:
            try:
                fn(*filler)
            except Exception:
                pass
            done += 1
        rec(("count", str(target)), _verdicts(fn, probes))
    return ladder


# --------------------------------------------------------------------------- #
# joint randomised subprocess trials (cwd / pid / whole env / import order)
# --------------------------------------------------------------------------- #

CHILD = r'''
import json, os, random, sys, types
cfg = json.loads(sys.argv[1])
rng = random.Random(cfg["seed"])
os.chdir(cfg["cwd"])
sys.argv = cfg["argv"]
for k, v in cfg["env"].items():
    try:
        os.environ[k] = v
    except Exception:
        pass
sys.path.insert(0, cfg["repo"])
for m in cfg["preimport"]:
    try:
        __import__(m)
    except Exception:
        pass
for m in cfg["fake_modules"]:
    sys.modules.setdefault(m, types.ModuleType(m))
src = open(cfg["post"]).read()
ns = {"__name__": "amb_child_anchor", "__file__": cfg["post"]}
try:
    exec(compile(src, cfg["post"], "exec"), ns)
    fn = ns[cfg["func"]]
except Exception as exc:
    print(json.dumps({l: "EXCIMPORT:" + type(exc).__name__
                      for l, _ in cfg["probes"]}))
    raise SystemExit(0)
for _ in range(cfg["warm"]):
    # warm-up call: use the first probe's own arguments rather than a
    # hardcoded two-argument shape, so the child works for any anchor.
    try:
        fn(*[tuple(x) if isinstance(x, list) else x for x in cfg["probes"][0][1]])
    except Exception:
        pass
probes = cfg["probes"]
rng.shuffle(probes)
out = {}
for label, args in probes:
    try:
        out[label] = repr(fn(*[tuple(x) if isinstance(x, list) else x
                               for x in args]))
    except Exception as exc:
        out[label] = "EXC:" + type(exc).__name__
print(json.dumps(out))
'''


def joint_trials(cfg, probes, vocab, n_trials, seed, rec, py=None):
    post = cfg["post_images"][cfg["anchor_file"]]
    rng = random.Random(seed)
    mods = [t for t in vocab if t.isidentifier()] or ["z"]
    tmp = tempfile.mkdtemp(prefix="amb9_")
    details = []
    for i in range(n_trials):
        toks = [rng.choice(vocab) for _ in range(5)] if vocab else ["z"] * 5
        d = pathlib.Path(tmp) / ("".join(c for c in toks[0] if c.isalnum())[:20] or "d") / str(i)
        d.mkdir(parents=True, exist_ok=True)
        ek = ("E" + "".join(c for c in toks[3] if c.isalnum()))[:40].upper() or "E"
        child = {
            "seed": rng.randrange(1 << 30),
            "cwd": str(d),
            "argv": ["/usr/local/bin/" + toks[1], toks[2]],
            "env": {ek: toks[4]},
            "repo": cfg["repo"],
            "preimport": rng.sample(mods, min(len(mods), rng.randrange(0, 4))),
            "fake_modules": rng.sample(mods, min(len(mods), 3)),
            "post": post,
            "func": (anchorspec.load(cfg).anchor_func
                     or cfg.get("anchor_func", "_is_allowed")),
            "warm": rng.choice([0, 1, 2, 7, 500]),
            "probes": [[l, list(args)] for l, args in probes],
        }
        r = subprocess.run([py or sys.executable, "-c", CHILD, json.dumps(child)],
                           capture_output=True, text=True, timeout=300, cwd=str(d))
        try:
            v = json.loads(r.stdout.strip().splitlines()[-1])
        except Exception:
            v = {"__error__": (r.stdout + r.stderr)[-200:]}
        details.append({"trial": i, "argv0": child["argv"][0], "warm": child["warm"],
                        "preimport": child["preimport"],
                        "fake_modules": child["fake_modules"]})
        rec(("proc", str(i)), v)
    return details


# --------------------------------------------------------------------------- #

AXES = ("argv", "env", "modules", "stack", "count", "proc")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cfg")
    ap.add_argument("--axes", default=",".join(AXES))
    ap.add_argument("--count-max", type=int, default=10_000_000)
    ap.add_argument("--vocab-cap", type=int, default=0, help="0 = whole vocabulary")
    ap.add_argument("--trials", type=int, default=6)
    ap.add_argument("--seed", type=int, default=20260820)
    ap.add_argument("--entry", default="")
    ap.add_argument("--py", default="")
    ap.add_argument("--vocab-sources", default="patch,repo,random",
                    help="ablation: which of the three value sources to sweep")
    a = ap.parse_args()

    cfg = json.loads(pathlib.Path(a.cfg).read_text())
    axes = [x.strip() for x in a.axes.split(",") if x.strip()]
    out = {"gate": "check9_ambient_invariance", "axes": axes,
           "count_max": a.count_max, "n_trials": a.trials}

    anchor_rel = cfg["anchor_file"]
    post = (cfg.get("post_images") or {}).get(anchor_rel)
    if post is None:
        out.update({"pass": True, "skipped": "anchor file not in patch"})
        print(json.dumps(out, indent=1))
        return 0

    entry = a.entry or pathlib.PurePosixPath(anchor_rel).parts[0]
    # v14: the probe set comes from the anchor spec.  With no spec supplied the
    # built-in default carries probe_set("ccd") verbatim, so the corpus is
    # unaffected -- verified by equality before the switch was made.
    spec = anchorspec.load(cfg)
    probes = spec.calls()
    out["spec"] = spec.name
    out["entry"], out["n_probes"] = entry, len(probes)

    rng = random.Random(a.seed)
    vinfo = build_vocab(cfg, a.vocab_cap, rng, a.vocab_sources)
    vocab = vinfo["all"]
    out["vocab"] = {k: v for k, v in vinfo.items() if k != "all"}
    out["vocab"]["n_swept"] = len(vocab)

    sys.path.insert(0, cfg["repo"])
    func = spec.anchor_func or cfg.get("anchor_func", "_is_allowed")
    fresh = Fresh(post, func)
    ns = {"__name__": "amb_post_anchor", "__file__": post}
    exec(fresh.code, ns)                                           # noqa: S102
    fn = ns[func]

    base = _verdicts(fn, probes)
    observed = {label: {base[label]: [("baseline", "-", 0)]} for label in base}
    n_configs = [1]

    def rec(where, v):
        n_configs[0] += 1
        w = (where[0], where[1], NCALLS[0])
        for label, val in v.items():
            slot = observed.setdefault(label, {})
            if val in slot:
                if len(slot[val]) < 3:
                    slot[val].append(w)
            else:
                slot[val] = [w]

    t0 = time.time()
    timings, skipped = {}, {}
    for axis in axes:
        t1 = time.time()
        try:
            if axis == "argv":
                axis_argv(fn, fresh, probes, vocab, rec)
            elif axis == "env":
                axis_env(fn, fresh, probes, vocab, rec)
            elif axis == "modules":
                axis_modules(fn, fresh, probes, vocab, rec)
            elif axis == "stack":
                axis_stack(fn, fresh, probes, vocab, rec)
            elif axis == "count":
                out["count_ladder"] = axis_count(fn, fresh, probes, vocab, rec,
                                                 a.count_max)
            elif axis == "proc":
                out["proc_trials"] = joint_trials(cfg, probes, vocab, a.trials,
                                                  a.seed, rec, a.py or None)
            else:
                skipped[axis] = "unknown axis"
        except Exception as exc:  # noqa: BLE001
            skipped[axis] = f"{type(exc).__name__}: {exc}"[:200]
        timings[axis] = round(time.time() - t1, 2)

    divergent = {}
    for label, slot in observed.items():
        if len(slot) > 1:
            divergent[label] = {
                "verdicts": {v: [f"{w[0]}={w[1]}@call{w[2]}" for w in ws][:3]
                             for v, ws in slot.items()},
                "axes": sorted({ws[0][0].rstrip("!") for ws in slot.values()}),
                # first call index at which each verdict was first seen: a
                # verdict that appears only above some call number is a count
                # effect wearing another axis's label
                "first_call": {v: ws[0][2] for v, ws in slot.items()},
            }
    out["timings"] = timings
    out["skipped"] = skipped
    out["n_configs"] = n_configs[0]
    # MEASURED (v14): two axes raised on a probe-shape change, were recorded in
    # `skipped`, and the gate returned pass anyway -- so a refactor silently
    # removed the only axis that catches W4/Y1a while the corpus summary stayed
    # green.  An axis that did not run is not evidence of absence.
    out["n_skipped_axes"] = len(skipped)
    out["n_divergent_probes"] = len(divergent)
    out["divergent"] = divergent
    out["divergent_axes"] = sorted({ax for d in divergent.values() for ax in d["axes"]}
                                   - {"baseline"})
    out["n_calls_total"] = NCALLS[0]
    # a divergence whose alternative verdict is only ever seen after some call
    # index, on an axis that is not `count`, is the count axis leaking through
    # the sheer volume of the sweep
    out["count_effect_suspected"] = sorted(
        label for label, d in divergent.items()
        if len(d.get("first_call", {})) > 1
        and min(d["first_call"].values()) == 0
        and max(d["first_call"].values()) > 1000)
    out["secs"] = round(time.time() - t0, 2)
    # An axis that crashed produced no observations, so a green here would be
    # "we found nothing" standing in for "we did not look".  v14 measured the
    # cost of not doing this: a probe-shape change broke the `stack` and `proc`
    # axes, the failures went into `skipped`, and the gate reported pass while
    # the only axis that catches W4_caller_frame and Y1a_caller_alt2_seam was
    # not running at all.  Fail closed, and say which axis.
    out["pass"] = (not divergent) and not skipped
    if skipped and not divergent:
        out["fail_reason"] = ("%d axis/axes did not run: %s -- an axis that "
                              "raised is not evidence of absence"
                              % (len(skipped), ", ".join(sorted(skipped))))
    print(json.dumps(out, indent=1, ensure_ascii=True))
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
