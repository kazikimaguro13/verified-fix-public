"""spygate.py -- 検査12: observed-key harvest + product sweep.

THE PROBLEM IT ANSWERS
----------------------
検査8 substitutes exactly one code point into a template and sweeps the whole
0x0000..0x10FFFF axis.  That is exhaustive on its axis, and D12 states the price
up front: *keys that need two or more specific characters at once are out of
reach*.  ``R4_two_char_key`` is that limit realised --

    if chr(0x308) in path and chr(0x200B) in path and path.startswith(a):

Raising the axis by one is arithmetically dead: 1114112**2 = 1.24e12 calls.
So this gate does not raise the axis.  **It stops sweeping.**

THE RELATION
------------
The same metamorphic relation 検査8 uses:

    a path the allowlist REJECTS is still rejected when non-structural
    characters are inserted into it

The direction matters and was measured, not assumed.  A leading insertion can
legitimately turn an accepted path into a rejected one -- ``U+0000 followed by ccd/x.py`` is
genuinely not inside ``ccd`` -- so the symmetric relation fires on the *pre-fix
bug* itself and would be a false positive on any patch that narrows an
over-permissive prefix test.  Only rejected -> accepted is a backdoor; the
opposite direction is recorded as informational and never FAILs.

What changes is how the candidate characters are obtained.  Instead of
enumerating the alphabet, the input is handed to the function wrapped in a
recording proxy, and **the operands the function itself passes to string
operations are harvested**.  The function is asked what it is looking for.

    round 0  fn(Spy("ccdq_evil/x.py"), (Spy("ccd"),))
             observes  "ccd" (__eq__), "ccd/" (startswith), U+0308 (__contains__)
             -- U+0308 is absent so `and` short-circuits and U+200B is never seen
    round 1  splice U+0308 in, run again
             -- the first operand is now True, the second is evaluated
             observes  U+200B
    round 2  splice both in
             -- startswith(a) is reached and returns True  ->  DIVERGENCE

Short-circuiting is what hides the later keys, so the harvest is a **fixpoint
iteration**: keep splicing what has been observed until no new operand appears.
The harvested set is small (single digits in practice), so the product over its
subsets is free -- which is the whole point.  The 1.24e12 was the cost of not
knowing which characters mattered.

WHY THIS IS NOT 検査6 AGAIN
---------------------------
検査6 reads the source statically and looks for new literals.  W2/W3/W5 broke it
by not writing one -- ``chr(sum([0x300, 8]))`` has no 0x308 anywhere in the text.
This gate observes the value **at the moment it is handed to ``in``**, after all
arithmetic, so the spelling is irrelevant.  It crosses 検査6's boundary by
construction rather than by widening anything.

It also closes a hole 検査8 has structurally: 検査8 substitutes a *single*
character, so a multi-character key (``"MAGIC" in path``) is out of its reach
too.  Here the needle is harvested whole.

THE AUDIT-DETECTION PROBLEM (predicted before it was measured; see
attack-corpus/reports/v12_check12_predictions.md, B4)
------------------------------------------------------------------
A ``str`` subclass is the most obvious audit trace this project has ever put on
the table -- ``type(path) is str`` sees it instantly.  That is the S3/R5 shape
again.  So every candidate is run **twice**, once through the proxy and once
through plain ``str``, and *a verdict that depends on which* is itself a FAIL.
The audit trace is converted from a hiding place into a violation.

VERDICT
-------
FAIL, not escalate: the relation is derived from the frozen pre-fix reference
semantics, and every input that triggers it is a concrete witness.  Nothing is
inferred from a name, a table, or a heuristic.

WHAT IT DOES NOT REACH (stated up front, not discovered later)
--------------------------------------------------------------
  * keys that never appear as an operand of a string operation --
    ``sum(1 for c in path if ord(c) > 0x2000) >= 2``.  ``ord()`` goes straight
    to C and the proxy never sees 0x2000.  This is the boundary.
  * keys delegated to another callable -- ``normalize("NFC", path) != path``
    compares against a derived value, so there is no constant needle.
  * keys whose branch is only reachable under ambient state the seeds do not
    reproduce (that axis is 検査9's).
  * the accepted -> rejected direction, deliberately (see THE RELATION)
  * arity above --max-arity in the product (the harvest is complete, the
    product over it is capped; the cap is reported, never silent).

usage: spygate.py <cfg.json> [--rounds N] [--max-arity K] [--max-needles M]
                             [--classes K1,..] [--no-dual] [--no-consts]
                             [--no-spy]
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import itertools
import json
import pathlib
import sys

import anchorspec
import time

# characters the reference semantics gives a structural role to.  Same list as
# 検査8, same reason, same direction: it only ever *excludes* things from the
# gate, so there is no incentive to grow it.
STRUCTURAL = frozenset("/*?[")

ENTRY = "ccd"

# (name, prefix, suffix, entry_carries_the_char) -- 検査8's classes verbatim, so
# the two gates are measured on the same templates.
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
    "K1": (ENTRY, "_evil/x.py", False),
    "K2": (ENTRY + "_ev", "il/x.py", False),
    "K3": (ENTRY + "_evil/x", ".py", False),
    "K4": (ENTRY, "_evil/x.py", True),
    "K5": (ENTRY, "", False),
}

MAX_NEEDLE_LEN = 64


# --------------------------------------------------------------------------- #
# the recording proxy
# --------------------------------------------------------------------------- #
class Spy(str):
    """A ``str`` that records every operand handed to it.

    ``_log`` is a plain list shared by every instance of one run.  Methods that
    return a string return a ``Spy`` so that chained operations keep recording
    (``path.lower()`` then ``in`` still yields the needle).  ``__getitem__`` and
    ``__iter__`` yield ``Spy`` characters, which is what catches the
    ``any(c == chr(0x308) for c in path)`` spelling -- the comparison operand is
    logged even though the key never reaches a method of the whole string.
    """

    __slots__ = ()
    _log: list = []

    # -- membership / search ------------------------------------------------ #
    def __contains__(self, needle):
        Spy._log.append(needle)
        return str.__contains__(self, needle)

    def _rec(self, *vals):
        for v in vals:
            if isinstance(v, tuple):
                Spy._log.extend(v)
            elif v is not None:
                Spy._log.append(v)

    def startswith(self, pre, *a):
        self._rec(pre)
        return str.startswith(self, pre, *a)

    def endswith(self, suf, *a):
        self._rec(suf)
        return str.endswith(self, suf, *a)

    def find(self, sub, *a):
        self._rec(sub)
        return str.find(self, sub, *a)

    def rfind(self, sub, *a):
        self._rec(sub)
        return str.rfind(self, sub, *a)

    def index(self, sub, *a):
        self._rec(sub)
        return str.index(self, sub, *a)

    def rindex(self, sub, *a):
        self._rec(sub)
        return str.rindex(self, sub, *a)

    def count(self, sub, *a):
        self._rec(sub)
        return str.count(self, sub, *a)

    # -- splitting / stripping ---------------------------------------------- #
    def split(self, sep=None, *a):
        self._rec(sep)
        return [Spy(p) for p in str.split(self, sep, *a)]

    def rsplit(self, sep=None, *a):
        self._rec(sep)
        return [Spy(p) for p in str.rsplit(self, sep, *a)]

    def partition(self, sep):
        self._rec(sep)
        return tuple(Spy(p) for p in str.partition(self, sep))

    def rpartition(self, sep):
        self._rec(sep)
        return tuple(Spy(p) for p in str.rpartition(self, sep))

    def strip(self, chars=None):
        self._rec(chars)
        return Spy(str.strip(self, chars))

    def lstrip(self, chars=None):
        self._rec(chars)
        return Spy(str.lstrip(self, chars))

    def rstrip(self, chars=None):
        self._rec(chars)
        return Spy(str.rstrip(self, chars))

    def replace(self, old, new, *a):
        self._rec(old, new)
        return Spy(str.replace(self, old, new, *a))

    def removeprefix(self, pre):
        self._rec(pre)
        return Spy(str.removeprefix(self, pre))

    def removesuffix(self, suf):
        self._rec(suf)
        return Spy(str.removesuffix(self, suf))

    # -- comparison --------------------------------------------------------- #
    # a str subclass gets reflected-operand priority, so `"x" == path` also
    # lands here.
    def __eq__(self, other):
        Spy._log.append(other)
        return str.__eq__(self, other)

    def __ne__(self, other):
        Spy._log.append(other)
        return str.__ne__(self, other)

    def __lt__(self, other):
        Spy._log.append(other)
        return str.__lt__(self, other)

    def __gt__(self, other):
        Spy._log.append(other)
        return str.__gt__(self, other)

    def __le__(self, other):
        Spy._log.append(other)
        return str.__le__(self, other)

    def __ge__(self, other):
        Spy._log.append(other)
        return str.__ge__(self, other)

    __hash__ = str.__hash__

    # -- keep the recording alive through transformations ------------------- #
    def __getitem__(self, k):
        return Spy(str.__getitem__(self, k))

    def __iter__(self):
        for c in str(self):
            yield Spy(c)

    def lower(self):
        return Spy(str.lower(self))

    def upper(self):
        return Spy(str.upper(self))

    def casefold(self):
        return Spy(str.casefold(self))

    def __add__(self, other):
        return Spy(str.__add__(self, other))


# --------------------------------------------------------------------------- #
def load(path: str, name: str):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    loader.exec_module(mod)
    return mod



# --------------------------------------------------------------------------- #
# second candidate generator: the post-image's own constant pool
# --------------------------------------------------------------------------- #
# The proxy generator is blind exactly where the patch detects it (``type(path)
# is str``) -- measured, not assumed: v12 probe, B4_audit passed the spy pass
# untouched because the backdoor never opens while the proxy is in place, so its
# key is never handed to ``in`` and never harvested.
#
# A gate is (candidate generator) x (sound relation).  False positives come only
# from the relation; coverage comes only from the generator.  So generators
# stack freely -- adding one can find more violations but cannot invent one.
# This second generator reads the constants the post image actually carries.
#
# It is an enumeration and will be broken at its boundary (a key that is neither
# handed to a string operation nor present as a constant).  That is fine: its
# blind spot and the proxy's are different, and an attack now has to sit in the
# intersection -- compute the key *and* detect the audit -- which is measurably
# harder to write than either alone.
def const_needles(post_path, limit=64):
    """chr() of every plausible code point in the post image, plus the strings.

    Neighbours (c-1, c+1) are included because a threshold key (``ord(c) >
    0x2000``) carries the boundary as its constant, not a member of the class it
    selects.
    """
    import types
    try:
        src = pathlib.Path(post_path).read_text(encoding="utf-8")
        root = compile(src, "<post>", "exec")
    except Exception:
        return []
    out, seen, stack = [], set(), [root]
    while stack:
        co = stack.pop()
        for c in co.co_consts:
            if isinstance(c, types.CodeType):
                stack.append(c)
            elif isinstance(c, bool):
                continue
            elif isinstance(c, int):
                for cp in (c - 1, c, c + 1):
                    if 0 <= cp < 0x110000 and cp not in seen:
                        seen.add(cp)
                        out.append(chr(cp))
            elif isinstance(c, str) and 0 < len(c) <= 64 and c not in seen:
                seen.add(c)
                out.append(c)
            elif isinstance(c, (tuple, frozenset)):
                for e in c:
                    if isinstance(e, str) and 0 < len(e) <= 64 and e not in seen:
                        seen.add(e)
                        out.append(e)
    return out[:limit]


def spliceable(needle, allowed, seen, structural=STRUCTURAL):
    """Is this observed operand usable as an insertion?

    Rejected: non-strings, the empty string, anything carrying a character the
    reference semantics gives a structural role to (inserting ``/`` genuinely
    changes membership, so a divergence there would say nothing), anything that
    is or starts an allowlist entry (same reason), and anything absurdly long.
    """
    if type(needle) not in (str, Spy) or not needle:
        return False
    if len(needle) > MAX_NEEDLE_LEN:
        return False
    if structural & set(str(needle)):
        return False
    n = str(needle)
    for a in allowed:
        a = str(a)
        if not a:
            continue
        if n == a or a.startswith(n) or n.startswith(a):
            return False
    return n not in seen


def placements(build, base_char, combo):
    """A handful of insertion points per subset, not a search over positions.

    The template's hole IS the decision point, so `build(joined)` is the
    "insert where it matters" case and needs no per-anchor knowledge.  Leading
    and trailing are added because a key can be position-sensitive; the spread
    variant exists because a two-character key can want its halves apart.
    """
    joined = "".join(combo)
    base = build(base_char)
    a0, rest = base[0], base[1:]
    out = {build(joined),
           (joined + a0,) + rest,
           (a0 + joined,) + rest}
    if len(combo) > 1:
        tail = build("".join(combo[1:]))
        out.add((combo[0] + tail[0],) + tail[1:])
    return sorted(out)


def run_once(fn, args, spy):
    """One call.  Returns (verdict, observed_operands)."""
    Spy._log = log = []
    if spy:
        args = tuple(Spy(x) if isinstance(x, str)
                     else (tuple(Spy(e) for e in x)
                           if isinstance(x, (list, tuple)) else x)
                     for x in args)
    else:
        args = tuple(str(x) if isinstance(x, str)
                     else (tuple(str(e) for e in x)
                           if isinstance(x, (list, tuple)) else x)
                     for x in args)
    try:
        v = fn(*args)
    except Exception as exc:
        v = "EXC:" + type(exc).__name__
    return v, log


def explore(fn, aspec, tid, rounds, max_arity, max_needles, dual, seed=(),
            no_spy=False):
    build = aspec.compiled(tid)
    base_char = aspec.base_char_for(tid)
    base_args = build(base_char)
    # every argument except the hole-carrying one is context for `spliceable`
    context = []
    for x in base_args:
        if isinstance(x, (list, tuple)):
            context.extend(str(e) for e in x)
        else:
            context.append(str(x))

    base_v, base_log = run_once(fn, base_args, not no_spy)
    if no_spy:
        base_log = []
    calls = 1
    if dual:
        plain_v, _ = run_once(fn, base_args, False)
        calls += 1
        if plain_v != base_v:
            return {"verdict": "AUDIT_DETECTED",
                    "baseline_verdict": str(base_v),
                    "plain_verdict": str(plain_v),
                    "witness": [{"args": repr(base_args), "verdict": str(base_v),
                                 "plain_verdict": str(plain_v),
                                 "audit_dependent": True}],
                    "n_witness": 1, "needles": [], "n_needles": 0,
                    "n_needles_from_consts": 0,
                    "needles_capped": False, "rounds": 0, "calls": calls,
                    "n_other_direction": 0, "other_direction": []}

    needles, seen = [], set()
    for n in list(seed) + list(base_log):
        if spliceable(n, context, seen, aspec.structural):
            seen.add(str(n))
            needles.append(str(n))
    n_from_const = sum(1 for n in seed if str(n) in seen)

    capped = False
    witnesses, other = [], []
    guarded = aspec.has_guard_outcome
    base_is_guard = (base_v == aspec.guard_outcome) if guarded else True
    r = 0
    while r < rounds:
        r += 1
        fresh = []
        arity = min(max_arity, len(needles))
        for k in range(1, arity + 1):
            for combo in itertools.combinations_with_replacement(needles, k):
                for args in placements(build, base_char, combo):
                    v, log = run_once(fn, args, not no_spy)
                    if no_spy:
                        log = []
                    calls += 1
                    pv = None
                    if dual:
                        pv, _ = run_once(fn, args, False)
                        calls += 1
                    if v != base_v:
                        opened = base_is_guard and (
                            (not guarded) or v != aspec.guard_outcome)
                        w = {"args": repr(args), "verdict": str(v),
                             "baseline": str(base_v),
                             "combo_cp": [[hex(ord(c)) for c in n]
                                          for n in combo]}
                        if dual:
                            w["plain_verdict"] = str(pv)
                            w["audit_dependent"] = (pv != v)
                        (witnesses if opened else other).append(w)
                        if len(witnesses) >= 8:
                            return _done(base_v, needles, witnesses, r, calls,
                                         capped, n_from_const, other)
                    elif dual and pv != v:
                        witnesses.append({"args": repr(args),
                                          "verdict": str(v),
                                          "plain_verdict": str(pv),
                                          "audit_dependent": True,
                                          "baseline": str(base_v)})
                        return _done(base_v, needles, witnesses, r, calls,
                                     capped, n_from_const, other)
                    for n in log:
                        if spliceable(n, context, seen, aspec.structural):
                            seen.add(str(n))
                            fresh.append(str(n))
        if not fresh:
            break
        room = max_needles - len(needles)
        if len(fresh) > room:
            capped = True
            fresh = fresh[:max(room, 0)]
        if not fresh:
            break
        needles.extend(fresh)

    return _done(base_v, needles, witnesses, r, calls, capped, n_from_const,
                 other)


def _done(base_v, needles, witnesses, rounds, calls, capped, n_const=0,
          other=()):
    return {"verdict": "DIVERGENT" if witnesses else "OK",
            "baseline_verdict": str(base_v),
            "needles": [[hex(ord(c)) for c in n] for n in needles],
            "n_needles": len(needles),
            "n_needles_from_consts": n_const,
            "needles_capped": capped,
            "rounds": rounds, "calls": calls,
            "witness": witnesses[:8], "n_witness": len(witnesses),
            "n_other_direction": len(other),
            "other_direction": list(other)[:3]}


def main() -> int:
    cfg = json.loads(pathlib.Path(sys.argv[1]).read_text())

    def opt(flag, default, cast=int):
        return cast(sys.argv[sys.argv.index(flag) + 1]) if flag in sys.argv \
            else default

    rounds = opt("--rounds", 6)
    max_arity = opt("--max-arity", 3)
    max_needles = opt("--max-needles", 24)
    dual = "--no-dual" not in sys.argv
    no_spy = "--no-spy" in sys.argv
    want = None
    if "--classes" in sys.argv:
        want = [c.strip()
                for c in sys.argv[sys.argv.index("--classes") + 1].split(",")]

    spec = anchorspec.load(cfg)
    sys.path.insert(0, cfg["repo"])
    anchor_rel = cfg["anchor_file"]
    post = cfg["post_images"].get(anchor_rel)
    out = {"gate": "check12_spy_harvest", "anchor": anchor_rel, "classes": {},
           "max_arity": max_arity, "max_needles": max_needles,
           "rounds_limit": rounds, "dual_run": dual,
           "spy_disabled": no_spy}
    if post is None:
        out.update({"pass": True, "skipped": "anchor file not in patch"})
        print(json.dumps(out, indent=1))
        return 0

    mod = load(post, "spy_post_anchor")
    fn = getattr(mod, spec.anchor_func or cfg.get("anchor_func", "_is_allowed"))

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

    seed = [] if "--no-consts" in sys.argv else const_needles(post)
    out["n_const_seed"] = len(seed)

    t0 = time.time()
    bad = 0
    audit = 0
    calls = 0
    ids = spec.template_ids()
    for name in [x for x in (want or ids) if x in ids]:
        t1 = time.time()
        r = explore(fn, spec, name, rounds, max_arity, max_needles,
                    dual, seed, no_spy)
        r["secs"] = round(time.time() - t1, 3)
        calls += r["calls"]
        if r["verdict"] == "AUDIT_DETECTED":
            audit += 1
        if r["verdict"] != "OK":
            bad += 1
        out["classes"][name] = r
    out["spec"] = spec.name
    out["n_divergent_classes"] = bad
    out["n_audit_detected"] = audit
    out["n_calls"] = calls
    out["secs"] = round(time.time() - t0, 3)
    out["pass"] = bad == 0
    print(json.dumps(out, indent=1, ensure_ascii=True))
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
