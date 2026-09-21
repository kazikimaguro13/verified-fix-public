"""diffgate2.py — トレーススコープ差分オラクル (DESIGN D2).

Replaces v0's hand-written semantic scope predicate (which false-rejected the
correct fix 105 times) with an **execution-trace** scope: the anchor is the F
*function* (``ccd/guard_pathmatch._is_allowed``), frozen before the fix.  For
each corpus input we run the PRE image with a touch-flag on the anchor:

  * anchor NOT touched  -> input is outside F's blast radius.  pre and post MUST
    agree; any divergence is an out-of-scope side effect -> REJECT.
  * anchor touched       -> the fix is allowed to change this.  Divergences are
    reported (count + sample) but NOT rejected — T (property) and check4 guard it.

Why this kills the survivors and spares the correct fix:
  * A single-line/one-function fix confined to the anchor can only change an
    input's output if the anchor ran for it => touched => in-scope.  So the
    correct fix produces ZERO out-of-scope divergences *by construction*
    (the 105-divergence false reject cannot recur).
  * A7a mutates ``_matches_any`` and A7b mutates ``cli_util._summarize_exception``
    — neither calls the anchor, so their corpora are out-of-scope and their
    divergences are rejected.  This is the "拡張コーパス圏外乖離" of the design:
    the corpus is grown to every changed module/function.

Config (single JSON arg):
  {"changed": ["ccd/guard_pathmatch.py", ...],
   "pre_images": {rel: abspath}, "post_images": {rel: abspath},
   "anchor_file": "ccd/guard_pathmatch.py", "anchor_func": "_is_allowed",
   "repo": "/path"}   # repo added to sys.path so ccd.* imports resolve
"""

from __future__ import annotations

import ast
import importlib.machinery
import importlib.util
import itertools
import json
import random
import sys

import anchorspec

# ---- the shared corpus (v0's 9,127-call corpus, reused) --------------------
TOKENS = [
    "ccd", "ccd/", "ccd/guard.py", "ccd/guard_pathmatch.py", "ccd_evil/x.py",
    "tests", "tests/", "tests/test_guard.py", "testsuite/x.py",
    "docs/spec_021.md", "docs/spec_021_leak.md", "docs", "doc",
    "scripts/launchers/a.sh", "scripts", "script",
    ".github/workflows/ci.yml", ".github", "pyproject.toml", "pyproject",
    "ccd/*.py", "ccd/v?.py", "ccd/v[0-9].py", "*.py", "**", "ccd/**",
    "a", "a/b", "a/b/c", "ab", "ab/c", "", "/", "//", "a//b",
    "x" * 40, "ccd\\guard.py", "ccd/./guard.py", "ccd/../etc/passwd",
]

# ---- v2: boundary constants, ALWAYS injected (DESIGN §8 proposal 2) --------
# check5 costs 0.12s, so breadth here is nearly free.  These are the classes
# the v1 generator never produced -- the class C1b escaped through is the
# backslash row.  Injected as *constants* (not sampled) so the coverage cannot
# drift with a seed change.
BOUNDARY_CONST = [
    # separators, doubled / mixed
    "ccd\\evil.py", "ccd\\\\evil.py", "ccd/\\evil", "ccd\\/evil", "\\ccd/x",
    "ccd\\", "\\", "\\\\", "/\\", "\\/",
    # pre-normalisation tokens
    "ccd/.", "ccd/..", "ccd/../x", "ccd/./x", "ccd_evil/../x", "./ccd/x",
    "../ccd/x", "ccd_evil/", "/ccd/x", "ccd//x", "...",
    # case
    "CCD", "CCD/x.py", "ccdEvil/x.py", "ccdE", "Ccd/x", "ccd/X.PY",
    # unicode: NFC / NFD / width / invisible / astral
    "ccdé", "ccdé", "ccdÉ", "ccdÉ",
    "ccdガ", "ccdガ",
    "ccd／evil.py", "ccd＼evil.py", "ccdＡ", "ccd．py",
    "ccd​evil", "ccd﻿evil", "ccd evil",
    "ccd⁄evil", "ccd∕evil",
    "ccd\U0001f600", "ccdİ", "ccdß", "ccdK",
    # control characters
    "ccd\x00evil", "\x00", "ccd\x01", "ccd\x1b[0m", "ccd\tevil", "ccd\nevil",
    "ccd\revil", "ccd\x7f",
    # length extremes
    "", "c", "ccd_" + "q" * 1024, "ccd_" + "q" * 4096, "q" * 8192,
    # punctuation / shell-adjacent
    "ccd~", "ccd%2e", "ccd#x", "ccd|x", "ccd:x", "ccd;x", "ccd@x", "ccd$x",
    "ccd evil", "ccd  ", " ccd", "ccd'", 'ccd"', "ccd`x",
]

# entry-side constants: what an allowlist entry may degenerate into
BOUNDARY_ENTRIES = [
    "", " ", "/", "//", "\\", "ccd/", "ccd\\", "ccd//", ".", "..",
    "CCD", "ccdé", "ccdé", "ccd\x00", "q" * 1024,
]

# arity constants: a branch keyed on len(allowed) is invisible to any
# character-class corpus, so the tuple sizes are enumerated explicitly.
ARITY_ENTRIES = ["a", "b", "c", "d", "e", "f", "g", "h"]
ARITY_VICTIMS = ["ccd_evil/x.py", "ccd/guard.py", "ccd", "ccd\\evil.py"]


def path_allowed_corpus(seed: int = 20260820):
    rng = random.Random(seed)
    cases = []
    for path, a in itertools.product(TOKENS, TOKENS):
        cases.append((path, (a,)))
    for _ in range(1200):
        path = rng.choice(TOKENS)
        n = rng.randint(0, 3)
        cases.append((path, tuple(rng.choice(TOKENS) for _ in range(n))))
    for _ in range(400):
        path = "".join(rng.choice("ab/*?[]._") for _ in range(rng.randint(0, 8)))
        allowed = tuple(
            "".join(rng.choice("ab/*?[]._") for _ in range(rng.randint(0, 5)))
            for _ in range(rng.randint(0, 2))
        )
        cases.append((path, allowed))

    # --- v2 constant injection (deterministic, seed-independent) -----------
    base_entries = ["ccd", "tests", "docs/spec_021.md", "a", "pyproject.toml"]
    for path in BOUNDARY_CONST:
        for a in base_entries:
            cases.append((path, (a,)))
        for a in BOUNDARY_ENTRIES:
            cases.append((path, (a,)))
    for a in BOUNDARY_ENTRIES:
        for path in TOKENS:
            cases.append((path, (a,)))
    for victim in ARITY_VICTIMS:
        for n in range(0, 9):
            head = tuple(ARITY_ENTRIES[:n])
            cases.append((victim, head))
            cases.append((victim, head + ("ccd",)))
            cases.append((victim, ("ccd",) + head))
    return cases


def exception_corpus():
    """Messages spanning cli_util._summarize_exception's 200/2000 thresholds."""
    lens = [0, 1, 5, 50, 150, 199, 200, 201, 250, 500, 1000, 1999, 2000, 2001, 3000]
    out = []
    for n in lens:
        out.append(ValueError("m" * n))
        out.append(RuntimeError("  " + "z" * n + "  "))
    out.append(KeyError("k" * 400))
    return [(e,) for e in out]


# ---- entry-point registry: (module rel) -> {func: (corpus, caller)} ---------
def build_registry(spec=None):
    """Which functions to compare, and with what arguments.

    With a non-default anchor spec the registry is BUILT FROM IT; without one
    the synthetic testbed's registry is returned verbatim, so the 72-entry
    corpus is unaffected.

    MEASURED (v13): before this the registry was keyed by ccd's own paths, so a
    different repository matched nothing, `compared` stayed 0, and the gate
    reported pass.  Zero comparisons is now fail-closed as well, but a gate that
    fails closed and can never apply is only half a fix -- this is the half that
    lets it apply.
    """
    if spec is not None and spec.anchor_file and spec.anchor_file not in (
            "ccd/guard_pathmatch.py", "ccd/cli_util.py"):
        corpus = [args for _, args in spec.calls()]
        for tid in spec.template_ids():
            for ch in anchorspec.BOUNDARY_CHARS:
                corpus.append(spec.build(tid, ch))
        fname = spec.anchor_func
        return {spec.anchor_file: {fname: (
            corpus,
            lambda m, args, _f=fname: getattr(m, _f)(*args),
        )}}
    return _ccd_registry()


def _ccd_registry():
    pa = path_allowed_corpus()
    return {
        "ccd/guard_pathmatch.py": {
            "_is_allowed": (
                [(p, tuple(str(x) for x in a)) for p, a in pa],
                lambda m, args: m._is_allowed(args[0], args[1]),
            ),
            "_matches_any": (
                [(p, list(a)) for p, a in pa],
                lambda m, args: m._matches_any(args[0], args[1]),
            ),
            "_normalize_allowed": (
                [(a,) for _, a in pa],
                lambda m, args: m._normalize_allowed(args[0]),
            ),
        },
        "ccd/cli_util.py": {
            "_summarize_exception": (
                exception_corpus(),
                lambda m, args: m._summarize_exception(args[0]),
            ),
        },
    }


def load(path: str, name: str):
    # explicit SourceFileLoader so image files need no .py suffix
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    loader.exec_module(mod)
    return mod


def changed_functions(pre_src: str, post_src: str) -> set:
    """Top-level def names whose source segment differs (added/removed/changed)."""
    def defs(src):
        try:
            tree = ast.parse(src)
        except SyntaxError:
            return {}
        out = {}
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out[n.name] = ast.get_source_segment(src, n) or ""
        return out
    a, b = defs(pre_src), defs(post_src)
    changed = set()
    for name in set(a) | set(b):
        if a.get(name) != b.get(name):
            changed.add(name)
    return changed


def one_hop_callers(post_src: str, target: str) -> set:
    """Names of top-level funcs whose body references `target` (static 1-hop)."""
    try:
        tree = ast.parse(post_src)
    except SyntaxError:
        return set()
    callers = set()
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(n):
                if isinstance(sub, ast.Name) and sub.id == target:
                    callers.add(n.name)
    return callers


def call(fn, m, args):
    try:
        return ("ok", repr(fn(m, args)))
    except Exception as exc:  # noqa: BLE001 — behaviour comparison
        return ("exc", type(exc).__name__ + ":" + str(exc)[:60])


def main() -> int:
    cfg = json.loads(open(sys.argv[1]).read())
    spec = anchorspec.load(cfg)
    repo = cfg["repo"]
    if repo not in sys.path:
        sys.path.insert(0, repo)
    anchor_file = cfg["anchor_file"]
    anchor_func = cfg["anchor_func"]
    registry = build_registry(spec)

    STATE = {"touch": False}

    out_of_scope, in_scope = [], []
    compared = 0
    covered_changed = set()
    all_changed = {}       # rel -> set(changed func names)

    for rel in cfg["changed"]:
        pre_p = cfg["pre_images"].get(rel)
        post_p = cfg["post_images"].get(rel)
        if not pre_p or not post_p:
            continue
        pre_src = open(pre_p).read()
        post_src = open(post_p).read()
        all_changed[rel] = changed_functions(pre_src, post_src)

    for rel in cfg["changed"]:
        funcs = registry.get(rel)
        if not funcs:
            continue
        i = rel.replace("/", "_").replace(".", "_")
        pre = load(cfg["pre_images"][rel], "_pre_" + i)
        post = load(cfg["post_images"][rel], "_post_" + i)

        # touch flag on the anchor function in its PRE image
        if rel == anchor_file and hasattr(pre, anchor_func):
            orig = getattr(pre, anchor_func)

            def wrapped(*a, __o=orig, **k):
                STATE["touch"] = True
                return __o(*a, **k)
            setattr(pre, anchor_func, wrapped)

        for fname, (corpus, caller) in funcs.items():
            covered_changed.add((rel, fname))
            for args in corpus:
                STATE["touch"] = False
                a = call(caller, pre, args)
                touched = STATE["touch"]
                b = call(caller, post, args)
                compared += 1
                if a != b:
                    rec = [rel, fname, repr(args)[:80], a, b]
                    (in_scope if touched else out_of_scope).append(rec)

    # coverage of changed out-of-anchor functions
    uncovered = []
    for rel, names in all_changed.items():
        post_src = open(cfg["post_images"][rel]).read() if rel in cfg["post_images"] else ""
        reg = registry.get(rel, {})
        for name in names:
            if rel == anchor_file and name == anchor_func:
                continue
            if name in reg:
                continue
            # covered if a registered entry-point of this module calls it (1-hop)
            callers = one_hop_callers(post_src, name)
            if callers & set(reg):
                continue
            uncovered.append(f"{rel}:{name}")

    # ---- fail closed when nothing was actually compared ------------------ #
    # MEASURED (v13, first real repository): this gate's input generator is
    # written for the synthetic anchor `_is_allowed(path, allowed)` -- two
    # arguments, path-shaped.  Pointed at mutatest's
    # `get_cache_file_loc(src_file)` every generated call raised on arity, every
    # comparison was skipped, and the gate printed
    #     {"compared_calls": 0, ..., "pass": true}
    # A patch carrying a plain side effect (M3_side_effect) walked through it.
    #
    # A gate that passes while comparing nothing is worse than a gate that is
    # switched off, because the report says it checked.  So: zero comparisons is
    # never a pass.  It is reported as INAPPLICABLE with the reason, and the
    # exit status is non-zero so the pipeline cannot read it as green.
    inapplicable = compared == 0
    ok = (not inapplicable) and (not out_of_scope) and (not uncovered)
    result = {
        "compared_calls": compared,
        "inapplicable": inapplicable,
        "fail_reason": ("no call was comparable -- the input generator produced "
                        "nothing this anchor accepts (check --anchor-func and "
                        "its signature)" if inapplicable else None),
        "out_of_scope_divergences": len(out_of_scope),
        "out_of_scope_sample": out_of_scope[:8],
        "in_scope_divergences": len(in_scope),
        "in_scope_sample": in_scope[:4],
        "uncovered_changed_functions": uncovered,
        "changed_functions": {k: sorted(v) for k, v in all_changed.items()},
        "pass": ok,
    }
    print(json.dumps(result, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
