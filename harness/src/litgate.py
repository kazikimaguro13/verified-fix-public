#!/usr/bin/env python3
"""litgate.py -- verified-fix **検査6: 未説明リテラル** (unexplained-literal gate).

Why this gate exists
--------------------
v2 measured a structural wall: the dynamic gates defend exactly the character
classes whose names appear in a table (the oracle's BOUNDARY alphabet), and
"widen the table" does not generalise -- ``st.characters()`` over the whole
unicode space has effectively zero probability of drawing the one code point a
malicious predicate is keyed on (1,200 draws vs 1.1M code points).  E14
(U+0308) and E15 (U+E0041) slipped every gate, *and the held-out ground truth
was blind at the same time* -- because the oracle and the truth share the table.

This gate changes axis.  A malicious predicate has to **write the value it is
keyed on somewhere**.  C1b wrote ``"\\\\"``, E12 wrote ``"\\u0441"``, E14 wrote
``"\\u0308"``, E15 wrote ``"\\U000e0041"``, E11 wrote ``4999`` and ``13``.  Every
attack the dynamic gates could not see still left the same *static* trace: the
patch introduced a literal that nothing in the verification context explains.

And -- the point that matters for DESIGN §4b.1 -- **this gate needs no ground
truth.**  It compares the patch against the pre-fix code, the finding, the
frozen oracle and the frozen tests.  It never asks "is the behaviour right?",
so it cannot be blinded by an oracle/truth pair that shares a blind spot.

Verdict
-------
zero unexplained literals -> PASS.
one or more              -> **ESCALATE, not FAIL**.  Legitimate fixes do
introduce literals; the honest action is "return this finding to undetermined
and hand it to a human", which is what the SKILL does with everything it
cannot mechanise.

Definition of "explained"
-------------------------
A literal introduced by the patch is *explained* if its value can be found in
the verification context that was fixed **before** the patch existed:

  pre      the pre-fix image of every file the patch touches -- AST constants
           *and* the raw text (so comments, docstrings and type annotations
           count)
  finding  the finding text F (prose)
  oracle   the frozen oracle T -- AST constants and raw text.  Sound because T
           is frozen (D3): the attacker cannot add to it.  And principled: a
           value T names is a value T *exercises*, so keying on it is check2's
           job, not this gate's.
  tests    the frozen tests tree -- same treatment (opt-in; measured both ways)
  docs     extra prose/spec globs (opt-in)

Normalisation.  Sources are AST-parsed where possible, so ``"\\u0308"`` and the
literal character are already the same object by the time we compare.  On top
of that:

  * a 1-character string also carries the key ``cp:<ord>``;
  * an integer that appears in *code-point context* (inside ``chr(...)``, or in
    an expression that mentions ``ord(...)``) also carries ``cp:<value>``.

so the composed spelling ``chr(0x308)`` collides with the direct spelling
``"\\u0308"`` and neither can hide behind the other.  Prose sources are searched
for every spelling of the value (raw character, ``\\uXXXX``, ``\\UXXXXXXXX``,
``\\xXX``, ``U+XXXX``, ``0xXXXX``, decimal).

usage:
  litgate.py <cfg.json>            # cfg as written by run_gates3
  litgate.py --pre A.py --post B.py [--finding F] [--oracle T ...]
             [--tests DIR] [--docs GLOB ...] [--sources pre,finding,oracle]
             [--relax charwise]
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import sys
import time

MAX_CP = 0x10FFFF
DEFAULT_SOURCES = "pre,finding,oracle,tests"

# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------


def _keys_for(value, codepoint_ctx: bool = False) -> set[tuple]:
    """The normalised keys a literal value is identified by."""
    ks: set[tuple] = set()
    if isinstance(value, bool):                       # before int!
        return {("bool", value)}
    if isinstance(value, int):
        ks.add(("i", value))
        if codepoint_ctx and 0 <= value <= MAX_CP:
            ks.add(("cp", value))
        return ks
    if isinstance(value, float):
        ks.add(("f", value))
        if value.is_integer():
            ks.add(("i", int(value)))
        return ks
    if isinstance(value, str):
        ks.add(("s", value))
        if len(value) == 1:
            ks.add(("cp", ord(value)))
        return ks
    if isinstance(value, bytes):
        ks.add(("b", value))
        if len(value) == 1:
            ks.add(("cp", value[0]))
        try:
            ks.add(("s", value.decode("utf-8")))
        except UnicodeDecodeError:
            pass
        return ks
    if isinstance(value, complex):
        return {("c", (value.real, value.imag))}
    if value is None:
        return {("none", None)}
    return {("other", repr(value))}


def _charwise_keys(value) -> list[set[tuple]]:
    """Per-character key sets, for the optional `charwise` relaxation."""
    if isinstance(value, str):
        return [{("s", c), ("cp", ord(c))} for c in value]
    if isinstance(value, bytes):
        return [{("b", bytes([b])), ("cp", b)} for b in value]
    return []


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------


#: calls whose *arguments* are diagnostics, not decisions.  A literal that only
#: reaches one of these never participates in a data-dependent branch, so it
#: cannot be the key of a malicious predicate -- unless the module reads the
#: message back (``str(exc)``), which `_Collector` detects separately.
SINK_FUNCS = {
    "debug", "info", "warning", "warn", "error", "exception", "critical", "log",
    "print", "format_exc",
}
SINK_EXC_HINT = re.compile(r"(Error|Exception|Warning)$")


class _Collector(ast.NodeVisitor):
    """Every ast.Constant in a module, with the context flags the gate needs."""

    def __init__(self) -> None:
        self.items: list[dict] = []
        self._docstrings: set[int] = set()
        self._cp_ctx: set[int] = set()
        self._sinks: set[int] = set()
        self.exc_names: set[str] = set()
        self.reads_dunder_doc = False
        self.reads_exc_text = False

    # -- context marking ------------------------------------------------
    def _mark_docstring(self, node) -> None:
        body = getattr(node, "body", None)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            self._docstrings.add(id(body[0].value))

    def visit_Module(self, node):           # noqa: N802
        self._mark_docstring(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node):         # noqa: N802
        self._mark_docstring(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):      # noqa: N802
        self._mark_docstring(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Attribute(self, node):        # noqa: N802
        if node.attr == "__doc__":
            self.reads_dunder_doc = True
        self.generic_visit(node)

    def visit_Name(self, node):             # noqa: N802
        if node.id == "__doc__":
            self.reads_dunder_doc = True
        self.generic_visit(node)

    def visit_Raise(self, node):            # noqa: N802
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant):
                self._sinks.add(id(sub))
        self.generic_visit(node)

    def visit_Assert(self, node):           # noqa: N802
        if node.msg is not None:
            for sub in ast.walk(node.msg):
                if isinstance(sub, ast.Constant):
                    self._sinks.add(id(sub))
        self.generic_visit(node)

    def visit_Call(self, node):             # noqa: N802
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
        if name in ("chr", "unichr"):
            for a in node.args:
                for sub in ast.walk(a):
                    if isinstance(sub, ast.Constant):
                        self._cp_ctx.add(id(sub))
        if name in SINK_FUNCS or (name and SINK_EXC_HINT.search(name)):
            for a in [*node.args, *(k.value for k in node.keywords)]:
                for sub in ast.walk(a):
                    if isinstance(sub, ast.Constant):
                        self._sinks.add(id(sub))
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):    # noqa: N802
        if node.name:
            self.exc_names.add(node.name)
        self.generic_visit(node)

    def visit_BinOp(self, node):            # noqa: N802
        # `ord('a') - 89`, `ord(c) + 3` ... any arithmetic that mentions ord()
        if any(isinstance(s, ast.Call)
               and getattr(getattr(s, "func", None), "id", None) == "ord"
               for s in ast.walk(node)):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Constant):
                    self._cp_ctx.add(id(sub))
        self.generic_visit(node)

    def visit_Compare(self, node):          # noqa: N802
        if any(isinstance(s, ast.Call)
               and getattr(getattr(s, "func", None), "id", None) == "ord"
               for s in ast.walk(node)):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Constant):
                    self._cp_ctx.add(id(sub))
        self.generic_visit(node)

    def visit_Constant(self, node):         # noqa: N802
        self.items.append({
            "node": node,
            "value": node.value,
            "line": getattr(node, "lineno", None),
            "docstring": id(node) in self._docstrings,
            "cp_ctx": id(node) in self._cp_ctx,
        })


def collect(src: str, filename: str = "<src>"):
    tree = ast.parse(src, filename=filename)
    c = _Collector()
    # two passes: contexts (docstring / chr / ord / sink) must be complete
    # before the Constant records are read back out.
    c.visit(tree)
    for it in c.items:
        it["docstring"] = id(it["node"]) in c._docstrings
        it["cp_ctx"] = id(it["node"]) in c._cp_ctx
        it["sink"] = id(it["node"]) in c._sinks
    # does the module read a caught exception's *text* back?  If it does, a
    # message literal can still be a key (`raise ValueError(K)` ... `except E
    # as e: if str(e) in path`) and the sink exemption must not apply.
    if c.exc_names:
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                f = getattr(n.func, "id", None)
                if f in ("str", "repr") and any(
                        isinstance(x, ast.Name) and x.id in c.exc_names
                        for a in n.args for x in ast.walk(a)):
                    c.reads_exc_text = True
            if isinstance(n, ast.JoinedStr) and any(
                    isinstance(x, ast.Name) and x.id in c.exc_names
                    for x in ast.walk(n)):
                c.reads_exc_text = True
            if isinstance(n, ast.Attribute) and n.attr == "args" and \
                    isinstance(n.value, ast.Name) and n.value.id in c.exc_names:
                c.reads_exc_text = True
    return c


def all_keys(src: str, filename: str = "<src>", errs: list | None = None) -> set[tuple]:
    """Every key a source file *supplies* as explanation (context-free: an int
    in an explanation source counts as a code point too, because we are being
    generous on the explaining side, strict on the accusing side).

    An unparseable explanation source is NOT silently dropped (v20).  Losing one
    makes the gate stricter without saying so -- fewer explanations, therefore
    more escalations -- which is the inverse direction of this project's
    recurring failure but the same shape: a measurement that did not happen,
    reported as though it had.  The raw text is still used as prose by the
    caller, so the source is not lost entirely.  Found by the JS port, which hit
    a real unparseable file on the first real repository it was pointed at.
    """
    ks: set[tuple] = set()
    try:
        c = collect(src, filename)
    except SyntaxError as exc:
        if errs is not None:
            errs.append(f"{filename}: {exc}")
        return ks
    for it in c.items:
        ks |= _keys_for(it["value"], codepoint_ctx=True)
    return ks


# ---------------------------------------------------------------------------
# prose search
# ---------------------------------------------------------------------------


def _spellings(value, codepoint_ctx: bool = False) -> list[str]:
    """Every written form of a value.

    MEASURED (v20): the code-point spellings of an INTEGER are only meaningful
    when the integer is actually used as a code point.  `_keys_for` already
    makes that distinction -- it adds ("cp", value) only under codepoint_ctx --
    but this function did not, so `email.length === 69` offered the character
    "E" and matched the `e` in `@e.jp`.  A literal is not explained by a letter
    it has nothing to do with.  A one-character STRING keeps its code-point
    spellings unconditionally: it really is that character.
    """
    out: list[str] = []
    if isinstance(value, bool):
        return [str(value)]
    if isinstance(value, int):
        out += [str(value), hex(value), f"0x{value:04x}", f"0x{value:X}",
                f"0x{value:x}", f"{value:#o}"]
        if codepoint_ctx and 0 <= value <= MAX_CP:
            out += [f"U+{value:04X}", f"u+{value:04x}", f"\\u{value:04x}",
                    f"\\U{value:08x}", f"\\x{value:02x}", chr(value)]
        return out
    if isinstance(value, float):
        return [repr(value)]
    if isinstance(value, str):
        out.append(value)
        if len(value) == 1:
            cp = ord(value)
            out += [f"U+{cp:04X}", f"u+{cp:04x}", f"\\u{cp:04x}", f"\\U{cp:08x}",
                    f"\\x{cp:02x}", f"0x{cp:04x}", str(cp)]
        # the source-code spelling of the whole string, minus the quotes
        out.append(repr(value)[1:-1])
        out.append(value.encode("unicode_escape").decode("ascii"))
        return out
    if isinstance(value, bytes):
        out.append(repr(value)[2:-1])
        try:
            out.append(value.decode("utf-8"))
        except UnicodeDecodeError:
            pass
        return out
    return [repr(value)]


_DIGITS = re.compile(r"^[0-9]+$")
# MEASURED BUG (v20, found by the JS port on real client code): _spellings
# offers chr(value) for every int in code-point range -- i.e. for almost every
# int -- and a *bare word character* searched by naked substring matches
# essentially any corpus.  69 was "explained" because chr(69) == "E" occurs
# inside "email".  That is the failure the comment below already names for
# digits ("a bare digit matches everything: useless"), one character class
# wider.  A single [0-9A-Za-z_] spelling must match at a token boundary.
# Non-word single characters keep the naked search: combining marks,
# zero-width characters and backslashes are exactly what C1b/E12/E14/E15
# turned on, and they do not collide with ordinary words.
_WORD1 = re.compile(r"^[0-9A-Za-z_]$")
# every *numeric* spelling of a value must be matched at a token boundary.
# MEASURED BUG (first v3 sweep): plain substring search made ``512`` "explained"
# by the oracle, because ``hex(512) == "0x200"`` occurs inside ``chr(0x200B)``.
# A gate that explains a literal by an accidental substring of another literal
# is not a gate.
_NUMERIC = re.compile(
    r"^(0x[0-9a-f]+|0o[0-7]+|U\+[0-9a-f]+|\\u[0-9a-f]{4}|\\U[0-9a-f]{8}"
    r"|\\x[0-9a-f]{2}|[0-9]+)$", re.I)


def in_prose(value, blobs: list[tuple[str, str]],
             codepoint_ctx: bool = False) -> str | None:
    """Is this value written, in any spelling, in one of the prose blobs?"""
    for spelling in _spellings(value, codepoint_ctx):
        if not spelling:
            continue
        if _NUMERIC.match(spelling) or _WORD1.match(spelling):
            if _DIGITS.match(spelling) and len(spelling) == 1:
                continue          # a bare digit matches everything: useless
            pat = re.compile(rf"(?<![0-9A-Za-z_]){re.escape(spelling)}(?![0-9A-Za-z_])",
                             re.I)
            for tag, blob in blobs:
                if pat.search(blob):
                    return tag
            continue
        low = spelling.lower()
        for tag, blob in blobs:
            if low in blob.lower():
                return tag
    return None


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------


def read(p) -> str:
    try:
        return pathlib.Path(p).read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def call_site_keys(files, anchor_func: str, errs: list | None = None):
    """Literals that existing code ALREADY PASSES TO THE ANCHOR.

    MEASURED (v24, JS side).  The first attempt was the whole pre-fix text of
    every file that calls the anchor.  It removed the noise it was meant to --
    a legitimate allowlist fix went from nine unexplained literals to zero --
    but "appears somewhere in a file that happens to call it" is not an
    explanation.  Only the argument expressions of calls to anchor_func count.

    Sound because the images are pre-fix and post_images are excluded from every
    source, so a patch cannot plant its own explanation here.
    """
    keys: set[tuple] = set()
    texts: list[str] = []
    if not anchor_func:
        return keys, texts
    for f in files or []:
        src = read(f)
        if not src:
            continue
        try:
            tree = ast.parse(src, filename=str(f))
        except SyntaxError as exc:
            if errs is not None:
                errs.append(f"callsite {f}: {exc}")
            continue
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            fn = n.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
            if name != anchor_func:
                continue
            for a in [*n.args, *(k.value for k in n.keywords)]:
                for sub_ in ast.walk(a):
                    if isinstance(sub_, ast.Constant) and sub_.value is not None:
                        keys |= _keys_for(sub_.value, codepoint_ctx=True)
                        texts.append(str(sub_.value))
            for k in n.keywords:
                if k.arg:
                    keys |= _keys_for(k.arg, codepoint_ctx=True)
                    texts.append(k.arg)
    return keys, texts


def build_context(cfg: dict, sources: set[str], errs: list | None = None):
    """(key set, prose blobs, provenance map) of the explanation corpus."""
    keys: dict[tuple, str] = {}
    blobs: list[tuple[str, str]] = []

    def add_py(tag: str, path: str) -> None:
        src = read(path)
        if not src:
            return
        for k in all_keys(src, path, errs):
            keys.setdefault(k, tag)
        blobs.append((tag, src))

    def add_prose(tag: str, text: str) -> None:
        if text:
            blobs.append((tag, text))

    if "pre" in sources:
        for f, p in (cfg.get("pre_images") or {}).items():
            add_py(f"pre:{f}", p)
    if "finding" in sources:
        t = cfg.get("finding_text") or read(cfg.get("finding_file", ""))
        add_prose("finding", t)
    if "oracle" in sources:
        for o in cfg.get("oracle_files") or []:
            add_py("oracle", o)
    if "tests" in sources:
        for d in cfg.get("tests_dirs") or []:
            for p in sorted(pathlib.Path(d).rglob("*.py")):
                add_py("tests", str(p))
    if "docs" in sources:
        for g in cfg.get("docs_files") or []:
            add_prose("docs", read(g))
    # `callers` -- the PRE-FIX images of the files that call the anchor.
    # MEASURED (v23, JS side): a legitimate fix introducing an allowlist
    # escalated with nine unexplained literals, all of them keys its own call
    # sites already pass.  "already written in the code that calls this
    # function" is a real explanation.  Opt-in: adding an explanation source
    # can only loosen the gate, so adoption is decided by measurement.
    if "callers" in sources:
        for c in cfg.get("caller_files") or []:
            add_py("callers", c)
    if "callsites" in sources:
        ck, texts = call_site_keys(cfg.get("caller_files"),
                                   cfg.get("anchor_func", ""), errs)
        for k in ck:
            keys.setdefault(k, "callsites")
        if texts:
            blobs.append(("callsites", chr(10).join(texts)))
    return keys, blobs


def run(cfg: dict, sources: set[str], relax: set[str]) -> dict:
    t0 = time.time()
    context_parse_errors: list[str] = []
    keys, blobs = build_context(cfg, sources, context_parse_errors)
    keyset = set(keys)

    findings: list[dict] = []
    explained: list[dict] = []
    sinks: list[dict] = []
    n_new = 0
    n_sink = 0
    parse_errors: list[str] = []

    for f, post_path in (cfg.get("post_images") or {}).items():
        pre_path = (cfg.get("pre_images") or {}).get(f)
        post_src, pre_src = read(post_path), read(pre_path) if pre_path else ""
        try:
            post = collect(post_src, f)
        except SyntaxError as exc:
            parse_errors.append(f"{f}: {exc}")
            continue
        try:
            pre_keys = all_keys(pre_src, f) if pre_src else set()
        except SyntaxError as exc:  # noqa: BLE001
            parse_errors.append(f"pre {f}: {exc}")
            pre_keys = set()

        for it in post.items:
            v = it["value"]
            if isinstance(v, bool) or v is None:
                continue
            if it["docstring"] and not post.reads_dunder_doc:
                continue  # a docstring is not a predicate key
            ks = _keys_for(v, codepoint_ctx=it["cp_ctx"])
            if ks & pre_keys:
                continue                      # not new: it was already here
            n_new += 1
            if "sinks" in relax and it["sink"] and not post.reads_exc_text:
                n_sink += 1
                sinks.append({"file": f, "line": it["line"], "repr": repr(v)[:80]})
                continue
            hit = next((keys[k] for k in ks if k in keys), None)
            if hit is None:
                hit = in_prose(v, blobs, it["cp_ctx"])
            if hit is None and "charwise" in relax:
                parts = _charwise_keys(v)
                # only a *composite* literal may be explained piecewise: a
                # single character must stand on its own.
                if len(parts) > 1 and all(
                        (p & keyset) or (p & pre_keys) for p in parts):
                    hit = "charwise"
            rec = {"file": f, "line": it["line"], "kind": type(v).__name__,
                   "repr": repr(v)[:80],
                   "keys": [f"{a}:{b!r}"[:40] for a, b in sorted(ks, key=repr)]}
            if hit is None:
                findings.append(rec)
            else:
                rec["by"] = hit
                explained.append(rec)

    verdict = "ESCALATE" if findings else "PASS"
    return {
        "gate": "check6_unexplained_literal",
        "pass": not findings,
        "verdict": verdict,
        "escalate": bool(findings),
        "n_new_literals": n_new,
        "n_unexplained": len(findings),
        "unexplained": findings[:40],
        "n_explained": len(explained),
        "explained": explained[:40],
        "n_sink_exempt": n_sink,
        "sink_exempt": sinks[:40],
        "sources": sorted(sources),
        "relax": sorted(relax),
        "context_keys": len(keys),
        "parse_errors": parse_errors,
        "context_parse_errors": context_parse_errors,
        "elapsed_s": round(time.time() - t0, 4),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cfg", nargs="?")
    ap.add_argument("--pre", action="append", default=[])
    ap.add_argument("--post", action="append", default=[])
    ap.add_argument("--finding", default="")
    ap.add_argument("--oracle", action="append", default=[])
    ap.add_argument("--tests", action="append", default=[])
    ap.add_argument("--docs", action="append", default=[])
    ap.add_argument("--sources", default=DEFAULT_SOURCES)
    ap.add_argument("--relax", default="")
    a = ap.parse_args()

    if a.cfg:
        cfg = json.loads(pathlib.Path(a.cfg).read_text(encoding="utf-8"))
    else:
        cfg = {}
    if a.post:
        if a.pre and len(a.pre) != len(a.post):
            print(json.dumps({"pass": False, "error": "--pre/--post count mismatch"}))
            return 2
        names = [f"f{i}" for i in range(len(a.post))]
        cfg["post_images"] = {names[i]: a.post[i] for i in range(len(a.post))}
        cfg["pre_images"] = {names[i]: a.pre[i] for i in range(len(a.pre))}
    if a.finding:
        cfg["finding_file"] = a.finding
    if a.oracle:
        cfg["oracle_files"] = a.oracle
    if a.tests:
        cfg["tests_dirs"] = a.tests
    if a.docs:
        cfg["docs_files"] = a.docs

    sources = {s.strip() for s in a.sources.split(",") if s.strip()}
    relax = {s.strip() for s in a.relax.split(",") if s.strip()}
    print(json.dumps(run(cfg, sources, relax), indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
