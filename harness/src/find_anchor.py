"""find_anchor.py -- turn a review finding into candidate anchors.

WHY THIS EXISTS
---------------
v8 pointed the harness at a real repository and recorded where the setup time
went.  The answer was unambiguous:

    "anchor identification (file:line + the quotable contract text)
     cost: the whole of the 25 minutes.  Nothing in the harness finds an
     anchor; a human (or an LLM lens) reads the module."

Everything else in that setup was already automatic or a one-line flag.  So the
harness's remaining manual step is this one, and it is mostly mechanical: the
finding already names a file and lines -- Phase 2's 層1 requires a *quotable*
anchor, so a convertible finding always does.  What was missing is the step that
maps those lines onto the enclosing function and pulls out the text the oracle
is allowed to quote.

WHAT IT DOES NOT DO
-------------------
It does not decide which candidate is right, and it does not write the anchor
spec's `calls` or `templates`.  Choosing the level (the function the finding is
about may be a helper, and the anchor the gates should drive may be its caller)
is a judgement, and the input domain is a design decision -- D19 exists because
neither is mechanical.  This narrows the reading to a ranked short list and puts
the quotable material next to it.

WHAT COUNTS AS QUOTABLE (Phase 2 層1 / D1 段2)
----------------------------------------------
Text that is in the PRE-fix source and that an agent writing the fix cannot
rewrite in its own favour:

  * the function's docstring          -- what it claims to do
  * parameter and return annotations  -- the contract's shape
  * the messages of its own raises/asserts -- the conditions it names
  * comparisons against literals      -- the boundaries it already draws

Those four are exactly what the F1/F4 oracles on mutatest were built from
("the annotation Union[str, Path]" and "the guard's own message").

usage:
    find_anchor.py <repo> --finding-file FILE      # a review finding, free text
    find_anchor.py <repo> --at path/to/f.py:48,62  # explicit file:lines
    [--json OUT] [--top N]
"""

from __future__ import annotations

import ast
import json
import pathlib
import re
import sys

# The line spec is matched explicitly rather than lazily: a lazy [0-9,-]+?
# whose lookahead contains a comma stops at the first comma, so
# "cache.py:48,62" yielded only 48 -- measured.
_NUM = r'\d+(?:\s*-\s*\d+)?'
CITE = re.compile(r'([\w./\\-]+\.py):(' + _NUM + r'(?:\s*,\s*' + _NUM + r')*)')


def parse_linespec(spec: str) -> set:
    """'48,62' or '99-101,124-126' -> {48, 62} / {99..101, 124..126}"""
    out: set = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a.isdigit() and b.isdigit():
                out.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.add(int(part))
    return out


def citations(text: str) -> dict:
    """{relpath: {lines}} for every `file.py:lines` in a finding."""
    out: dict = {}
    for m in CITE.finditer(text):
        rel, spec = m.group(1).replace("\\", "/"), m.group(2)
        lines = parse_linespec(spec)
        if lines:
            out.setdefault(rel, set()).update(lines)
    return out


class Fn:
    def __init__(self, node, src_lines, rel):
        self.node = node
        self.rel = rel
        self.name = node.name
        self.lo = node.lineno
        self.hi = getattr(node, "end_lineno", node.lineno)
        self.src_lines = src_lines

    @property
    def span(self):
        return set(range(self.lo, self.hi + 1))

    def signature(self) -> dict:
        a = self.node.args
        pos = [p.arg for p in a.posonlyargs] + [p.arg for p in a.args]
        ann = {}
        for p in a.posonlyargs + a.args + a.kwonlyargs:
            if p.annotation is not None:
                ann[p.arg] = ast.unparse(p.annotation)
        return {"positional": pos,
                "kwonly": [p.arg for p in a.kwonlyargs],
                "vararg": a.vararg.arg if a.vararg else None,
                "kwarg": a.kwarg.arg if a.kwarg else None,
                "annotations": ann,
                "returns": ast.unparse(self.node.returns)
                if self.node.returns else None,
                "n_positional": len(pos)}

    def quotable(self) -> dict:
        """The four kinds of pre-fix text an oracle may cite (see module doc)."""
        doc = ast.get_docstring(self.node)
        raises, compares = [], []
        for n in ast.walk(self.node):
            if isinstance(n, ast.Raise) and n.exc is not None:
                try:
                    raises.append(ast.unparse(n.exc))
                except Exception:                               # noqa: BLE001
                    pass
            elif isinstance(n, ast.Assert) and n.msg is not None:
                try:
                    raises.append("assert ... , " + ast.unparse(n.msg))
                except Exception:                               # noqa: BLE001
                    pass
            elif isinstance(n, ast.Compare):
                for c in n.comparators:
                    if isinstance(c, ast.Constant):
                        try:
                            compares.append(ast.unparse(n))
                        except Exception:                       # noqa: BLE001
                            pass
                        break
        sig = self.signature()
        return {"docstring": doc,
                "annotations": sig["annotations"],
                "returns": sig["returns"],
                "raises": raises[:8],
                "literal_comparisons": sorted(set(compares))[:8]}


def functions(repo: pathlib.Path, rel: str):
    path = repo / rel
    if not path.exists():
        return None, "file not found: %s" % rel
    try:
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
    except Exception as exc:                                    # noqa: BLE001
        return None, "%s: %s" % (type(exc).__name__, exc)
    lines = src.splitlines()
    out = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(Fn(n, lines, rel))
    return out, None


def callers_of(fns, name: str) -> list:
    """Which functions in this file call `name` -- the caller may be the anchor
    the gates should drive (D2's altitude question), so it is reported."""
    out = []
    for f in fns:
        if f.name == name:
            continue
        for n in ast.walk(f.node):
            if isinstance(n, ast.Call):
                t = n.func
                nm = getattr(t, "id", None) or getattr(t, "attr", None)
                if nm == name:
                    out.append(f.name)
                    break
    return sorted(set(out))


def rank(repo: pathlib.Path, cites: dict, top: int) -> list:
    cands = []
    for rel, lines in cites.items():
        fns, err = functions(repo, rel)
        if fns is None:
            cands.append({"file": rel, "error": err})
            continue
        for f in fns:
            hit = f.span & lines
            if not hit:
                continue
            # innermost wins: a nested def covering the same lines is a tighter
            # reading of the finding than the function that contains it.
            enclosing = sum(1 for g in fns
                            if g is not f and f.span <= g.span)
            cands.append({
                "anchor": "%s:%s" % (rel, f.name),
                "file": rel, "func": f.name,
                "lines": [f.lo, f.hi],
                "cited_lines_hit": sorted(hit),
                "n_hit": len(hit),
                "nesting_depth": enclosing,
                "private": f.name.startswith("_"),
                "signature": f.signature(),
                "quotable": f.quotable(),
                "in_file_callers": callers_of(fns, f.name),
            })
    cands.sort(key=lambda c: (-c.get("n_hit", 0), -c.get("nesting_depth", 0),
                              c.get("func", "")))
    return cands[:top]


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    repo = pathlib.Path(sys.argv[1])

    def opt(flag, default=None):
        return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default

    top = int(opt("--top", "5"))
    text = ""
    if "--finding-file" in sys.argv:
        text = pathlib.Path(opt("--finding-file")).read_text(encoding="utf-8")
    if "--at" in sys.argv:
        text += "\n" + opt("--at")
    if not text.strip():
        print("nothing to read: pass --finding-file and/or --at")
        return 2

    cites = citations(text)
    if not cites:
        print(json.dumps({"error": "no `file.py:line` citation found in the "
                                   "finding.  Phase 2 層1 requires a quotable "
                                   "anchor, so a finding without one is not "
                                   "convertible as written.",
                          "hint": "pass --at path/to/file.py:LINES"}, indent=1))
        return 1

    cands = rank(repo, cites, top)
    report = {"repo": str(repo),
              "citations": {k: sorted(v) for k, v in cites.items()},
              "n_candidates": len(cands), "candidates": cands}
    if "--json" in sys.argv:
        pathlib.Path(opt("--json")).write_text(
            json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")

    print("cited: %s" % ", ".join("%s:%s" % (k, ",".join(map(str, sorted(v)[:6])))
                                  for k, v in cites.items()))
    print()
    for i, c in enumerate(cands, 1):
        if "error" in c:
            print("%d. %-30s %s" % (i, c["file"], c["error"]))
            continue
        s = c["signature"]
        print("%d. %-34s lines %d-%d   hits %d   arity %d%s"
              % (i, c["anchor"], c["lines"][0], c["lines"][1], c["n_hit"],
                 s["n_positional"], "  (nested)" if c["nesting_depth"] else ""))
        if s["annotations"] or s["returns"]:
            print("     signature : (%s)%s"
                  % (", ".join("%s: %s" % (k, v)
                               for k, v in s["annotations"].items()) or
                     ", ".join(s["positional"]),
                     " -> " + s["returns"] if s["returns"] else ""))
        q = c["quotable"]
        if q["docstring"]:
            first = q["docstring"].strip().splitlines()[0]
            print("     docstring : %s" % first[:88])
        for r in q["raises"][:2]:
            print("     raises    : %s" % r[:88])
        for cm in q["literal_comparisons"][:2]:
            print("     compares  : %s" % cm[:88])
        if c["in_file_callers"]:
            print("     called by : %s   <- the caller may be the right altitude"
                  % ", ".join(c["in_file_callers"][:4]))
        print()
    print("Pick one, then write its anchor spec (see anchorspec.py).  The "
          "quotable text above is what Phase 2 層1 lets the oracle cite; the "
          "input domain is still a design decision (D19).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
