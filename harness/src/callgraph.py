#!/usr/bin/env python3
"""callgraph.py -- mechanically enumerate the *altitudes* above an anchor.

DESIGN 4b.3 records the open question this answers: T' picks **one** call-site
by hand, so "which boundary do you write the property at" was a human judgement
and therefore not a general answer.  This walks the repo's AST instead.

An *altitude* is one level of the reverse call graph rooted at the anchor:

    altitude 0   the anchor itself                 ccd/guard_pathmatch.py:_is_allowed
    altitude 1   every in-repo function that calls it
    altitude 2   every in-repo function that calls one of those
    ...

Deliberately conservative and deliberately *stated*:

  * name-based resolution (a call to ``foo(...)``/``x.foo(...)`` is credited to
    every def named ``foo``).  Over-approximates, never under-approximates,
    which is the safe direction for a defence.
  * ``tests/`` and ``registry/`` are excluded: they are the verification
    context, not the product's call graph.  They are reported separately so
    "the only caller is a test" cannot hide.
  * **the enumeration is repo-bounded.**  A caller that lives outside this
    repository (a downstream importer of ``ccd.guard``) is invisible here and
    therefore invisible to any altitude property derived from it.  That bound
    is the thing to attack, and v6 does.

usage: callgraph.py <repo> <file.py:func> [--depth N] [--json]
"""

from __future__ import annotations

import ast
import json
import pathlib
import sys

SKIP_PARTS = {"__pycache__", ".git", ".hypothesis", ".pytest_cache", "venv",
              ".venv", "node_modules"}


class Fn:
    __slots__ = ("rel", "qual", "name", "lineno", "calls")

    def __init__(self, rel, qual, name, lineno):
        self.rel, self.qual, self.name, self.lineno = rel, qual, name, lineno
        self.calls: set[str] = set()

    def key(self):
        return f"{self.rel}:{self.qual}"


def collect(repo: pathlib.Path):
    fns: list[Fn] = []
    for p in sorted(repo.rglob("*.py")):
        if any(part in SKIP_PARTS for part in p.parts):
            continue
        rel = str(p.relative_to(repo))
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        stack: list[str] = []

        def walk(node, stack=stack):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qual = ".".join(stack + [child.name])
                    fn = Fn(rel, qual, child.name, child.lineno)
                    for sub in ast.walk(child):
                        if isinstance(sub, ast.Call):
                            f = sub.func
                            if isinstance(f, ast.Name):
                                fn.calls.add(f.id)
                            elif isinstance(f, ast.Attribute):
                                fn.calls.add(f.attr)
                    fns.append(fn)
                    stack.append(child.name)
                    walk(child)
                    stack.pop()
                elif isinstance(child, ast.ClassDef):
                    stack.append(child.name)
                    walk(child)
                    stack.pop()
                else:
                    walk(child)

        walk(tree)
    return fns


def is_verification(rel: str) -> bool:
    return rel.startswith("tests/") or rel.startswith("registry/") \
        or pathlib.Path(rel).name.startswith("test_")


def main() -> int:
    repo = pathlib.Path(sys.argv[1])
    anchor = sys.argv[2]
    depth = 3
    if "--depth" in sys.argv:
        depth = int(sys.argv[sys.argv.index("--depth") + 1])
    arel, _, afunc = anchor.partition(":")

    fns = collect(repo)
    levels = [[{"rel": arel, "qual": afunc, "name": afunc, "lineno": None}]]
    frontier = {afunc}
    seen = {f"{arel}:{afunc}"}
    ver_callers: list[dict] = []

    for _ in range(depth):
        nxt, nxt_names = [], set()
        for fn in fns:
            if fn.calls & frontier and fn.key() not in seen:
                row = {"rel": fn.rel, "qual": fn.qual, "name": fn.name,
                       "lineno": fn.lineno}
                if is_verification(fn.rel):
                    ver_callers.append(row)
                    continue
                nxt.append(row)
                nxt_names.add(fn.name)
                seen.add(fn.key())
        if not nxt:
            break
        levels.append(sorted(nxt, key=lambda r: (r["rel"], r["lineno"] or 0)))
        frontier = nxt_names

    out = {
        "repo": str(repo),
        "anchor": anchor,
        "n_functions_scanned": len(fns),
        "altitudes": {str(i): lv for i, lv in enumerate(levels)},
        "altitude_count": len(levels),
        "verification_callers_excluded": ver_callers,
        "bound": "repo-local only; importers outside this repo are not enumerable",
    }
    print(json.dumps(out, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
