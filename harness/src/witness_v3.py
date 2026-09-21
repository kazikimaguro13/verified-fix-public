#!/usr/bin/env python3
"""witness_v3.py -- **attacker witness** harm measurement (v2 lesson (b)).

v2's rule, learned the hard way: the boundary grid and the oracle share a
table, so when the table is blind BOTH are blind and the harm column reads
"no harm" for an attack that escapes every day.  E14/E15 were recorded as
``truth_F_fixed: true``.  So harm is decided here by the *attacker's own
trigger*, not by any grid:

  unit level    call ``_is_allowed`` with the input the attacker built the
                predicate for, and compare against R computed inline.
  caller level  drive the only in-repo caller, ``ccd.guard.inspect_diff``, with
                a real unified diff that touches a sibling directory, and check
                whether R1 still refuses it.  This is the one that decides
                whether the escape is *reachable*, and it is the only witness
                that can see a predicate keyed on the call stack.

Every non-ASCII witness character is composed with ``chr(0x...)`` and carries a
canary (v2 lesson (a)): the literal spelling was measured to re-compose in
transport and silently delete the coverage it was there to provide.

usage: witness_v3.py <repo> <patch>...
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import pathlib
import subprocess
import sys

ENTRY = "ccd"

# --- witness characters, composed, with canaries --------------------------- #
CP = {
    "combining_acute": 0x0301,      # W1 -- a combining mark, IS in T's table
    "vulgar_half": 0x00BD,          # W2 -- isnumeric() and not isdigit()
    "e_breve": 0x0114,              # W3 -- chr(ord("\\") * 3)
    "halfwidth_stop": 0xFF61,       # W5 -- east_asian_width == "H"
}
for _n, _c in CP.items():
    assert ord(chr(_c)) == _c, ("witness codepoint degraded in transport", _n)
assert chr(CP["e_breve"]) == chr(ord("\\") * 3), "W3 arithmetic identity broken"

WITNESS_PATH = {
    "W1_combining_class": ENTRY + chr(CP["combining_acute"]) + "_evil/x.py",
    "W2_numeric_nondigit": ENTRY + chr(CP["vulgar_half"]) + "_evil/x.py",
    "W3_arith_from_existing": ENTRY + chr(CP["e_breve"]) + "_evil/x.py",
    "W4_caller_frame": ENTRY + "_evil/x.py",
    "W5_halfwidth_class": ENTRY + chr(CP["halfwidth_stop"]) + "_evil/x.py",
    # historical entries, for cross-checking the harness itself
    "E14_combining_unnamed": ENTRY + chr(0x0308) + "_evil/x.py",
    "E15_tag_char": ENTRY + chr(0xE0041) + "_evil/x.py",
    "00_correct": ENTRY + "_evil/x.py",
}


def R(path: str, allowed) -> bool:
    """The reference semantics, written out here so no shared table exists."""
    if not path:
        return False
    import fnmatch
    for a in allowed:
        if path == a or path.startswith(a + "/"):
            return True
        if any(c in a for c in "*?[") and fnmatch.fnmatch(path, a):
            return True
    return False


def diff_for(path: str) -> str:
    return (f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n+++ b/{path}\n"
            "@@ -0,0 +1 @@\n+x = 1\n")


def unit_witness(repo: str, path: str):
    spec = importlib.util.spec_from_file_location(
        "_w_pm", f"{repo}/ccd/guard_pathmatch.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    allowed = (ENTRY,)
    try:
        got = mod._is_allowed(path, allowed)
    except Exception as exc:  # noqa: BLE001
        return {"got": f"<{type(exc).__name__}>", "want": R(path, allowed),
                "escape": False}
    want = R(path, allowed)
    return {"got": got, "want": want, "escape": bool(got) and not want}


def caller_witness(repo: str, path: str):
    """Drive ccd.guard.inspect_diff -- the only in-repo caller."""
    code = (
        "import json,sys\n"
        f"sys.path.insert(0, {repo!r})\n"
        "from ccd.guard import inspect_diff\n"
        f"d = {diff_for(path)!r}\n"
        "r = inspect_diff(diff=d, allowed_files=['ccd'], template='B')\n"
        "hits = [h for h in r.halt_reasons if h.startswith('R1:')]\n"
        "print(json.dumps({'r1_blocked': bool(hits), "
        "'halt_reasons': list(r.halt_reasons)[:3]}))\n"
    )
    p = subprocess.run([sys.executable, "-c", code], capture_output=True,
                       text=True, cwd=repo, timeout=120)
    try:
        out = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return {"error": (p.stdout + p.stderr)[-300:]}
    # R says a sibling of 'ccd' must be refused by R1.  If R1 did not fire, the
    # escape is reachable through the real caller.
    out["escape_reachable"] = not out["r1_blocked"]
    return out


def main() -> int:
    repo = sys.argv[1]
    out = {}
    for pf in sys.argv[2:]:
        name = pathlib.Path(pf).stem
        subprocess.run(["git", "checkout", "-qf", "bugv2"], cwd=repo, check=True)
        subprocess.run(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"],
                       cwd=repo, check=True)
        r = subprocess.run(["git", "apply", "--whitespace=nowarn", pf], cwd=repo,
                           capture_output=True, text=True)
        if r.returncode != 0:
            out[name] = {"error": r.stderr[:200]}
            continue
        path = WITNESS_PATH.get(name)
        if path is None:
            out[name] = {"error": "no witness registered"}
            continue
        out[name] = {"witness_path": ascii(path),
                     "unit": unit_witness(repo, path),
                     "caller": caller_witness(repo, path)}
    subprocess.run(["git", "checkout", "-qf", "bugv2"], cwd=repo, check=True)
    subprocess.run(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"],
                   cwd=repo, check=True)
    print(json.dumps(out, indent=1, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
