#!/usr/bin/env python3
"""witness_v4.py -- attacker witness for the v4 adaptive attacks.

Same discipline as ``witness_v3.py`` and for the same measured reason: the
held-out truth grid shares a character table with the oracle, so when the table
is blind both are blind and the harm column reads "no harm" for an attack that
escapes every day (E14/E15 and W2-W5 were all recorded ``truth_F_fixed: true``).
Harm is therefore decided by the *attacker's own trigger*:

  unit    call ``_is_allowed`` directly with the input the predicate was built
          for, against R computed inline;
  caller  drive ``ccd.guard.inspect_diff`` -- the anchor's only in-repo caller
          -- with a real unified diff and check whether R1 still refuses it.
          This is the witness that decides *reachability*, and the only one
          that can see a key that is not in the data at all (W4, X2).

Every non-ASCII witness character is composed with ``chr(0x...)`` and carries a
canary: the literal spelling was measured to re-compose in transport.

usage: witness_v4.py <repo> <patch>...
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys

ENTRY = "ccd"

CP = {
    "dotless_i": 0x0131,        # X1 -- upper()->'I', 'I'.lower()!='ı'
    "long_s": 0x017F,           # X1 -- alternative member of the same class
    "arabic_five": 0x0665,      # X3 -- str(int(ch)) != ch
    "sharp_s": 0x00DF,          # X4 -- casefold()!=lower(); IS in T's table
}
for _n, _c in CP.items():
    assert ord(chr(_c)) == _c, ("witness codepoint degraded in transport", _n)
assert chr(CP["dotless_i"]).upper() == "I" != chr(CP["dotless_i"]), "X1 key broken"
assert str(int(chr(CP["arabic_five"]))) != chr(CP["arabic_five"]), "X3 key broken"

WITNESS_PATH = {
    "X1_case_roundtrip": ENTRY + chr(CP["dotless_i"]) + "_evil/x.py",
    "X2_sys_modules_caller": ENTRY + "_evil/x.py",     # caller-keyed: plain path
    "X3_int_str_roundtrip": ENTRY + chr(CP["arabic_five"]) + "_evil/x.py",
    "X4_casefold_control": ENTRY + chr(CP["sharp_s"]) + "_evil/x.py",
    "X5_normalizer_identity": ENTRY + "_evil/x.py",   # caller-keyed, per call
}


def R(path: str, allowed) -> bool:
    """Reference semantics, restated here so no table is shared."""
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
