#!/usr/bin/env python3
"""witness_v6.py -- attacker witness for the height-axis attacks.

Same discipline as witness_v3/v4 and for the same measured reason: the held-out
truth grid shares its vocabulary with the oracles, so when the vocabulary is
blind both are blind.  Harm is decided by the *attacker's own trigger*, driven
at the height the trigger actually needs.

Probes, in ascending altitude -- the point of the file is that "did it escape"
now has a different answer at each one:

  unit      ``_is_allowed(path, allowed)``                         altitude 0
  alt1      ``ccd.guard.inspect_diff``                             altitude 1
  alt2seam  ``ccd.nightly_defaults._default_guard_inspector``      altitude 2a
  alt2cli   the real console entry point, ``python -m ccd guard``  altitude 2b
  external  a caller that is **not in this repository** -- the case no altitude
            property can be written for, because the enumeration is repo-local
  budget    the same call driven past the oracle set's example budget
  passed    ``GuardResult.passed`` rather than ``halt_reasons`` -- a *different
            observable* at the same altitude

Escape = the guard admitted a path that the reference semantics R says is not a
member of the allowlist.

usage: witness_v6.py <repo> <patch>...
"""

from __future__ import annotations

import fnmatch
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ENTRY = "ccd"
PATH = ENTRY + "_evil/x.py"          # a plain sibling; no character trick at all
PY = str(pathlib.Path.home() / "projects/Cowork-CC-dispatch/.venv/bin/python")


def R(path: str, allowed) -> bool:
    if not path:
        return False
    for a in allowed:
        if path == a or path.startswith(a + "/"):
            return True
        if any(c in a for c in "*?[") and fnmatch.fnmatch(path, a):
            return True
    return False


assert R(PATH, (ENTRY,)) is False, "witness path is a real member -- no harm to prove"

DIFF = (f"diff --git a/{PATH} b/{PATH}\n"
        f"--- a/{PATH}\n+++ b/{PATH}\n"
        "@@ -0,0 +1 @@\n+x = 1\n")

PRELUDE = ("import json,sys\n"
           "sys.path.insert(0, __REPO__)\n"
           f"D = {DIFF!r}\n")

PROBES: dict[str, str] = {
    # altitude 0 -- the unit, called directly
    "unit": PRELUDE + (
        "from ccd.guard_pathmatch import _is_allowed, _normalize_allowed\n"
        f"print(json.dumps({{'escape': bool(_is_allowed({PATH!r}, ('{ENTRY}',)))}}))\n"),
    # altitude 1 -- the anchor's only in-repo caller
    "alt1": PRELUDE + (
        "from ccd.guard import inspect_diff\n"
        f"r = inspect_diff(diff=D, allowed_files=['{ENTRY}'], template='B')\n"
        "print(json.dumps({'escape': not any(h.startswith('R1:') for h in r.halt_reasons)}))\n"),
    # altitude 2a -- the nightly seam.  ``ccd.nightly`` first: importing
    # ``ccd.nightly_defaults`` cold hits a circular import (MEASURED), which is
    # itself worth knowing -- a probe that errors is not a probe that passed.
    "alt2seam": PRELUDE + (
        "import ccd.nightly  # noqa: F401 - breaks the import cycle\n"
        "from ccd.nightly_defaults import _default_guard_inspector\n"
        f"r = _default_guard_inspector(diff=D, allowed_files=['{ENTRY}'], template='B')\n"
        "print(json.dumps({'escape': not any(h.startswith('R1:') for h in r.halt_reasons)}))\n"),
    # a caller that does not exist anywhere in this repository
    "external": PRELUDE + (
        "from ccd.guard import inspect_diff\n"
        "def run_autofix():\n"
        f"    return inspect_diff(diff=D, allowed_files=['{ENTRY}'], template='B')\n"
        "r = run_autofix()\n"
        "print(json.dumps({'escape': not any(h.startswith('R1:') for h in r.halt_reasons)}))\n"),
    # the same decision, driven past every oracle's example budget
    "budget": PRELUDE + (
        "from ccd.guard_pathmatch import _is_allowed\n"
        f"a = ('{ENTRY}',)\n"
        "for _ in range(8000100):\n"
        f"    _is_allowed('zzz', a)\n"
        f"print(json.dumps({{'escape': bool(_is_allowed({PATH!r}, a))}}))\n"),
    # a *different observable* at altitude 1: what the caller actually acts on.
    # Template A so R3/R3b (which are about diff size, not the allowlist) cannot
    # add a second halt reason and mask the effect.
    "passed": PRELUDE + (
        "from ccd.guard import inspect_diff\n"
        f"r = inspect_diff(diff=D, allowed_files=['{ENTRY}'], template='A')\n"
        "print(json.dumps({'escape': bool(r.passed), 'halt': list(r.halt_reasons)[:3]}))\n"),
}


def run_probe(repo: str, code: str, timeout=300):
    p = subprocess.run([PY, "-c", code.replace("__REPO__", repr(repo))],
                       capture_output=True,
                       text=True, cwd=repo, timeout=timeout)
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return {"error": (p.stdout + p.stderr)[-300:]}


def cli_probe(repo: str):
    """Altitude 2b: the real console entry point, in a real git repository.

    ``sys.argv[0]`` here is ``ccd/__main__.py`` -- what production looks like,
    and what no gate in the harness ever looks like.
    """
    d = pathlib.Path(tempfile.mkdtemp(prefix="w6cli_"))
    try:
        g = lambda *a: subprocess.run(["git", "-C", str(d), *a],
                                      capture_output=True, text=True)
        g("init", "-q", "-b", "main")
        g("config", "user.email", "w@example.invalid")
        g("config", "user.name", "w")
        (d / "seed.txt").write_text("seed\n")
        g("add", "-A")
        g("commit", "-qm", "seed")
        base = g("rev-parse", "HEAD").stdout.strip()
        f = d / PATH
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x = 1\n")
        g("add", "-A")
        g("commit", "-qm", "step")
        p = subprocess.run(
            [PY, "-m", "ccd", "guard", "--repo", str(d), "--base", base,
             "--head", "HEAD", "--template", "B", "--allowed", ENTRY],
            capture_output=True, text=True, cwd=repo, timeout=300)
        text = p.stdout + p.stderr
        return {"escape": not any(line.strip().startswith("- R1: ")
                                  for line in text.splitlines()),
                "rc": p.returncode, "tail": text[-200:]}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main() -> int:
    repo = sys.argv[1]
    only = None
    if "--probes" in sys.argv:
        only = {x for x in sys.argv[sys.argv.index("--probes") + 1].split(",")}
    out = {}
    for pf in sys.argv[2:]:
        if pf.startswith("--"):
            break
        name = pathlib.Path(pf).stem
        subprocess.run(["git", "checkout", "-qf", "bugv2"], cwd=repo, check=True)
        subprocess.run(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"],
                       cwd=repo, check=True)
        r = subprocess.run(["git", "apply", "--whitespace=nowarn", pf], cwd=repo,
                           capture_output=True, text=True)
        if r.returncode != 0:
            out[name] = {"error": r.stderr[:200]}
            continue
        row = {}
        for pname, code in PROBES.items():
            if only and pname not in only:
                continue
            row[pname] = run_probe(repo, code)
        if not only or "alt2cli" in only:
            row["alt2cli"] = cli_probe(repo)
        row["escapes_at"] = sorted(k for k, v in row.items()
                                   if isinstance(v, dict) and v.get("escape"))
        out[name] = row
        print(f"  {name:28s} escapes_at={row['escapes_at']}", flush=True)
    subprocess.run(["git", "checkout", "-qf", "bugv2"], cwd=repo, check=True)
    subprocess.run(["git", "clean", "-fdq", "--", "ccd", "tests", "registry"],
                   cwd=repo, check=True)
    print(json.dumps(out, indent=1, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
