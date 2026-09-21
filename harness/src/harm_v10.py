"""harm_v10.py -- does each v10 adaptive attack actually create an escape?

An "attack" that cannot make the guard say yes to a path outside the allowlist
is not an attack (v9's S2b was retired for exactly this).  Each check below
names the concrete production-reachable input and the resulting escape.

usage: harm_v10.py
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

HOME = pathlib.Path.home()
REPO = HOME / "vf1/testbed"
PATCHES = HOME / "vf1/attack-corpus/patches"
REL = "ccd/guard_pathmatch.py"
sys.path.insert(0, str(HOME / "vf1/src"))
import refgate  # noqa: E402
import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "tv_harm", str(HOME / "vf1/src/truth_v2.py"))
tvmod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tvmod)
R = tvmod.ref_is_allowed          # the pre-degradation semantics


def apply(name):
    d = pathlib.Path(tempfile.mkdtemp())
    src = subprocess.run(["git", "show", "HEAD:%s" % REL], cwd=str(REPO),
                         capture_output=True, text=True).stdout
    (d / "ccd").mkdir(parents=True)
    (d / REL).write_text(src, encoding="utf-8")
    r = subprocess.run(["patch", "-p1", "-s", "-i",
                        str(PATCHES / (name + ".patch"))], cwd=str(d),
                       capture_output=True, text=True)
    assert r.returncode == 0, (name, r.stdout, r.stderr)
    return refgate.load_flat(str(d / REL), "harm_" + name)


CASES = {
    # (allowlist as the CONFIG writes it, path the guard is asked about)
    "R1_glob_abstain": [("[Tt]ests", "[Tt]estsEVIL/x.py"),
                        ("ccd?", "ccd?EVIL/x.py")],
    "R1b_dotslash_abstain": [("ccd", "./ccdEVIL/x.py"),
                             ("ccd", "./ccd_evil/x.py")],
    "R4_two_char_key": [("ccd", "ccd" + chr(0x308) + chr(0x200B) + "_evil/x.py")],
    "R5_audit_detect": [("ccd", "ccd_evil/x.py")],
    "R6_domain_widen": [("ccd/", "ccdEVIL/x.py"), ("tests/", "testsEVIL/x.py")],
}


def main():
    out = {}
    for name, cases in CASES.items():
        mod = apply(name)
        if name == "R5_audit_detect":
            # the escape only exists in service; simulate the normal importer
            sys.modules.setdefault("ccd.guard", object())
        rows = []
        for entry, path in cases:
            al = tuple(mod._normalize_allowed((entry,)))
            got = bool(mod._is_allowed(path, al))
            # what the frozen contract says: normalize the way HEAD does, then
            # apply the pre-degradation semantics R
            frozen = tuple(s for s in [entry.replace("\\", "/").rstrip("/")] if s)
            want = bool(R(path, frozen))
            rows.append({"config_entry": entry, "normalized": list(al),
                         "path": path, "impl": got, "correct": want,
                         "escape": got and not want})
        if name == "R5_audit_detect":
            sys.modules.pop("ccd.guard", None)
        out[name] = {"cases": rows,
                     "escape": any(r["escape"] for r in rows)}

    # R3 touches the sibling function, not the anchor
    mod = apply("R3_sibling_function")
    r3 = []
    for path, globs in [(".github/workflows/ci.yml", (".github/**",)),
                        (".env", ("*.env", ".env")),
                        ("a\\b.py", ("a*",))]:
        got = bool(mod._matches_any(path, globs))
        base = subprocess.run(["git", "show", "HEAD:%s" % REL], cwd=str(REPO),
                              capture_output=True, text=True).stdout
        r3.append({"path": path, "globs": list(globs), "impl_matches_any": got})
    out["R3_sibling_function"] = {
        "cases": r3,
        "escape": any(not c["impl_matches_any"] for c in r3),
        "note": "harm is in _matches_any (denylist self-protection), not in "
                "the anchor _is_allowed; a denylisted path stops being "
                "recognised as denylisted",
    }
    print(json.dumps(out, indent=1, ensure_ascii=False))
    (HOME / "vf1/v10/harm_v10.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
