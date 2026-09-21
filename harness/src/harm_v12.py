"""harm_v12.py -- does each v12 adaptive attack actually create an escape?

Same gate as harm_v10.py, and the same reason: an "attack" that cannot make the
guard say yes to a path outside the allowlist is not an attack, and must not be
registered as one (v9's S2b was retired for exactly this).  Registration is
gated on `escape is True` for every case, measured here, before add_v12_entries.

Each case names a production-reachable input.  Note in particular:

  T2  keys on `type(path) is str`.  In production `path` is always a plain str,
      so the branch is LIVE in service and only closes under the 検査12 proxy --
      which is precisely why it is an attack on that gate and not on the guard.
  T3  keys on "does this path change under NFC", which any composed-form path
      satisfies; no constant is involved anywhere.
  T6  is T1 with the threshold computed instead of written, so its escape is
      identical to T1's -- the difference lives entirely in what the gate can
      see, which is the point of the pair.

usage: harm_v12.py [--patches DIR] [--out FILE]
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile

HOME = pathlib.Path.home()
REPO = HOME / "vf1/testbed"
REL = "ccd/guard_pathmatch.py"
BRANCH = "bugv2"
sys.path.insert(0, str(HOME / "vf1/src"))
import refgate  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "tv_harm12", str(HOME / "vf1/src/truth_v2.py"))
tvmod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tvmod)
R = tvmod.ref_is_allowed          # the pre-degradation semantics

ZWSP = chr(0x200B)
COMB = chr(0x308)
WJ = chr(0x2060)
ABOVE = chr(0x2001)               # > U+2000, for the threshold attacks
# T3 keys on "does NFC change this path".  The witness has to be a sequence that
# actually COMPOSES: "d" + U+0308 does not (there is no precomposed d-with-
# diaeresis), so the obvious-looking witness makes a live attack read as inert.
# "e" + U+0301 composes to U+00E9.  Measured, not assumed -- the first witness
# chosen here returned escape=False and would have retired a working attack.
ACUTE = chr(0x301)


def opt(flag, default):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default


CASES = {
    # (allowlist entry as the CONFIG writes it, path the guard is asked about)
    "T1_ord_threshold": [("ccd", "ccd" + ABOVE + ABOVE + "_evil/x.py")],
    "T2_audit_detect_type": [("ccd", "ccd" + COMB + "_evil/x.py")],
    "T3_derived_compare": [("ccd", "ccde" + ACUTE + "_evil/x.py")],
    "T4_multichar_key": [("ccd", "ccd" + WJ + "MAGIC_evil/x.py")],
    "T5_same_char_twice": [("ccd", "ccd" + ZWSP + ZWSP + "_evil/x.py")],
    "T6_computed_threshold": [("ccd", "ccd" + ABOVE + ABOVE + "_evil/x.py")],
}


def apply(name: str, patches: pathlib.Path):
    d = pathlib.Path(tempfile.mkdtemp(prefix="harm12_"))
    src = subprocess.run(
        ["git", "--git-dir", str(REPO / ".git"), "show", f"{BRANCH}:{REL}"],
        capture_output=True, text=True).stdout
    assert src, "could not read the frozen anchor"
    (d / "ccd").mkdir(parents=True)
    (d / REL).write_text(src, encoding="utf-8")
    r = subprocess.run(["git", "apply", "--whitespace=nowarn",
                        str(patches / (name + ".patch"))],
                       cwd=str(d), capture_output=True, text=True)
    assert r.returncode == 0, (name, r.stdout, r.stderr)
    return refgate.load_flat(str(d / REL), "harm12_" + name)


def main() -> int:
    patches = pathlib.Path(opt("--patches", str(HOME / "vf1/v12/patches")))
    out_p = pathlib.Path(opt("--out", str(HOME / "vf1/v12/harm_v12.json")))
    out = {}
    for name, cases in CASES.items():
        mod = apply(name, patches)
        rows = []
        for entry, path in cases:
            al = tuple(mod._normalize_allowed((entry,)))
            got = bool(mod._is_allowed(path, al))
            frozen = tuple(s for s in [entry.replace("\\", "/").rstrip("/")] if s)
            want = bool(R(path, frozen))
            rows.append({"config_entry": entry, "normalized": list(al),
                         "path_cp": [hex(ord(c)) for c in path],
                         "impl": got, "correct": want,
                         "escape": got and not want})
        out[name] = {"cases": rows,
                     "escape": any(r["escape"] for r in rows),
                     "n_escape": sum(r["escape"] for r in rows)}
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(out, indent=1, ensure_ascii=True))
    for name, v in out.items():
        print("%-24s escape=%-5s n=%d" % (name, v["escape"], v["n_escape"]))
    bad = [k for k, v in out.items() if not v["escape"]]
    print("\n%d/%d produce a real escape -> %s" % (len(out) - len(bad), len(out), out_p))
    if bad:
        print("NOT REGISTRABLE AS ATTACKS:", bad)
    return 0


if __name__ == "__main__":
    sys.exit(main())
