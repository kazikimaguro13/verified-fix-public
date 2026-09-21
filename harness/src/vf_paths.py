# -*- coding: utf-8 -*-
"""vf_paths.py -- the ONE place the Python side of this harness learns where
things are.  Introduced by judgement 61 (option A, v134).

WHY: MEASURED (v131 staging audit, §4): five machine paths were written out as
string literals in 109 places across 47 files.  They are five facts, not 109,
and a public copy of this repository cannot carry any of them.

WHAT IT IS NOT: not a gate, not a pass condition.  Nothing here is read by
run_gates / freeze; it is read by the drivers and generators around them.

⛔ THE DEFAULTS REPRODUCE THE OLD LITERALS on the machine they were written on,
  and that is checked: reports/v134_raw/paths_resolved.txt prints every value
  from all three languages next to the literal it replaced.

Import it from anywhere in the tree:

    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))
    from vf_paths import CLIENT_VF, VF_SKILL_DIR        # parents[2] from
                                                    # harness/js/{tools,attacks}
                                                    # and harness/tools/hooks

Windows-side Python works too: the derivation is Path(__file__)-relative, and
VF_HOME falls back to Path.home() (%USERPROFILE%) when VF_HOME is unset.
"""
import os
import pathlib

__all__ = [
    "VF_HOME", "VF_SKILL_DIR", "CLIENT_PORTAL", "CLIENT_VF", "JS_GATES_DIR",
    "NODE_BIN_DIR", "VF_PATHS_ORDER", "VF_PATHS",
]


def _env(name):
    v = os.environ.get(name)
    return v if v else None


_HOME = pathlib.Path(os.path.expanduser("~"))

# ---- VF_HOME: the scratch root.  Was: /home/<user>/vf1 --------------------
VF_HOME = str(pathlib.Path(_env("VF_HOME") or (_HOME / "vf1")))

# ---- VF_SKILL_DIR: this checkout ------------------------------------------
# Derived from THIS FILE's location (<skill>/harness/src/vf_paths.py -> two up),
# because a checkout knows where it is better than an exported variable does.
# The env value is the FALLBACK, for a copied-out single file.
# Was: /mnt/c/Users/<user>/.claude/skills/verified-fix
_DERIVED_SKILL = pathlib.Path(__file__).resolve().parents[2]


def _looks_like_skill(d):
    try:
        return (d / "SKILL.md").is_file() and (d / "harness").is_dir()
    except OSError:
        return False


VF_SKILL_DIR = str(_DERIVED_SKILL if _looks_like_skill(_DERIVED_SKILL)
                   else pathlib.Path(_env("VF_SKILL_DIR") or _DERIVED_SKILL))

# ---- the client clone (read only -- never pushed to) ----------------------
# Was: /home/<user>/vf1/client/portal
# ★v135 (judgement 63): the old export name carried the client's initials
#   into the public copy.  VF_CLIENT_PORTAL is the environment spelling;
#   the bare CLIENT_PORTAL is still read because vf_env.sh exports that
#   spelling to its children.
CLIENT_PORTAL = str(pathlib.Path(
    _env("VF_CLIENT_PORTAL") or _env("CLIENT_PORTAL")
    or (pathlib.Path(VF_HOME) / "client" / "portal")))

# ---- the variant / cfg store.  Was: /home/<user>/vf1/client/vf ------------
CLIENT_VF = str(pathlib.Path(
    _env("VF_CLIENT_VF") or _env("CLIENT_VF")
    or (pathlib.Path(VF_HOME) / "client" / "vf")))

# ---- the RUNNING copy of the gates ----------------------------------------
# VF_GATES is honoured first: gate_power.mjs and run_check5.mjs already read
# that spelling and it must keep working.
# Was: /home/<user>/vf1/jsharness/gates
JS_GATES_DIR = str(pathlib.Path(
    _env("VF_GATES") or _env("JS_GATES_DIR")
    or (pathlib.Path(VF_HOME) / "jsharness" / "gates")))


# ---- Node 22.  Was: /home/<user>/.nvm/versions/node/v22.23.2/bin ----------
# VF_NODE_BIN, else the FIRST $HOME/.nvm/versions/node/v22*/bin that exists
# (ascending name order), else "" -- and "" means "use PATH".
def _find_node_bin():
    e = _env("VF_NODE_BIN")
    if e:
        return e
    base = _HOME / ".nvm" / "versions" / "node"
    try:
        names = sorted(p.name for p in base.iterdir() if p.name.startswith("v22"))
    except OSError:
        return ""
    for n in names:
        b = base / n / "bin"
        if b.is_dir():
            return str(b)
    return ""


NODE_BIN_DIR = _find_node_bin()

# Fixed order, shared with vf_paths.mjs and vf_env.sh, so the three outputs of
# reports/v134_raw/paths_resolved.txt compare line by line.
VF_PATHS_ORDER = ["VF_HOME", "VF_SKILL_DIR", "CLIENT_PORTAL", "CLIENT_VF",
                  "JS_GATES_DIR", "NODE_BIN_DIR"]
VF_PATHS = {
    "VF_HOME": VF_HOME,
    "VF_SKILL_DIR": VF_SKILL_DIR,
    "CLIENT_PORTAL": CLIENT_PORTAL,
    "CLIENT_VF": CLIENT_VF,
    "JS_GATES_DIR": JS_GATES_DIR,
    "NODE_BIN_DIR": NODE_BIN_DIR,
}

if __name__ == "__main__":
    for k in VF_PATHS_ORDER:
        print("%-13s %s" % (k, VF_PATHS[k]))
