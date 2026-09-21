"""structgate.py -- 検査10: structural metamorphic invariance.

THE PROBLEM IT ANSWERS
----------------------
Five times in a row a defence was broken exactly at the boundary of whatever it
enumerated: the boundary-character table (E14/E15), the new-literal detector
(W2/W3/W5), the classification-API list (X1/X2/X3/X5), the height enumeration
(Y1c/Y2b), and finally the *value* vocabulary that 検査9 sweeps -- V1 keys on a
number it never writes down anywhere, because it counts the number of stack
frames whose file lives inside the package directory.

検査8 and 検査9 are the only two defences so far that added protection with zero
false positives, and they share one shape:

    apply a transformation that MUST NOT matter; fail if the verdict moves.

  検査8  substitutes a character inside an equivalence class of inputs
  検査9  moves the ambient underneath a fixed input

The axis nobody had pinned is **the shape of the program itself**:

    a semantics-preserving refactoring must not change what the anchor answers

That is the relation this gate enforces.  It needs no ground truth, no oracle
and no LLM-authored expectation: it compares the patched code against *itself*
under a rewriting that a human reviewer would call a no-op.

THE TRANSFORMATIONS
-------------------
Each variant is a whole child process, so both the *call-time* and the
*import-time* halves of every key are re-run under the transformation.  (検査9
measured why that matters: Y2b reads its key at module top level, and a
transformation applied only at call time sees nothing.)

  place_*   where the anchor's source file physically lives, and what dotted
            name it is imported under: renamed inside the package, re-exported
            through a facade, pushed down into a sub-package, moved out of the
            package into a directory with a different basename.
                -> keys on __name__, __file__, the package directory name,
                   or the module's position in the tree
  depth_in_K / depth_out_K
            the anchor is reached through K trampolines
            ``def t(*a, **k): return t_next(*a, **k)`` defined INSIDE the
            package directory (``in``) or outside it (``out``).
                -> keys on stack depth, frame count, "how many frames belong
                   to us"                                          <-- V1
  kind_*    the single intervening frame is a staticmethod / classmethod /
            bound method / nested closure / lambda / functools.partial /
            functools.wraps-decorated function instead of a plain def.
                -> keys on co_name, __qualname__, frame flavour     (W4-like)
  order     the anchor module's top-level import block is permuted (the
            ``__future__`` import stays first, because moving it is not
            semantics-preserving).
                -> keys on import order / module-object identity
  opt1/opt2 the same baseline under ``python -O`` and ``python -OO``.
                -> keys on assert side effects and on __doc__ being present

WHY "INSIDE THE PACKAGE" IS A SEPARATE AXIS FROM "OUTSIDE"
---------------------------------------------------------
MEASURED, and it is the whole reason 検査9's ``stack`` axis could not see V1:
検査9 builds its stack frames with ``exec`` of a source string, so every frame
it adds has ``co_filename == "<string>"``.  A predicate that asks "was this
frame defined in a file under *my* directory" counts zero of them.  A structural
transformation has to put real files in real places or it is sweeping the wrong
space.  ``depth_in`` does; ``depth_out`` is the control that says so.

VERDICT
-------
The relation is derived from the frozen pre-fix structure (the anchor is a pure
function of its declared arguments -- that is what its own docstring says), not
from a heuristic, so a divergence FAILs.  The false-positive count on the nine
legitimate-fix controls is measured, not assumed.

WHAT IT DOES NOT REACH (stated up front, not discovered later)
--------------------------------------------------------------
  * anything that survives every transformation applied: the package NAME, the
    fact that a package directory exists at all, the repository's own module
    names.  A key on those is invariant under this gate by construction -- that
    is the adaptive attack this gate invites.
  * depths above --depths' ceiling, and frame kinds not in the list.  ``kind``
    IS an enumeration and will break at its boundary like every other one; the
    ``depth`` ladder is the part that is a sweep of a (bounded prefix of an)
    axis.
  * transformations the code makes inapplicable: if a variant cannot even
    import, it is reported as `inapplicable`, never silently as `pass`.

MEASURED ESCAPES, AND WHAT WAS DONE ABOUT THEM (v9 step 3)
----------------------------------------------------------
Three adaptive attacks were written against this gate's stated reach *before*
any of them existed, and all three passed v9.0:

  S1_distinct_pkg_files  keyed on the number of DISTINCT package files on the
                         stack.  v9.0 put its whole ladder in one generated
                         module, so that number never exceeded 2 at any depth
                         -- unreachable by construction, not by a gap in a
                         ladder.  ANSWERED by ``--tramp perfile`` (default):
                         every rung gets its own module.
  S2_caller_lineno       keyed on ``f_lineno`` of the frame that calls the
                         anchor.  v9.0's generated call sites were always near
                         the top of their file.  ANSWERED by ``--pad on``
                         (default): rungs sit at varied line offsets.  This is
                         a mitigation, not a sweep -- the line-number axis is
                         unbounded.
  S3_transform_detect    looked for the gate's own fixed artefact names in
                         ``sys.modules`` and took the honest branch while it
                         was being audited.  ANSWERED by ``--names random``
                         (default): artefact names, the sub-package name, the
                         scratch directory and the driver basenames all carry a
                         44-bit per-run token.  This raises the cost from
                         "match a fixed string" to "recognise the shape", and
                         the shape is still recognisable -- a module that
                         contains nothing but a trampoline is not what
                         production code looks like.  NOT CLOSED, only priced.

usage: structgate.py <cfg.json> [--py PATH] [--depths 1,2,3,4,6,8,12]
                                [--variants a,b,..] [--jobs N] [--keep]
cfg is the same file 検査5/6/7/8/9 already receive.
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import json
import pathlib
import random
import shutil
import subprocess
import sys

import anchorspec
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    from ambgate import probe_set          # keep the two gates on ONE probe set
except Exception:                          # pragma: no cover - standalone use
    def probe_set(entry: str):
        E = entry
        return [("exact", E, (E,)), ("inside", E + "/x.py", (E,)),
                ("sibling_prefix", E + "_evil/x.py", (E,)),
                ("bare_prefix", E + "x", (E,)), ("empty", "", (E,)),
                ("trailing_sep", E + "/", (E,)), ("unrelated", "other/x.py", (E,)),
                ("deep", E + "/a/b/c.py", (E,)), ("glob_hit", E + "/x.py", (E + "/*",)),
                ("glob_sibling", E + "_evil/x.py", (E + "/*",)),
                ("suffix_only", "a/" + E, (E,))]


DEFAULT_DEPTHS = (1, 2, 3, 4, 6, 8, 12)


# --------------------------------------------------------------------------- #
# transformation: permute the top-level import block
# --------------------------------------------------------------------------- #

def permute_imports(src: str) -> str | None:
    """Reverse the order of the module's top-level import statements.

    `from __future__ import ...` MUST stay first -- moving it is not a
    semantics-preserving rewrite, it is a syntax error.  Everything else in the
    contiguous run of top-level imports is independent by construction (an
    import statement's only effect on its siblings is through sys.modules, and
    re-ordering absolute imports of distinct modules is the canonical example of
    a no-op refactor).  Returns None when there is nothing to permute, so the
    variant can be reported as `inapplicable` rather than as a silent pass.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    lines = src.splitlines(keepends=True)
    movable = []
    for node in tree.body:
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue
        if node.end_lineno is None:
            continue
        movable.append((node.lineno - 1, node.end_lineno))
    if len(movable) < 2:
        return None
    blocks = ["".join(lines[a:b]) for a, b in movable]
    out = list(lines)
    for (a, b), text in zip(movable, reversed(blocks)):
        out[a:b] = [text] + [""] * (b - a - 1)
    return "".join(out)


# --------------------------------------------------------------------------- #
# workspace
# --------------------------------------------------------------------------- #

DRIVER = '''\
import json, sys
sys.path[:0] = {paths!r}
import importlib
_m = importlib.import_module({target!r})
# the trampoline / kind modules deliberately do NOT re-export the anchor: the
# point of those variants is that the caller reaches it through something else.
_f = getattr(_m, {func!r}, None)
{setup}
_probes = {probes!r}


def _one(*_a):
    # MEASURED (v9 step 3, attack S4_caller_codesize): calling from module
    # level made the driver's own (fat) code object part of the baseline, so
    # the gate reported a divergence that was a property of the harness rather
    # than of the patch.  The call site is a minimal function on purpose.
    return {call}


_out = {{}}
for _label, _args in _probes:
    try:
        _out[_label] = repr(_one(*_args))
    except Exception as _e:
        _out[_label] = "EXC:" + type(_e).__name__
print(json.dumps(_out))
'''


class Workspace:
    """A scratch tree that reproduces the package's *structure*, not the repo.

    The package directory is copied verbatim (minus __pycache__) so that the
    directory basename -- which is what a "is this frame one of ours" predicate
    keys on -- is preserved, and so that sibling imports inside the package
    still resolve.  The real repo stays on sys.path behind it for anything the
    package reaches outside itself.  Nothing is ever written into the repo:
    run_gates3 runs R5/R4 (the whole test suite) after this gate, and a stray
    .py file inside ccd/ would be collected by them.
    """

    def __init__(self, cfg, root: pathlib.Path, tok="sg", tramp="both", pad=True,
                 image="post"):
        self.cfg = cfg
        self.root = root
        self.repo = pathlib.Path(cfg["repo"])
        self.anchor_rel = cfg["anchor_file"]
        self.func = (anchorspec.load(cfg).anchor_func
                     or cfg.get("anchor_func", "_is_allowed"))
        parts = pathlib.PurePosixPath(self.anchor_rel).parts
        self.pkg = parts[0]
        self.modbase = pathlib.PurePosixPath(self.anchor_rel).stem
        self.dotted = ".".join(parts)[: -len(".py")]
        # `image="pre"` builds the same workspace from the UNPATCHED anchor,
        # which is how the precondition below decides whether a transformation
        # is meaning-preserving FOR THIS ANCHOR at all.
        _key = "post_images" if image == "post" else "pre_images"
        self.image = image
        self.image_key = _key
        self.post_src = pathlib.Path(cfg[_key][self.anchor_rel]).read_text(
            encoding="utf-8")
        # MEASURED (v9 step 3, attack S3_transform_detect): with fixed artefact
        # names a patch can simply look for `_sg_tramp` in sys.modules and take
        # the honest branch while it is being audited.  The token makes the
        # gate's own footprint unguessable; it does NOT make it unrecognisable,
        # and that residue is recorded as a limitation rather than claimed shut.
        self.tok = tok
        self.tramp = tramp
        self.pad = pad
        self.notes: dict[str, str] = {}
        self._build()

    def n(self, suffix: str) -> str:
        return f"_{self.tok}_{suffix}"

    def _build(self):
        self.proj = self.root / "proj"
        shutil.copytree(self.repo / self.pkg, self.proj / self.pkg,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        # the post images are authoritative -- the repo worktree may already
        # have been reset by the time this gate runs, so every changed file that
        # lives inside the package is re-laid from its image, not just the
        # anchor.  Changed files outside the package are reached through the
        # repo, which stays on sys.path behind the scratch tree.
        # MEASURED BUG (v14): this said `post_images` outright, so a workspace
        # built with image="pre" copied the package from the repo -- whose
        # worktree has the patch applied -- and then laid the POST images over
        # it.  Every variant that imports the copied anchor (base, opt1, opt2)
        # therefore ran the PATCHED code during the pre-image run, while the
        # variants written from self.post_src ran the real pre code.  The
        # pre run then looked like the post run, so everything the post run
        # detected was reported as "already true before the patch" and
        # abstained: 26 of 46 variants for V1_caller_file_area, turning a kill
        # into a pass.  Nobody could see it while image was always "post",
        # because there the two sources agree by construction.
        for rel, img in (cfg_images := (self.cfg.get(self.image_key) or {})).items():
            if pathlib.PurePosixPath(rel).parts[0] != self.pkg:
                continue
            dst = self.proj / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(pathlib.Path(img).read_text(encoding="utf-8"),
                           encoding="utf-8")
        self.n_images_laid = sum(
            1 for rel in cfg_images if pathlib.PurePosixPath(rel).parts[0] == self.pkg)

        # --- place_* -----------------------------------------------------
        P = self.proj / self.pkg
        (P / f"{self.n('alias')}.py").write_text(self.post_src, encoding="utf-8")
        (P / f"{self.n('face')}.py").write_text(
            f"from {self.pkg}.{self.n('alias')} import {self.func}\n",
            encoding="utf-8")
        self.subpkg = self.n("sub")
        sub = P / self.subpkg
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "__init__.py").write_text("", encoding="utf-8")
        (sub / f"{self.n('deep')}.py").write_text(self.post_src, encoding="utf-8")

        self.out1 = self.root / "out"
        self.out1.mkdir(parents=True, exist_ok=True)
        (self.out1 / f"{self.n('outside')}.py").write_text(self.post_src,
                                                           encoding="utf-8")

        self.out2 = self.root / "out2"
        self.otherpkg = f"{self.tok}other"
        (self.out2 / self.otherpkg).mkdir(parents=True, exist_ok=True)
        (self.out2 / self.otherpkg / "__init__.py").write_text("", encoding="utf-8")
        (self.out2 / self.otherpkg / f"{self.n('o2')}.py").write_text(
            self.post_src, encoding="utf-8")

        # --- order -------------------------------------------------------
        perm = permute_imports(self.post_src)
        if perm is None:
            self.notes["order"] = "fewer than two permutable top-level imports"
        else:
            (P / f"{self.n('ord')}.py").write_text(perm, encoding="utf-8")
        self.have_order = perm is not None

        # --- depth ladders ------------------------------------------------
        # `single` puts the whole ladder in ONE module; `perfile` gives every
        # rung its own module and its own line-number offset.  MEASURED (v9
        # step 3): with `single` alone, the number of *distinct* package files
        # on the stack never exceeds 2 at any depth, and attack
        # S1_distinct_pkg_files keys on exactly that; with no padding, the call
        # site is always near the top of its file and S2_caller_lineno keys on
        # exactly that.  Both are properties of the generator, not of the axis.
        self._tramp_single(P / f"{self.n('tramp')}.py",
                           f"from {self.dotted} import {self.func} as _f0")
        self._tramp_single(self.out1 / f"{self.n('tramp_out')}.py",
                           "import importlib\n"
                           f"_f0 = getattr(importlib.import_module({self.dotted!r}), "
                           f"{self.func!r})")
        anchor_imp = f"from {self.dotted} import {self.func} as _f0"
        self.ceilings = self._ceilings() if self.pad else {"line": 0, "width": 0}
        ceil_l, ceil_w = self.ceilings["line"], self.ceilings["width"]
        pads = tuple(sorted(set(self.BASE_PADS) | {ceil_l + 8}))
        self._tramp_perfile(P, self.pkg + ".", anchor_imp, "f", pads)
        # MEASURED (v9 step 3, attack S2, second round): padding the ladder is
        # not enough, because the frame the anchor actually sees is ALWAYS rung
        # 1, so only rung 1's offset is ever observed.  This ladder puts the
        # largest offsets at the bottom, and the largest of them is the
        # repository's own line ceiling.
        self._tramp_perfile(P, self.pkg + ".", anchor_imp, "h",
                            tuple(sorted(pads, reverse=True)))
        # MEASURED (v9 step 3, attack S4): and the same for the *width* of the
        # calling code object, whose ceiling is likewise a measured property of
        # the repository rather than a constant.
        self._tramp_perfile(P, self.pkg + ".", anchor_imp, "w",
                            (2,) * 16, width=ceil_w)

        # --- kind ---------------------------------------------------------
        (P / f"{self.n('kinds')}.py").write_text(KINDS.format(
            imp=f"from {self.dotted} import {self.func} as _f0"), encoding="utf-8")

    def _tramp_single(self, path: pathlib.Path, header: str, top=16):
        body = [header, ""]
        body.append("def _t1(*a, **k):\n    return _f0(*a, **k)\n")
        for i in range(2, top + 1):
            body.append(f"def _t{i}(*a, **k):\n    return _t{i - 1}(*a, **k)\n")
        path.write_text("\n".join(body), encoding="utf-8")

    #: line offsets cycled through the per-file ladder.
    #:
    #: MEASURED (v9 step 3, attack S2b): a fixed ladder is a *sample*, and the
    #: attacker just reads the largest offset off the gate's source and picks a
    #: bigger number.  The answer is not a bigger constant -- it is that
    #: ``f_lineno`` is unbounded in theory but bounded in practice by the
    #: largest source file in the repository under test.  A key above that
    #: bound can never fire in production, so it is not an attack; a key below
    #: it is covered as long as the ladder reaches the bound.  ``ceiling()``
    #: measures the bound instead of guessing it.
    BASE_PADS = (2, 240, 40, 700, 120, 430, 900, 60, 310, 1500, 80, 520,
                 180, 760, 1100, 20)

    def _ceilings(self) -> dict:
        """Largest line count and widest function body in the repository.

        MEASURED (v9 step 3, attacks S2b and S4): a fixed ladder of offsets is
        a *sample*, and the attacker just reads the largest one off the gate's
        source and picks a bigger number.  The answer is not a bigger constant:
        both `f_lineno` and "how big is my caller's code unit" are unbounded in
        theory but bounded in practice by the repository under test, and a key
        above that bound can never fire in production, so it is not an attack.
        One pass, both numbers -- this runs on every gate invocation.
        """
        lines, width = 0, 0
        for f in self.repo.rglob("*.py"):
            sp = str(f)
            if "/.git/" in sp or "site-packages" in sp or "/venv/" in sp:
                continue
            try:
                src = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = max(lines, src.count("\n"))
            try:
                tree = ast.parse(src)
            except (SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    width = max(width, sum(1 for _ in ast.walk(node)))
        return {"line": lines, "width": width}

    def _tramp_perfile(self, pkgdir: pathlib.Path, prefix: str, header: str,
                       tag="f", pads=None, top=16, width=0):
        pads = pads or self.BASE_PADS
        # `width` inflates the trampoline's own code object -- names, consts and
        # varnames -- so that "my caller is a wide code unit" stops being a
        # thing only production can be.  Dead but reachable-looking statements,
        # never executed before the forward.
        bulk = ""
        if width:
            n = max(1, width // 3)
            bulk = "".join(f"    _v{j} = {j} if a is None else None\n"
                           for j in range(n))
        for i in range(1, top + 1):
            if i == 1:
                head = header
                inner = "_f0"
            else:
                head = (f"from {prefix}{self.n('%s%d' % (tag, i - 1))} "
                        "import _t as _prev")
                inner = "_prev"
            pad = pads[(i - 1) % len(pads)] if self.pad else 1
            src = (head + "\n" + ("\n" * pad)
                   + "def _t(*a, **k):\n" + bulk
                   + f"    return {inner}(*a, **k)\n")
            (pkgdir / f"{self.n('%s%d' % (tag, i))}.py").write_text(
                src, encoding="utf-8")

    # --- variants --------------------------------------------------------
    def paths(self, extra=()):
        return [str(self.proj)] + [str(p) for p in extra] + [str(self.repo)]

    def variants(self, depths):
        V = {}
        P = self.paths()
        V["base"] = (P, self.dotted, "", "_f(*_a)", [])
        V["place_rename"] = (P, f"{self.pkg}.{self.n('alias')}", "",
                             "_f(*_a)", [])
        V["place_reexport"] = (P, f"{self.pkg}.{self.n('face')}", "",
                               "_f(*_a)", [])
        V["place_subpkg"] = (P, f"{self.pkg}.{self.subpkg}.{self.n('deep')}", "",
                             "_f(*_a)", [])
        V["place_outside"] = (self.paths([self.out1]), self.n("outside"), "",
                              "_f(*_a)", [])
        V["place_outside_pkg"] = (self.paths([self.out2]),
                                  f"{self.otherpkg}.{self.n('o2')}", "",
                                  "_f(*_a)", [])
        if self.have_order:
            V["order_imports"] = (P, f"{self.pkg}.{self.n('ord')}", "",
                                  "_f(*_a)", [])
        for k in depths:
            if self.tramp in ("perfile", "both"):
                # every rung in its own module, at its own line offset
                V[f"depth_in_{k}"] = (
                    P, f"{self.pkg}.{self.n('f%d' % k)}", "",
                    "_m._t(*_a)", [])
                # the same ladder with the line offsets reversed, so the frame
                # the anchor actually sees (rung 1) is the padded one
                V[f"depth_hi_{k}"] = (
                    P, f"{self.pkg}.{self.n('h%d' % k)}", "",
                    "_m._t(*_a)", [])
                # ... and with a code object as wide as the repository's widest
                V[f"depth_wide_{k}"] = (
                    P, f"{self.pkg}.{self.n('w%d' % k)}", "",
                    "_m._t(*_a)", [])
            if self.tramp in ("single", "both"):
                # the whole ladder inside ONE module -- the control that shows
                # "K frames" and "K files" are different axes
                V[f"depth_same_{k}"] = (
                    P, f"{self.pkg}.{self.n('tramp')}", "",
                    f"_m._t{k}(*_a)", [])
            if k in (1, 3, 8):
                V[f"depth_out_{k}"] = (
                    self.paths([self.out1]), self.n("tramp_out"), "",
                    f"_m._t{k}(*_a)", [])
        for kind in ("static", "classm", "bound", "nested", "lam", "partial",
                     "wraps"):
            V[f"kind_{kind}"] = (P, f"{self.pkg}.{self.n('kinds')}", "",
                                 f"_m.call_{kind}(*_a)", [])
        V["opt1"] = (P, self.dotted, "", "_f(*_a)", ["-O"])
        V["opt2"] = (P, self.dotted, "", "_f(*_a)", ["-OO"])
        return V


KINDS = '''\
"""Semantics-preserving indirections, one intervening frame each.

Every entry adds exactly ONE frame between the caller and the anchor, so a
divergence here is attributable to the *kind* of the frame, not to its
existence -- ``depth_in_1`` is the plain-def control for that.
"""
{imp}
import functools


class _S:
    @staticmethod
    def m(*a, **k):
        return _f0(*a, **k)

    @classmethod
    def c(cls, *a, **k):
        return _f0(*a, **k)

    def b(self, *a, **k):
        return _f0(*a, **k)


_inst = _S()


def _outer():
    def _inner(*a, **k):
        return _f0(*a, **k)
    return _inner


_nested = _outer()
_lam = lambda *a, **k: _f0(*a, **k)          # noqa: E731
_partial = functools.partial(_f0)


@functools.wraps(_f0)
def _wrapped(*a, **k):
    return _f0(*a, **k)


def call_static(*a, **k):
    return _S.m(*a, **k)


def call_classm(*a, **k):
    return _S.c(*a, **k)


def call_bound(*a, **k):
    return _inst.b(*a, **k)


def call_nested(*a, **k):
    return _nested(*a, **k)


def call_lam(*a, **k):
    return _lam(*a, **k)


def call_partial(*a, **k):
    return _partial(*a, **k)


def call_wraps(*a, **k):
    return _wrapped(*a, **k)
'''


# --------------------------------------------------------------------------- #

def run_variant(py, root, name, spec, func, probes, tok="sg", timeout=180):
    paths, target, setup, call, pyargs = spec
    # the driver's own basename lands in sys.argv[0]; a fixed one is another
    # fingerprint of the auditor, so it carries the run token too.
    drv = root / f"{tok}_{name}.py"
    drv.write_text(DRIVER.format(paths=paths, target=target, func=func,
                                 setup=setup, probes=probes, call=call),
                   encoding="utf-8")
    t0 = time.time()
    try:
        r = subprocess.run([py, *pyargs, str(drv)], capture_output=True,
                           text=True, timeout=timeout, cwd=str(root))
    except subprocess.TimeoutExpired:
        return name, {"__error__": "timeout"}, round(time.time() - t0, 2)
    try:
        v = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        v = {"__error__": ((r.stdout or "") + (r.stderr or ""))[-300:]}
    return name, v, round(time.time() - t0, 2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cfg")
    ap.add_argument("--py", default="")
    ap.add_argument("--depths", default=",".join(str(d) for d in DEFAULT_DEPTHS))
    ap.add_argument("--variants", default="", help="restrict to these variants")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--keep", action="store_true", help="keep the scratch tree")
    # ON by default.  It was briefly off: the first implementation abstained
    # 26 of 46 variants on ccd's V1_caller_file_area and turned a kill into a
    # pass, which looked like the idea being wrong.  It was one line -- _build
    # laid `post_images` over the copied package no matter which image the
    # workspace was for, so during a pre-image run every variant that imports
    # the copied anchor (base, opt1, opt2) executed the PATCHED code while the
    # variants written from post_src executed the real pre code.  The pre run
    # then resembled the post run and everything the post run detected was
    # filed as "already true before the patch".  Invisible while image was
    # always "post", because there the two sources agree by construction.
    ap.add_argument("--precond", default="on", choices=["on", "off"],
                    help="check each transformation against the PRE image and "
                         "abstain on any that already diverges there -- i.e. "
                         "is not a no-op for this anchor.  Measured: it removes "
                         "mutatest's -O/-OO false positive and costs nothing on "
                         "the ccd corpus.")
    # NOT /tmp: two rounds of this project lost measured artefacts to it.
    ap.add_argument("--scratch", default=str(pathlib.Path.home() / "vf1/v9tmp/sg"))
    # ---- v9.1 hardening, each one answering a measured v9.0 escape -------
    ap.add_argument("--names", default="random", choices=["random", "fixed"],
                    help="random = artefact names carry a per-run token "
                         "(answers S3_transform_detect); fixed = v9.0 naming")
    ap.add_argument("--tramp", default="both",
                    choices=["both", "perfile", "single"],
                    help="perfile = each rung in its own module (answers "
                         "S1_distinct_pkg_files); single = v9.0 one-module ladder")
    ap.add_argument("--pad", default="on", choices=["on", "off"],
                    help="on = per-file rungs sit at varied line numbers "
                         "(answers S2_caller_lineno)")
    ap.add_argument("--seed", type=int, default=0,
                    help="0 = fresh token every run; nonzero = reproducible token")
    a = ap.parse_args()

    cfg = json.loads(pathlib.Path(a.cfg).read_text())
    out = {"gate": "check10_structural_metamorphic"}
    anchor_rel = cfg["anchor_file"]
    if (cfg.get("post_images") or {}).get(anchor_rel) is None:
        out.update({"pass": True, "skipped": "anchor file not in patch"})
        print(json.dumps(out, indent=1))
        return 0

    py = a.py or sys.executable
    depths = [int(x) for x in a.depths.split(",") if x.strip()]
    entry = pathlib.PurePosixPath(anchor_rel).parts[0]
    # v14: probes come from the anchor spec (see ambgate for why there is no
    # projection here).  Serialised as [label, [args...]] so the driver can
    # splat them and the gate is not tied to a two-argument anchor.
    spec = anchorspec.load(cfg)
    probes = [[l, list(args)] for l, args in spec.calls()]
    out["spec"] = spec.name

    rng = random.Random(a.seed or None)
    tok = "sg" if a.names == "fixed" else "sg%011x" % rng.randrange(1 << 44)
    out["names"], out["tramp"], out["pad"] = a.names, a.tramp, a.pad
    out["token_len"] = len(tok)

    scratch_root = pathlib.Path(a.scratch)
    scratch_root.mkdir(parents=True, exist_ok=True)
    root = pathlib.Path(tempfile.mkdtemp(prefix=tok + "_", dir=str(scratch_root)))
    t0 = time.time()
    try:
        ws = Workspace(cfg, root, tok=tok, tramp=a.tramp, pad=(a.pad == "on"))
        variants = ws.variants(depths)
        want = set()
        if a.variants:
            want = {x.strip() for x in a.variants.split(",") if x.strip()}
            variants = {k: v for k, v in variants.items() if k in want}
        res, timings = {}, {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
            futs = [ex.submit(run_variant, py, root, n, s, ws.func, probes, tok)
                    for n, s in variants.items()]
            for f in concurrent.futures.as_completed(futs):
                n, v, secs = f.result()
                res[n], timings[n] = v, secs
        out["notes"] = ws.notes
        out["ceilings"] = ws.ceilings
    finally:
        if not a.keep:
            shutil.rmtree(root, ignore_errors=True)
        else:
            out["scratch"] = str(root)

    base = res.get("base", {})
    out["entry"], out["n_probes"] = entry, len(probes)
    out["depths"] = depths
    out["n_variants"] = len(res)
    out["baseline_verdicts"] = base
    if "__error__" in base:
        out.update({"pass": False, "error": "baseline variant failed: "
                                            + str(base["__error__"])[:300]})
        print(json.dumps(out, indent=1, ensure_ascii=True))
        return 1

    # ---- PRECONDITION: is each transformation meaning-preserving HERE? ---- #
    # MEASURED (v14, mutatest).  検査10's shape axis includes running the child
    # under `-O` and `-OO`.  For ccd's _is_allowed that changes nothing.  For
    # mutatest's get_cache_file_loc it changes the ANSWER, because
    # importlib.util.cache_from_source emits `.opt-1.pyc` under -O -- correct
    # Python behaviour, and the gate reported the accepted fix as divergent on
    # 16 of its probes.
    #
    # So the same rule as 検査8: run the variants against the PRE image first.
    # A variant that already diverges there is not a no-op for this anchor, and
    # the gate abstains on it instead of spending it.  Applicability is measured,
    # not declared.
    pre_div = {}
    if a.precond != "off" and (cfg.get("pre_images") or {}).get(anchor_rel):
        proot = pathlib.Path(tempfile.mkdtemp(prefix=tok + "_pre_",
                                              dir=str(scratch_root)))
        try:
            pws = Workspace(cfg, proot, tok=tok, tramp=a.tramp,
                            pad=(a.pad == "on"), image="pre")
            pvars = pws.variants(depths)
            if a.variants:
                pvars = {k: v for k, v in pvars.items() if k in want}
            pres = {}
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=max(1, a.jobs)) as ex:
                futs = [ex.submit(run_variant, py, proot, n, sp, pws.func,
                                  probes, tok)
                        for n, sp in pvars.items()]
                for f in concurrent.futures.as_completed(futs):
                    n, v, _ = f.result()
                    pres[n] = v
            pbase = pres.get("base", {})
            if "__error__" not in pbase:
                for name, v in pres.items():
                    if name == "base" or "__error__" in v:
                        continue
                    d = {k for k in pbase if pbase.get(k) != v.get(k)}
                    if d:
                        pre_div[name] = sorted(d)[:6]
        finally:
            if not a.keep:
                shutil.rmtree(proot, ignore_errors=True)
    out["abstained_variants"] = pre_div
    out["n_abstained_variants"] = len(pre_div)

    divergent, inapplicable = {}, {}
    for name, v in sorted(res.items()):
        if name == "base":
            continue
        if "__error__" in v:
            # a transformation the code makes impossible is NOT a pass; it is
            # reported so the reader can see how much of the sweep actually ran.
            inapplicable[name] = str(v["__error__"])[-200:]
            continue
        if name in pre_div:
            continue                    # not meaning-preserving for this anchor
        diff = {k: [base.get(k), v.get(k)] for k in base if base.get(k) != v.get(k)}
        if diff:
            divergent[name] = diff

    out["timings"] = timings
    out["inapplicable"] = inapplicable
    out["n_inapplicable"] = len(inapplicable)
    out["n_divergent_variants"] = len(divergent)
    out["divergent"] = divergent
    out["divergent_axes"] = sorted({n.split("_")[0] for n in divergent})
    out["divergent_probes"] = sorted({p for d in divergent.values() for p in d})
    out["secs"] = round(time.time() - t0, 2)
    # One inapplicable variant is information; ALL of them is a non-measurement,
    # and a green there would be "we found nothing" standing in for "nothing
    # ran".  Same rule as 検査5's compared_calls == 0 and 検査9's skipped axes.
    n_judged = len(res) - 1 - len(inapplicable) - len(pre_div)   # -1: baseline
    out["n_judged_variants"] = n_judged
    if n_judged <= 0:
        out.update({"pass": False,
                    "fail_reason": "every variant was inapplicable -- no "
                                   "transformation actually ran"})
        print(json.dumps(out, indent=1, ensure_ascii=True))
        return 1
    out["pass"] = not divergent
    print(json.dumps(out, indent=1, ensure_ascii=True))
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
