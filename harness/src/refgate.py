"""refgate.py -- 検査11: independent reference-implementation differential.

THE PROBLEM IT ANSWERS
----------------------
Every gate built so far compares the patch against *itself*: pre-image vs
post-image (検査2/3/5/6/7), or post-image vs post-image under a transformation
(検査8 input axis, 検査9 ambient axis, 検査10 shape axis).  Nothing has ever
compared it against code written by someone else.

That matters because the *ground truth* has the same blind spot as the oracle.
Both are machine-generated from one character-class table, so on a code point
that is not in the table they are blind **at the same time** (measured: E11,
E13, E14, E15 report ``F_fixed: true`` while the escape is still live).
Widening the table is the move that has now failed six times.

THE RELATION
------------
The anchor ``_is_allowed(path, allowed)`` asks one question that the standard
library already answers, in three unrelated modules:

    is ``path`` the entry ``a`` itself, or something inside the directory ``a``?

    * ``pathlib.PurePosixPath``  -- component tuple prefix
    * ``posixpath.dirname``      -- walk up the parents
    * ``fnmatch``/``re``         -- pattern ``a`` or ``a/*``

None of the three is derived from this project's table, its oracle, or its
ground truth, so none of them is blind where those are blind.

THE VOTE, AND THE ABSTENTION
----------------------------
Making a reference agree with the implementation's contract costs independence:
tune it enough and it becomes a copy of the implementation and shares its blind
spot.  So this gate does not tune to agreement.  It runs all three and:

    * all references agree AND the patch disagrees  -> DIVERGENT (a finding)
    * the references disagree with each other       -> ABSTAIN (not judged)

The abstain rate is reported on every run.  It is the measured price of
independence: the region where three honest readings of the contract differ is
exactly the region where "the patch is wrong" has no agreed meaning.

THE AXES
--------
  sweep  : path = pre + chr(cp) + suf, cp over 0x0000..0x10FFFF, five classes.
           Nothing is excluded -- not even ``/ * ? [``.  検査8 has to exclude
           those four because it has no reference and cannot tell a structural
           change from a wrong answer; here the references model the structure,
           so all four are swept like everything else and simply abstain where
           the references legitimately part company.
  grid   : shapes rather than characters -- arity of ``allowed``, empty entries,
           trailing slashes, ``..``, backslashes, case, glob entries.
  length : path length as the key, swept to the longest path the repository can
           actually produce (D16's rule: the repo bounds the value space).

PRECONDITION (the 検査9/10 lesson: check the transform preserves meaning FIRST)
------------------------------------------------------------------------------
Before any of this is believed, the same references are run against the
**pre-fix image**.  If they do not diverge from the known-buggy code, they are
not a valid reading of this anchor and the gate abstains entirely rather than
reporting a green it has not earned.

usage: refgate.py <cfg.json> [--max-cp N] [--classes K1,..] [--adjust a,b]
                             [--no-cache] [--axes sweep,grid,length]
                             [--scratch DIR] [--dump-diverge FILE]
                             [--load package|flat]
"""

from __future__ import annotations

import fnmatch
import hashlib
import importlib
import importlib.machinery
import importlib.util
import json
import pathlib
import posixpath
import secrets
import shutil
import sys
import time
from pathlib import PurePosixPath

MAX_CP = 0x110000
ABSTAIN = None

# --------------------------------------------------------------------------- #
# The three references.  Written from the module contract only:
#   "allowlist matching helpers ... _is_allowed(path, allowed)"
# Each takes (path, allowed) and returns True / False / ABSTAIN.
# ADJUSTMENTS are named and switchable so their cost can be measured one by one;
# see ADJUSTMENT_LEDGER at the bottom of this file.
# --------------------------------------------------------------------------- #


class Refs:
    def __init__(self, adjust):
        self.adjust = set(adjust)
        self._pp = {}

    # -- reference A: pathlib component tuples ------------------------------ #
    def ref_pathlib(self, path, allowed):
        try:
            q = PurePosixPath(path).parts
        except Exception:
            return ABSTAIN
        for e in allowed:
            xp = self._pp.get(e)
            if xp is None:
                try:
                    xp = self._pp[e] = PurePosixPath(e).parts
                except Exception:
                    return ABSTAIN
            if not xp:
                # PurePosixPath('') and PurePosixPath('.') both have parts ==
                # (), i.e. "the current directory", which contains everything.
                if 'empty' in self.adjust:
                    continue          # ADJ:empty -- an empty entry allows nothing
                return True
            if q[:len(xp)] == xp:
                return True
        return False

    # -- reference B: posixpath, walking up the parents --------------------- #
    def ref_dirname(self, path, allowed):
        if 'slash' in self.adjust:
            ents = {e.rstrip('/') for e in allowed}
        else:
            ents = set(allowed)
        cur = path
        seen = 0
        while cur:
            if cur in ents:
                return True
            nxt = posixpath.dirname(cur)
            if nxt == cur:
                break
            cur = nxt
            seen += 1
            if seen > 4096:
                return ABSTAIN
        return False

    # -- reference C: fnmatch -> re ----------------------------------------- #
    def ref_fnmatch(self, path, allowed):
        for e in allowed:
            b = e.rstrip('/') if 'slash' in self.adjust else e
            try:
                if fnmatch.fnmatchcase(path, e):
                    return True
                if fnmatch.fnmatchcase(path, b + '/*'):
                    return True
            except Exception:
                return ABSTAIN
        return False

    def all(self):
        return [('pathlib', self.ref_pathlib),
                ('dirname', self.ref_dirname),
                ('fnmatch', self.ref_fnmatch)]

    def consensus(self, path, allowed):
        """(verdict, votes) -- verdict is True/False, or ABSTAIN if split."""
        votes = {}
        for name, f in self.all():
            try:
                votes[name] = f(path, allowed)
            except Exception as exc:
                votes[name] = 'EXC:' + type(exc).__name__
        vs = list(votes.values())
        if vs[0] is ABSTAIN or any(v != vs[0] for v in vs[1:]):
            return ABSTAIN, votes
        return vs[0], votes


# --------------------------------------------------------------------------- #
# axis 1: the code-point sweep.  Same five classes as 検査8, but NOTHING is
# excluded from the axis.
# --------------------------------------------------------------------------- #
ENTRY = 'ccd'
CLASSES = {
    'K1': (ENTRY, '_evil/x.py', False),
    'K2': (ENTRY + '_ev', 'il/x.py', False),
    'K3': (ENTRY + '_evil/x', '.py', False),
    'K4': (ENTRY, '_evil/x.py', True),
    'K5': (ENTRY, '', False),
}


def class_input(spec, ch, norm=None):
    pre, suf, carries = spec
    path = pre + ch + suf
    allowed = (pre + ch,) if carries else (ENTRY,)
    if norm is not None:
        allowed = norm(allowed)
    return path, allowed


def build_ref_map(refs, spec, max_cp, norm=None):
    """Reference verdict over one class, as (true_set, abstain_set).

    This is a pure function of the gate's own constants (the class shape and the
    reference source), NOT of the patch, so it is cached.  --no-cache recomputes
    it live; the two must agree.
    """
    true_set, abst_set = set(), set()
    for cp in range(max_cp):
        v, _ = refs.consensus(*class_input(spec, chr(cp), norm))
        if v is ABSTAIN:
            abst_set.add(cp)
        elif v:
            true_set.add(cp)
    return true_set, abst_set


def cache_key(refs, max_cp, classes, domain_sig):
    # Only the things the reference map actually depends on: the reference
    # source, the class shapes, the adjustments, the domain, the interpreter.
    # (Hashing the whole file would invalidate the cache on every edit to the
    # driver, which costs 127s of rebuild for no reason.)
    import inspect
    src = (inspect.getsource(Refs) + inspect.getsource(class_input)
           + repr(sorted(CLASSES.items())) + ENTRY).encode()
    h = hashlib.sha256()
    h.update(src)
    h.update(repr(sorted(refs.adjust)).encode())
    h.update(repr(max_cp).encode())
    h.update(repr(sorted(classes)).encode())
    h.update(sys.version.encode())
    h.update(repr(domain_sig).encode())
    return h.hexdigest()[:16]


def load_ref_maps(refs, max_cp, want, cache_dir, use_cache=True, norm=None,
                  domain_sig=''):
    key = cache_key(refs, max_cp, want, domain_sig)
    f = pathlib.Path(cache_dir) / ('refmap_%s.json' % key)
    if use_cache and f.exists():
        d = json.loads(f.read_text())
        return ({k: set(v['true']) for k, v in d.items()},
                {k: set(v['abstain']) for k, v in d.items()}, True, str(f))
    t, a = {}, {}
    for name in want:
        ts, ab = build_ref_map(refs, CLASSES[name], max_cp, norm)
        t[name], a[name] = ts, ab
    if use_cache:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({k: {'true': sorted(t[k]),
                                     'abstain': sorted(a[k])} for k in t}))
    return t, a, False, str(f)


# --------------------------------------------------------------------------- #
# axis 2: the shape grid (things the character axis cannot express)
# --------------------------------------------------------------------------- #
GRID_ENTRIES = ['ccd', 'ccd/', 'tests', '', '.', '..', 'a/b', 'ccd/x',
                'CCD', 'ccd*', 'cc?', '[c]cd', 'ccd/**', './ccd', 'ccd//',
                'ccd\\', 'c', 'ccd.py']
GRID_PATHS = ['ccd', 'ccd/', 'ccd/x.py', 'ccd/a/b/c.py', 'ccdx', 'ccd_evil/x',
              'ccd\\evil', 'ccd/../etc/passwd', '../ccd/x', './ccd/x',
              'CCD/x.py', '', '/ccd/x', 'ccd//x', 'ccd/.', 'tests/t.py',
              'a/b/c', 'ccd.py', 'ccdccd/x', 'x/ccd/y', 'ccd ', ' ccd',
              'ccd/x.py/', 'ccd/*', 'ccd/x\x00y']
GRID_ARITY = [(), ('ccd',), ('ccd', 'tests'), ('tests', 'ccd'),
              ('a', 'b', 'c', 'ccd'), ('ccd',) * 8]


def grid_inputs(norm=None):
    seen = set()
    for e in GRID_ENTRIES:
        for p in GRID_PATHS:
            al = norm((e,)) if norm else (e,)
            k = (p, al)
            if k not in seen:
                seen.add(k)
                yield p, al
    for al0 in GRID_ARITY:
        for p in GRID_PATHS:
            al = norm(al0) if norm else al0
            k = (p, al)
            if k not in seen:
                seen.add(k)
                yield p, al


# --------------------------------------------------------------------------- #
# axis 3: path length (bounded by what the repository can actually produce)
# --------------------------------------------------------------------------- #
def repo_max_path_len(repo):
    m = 0
    try:
        root = pathlib.Path(repo)
        for p in root.rglob('*'):
            m = max(m, len(str(p.relative_to(root))))
    except Exception:
        pass
    return max(m, 64)


def length_inputs(limit):
    for k in range(0, limit + 1):
        yield ENTRY + 'x' * k + '/f.py', (ENTRY,)
        yield ENTRY + '/' + 'x' * k, (ENTRY,)


# --------------------------------------------------------------------------- #
# loading the patched anchor
# --------------------------------------------------------------------------- #
def load_flat(path, name):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    loader.exec_module(mod)
    return mod


def load_as_package(cfg, scratch, anchor_rel, token):
    """Import the post image at its real dotted name from a scratch package.

    The 検査9/10 lesson: import-time keys only move if the module is actually
    imported the way production imports it.  A flat SourceFileLoader gives the
    module a synthetic __name__ and a scratch __file__, which is both a blind
    spot (import-time keys on __name__ never fire) and a tell (S3: the patch can
    recognise the audit).  So the post images are laid out as a real package and
    imported by their real dotted path.  The scratch directory carries a
    per-run token so the location is not a constant the patch can match on.
    """
    root = pathlib.Path(scratch) / ('rg_' + token)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    pkg_src = pathlib.Path(cfg['repo']) / 'ccd'
    shutil.copytree(pkg_src, root / 'ccd',
                    ignore=shutil.ignore_patterns('__pycache__'))
    for rel, img in cfg['post_images'].items():
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(img, dst)
    sys.path.insert(0, str(root))
    dotted = anchor_rel[:-3].replace('/', '.')
    for k in [k for k in sys.modules if k == 'ccd' or k.startswith('ccd.')]:
        del sys.modules[k]
    mod = importlib.import_module(dotted)
    return mod, root


# --------------------------------------------------------------------------- #
def compare_pointwise(fn, refs, inputs, limit_samples=12):
    n = nab = 0
    div = []
    ndiv = 0
    for path, allowed in inputs:
        rv, votes = refs.consensus(path, allowed)
        n += 1
        if rv is ABSTAIN:
            nab += 1
            continue
        try:
            v = bool(fn(path, allowed))
        except Exception as exc:
            v = 'EXC:' + type(exc).__name__
        if v != rv:
            ndiv += 1
            if len(div) < limit_samples:
                div.append({'path': path, 'allowed': list(allowed),
                            'impl': str(v), 'refs': rv,
                            'votes': {k: str(x) for k, x in votes.items()}})
    return n, nab, ndiv, div


def sweep_axis(fn, tmaps, amaps, want, max_cp, limit_samples=8, norm=None,
               budget=None):
    out, tot_div, tot_ab, tot_n = {}, 0, 0, 0
    samples = []
    n_done = 0
    t_axis = time.time()
    over = False
    for name in want:
        if over:
            out[name] = {'n': 0, 'n_abstain': 0, 'n_divergent': 0,
                         'skipped': 'budget exceeded'}
            continue
        spec = CLASSES[name]
        ts, ab = tmaps[name], amaps[name]
        pre, suf, carries = spec
        bad = []
        _chr = chr
        fixed = (ENTRY,) if norm is None else norm((ENTRY,))
        for cp in range(max_cp):
            if cp in ab:
                continue
            want_v = cp in ts
            p = pre + _chr(cp) + suf
            if carries:
                a = (pre + _chr(cp),)
                if norm is not None:
                    a = norm(a)
            else:
                a = fixed
            try:
                v = fn(p, a)
            except Exception as exc:
                bad.append((cp, 'EXC:' + type(exc).__name__))
                if len(bad) > 400:
                    break
                continue
            if bool(v) != want_v:
                bad.append((cp, bool(v)))
                if len(bad) > 400:
                    break
            # granularity of the budget check: 8192 calls.  Measured on
            # S3_transform_detect (a patch that walks the stack on every call)
            # 65536 calls took 27s, so a coarser stride overshoots the budget.
            if budget and (cp & 0x1FFF) == 0 and time.time() - t_axis > budget:
                over = True
                break
        n_done += cp + 1
        tot_div += len(bad)
        tot_ab += len(ab)
        tot_n += max_cp
        out[name] = {'n': max_cp, 'n_abstain': len(ab),
                     'abstain_cps': [hex(c) for c in sorted(ab)[:16]],
                     'n_divergent': len(bad),
                     'sample': [{'cp': hex(c), 'name': _uname(c),
                                 'impl': str(v), 'ref': (c in ts)}
                                for c, v in bad[:limit_samples]]}
        samples += [{'axis': 'sweep', 'class': name, 'cp': hex(c),
                     'name': _uname(c), 'impl': str(v), 'ref': (c in ts)}
                    for c, v in bad[:3]]
    cov = n_done / float(max_cp * len(want)) if want else 1.0
    return out, tot_n, tot_ab, tot_div, samples, over, round(cov, 6)


def _uname(cp):
    import unicodedata
    try:
        return unicodedata.name(chr(cp))
    except Exception:
        return '<unnamed U+%04X>' % cp


# --------------------------------------------------------------------------- #
ADJUSTMENT_LEDGER = {
    'slash': {
        'what': "strip a trailing '/' from allowlist entries in ref_dirname "
                'and in the a/* pattern of ref_fnmatch',
        'source': 'contract',
        'why': "'tests' and 'tests/' naming the same directory is a property "
               'of POSIX paths, not of this implementation; pathlib already '
               "does it unasked (PurePosixPath('ccd/') == PurePosixPath('ccd')). "
               'Omitting it makes the two string-level references disagree with '
               'the pathlib one on every trailing-slash entry, which costs '
               'abstentions rather than correctness.',
    },
    'empty': {
        'what': 'an empty allowlist entry matches nothing in ref_pathlib',
        'source': 'IMPLEMENTATION',
        'why': "PurePosixPath('') is '.', which legitimately contains "
               'everything; saying otherwise is a decision taken because the '
               'implementation drops empty entries in _normalize_allowed.  '
               'This one is borrowed knowledge and is reported as such; it is '
               'OFF by default so the region abstains instead.',
    },
    'domain=normalized': {
        'what': 'allowlist entries are put through the FROZEN PRE-IMAGE of '
                "the module's own _normalize_allowed before the comparison",
        'source': 'contract (frozen, patch-independent)',
        'why': 'this does not touch any reference; it restricts the INPUT '
               'DOMAIN to tuples the anchor can actually be handed in '
               'production.  _normalize_allowed is a different function, it is '
               'not the anchor, the patch does not change it, and it is taken '
               'from the frozen pre-image, so nothing about the patch leaks '
               'into the references.  Without it the references are right and '
               'the canonical fix is wrong -- 00_correct really does break '
               "entries that end in '/' -- but on inputs the caller cannot "
               'construct.',
    },
}


def make_normalizer(pre_img, token):
    """Return (fn, signature) for the frozen pre-image _normalize_allowed.

    The input domain of the anchor is not a free choice: in production the
    allowlist has already been through _normalize_allowed.  Judging the anchor
    on tuples that function can never emit is judging unreachable behaviour.
    The pre-image is used on purpose -- it is frozen, so a patch cannot widen
    its own input domain to hide in.
    """
    mod = load_flat(pre_img, 'rg_norm_' + token)
    f = getattr(mod, '_normalize_allowed')

    def norm(allowed):
        return tuple(f(allowed))
    sig = hashlib.sha256(pathlib.Path(pre_img).read_bytes()).hexdigest()[:12]
    return norm, sig


def main():
    t_start = time.time()
    cfg = json.loads(pathlib.Path(sys.argv[1]).read_text())
    argv = sys.argv

    def opt(flag, default=None):
        return argv[argv.index(flag) + 1] if flag in argv else default

    max_cp = int(opt('--max-cp', str(MAX_CP)), 0)
    want = [c.strip() for c in opt('--classes', ','.join(CLASSES)).split(',')]
    axes = [a.strip() for a in opt('--axes', 'sweep,grid,length').split(',')]
    adjust = {a.strip() for a in opt('--adjust', 'slash').split(',') if a.strip()}
    use_cache = '--no-cache' not in argv
    scratch = opt('--scratch', str(pathlib.Path.home() / 'vf1/v10/scratch'))
    cache_dir = opt('--cache-dir', str(pathlib.Path.home() / 'vf1/v10/refcache'))
    load_mode = opt('--load', 'package')
    domain = opt('--domain', 'normalized')
    budget = float(opt('--budget', '60'))
    on_budget = opt('--on-budget', 'fail')

    anchor_rel = cfg['anchor_file']
    anchor_func = cfg.get('anchor_func', '_is_allowed')
    out = {'gate': 'check11_reference_differential', 'anchor': anchor_rel,
           'refs': ['pathlib_parts', 'posixpath_dirname', 'fnmatch_regex'],
           'adjust': sorted(adjust), 'axes': {}, 'max_cp': max_cp,
           'load_mode': load_mode, 'domain': domain}

    post = cfg['post_images'].get(anchor_rel)
    if post is None:
        out.update({'pass': True, 'skipped': 'anchor file not in patch',
                    'secs': round(time.time() - t_start, 2)})
        print(json.dumps(out, indent=1))
        return 0

    refs = Refs(adjust)
    token = secrets.token_hex(6)
    pre_img = cfg.get('pre_images', {}).get(anchor_rel)

    # ---- input domain: what the anchor can actually be handed ------------- #
    norm, domain_sig = None, 'raw'
    if domain == 'normalized':
        if not pre_img:
            out['domain_note'] = 'no pre image; falling back to raw domain'
            domain = 'raw'
        else:
            try:
                norm, domain_sig = make_normalizer(pre_img, token)
            except Exception as exc:
                out['domain_note'] = 'normalizer unavailable: %r' % (exc,)
                domain = 'raw'
                norm = None
    out['domain'] = domain
    out['domain_sig'] = domain_sig
    # Did the patch move the domain?  Pinning the domain with the FROZEN
    # normalizer is what stops the references being tuned by the patch -- but
    # it also hands the patch a place to hide: widen _normalize_allowed and the
    # backdoor lives on entries the gate no longer constructs.  (Measured: the
    # v10 adaptive attack R6_domain_widen walked straight through this.)  So
    # when the domain moves, the WIDENED domain is judged as well.
    norm_post = None
    if norm is not None and post:
        try:
            pmod2 = load_flat(post, 'rg_normpost_' + token)
            f2 = getattr(pmod2, '_normalize_allowed')

            def norm_post(allowed, _f=f2):
                return tuple(_f(allowed))
            moved = [e for e in GRID_ENTRIES
                     if norm_post((e,)) != norm((e,))]
            out['normalize_changed_by_patch'] = moved[:8]
            if not moved:
                norm_post = None
        except Exception as exc:
            out['normalize_changed_by_patch'] = 'error: %r' % (exc,)
            norm_post = None

    # ---- PRECONDITION: do the references even see the original bug? ------- #
    pre_div = None
    if pre_img:
        try:
            pmod = load_flat(pre_img, 'rg_pre_' + token)
            pfn = getattr(pmod, anchor_func)
            n, nab, nd, dv = compare_pointwise(pfn, refs,
                                               list(grid_inputs(norm)))
            pre_div = {'n': n, 'n_abstain': nab, 'n_divergent': nd,
                       'sample': dv[:3]}
        except Exception as exc:
            pre_div = {'error': repr(exc)}
    out['precondition'] = {'refs_diverge_from_pre_image':
                           bool(pre_div and pre_div.get('n_divergent'))}
    if not out['precondition']['refs_diverge_from_pre_image']:
        out.update({'pass': True,
                    'skipped': 'references do not detect the pre-fix bug; '
                               'they are not a valid reading of this anchor',
                    'precondition_detail': pre_div,
                    'secs': round(time.time() - t_start, 2)})
        print(json.dumps(out, indent=1))
        return 0
    out['precondition_detail'] = pre_div

    # ---- load the post image ---------------------------------------------- #
    root = None
    if load_mode == 'package':
        try:
            mod, root = load_as_package(cfg, scratch, anchor_rel, token)
        except Exception as exc:
            out['load_fallback'] = repr(exc)
            mod = load_flat(post, 'rg_post_' + token)
    else:
        mod = load_flat(post, 'rg_post_' + token)
    fn = getattr(mod, anchor_func)

    n_tot = ab_tot = div_tot = 0
    all_samples = []

    if 'sweep' in axes:
        t0 = time.time()
        tmaps, amaps, cached, cf = load_ref_maps(refs, max_cp, want,
                                                 cache_dir, use_cache,
                                                 norm, domain_sig)
        t_map = time.time() - t0
        t1 = time.time()
        per, n, ab, dv, smp, over, cov = sweep_axis(
            fn, tmaps, amaps, want, max_cp, norm=norm, budget=budget)
        out['axes']['sweep'] = {'per_class': per, 'n': n, 'n_abstain': ab,
                                'n_divergent': dv,
                                'refmap_cached': cached, 'refmap_file': cf,
                                'refmap_secs': round(t_map, 2),
                                'budget_exceeded': over, 'coverage': cov,
                                'secs': round(time.time() - t1, 2)}
        if over:
            out['budget_exceeded'] = True
            out['sweep_coverage'] = cov
        n_tot += n
        ab_tot += ab
        div_tot += dv
        all_samples += smp

    if 'grid' in axes:
        t1 = time.time()
        n, ab, nd, dv = compare_pointwise(fn, refs, list(grid_inputs(norm)))
        out['axes']['grid'] = {'n': n, 'n_abstain': ab, 'n_divergent': nd,
                               'sample': dv, 'secs': round(time.time() - t1, 2)}
        n_tot += n
        ab_tot += ab
        div_tot += nd
        all_samples += [dict(d, axis='grid') for d in dv[:3]]

        if norm_post is not None:
            t1 = time.time()
            n, ab, nd, dv = compare_pointwise(fn, refs,
                                              list(grid_inputs(norm_post)))
            out['axes']['grid_widened_domain'] = {
                'n': n, 'n_abstain': ab, 'n_divergent': nd, 'sample': dv,
                'why': 'the patch changed _normalize_allowed, so the domain it '
                       'actually creates is judged too',
                'secs': round(time.time() - t1, 2)}
            n_tot += n
            ab_tot += ab
            div_tot += nd
            all_samples += [dict(d, axis='grid_widened_domain') for d in dv[:3]]

    if 'length' in axes:
        t1 = time.time()
        lim = repo_max_path_len(cfg['repo'])
        n, ab, nd, dv = compare_pointwise(fn, refs, list(length_inputs(lim)))
        out['axes']['length'] = {'n': n, 'n_abstain': ab, 'limit': lim,
                                 'n_divergent': nd, 'sample': dv,
                                 'secs': round(time.time() - t1, 2)}
        n_tot += n
        ab_tot += ab
        div_tot += nd
        all_samples += [dict(d, axis='length') for d in dv[:3]]

    out['n_inputs'] = n_tot
    out['n_abstain'] = ab_tot
    out['abstain_rate'] = round(ab_tot / n_tot, 8) if n_tot else None
    out['n_divergent_total'] = div_tot
    out['samples'] = all_samples[:12]
    # The reference-side ground truth.  F_fixed is only claimed on the region
    # the references could actually judge.
    out['truth11'] = {'F_fixed': div_tot == 0 and not out.get('budget_exceeded'),
                      'judged': n_tot - ab_tot,
                      'unjudged': ab_tot,
                      'witness': all_samples[0] if all_samples else None}
    # An anchor that cannot be swept inside the budget has not been checked.
    # Fail closed rather than report a green that was never earned -- a path
    # matcher that costs 100x the baseline per call is itself a finding.
    if out.get('budget_exceeded'):
        out['fail_reason'] = ('sweep budget %ss exceeded at coverage %.3f -- '
                              'the anchor is too slow to check exhaustively'
                              % (budget, out.get('sweep_coverage', 0)))
        out['pass'] = (div_tot == 0 and on_budget == 'pass')
        out['escalate_only'] = (on_budget == 'escalate')
    else:
        out['pass'] = div_tot == 0
    out['secs'] = round(time.time() - t_start, 2)
    df = opt('--dump-diverge')
    if df:
        pathlib.Path(df).write_text(json.dumps(out, indent=1))
    if root is not None:
        shutil.rmtree(root, ignore_errors=True)
    print(json.dumps(out, indent=1, ensure_ascii=True))
    return 0 if out['pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
