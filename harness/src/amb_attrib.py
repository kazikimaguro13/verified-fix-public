#!/usr/bin/env python3
"""Which token witnessed each 検査9 divergence, and where does that token live?

The gate's design claim is that the values it feeds back are drawn from
(patch-new tokens) U (repository vocabulary) U (random).  If every catch is
witnessed only by a patch-new token, the gate is really 検査6 with a different
verdict rule; if repository tokens do the work, it is not.  Measured, not
assumed.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

import pathlib as _pathlib
import sys as _sys

# ★v134 (judgement 61): the machine paths below are resolved in ONE
# place now -- harness/src/vf_paths.py.  They used to be literals here.
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
from vf_paths import VF_HOME  # noqa: E402

d = json.load(open(sys.argv[1] if len(sys.argv) > 1
                   else os.path.join(VF_HOME, "v7tmp", "amb_full.json")))
out = {}
for name, r in d.items():
    if r.get("pass") is not False:
        continue
    patch_new = set(r.get("vocab", {}).get("patch_new") or [])
    wit = []
    for probe, det in (r.get("divergent") or {}).items():
        base = None
        for verdict, wheres in det["verdicts"].items():
            for w in wheres:
                axis, _, rest = w.partition("=")
                tok = rest.split("@call")[0]
                wit.append((axis, tok, verdict))
    # the witnessing token is the one carrying the MINORITY verdict
    minority = []
    for probe, det in (r.get("divergent") or {}).items():
        fc = det.get("first_call", {})
        late = max(fc, key=lambda k: fc[k]) if fc else None
        for w in det["verdicts"].get(late, []):
            axis, _, rest = w.partition("=")
            minority.append((axis.rstrip("!"), rest.split("@call")[0]))
    toks = sorted({t for _, t in minority})
    out[name] = {
        "axes": r.get("divergent_axes"),
        "witness_tokens": toks[:6],
        "in_patch_new": sorted(t for t in toks if t in patch_new),
        "repo_only": sorted(t for t in toks if t not in patch_new),
        "count_effect_suspected": r.get("count_effect_suspected"),
    }
print(json.dumps(out, indent=1, ensure_ascii=False))
