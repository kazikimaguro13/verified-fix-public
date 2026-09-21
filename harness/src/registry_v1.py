"""registry_v1.py — 不変条件レジストリ (DESIGN D4), minimal.

When a correct fix is accepted, the property it guaranteed is registered as an
**executable** invariant (prose is banned): a property test dropped in
``registry/`` plus an append-only ``index.jsonl`` row.  Because ``registry/`` is
part of the frozen manifest (D3), a later fix that rewrites the registry is
rejected at freeze (attack #8); because the gate runner collects ``registry/``
on every run, active invariants execute in Phase 4 and count toward R4 (D4:
"黙って消せば R4 が落ちる").

Commands:
  register --id inv_0001 --stated "..." --finding F --commit <sha> --oracle <path>
  list
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

# A registered invariant IS a property test (test_ prefix so pytest collects it
# from registry/).  This one pins F's guarantee: an allowlist entry grants real
# members but never siblings/extensions.
INV_0001 = '''"""Registered invariant inv_0001 — F's guarantee (verified-fix D4).

Accepted with the correct fix of ccd/guard_pathmatch._is_allowed.  Runs in every
subsequent Phase 4; a future regression that re-opens the allowlist escape fails
here before acceptance.
"""
from hypothesis import given, settings
from hypothesis import strategies as st

from ccd.guard_pathmatch import _is_allowed

_seg = st.from_regex(r"[a-z][a-z0-9_]{0,6}", fullmatch=True)
_entries = st.lists(_seg, min_size=1, max_size=3).map("/".join)
_suffix = st.from_regex(r"[a-z0-9_.\\-][a-z0-9_./\\-]{0,8}", fullmatch=True)


@settings(max_examples=150, derandomize=True, deadline=None)
@given(entry=_entries, suffix=_suffix)
def test_inv_0001_sibling_never_granted(entry, suffix):
    path = entry + suffix
    if path == entry or path.startswith(entry + "/"):
        return
    assert _is_allowed(path, (entry,)) is False
'''

ORACLES = {"inv_0001": INV_0001}


def register(reg: pathlib.Path, inv_id, stated, finding, commit, oracle_rel, anchor):
    reg.mkdir(parents=True, exist_ok=True)
    body = ORACLES.get(inv_id)
    if body is None:
        raise SystemExit(f"no oracle body known for {inv_id}")
    testfile = reg / f"test_{inv_id}_sibling.py"
    testfile.write_text(body)
    row = {"id": inv_id, "stated": stated,
           "source": {"finding": finding, "commit": commit,
                      "accepted": time.strftime("%Y-%m-%d")},
           "oracle": f"registry/{testfile.name}",
           "anchor": anchor, "status": "active", "supersedes": None}
    with (reg / "index.jsonl").open("a") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return testfile, row


def load_index(reg: pathlib.Path):
    idx = reg / "index.jsonl"
    if not idx.exists():
        return []
    return [json.loads(l) for l in idx.read_text().splitlines() if l.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["register", "list"])
    ap.add_argument("--registry", required=True)
    ap.add_argument("--id", default="inv_0001")
    ap.add_argument("--stated", default="allowlist entry grants real members, never siblings")
    ap.add_argument("--finding", default="F")
    ap.add_argument("--commit", default="HEAD")
    ap.add_argument("--oracle", default="")
    ap.add_argument("--anchor", action="append", default=["ccd/guard_pathmatch.py:_is_allowed"])
    a = ap.parse_args()
    reg = pathlib.Path(a.registry)

    if a.cmd == "list":
        print(json.dumps(load_index(reg), indent=1, ensure_ascii=False))
        return 0

    tf, row = register(reg, a.id, a.stated, a.finding, a.commit, a.oracle, a.anchor)
    print(json.dumps({"registered": row, "oracle_file": str(tf),
                      "active_count": len(load_index(reg))}, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
