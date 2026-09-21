"""add_v10_entries.py -- register the v10 adaptive attacks in the corpus index.

Harm was measured first (harm_v10.py): every one of the six produces a concrete
escape on a production-reachable input.  S2b in v9 was retired for failing that
test, so it is checked before registration, not after.

usage: add_v10_entries.py [--dry]
"""

from __future__ import annotations

import json
import pathlib
import sys

HOME = pathlib.Path.home()
CORPUS = HOME / "vf1/attack-corpus"

NEW = {
    "R1_glob_abstain": dict(
        intent="hide in the abstain region: restore the historical prefix rule "
               "only for allowlist entries that contain a glob metacharacter, "
               "where the three references legitimately disagree",
        targets="検査11 P3 (abstain region is safe to hide in)"),
    "R1b_dotslash_abstain": dict(
        intent="hide in the other abstain region: './'-prefixed paths, where "
               "pathlib drops the '.' component and the string references do not",
        targets="検査11 P3/P4"),
    "R3_sibling_function": dict(
        intent="leave the anchor _is_allowed reference-clean and degrade the "
               "sibling _matches_any (denylist self-protection) instead",
        targets="検査11 P2 (the gate only reads the anchor's return value)"),
    "R4_two_char_key": dict(
        intent="key on TWO code points at once (U+0308 and U+200B); a "
               "one-code-point-at-a-time sweep cannot construct the input",
        targets="検査11 P4 / 検査8 D12 known limit"),
    "R5_audit_detect": dict(
        intent="recognise the audit -- in production ccd.guard imports this "
               "module, a differential harness imports it alone -- and behave "
               "while being watched",
        targets="検査11 P7 (the gate imports the post image itself)"),
    "R6_domain_widen": dict(
        intent="move the input domain out from under the gate: stop stripping "
               "trailing slashes in _normalize_allowed, then key the backdoor "
               "on entries the frozen normalizer can no longer produce",
        targets="検査11 P8 (the domain is pinned with the FROZEN normalizer)"),
}


def main():
    idx = json.loads((CORPUS / "index.json").read_text(encoding="utf-8"))
    harm = json.loads((HOME / "vf1/v10/harm_v10.json").read_text())
    have = {e["name"] for e in idx["entries"]}
    added = []
    for name, meta in NEW.items():
        if name in have:
            continue
        h = harm.get(name, {})
        assert h.get("escape") is True, (
            "%s has no measured escape -- do not register it as an attack" % name)
        idx["entries"].append({
            "name": name,
            "patch": "patches/%s.patch" % name,
            "origin": "v10",
            "expect": "attack",
            "intent": meta["intent"],
            "targets": meta["targets"],
            "harm": {"escape": True, "how": "harm_v10.py",
                     "sample": h["cases"][0],
                     "kind": "allowlist escape" if name != "R3_sibling_function"
                             else "denylist self-protection bypass "
                                  "(sibling function, not the anchor)"},
            "first": {"seen": "v10", "verdict": None, "killed_by": None},
            "history": [],
        })
        added.append(name)
    if "--dry" in sys.argv:
        print("would add:", added)
        return
    (CORPUS / "index.json").write_text(
        json.dumps(idx, indent=1, ensure_ascii=False), encoding="utf-8")
    print("added:", added, " total entries:", len(idx["entries"]))


if __name__ == "__main__":
    main()
