# -*- coding: utf-8 -*-
"""verified-fix hook -- PostToolUse on Edit|Write|Bash.

After anything that touches HANDOFF.md (a direct Edit/Write, or a Bash that runs
one of the vNN_handoff.py scripts), run the two hygiene checks that were skipped
by hand three times each:
  check_line_endings.py  -- bare LF inside the CRLF file (v79, v80)
  dedupe.py --check      -- a clause repeated in the 最終更新 line (v76, v78, v79)
Report-only: nothing is rewritten here, so the Edit tool's view of the file stays
valid.  Exit 2 with the findings on stderr when something is off; exit 0 silently
when clean or when the tool call had nothing to do with HANDOFF.
"""
import json, subprocess, sys

try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
ti = d.get("tool_input") or {}
touched = " ".join(str(ti.get(k, "")) for k in
                   ("file_path", "command", "content", "old_string", "new_string"))
if "handoff" not in touched.lower():
    sys.exit(0)

# ★v134 (judgement 61): derived from this file's own location, with the
# same fallback vf_paths.py itself uses.  The try/except is deliberate:
# this hook runs on EVERY Edit/Write/Bash, so it must not be able to die
# because a module moved.
import pathlib as _pathlib
sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[2] / "src"))
try:
    from vf_paths import VF_SKILL_DIR as SK  # noqa: E402
except Exception:
    SK = str(_pathlib.Path(__file__).resolve().parents[3])
problems = []
r = subprocess.run(["python3", SK + "/harness/js/tools/check_line_endings.py"],
                   capture_output=True, text=True)
row = [l for l in r.stdout.splitlines() if l.startswith("HANDOFF.md")]
if not row:
    problems.append("check_line_endings.py printed no HANDOFF.md row: " + (r.stderr or r.stdout)[-200:])
elif "単独LF=0" not in row[0]:
    problems.append("HANDOFF.md has bare LF: " + row[0].strip())
r = subprocess.run(["python3", SK + "/harness/attack-corpus/reports/v79_raw/dedupe.py", "--check"],
                   capture_output=True, text=True)
if r.returncode != 0:
    last = (r.stdout.strip().splitlines() or ["(no output)"])[-1]
    problems.append("dedupe.py --check found a repeated clause in the 最終更新 line: " + last)
if not problems:
    sys.exit(0)
sys.stderr.write("verified-fix hook: HANDOFF.md hygiene after this edit:\n  - "
                 + "\n  - ".join(problems)
                 + "\nFix before committing (normalize CRLF / run dedupe.py without --check).\n")
sys.exit(2)
