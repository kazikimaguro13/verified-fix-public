# -*- coding: utf-8 -*-
"""verified-fix hook -- PreToolUse on Bash.

Two guards on the Python corpus runners (HANDOFF traps 2, 12, 13; decision 12
of 2026-09-07):

  * run_corpus.py (the OLD runner) is refused outright.  It has no per-clone
    TMPDIR, so the shared-temp glob test (trap 2) turns R4/R5 red at random
    across parallel clones; v83's record carried three such kills and a
    control could have come back as a hard false positive.  Its defaults are
    also stale (manifest_v2 / one oracle -- traps 12/13, v82).
  * run_corpus_v11.py (the isolating runner) is refused unless it names the
    three oracles and puts --profile INSIDE --gate-args as well: the runner
    uses its own --profile only for directory names and does not forward it
    to the gates, so a "strict" run without it silently runs the gates in
    their default profile.

Any other Bash command passes through untouched (exit 0, no output).  Only an
INVOCATION counts (`python3 [path/]run_corpus*.py ...` or `/path/run_corpus*.py`);
a bare mention in prose (a commit message, a memory line) must pass --
measured (v87): matching the substring anywhere blocked a commit whose message
merely named the script.

Reads the hook JSON on stdin.  Exit 2 = block; stderr is shown to Claude.
(Kept as a .py file on purpose: a `python3 - <<EOF` heredoc inside the .sh
consumed stdin, so the hook payload was never read -- caught by the pipe test.)
"""
import json, re, sys

try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)                      # not our business; never block on a parse error
cmd = str((d.get("tool_input") or {}).get("command", ""))

CORRECT = (
    "  python3 harness/src/run_corpus_v11.py --profile <p> --jobs 4 --outdir ~/vf1/<label> \\\n"
    "      --label <label> --manifest ~/vf1/manifest_v8.json --baseline ~/vf1/baseline_v8.json \\\n"
    "      --gate-args \"--profile <p> --oracle alt0=tests/test_oracle_F_pbt.py "
    "--oracle alt1=tests/test_oracle_Fprime_caller.py --oracle alt2=tests/test_oracle_Falt2_top.py\"\n")

# ---- the old runner: refused ----------------------------------------------
if re.search(r"(python3?\s+\S*run_corpus\.py|/run_corpus\.py)(\s|$)", cmd):
    sys.stderr.write(
        "verified-fix hook (HANDOFF 罠2 / 判断12, 2026-09-07): run_corpus.py is the OLD runner.\n"
        "It gives the parallel clones ONE shared TMPDIR, so tests/test_adversarial.py::"
        "test_tmp_fixture_dir_is_cleaned_up_on_exit goes red at random and R4/R5 kills move "
        "between runs (v83 carried three; a control would read as a hard false positive).\n"
        "Use run_corpus_v11.py (per-clone TMPDIR, resume, split false positives):\n" + CORRECT)
    sys.exit(2)

# ---- the isolating runner: check the arguments the gates depend on ---------
if not re.search(r"(python3?\s+\S*run_corpus_v11\.py|/run_corpus_v11\.py)(\s|$)", cmd):
    sys.exit(0)
missing = []
if len(re.findall(r"--oracle\s+\S+", cmd)) < 3:
    missing.append("--oracle x3 (alt0 / alt1 / alt2) inside --gate-args")
m = re.search(r"--gate-args\s+(\"[^\"]*\"|'[^']*'|\S+)", cmd)
if not (m and "--profile" in m.group(1)):
    missing.append("--profile <p> INSIDE --gate-args (the runner's own --profile only names directories)")
if not missing:
    sys.exit(0)
sys.stderr.write(
    "verified-fix hook (HANDOFF 罠3/罠13): run_corpus_v11.py is missing "
    + "; ".join(missing) + ".\n"
    "Without them the gates run in their default profile with one oracle and the run reads "
    "as defence while measuring something else. Correct shape:\n" + CORRECT)
sys.exit(2)
