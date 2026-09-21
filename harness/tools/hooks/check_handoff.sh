#!/usr/bin/env bash
# Thin wrapper: the logic lives in check_handoff.py so the hook JSON on stdin
# reaches Python untouched (same heredoc-eats-stdin lesson as guard_run_corpus.sh).
exec python3 "$(dirname "$0")/check_handoff.py"
