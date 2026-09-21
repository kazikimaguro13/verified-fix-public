#!/usr/bin/env bash
# Thin wrapper: the logic lives in guard_run_corpus.py so the hook JSON on stdin
# reaches Python untouched.  (A `python3 - <<EOF` heredoc here consumed stdin and
# the guard silently passed everything -- caught by the pipe test, v87.)
exec python3 "$(dirname "$0")/guard_run_corpus.py"
