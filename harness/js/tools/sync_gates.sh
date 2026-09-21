#!/bin/bash
# 正本（Windows 側リポジトリ）→ WSL の実行コピーへ同期して構文検査する。
#
# なぜスクリプトにするか: `wsl.exe bash -c '... for f in ...; do $f ...'` は
# **外側の Git Bash が $f を先に空へ展開する**（HANDOFF 罠10）。
# 空文字を渡された `node --check ""` は標準入力を待って固まる。
set -u
# ★v134 (judgement 61): the five machine paths below are resolved in ONE
# place now -- harness/tools/vf_env.sh.  They used to be literals here.
. "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)/tools/vf_env.sh"
WIN="$VF_SKILL_DIR/harness/js/gates"
DST="$JS_GATES_DIR"
NODE="${NODE_BIN_DIR:+$NODE_BIN_DIR/}node"

# v44: diffgate.mjs / parse.mjs joined the default set when 検査5 was wired to
# the anchor spec.  Leaving them out is how a measurement gets taken with an old
# copy of the gate that was just edited.
FILES="${*:-drive.mjs mrgate.mjs regexgen.mjs anchorspec.mjs run_gates.mjs mutgate.mjs diffgate.mjs parse.mjs}"
RC=0
for F in $FILES; do
  cp "$WIN/$F" "$DST/$F" || { echo "NG  $F コピー失敗"; RC=1; continue; }
  if "$NODE" --check "$DST/$F" 2>/tmp/chk.err; then
    echo "OK  $F"
  else
    echo "NG  $F 構文エラー:"; sed -n 1,6p /tmp/chk.err; RC=1
  fi
done
exit $RC
