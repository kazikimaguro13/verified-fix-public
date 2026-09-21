#!/bin/bash
# v46: gate_power.mjs を PowerShell から呼ぶための包み。
#
#   wsl.exe bash .../tools/run_gate_power.sh <変種ID> [追加フラグ...]
#
# 例:
#   run_gate_power.sh S5_refactor --out /tmp/gp_S5.json
#   run_gate_power.sh S5_refactor --positive-control src/lib/gmail-oauth-sender.ts=/abs/PWR2.ts
#
# ★変数をここに書いてあるのは HANDOFF 罠10 のため。
#   `wsl.exe bash -c '... $V ...'` は外側のシェルが先に $V を空へ展開する。
# ★道具とゲートは正本から同期する。古いコピーで測ると測定そのものが無効になる。
set -u
# ★v134 (judgement 61): the five machine paths below are resolved in ONE
# place now -- harness/tools/vf_env.sh.  They used to be literals here.
. "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)/tools/vf_env.sh"
NODE="${NODE_BIN_DIR:+$NODE_BIN_DIR/}node"
GATES="$JS_GATES_DIR"
ORCH="$CLIENT_VF/orch2"
WIN="$VF_SKILL_DIR/harness/js"

ID="${1:?変種ID を渡すこと（例: S5_refactor）}"; shift

cp "$WIN/tools/gate_power.mjs" /tmp/gate_power.mjs || exit 1
"$NODE" --check /tmp/gate_power.mjs || exit 1
# 測る対象のゲートも正本から（sync_gates.sh の既定集合と同じ狙い）
bash "$WIN/tools/sync_gates.sh" diffgate.mjs parse.mjs anchorspec.mjs drive.mjs mutgate.mjs || exit 1

exec "$NODE" /tmp/gate_power.mjs "$ORCH/$ID.cfg.json" --gates "$GATES" "$@"
