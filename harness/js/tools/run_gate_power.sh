#!/bin/bash
# v46: gate_power.mjs を PowerShell から呼ぶための包み。
#
#   wsl.exe bash .../tools/run_gate_power.sh <変種ID> [追加フラグ...]
#
# 例:
#   run_gate_power.sh S5_refactor --out /tmp/gp_S5.json
#   run_gate_power.sh S5_refactor --positive-control src/lib/gmail-oauth-sender.ts=/abs/PWR2.ts
#   run_gate_power.sh N17_allowlist_key --gate check8 --no-early-stop
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
# ★v139: the cfg store is an override, because a measurement that must not
#   touch the shipping clone (v139 ran on the client clone) needs to point
#   somewhere else without editing this file.  Default is unchanged.
ORCH="${VF_ORCH_DIR:-$CLIENT_VF/orch2}"
WIN="$VF_SKILL_DIR/harness/js"

ID="${1:?変種ID を渡すこと（例: S5_refactor）}"; shift

# ★v139: the tool is run FROM THE CHECKOUT, not from a copy in /tmp.
#   MEASURED: `cp gate_power.mjs /tmp` and running it there has been broken
#   since v134, because the file imports `./vf_paths.mjs` -- a relative
#   specifier that resolves next to the COPY, where that module does not exist.
#   `--check` still passed (it only parses), so the breakage was invisible.
#   The syntax check stays; what moved is which file is executed.
"$NODE" --check "$WIN/tools/gate_power.mjs" || exit 1

# 測る対象のゲートも正本から（sync_gates.sh の既定集合と同じ狙い）。
# ★v139 (A7-r 1): 検査8/9/12 も測るようになったので、それらとその依存も同期する。
#   VF_NO_SYNC=1 で飛ばせる — ゲートに1バイトも触ってはならない走行のため。
if [ "${VF_NO_SYNC:-0}" != "1" ]; then
  bash "$WIN/tools/sync_gates.sh" \
    diffgate.mjs parse.mjs anchorspec.mjs drive.mjs mutgate.mjs \
    mrgate.mjs ambgate.mjs spygate.mjs regexgen.mjs scratch.mjs \
    parse_acorn.mjs parse_babel.mjs || exit 1
fi

exec "$NODE" "$WIN/tools/gate_power.mjs" "$ORCH/$ID.cfg.json" --gates "$GATES" "$@"
