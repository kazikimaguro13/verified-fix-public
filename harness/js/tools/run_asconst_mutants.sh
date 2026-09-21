#!/bin/bash
# v50: asconst_mutants.mjs を PowerShell から呼ぶための包み。**ゲートではない。**
#
#   wsl.exe bash .../tools/run_asconst_mutants.sh <変種ID> [追加フラグ...]
#
# ★変数をここに書いてあるのは HANDOFF 罠10 のため。
#   `wsl.exe bash -c '... $V ...'` は外側のシェル（Git Bash でも PowerShell でも）が
#   先に $V を空へ展開する。
#
# ★★このファイルは LF で保存すること（v50 実測）。
#   CRLF の .sh を `wsl.exe bash /mnt/c/....sh` で直接走らせると、`set -u` が
#   `set: -: 無効なオプション` になり、`cd "$D"` は $'...\r' を探して落ちる。
#   全数（追跡862ファイル）を数えた結果、CRLF は16本・混在0（v50: reports/v50_raw/crlf_census_v50.txt）。
#   tools/ は .sh も .mjs も全部 LF なので、ここも LF に合わせる。
#
# ★道具は正本から同期する。古いコピーで測ると測定そのものが無効になる。
set -u
# ★v134 (judgement 61): the five machine paths below are resolved in ONE
# place now -- harness/tools/vf_env.sh.  They used to be literals here.
. "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)/tools/vf_env.sh"
NODE="${NODE_BIN_DIR:+$NODE_BIN_DIR/}node"
GATES="$JS_GATES_DIR"
ORCH="$CLIENT_VF/orch2"
WIN="$VF_SKILL_DIR/harness/js"
OUT="$CLIENT_VF/orch2/results_v50"

ID="${1:?変種ID を渡すこと（例: S1_control）}"; shift

mkdir -p "$OUT" || exit 1
cp "$WIN/tools/asconst_mutants.mjs" /tmp/asconst_mutants.mjs || exit 1
"$NODE" --check /tmp/asconst_mutants.mjs || exit 1
bash "$WIN/tools/sync_gates.sh" mutgate.mjs || exit 1

exec "$NODE" /tmp/asconst_mutants.mjs "$ORCH/$ID.cfg.json" --gates "$GATES" --raw-dir "$OUT" --out "$OUT/$ID.v50.json" "$@"
