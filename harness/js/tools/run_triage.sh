#!/bin/bash
# v42: 検査4 の「生存」報告を、手で同じ変異を当てて検算する。
#
#   wsl.exe bash .../tools/run_triage.sh <変種ID> [--run] [追加フラグ...]
#
# 例:
#   run_triage.sh S16_scrypt_cost --run          # 検査4 を回し直してから仕分ける
#   run_triage.sh S16_scrypt_cost                # いま repo にある report を使う
#   run_triage.sh S16_scrypt_cost --run --extra-args "--coverage-analysis perTest"
#
# ★変数をここに書いてあるのは HANDOFF 罠10 のため。
#   `wsl.exe bash -c '... $V ...'` は外側の Git Bash が先に $V を空へ展開する。
set -u
# ★v134 (judgement 61): the five machine paths below are resolved in ONE
# place now -- harness/tools/vf_env.sh.  They used to be literals here.
. "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)/tools/vf_env.sh"
NODE="${NODE_BIN_DIR:+$NODE_BIN_DIR/}node"
GATES="$JS_GATES_DIR"
ORCH="$CLIENT_VF/orch2"
WIN="$VF_SKILL_DIR/harness/js"

ID="${1:?変種ID を渡すこと（例: S16_scrypt_cost）}"; shift

# 道具も正本から同期する（古いコピーで測ると測定が無効になる）
cp "$WIN/tools/mutant_triage.mjs" /tmp/mutant_triage.mjs || exit 1
cp "$WIN/gates/mutgate.mjs" "$GATES/mutgate.mjs" || exit 1
"$NODE" --check /tmp/mutant_triage.mjs || exit 1
"$NODE" --check "$GATES/mutgate.mjs"   || exit 1

exec "$NODE" /tmp/mutant_triage.mjs "$ORCH/$ID.cfg.json" --gates "$GATES" "$@"
