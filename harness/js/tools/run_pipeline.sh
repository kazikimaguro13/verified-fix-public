#!/bin/bash
# v33: 追加フラグ付きでパイプラインを回す。
#   $1 = profile, $2 = 出力サフィックス, $3 = run_gates への追加フラグ（空文字可）,
#   $4.. = 変種名
set -u
# ★v134 (judgement 61): the five machine paths below are resolved in ONE
# place now -- harness/tools/vf_env.sh.  They used to be literals here.
. "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)/tools/vf_env.sh"
NODE="${NODE_BIN_DIR:+$NODE_BIN_DIR/}node"
GATES="$JS_GATES_DIR"
ORCH="$CLIENT_VF/orch2"
WIN="$VF_SKILL_DIR/harness/js/gates"

# v44: diffgate.mjs / parse.mjs added (検査5 now runs from the anchor spec).
for F in run_gates.mjs mrgate.mjs drive.mjs anchorspec.mjs mutgate.mjs regexgen.mjs diffgate.mjs parse.mjs; do
  cp "$WIN/$F" "$GATES/$F" || exit 1
done

PROFILE="$1"; shift
SUF="$1"; shift
EXTRA="$1"; shift

cd "$ORCH" || exit 1
for V in "$@"; do
  START=$(date +%s)
  "$NODE" "$GATES/run_gates.mjs" "$ORCH/$V.cfg.json" \
      --profile "$PROFILE" --out "$ORCH/results_$SUF" $EXTRA \
      > "/tmp/pipe_${V}_${SUF}.json" 2> "/tmp/pipe_${V}_${SUF}.err"
  echo "$V [$PROFILE $EXTRA] exit=$? wall=$(( $(date +%s) - START ))s"
done
