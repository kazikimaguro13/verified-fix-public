#!/bin/bash
# v29: 検査8（mrgate）を全軸で3変種に当てる。
#
# なぜスクリプトファイルにするか: `wsl.exe bash -lc '... $V ...'` は
# **外側の Git Bash が先に $V を展開してしまう**ため、ループ変数が空になる。
# （HANDOFF 罠7 の別の顔。$? のような特殊変数だけが「生きて見える」ので気づきにくい。）
set -u

# ★v134 (judgement 61): the five machine paths below are resolved in ONE
# place now -- harness/tools/vf_env.sh.  They used to be literals here.
. "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)/tools/vf_env.sh"
NODE="${NODE_BIN_DIR:+$NODE_BIN_DIR/}node"
GATES="$JS_GATES_DIR"
LIT2="$CLIENT_VF/lit2"
REPO="$CLIENT_PORTAL/apps/portal-web"
MK="$VF_SKILL_DIR/harness/js/tools/mk_check8_cfg.py"

MAXCP="${1:-0x110000}"
PRECOND="${2:-0x800}"
shift 2 2>/dev/null || true
VARIANTS="${*:-N10_codepoint_class S1_control N11_two_char}"

cd "$REPO" || exit 1

for V in $VARIANTS; do
  python3 "$MK" "$V" "$MAXCP" "$PRECOND" > /dev/null || { echo "$V: cfg NG"; continue; }
  START=$(date +%s)
  "$NODE" "$GATES/mrgate.mjs" "$LIT2/$V.mr.cfg.json" \
      > "/tmp/mr_$V.json" 2> "/tmp/mr_$V.err"
  echo "$V exit=$? wall=$(( $(date +%s) - START ))s"
done
