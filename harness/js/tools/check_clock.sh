#!/bin/bash
# v30: 計時の食い違いを、生の値を出して切り分ける。
# 仮説A: ゲートの performance.now() がずれている  -> プロセス内比較で否定済み(drift 0%)
# 仮説B: 外側の date 計測がおかしい               -> 生の値を出せば分かる
set -u
# ★v134 (judgement 61): the five machine paths below are resolved in ONE
# place now -- harness/tools/vf_env.sh.  They used to be literals here.
. "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)/tools/vf_env.sh"
cd "$CLIENT_PORTAL/apps/portal-web" || exit 1
for I in 1 2; do
  S=$(date +%s%N)
  "${NODE_BIN_DIR:+$NODE_BIN_DIR/}node" \
    "$JS_GATES_DIR/mrgate.mjs" \
    "$CLIENT_VF/lit2/S1_control.mr.cfg.json" > /tmp/mr_timing.json 2>/dev/null
  E=$(date +%s%N)
  echo "run $I:  S=$S  E=$E"
  echo "        外側 = $(( (E - S) / 1000000 )) ms"
  python3 -c '
import json, io
d = json.load(io.open("/tmp/mr_timing.json", encoding="utf-8"))
print("        ゲート = %.0f ms  (elapsed_s=%s)" % (d["elapsed_s"] * 1000, d["elapsed_s"]))
'
done
