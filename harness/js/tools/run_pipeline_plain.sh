#!/bin/bash
# v43: run_pipeline.sh の薄い包み。**追加フラグが空のとき専用。**
#
# なぜ要るか（v42 §0-j-4 ⑤ で記録された罠の恒久化）:
#   PowerShell から `wsl.exe bash .../run_pipeline.sh fast v43 "" S1_control` と書くと
#   **空文字の引数が途中で落ちる**。落ちると EXTRA に変種名が入り、変種が1つ消える。
#   v42 はその場で包みを書いて捨てた。ここに残す。
#
#   $1 = profile, $2 = 出力サフィックス, $3.. = 変種名
set -u
exec bash "$(dirname "$0")/run_pipeline.sh" "$1" "$2" "" "${@:3}"
