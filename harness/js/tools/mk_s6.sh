#!/bin/bash
# v42: S6_new_export を組み直す（§12-A0c2）。
#
#   wsl.exe bash .../tools/mk_s6.sh
#
# ★mk_controls.sh とは別のスクリプトにしてある理由:
#   list.txt は「1変種 = 1ソースファイル」の形で、S6 だけが**複数ファイルにまたがる修正**。
#   その1本のために列を増やすと、他の10本の定義まで読みにくくなる。
#   ハーネス側（run_gates.mjs の installImages）は最初から複数ファイルの image を受ける。
#
# 何を組むか（詳細は mk_s6_pre.mjs の冒頭）:
#   pre_images = { rate-limit.ts: 2835baf^ の版,  route.ts: HEAD から要求枠の2か所だけ外した版 }
#   post_images = { 両方とも HEAD }
#   base_ref   = refs/vf/pre/S6_new_export（HEAD の木の、その2ファイルだけ pre に差し替え）
set -u
# ★v134 (judgement 61): the five machine paths below are resolved in ONE
# place now -- harness/tools/vf_env.sh.  They used to be literals here.
. "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)/tools/vf_env.sh"
NODE="${NODE_BIN_DIR:+$NODE_BIN_DIR/}node"
GATES="$JS_GATES_DIR"
WIN="$VF_SKILL_DIR/harness/js"
P="$CLIENT_PORTAL"
W=$P/apps/portal-web
V="$CLIENT_VF"
D=$V/ctrl
ORCH=$V/orch2

ID=S6_new_export
COMMIT=2835baf
RL=apps/portal-web/src/lib/internal-mail-rate-limit.ts
RT=apps/portal-web/src/app/api/batch/mail-send/route.ts
RLREL=src/lib/internal-mail-rate-limit.ts
RTREL=src/app/api/batch/mail-send/route.ts
ORACLE=src/lib/internal-mail-rate-limit.test.ts
ANCHOR=consumeInternalMailQuota
export GIT_AUTHOR_NAME=vf GIT_AUTHOR_EMAIL=vf@local
export GIT_COMMITTER_NAME=vf GIT_COMMITTER_EMAIL=vf@local
mkdir -p "$D" "$ORCH"
RC=0

cp "$WIN"/controls/$ID.finding.txt "$D/" || RC=1

echo "=================== 1. pre/post イメージ ==================="
# rate-limit.ts: 2835baf の差分は 43行の純追加なので、丸ごと戻すことが
# 「新しい export を足す前」と厳密に同じ意味になる（実測: git show --numstat = 43 0）。
NUMSTAT=$(git -C "$P" show --numstat "$COMMIT" -- "$RL" | tail -1)
echo "rate-limit.ts の 2835baf 差分 (added deleted path): $NUMSTAT"
case "$NUMSTAT" in
  *"	0	"*) : ;;   # 削除0 = 純追加
  *) echo "★純追加でなくなっている。丸ごと戻す前提が崩れた"; RC=1 ;;
esac
git -C "$P" show "$COMMIT^:$RL" > "$D/$ID.pre.ts"        || { echo "pre 取得失敗"; exit 1; }
git -C "$P" show "$COMMIT:$RL"  > "$D/$ID.post.ts"       || { echo "post 取得失敗"; exit 1; }

# route.ts: HEAD を土台に、指摘の2か所だけ外す
cp "$W/$RTREL" "$D/$ID.route.post.ts"                    || exit 1
"$NODE" "$WIN/tools/mk_s6_pre.mjs" "$W/$RTREL" "$D/$ID.route.pre.ts" || exit 1

echo ""
echo "=================== 1b. 検算 ==================="
for pair in "$RL:$ID.post.ts" "$RT:$ID.route.post.ts"; do
  f=${pair%%:*}; img=${pair##*:}
  if diff -q "$D/$img" "$P/$f" >/dev/null; then
    echo "post==HEAD  YES  $f"
  else
    echo "post==HEAD  NO   $f  <-- 対照として成立しない"; RC=1
  fi
done
echo "pre と post の差 (rate-limit.ts): $(diff "$D/$ID.pre.ts" "$D/$ID.post.ts" | grep -c '^[<>]') 行"
echo "pre と post の差 (route.ts)     : $(diff "$D/$ID.route.pre.ts" "$D/$ID.route.post.ts" | grep -c '^[<>]') 行"
echo "--- route.ts の pre への差分（これが指摘の範囲そのものであること）---"
diff -u "$D/$ID.route.post.ts" "$D/$ID.route.pre.ts" | sed -n '1,40p'

echo ""
echo "=================== 2. PRE ref（2ファイル差し替え）==================="
idx="$V/.idx.$ID"; rm -f "$idx"
GIT_INDEX_FILE="$idx" git -C "$P" read-tree HEAD || exit 1
b1=$(git -C "$P" hash-object -w "$D/$ID.pre.ts")        || exit 1
b2=$(git -C "$P" hash-object -w "$D/$ID.route.pre.ts")  || exit 1
GIT_INDEX_FILE="$idx" git -C "$P" update-index --add --cacheinfo "100644,$b1,$RL" || exit 1
GIT_INDEX_FILE="$idx" git -C "$P" update-index --add --cacheinfo "100644,$b2,$RT" || exit 1
tree=$(GIT_INDEX_FILE="$idx" git -C "$P" write-tree)    || exit 1
cm=$(git -C "$P" commit-tree "$tree" -p HEAD -m "vf: PRE image for $ID (2 files)") || exit 1
git -C "$P" update-ref "refs/vf/pre/$ID" "$cm"          || exit 1
rm -f "$idx"
n=$(git -C "$W" diff -U0 --relative "refs/vf/pre/$ID" -- src | grep -c '^@@')
nf=$(git -C "$W" diff --name-only --relative "refs/vf/pre/$ID" -- src | wc -l)
echo "$ID  ref=${cm:0:8}  検査4 が見る hunk 数=$n  ファイル数=$nf"
[ "$n" -eq 0 ] && { echo "   ★hunk が0 — 検査4 は gate_could_not_run になる"; RC=1; }
[ "$nf" -eq 2 ] || { echo "   ★差分が2ファイルになっていない"; RC=1; }

echo ""
echo "=================== 3. freeze マニフェスト ==================="
"$NODE" "$GATES/freeze.mjs" build --repo "$W" \
    --manifest "$V/manifest_${ID}.json" --registry "$V/registry_${ID}" \
    --oracle "$ORACLE" --anchor "$RLREL:$ANCHOR" 2>&1 \
| "$NODE" -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
    try{const j=JSON.parse(s);
      console.log("manifest: anchors="+JSON.stringify(j.anchors)
        +" problems="+JSON.stringify(j.anchor_problems)
        +" n_oracles="+Object.keys(j.oracles||{}).length
        +" n_test_files="+(j.n_tests_files??j.n_test_files??"?"));
    }catch(e){console.log("manifest: UNPARSEABLE "+s.slice(0,200));}})'

echo ""
echo "=================== 4. cfg ==================="
cat > "$ORCH/$ID.cfg.json" <<CFG
{
 "name": "$ID",
 "repo": "$W",
 "anchor_file": "$RLREL",
 "anchor_func": "$ANCHOR",
 "oracle_files": ["$ORACLE"],
 "pre_images": {
  "$RLREL": "$D/$ID.pre.ts",
  "$RTREL": "$D/$ID.route.pre.ts"
 },
 "post_images": {
  "$RLREL": "$D/$ID.post.ts",
  "$RTREL": "$D/$ID.route.post.ts"
 },
 "manifest": "$V/manifest_${ID}.json",
 "registry": "$V/registry_${ID}",
 "finding_file": "$D/$ID.finding.txt",
 "tests_dirs": ["$W/src/lib"],
 "baseline": "$ORCH/baseline_${ID}.json",
 "out": "$ORCH/results",
 "r5_seeds": [11, 22],
 "base_ref": "refs/vf/pre/$ID",
 "amb_budget_s": 30
}
CFG
"$NODE" -e 'const j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));
            console.log("cfg OK  pre_images="+Object.keys(j.pre_images).length
              +"  post_images="+Object.keys(j.post_images).length
              +"  oracle_files="+j.oracle_files.length)' "$ORCH/$ID.cfg.json" || RC=1

echo ""
echo "次: node run_gates.mjs $ORCH/$ID.cfg.json --build-baseline  してから run_pipeline.sh"
exit $RC
