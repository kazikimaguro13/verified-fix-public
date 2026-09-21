# 公開範囲（PUBLIC_SCOPE）

**この repo には、公開する部分と公開しない部分がある。** その境目をここに書く。
判断63 第2段（v136・2026-09-21）で確定。決定は
`harness/attack-corpus/reports/v136_predictions.md` の「決定」表。

**private repo（`kazikimaguro13/verified-fix-public`。名前に反して private）は
すべてを保持する。** ここに並ぶのは「公開用の写しから外すもの」であって、
消すものではない。外したファイルは private 側にそのまま残る。

---

## 1. 公開用の写しに入るもの

| 入るもの | |
|---|---|
| `harness/js/` | ゲート本体・道具・テスト |
| `harness/src/` | Python 側の実装 |
| `harness/tools/` | 解析・レポート生成 |
| `README.md`・`SKILL.md`・`DESIGN.md`・`PUBLIC_SCOPE.md`・`LICENSE`（MIT・2026-09-21 本人決裁） | 文書 |

**ここに挙がっていないものは、そもそも公開用の写しに入らない。**
`HANDOFF.md`・`harness/attack-corpus/**`（予測・測定の生記録）・repo 直下の
`reports/**` は、除外リストに載る以前に**範囲の外**である。

## 2. 範囲の中から外すもの（客先由来の実体。置換では消せない）

| 外すもの | 件数 | 理由 |
|---|---|---|
| `harness/js/controls/**` | 23 | 実クライアントのオラクル本体・アンカー仕様 JSON・指摘本文。`S8_batch_sync_oneway.finding.txt` は**客先のレビューコメントそのもの**で、書き換えれば「実際に来た指摘」ではなくなる |
| `harness/js/attacks/**` | 15 | 実クライアントのアンカーに対する攻撃生成器。`HELPER_ANCHOR` の照合文字列に客先の関数名が**値として**入っており、置換すると攻撃が当たらなくなる |
| `harness/js/gates/*.v1[0-9][0-9]` | 5 | 凍結写し（`freeze.mjs.v117`・`run_gates.mjs.v111/113/115/117`）。**中身を変えたら写しの意味が無い** |
| `harness/js/tools/build_corpus_index.py` | 1 | 私的コーパスの索引生成器。文字列リテラルが `corpus/index.json` そのもの |
| `harness/js/tools/mk_controls.sh` | 1 | 客先パスを引数に持つ作業手順 |
| `harness/js/tools/run_mutant_ranges.sh` | 1 | 同上 |

**なぜ「置換では消せない」のか。** 判断63 第1段（v135）と第2段（v136）で行った
のは**名前の中立化**であり、文章・docstring・コメントの中の綴りを役割名に置き
換える作業である。上の6つは綴りが**文章ではなく値**として効いている
（照合する文字列・読み込む JSON のキー・コマンドの引数・凍結した過去の写し）。
値を書き換えれば道具が壊れるか、記録としての意味が消える。**だから外す。**

（件数は**常時の除外を適用したあとの実ファイル数**。`harness/js/attacks/` には
`__pycache__` の `.pyc` が 9 本あるが、それは §3 で先に落ちている。
実際に staging から外れたのは合計 **46 ファイル**で、全一覧は
`harness/attack-corpus/reports/v136_raw/staging_excluded.txt`。）

## 3. 常時の除外（客先とは無関係。生成物・大きさ）

| 外すもの | 理由 |
|---|---|
| `node_modules/` | 依存の実体 |
| `__pycache__/` | 生成物 |
| `.stryker-tmp/` | 変異実行の作業領域 |
| `harness/src/results2/` | 測定の生出力 |
| `harness/v0-measured/` | 測定の生出力（そもそも範囲外） |
| `*.log`・`*.out` | 実行ログ |

## 4. `harness/js/corpus/index.json`

**公開用の写しでは `entries` を空配列 `[]` にして出す。**
schema・`what`・`not_a_gate`・`built_by`・`read_with`・`verdict_vocabulary`・
`how_the_verdicts_were_pulled`・`known_limits` は**そのまま・同じ順で**残す。
索引の**形**は公開して意味があるが、**中身は客先由来**だからである。

実測（v131 §2）: 登録されている 33 エントリは**全部が実クライアント由来で、
OSS 由来は1件も無い**。よって空にしても公開できる例は1件も失われない。

## 5. 残っている綴り（隠さずに書く）

客先由来の定数名は **v137 で中立化した**。`DESIGN.md:1114`・
`harness/js/gates/anchorspec.mjs:7`・`harness/js/tools/README.md:203` の
三か所で、いまはどれも中立な綴りである。
**この文書は識別子そのものを綴らない。**

- `DESIGN.md:3` の著者名 — 本人の名前。**本人が残すと決めた（2026-09-21）**

**これを直すかどうかは判断であって、作業ではない。** 規則表に足されるまで
触らない。
