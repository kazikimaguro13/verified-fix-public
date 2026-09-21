# harness/js/tools — 走らせるための道具

**JS ハーネスを回すのに毎回要るスクリプト。**
以前はセッション専用のスクラッチパッドに置いていたが、**そこはセッションごとに消える**ので、
**v37 でここへ移した。**（引き継ぎ書が消えるパスを指していた。）

**すべて WSL 側で走る。** Windows から呼ぶときは
`wsl.exe bash $VF_SKILL_DIR/harness/js/tools/<名前>` の形。

> **★変数を使うなら、コマンド文字列ではなくスクリプトに書くこと。**
> `wsl.exe bash -c '... $V ...'` は**外側の Git Bash が先に `$V` を空へ展開する**
> （HANDOFF 罠10）。ここのスクリプトが全部ファイルなのはそのため。

---

## `sync_gates.sh` — 正本 → 実行コピーへ同期して構文検査

```bash
wsl.exe bash .../tools/sync_gates.sh                    # 主要6本
wsl.exe bash .../tools/sync_gates.sh drive.mjs mrgate.mjs   # 指定したものだけ
```

**Windows 側リポジトリ（正本）から `$JS_GATES_DIR/` へコピーし、`node --check` する。**
**測定の前に必ず通すこと** — 古いコピーで測ると測定そのものが無効になる。
**★v44 で既定の集合に `diffgate.mjs` と `parse.mjs` を足した**（検査5 を配線したので。
`run_pipeline.sh` が持っているコピー一覧も同じ。**入れ忘れると編集したゲートの古い版で測る**）。

## `run_pipeline.sh` — パイプライン本体

```bash
wsl.exe bash .../tools/run_pipeline.sh <profile> <出力サフィックス> <追加フラグ> <変種...>

# 例
... run_pipeline.sh fast v40 "" S1_control N13_sliced_prefix
... run_pipeline.sh strict v40s "" N12_dynamic_regex
... run_pipeline.sh fast v40b --no-check8-in-fast S1_control
```

- **同期を自分でやる**ので `sync_gates.sh` を別に呼ぶ必要はない
- 結果は `/tmp/pipe_<変種>_<サフィックス>.json`、標準エラーは `.err`
- **1変種あたり `fast` 約100〜120秒／`strict` 約165〜200秒**（§0-g の注意も読むこと）
- **★同じ作業ツリーに2つの実験を同時に走らせない**（罠9）

## `run_pipeline_plain.sh` — 追加フラグが空のとき専用の薄い包み（v43）

```bash
wsl.exe bash .../tools/run_pipeline_plain.sh <profile> <出力サフィックス> <変種...>
```

**PowerShell から `wsl.exe bash .../run_pipeline.sh fast v43 "" S1_control` と書くと
空文字の引数が落ちる**（v42 §0-j-4 ⑤ が記録した罠）。落ちると `EXTRA` に変種名が入り、
**変種が1つ静かに消える。** v42 はその場で包みを書いて捨てた。ここに残してある。

**★v43 の実測（罠10 の親戚として記録）**: `wsl.exe bash -c '...' -- a b "" c` は
**引数が1つも渡らない**（`$# = 0`）。**引数を渡すならスクリプトをファイルに置いて
`wsl.exe bash /mnt/c/.../x.sh a b c` の形で呼ぶこと。**

## `show_pipeline.py` — 結果を読む

```bash
wsl.exe bash -c 'python3 .../tools/show_pipeline.py v40 S1_control N13_sliced_prefix'
```

判定・撃墜したゲート・エスカレート・コストを並べる。
**`killed_by_all` と `errored_gates` は別物**（D22）。要約は `FAIL` と `ERROR` を書き分ける。

## `run_check8.sh` / `mk_check8_cfg.py` / `show_check8.py` — 検査8 を単独で

```bash
wsl.exe bash .../tools/run_check8.sh 0x110000 0x800 S1_control N13_sliced_prefix
wsl.exe bash -c 'python3 .../tools/show_check8.py S1_control N13_sliced_prefix'
```

- 第1引数 = 掃く上限（`0x110000` が全軸）、第2 = 前提条件の上限（既定 `0x800`）
- **配管の確認だけなら `0x100` で 30秒**。全軸は1変種 30〜40秒
- `mk_check8_cfg.py` はパイプラインの cfg から検査8 単独用 cfg を作る（`run_check8.sh` が呼ぶ）

## `mk_controls.sh` — 対照変種を実クライアント（Next.js／TS の業務ポータル）の git 履歴から組み立てる（v38）

```bash
wsl.exe bash .../tools/mk_controls.sh
```

**定義の正本は `harness/js/controls/list.txt`**（変種ID・修正コミット・ファイル・オラクル・アンカー
・**追加オラクル**・**アンカー仕様**）と `harness/js/controls/*.finding.txt`（指摘文＝当時のコミットメッセージの言葉）。

**★v44 で足した1つ**: **`list.txt` の9列目 = アンカー仕様**（正本は `harness/js/controls/<名前>.json`）。
在ると `$V/lit2/` へ設置され、cfg に `anchor_spec` が付き、**検査5 が anchorspec 由来の入力で走る**。
同じ仕様を検査8/12 も読む（`decides: false` なら検査8 は「範囲外」と言って 0.1秒で通す）。
**設置時に `calls` / `templates` / `decides` / `driver` の件数を出す** — v44 はこの検算が
仕様に紛れた NUL を1発で捕まえた（§0-c を設置スクリプトにも当てる）。
**クライアントのリポジトリには push しない** — 触るのは `$CLIENT_PORTAL` というクローン。

**★v39 で足した2つ（§12-A0b2）**

1. **`list.txt` の8列目 = 追加オラクル（任意）。** 検査4 が出した「T への義務」を埋めるために
   **足した**テストファイルを、リポジトリ相対のパスで書く。実体の正本は
   `harness/js/controls/<basename>` で、**このスクリプトがクローンへ設置する**。
   cfg の `oracle_files` へ**追記**する（既存のオラクルは置き換えない＝純追加）。
2. **3b 節: 攻撃側の `manifest_s1.json` を毎回作り直す。**
   freeze は「テスト木にファイルが増えたこと」を検知する（攻撃#2 対策）ので、
   **オラクルを1本足した時点で、この repo を見るすべてのマニフェストが古くなる。**
   11本の攻撃変種はこの1本を共有しており、**作り直さないと11本とも freeze で落ちる。**
   **しかも freeze は hard ゲートなので「撃墜が増えた」ようにしか見えない**
   （`compare_runs.py` は撃墜が増えても失敗にしない）。**測定が壊れていることに気づけない形。**

pre/post イメージ・`refs/vf/pre/<id>`・freeze マニフェスト・cfg を作る。**そのあと自分で:**

```bash
# 変種ごとにベースライン（PRE ツリーの全スイート・約20秒）
node .../run_gates.mjs <ORCH>/<id>.cfg.json --build-baseline
# それからパイプライン
... run_pipeline.sh fast v38 "" S2_mailer_url S3_overtight S4_division S5_refactor S6_new_export
```

> **★`base_ref` を必ず `refs/vf/pre/<id>` にすること。**
> 検査4 は **post を入れた状態で `git diff <base_ref> -- src`** を取る。この対照は
> **post == HEAD** なので、`HEAD` を渡すと差分が0行になり、v34 の早期脱出
> （`no changed source lines`）で **全変種が `gate_could_not_run`** になる。
> `mk_controls.sh` は hunk 数を出力し、0 なら非ゼロ終了する。

## `show_verdicts.py` — 「受理したか」を1行で（v38）

```bash
wsl.exe bash -c 'python3 .../tools/show_verdicts.py v38 S2_mailer_url S3_overtight ...'
```

**D22 のとおり列を分ける**: 却下したゲート（`killed_by_all`）／走れなかった（`errored_gates`）／
エスカレート（検査6・7）。**混ぜて読むと撃墜を捏造する。**
そのあと却下・ERROR の理由と witness（生存変異など）を並べる。

## `check_line_endings.py` — CRLF に単独 LF が紛れていないか（v47b）

```bash
python3 harness/js/tools/check_line_endings.py        # 検査（単独 LF があれば非ゼロ終了）
python3 harness/js/tools/check_line_endings.py --fix  # 直す（行数が変わらないことを assert する）
```

**★なぜ道具にしたか**: 2026-08-26 に **同じミスを2回**した。
どちらも**挿入する文字列の片方だけに改行変換を掛け忘れた**もので、1回目は14行・2回目は1行。
**どちらもコミット後の検算で見つかった** — つまり**直前まで気づいていない。**

**`HANDOFF.md` を編集したら、コミット前にこれを通すこと。**
LF にすると **全行が差分になり、レビューが不可能になる**（`.gitattributes` の `* -text` により git は改行を正規化しない）。

**CRLF のファイルは実測で決めてある**（`CRLF_FILES`）。増えたらそこに足す。
⚠️ v43 が全711ファイルを数えた時点では **CRLF は15ファイル**あった。この道具が見ているのは**編集頻度が高い3本だけ**で、全数ではない。

## `check_clock.sh` — 計時のずれを見る

**この箱では単調時計（`performance.now()`）が実時刻より約2.4秒進む**（§0-g）。
**コストの数字を報告する前に、おかしいと思ったらこれを走らせる。**
ゲートが**自分のプロセスの実時間より長い経過時間**を報告したら、それは計時が壊れている。

## `run_triage.sh` / `mutant_triage.mjs` — 検査4 の「生存」を手で検算する（v42）

```bash
wsl.exe bash .../tools/run_triage.sh S16_scrypt_cost --run --controls 3 --out /tmp/t.json
wsl.exe bash .../tools/run_triage.sh S16_scrypt_cost              # いまの report を使う
```

**なぜ要るか（v40 §5-c-b 実測）**: 検査4 が「生存」と報告した9件のうち **5件は、
同じ変異を手で当てると T が落ちる**。**モジュール直下（static）の変異体は、Stryker の
切り替えが効く前にモジュールの初期化が終わっており、変異したコードが一度も走らない**
（Stryker 自身の被覆が `coveredBy: []` と記録している。v42 §2-c）。
**Stryker はテストを全部走らせ、緑を見て `Survived` と書く。**
判定は fail closed で安全だが、**`fp_to_oracle` が人間へ渡す義務の一覧が汚染される。**

**v39 の反例探しも v40 のこの仕分けも、その場で書いて捨てられていた。ここに残してある。**

やること: report の `location` と `replacement` でソースへ**同じ変異を splice し**、
オラクルを走らせ、失敗数を数え、**必ず元へ戻す**。

**この道具が自分について測ること**（§0-c を道具にも当てる）:

1. Stryker が変異させた本文と disk の本文が**同じバイトか**。違えば座標が別の場所を指すので落ちる
2. 変異前に**オラクルが緑か**。緑でなければ「落ちた」を数えても意味がない
3. `--controls N` = **Stryker が `Killed` と言った変異体**を同じ手順で当てる。
   **落ちなければ splice が壊れている** → 他の行も信用しない
4. 最後に**バイトが元へ戻っているか**。戻っていなければ非ゼロ終了

出力は `static` との相関表つき。**`mutgate.mjs` の `n_survivors_static` が非ゼロなら、これを回す。**

## `run_spygate_cap.mjs` — 検査12 を候補上限を変えて単独に回す（v43・§12-A1c）

```bash
node .../tools/run_spygate_cap.mjs <orch2 の cfg.json> <上限> [rounds]
```

**なぜ要るか**: 検査12 の候補は「スパイの収穫 ∪ post イメージの文字列リテラル」で、
**1ラウンドあたり `max_candidates`（既定24）で打ち切られる**（`spygate.mjs:200`）。
`CAP-TRUNCATED` は出しているが**尾を測る手段が無かった**。
strict を丸ごと回すと160秒、**検査12 単独なら約50秒。**

- **必ず件数を出す**（§0-c）: `n_candidates_tried` / `n_consts_gate` / `n_tail` / `coverage_note`
- `tail_candidates_25_plus` は「25番目以降に何が居たか」。⚠ **その一覧は
  `spygate.mjs` の `literals()` と同じ歩き方をこの道具が写したもの**なので、
  **件数をゲート自身の `n_consts` と突き合わせて検算する**。合わなければ
  `const_list_matches_gate: false` を出し、**順位の主張はしない**

> **★v43 の実測（読む前に知っておくこと）**: `anchor-c` アンカーでは
> **上限を147以上に上げると、正当な対照 `S1_control` が落ちる。**
> 出てくる13件は許可リスト `ANCHOR_C_KEYS` そのもので、**偽陽性**。
> **既定の24 は速さのための摘みではなく、実は偽陽性の抑制として働いている**（HANDOFF §0-j-6 ③）。
> **上げたまま出荷しないこと。**

## `run_apigate_groups.mjs` — 検査7 を別の群の組み合わせで単独に回す（v43）

```bash
node .../tools/run_apigate_groups.mjs <orch2 の cfg.json> [群1] [群2] ...
# 省略すると "classify,ambient"（既定）と "classify,ambient,codepoint" の2本
```

検査7 の curated list は3群あるが、**既定で有効なのは `classify` と `ambient` だけ**
（`run_gates.mjs` の `cfg.check7_groups || "classify,ambient"`）。
「その名前は表に在ったのか、既定で off だっただけか」を **0.1秒で** 区別する。

⚠ **既定を変える道具ではない。** エスカレートは却下ではない（D22）ので鳴っても判定は動かない。
**測るのは「どの列挙なら当たったか」だけ。**
`caller_files` は直前の走行が残した `.vf/litgate.cfg.json` から借りる。
**借りられなければ空にして、その事実を出力に書く**（§0-c）。

## `run_check5.mjs` — 検査5 を単独で当てる／**力を測る**（v44・§12-A1b）

```bash
node .../tools/run_check5.mjs <orch2 の cfg.json> [--post <rel>=<絶対パス>] [--out <file>]
```

**なぜ要るか**: 検査5（`diffgate.mjs`）は POST を作業ツリーに置いた状態でしか意味を持たない
（駆動器がツリーからアンカーを import する）。`run_gates.mjs` はそれを `installImages` でやるが、
**パイプライン1本は fast でも 127〜151秒**。**検査5 単独なら約18秒**で、
「このコーパスに力があるか」を測るのに何度も回す必要がある。

- **`--post` は POST イメージを差し替える。これが力の測定用。**
  「本当に振る舞いを変えた版」を当てて乖離が出るかを見る。
  **出なければコーパスがその差に盲目、出れば空振りでない。片方だけ測って結論を書かない**（§0-c）。
- v44 の実測（`S5_refactor` / `verifyGmailOAuthAuthz`）:
  **ボディの中身だけを変えた版 → 乖離0（盲目）／戻り値に出る改変 → type 乖離1（空振りではない）。**
  差が**注入された `fetchImpl` 越しにしか見えない**からで、`anchorspec.mjs` の LIMITS #1 のとおり。
- ⚠ **作業ツリーを一時的に書き換える。走行中は他の実験を走らせない**（罠9）。

> **★読み方（v44）**: `n_untouched == 0` なら **D2 が hard にしている規則は0件を検査している。**
> アンカー仕様の `calls` は定義上すべてアンカーに入るので、これは常にそうなる。
> **`pass` は「振る舞いが変わっていない」ではない。** ゲートが `blast_radius_note` にそう書く。
> 圏内の乖離（`in_scope_divergences`）は**報告されるが判定に使われない**（合格条件は変えていない）。

> **★既定 on の代価（v44 実測・人間の判断待ち）**: `anchor_spec` が在る cfg では検査5 が既定で走る
> （`check5_from_spec: false` で外せる）。**その結果、v41〜v43 で受理されていた対照
> `S26_date_validation` が却下へ変わった**（型乖離14件。「壊れた文字列を返す」→「throw する」は
> `typeof` を変えるため）。**攻撃11本の撃墜は増減ゼロ。** 詳細は `reports/v44_check5_wiring_results.md` §5・§7-c。

## `run_gate_power.sh` / `gate_power.mjs` — ★ゲートの `pass` に力があるかを測る（v46・§12-A7 / D24）

```bash
wsl.exe -e bash .../tools/run_gate_power.sh <変種ID> [--gate check5]
   [--positive-control <rel>=<絶対パス>] [--no-early-stop] [--max-mutants N] [--out F]
#   ※ 行継ぎの \ はここに書かない（罠8: 転送で消える。v46 で実際に消えた）
```

**⛔ これはゲートではない。** 番号を持たず、`run_gates.mjs` から呼ばれず、
**どのゲートの合否条件にも入らない**（D24 論点6/8）。出力は材料であって判定ではない。

**問い**: ゲートが `pass` と言ったとき、それは「見た上で問題なし」か「見えていないだけ」か。

**やること**（D24 の9論点そのまま）:
1. **パッチが変えた行だけ**の変異を Stryker から取る（`--mutate` レンジ・`refs/vf/pre/<id>`。
   **`mutgate.mjs` をそのまま呼ぶ**＝検査4 と同じ仕組み。ゲートは編集していない）
2. 変異を**1件ずつ POST イメージに当てる**
3. **そのゲートを自分で走らせて pass/fail を記録する**
4. **早期終了つき全件走査**（1件で「力あり」・全件で「空虚」）

> ⚠ **Stryker の判定は使わない。** v42 実測で **static 変異体は「走らせていないのに Survived」**
> と記録される。かつ Stryker の判定は「テストスイートが気づいたか」で、
> **知りたいのは「このゲートが気づいたか」**である。
> **v46 の初回測定でその差が実物になった** — `S5_refactor` の2件は Stryker が両方 `Killed`
> （T は気づく）なのに、**検査5 は2件とも pass（気づかない）**。

**判定は3値**: `HAS_POWER` / `VACUOUS` / `NOT_MEASURED`。
**`NOT_MEASURED` を `VACUOUS` と読まないこと。** 出るのは3通り —
①変異を当てる前から baseline が FAIL ②ゲートが走れない（例: `anchor_spec` が無い）
③全件を当てていない。**件数（`n_mutants_total` / `n_tried` / `n_caught` / `n_blind` /
`n_errored` / `stopped_early` / `coverage_note`）が必ずどちらかを言う**（§0-c）。
**`gate_could_not_run` / `inapplicable` は `n_errored` へ入り、`n_caught` には入らない**（D22）。

- **`--positive-control rel=abs`**: 観測できると**分かっている**改変を先に当てる自己検査。
  ゲートがそれも pass したら、blind は道具の沈黙と区別できないので `NOT_MEASURED` で止まる。
- **`n_blind_but_observed`**: pass なのに**報告専用の欄**（`in_scope` / `emitted`）が動いた件数。
  「見えていない」と「見えているが判定に使っていない」は別。**⚠ ゲートの標本は打ち切られている**ので、
  **差が出れば動いた証拠／差が無いことは動いていない証拠にならない**（出力の `blind_but_observed_note`）。
- **ゲートを増やすとき**は `GATE_RUNNERS` に1エントリ足す（D24 論点5 の順に検査8/9/12）。

> **★v46 実測**: `S5_refactor` **0/2 で `VACUOUS`**（自己検査の PWR2 は捕まえる）。
> `S1_control` **0/12 で `VACUOUS`・偽陽性0・うち7件は `emitted` が動いている**。
> `S26_date_validation` は **baseline が FAIL（型乖離14）なので `NOT_MEASURED`**（v44 の数字を再現）。
> `S3` / `S27` は **`anchor_spec` が無いので測れない**。詳細は `reports/v46_gate_power_results.md`。

> **★生成器の穴（v46 実測・重要）**: StrykerJS 10.0.0 は **`X as const` / `X as T` を部分木ごと
> 走査から外す**（`instrumenter` の `syntax-helpers.js:116/140` と `babel-transformer.js:137`）。
> **このリポジトリの許可リストは全部 `[...] as const`** なので、
> **検査4 も A7 もその中身を一度も壊していない。** `--mutate` をその行だけに絞って0件を実測した
> （`reports/v46_raw/probe_asconst.sh`）。**「力がある」は常に「この生成器の範囲で」である**（D24 論点7）。

## `run_asconst_mutants.sh` / `asconst_mutants.mjs` — ★`as const` の中を変異させて測る（v50・§12-A15）

**⛔ ゲートではない。** 番号なし・`run_gates.mjs` 非接続・**合否に一切参加しない。**
出すのは件数と証人だけで、判定はしない。

> **★★v54（2026-08-27・§12-A17）: この道具のやり方が `gates/mutgate.mjs`（検査4）に配線された。**
> **⛔ この道具は今も合否に参加しない。** 役割が「配線するかを決めるための測定」から
> **「ゲートの外から同じことを測り直せる第二の目」**に変わっただけである。
> ゲート側の欄は `asconst_stripped` / `n_asconst_regions` / `n_asconst_regions_in_mutate_range` /
> `n_asconst_new_mutants` / `n_asconst_killed` / `n_asconst_survived` / **`n_unmappable`** /
> `asconst_mapping` / `asconst_selfcheck` / `asconst_rows` で、**この道具の出力と1対1に読める。**
> **合否条件（`const pass` の式）は1文字も変わっていない** — 足したのは変異の生成と、その手当ての結果だけ。
> **v54 は `S1_control` 14/4/10・`N17` 15/4/11・`N18` 23/10/13 をゲートの中で再現した**（＝移植で数字が動いていない）。
> **★実測で分かった射程外**: **入れ子の `as`**（`X as const` の中に `y as T` が在る形）は、
> 外側を丸ごと置き換える変異の span が潰した範囲を跨ぐので **`UNMAPPABLE` になって当てられない**
> （`A7aJS_sibling_side_effect` で7件。`reports/v54_asconst_wired_results.md` §4）。
> **v50 は3変種しか測っていないのでこの形は出ていなかった。**

```bash
wsl.exe bash .../tools/run_asconst_mutants.sh S1_control
wsl.exe bash .../tools/run_asconst_mutants.sh N18_asconst_predicate --count-only
```

**何をするか**（上の「生成器の穴」を回り込んで測るだけ）:

1. POST イメージを置き、**検査4（`mutgate.mjs`）をそのまま回して `mutate_spec` を取る**
   （レンジを自前で計算しないのは、検査4 とドリフトさせない唯一の方法だから）
2. `as T` / `as const` / `satisfies T` / `<T>x` を **同じ長さの空白で塗り潰した版**を作る
   （TypeScript の実物のパーサを対象リポジトリの `node_modules` から解決して使う）
3. **同じレンジで** Stryker に変異を生成させる
4. **★変異を元のソース（`as const` 付き）に1件ずつ当てて T を走らせ、撃墜されるか見る**

**★塗り潰しを「同じ長さ」にしてあるのが肝**: `as` は型レベルの表明で実行時に消えるので**意味は変わらず**、
長さを保つので **行も列も動かない ⇒ 位置の写像が恒等写像になる。**
それでも**写像は機械で検算する**（出力の `strip` と各行の判定）:
①潰した版と元の版が同じバイト長で、違いは全部潰した範囲の中／②各変異の span の本文が両版で同一
（違えば **`UNMAPPABLE` にして当てない**）／③splice 後の本文が元と**1区間だけ**違う。

**⚠ 当てるのは元のソースである。** 潰した版に当てて測ると、測っているものが本物のソースでなくなる。

- **`--controls N`**（既定3）: **自己検査。**「外す前」の走行で Stryker が `Killed` と言った変異を N 件混ぜ、
  **手で当てても撃墜されること**を確かめる。1件でも外れたら splice が壊れており、他の行は全部無効。
- **`--count-only`**: T を走らせず件数だけ。
- **`--raw-dir D` / `--out F`**: Stryker のレポート（前・後）と全結果 JSON。
- **`verdict_if_wired`**: **仮定の値。** 検査4 の合格条件をこの測定に当てたらどうなるかを書いてあるだけで、
  **何にも読まれない。** 配線するかは人間が決める。
- **Stryker の `status` は判定に使わない**（D24 論点3）。**v50 実測で食い違いが 4/14・4/15・6/23 出た**
  — 全部 `static` 変異体で、Stryker は「Survived」、手で当てると T が落ちる。

> **★v50 実測**: 許可リストのレンジの変異は **0 → 14/15/23件**（`S1_control` / `N17` / `N18`）。
> **`N18` の裏口の述語からは 9件出て 3件が生存**（＝T は裏口の有無を区別できない）。
> **ただし `S1_control` も 10件生存して落ちる**ので、判定は3変種とも同じ `fail`。
> **`UNMAPPABLE` 0件・自己検査 3/3 × 3変種。** 詳細は `reports/v50_asconst_close_results.md`。

**`reports/v50_fp_bridge.mjs`** はこの測定を `harness/src/fp_to_oracle.py` が読める形へ落とす一回きりの橋渡し
（**これもゲートではない**）。`run_gates.mjs:304` と同じ変換をするので、
**証人の打ち切り（`WITNESS_CAP` 12）も同じように効く** — `N18` は生存13件で既に当たっている。

## `mk_s6.sh` / `mk_s6_pre.mjs` — `S6_new_export` だけ別に組む（v42）

```bash
wsl.exe bash .../tools/mk_s6.sh
```

**`mk_controls.sh` に混ぜていない理由**: `list.txt` は「1変種＝1ソースファイル」の形で、
**S6 だけが複数ファイルにまたがる修正**（新しい export ＋ その呼び出し元）。
1本のために列を増やすと他の10本の定義まで読みにくくなる。
**ハーネス側（`installImages`）は最初から複数ファイルの image を受ける。**

**呼び出し元 `route.ts` は `f51ffc7` でさらに変わっている**ので `2835baf^` の版は使えない。
代わりに **HEAD から「指摘の範囲だけ」を外す**（import 1つと呼び出しブロック1つ）。
**位置は日本語コメントの写しではなく構造で探す**（罠8）。見つからなければ落ちる。

検算はスクリプトが毎回出す: 純追加であること・`post==HEAD`・hunk 数・ファイル数・
freeze の anchors。**そのあと `--build-baseline` を忘れないこと**（PRE ツリーの全スイート）。
**失敗数が他の対照の帯（13〜33件）から外れていたら、構成が壊れている**（v38 は156件だった）。

---

## `build_corpus_index.py` / `show_corpus.py` — ★JS 側の変種一覧と判定履歴（v53・§0-c）

**どちらもゲートではない。**番号を持たず、`run_gates.mjs` に配線されておらず、合否に一切参加しない。
**走行しない・測定しない。**既にディスクに在る記録を読んで1本のファイルにするだけ。

**正本は `harness/js/corpus/index.json`**（Python 側の `harness/attack-corpus/index.json` に対応するもの）。

```
python3 harness/js/tools/build_corpus_index.py   # index.json を作り直す
python3 harness/js/tools/show_corpus.py          # 全33件を1行ずつ
python3 harness/js/tools/show_corpus.py --slips  # attack で all_gates_passed=true のものだけ
python3 harness/js/tools/show_corpus.py --stale  # latest を引けなかったものだけ
python3 harness/js/tools/show_corpus.py --counts # 件数だけ
```

**判定は `killed_by_all` と `errored_gates` から引く。**
⚠ **`killed_by` はスカラー**（最初の1本だけ）なので**集計に使わない**（§0-h「★判定の読み方（v38）」）。
`reports/**/*.json` のうち **`name` と `killed_by_all` を両方持つもの**＝ `run_gates.mjs` の出力の形、が材料。

**引けなかったものは `null` ＋ `why_null`。埋めない。**
**v19〜v37 のラウンドは判定を `reports/*.md` の表にしか残していない**ので、
**アンカー1 の6変種（`F1_control` / `M1` / `M2` / `M5` / `M6` / `M7`）は `latest: null`。**
これは「判定が無い」ではなく「判定を引けない」で、`--stale` はその2つを混ぜない。

**各走行に `gates_run` / `gates_skipped` を持たせてある。**
**「どのゲートも文句を言わなかった」と「そのゲートがそもそも入っていなかった」は別の事実**で、
混ぜると §0-c そのものになる。`S26_date_validation` が現物の例（`caveat` を読むこと）。

⛔ **これはゲートの健全性には答えない。** あるゲートが撃墜を失っても、ここの判定は1行も変わらないことがある
（§0-d・v14 実測）。**ゲートに触ったら `src/compare_runs.py` を見る。**

---

## 置き場所（スクリプトが前提にしているパス）

| | |
|---|---|
| 正本 | `$VF_SKILL_DIR/harness/js/gates/` |
| 実行コピー | `$JS_GATES_DIR/` |
| クライアント（**読むだけ・書かない**） | `$CLIENT_PORTAL/apps/portal-web/` |
| cfg | `$CLIENT_VF/orch2/` |
| アンカー仕様・変種のソース | `$CLIENT_VF/lit2/` |
| Node 22（**絶対パスで叩く**） | `$NODE_BIN_DIR/node` |

### ★v134（判断61 A）: 上の `$...` はどこから来るか

上表の5つの値は、以前は 109 箇所 / 47 ファイルに**直書きされていた**（v131 staging 監査 §4）。
今は**言語ごとに1つの解決点**から来る。どれも同じ6つを出す。

| 言語 | ファイル | 使い方 |
|---|---|---|
| shell | `harness/tools/vf_env.sh` | `. "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)/tools/vf_env.sh"` |
| ESM | `harness/js/tools/vf_paths.mjs` | `import { JS_GATES_DIR } from "./vf_paths.mjs";` |
| Python | `harness/src/vf_paths.py` | `sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))` → `from vf_paths import CLIENT_VF` |

| 名前 | 既定（環境変数が無いとき） |
|---|---|
| `VF_HOME` | `$HOME/vf1` |
| `VF_SKILL_DIR` | **そのファイル自身の位置**から導く（`import.meta.url` / `${BASH_SOURCE[0]}` / `__file__`）。環境変数は**後ろ**の手 |
| `CLIENT_PORTAL` | `$VF_HOME/client/portal`（環境変数は `VF_CLIENT_PORTAL`。シェルが export する `CLIENT_PORTAL` も見る） |
| `CLIENT_VF` | `$VF_HOME/client/vf`（環境変数は `VF_CLIENT_VF`。シェルが export する `CLIENT_VF` も見る） |
| `JS_GATES_DIR` | `$VF_GATES` があればそれ、無ければ `$VF_HOME/jsharness/gates` |
| `NODE_BIN_DIR` | `$VF_NODE_BIN`、無ければ最初に見つかった `$HOME/.nvm/versions/node/v22*/bin`、無ければ**空**（= PATH の node） |

**既定はこの機体で旧リテラルを再現する**。希望ではなく測ってある:
`reports/v134_raw/paths_resolved.txt`（環境変数を8つとも除いた子プロセスで、
3言語とも 6/6 が旧リテラルと一致）。

★**v135（判断63）で `CLIENT_PORTAL` / `CLIENT_VF` の既定の綴りが変わった**ので、
この2つの確認は**両側**になった: 既定が `$VF_HOME/client/{portal,vf}` に解決すること、
**かつ**その `realpath()` が v134 が記録したディレクトリと一致すること
（この機体では `client` はシンボリックリンクで、実体は v134 と同じ）。
**3言語とも 6/6 一致・realpath も 2/2 一致**: `reports/v135_raw/paths_resolved.txt`。
綴りだけ変えてディレクトリを動かしてしまった場合、**前半は通って後半が落ちる**。
`NODE=` は `NODE="${NODE_BIN_DIR:+$NODE_BIN_DIR/}node"` と書く — 空のとき `/node` にならないため。

**`nvm use 22` は効かない** — PATH の前方に `/usr/bin/node`（v20）がいる。**絶対パスで叩く。**
**StrykerJS は Node 22 以上を要求する**ので、v20 で呼ぶと検査4 が起動に失敗する（D22）。
