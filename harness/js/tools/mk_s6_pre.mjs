// mk_s6_pre.mjs — S6_new_export の PRE イメージを組み立てる（v42・§12-A0c2）
//
// WHY THIS IS NOT JUST `git show <commit>^:<file>`
// ------------------------------------------------
// v38 は S6 を他の対照と同じ形（1ファイルを丸ごと pre へ戻す）で組んで、**失敗した**。
// 修正コミット `2835baf` は
//     src/lib/internal-mail-rate-limit.ts        （新しい export を足す・純追加43行）
//     src/app/api/batch/mail-send/route.ts       （その export を呼ぶ）
// を**同じコミットで**変えている。前者だけを戻すと、HEAD の route.ts が
// 存在しない関数を呼ぶ**歴史上存在しないツリー**になる（v38 のベースラインが
// 1123/1279 = 156件失敗だったのがその証拠）。
//
// では route.ts も `2835baf^` の版に戻せばよいかというと、戻せない。
// route.ts は `f51ffc7`（6周目レビュー）でさらに70行変わっており、
// `2835baf^` の版を置くと **f51ffc7 の修正まで巻き戻る**。それは S6 の指摘とは
// 無関係な変更で、対照が測るものが変わってしまう。
//
// WHAT THIS DOES INSTEAD
// ----------------------
// **指摘の範囲だけを HEAD から取り除く。** S6 の指摘（`S6_new_export.finding.txt`）は
// 「拒否された依頼も数える要求枠を、検査より先に消費すること」の1件だけである。
// その1件に対応する route.ts の変更は2か所しかない:
//
//   (1) `consumeInternalMailRequestQuota` の import
//   (2) POST の先頭でそれを呼ぶブロック（直上の説明コメントを含む）
//
// この2か所だけを外すと、**他は HEAD のまま**の PRE ツリーになる。
// 他の対照が「1ファイルを丸ごと戻す」のと同じ意味 —「その指摘が直る前の木」— を、
// 修正が複数ファイルにまたがる場合に取り出したのがこれである。
//
// ★f51ffc7 は要求枠の行を1行も触っていない（実測: `git show f51ffc7 -- route.ts`
//   に `RequestQuota` が現れない）ので、この切り取りと f51ffc7 は干渉しない。
//
// 位置はテキストで指定せず**構造で**探す（罠8: 日本語コメントを書き写すと
// バイトがずれる）。見つからなければ黙って何もしないのではなく、落ちる。
//
// usage: node mk_s6_pre.mjs <HEAD の route.ts> <出力する pre route.ts>

import fs from "node:fs";

const [, , inPath, outPath] = process.argv;
if (!inPath || !outPath) {
  console.error("usage: node mk_s6_pre.mjs <in route.ts> <out pre route.ts>");
  process.exit(2);
}
const src = fs.readFileSync(inPath, "utf8");
const SYM = "consumeInternalMailRequestQuota";

function die(msg) { console.error("★S6 の PRE を組めない: " + msg); process.exit(3); }

// --- (1) import ------------------------------------------------------------ //
// HEAD の形（2835baf が作った形）:
//   import {
//     consumeInternalMailQuota,
//     consumeInternalMailRequestQuota,
//   } from '@/lib/internal-mail-rate-limit';
// 2835baf^ の形:
//   import { consumeInternalMailQuota } from '@/lib/internal-mail-rate-limit';
const MOD = "@/lib/internal-mail-rate-limit";
let lines = src.split("\n");
const impStart = lines.findIndex((l) => l.trim() === "import {");
let impFrom = -1;
for (let i = 0; i < lines.length; i++)
  if (lines[i].includes("} from '" + MOD + "'") || lines[i].includes('} from "' + MOD + '"')) impFrom = i;
if (impFrom < 0) die("`} from '" + MOD + "'` の行が無い（import の形が変わった）");
let impOpen = impFrom;
while (impOpen >= 0 && lines[impOpen].trim() !== "import {") impOpen--;
if (impOpen < 0) die("その import の開き `import {` が見つからない");
const named = lines.slice(impOpen + 1, impFrom).map((l) => l.trim().replace(/,$/, ""));
if (!named.includes(SYM)) die("import に " + SYM + " が無い（既に PRE になっている？）");
const kept = named.filter((n) => n !== SYM);
if (!kept.length) die("この import は " + SYM + " しか持っていない。想定と違う");
lines.splice(impOpen, impFrom - impOpen + 1,
             "import { " + kept.join(", ") + " } from '" + MOD + "';");
void impStart;

// --- (2) 呼び出しブロック --------------------------------------------------- //
const callIdx = lines.findIndex((l) => l.includes("if (!" + SYM + "("));
if (callIdx < 0) die("`if (!" + SYM + "(` の行が無い");
if (lines.filter((l) => l.includes("if (!" + SYM + "(")).length !== 1)
  die("`if (!" + SYM + "(` が2か所以上ある。構造で切れない");
let start = callIdx;
while (start > 0 && /^\s*\/\//.test(lines[start - 1])) start--;   // 直上のコメント塊も外す
let end = callIdx;
while (end < lines.length && lines[end].trim() !== "}") end++;
if (end >= lines.length) die("呼び出しブロックの閉じ `}` が見つからない");
let last = end;
if (lines[last + 1] !== undefined && lines[last + 1].trim() === "") last++;  // 続く空行1つ
const cut = lines.slice(start, last + 1);
lines.splice(start, last - start + 1);

const out = lines.join("\n");
if (out.includes(SYM)) die(SYM + " が残っている（切り取りが足りない）");

fs.writeFileSync(outPath, out, "utf8");
const nIn = src.split("\n").length, nOut = out.split("\n").length;
console.log("S6 PRE route.ts を書いた: " + outPath);
console.log("  行数        : " + nIn + " -> " + nOut + "  (-" + (nIn - nOut) + ")");
console.log("  import 置換 : " + named.join(",") + "  ->  " + kept.join(","));
console.log("  外した塊    : " + cut.length + " 行 (" + (start + 1) + "-" + (last + 1) + " 行目)");
console.log("  残りの " + SYM + " 参照: 0 件");
