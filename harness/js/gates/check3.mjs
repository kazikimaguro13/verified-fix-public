// check3.mjs — 検査3（巻き戻し負の対照）の JS 版。
// 「修正を戻したら T は本当に落ちるか」。落ちなければ T は修正を検査していない。
//
// ★JS 固有の困難（実測で確定・Python より弱い）:
//   Python 版は「同一テストIDが *assertion* で失敗したか」を pytest の
//   outcome（passed/failed/error）で構造的に判定できる。collection/ImportError は
//   `error` になるので「T が落ちた」と数えない ⇒ 攻撃#5（修正が導入した
//   シンボルへの偽の依存）を検出できた。
//
//   vitest/vite では:
//     (a) **存在しない名前付き export を import しても一切エラーにならない**
//         （undefined に束縛され、スイートは "passed" のまま）。実測済み。
//     (b) 実行時に TypeError になった場合も JSON レポータ上は status="failed" で、
//         assertion 失敗と区別が付かない。
//   ⇒ 判定は failureMessages の **本文検査** に頼るしかない。構造判定より弱い。
//      本ファイルはその本文検査を明示的に実装し、判定根拠を出力に残す。

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { scratchPath } from "./scratch.mjs";

const repo = path.resolve(process.argv[2] || ".");
const preImage = process.argv[3];               // 巻き戻し先（修正前ソース）
const target = process.argv[4] || "src/guardPathmatch.js";
const oracle = process.argv[5] || "tests/guard.property.test.js";

// T が「本物の挙動失敗」で落ちたと認めるパターン
const GENUINE = [
  /Property failed after/i,          // fast-check
  /AssertionError/i,
  /expected .* to (be|equal)/i,
];
// 「T が壊れて落ちた」= 認めないパターン（攻撃#5 の痕跡）
const BOGUS = [
  /TypeError: .* is not a function/i,
  /ReferenceError/i,
  /does not provide an export named/i,
  /Cannot find module|Failed to resolve import/i,
  /Cannot read propert(y|ies) of undefined/i,
];

// ★v110 (decision 33): out of the repository under test.
const outFile = scratchPath(repo, "check3.json");
const clsFile = scratchPath(repo, "check3.tclass.json");
const cur = fs.readFileSync(path.join(repo, target), "utf8");

let verdict;
try {
  fs.rmSync(clsFile, { force: true });
  fs.writeFileSync(path.join(repo, target), fs.readFileSync(preImage, "utf8")); // 巻き戻し
  spawnSync("npx", ["vitest", "run", oracle, "--reporter=json", "--outputFile", outFile],
    { cwd: repo, encoding: "utf8", env: { ...process.env, VF_TCLASS: clsFile } });

  const j = JSON.parse(fs.readFileSync(outFile, "utf8"));
  const suite = (j.testResults || [])[0] || {};
  const results = suite.assertionResults || [];
  const failed = results.filter((r) => r.status === "failed");
  const msgs = failed.flatMap((r) => r.failureMessages || []);

  // ★構造判定（本命）: ハーネス所有の assertWithCorpus が残した種別記録を読む。
  //   これがある場合は本文正規表現より優先する。
  let tclass = [];
  try { tclass = JSON.parse(fs.readFileSync(clsFile, "utf8")); } catch { /* noop */ }

  const collected = results.length > 0;
  const anyFailed = failed.length > 0;
  const structuralByClass = tclass.some((c) => c.kind === "structural");
  const behaviouralByClass = tclass.some((c) => c.kind === "behavioural");

  // フォールバック（T がハーネスのラッパを使っていない場合のみ）
  const genuine = tclass.length ? behaviouralByClass : msgs.some((m) => GENUINE.some((re) => re.test(m)));
  const bogus = tclass.length ? structuralByClass : msgs.some((m) => BOGUS.some((re) => re.test(m)));

  let reason = null;
  if (!collected) reason = "oracle produced no test results (suite did not load)";
  else if (!anyFailed) reason = "oracle STILL PASSED after reverting the fix — it does not test the fix";
  else if (bogus) reason = "oracle failed with a STRUCTURAL error (TypeError/ReferenceError/import), not a behavioural violation — 攻撃#5（偽の依存点）";
  else if (!genuine) reason = "oracle failed but the failure could not be classified as behavioural — 判定不能として却下";

  verdict = {
    gate: "check3 (revert negative control)",
    pass: collected && anyFailed && genuine && !bogus,
    collected, n_tests: results.length, n_failed: failed.length,
    failed_ids: failed.map((r) => r.fullName),
    classification_source: tclass.length ? "fc.check RunDetails.errorInstance (structural)" : "failureMessages regex (fallback, weak)",
    failure_classes: tclass,
    genuine_behavioural_failure: genuine, structural_error: bogus,
    reason,
    js_caveat: "vite は存在しない named export を undefined に束縛しエラーを出さない。かつ fc.assert は TypeError を 'Property failed' に潰す。ハーネスが fc.check をラップしない限り攻撃#5 は検出不能（実測）",
    sample_message: String(msgs[0] || "").slice(0, 160),
  };
} finally {
  fs.writeFileSync(path.join(repo, target), cur); // 元に戻す
}

console.log(JSON.stringify(verdict, null, 1));
process.exit(verdict.pass ? 0 : 1);
