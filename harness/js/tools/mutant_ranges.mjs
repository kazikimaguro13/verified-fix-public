// mutant_ranges.mjs — §12-A11 の材料。**ゲートではない**（番号なし・run_gates 非接続・
// 合否に不参加）。検査4 が出した `mutate_spec` の**レンジごとの変異数**を数える。
//
// WHY (HANDOFF §0-j-9 ④-c)
// ------------------------
// §0-c の教訓は「検査した件数を必ず出力に載せる」だった。v46 で件数は出ていた（12件）。
// **それでも穴は隠れた。件数は「どこに載ったか」を言わないからである。**
// 検査4 の合格条件は `mutants >= 1 && survived === 0 && noCov === 0` で、どのレンジから
// 出た変異かを問わない。あるレンジが0件なら「そのレンジは検証されていない」のに、
// 出力からはそう読めない。
//
// この道具は、検査4 が書き残した Stryker の JSON レポートを読み、mutate_spec の各
// レンジに何件載ったかを突き合わせるだけ。**判定はしない。**
//
// usage: mutant_ranges.mjs <repo> <check4-detail.json | 結果 JSON>
//   結果 JSON（run_gates の出力）なら `.check4.mutate_spec` を使う。
//   レポートは <repo>/reports/mutation.json（検査4 が最後に走った版）。

import fs from "node:fs";
import path from "node:path";

const repo = process.argv[2];
const resultFile = process.argv[3];
if (!repo || !resultFile) {
  console.error("usage: mutant_ranges.mjs <repo> <result.json>");
  process.exit(2);
}

const res = JSON.parse(fs.readFileSync(resultFile, "utf8"));
const c4 = res.check4 || res;
const spec = c4.mutate_spec || [];
const reportFile = path.join(repo, "reports/mutation.json");

if (!spec.length) {
  console.log(JSON.stringify({
    tool: "mutant_ranges", measured: false,
    why: "the result carries no mutate_spec (検査4 did not run, or could not run)",
  }, null, 1));
  process.exit(1);
}
if (!fs.existsSync(reportFile)) {
  console.log(JSON.stringify({
    tool: "mutant_ranges", measured: false,
    why: "no Stryker report at " + reportFile + " -- 検査4 rewrites it every run, "
       + "so this must be read right after the run whose ranges are being counted",
  }, null, 1));
  process.exit(1);
}

const ranges = spec.map((s) => {
  const m = /^(.*):(\d+)-(\d+)$/.exec(s);
  return { spec: s, file: m[1], lo: +m[2], hi: +m[3], n: 0, killed: 0,
           survived: 0, no_coverage: 0, operators: {} };
});

const rep = JSON.parse(fs.readFileSync(reportFile, "utf8"));
let total = 0;
const unattributed = [];
for (const [file, f] of Object.entries(rep.files || {}))
  for (const m of f.mutants || []) {
    total++;
    const line = m.location.start.line;
    const hit = ranges.filter((r) => file.endsWith(r.file) && line >= r.lo && line <= r.hi);
    if (!hit.length) { unattributed.push(`${file}:${line} ${m.mutatorName}`); continue; }
    for (const r of hit) {
      r.n++;
      r.operators[m.mutatorName] = (r.operators[m.mutatorName] || 0) + 1;
      if (m.status === "Killed") r.killed++;
      else if (m.status === "Survived") r.survived++;
      else if (m.status === "NoCoverage") r.no_coverage++;
    }
  }

console.log(JSON.stringify({
  tool: "mutant_ranges",
  note: "NOT A GATE.  Counts only; the verdict stays with 検査4.",
  measured: true,
  variant: res.name || null,
  profile: res.profile || null,
  report: reportFile,
  mutants_in_report: total,
  mutants_reported_by_check4: c4.mutants ?? null,
  ranges: ranges.map((r) => ({
    spec: r.spec, mutants: r.n, killed: r.killed, survived: r.survived,
    no_coverage: r.no_coverage, operators: r.operators,
    // ★これが A11 の要点。0件のレンジは「そのレンジは検証されていない」と読める形で出す。
    verdict_note: r.n === 0
      ? "UNVERIFIED RANGE: the patch changed these lines and no mutant was "
      + "generated on them, so nothing about them was tested by 検査4"
      : null,
  })),
  n_unverified_ranges: ranges.filter((r) => r.n === 0).length,
  unattributed_mutants: unattributed,
}, null, 1));
