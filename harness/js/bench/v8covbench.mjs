// v8covbench.mjs — D) NODE_V8_COVERAGE と c8 の実測。
// 「入力ごとの touch 判定」に使えるかを問う。V8 coverage はプロセス終了時に
// 1ファイル書き出す設計なので、入力ごとに判定するにはプロセスを分ける必要がある。
// ここでは 1入力 = 1プロセス のコストを実測して外挿する。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "vf-v8cov-"));
const modPath = path.join(TMP, "m.mjs");
fs.writeFileSync(modPath, `
export function isAllowed(p, allowed) {
  for (const a of allowed) if (p === a || p.startsWith(a + "/")) return true;
  return false;
}
export function checkAccess(p, allowed) {
  if (p.startsWith("public/")) return true;
  return isAllowed(p, allowed);
}
`);
const runner = path.join(TMP, "run.mjs");
fs.writeFileSync(runner, `
import { checkAccess } from ${JSON.stringify(pathToFileURL(modPath).href)};
checkAccess(process.argv[2], ["ccd"]);
`);

function oneProcess(input, covDir) {
  fs.rmSync(covDir, { recursive: true, force: true });
  fs.mkdirSync(covDir, { recursive: true });
  const t0 = performance.now();
  spawnSync(process.execPath, [runner, input], {
    env: { ...process.env, NODE_V8_COVERAGE: covDir },
    stdio: "ignore",
  });
  const spawnMs = performance.now() - t0;
  // 生出力から関数単位の touch を読む
  let touched = null, files = 0, bytes = 0;
  for (const f of fs.readdirSync(covDir)) {
    const p = path.join(covDir, f);
    bytes += fs.statSync(p).size;
    files++;
    const j = JSON.parse(fs.readFileSync(p, "utf8"));
    for (const s of j.result || []) {
      if (s.url !== pathToFileURL(modPath).href) continue;
      for (const fn of s.functions) {
        if (fn.functionName !== "isAllowed") continue;
        touched = fn.ranges.reduce((a, r) => a + r.count, 0) > 0;
      }
    }
  }
  return { spawnMs, touched, files, bytes };
}

const covDir = path.join(TMP, "cov");
const warm = oneProcess("ccd/warm", covDir);
const hit = oneProcess("ccd/y1", covDir);      // アンカー到達
const miss = oneProcess("public/x2", covDir);  // アンカー不到達

let total = 0;
const REPS = 10;
for (let i = 0; i < REPS; i++) total += oneProcess("ccd/y" + i, covDir).spawnMs;
const perProc = total / REPS;

// c8 の起動コストも参考測定
const t0 = performance.now();
const c8 = spawnSync("npx", ["c8", "--reporter=json", "--reports-dir", path.join(TMP, "c8out"),
  "node", runner, "ccd/y1"], { stdio: "ignore", shell: false });
const c8Ms = performance.now() - t0;

console.log(JSON.stringify({
  method: "D NODE_V8_COVERAGE (per-process)",
  function_level_touch_readable: hit.touched === true && miss.touched === false,
  hit_touched: hit.touched, miss_touched: miss.touched,
  cov_files_per_run: hit.files, cov_bytes_per_run: hit.bytes,
  ms_per_process: +perProc.toFixed(1),
  extrapolated_s_for_9132_inputs: +((perProc * 9132) / 1000).toFixed(1),
  c8_single_run_ms: +c8Ms.toFixed(0), c8_rc: c8.status,
  note: "V8 coverage はプロセス終了時ダンプ。入力ごとの touch には 1入力=1プロセスが必要",
}, null, 1));
fs.rmSync(TMP, { recursive: true, force: true });
