// tracebench.mjs — 「入力の実行トレースがアンカー関数に触れたか」を JS で取る
// 4方式の実地比較。DESIGN 検査5 の JS 移植の中核判断材料。
//
//   A) source-transform   : PRE 像のアンカー本体先頭に触フラグを注入
//   B) export-wrap        : 輸出をラップ（Python の setattr 相当）
//   C) node:inspector     : Profiler.startPreciseCoverage + takePreciseCoverage 差分
//   D) NODE_V8_COVERAGE   : プロセス終了時ダンプ（別スクリプトで計測）
//
// 題材は「公開入口 checkAccess が内部でアンカー isAllowed を呼ぶ」構造。
// これが実務での普通の形（アンカーは内部ヘルパ）。

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import inspector from "node:inspector";
import { instrumentAnchor } from "../gates/diffgate.mjs";

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "vf-bench-"));

const MODULE_SRC = `
export function isAllowed(p, allowed) {          // ← ANCHOR
  for (const a of allowed) if (p === a || p.startsWith(a + "/")) return true;
  return false;
}
export function checkAccess(p, allowed) {        // 公開入口。内部でアンカーを呼ぶ
  if (p.startsWith("public/")) return true;      // アンカーに触れない分岐
  return isAllowed(p, allowed);                  // アンカーに触れる分岐
}
`;

const N = 20000;
const INPUTS = Array.from({ length: N }, (_, i) =>
  i % 2 === 0 ? ["public/x" + i, ["ccd"]] : ["ccd/y" + i, ["ccd"]]);
// 偶数 = public/ 分岐（アンカー不到達）, 奇数 = アンカー到達。正解は 50% touched。

async function loadFrom(src, tag) {
  const p = path.join(TMP, tag + ".mjs");
  fs.writeFileSync(p, src);
  return import(pathToFileURL(p).href);
}

const results = [];

// ---------- A) source transform ----------
{
  globalThis.__VF_TOUCH = { hit: false };
  const { src, ok } = instrumentAnchor(MODULE_SRC, "isAllowed");
  const m = await loadFrom(src, "A");
  const t0 = performance.now();
  let touched = 0;
  for (const [p, a] of INPUTS) {
    globalThis.__VF_TOUCH.hit = false;
    m.checkAccess(p, a);
    if (globalThis.__VF_TOUCH.hit) touched++;
  }
  const dt = performance.now() - t0;
  results.push({
    method: "A source-transform", instrumentable: ok, calls: N,
    touched, touched_pct: +(100 * touched / N).toFixed(1),
    total_ms: +dt.toFixed(1), us_per_call: +((dt * 1000) / N).toFixed(2),
    catches_internal_calls: touched > 0,
  });
}

// ---------- B) export wrap (Python の setattr 相当) ----------
{
  const m = await loadFrom(MODULE_SRC, "B");
  let hit = false;
  // ESM 名前空間は凍結・読取専用。まず「書けるか」を実測する。
  let wrapError = null, wrapped = false;
  try {
    const orig = m.isAllowed;
    Object.defineProperty(m, "isAllowed", {
      value: (...a) => { hit = true; return orig(...a); },
      configurable: true, writable: true,
    });
    wrapped = m.isAllowed !== orig;
  } catch (e) { wrapError = String(e.message).slice(0, 120); }

  // CJS でも同じことを試す（module.exports は可変オブジェクト）
  const cjsPath = path.join(TMP, "B.cjs");
  fs.writeFileSync(cjsPath, `
function isAllowed(p, allowed) {
  for (const a of allowed) if (p === a || p.startsWith(a + "/")) return true;
  return false;
}
function checkAccess(p, allowed) {
  if (p.startsWith("public/")) return true;
  return isAllowed(p, allowed);   // 内部呼び出しは字句束縛
}
module.exports = { isAllowed, checkAccess };
`);
  const { createRequire } = await import("node:module");
  const req = createRequire(import.meta.url);
  const cjs = req(cjsPath);
  let cjsHit = false;
  const cjsOrig = cjs.isAllowed;
  cjs.isAllowed = (...a) => { cjsHit = true; return cjsOrig(...a); };
  const cjsWrapOk = cjs.isAllowed !== cjsOrig;

  const t0 = performance.now();
  let touched = 0, cjsTouched = 0;
  for (const [p, a] of INPUTS) {
    hit = false; cjsHit = false;
    if (wrapped) m.checkAccess(p, a);
    cjs.checkAccess(p, a);
    if (hit) touched++;
    if (cjsHit) cjsTouched++;
  }
  const dt = performance.now() - t0;
  results.push({
    method: "B export-wrap", esm_namespace_writable: wrapped, esm_wrap_error: wrapError,
    cjs_exports_writable: cjsWrapOk,
    calls: N, touched_esm: touched, touched_cjs: cjsTouched,
    total_ms: +dt.toFixed(1),
    catches_internal_calls: touched > 0 || cjsTouched > 0,
    note: "内部呼び出しは字句解決されるので輸出を差し替えても捕捉できない（Python との決定的な差）",
  });
}

// ---------- C) node:inspector precise coverage ----------
{
  const m = await loadFrom(MODULE_SRC, "C");
  const session = new inspector.Session();
  session.connect();
  const post = (method, params) =>
    new Promise((res, rej) => session.post(method, params, (e, r) => (e ? rej(e) : res(r))));

  await post("Profiler.enable");
  await post("Profiler.startPreciseCoverage", { callCount: true, detailed: true });

  const url = pathToFileURL(path.join(TMP, "C.mjs")).href;
  const anchorCount = (cov) => {
    for (const s of cov.result) {
      if (s.url !== url) continue;
      for (const f of s.functions) if (f.functionName === "isAllowed")
        return f.ranges.reduce((a, r) => a + r.count, 0);
    }
    return 0;
  };

  // 1回ウォーム
  m.checkAccess("ccd/warm", ["ccd"]);
  let prev = anchorCount(await post("Profiler.takePreciseCoverage"));

  const SUB = 2000; // inspector は重いので部分計測
  const t0 = performance.now();
  let touched = 0;
  for (let i = 0; i < SUB; i++) {
    const [p, a] = INPUTS[i];
    m.checkAccess(p, a);
    const cur = anchorCount(await post("Profiler.takePreciseCoverage"));
    if (cur > prev) touched++;
    prev = cur;
  }
  const dt = performance.now() - t0;
  await post("Profiler.stopPreciseCoverage");
  session.disconnect();
  results.push({
    method: "C node:inspector preciseCoverage", calls: SUB,
    touched, touched_pct: +(100 * touched / SUB).toFixed(1),
    total_ms: +dt.toFixed(1), us_per_call: +((dt * 1000) / SUB).toFixed(2),
    catches_internal_calls: touched > 0,
    note: "takePreciseCoverage は全スクリプト分の JSON を毎回返すので入力ごとに呼ぶと高い",
  });
}

console.log(JSON.stringify({ inputs: N, tmp: TMP, results }, null, 1));
fs.rmSync(TMP, { recursive: true, force: true });
