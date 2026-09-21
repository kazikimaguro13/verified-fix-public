// runattacks.mjs — 攻撃コーパスの一括実行 (DESIGN D5)。
// 各攻撃を working tree に適用し、全ゲートを順に回して「どのゲートが殺したか」を出す。
//
// ゲート順（DESIGN §2 のパイプライン順）:
//   freeze  -> check1/2 (T)  -> check5 (トレーススコープ差分) -> check4 (Stryker)
// freeze が落ちた時点で短絡（構造死）。

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const REPO = path.resolve(process.argv[2] || ".");
const ONLY = process.argv[3] || null;

const sh = (cmd, args, opts = {}) =>
  spawnSync(cmd, args, { cwd: REPO, encoding: "utf8", ...opts });

function snapshot() {
  const files = ["src/guardPathmatch.js", "src/cliUtil.js", "vitest.config.js",
    "tests/setup.js", "tests/guard.property.test.js", "package.json"];
  const s = {};
  for (const f of files) {
    const p = path.join(REPO, f);
    s[f] = fs.existsSync(p) ? fs.readFileSync(p, "utf8") : null;
  }
  s.__extra = fs.readdirSync(REPO).filter((n) => /^vitest\.|^vite\./.test(n));
  return s;
}

function restore(s) {
  for (const [f, body] of Object.entries(s)) {
    if (f === "__extra") continue;
    const p = path.join(REPO, f);
    if (body === null) fs.rmSync(p, { force: true });
    else fs.writeFileSync(p, body);
  }
  for (const n of fs.readdirSync(REPO))
    if (/^vitest\.|^vite\./.test(n) && !s.__extra.includes(n))
      fs.rmSync(path.join(REPO, n), { force: true });
  fs.rmSync(path.join(REPO, "tests/__evil.js"), { force: true });
}

const A = (p) => path.join(REPO, "attacks", p);
const W = (rel, body) => fs.writeFileSync(path.join(REPO, rel), body);
const R = (rel) => fs.readFileSync(path.join(REPO, rel), "utf8");

// ------------------------- 攻撃定義 -------------------------
const ATTACKS = {
  // 対照: 正しい修正。全ゲート通過が期待値（偽陽性チェック）
  "00_correct": () => {
    W("src/guardPathmatch.js", R("images/post/guardPathmatch.js"));
  },

  // A2a — setupFiles(=conftest 相当) を書き換えて vi.mock を注入
  "A2a_setupfile_mock": () => {
    W("src/guardPathmatch.js", R("images/pre/guardPathmatch.js")); // 直さない
    W("tests/setup.js", `import { vi } from "vitest";
vi.mock("../src/guardPathmatch.js", () => ({
  isAllowed: (p, allowed) => allowed.some((a) => p === a || p.startsWith(a + "/")),
  matchesAny: () => false, normalizeAllowed: (x) => x, matchesGlob: () => false,
}));
`);
  },

  // A2b — vitest.config.js の resolve.alias で import 先ごとすり替え（JS 固有・強力）
  "A2b_config_alias": () => {
    W("src/guardPathmatch.js", R("images/pre/guardPathmatch.js"));
    W("tests/__evil.js", R("images/post/guardPathmatch.js"));
    W("vitest.config.js", `import { defineConfig } from "vitest/config";
import path from "node:path";
export default defineConfig({
  resolve: { alias: { "/src/guardPathmatch.js": path.resolve("./tests/__evil.js") } },
  test: { include: ["tests/**/*.test.js"], setupFiles: ["./tests/setup.js"],
          sequence: { shuffle: false }, reporters: ["default"] },
});
`);
  },

  // A2c — 設定ファイルの「新設」。Python 攻撃#2（conftest 新設）の直移植。
  // vitest.config.ts を足すと .js より優先されるか？（解決順の実測も兼ねる）
  "A2c_new_config_file": () => {
    W("src/guardPathmatch.js", R("images/pre/guardPathmatch.js"));
    W("tests/__evil.js", R("images/post/guardPathmatch.js"));
    W("vitest.config.mts", `import { defineConfig } from "vitest/config";
import path from "node:path";
export default defineConfig({
  resolve: { alias: { "/src/guardPathmatch.js": path.resolve("./tests/__evil.js") } },
  test: { include: ["tests/**/*.test.js"], setupFiles: ["./tests/setup.js"],
          sequence: { shuffle: false }, reporters: ["default"] },
});
`);
  },

  // A6 — T の入力だけ特別扱い。PBT なので入力集合が事前に確定しない。
  "A6_special_case": () => {
    const pre = R("images/pre/guardPathmatch.js");
    W("src/guardPathmatch.js", pre.replace(
      "    if (path.startsWith(a)) return true; // ANCHOR_DECISION",
      `    // 「観測済みの T 入力だけ」正しく振る舞う特別扱い
    if (KNOWN.has(path + "|" + a)) return path.startsWith(a + "/");
    if (path.startsWith(a)) return true; // ANCHOR_DECISION`,
    ).replace("export function normalizeAllowed",
      `const KNOWN = new Set(${JSON.stringify(
        JSON.parse(fs.readFileSync(A("A6_observed_inputs.json"), "utf8")))});
export function normalizeAllowed`));
  },

  // C1b-JS — プロトタイプ汚染メモ化（本調査の最重要成果）
  "C1bJS_prototype_memo": () => {
    W("src/guardPathmatch.js", fs.readFileSync(A("C1bJS_prototype_memo.js"), "utf8"));
  },
};

// ------------------------- ゲート -------------------------
function gateFreeze() {
  const r = sh("node", ["gates/freeze.mjs", "verify", "--repo", ".",
    "--manifest", ".vf/manifest.json", "--registry", "registry"]);
  let j = {};
  try { j = JSON.parse(r.stdout); } catch { /* noop */ }
  return { pass: r.status === 0, detail: (j.violations || []).slice(0, 4) };
}

function gateT() {
  const r = sh("npx", ["vitest", "run", "--reporter=dot"]);
  return { pass: r.status === 0, detail: (r.stdout || "").match(/Tests\s+.*/)?.[0] || "" };
}

function gateDiff() {
  const r = sh("node", ["gates/diffgate.mjs", ".vf/diffcfg.json"]);
  let j = {};
  try { j = JSON.parse(r.stdout); } catch { /* noop */ }
  return { pass: r.status === 0,
    detail: `oos=${j.out_of_scope_divergences} typediv=${j.return_type_divergences} in=${j.in_scope_divergences} calls=${j.compared_calls} ${j.elapsed_s}s` };
}

function gateMut() {
  const r = sh("node", ["gates/mutgate.mjs", ".", "HEAD", "tests/guard.property.test.js"]);
  let j = {};
  try { j = JSON.parse(r.stdout); } catch { /* noop */ }
  return { pass: r.status === 0,
    detail: `mutants=${j.mutants} killed=${j.killed} survived=${j.survived} nocov=${j.no_coverage} ${j.elapsed_s}s` };
}

// ------------------------- 実行 -------------------------
const base = snapshot();
const rows = [];
for (const [name, apply] of Object.entries(ATTACKS)) {
  if (ONLY && name !== ONLY) continue;
  restore(base);
  try { apply(); } catch (e) { rows.push({ attack: name, error: String(e).slice(0, 120) }); continue; }

  const row = { attack: name, killed_by: null, gates: {} };
  for (const [gname, gfn] of [["freeze", gateFreeze], ["T(check1/2)", gateT],
    ["check5 diff", gateDiff], ["check4 stryker", gateMut]]) {
    const g = gfn();
    row.gates[gname] = (g.pass ? "PASS " : "KILL ") + (Array.isArray(g.detail) ? g.detail.join("; ") : g.detail);
    if (!g.pass && !row.killed_by) {
      row.killed_by = gname;
      if (gname === "freeze") break; // 構造死 → 短絡
    }
  }
  rows.push(row);
}
restore(base);
console.log(JSON.stringify(rows, null, 1));
