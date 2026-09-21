// run_check5.mjs — 検査5（diffgate.mjs）だけを、パイプラインを回さずに当てる（v44・§12-A1b）。
//
//   node run_check5.mjs <orch2 の cfg.json> [--post <rel>=<絶対パス>] [--out <file>]
//
// なぜ要るか
// ----------
// 検査5 は POST イメージを作業ツリーに置いた状態でしか意味を持たない（駆動器は
// ツリーからアンカーを import する）。run_gates.mjs はそれを installImages でやるが、
// パイプライン1本は fast でも 100〜120秒かかる。**検査5 だけなら数秒**で、
// 「力があるか」を測るのに何度も回す必要がある。
//
// --post は POST イメージを差し替える。**ゲートの力を測るため**にある:
// 「本当に振る舞いを変えた版」を当てて乖離が出るかを見る。出なければ
// コーパスがその差に**盲目**だと分かる。出れば空振りでないと分かる。
// **どちらか片方だけを測って結論を書かないこと**（§0-c の14回はぜんぶこの形）。
//
// ⚠ 作業ツリーを一時的に書き換える。走行中は他の実験を走らせない（罠9）。
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { JS_GATES_DIR } from "./vf_paths.mjs";

const args = process.argv.slice(2);
const cfgPath = args[0];
if (!cfgPath) {
  console.error("usage: run_check5.mjs <cfg.json> [--post rel=abs] [--out file]");
  process.exit(2);
}
const overrides = {};
let outFile = null;
for (let i = 1; i < args.length; i++) {
  if (args[i] === "--post") {
    const kv = args[++i] || "";
    const j = kv.indexOf("=");
    if (j < 0) { console.error("--post wants rel=abs"); process.exit(2); }
    overrides[kv.slice(0, j)] = kv.slice(j + 1);
  } else if (args[i] === "--out") outFile = args[++i];
}

const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const repo = cfg.repo;
const HERE = path.dirname(new URL(import.meta.url).pathname);
const GATES = JS_GATES_DIR;   // ★v134 (judgement 61): still honours VF_GATES

const post = { ...(cfg.post_images || {}), ...overrides };

// install, run, restore -- same shape as run_gates.mjs's installImages()
const saved = new Map();
for (const [rel, src] of Object.entries(post)) {
  const dst = path.join(repo, rel);
  saved.set(dst, fs.existsSync(dst) ? fs.readFileSync(dst, "utf8") : null);
  fs.copyFileSync(src, dst);
}
let result;
try {
  const dgCfg = path.join(repo, ".vf/diffgate.standalone.cfg.json");
  fs.mkdirSync(path.dirname(dgCfg), { recursive: true });
  fs.writeFileSync(dgCfg, JSON.stringify({
    repo, anchor_file: cfg.anchor_file, anchor_func: cfg.anchor_func,
    spec: JSON.parse(fs.readFileSync(cfg.anchor_spec, "utf8")),
    spec_source: cfg.anchor_spec,
    pre_images: cfg.pre_images, post_images: post,
  }), "utf8");
  const r = spawnSync(process.execPath, [path.join(GATES, "diffgate.mjs"), dgCfg],
    { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  try { result = JSON.parse(r.stdout); }
  catch {
    result = { pass: false, error: "diffgate produced no parseable JSON",
               exit_code: r.status,
               stdout_tail: String(r.stdout || "").split("\n").slice(-10).join("\n"),
               stderr_tail: String(r.stderr || "").split("\n").slice(-10).join("\n") };
  }
} finally {
  for (const [dst, prev] of saved) {
    if (prev === null) fs.rmSync(dst, { force: true });
    else fs.writeFileSync(dst, prev, "utf8");
  }
}
result.variant = cfg.name;
result.post_overrides = Object.keys(overrides);
const text = JSON.stringify(result, null, 1);
if (outFile) fs.writeFileSync(outFile, text, "utf8");
console.log(text);
// 一行要約は stderr へ（v38 の読み方: 終了コードで受理を判定しない）
console.error(`${cfg.name}  check5=${result.pass ? "pass" : "FAIL"}`
  + `  compared=${result.compared_calls ?? "-"}`
  + `  touched=${result.n_touched ?? "-"}/${result.compared_calls ?? "-"}`
  + `  out_of_scope=${result.out_of_scope_divergences ?? "-"}`
  + `  type=${result.return_type_divergences ?? "-"}`
  + `  in_scope=${result.in_scope_divergences ?? "-"}`
  + `  emitted=${result.emitted_divergences ?? "-"}`
  + `  uncovered=${(result.uncovered_changed_functions || []).length}`
  + (result.gate_could_not_run ? "  COULD-NOT-RUN" : "")
  + (result.inapplicable ? "  INAPPLICABLE" : ""));
process.exit(result.pass === true ? 0 : 1);
