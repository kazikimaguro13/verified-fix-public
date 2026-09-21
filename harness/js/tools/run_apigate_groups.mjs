// run_apigate_groups.mjs — 検査7 を「別の群の組み合わせ」で単独に回す（v43）
//
// なぜ要るか
// ----------
// 検査7 の curated list は3群（classify / ambient / codepoint）あるが、
// **既定で有効なのは classify と ambient の2つだけ**（run_gates.mjs の
// `cfg.check7_groups || "classify,ambient"`）。
// 「その名前は表に在ったのか、それとも既定で off だっただけか」を区別したいとき、
// パイプラインを丸ごと回し直すのは高い（100〜160秒）。**検査7 単独なら 0.1 秒。**
//
// ★これは既定を変える道具ではない。**どの列挙なら当たったかを測る**道具。
//   エスカレートは却下ではない（D22）ので、鳴っても判定は動かない。
//
// usage:
//   node run_apigate_groups.mjs <orch2 の cfg.json> [群1] [群2] ...
//   （群を省略すると "classify,ambient" と "classify,ambient,codepoint" の2本を回す）

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { JS_GATES_DIR } from "./vf_paths.mjs";

const GATES = JS_GATES_DIR;   // ★v134 (judgement 61): see tools/vf_paths.mjs
const cfgPath = process.argv[2];
if (!cfgPath) { console.error("usage: run_apigate_groups.mjs <cfg.json> [groups...]"); process.exit(2); }
const groupSets = process.argv.slice(3);
if (!groupSets.length) groupSets.push("classify,ambient", "classify,ambient,codepoint");

const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const repo = cfg.repo;

// run_gates.mjs が書くのと同じ形の litgate cfg。`caller_files` は run_gates の
// findCallers と同じものを使いたいので、**直前の走行が残した cfg があればそこから借りる**。
// 借りられないときは空にして、その事実を出力に書く（§0-c: 測っていないことは黙らない）。
const liveLit = path.join(repo, ".vf/litgate.cfg.json");
let callers = [], callersFrom = "empty (no previous run to borrow from)";
if (fs.existsSync(liveLit)) {
  try {
    const prev = JSON.parse(fs.readFileSync(liveLit, "utf8"));
    if (Array.isArray(prev.caller_files)) {
      callers = prev.caller_files;
      callersFrom = liveLit + " (" + callers.length + " files)";
    }
  } catch { /* 借りられない。上の既定のまま */ }
}

const litCfg = path.join(repo, ".vf/apigate_groups.cfg.json");
fs.mkdirSync(path.dirname(litCfg), { recursive: true });
fs.writeFileSync(litCfg, JSON.stringify({
  repo,
  pre_images: cfg.pre_images, post_images: cfg.post_images,
  finding_file: cfg.finding_file, finding_text: cfg.finding_text,
  oracle_files: (cfg.oracle_files || []).map((o) => path.join(repo, o)),
  tests_dirs: cfg.tests_dirs || [],
  caller_files: callers,
  anchor_func: cfg.anchor_func,
}), "utf8");

const out = { variant: cfg.name, caller_files_from: callersFrom, runs: [] };
for (const groups of groupSets) {
  const r = spawnSync(process.execPath,
    [path.join(GATES, "apigate.mjs"), litCfg, groups],
    { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  let detail = null;
  try { detail = JSON.parse(r.stdout); }
  catch { detail = { parse_failed: true, stdout_tail: (r.stdout || "").slice(-400),
                     stderr_tail: (r.stderr || "").slice(-400) }; }
  out.runs.push({ groups, exit: r.status, detail });
}
console.log(JSON.stringify(out, null, 1));
