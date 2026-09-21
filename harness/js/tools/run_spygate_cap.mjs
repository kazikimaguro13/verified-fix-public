// run_spygate_cap.mjs — 検査12 を候補上限を変えて単独に回す（v43・§12-A1c）
//
// なぜ要るか
// ----------
// 検査12 の候補は「スパイの収穫 ∪ post イメージの文字列リテラル」で、
// **1ラウンドあたり `max_candidates`（既定24）で打ち切られる**（spygate.mjs:200）。
// `coverage_note` に `CAP-TRUNCATED` は出しているが、**尾に何も無いことは測っていない。**
// パイプラインを strict で回すと160秒かかる。**検査12 単独なら約50秒。**
//
// ★§0-c: 「尾に何も無かった」と「尾を測っていない」は別。
//   この道具は **何番目まで試したかを必ず件数で出す**。
//
// usage:
//   node run_spygate_cap.mjs <orch2 の cfg.json> <cap> [rounds]
//
// 出力の `tail_candidates` は「25番目以降に実際に何が居たか」。
// ⚠ その一覧は **spygate の `literals()` と同じ歩き方をこのファイルが写したもの**で、
//   本体の出力ではない。**件数を spygate 自身の `n_consts` と突き合わせて検算する**
//   （合わなければ `const_list_matches_gate: false` を出し、順位の主張はしない）。

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
// ★v134 (judgement 61): the gates live OUTSIDE this checkout, so the path
// has to be resolved -- which a static import specifier cannot do.  The
// module loaded is exactly the one the old literal named.
import { pathToFileURL } from "node:url";
import { JS_GATES_DIR } from "./vf_paths.mjs";
const { parseSource } =
  await import(pathToFileURL(path.join(JS_GATES_DIR, "parse.mjs")).href);

const GATES = JS_GATES_DIR;
const cfgPath = process.argv[2];
const cap = Number(process.argv[3] || 24);
const rounds = Number(process.argv[4] || 3);
if (!cfgPath) { console.error("usage: run_spygate_cap.mjs <cfg.json> <cap> [rounds]"); process.exit(2); }

const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const repo = cfg.repo;

// ---- spygate の cfg（run_gates.mjs:419-427 と同じ形） ---------------------- //
const spyCfg = path.join(repo, ".vf/spygate_cap.cfg.json");
fs.mkdirSync(path.dirname(spyCfg), { recursive: true });
fs.writeFileSync(spyCfg, JSON.stringify({
  repo, anchor_file: cfg.anchor_file, anchor_func: cfg.anchor_func,
  spec: JSON.parse(fs.readFileSync(cfg.anchor_spec, "utf8")),
  spec_source: cfg.anchor_spec,
  pre_images: cfg.pre_images, post_images: cfg.post_images,
  max_rounds: rounds,
  max_candidates: cap,
}), "utf8");

// ---- spygate.mjs の literals() の写し（順序も含めて同じ歩き方） ------------ //
const SKIP_KEYS = new Set(["type", "start", "end", "loc", "range", "parent"]);
function literalsInOrder(src) {
  const out = [];
  const have = new Set();
  const tree = parseSource(src);
  const seen = new Set();
  const add = (v) => { if (v && v.length > 0 && v.length <= 64 && !have.has(v)) { have.add(v); out.push(v); } };
  const walk = (n) => {
    if (!n || typeof n !== "object") return;
    if (Array.isArray(n)) { for (const x of n) walk(x); return; }
    if (typeof n.type !== "string" || seen.has(n)) return;
    seen.add(n);
    if (n.type === "Literal" && typeof n.value === "string") add(n.value);
    if (n.type === "TemplateLiteral")
      for (const q of n.quasis || []) add(q.value && q.value.cooked);
    for (const k of Object.keys(n)) { if (!SKIP_KEYS.has(k)) walk(n[k]); }
  };
  walk(tree);
  return out;
}

const postImage = Object.values(cfg.post_images || {})[0];
let consts = [];
let constErr = null;
try { consts = literalsInOrder(fs.readFileSync(postImage, "utf8")); }
catch (e) { constErr = String(e.message).slice(0, 200); }

// ---- 走らせる -------------------------------------------------------------- //
const t0 = Date.now();
const r = spawnSync(process.execPath, [path.join(GATES, "spygate.mjs"), spyCfg],
                    { cwd: repo, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
const wall = (Date.now() - t0) / 1000;
let detail = null;
try { detail = JSON.parse(r.stdout); }
catch { detail = { parse_failed: true, stdout_tail: (r.stdout || "").slice(-600),
                   stderr_tail: (r.stderr || "").slice(-600) }; }

const nConstsGate = detail && detail.n_consts;
const matches = constErr === null && nConstsGate === consts.length;

console.log(JSON.stringify({
  variant: cfg.name,
  post_image: postImage,
  cap_requested: cap,
  rounds_requested: rounds,
  exit: r.status,
  wall_s: +wall.toFixed(2),
  // ★件数を必ず出す（§0-c）
  n_consts_gate: nConstsGate,
  n_consts_local: constErr === null ? consts.length : null,
  const_list_matches_gate: matches,
  const_list_error: constErr,
  n_candidates_tried: detail && detail.n_candidates_tried,
  coverage_note: detail && detail.coverage_note,
  head_candidates_1_24: matches ? consts.slice(0, 24) : null,
  tail_candidates_25_plus: matches ? consts.slice(24) : null,
  n_tail: matches ? Math.max(0, consts.length - 24) : null,
  gate: detail,
}, null, 1));
