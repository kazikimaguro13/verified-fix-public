// freeze.mjs — 凍結マニフェスト v2 (DESIGN D3) の JS 版。
//
// Python 版との最大の違い: pytest の "conftest.py 全階層 + pytest.ini" に対して
// vitest の検証文脈は **もっと広い**。実測で確定した凍結対象:
//
//   1. oracle T 本体                       (明示ハッシュ)
//   2. tests/ ツリー全体                    (add/modify/delete 検知)  ← 攻撃A1/A3/A5
//   3. vitest.config.* / vite.config.*      ← conftest.py 相当の第一。**alias 経由の
//      すり替えが可能なので pytest より攻撃力が高い**
//   4. config が指す setupFiles / globalSetup / provide  ← conftest.py 相当の第二
//   5. vitest.workspace.* / test.projects   ← プロジェクト分割で別 config を差し込む口
//   6. package.json                         ← "type"/"imports"(#subpath)/"exports"/scripts
//      **JS 固有**: package.json の `imports` マップは import 先を丸ごと差し替えられる
//   7. tsconfig.json / jsconfig.json        ← paths エイリアス。**JS/TS 固有の第二の口**
//   8. F アンカー file:function 存在        (acorn AST)
//   9. registry/ ディレクトリ                (D4 改竄防止)
//
// 3/5/6/7 は Python 版には存在しない攻撃面。ここを凍結しないと A2 相当が通る。

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parseFile } from "./parse.mjs";

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".vf", "coverage", ".vite", "dist", ".stryker-tmp",
  "reports", ".nyc_output",
]);

const CONFIG_GLOBS = [
  "vitest.config", "vite.config", "vitest.workspace", "vitest.projects",
];
const CONFIG_EXTS = [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".json"];
const ROOT_FILES = ["package.json", "tsconfig.json", "jsconfig.json", ".npmrc"];

const h = (buf) => createHash("sha256").update(buf).digest("hex");

function hashFile(p) {
  try {
    return h(fs.readFileSync(p));
  } catch {
    return "<unreadable>";
  }
}

function* walk(root) {
  if (!fs.existsSync(root)) return;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let ents;
    try {
      ents = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of ents.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (SKIP_DIRS.has(e.name)) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) stack.push(p);
      else if (e.isFile()) yield p;
    }
  }
}

// Test files are found by NAME, not by living in a directory called tests/.
// MEASURED (v17, 実クライアント（Next.js／TS の業務ポータル）): its tests are colocated as src/**/*.test.ts, so
// freezing `<repo>/tests` hashed an empty tree and reported n_tests_files: 0 --
// a freeze watching no tests at all, reported as passing.  Same shape as the
// Python side's hardcoded repo/tests (v13).
const TEST_RE = /\.(test|spec)\.(m|c)?[jt]sx?$/;

function testTreeMap(repo, testsDir) {
  const out = {};
  const root = testsDir ? path.join(repo, testsDir) : repo;
  if (!fs.existsSync(root)) return out;
  for (const p of walk(root)) {
    if (!TEST_RE.test(path.basename(p))) continue;
    out[path.relative(repo, p).split(path.sep).join("/")] = hashFile(p);
  }
  return out;
}

function treeMap(root, base) {
  const out = {};
  for (const p of walk(root)) out[path.relative(base, p).split(path.sep).join("/")] = hashFile(p);
  return out;
}

// --- vitest の設定ファイル群（任意の深さ。projects 分割にも耐える） ---
// ★v127 (decision 48): WHERE the package manifests live.
// MEASURED (v124, zod): ROOT_FILES is read from the repo ROOT only -- the
// four files package.json / tsconfig.json / jsconfig.json / .npmrc -- so in
// a monorepo packages/zod/package.json was outside the freeze.  (The
// vitest.config glob above already walks the whole tree; only these four
// were root-pinned.)
// ⛔ The default [""] joins to the repo root and keys the entry by the BARE
//   NAME, exactly as before, so an existing manifest stays byte-identical.
function findConfigs(repo, packageDirs = [""]) {
  const out = {};
  for (const p of walk(repo)) {
    const base = path.basename(p);
    const ext = path.extname(base);
    const stem = base.slice(0, base.length - ext.length);
    if (CONFIG_GLOBS.includes(stem) && CONFIG_EXTS.includes(ext)) {
      out[path.relative(repo, p).split(path.sep).join("/")] = hashFile(p);
    }
  }
  for (const dir of packageDirs) {
    for (const name of ROOT_FILES) {
      // path.join drops zero-length segments, so dir === "" is the root.
      const p = path.join(repo, dir, name);
      if (fs.existsSync(p)) out[dir ? dir + "/" + name : name] = hashFile(p);
    }
  }
  return out;
}

// --- config を実際に評価して setupFiles/globalSetup を解決する ---
// (静的にファイル名を眺めるだけでは、config が動的に返す setup を取り逃がす)
// ★v127 (decision 48): WHERE the vitest config lives, and which extensions
// count.  MEASURED (v124, zod): setup resolution looked at the repo root
// only, and only at .js / .mjs / .ts.
// ⛔ .mts and .cts are appended AFTER .ts -- putting them first would change
//   which file wins on 実クライアント -- and the dir loop is OUTERMOST with the root
//   first, so at the default [""] the same candidates are tried in the same
//   order and the same single file is picked FIRST (v132: "first" now decides
//   the key spelling and the alias, no longer where the function stops).
//
// ★v132 (decision 59 B, owner 2026-09-21): FOLLOW REFERENCES, DO NOT ADD NAMES.
// MEASURED (v131, zod): the ROOT config's `test.projects` listed
// `./vitest.compile.config.ts`.  That stem is in no CONFIG_GLOBS entry, so the
// file was outside `configs`, and ITS OWN setupFiles (scripts/enable-compile.ts)
// were in NO manifest map at all.  `freeze verify` was blind twice: to an edit
// of that config (M2: pass / 0 violations) and to a setupFile injected into it
// (M3b: pass / 0 violations, and the injected file demonstrably ran in all 190
// compile-mode files).  Two things change here:
//   (1) a config's `test.projects` STRING entries are RESOLVED, and the config
//       files they point at are returned in `added`, which buildManifest
//       appends to `configs`;
//   (2) EVERY config in `configs` -- not only the first one found -- has its
//       setupFiles / globalSetup read, resolved against ITS OWN directory.
// WHY NOT decision 59 A (add `vitest.*.config.*` to CONFIG_GLOBS): `projects`
// can name ANY file, so a list of names is broken by the next name.  The whole
// finding of this project is that enumeration breaks at the boundary; a
// reference has no boundary.  CONFIG_GLOBS is NOT touched.
//
// ⛔ THE DEFAULT IS UNCHANGED, and mechanically so:
//   - the config the OLD search would have returned on (dir, then ext, then
//     stem, first hit) is still processed FIRST, still keys its entries by the
//     string AS WRITTEN, and is still the ONLY one whose `resolve.alias` is
//     hashed into `__alias__`;
//   - every other config's entries are APPENDED after it, and configs reached
//     through `test.projects` are appended to `configs` after everything
//     findConfigs found.  NOTHING IS RE-SORTED, so a repo with one config and
//     no `test.projects` -- 実クライアント: configs {vitest.config.ts, package.json,
//     tsconfig.json}, setup {__alias__} -- rebuilds BYTE-IDENTICAL.
// ⛔ DEDUPE IS BY RESOLVED FILE, NOT BY SPELLING: (kind, absolute path).  zod's
//   root / compile / docs / resolution configs all end up listing the same
//   scripts/fail-on-console.ts (the last three inherit it through mergeConfig);
//   it is hashed ONCE, under the spelling the first config used.
// ⛔ setupFiles ARE NOW RESOLVED AGAINST THE CONFIG'S OWN DIRECTORY, which is
//   what vitest does (project root = the config's dir).  The old code resolved
//   against the REPO root.  For every manifest that exists today the two agree
//   -- the first config is at the repo root, and zod's strings are absolute.
// ⛔ A CONFIG THAT CANNOT BE IMPORTED IS RECORDED, NOT SKIPPED, as
//   `__config_load_error__:<path>`.  MEASURED (2026-09-21):
//   packages/zod/vitest.config.ts imports "../../vitest.config.js", which vite
//   resolves to the .ts file and plain node does not, so ITS setupFiles cannot
//   be read here.  An unreadable config is an UNMEASURED region, and §0-c is
//   exactly the habit of letting that read as an absent problem.
// ⛔ The cache-buster query is stripped from that message: a value carrying
//   `?t=<Date.now()>` would differ at every build and `verify` would then
//   report a MODIFIED setup entry forever.
// ⛔ INLINE (object) project entries are skipped ON PURPOSE -- their body is
//   inside the config that is already frozen.  A `vitest.workspace.*` file that
//   default-exports the project ARRAY (rather than `test.projects`) is NOT
//   followed: the workspace file itself is frozen by CONFIG_GLOBS, its entries
//   are not.  NOT MEASURED -- no repository in this harness has one.

// ★v132: the smallest glob matcher that does the job.  `test.projects` entries
// are globs like `packages/*`, and the gate must keep running from a bare node,
// so no dependency is added.  `*` / `?` do not cross a `/`; `**` matches any
// number of directories; SKIP_DIRS is honoured, so node_modules and
// .stryker-tmp cannot be walked into.
function globSegRe(seg) {
  let out = "";
  for (const ch of seg) {
    if (ch === "*") out += "[^/]*";
    else if (ch === "?") out += "[^/]";
    else out += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp("^" + out + "$");
}

function readEnts(dir) {
  try { return fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
}

function globPaths(base, pattern) {
  const segs = pattern.split("/").filter((x) => x.length && x !== ".");
  let cur = [base];
  for (const seg of segs) {
    const next = [];
    if (seg === "**") {
      const stack = [...cur], hit = new Set();
      while (stack.length) {
        const d = stack.pop();
        if (hit.has(d)) continue;
        hit.add(d); next.push(d);
        for (const e of readEnts(d))
          if (e.isDirectory() && !SKIP_DIRS.has(e.name)) stack.push(path.join(d, e.name));
      }
    } else if (seg.includes("*") || seg.includes("?")) {
      const re = globSegRe(seg);
      for (const d of cur)
        for (const e of readEnts(d))
          if (!SKIP_DIRS.has(e.name) && re.test(e.name)) next.push(path.join(d, e.name));
    } else {
      for (const d of cur) {
        const p = path.join(d, seg);
        if (fs.existsSync(p)) next.push(p);
      }
    }
    cur = [...new Set(next)];
  }
  return cur;
}

// A project DIRECTORY contributes the config file(s) inside it, found by the
// same CONFIG_GLOBS every other config is found by -- no new name is invented.
function configsInDir(dir) {
  const out = [];
  for (const e of readEnts(dir)) {
    if (!e.isFile()) continue;
    const ext = path.extname(e.name);
    const stem = e.name.slice(0, e.name.length - ext.length);
    if (CONFIG_GLOBS.includes(stem) && CONFIG_EXTS.includes(ext)) out.push(path.join(dir, e.name));
  }
  return out.sort();
}

// `test.projects` -> the config files it reaches.  `!pattern` entries exclude.
function resolveProjects(baseDir, projects) {
  const inc = [], exc = [];
  for (const entry of projects) {
    if (typeof entry !== "string") continue;
    if (entry.startsWith("!")) exc.push(entry.slice(1));
    else inc.push(entry);
  }
  const excluded = [];
  for (const e of exc) for (const p of globPaths(baseDir, e)) excluded.push(p);
  const isExcluded = (p) => excluded.some((x) => p === x || p.startsWith(x + path.sep));
  const out = [];
  for (const e of inc) {
    for (const m of globPaths(baseDir, e)) {
      if (isExcluded(m)) continue;
      let st = null;
      try { st = fs.statSync(m); } catch { continue; }
      if (st.isDirectory()) out.push(...configsInDir(m).filter((f) => !isExcluded(f)));
      else if (st.isFile()) out.push(m);
    }
  }
  return [...new Set(out)].sort();
}

const IMPORTABLE_EXTS = [".js", ".mjs", ".ts", ".mts", ".cts"];

function repoRel(repo, p) {
  const r = path.relative(repo, p);
  if (!r || r.startsWith("..") || path.isAbsolute(r)) return null;
  return r.split(path.sep).join("/");
}

async function loadConfig(p) {
  const mod = await import(pathToFileURL(p).href + "?t=" + Date.now());
  return typeof mod.default === "function" ? await mod.default({}) : mod.default;
}

// Returns BOTH maps: `setup` exactly as before, and `added` -- the config files
// reached through `test.projects`, which buildManifest appends to `configs`.
async function resolveSetupFiles(repo, configDirs = [""], configs = {}) {
  const found = {};
  const added = {};
  // The config the OLD code would have returned on.  Processed first; keeps the
  // original key spelling; the only one whose alias is hashed.
  let legacy = null;
  for (const dir of configDirs) {
    for (const ext of IMPORTABLE_EXTS) {
      for (const stem of ["vitest.config", "vite.config"]) {
        const p = path.join(repo, dir, stem + ext);
        if (fs.existsSync(p)) { legacy = p; break; }
      }
      if (legacy) break;
    }
    if (legacy) break;
  }

  const queue = [];
  if (legacy) queue.push(legacy);
  // ★v140 (decision 65 A, owner 2026-09-22): THE QUEUE IS EVERY IMPORTABLE
  // MODULE IN `configs`, not only the ones whose STEM is in CONFIG_GLOBS.
  // MEASURED (v140 probe, zod -- reports/v140_raw/zod_probe65_a.log): j64
  // (v138) put `vitest.root.mjs` into `configs` (two package configs import
  // `../../vitest.root.mjs`), so editing THAT FILE is caught.  But the file
  // also DECLARES `test.setupFiles`, and this queue never read it, because the
  // filter here was the CONFIG_GLOBS stem list.  With `./vf_probe65_setup.mjs`
  // added to that array the manifest recorded only
  //     setupFiles:packages/docs/vf_probe65_setup.mjs       = <missing>
  //     setupFiles:packages/resolution/vf_probe65_setup.mjs = <missing>
  // -- the relative string resolved against the dir of each config that MERGED
  // it -- and the real file at the repo root was in NO entry: rewriting it left
  // `freeze verify` at pass / 0 violations.  A freeze that hashes the config
  // but not what the config says to RUN is watching the letter, not the order.
  // ⛔ THE IMPORT CLOSURE IS COMPUTED HERE, not taken from buildManifest, so
  //   the KEY ORDER of `configs` does not move.  JSON.stringify preserves
  //   insertion order, so reordering it would move the md5 of EVERY manifest;
  //   buildManifest is unchanged and still appends the same two groups in the
  //   same place afterwards.  MEASURED (v138, client anchor 1 / T1): the closure
  //   is empty on that repo, so this loop queues exactly what it queued before.
  // ⛔ BEING IMPORTABLE IS NOT BEING A CONFIG.  A module with no `test`
  //   contributes NOTHING -- `cfg.test` is `{}` below, so no setupFiles, no
  //   globalSetup, no projects are read.  The cost of asking is one import.
  // ⛔ ONE THAT CANNOT BE IMPORTED keeps the `__config_load_error__:<label>`
  //   convention (§0-c): "could not be read" must not be recorded as "was not
  //   there".  That is what makes widening this queue safe to read -- a module
  //   plain node refuses becomes a RECORDED entry, not a silence.
  // ⛔ NOT followed: the relative imports of a config first reached through
  //   `test.projects` in the loop below (it is discovered after this point).
  //   Written down as a remaining edge, not left as an absence.
  const queueKeys = new Set(Object.keys(configs));
  for (const k of Object.keys(followConfigImports(repo, configs).added)) queueKeys.add(k);
  for (const k of [...queueKeys].sort()) {
    if (k.startsWith("__")) continue;
    if (IMPORTABLE_EXTS.includes(path.extname(k))) queue.push(path.join(repo, k));
  }

  const seen = new Set();
  const recorded = new Set();
  while (queue.length) {
    const p = path.resolve(queue.shift());
    if (seen.has(p) || !fs.existsSync(p)) continue;
    seen.add(p);
    const isLegacy = legacy !== null && path.resolve(legacy) === p;
    const label = isLegacy ? path.basename(p) : (repoRel(repo, p) || p);
    let cfg = null;
    try {
      cfg = await loadConfig(p);
    } catch (e) {
      found["__config_load_error__:" + label] =
        String(e).replace(/\?t=\d+/g, "").slice(0, 120);
      continue;
    }
    const t = (cfg && cfg.test) || {};
    // resolve.alias は「import 先のすり替え」なので中身も凍結対象
    if (isLegacy) {
      const alias = (cfg && cfg.resolve && cfg.resolve.alias) || t.alias || null;
      if (alias) found["__alias__"] = h(Buffer.from(JSON.stringify(alias)));
    }
    const dir = path.dirname(p);
    for (const key of ["setupFiles", "globalSetup"]) {
      const v = t[key];
      if (!v) continue;
      for (const f of Array.isArray(v) ? v : [v]) {
        if (typeof f !== "string") continue;
        const abs = path.resolve(dir, f);
        const id = key + ">" + abs;
        if (recorded.has(id)) continue;
        recorded.add(id);
        // The key keeps the string AS WRITTEN whenever that is unambiguous --
        // i.e. whenever resolving it against the repo root lands on the same
        // file, which is always true for an absolute string and for a config
        // at the repo root.  That covers every entry any existing manifest
        // holds.  A RELATIVE string in a SUBDIRECTORY config would otherwise
        // collide with the same spelling under another directory, so it is
        // keyed by the resolved repo-relative path instead.
        const spell = abs === path.resolve(repo, f) ? f : (repoRel(repo, abs) || abs);
        found[key + ":" + spell] = fs.existsSync(abs) ? hashFile(abs) : "<missing>";
      }
    }
    if (Array.isArray(t.projects)) {
      for (const f of resolveProjects(dir, t.projects)) {
        const r = repoRel(repo, f);
        if (r === null) continue;
        if (!(r in configs) && !(r in added)) added[r] = hashFile(f);
        queue.push(f);
      }
    }
  }
  return { setup: found, added };
}

// --- config が相対 import で引き込むファイルも凍結する ---
// ★v138 (decision 64 A, owner 2026-09-22): FOLLOW THE IMPORT GRAPH OF THE
// CONFIGS -- still without adding a NAME.
// MEASURED (v132 §残余 2, zod): the docs / resolution configs `import` from
// `../../vitest.root.mjs`.  That stem is in no CONFIG_GLOBS entry and no
// `test.projects` names it, so the file was in NO map at all: editing it
// changes what every project in the repo runs and `freeze verify` stays green.
// j59 closed the `test.projects` edge; this closes the `import` edge.  The two
// are the same move -- follow a REFERENCE, do not enumerate a NAME.
//
// WHAT IS READ: the SOURCE TEXT of every file already in `configs` whose
// extension is a JS/TS module one.  The modules are NOT evaluated.  loadConfig
// above already showed that plain node cannot even import some of them
// (`__config_load_error__:packages/zod/vitest.config.ts`), and a freeze that
// can only watch what it can execute watches less than an attacker can edit.
// WHAT IS FOLLOWED: only specifiers starting with `./` or `../`, in the four
// forms decision 64 names -- `import … from`, `export … from`, `import(…)`,
// `require(…)`.  A bare specifier is a package; anything landing on a
// `node_modules` segment is dropped.
// HOW IT RESOLVES: as written, then the extension swapped/appended in the
// order .ts .mts .cts .js .mjs .cjs .json, then `<spec>/index.{ts,mts,js,mjs}`.
// That order is what makes `../../vitest.config.js` land on `vitest.config.ts`
// -- what vite does and what plain node does not.
// TRANSITIVE, BOUNDED BY THE REPO: an import of an import is followed; a file
// that resolves OUTSIDE the repo is neither added nor walked (it cannot be
// keyed repo-relative, and it is outside what this manifest claims to cover).
// ⛔ AN UNRESOLVABLE RELATIVE SPECIFIER IS RECORDED, NOT SKIPPED, as
//   `__import_unresolved__:<importing file>:<spec>`, exactly the thinking of
//   `__config_load_error__` (§0-c: "could not be read" must not read as "was
//   not there").  Its value is the CONSTANT "unresolved" on purpose: a value
//   carrying an error string or a path would move with the environment and
//   `verify` would then report a MODIFIED entry that is not an edit.
// ⛔ THE DEFAULT IS UNCHANGED.  A config with no relative import returns two
//   empty maps and an empty loop inserts nothing, so such a repo rebuilds
//   BYTE-IDENTICAL.  Nothing already in `configs` is re-sorted or re-keyed;
//   the two new groups are APPENDED, each sorted among itself.
// ⛔ THIS IS A TEXT SCAN, NOT A PARSE.  A specifier inside a comment or a
//   string IS followed.  That over-freezes (one more file watched) and is
//   stable across rebuilds, which is the direction to err in.  A DYNAMIC
//   specifier (`import(someVar)`) is NOT followed and NOT recorded -- there is
//   no string to resolve.  NOT MEASURED how often either occurs.
// ⛔ A SIDE-EFFECT import with no `from` (`import "./x"`) is NOT followed:
//   decision 64 names four forms and that is not one of them.  Written down as
//   a known remaining edge, not left as an absence.
// ⛔ `verify` NEEDS NO CHANGE (read, not assumed): it rebuilds through
//   buildManifest and diffs `configs` as a map, so these entries are compared
//   like every other one.
const IMPORT_SCAN_EXTS = [".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"];
const IMPORT_RESOLVE_EXTS = [".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".json"];
const IMPORT_INDEX_EXTS = [".ts", ".mts", ".js", ".mjs"];

// The class `[\w$*{},\s]` cannot cross a quote, a semicolon or a parenthesis,
// so the lazy middle cannot run past the clause it belongs to; and `import.`
// does not match at all, because whitespace is required after the keyword.
const IMPORT_RES = [
  /\b(?:import|export)\s+(?:type\s+)?[\w$*{},\s]*?\bfrom\s*(['"])([^'"\n]+)\1/g,
  /\bimport\s*\(\s*(['"])([^'"\n]+)\1\s*\)/g,
  /\brequire\s*\(\s*(['"])([^'"\n]+)\1\s*\)/g,
];

function relImportSpecs(src) {
  const out = [];
  for (const re of IMPORT_RES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(src)) !== null) {
      const spec = m[2];
      if (spec.startsWith("./") || spec.startsWith("../")) out.push(spec);
    }
  }
  return out;
}

function resolveRelImport(fromDir, spec) {
  const base = path.resolve(fromDir, spec);
  const cands = [base];
  const ext = path.extname(base);
  if (ext) {
    const stem = base.slice(0, base.length - ext.length);
    for (const e of IMPORT_RESOLVE_EXTS) cands.push(stem + e);
  }
  for (const e of IMPORT_RESOLVE_EXTS) cands.push(base + e);
  for (const e of IMPORT_INDEX_EXTS) cands.push(path.join(base, "index" + e));
  for (const c of cands) {
    try { if (fs.statSync(c).isFile()) return c; } catch { /* next candidate */ }
  }
  return null;
}

// Returns the two groups buildManifest appends to `configs`.
function followConfigImports(repo, configs) {
  const added = {};
  const unresolved = {};
  const known = new Set();
  const queue = [];
  for (const k of Object.keys(configs)) {
    if (k.startsWith("__")) continue;
    const abs = path.resolve(repo, k);
    known.add(abs);
    if (IMPORT_SCAN_EXTS.includes(path.extname(abs))) queue.push(abs);
  }
  const seen = new Set();
  while (queue.length) {
    const p = queue.shift();
    if (seen.has(p)) continue;
    seen.add(p);
    let src = null;
    try { src = fs.readFileSync(p, "utf8"); } catch { continue; }
    const from = repoRel(repo, p) || p;
    for (const spec of relImportSpecs(src)) {
      const abs = resolveRelImport(path.dirname(p), spec);
      if (abs === null) {
        unresolved["__import_unresolved__:" + from + ":" + spec] = "unresolved";
        continue;
      }
      const r = repoRel(repo, abs);
      if (r === null) continue;                          // outside the repo
      if (r.split("/").includes("node_modules")) continue;
      if (!known.has(abs)) { known.add(abs); added[r] = hashFile(abs); }
      if (IMPORT_SCAN_EXTS.includes(path.extname(abs)) && !seen.has(abs)) queue.push(abs);
    }
  }
  return { added, unresolved };
}

// --- アンカー（file:function）が AST 上に存在するか ---
// MEASURED (v17, 実クライアント): this used to `return false` when the file failed
// to parse, which reads as "the anchor is not there" -- a finding -- when the
// truth is "nothing was read".  The parser was JavaScript-only and the
// client's source is TypeScript, so EVERY anchor in a .ts file came back
// false and
// `verify` passed anyway, because it only complains about an anchor that was
// present at build time.  A TypeScript repository would have been frozen with
// no anchor watched at all, forever, and reported green.
//
// The three outcomes are now distinct: true / "MISSING" / "UNPARSEABLE: ...".
// Only `true` is a pass; `verify` treats the other two as violations.
function anchorPresent(repo, spec) {
  const i = spec.lastIndexOf(":");
  const rel = i < 0 ? spec : spec.slice(0, i);
  const fn = i < 0 ? "" : spec.slice(i + 1);
  const f = path.join(repo, rel);
  if (!fs.existsSync(f)) return "MISSING: no such file";
  const { tree, error } = parseFile(f);
  if (error) return error;
  let hit = false;
  const visit = (n) => {
    if (!n || typeof n !== "object") return;
    if (n.type === "FunctionDeclaration" && n.id && n.id.name === fn) hit = true;
    if ((n.type === "VariableDeclarator" || n.type === "MethodDefinition" ||
         n.type === "PropertyDefinition" || n.type === "Property") &&
        n.id && n.id.name === fn) hit = true;
    for (const k of Object.keys(n)) {
      const v = n[k];
      if (Array.isArray(v)) v.forEach(visit);
      else if (v && typeof v === "object" && v.type) visit(v);
    }
  };
  visit(tree);
  return hit ? true : "MISSING: no such function in the parsed module";
}

// ★v66 (decision 1, step 2): anchor specs are frozen too.
// MEASURED (v65): copying spec_safelog.json, flipping `decides` to false and
// pointing a cfg at the copy took N10_codepoint_class from
// killed_by_all ['check4','check8'] to ['check4'] -- 検査8 stopped sweeping and
// returned a green -- and freeze reported no violation, because the spec is
// neither in the manifest nor inside the repo.  A file that can silence a hard
// gate belongs in the freeze.
// Specs are keyed by the path as given (they live OUTSIDE the repo, unlike
// every other map here), which matches how cfgs already carry absolute
// pre_images / post_images paths.
// ★v118 (decision 44): findings are frozen for the same reason specs are.
// MEASURED (v116): the finding text is one of 検査6's explanation sources
// (`pre,finding,oracle,tests,callsites`), and it was not in the manifest.
// Appending ONE sentence to it -- "実装上の既定として 69 を用いる。" -- took
// M1_hardcode's 検査6 from escalate=true with the numeric literal 69
// unexplained, to escalate=false with 69 explained BY THE FINDING.  Same patch,
// same oracle, same tests.  A file that can silence a gate belongs in the
// freeze, and run_gates3.py's own comment already claimed every 検査6 source
// was frozen.  Keyed by the path as given, like specs: findings live outside
// the repo too.
// ★v127 (decision 48): package_dirs / config_dirs are recorded IN THE
// MANIFEST, and `verify` rebuilds from what the manifest says.  The
// alternative -- passing the same flags to verify -- means every caller has
// to remember them, and a caller that forgets gets a `tree`-shaped
// disagreement rather than an error.  run_gates.mjs calls freeze verify with
// no directory flags at all, so recording it is what keeps that call site
// unchanged.
// ⛔ At the default [""] NEITHER field is written.  JSON.stringify preserves
//   insertion order and an empty spread inserts nothing, so a manifest built
//   today is byte-identical to one built before this change.
export async function buildManifest(repo, oracles, anchors, registry,
                                    testsDir, specs = [], findings = [],
                                    packageDirs = [""], configDirs = [""]) {
  // ⛔ An EMPTY array is normalised to [""].  A freeze told to search no
  //   directory at all would hash nothing and report clean, which is §0-c
  //   inside our own instrument.
  packageDirs = Array.isArray(packageDirs) && packageDirs.length ? packageDirs : [""];
  configDirs = Array.isArray(configDirs) && configDirs.length ? configDirs : [""];
  const isRootOnly = (a) => a.length === 1 && a[0] === "";
  // ★v132 (decision 59 B): the configs reached through `test.projects` are
  // APPENDED to what findConfigs found -- sorted among themselves, never
  // re-sorting what was already there.  `added` is empty for a repo with no
  // `test.projects`, and an empty loop inserts nothing, so the manifest of
  // such a repo is byte-identical to one built before this change.
  const configs = findConfigs(repo, packageDirs);
  const { setup, added } = await resolveSetupFiles(repo, configDirs, configs);
  for (const k of Object.keys(added).sort()) configs[k] = added[k];
  // ★v138 (decision 64 A): and the files those configs pull in by RELATIVE
  // import, transitively, bounded by the repo.  Appended AFTER everything
  // above, each group sorted among itself; both are empty for a config with
  // no relative import, and an empty loop inserts nothing, so such a repo
  // rebuilds byte-identical.
  const imported = followConfigImports(repo, configs);
  for (const k of Object.keys(imported.added).sort()) configs[k] = imported.added[k];
  for (const k of Object.keys(imported.unresolved).sort())
    configs[k] = imported.unresolved[k];
  return {
    repo,
    oracles: Object.fromEntries(oracles.map((o) => [o, hashFile(path.join(repo, o))])),
    configs,
    setup,
    ...(isRootOnly(packageDirs) ? {} : { package_dirs: packageDirs }),
    ...(isRootOnly(configDirs) ? {} : { config_dirs: configDirs }),
    tests_dir: testsDir || null,
    tests_tree: testTreeMap(repo, testsDir),
    anchors: Object.fromEntries(anchors.map((a) => [a, anchorPresent(repo, a)])),
    registry: registry && fs.existsSync(registry) ? treeMap(registry, registry) : {},
    specs: Object.fromEntries([...new Set(specs.filter(Boolean))]
      .map((sp) => [sp, hashFile(sp)])),
    findings: Object.fromEntries([...new Set(findings.filter(Boolean))]
      .map((f) => [f, hashFile(f)])),
  };
}

// An anchor entry that is not exactly `true` means the gate is not watching the
// thing it was told to watch.  Reported at BUILD time too, so it cannot be
// discovered only when something else goes wrong.
export function anchorViolations(m) {
  const v = [];
  // A freeze whose test tree is empty is watching nothing: the suite could be
  // rewritten wholesale and `verify` would still be green.
  if (Object.keys(m.tests_tree || {}).length === 0) {
    v.push("tests_tree: empty -- no *.test.* / *.spec.* file was found under " +
           (m.tests_dir ? m.tests_dir : "the repo root") +
           ".  Pass --tests-dir, or check the project's layout: a freeze that " +
           "hashes zero tests cannot notice the suite changing.");
  }
  for (const [a, state] of Object.entries(m.anchors || {})) {
    if (state !== true) v.push(`anchor: ${a} -> ${state}`);
  }
  return v;
}

function diffMap(oldM, newM, kind) {
  const v = [];
  for (const k of Object.keys(oldM))
    if (!(k in newM)) v.push(`${kind}: REMOVED ${k}`);
    else if (oldM[k] !== newM[k]) v.push(`${kind}: MODIFIED ${k}`);
  for (const k of Object.keys(newM)) if (!(k in oldM)) v.push(`${kind}: ADDED ${k}`);
  return v;
}

export async function verify(manifest, repo, registry, specsInUse = [],
                             findingsInUse = []) {
  // Rehash the specs the manifest recorded AND the ones this run is actually
  // using.  The first catches an edited spec; the second catches a cfg pointed
  // at a different spec file, which an edit-only check would not see.
  const specKeys = [...new Set([...Object.keys(manifest.specs || {}),
                                ...specsInUse.filter(Boolean)])];
  // Same union for findings, and for the same two reasons (edited / re-pointed).
  const findingKeys = [...new Set([...Object.keys(manifest.findings || {}),
                                   ...findingsInUse.filter(Boolean)])];
  // ★v127 (decision 48): rebuild with the directories the MANIFEST recorded,
  // not with whatever this caller happens to pass.  A manifest built before
  // this change carries neither field, so both are [""] -- unchanged.
  const cur = await buildManifest(repo, Object.keys(manifest.oracles),
    Object.keys(manifest.anchors), registry, "", specKeys, findingKeys,
    manifest.package_dirs || [""], manifest.config_dirs || [""]);
  let v = [];
  for (const kind of ["oracles", "configs", "setup", "tests_tree", "registry"])
    v = v.concat(diffMap(manifest[kind] || {}, cur[kind] || {}, kind));
  // A manifest built before specs were frozen has no `specs` key at all.  That
  // is NOT silently treated as "no specs to check" -- see specsUnfrozen() and
  // the `specs_frozen` field the CLI reports; §0-c is exactly the habit of
  // reading an absent measurement as an absent problem.
  if (manifest.specs)
    v = v.concat(diffMap(manifest.specs, cur.specs || {}, "specs"));
  // Same treatment as specs: an absent `findings` key is NOT read as "no
  // findings to check" -- findingsUnfrozen() and the CLI's findings_frozen
  // field say so out loud (§0-c).
  if (manifest.findings)
    v = v.concat(diffMap(manifest.findings, cur.findings || {}, "findings"));
  for (const [a, present] of Object.entries(manifest.anchors))
    if (present && !cur.anchors[a]) v.push(`anchor: MISSING ${a}`);
  return v;
}

// A manifest predating v66 has no `specs` key.  Runs using such a manifest are
// NOT blocked -- that would break every existing variant at once -- but the
// state is reported so it cannot pass for "checked and fine", and the round
// that introduced it rebuilt every affected manifest.
export function specsUnfrozen(manifest, specsInUse = []) {
  return !manifest.specs && specsInUse.filter(Boolean).length > 0;
}

// ★v118 (decision 44): a manifest built before findings were frozen has no
// `findings` key.  Same handling as specs -- report it rather than let an
// unchecked source read as a checked one.
export function findingsUnfrozen(manifest, findingsInUse = []) {
  return !manifest.findings && findingsInUse.filter(Boolean).length > 0;
}

// ---------------- CLI ----------------
const argv = process.argv.slice(2);
if (argv.length) {
  const cmd = argv[0];
  const get = (n, d) => {
    const i = argv.indexOf(n);
    return i >= 0 ? argv[i + 1] : d;
  };
  const many = (n) => argv.reduce((a, x, i) => (x === n ? [...a, argv[i + 1]] : a), []);
  const repo = path.resolve(get("--repo", "."));
  const mpath = path.resolve(get("--manifest", ".vf/manifest.json"));
  const registry = path.resolve(get("--registry", "registry"));
  fs.mkdirSync(path.dirname(mpath), { recursive: true });

  // ★v127 (decision 48): repeatable --package-dir / --config-dir.  None given
  // means [""] = the repo root, which is what this CLI has always searched.
  // `verify` takes NO such flag: it reads what the manifest recorded.
  // ★v129 (decision 51, owner 2026-09-20): the repo ROOT is searched WHETHER
  // OR NOT a directory flag is given.
  // MEASURED (read, freeze.mjs findConfigs): the loop visits only the dirs
  // given, so a monorepo flag silently un-froze the root; zod_rerun.sh had to
  // pass "" explicitly.
  // resolveSetupFiles above had the same shape -- its OUTERMOST loop is over
  // configDirs and it STOPPED at the first config it found -- so
  // `--config-dir packages/zod` alone left the ROOT config's setupFiles
  // unfrozen as well.
  // ★v132 (decision 59 B): that CONSEQUENCE is now false -- every config in
  //   `configs` is parsed, and findConfigs walks the whole tree from the
  //   repo root regardless of the flags.  The first-hit rule survives only
  //   as the choice of WHICH config keeps the original key spelling and
  //   writes `__alias__`.  withRoot is kept: `package_dirs` still decides
  //   where the four ROOT_FILES are read from, and that is unchanged.
  // WHY AT THE PARSE SITE, and not inside findConfigs/resolveSetupFiles:
  //   buildManifest records the list it was handed (`package_dirs` /
  //   `config_dirs`), and `verify` rebuilds from what the MANIFEST says
  //   (verify: `manifest.package_dirs || [""]`).  Normalising once here is
  //   therefore what puts "" into the manifest, so the root comes back on the
  //   verify side too -- with no flag at the verify call site and no change
  //   to any caller.  Normalising deeper would fix the build and leave the
  //   manifest still saying `["packages/zod"]`.
  // ⛔ THE DEFAULT IS UNCHANGED.  With no flag `many()` returns [], so
  //   ["", ...[]] is [""]: `pkgDirs.length ? pkgDirs : [""]` below picks the
  //   same [""], isRootOnly() in buildManifest stays true, and neither
  //   `package_dirs` nor `config_dirs` is written to the manifest.
  // ⛔ ROOT FIRST, AND ONLY ONCE.  Set preserves insertion order, so an
  //   explicit `--package-dir ""` -- which is what zod_rerun.sh passes by
  //   default -- folds into the same single "" instead of hashing the root
  //   twice, and a monorepo flag records `["", "packages/zod"]`.
  // ⛔ A CALLER CAN NO LONGER OPT OUT of the root.  That is the point, but
  //   it is also a behaviour change for anyone who was relying on
  //   `["packages/zod"]` exactly (zod_rerun.sh's VF_ZOD_INCLUDE_ROOT=0 arm
  //   asserts that string).  Such a caller now gets `["", "packages/zod"]`.
  // ⛔ NOT MEASURED: nothing in this comment comes from a run.  No claim is
  //   made here about any repository's manifest actually changing.
  const withRoot = (dirs) => [...new Set(["", ...dirs])];
  const pkgDirs = withRoot(many("--package-dir"));
  const cfgDirs = withRoot(many("--config-dir"));

  if (cmd === "build") {
    const m = await buildManifest(repo, many("--oracle"), many("--anchor"),
                                  registry, get("--tests-dir", ""),
                                  many("--spec"), many("--finding"),
                                  pkgDirs.length ? pkgDirs : [""],
                                  cfgDirs.length ? cfgDirs : [""]);
    fs.writeFileSync(mpath, JSON.stringify(m, null, 1));
    console.log(JSON.stringify({
      built: mpath,
      oracles: Object.keys(m.oracles),
      configs: Object.keys(m.configs),
      setup: Object.keys(m.setup),
      // ★v127 (decision 48): absent unless a non-default directory was given,
      // so the default build report is byte-identical.
      ...(m.package_dirs ? { package_dirs: m.package_dirs } : {}),
      ...(m.config_dirs ? { config_dirs: m.config_dirs } : {}),
      n_tests_files: Object.keys(m.tests_tree).length,
      anchors: m.anchors,
      anchor_problems: anchorViolations(m),
      n_registry_files: Object.keys(m.registry).length,
      specs: Object.keys(m.specs || {}),
      findings: Object.keys(m.findings || {}),
    }, null, 1));
    // refuse to write a manifest that watches nothing: the whole point of the
    // freeze is that the anchor cannot move unnoticed.
    process.exit(anchorViolations(m).length ? 1 : 0);
  }
  if (cmd === "verify") {
    const m = JSON.parse(fs.readFileSync(mpath, "utf8"));
    // an anchor the gate cannot see is a violation of the freeze itself, not
    // something to notice later
    const specsInUse = many("--spec");
    const findingsInUse = many("--finding");
    const v = [...anchorViolations(m),
               ...(await verify(m, repo, registry, specsInUse, findingsInUse))];
    console.log(JSON.stringify({
      pass: v.length === 0, n_violations: v.length, violations: v.slice(0, 40),
      // ★v127 (decision 48): WHAT verify rebuilt with, read off the manifest.
      // Absent for a manifest that recorded neither -- i.e. every existing one.
      ...(m.package_dirs ? { package_dirs: m.package_dirs } : {}),
      ...(m.config_dirs ? { config_dirs: m.config_dirs } : {}),
      n_specs_frozen: Object.keys(m.specs || {}).length,
      specs_in_use: specsInUse,
      specs_frozen: !specsUnfrozen(m, specsInUse),
      specs_frozen_note: specsUnfrozen(m, specsInUse)
        ? "★ this manifest predates spec freezing and the run IS using a spec: "
          + "the spec was NOT checked.  Rebuild the manifest with --spec.  Not "
          + "blocking, but not checked either -- do not read this as a pass."
        : undefined,
      n_findings_frozen: Object.keys(m.findings || {}).length,
      findings_in_use: findingsInUse,
      findings_frozen: !findingsUnfrozen(m, findingsInUse),
      findings_frozen_note: findingsUnfrozen(m, findingsInUse)
        ? "★ this manifest predates finding freezing and the run IS using a "
          + "finding: 検査6 reads that text as an explanation source and it was "
          + "NOT checked.  Rebuild the manifest with --finding."
        : undefined,
    }, null, 1));
    process.exit(v.length ? 1 : 0);
  }
  // ★v127 (decision 48): --package-dir / --config-dir are BUILD-time flags,
  // repeatable, default [""] = the repo root.  `verify` takes neither: it
  // reads what the manifest recorded, so a caller cannot forget them.
  console.error("usage: freeze.mjs build|verify --repo R --manifest M --registry G [--oracle f]* [--anchor f:fn]* [--spec path]* [--finding path]* [--package-dir d]* [--config-dir d]*");
  process.exit(2);
}
