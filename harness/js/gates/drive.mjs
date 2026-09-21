// drive.mjs — call the anchor with chosen inputs and read a verdict.
//
// The missing piece 検査5, 検査8 and 検査12 all需要 (v27).  検査5 has been
// "inapplicable" on both 実クライアント（Next.js／TS の業務ポータル） anchors because there was no way to do this.
//
// WHY IT GOES THROUGH VITEST
// --------------------------
// The anchor is TypeScript and resolves the repository's own aliases (`@/lib/...`).
// Nothing else in the harness can load that: acorn parses but does not execute,
// and node cannot import .ts.  vitest already transpiles and resolves exactly
// the way the repository's own tests do, which is also the semantics we want --
// the anchor as its own project runs it.
//
// WHERE THE PROBE LIVES (measured, not guessed)
// ---------------------------------------------
// The probe has to be somewhere vitest will run it, invisible to freeze, and
// invisible to the repository's own suite.  Three placements were measured:
//
//   .vf/probe.test.ts            vitest SKIPS it (globs ignore dot-directories)
//                                and a --config with a dot include finds nothing
//   src/**/x.test.ts             vitest runs it -- and freeze SEES it, because
//                                freeze finds tests by name anywhere in the tree
//   vf_drive/x.probe.mts + own config
//                                runs under `--config`, and is invisible to both:
//                                the name matches neither freeze's
//                                /\.(test|spec)\./ nor the app's own
//                                include (`src/**/*.test.ts`).  MEASURED:
//                                n_tests_files 81 -> 81, suite 81 -> 81.
//
// The directory is created and removed inside one call, in a finally.  A stray
// probe left in a client repository would be worse than a missing measurement.
//
// COST
// ----
// One vitest start-up is ~1s and dominates, so the probe evaluates EVERY call in
// a single run and writes them all to one file.  A driver that spawned per call
// would make 検査12 unaffordable the way 検査9 was before v25.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const DIR = "vf_drive";
const PROBE = "probe.probe.mts";
const CONFIG = "driver.config.mts";
const OUT = "out.json";

// Durations from a monotonic clock (v25).
const now = () => performance.now();

/** The probe source.  Everything it needs is baked in as JSON so there is no
 *  expression for a spec to smuggle code through (原則3). */
function probeSource(anchorImport, funcName, callsJson, harvest) {
  const NL = String.fromCharCode(10);
  return [
    `import { test } from 'vitest';`,
    `import * as fs from 'node:fs';`,
    `import * as M from '${anchorImport}';`,
    `const CALLS = ${callsJson};`,
    `const HARVEST = ${harvest ? "true" : "false"};`,
    ``,
    `// 検査12's spy.  Python uses a str subclass; JS strings are primitives, so`,
    `// the comparison METHODS are patched instead, and only while the anchor is`,
    `// running, so unrelated code does not pollute the harvest.`,
    `const METHODS = ['startsWith', 'endsWith', 'includes', 'indexOf',`,
    `                 'lastIndexOf', 'localeCompare', 'split', 'search'];`,
    `const harvested = new Set();`,
    `let inAnchor = false;`,
    `const originals = {};`,
    `if (HARVEST) {`,
    `  for (const m of METHODS) {`,
    `    const orig = String.prototype[m];`,
    `    if (typeof orig !== 'function') continue;`,
    `    originals[m] = orig;`,
    `    Object.defineProperty(String.prototype, m, {`,
    `      configurable: true, writable: true,`,
    `      value: function (...a) {`,
    `        if (inAnchor) for (const x of a)`,
    `          if (typeof x === 'string' && x.length > 0 && x.length <= 64) harvested.add(x);`,
    `        return orig.apply(this, a);`,
    `      },`,
    `    });`,
    `  }`,
    `}`,
    ``,
    `function safe(v) {`,
    `  if (v === undefined) return { __undef: true };`,
    `  try { JSON.stringify(v); return v; } catch { return { __unserialisable: String(v) }; }`,
    `}`,
    ``,
    `test('vf drive', async () => {`,
    `  const out = [];`,
    `  for (const c of CALLS) {`,
    `    const cap = [];`,
    `    const w = console.warn, l = console.log, e = console.error;`,
    `    const grab = (...a) => { cap.push(a.map((x) => typeof x === 'string' ? x : String(x)).join(' ')); };`,
    `    console.warn = grab; console.log = grab; console.error = grab;`,
    `    let ok = true, res, exc = null;`,
    `    inAnchor = true;`,
    `    try { res = await M['${funcName}'](...c.args); }`,
    `    catch (x) { ok = false; exc = (x && x.constructor && x.constructor.name) || 'Error'; }`,
    `    finally { inAnchor = false; console.warn = w; console.log = l; console.error = e; }`,
    `    out.push({ id: c.id, ok, exc, res: safe(res), emitted: cap });`,
    `  }`,
    `  fs.writeFileSync(new URL('./${OUT}', import.meta.url),`,
    `    JSON.stringify({ observations: out, harvested: [...harvested] }), 'utf8');`,
    `});`,
  ].join(NL) + NL;
}

function configSource() {
  const NL = String.fromCharCode(10);
  return [
    `import { defineConfig, mergeConfig } from 'vitest/config';`,
    `import { resolve } from 'node:path';`,
    `import { fileURLToPath } from 'node:url';`,
    `const here = fileURLToPath(new URL('.', import.meta.url));`,
    `const app = resolve(here, '..');`,
    `// Reuse the app's own config so aliases and transforms match what its own`,
    `// tests get; override only where the probe has to differ.`,
    `let base = {};`,
    `try { base = (await import(resolve(app, 'vitest.config.ts'))).default; } catch {}`,
    `export default mergeConfig(base, defineConfig({`,
    `  test: { environment: 'node', root: app, include: ['${DIR}/*.probe.mts'] },`,
    `  resolve: { alias: { '@': resolve(app, 'src') } },`,
    `}));`,
  ].join(NL) + NL;
}

// --------------------------------------------------------------------------- //
// SWEEP MODE (v29) -- 検査8 needs 1,114,112 calls per template.
//
// WHY THIS IS NOT JUST `drive(repo, ..., calls)`
// ----------------------------------------------
// The normal path embeds the calls as JSON in the probe.  mrgate.py sweeps the
// whole code-point axis, so three templates is 3.3M calls; as JSON that probe
// would be hundreds of megabytes.  Python can do this in-process and does.
// So the LOOP MOVES INTO THE PROBE: it is handed a template, a projection NAME
// and a range, and returns only the divergences (capped) plus counts.
//
// THE PROJECTION IS IMPORTED, NOT COPIED
// --------------------------------------
// The probe needs project() to reduce each call to a verdict.  Re-implementing
// it here would put the same enum in two places, and v19 measured what that
// costs: a fix that did not travel to the port shipped broken for six rounds.
// So the probe imports anchorspec.mjs by a relative path.  If vitest refuses to
// resolve it the gate reports that it could not run -- it does not fall back to
// a private copy.
// --------------------------------------------------------------------------- //
function sweepProbeSource(o) {
  const NL = String.fromCharCode(10);
  return [
    `import { test } from 'vitest';`,
    `import * as fs from 'node:fs';`,
    `import * as M from '${o.anchorImport}';`,
    // v30: the PRE image is imported ALONGSIDE the post one so the precondition
    // and the sweep share a single vitest start-up.  v29 paid ~23s of start-up
    // for the precondition alone -- about 45% of the gate's cost -- because it
    // installed pre, ran, restored, installed post, ran again.
    o.preImport ? `import * as PRE from '${o.preImport}';`
                : `const PRE = null;`,
    `import { project, HOLE } from '${o.specImport}';`,
    `const TEMPLATES = ${o.templatesJson};`,
    `const REFCALLS = ${o.refCallsJson};`,
    `const PROJECTION = ${JSON.stringify(o.projection)};`,
    `const SKIP = new Set(${o.skipJson});`,
    `const MAX_CP = ${o.maxCp};`,
    `const PRECOND_MAX_CP = ${o.precondMaxCp};`,
    `const CAP = ${o.cap};`,
    // v32: multi-character candidates.  The code-point sweep is exhaustive on
    // ONE character and therefore cannot reach a key that needs two at once --
    // measured, twice: N9 (a derived 'ce' prefix) and N11 (a two-class regex)
    // both walk through `fast`.  These come from generators that read what the
    // PATCH ITSELF introduced, so they stack onto the same relation (D18).
    `const CANDIDATES = ${o.candidatesJson};`,
    ``,
    `// anchorspec's fill(), by value.  Kept here because it is three lines of`,
    `// structural recursion with no policy in it; project() is the part that`,
    `// carries meaning and that one is imported.`,
    `function fill(x, ch) {`,
    `  if (typeof x === 'string') return x.split(HOLE).join(ch);`,
    `  if (Array.isArray(x)) return x.map((y) => fill(y, ch));`,
    `  if (x && typeof x === 'object') {`,
    `    const o = {};`,
    `    for (const k of Object.keys(x)) o[fill(k, ch)] = fill(x[k], ch);`,
    `    return o;`,
    `  }`,
    `  return x;`,
    `}`,
    ``,
    `const W = console.warn, L = console.log, E = console.error;`,
    `let cap_ = [];`,
    `const grab = (...a) => {`,
    `  cap_.push(a.map((x) => typeof x === 'string' ? x : String(x)).join(' '));`,
    `};`,
    ``,
    `async function verdict(mod, args) {`,
    `  cap_ = [];`,
    `  console.warn = grab; console.log = grab; console.error = grab;`,
    `  let ok = true, res, exc = null;`,
    `  inAnchor = true;`,
    `  try {`,
    `    res = mod['${o.funcName}'](...args);`,
    `    // only pay for a microtask when the anchor actually returns a thenable`,
    `    if (res && typeof res.then === 'function') res = await res;`,
    `  } catch (x) { ok = false; exc = (x && x.constructor && x.constructor.name) || 'Error'; }`,
    `  finally { inAnchor = false; console.warn = W; console.log = L; console.error = E; }`,
    `  return project(PROJECTION, { ok, exc, res, emitted: cap_ }, { args });`,
    `}`,
    ``,
    // ---- G2: the spy (検査12's harvester, riding along) ------------------ //
    // Patched only while the BASELINE and REFERENCE calls run, then removed:`,
    // the 3.3M-call sweep must not pay for a wrapper on every comparison, and`,
    // it would learn nothing new anyway -- the operands an anchor compares are`,
    // fixed by its code, not by which character we handed it.`,
    `const METHODS = ['startsWith', 'endsWith', 'includes', 'indexOf',`,
    `                 'lastIndexOf', 'localeCompare', 'split', 'search'];`,
    `const harvested = new Set();`,
    `const originals = {};`,
    `// MEASURED (v32): without this guard the spy harvested '{C}' -- the`,
    `// HOLE marker -- because fill() uses String.prototype.split, which is`,
    `// one of the patched methods.  The instrument was observing itself.`,
    `// Harmless (a wasted candidate) but it is exactly the shape of thing`,
    `// this project refuses to leave in.  spygate.mjs has had this guard`,
    `// since v28; it did not travel with the port (v19's lesson, again).`,
    `let inAnchor = false;`,
    `function spyOn() {`,
    `  for (const m of METHODS) {`,
    `    const orig = String.prototype[m];`,
    `    if (typeof orig !== 'function') continue;`,
    `    originals[m] = orig;`,
    `    Object.defineProperty(String.prototype, m, {`,
    `      configurable: true, writable: true,`,
    `      value: function (...a) {`,
    `        if (inAnchor) for (const x of a)`,
    `          if (typeof x === 'string' && x.length > 0 && x.length <= 64) harvested.add(x);`,
    `        return orig.apply(this, a);`,
    `      },`,
    `    });`,
    `  }`,
    `}`,
    `function spyOff() {`,
    `  for (const m of Object.keys(originals))`,
    `    Object.defineProperty(String.prototype, m, {`,
    `      configurable: true, writable: true, value: originals[m] });`,
    `}`,
    ``,
    `async function sweepOne(mod, t, maxCp) {`,
    `  const t0 = performance.now();`,
    `  const base = await verdict(mod, fill(t.args, t.baseline_fill));`,
    `  const bk = JSON.stringify(base);`,
    `  const bad = [];`,
    `  let n = 0, truncated = false;`,
    `  for (let cp = 0; cp < maxCp; cp++) {`,
    `    if (SKIP.has(cp)) continue;`,
    `    n++;`,
    `    const v = await verdict(mod, fill(t.args, String.fromCodePoint(cp)));`,
    `    if (JSON.stringify(v) !== bk) {`,
    `      bad.push({ cp, verdict: v });`,
    `      if (bad.length > CAP) { truncated = true; break; }`,
    `    }`,
    `  }`,
    `  return { id: t.id, baseline_verdict: base, n_divergent: bad.length,`,
    `           divergent: bad.slice(0, 8), cp_tried: n, truncated,`,
    `           secs: +((performance.now() - t0) / 1000).toFixed(2) };`,
    `}`,
    ``,
    `test('vf sweep', async () => {`,
    `  // 1. PRECONDITION on the unpatched anchor, over a cheap prefix.  Same`,
    `  //    order as mrgate.py: a relation that is false for an anchor is false`,
    `  //    near the start, and a template already violated here ABSTAINS -- so`,
    `  //    it must not be swept on the post image either (that is what keeps`,
    `  //    folding the two runs together from costing more than it saves).`,
    `  spyOn();`,
    `  const pre = [];`,
    `  if (PRE) for (const t of TEMPLATES) pre.push(await sweepOne(PRE, t, PRECOND_MAX_CP));`,
    `  const abstained = new Set(pre.filter((p) => p.n_divergent > 0).map((p) => p.id));`,
    ``,
    `  // 2. The ACCEPTED reference, on the post image, in the same run.  Without`,
    `  //    it "the verdict moved" cannot be split into the direction that is a`,
    `  //    violation and the direction that is a legitimate narrowing (v12).`,
    `  const refs = [];`,
    `  for (const c of REFCALLS) refs.push({ id: c.id, verdict: await verdict(M, c.args) });`,
    ``,
    `  // 3. The multi-character candidate pass, BEFORE the big sweep so that a`,
    `  //    two-character key is reported even if the sweep is later truncated.`,
    `  //    Baselines are taken per template with the spy still on.`,
    `  const baseOf = {};`,
    `  for (const t of TEMPLATES)`,
    `    baseOf[t.id] = JSON.stringify(await verdict(M, fill(t.args, t.baseline_fill)));`,
    `  spyOff();`,
    `  const cands = [...new Set([...CANDIDATES, ...harvested])]`,
    `    .filter((c) => c.length > 0 && c.length <= 64);`,
    `  const candHits = [];`,
    `  for (const t of TEMPLATES) {`,
    `    if (abstained.has(t.id)) continue;`,
    `    for (const c of cands) {`,
    `      const v = await verdict(M, fill(t.args, c));`,
    `      if (JSON.stringify(v) !== baseOf[t.id])`,
    `        candHits.push({ template: t.id, candidate: c, verdict: v });`,
    `    }`,
    `  }`,
    ``,
    `  // 4. The sweep proper, on the post image, over the whole axis.`,
    `  const out = [];`,
    `  for (const t of TEMPLATES)`,
    `    if (!abstained.has(t.id)) out.push(await sweepOne(M, t, MAX_CP));`,
    ``,
    `  fs.writeFileSync(new URL('./${OUT}', import.meta.url),`,
    `    JSON.stringify({ sweeps: out, refs, pre_sweeps: pre,`,
    `                     candidate_hits: candHits,`,
    `                     n_candidates: cands.length,`,
    `                     harvested: [...harvested].slice(0, 32),`,
    `                     n_harvested: harvested.size }), 'utf8');`,
    `});`,
  ].join(NL) + NL;
}

/**
 * Sweep the code-point axis for each template against the anchor in `repo`.
 *
 * templates: [{ id, args, baseline_fill }]   (args contain anchorspec's HOLE)
 * returns { ok, sweeps: [{id, baseline_verdict, n_divergent, divergent,
 *                         cp_tried, truncated, secs}], secs }
 * On failure { ok:false, why } -- never a silent empty result.
 */
export function sweepAxis(repo, anchorFile, funcName, templates,
                          { projection, refCalls = [], skipCodepoints = [],
                            maxCp = 0x110000, precondMaxCp = 0x800,
                            preImage = null, candidates = [],
                            cap = 200, gatesDir } = {}) {
  const t0 = now();
  const dir = path.join(repo, DIR);
  const relOf = (abs) => {
    const r = path.relative(dir, abs).split(path.sep).join("/")
      .replace(/\.[cm]?tsx?$/, "");
    return r.startsWith(".") ? r : "./" + r;
  };
  const importPath = relOf(path.join(repo, anchorFile));
  const here = gatesDir || path.dirname(new URL(import.meta.url).pathname);
  const specRel = path.relative(dir, path.join(here, "anchorspec.mjs"))
    .split(path.sep).join("/");
  const specImport = specRel.startsWith(".") ? specRel : "./" + specRel;

  // The PRE copy goes BESIDE THE ANCHOR, not into vf_drive.  An anchor that
  // imports `./db` has to keep resolving it, and moving the file would break
  // that -- this anchor happens to import nothing, but "works here" and "works"
  // are different claims.  The name matches neither freeze's /\.(test|spec)\./
  // nor the app's own include, and it is removed in the finally below: leaving
  // a file in a client repository is worse than losing a measurement (v28).
  let preAbs = null, preImport = null;
  if (preImage) {
    const ext = path.extname(anchorFile);
    preAbs = path.join(repo, anchorFile.slice(0, -ext.length) + ".vfpre" + ext);
    preImport = relOf(preAbs);
  }
  try {
    fs.mkdirSync(dir, { recursive: true });
    if (preAbs) fs.copyFileSync(preImage, preAbs);
    fs.writeFileSync(path.join(dir, PROBE), sweepProbeSource({
      anchorImport: importPath, preImport, specImport, funcName,
      templatesJson: JSON.stringify(templates),
      refCallsJson: JSON.stringify(refCalls),
      projection, skipJson: JSON.stringify(skipCodepoints),
      maxCp, precondMaxCp, cap,
      candidatesJson: JSON.stringify(candidates),
    }), "utf8");
    fs.writeFileSync(path.join(dir, CONFIG), configSource(), "utf8");
    const r = spawnSync(process.execPath,
      [path.join(repo, "node_modules/vitest/vitest.mjs"), "run",
       "--config", `${DIR}/${CONFIG}`],
      { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    let parsed = null;
    try { parsed = JSON.parse(fs.readFileSync(path.join(dir, OUT), "utf8")); } catch { /* below */ }
    if (!parsed)
      return {
        ok: false,
        why: "the sweep probe produced no result file (exit " + r.status + ")",
        stderr_tail: String(r.stderr || "").split("\n").slice(-12).join("\n"),
        stdout_tail: String(r.stdout || "").split("\n").slice(-12).join("\n"),
        secs: +((now() - t0) / 1000).toFixed(2),
      };
    return { ok: true, sweeps: parsed.sweeps, refs: parsed.refs || [],
             pre_sweeps: parsed.pre_sweeps || [],
             candidate_hits: parsed.candidate_hits || [],
             n_candidates: parsed.n_candidates || 0,
             harvested: parsed.harvested || [],
             n_harvested: parsed.n_harvested || 0,
             secs: +((now() - t0) / 1000).toFixed(2) };
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* noop */ }
    // not conditional on success, and separate from the directory above,
    // because this one lives inside the client's own source tree
    if (preAbs) { try { fs.rmSync(preAbs, { force: true }); } catch { /* noop */ } }
  }
}

// --------------------------------------------------------------------------- //
// DIFF MODE (v44) -- 検査5 needs the SAME input run against BOTH images.
//
// WHY IT IS NOT TWO CALLS TO drive()
// ----------------------------------
// D2's rule is stated per input: "did the PRE run touch the anchor".  Two
// separate vitest start-ups would pay ~1s twice AND would have to carry the
// touch flag across processes.  sweepAxis already proved the shape that works
// (v30): copy the PRE image BESIDE the anchor and import both in one probe.
// This reuses it.
//
// THE TOUCH FLAG IS INJECTED BY THE CALLER
// ----------------------------------------
// diffgate.mjs owns instrumentAnchor(); it hands this function an ALREADY
// instrumented PRE image.  Putting the AST transform here would give drive.mjs
// a second reason to parse, and diffgate is where the D2 rule lives.
//
// WHAT IS NOT COMPARED HERE
// -------------------------
// Nothing.  This function returns the raw pair for every call and does not
// decide anything; the classification (out-of-scope / in-scope / type) is the
// gate's, so the pass condition stays in one file.
// --------------------------------------------------------------------------- //
function diffProbeSource(o) {
  const NL = String.fromCharCode(10);
  return [
    `import { test } from 'vitest';`,
    `import * as fs from 'node:fs';`,
    `import * as POST from '${o.postImport}';`,
    `import * as PRE from '${o.preImport}';`,
    `const CALLS = ${o.callsJson};`,
    `const FN = ${JSON.stringify(o.drivenExport)};`,
    ``,
    `// The PRE image carries an injected 'globalThis.__VF_TOUCH.hit = true' at`,
    `// the top of the anchor's body.  It must exist before the first call.`,
    `globalThis.__VF_TOUCH = { hit: false };`,
    ``,
    `// Byte-for-byte the rule diffgate.mjs's callSafe() uses, so the two paths`,
    `// through the gate compare the same thing (v19: a fix that did not travel`,
    `// to the second implementation shipped broken for six rounds).`,
    `function shape(ok, res, exc) {`,
    `  if (!ok) return { t: 'throw:' + exc.name,`,
    `                    v: 'exc:' + exc.name + ':' + String(exc.message).slice(0, 60) };`,
    `  let s;`,
    `  try { s = JSON.stringify(res); } catch { s = 'UNSERIALISABLE:' + String(res); }`,
    `  return { t: res === null ? 'null' : Array.isArray(res) ? 'array' : typeof res,`,
    `           v: 'ok:' + s };`,
    `}`,
    ``,
    `async function one(mod, args) {`,
    `  const cap = [];`,
    `  const w = console.warn, l = console.log, e = console.error;`,
    `  const grab = (...a) => {`,
    `    cap.push(a.map((x) => typeof x === 'string' ? x : String(x)).join(' '));`,
    `  };`,
    `  console.warn = grab; console.log = grab; console.error = grab;`,
    `  let ok = true, res, exc = null;`,
    `  try {`,
    `    res = mod[FN](...args);`,
    `    if (res && typeof res.then === 'function') res = await res;`,
    `  } catch (x) {`,
    `    ok = false;`,
    `    exc = { name: (x && x.name) || 'Error', message: (x && x.message) || String(x) };`,
    `  } finally { console.warn = w; console.log = l; console.error = e; }`,
    `  const sh = shape(ok, res, exc);`,
    `  return { t: sh.t, v: sh.v, emitted: cap };`,
    `}`,
    ``,
    `test('vf diff', async () => {`,
    `  const missing = [];`,
    `  if (typeof PRE[FN] !== 'function') missing.push('pre');`,
    `  if (typeof POST[FN] !== 'function') missing.push('post');`,
    `  const pairs = [];`,
    `  if (missing.length === 0) {`,
    `    for (const c of CALLS) {`,
    `      globalThis.__VF_TOUCH.hit = false;`,
    `      const a = await one(PRE, c.args);`,
    `      const touched = globalThis.__VF_TOUCH.hit === true;`,
    `      const b = await one(POST, c.args);`,
    `      pairs.push({ id: c.id, args_repr: JSON.stringify(c.args).slice(0, 160),`,
    `                   touched, pre: a, post: b });`,
    `    }`,
    `  }`,
    `  fs.writeFileSync(new URL('./${OUT}', import.meta.url),`,
    `    JSON.stringify({ pairs, missing_export: missing,`,
    `                     exports_seen: Object.keys(POST).slice(0, 40) }), 'utf8');`,
    `});`,
  ].join(NL) + NL;
}

/**
 * Run every call in `calls` against BOTH images of `anchorFile`, in one vitest.
 *
 * preImage: an absolute path to the PRE source, ALREADY instrumented with the
 *           touch flag by the caller (diffgate.mjs).
 * drivenExport: the exported name to call.  It is not always the anchor: an
 *           anchor can be module-private (実クライアントの fetchAccessToken is), and a
 *           probe can only import what the module exports.  The spec names it;
 *           it is a NAME, not an expression, so 原則3 still holds.
 *
 * returns { ok, pairs:[{id, args_repr, touched, pre:{t,v,emitted},
 *                       post:{t,v,emitted}}], missing_export:[...], secs }
 * On failure { ok:false, why } -- never a silent empty result.
 */
export function driveDiff(repo, anchorFile, calls,
                          { preImage, drivenExport } = {}) {
  const t0 = now();
  const dir = path.join(repo, DIR);
  const relOf = (abs) => {
    const r = path.relative(dir, abs).split(path.sep).join("/")
      .replace(/\.[cm]?tsx?$/, "");
    return r.startsWith(".") ? r : "./" + r;
  };
  const postImport = relOf(path.join(repo, anchorFile));
  const ext = path.extname(anchorFile);
  // Beside the anchor, for sweepAxis's reason: an anchor that imports './db'
  // has to keep resolving it.  Removed in the finally.
  const preAbs = path.join(repo, anchorFile.slice(0, -ext.length) + ".vfpre" + ext);
  const preImport = relOf(preAbs);
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.copyFileSync(preImage, preAbs);
    fs.writeFileSync(path.join(dir, PROBE), diffProbeSource({
      postImport, preImport, drivenExport,
      callsJson: JSON.stringify(calls),
    }), "utf8");
    fs.writeFileSync(path.join(dir, CONFIG), configSource(), "utf8");
    const r = spawnSync(process.execPath,
      [path.join(repo, "node_modules/vitest/vitest.mjs"), "run",
       "--config", `${DIR}/${CONFIG}`],
      { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    let parsed = null;
    try { parsed = JSON.parse(fs.readFileSync(path.join(dir, OUT), "utf8")); } catch { /* below */ }
    if (!parsed)
      return {
        ok: false,
        why: "the diff probe produced no result file (exit " + r.status + ")",
        stderr_tail: String(r.stderr || "").split("\n").slice(-12).join("\n"),
        stdout_tail: String(r.stdout || "").split("\n").slice(-12).join("\n"),
        secs: +((now() - t0) / 1000).toFixed(2),
      };
    return { ok: true, pairs: parsed.pairs || [],
             missing_export: parsed.missing_export || [],
             exports_seen: parsed.exports_seen || [],
             n_calls: calls.length,
             secs: +((now() - t0) / 1000).toFixed(2) };
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* noop */ }
    try { fs.rmSync(preAbs, { force: true }); } catch { /* noop */ }
  }
}

/**
 * Run `calls` against the anchor in `repo`.
 *
 * calls: [{ id, args:[...] }]
 * returns { ok, observations:[{id, ok, exc, res, emitted}], harvested:[...], secs }
 * On failure returns { ok:false, why } -- never a silent empty result, because a
 * driver that cannot run and an anchor that decided nothing must not look alike.
 */
export function drive(repo, anchorFile, funcName, calls, { harvest = false } = {}) {
  const t0 = now();
  const dir = path.join(repo, DIR);
  const rel = path.relative(dir, path.join(repo, anchorFile))
    .split(path.sep).join("/").replace(/\.[cm]?tsx?$/, "");
  const importPath = rel.startsWith(".") ? rel : "./" + rel;
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, PROBE),
      probeSource(importPath, funcName, JSON.stringify(calls), harvest), "utf8");
    fs.writeFileSync(path.join(dir, CONFIG), configSource(), "utf8");
    const r = spawnSync(process.execPath,
      [path.join(repo, "node_modules/vitest/vitest.mjs"), "run",
       "--config", `${DIR}/${CONFIG}`],
      { cwd: repo, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    let parsed = null;
    try { parsed = JSON.parse(fs.readFileSync(path.join(dir, OUT), "utf8")); } catch { /* below */ }
    if (!parsed) {
      return {
        ok: false,
        why: "the probe produced no result file (exit " + r.status + ")",
        stderr_tail: String(r.stderr || "").split("\n").slice(-12).join("\n"),
        stdout_tail: String(r.stdout || "").split("\n").slice(-12).join("\n"),
        secs: +((now() - t0) / 1000).toFixed(2),
      };
    }
    return {
      ok: true,
      observations: parsed.observations,
      harvested: parsed.harvested || [],
      n_calls: calls.length,
      secs: +((now() - t0) / 1000).toFixed(2),
    };
  } finally {
    // A stray probe left behind in a repository would be worse than a missing
    // measurement, so this is not conditional on success.
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* noop */ }
  }
}
