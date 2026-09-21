// run_gates.mjs — JS/TS 側のゲート・オーケストレータ。run_gates3.py の対応物。
//
// なぜこれが要るか (v19/v20 の実測が動機)
// ----------------------------------------
// JS のゲートは6本になったが (freeze / 検査2 / 検査3 / 検査4 / 検査5 / 検査6)、
// 全部手で呼んでいた。その結果:
//   * D20 の CONTRADICTION 判定が JS 側でできない。fp_to_oracle.py が読むのは
//     Python の results 形だけで、必要なのは4つ (検査1/2/3 の可否と、R4/R5 で
//     新たに赤くなったテスト名) しかないのに、集約する場所が無かった。
//   * compare_runs.py も効かない。「ゲートが黙った」ことは要約では見えない (v14)。
//   * 同じ作業ツリーに2つの実験を同時に走らせて1行汚染した (v19 の罠)。
//
// **出力の形は Python 側と1対1にする。** そうすれば fp_to_oracle.py と
// compare_runs.py がそのまま JS の結果にも効く。書くもの:
//   <out>/<name>.json        gates / check1_oracle_fails_on_bug / check2_by_oracle
//                            / check4 / check5 / check6 / suite_regression / killed_by
//   <out>/<name>.img/cfg.json  pre_images と post_images (fp_to_oracle が引用元にする)
//
// 既定プロファイルは **strict**。Python 側の既定は fast だが、その根拠 (D15) は
// **12ラウンド強化した T** で測ったもので、v19 が実案件の初版 T では検査4 の
// 固有撃墜が 2/4 だと実測した。JS 側にはまだ検査8〜12 が無く T も初版なので、
// ここで検査4 を切る根拠が無い。
//
// usage:
//   run_gates.mjs <cfg.json> [--profile fast|strict] [--out DIR]
//                 [--check4-in-fast] [--no-check8-in-fast]
//   run_gates.mjs <cfg.json> --build-baseline      # PRE ツリーで per-test 結果を凍結

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import { scratchPath } from "./scratch.mjs";

// Durations and deadlines come from a MONOTONIC clock.  MEASURED (v25):
// with Date.now() a gate reported -1.39 seconds, which is not a fast gate,
// it is a wall clock that moved backwards.  performance.now() cannot.
const now = () => performance.now();

const HERE = path.dirname(new URL(import.meta.url).pathname);
// ★v113 (decision 35): bump this whenever the shape of a baseline's
// `passing` entries changes.  R5 refuses a baseline that does not
// declare the same value, so a stale one stops the run instead of
// silently matching nothing.
const KEY_FORMAT = "file::fullName";

const ESCALATE_ONLY = new Set(["check6", "check7"]);

// --------------------------------------------------------------------------- //
// helpers
// --------------------------------------------------------------------------- //
function readJson(p, dflt = null) {
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return dflt; }
}

// ★v117 (decision 42): which TEST TREE was this baseline built against?
//
// decision 35 stamped `key_format`, which catches a baseline of the wrong
// SHAPE.  It does not catch a baseline of the right shape built against a
// different tree, and MEASURED (v115) that is not hypothetical: with decision
// 43 applied and the baselines not yet rebuilt, R4 compared 1374 against 1370
// and ACCEPTED -- reading "the suite grew by four" where nothing had grown.
// Two such baselines were also produced by hand the same night (four controls
// 30 tests stale; six anchor-1 baselines built with the anchor oracle absent).
//
// The freeze manifest already hashes every test file, so reuse it rather than
// invent a second notion of "the tree".  `oracles` is folded in because the
// anchor-1 oracle lives there, not in tests_tree: manifest_s1 has 89 files and
// manifest_a1 has 90, which is exactly the mistake to catch.  The per-file
// CONTENT hash matters too -- tests added to an EXISTING file do not change the
// file set at all, and that was the other mistake.
function treeFingerprint(cfg) {
  if (!cfg.manifest) return null;
  const m = readJson(cfg.manifest);
  if (!m) return null;
  const tree = { ...(m.tests_tree || {}), ...(m.oracles || {}) };
  const files = Object.keys(tree).sort();
  if (!files.length) return null;
  const h = crypto.createHash("sha256");
  for (const f of files) h.update(f + "\u0000" + String(tree[f]) + "\u0000");
  return { digest: h.digest("hex").slice(0, 16), n_files: files.length, files };
}

// Returns null when the baseline is comparable, else why it is not.
// ONE direction refuses (B', decision 42): a baseline that knows FEWER files
// than the tree cannot see a failure in the ones it does not know -- silent
// blindness.  The other direction (tests gone) is R4's own job and gets a note,
// not a second kill.
function baselineTreeCheck(base, cfg) {
  const cur = treeFingerprint(cfg);
  if (!cur) return null;                      // no manifest: freeze already says so
  if (!base.tests_digest) {
    return { stop: true, reason: "baseline predates the tree stamp",
             baseline_digest: null, current_digest: cur.digest,
             detail: "This baseline was written before decision 42, so it does " +
                     "not record which test tree it was built against and " +
                     "cannot be checked for staleness.  Rebuild it with " +
                     "--build-baseline." };
  }
  // Checked BEFORE the digest shortcut: a baseline can carry the right digest
  // and still be wrong, because the digest is about the manifest and this is
  // about the tree that was on disk when the baseline ran.  MEASURED: in a
  // healthy build these two sets are identical (89/89 and 90/90, zero
  // difference either way), so a file the manifest lists but the baseline never
  // ran is a real anomaly, not normal slack.
  if (Array.isArray(base.ran_files)) {
    const ran = new Set(base.ran_files);
    const neverRan = cur.files.filter((f) => !ran.has(f));
    if (neverRan.length) {
      return {
        stop: true,
        reason: "baseline never ran every test file the manifest lists",
        baseline_n_ran_files: base.ran_files.length, current_n_files: cur.n_files,
        never_ran: neverRan.slice(0, 8), n_never_ran: neverRan.length,
        detail: "The baseline was built while these files were absent from the " +
                "tree, so nothing in them is in its passing set and R5 cannot " +
                "call a failure in them new.  MEASURED (v115): built this way, " +
                "the anchor-1 baselines held 1370 where the tree gives 1389, " +
                "and R4 compared 1389 against 1370 and passed.  Rebuild it " +
                "with --build-baseline, with the tree in the state the run " +
                "will use.",
      };
    }
  }
  if (base.tests_digest === cur.digest) return null;
  const had = new Set(base.test_files || []);
  const curSet = new Set(cur.files);
  const missingFromBaseline = cur.files.filter((f) => !had.has(f));
  const goneFromTree = (base.test_files || []).filter((f) => !curSet.has(f));
  if (missingFromBaseline.length === 0 && goneFromTree.length > 0) {
    return { stop: false, reason: "test files disappeared since the baseline",
             gone_from_tree: goneFromTree.slice(0, 8), n_gone: goneFromTree.length };
  }
  return {
    stop: true,
    reason: missingFromBaseline.length
      ? "baseline does not know every test file in this tree"
      : "baseline was built against a different test tree",
    baseline_digest: base.tests_digest, current_digest: cur.digest,
    baseline_n_files: base.n_test_files, current_n_files: cur.n_files,
    missing_from_baseline: missingFromBaseline.slice(0, 8),
    n_missing_from_baseline: missingFromBaseline.length,
    detail: "R4 asks `executed >= base.executed` and R5 counts a failure as new " +
            "only when that test is in the baseline passing set.  A baseline " +
            "built against a different tree answers both questions about the " +
            "wrong suite -- MEASURED (v115): a stale one made R4 compare 1374 " +
            "against 1370 and accept.  Rebuild it with --build-baseline.",
  };
}

/** Run a gate CLI and parse its JSON stdout.
 *  A gate whose output cannot be read is an ERROR, never a pass -- the whole
 *  point of this project is that an absent measurement is not "nothing is
 *  wrong" (§0-c, nine occurrences and counting). */
function gate(name, args, cwd, extraEnv = {}) {
  const t0 = now();
  const r = spawnSync(process.execPath, args, {
    cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, ...extraEnv },
  });
  let secs = +((now() - t0) / 1000).toFixed(2);
  // A negative duration means the clock moved, not that the gate was fast.
  // Say so rather than print an impossible number (v25).
  let clockWentBackwards = false;
  if (secs < 0) { clockWentBackwards = true; secs = 0; }
  let out = null;
  try { out = JSON.parse(r.stdout); } catch { /* handled below */ }
  if (out === null) {
    return {
      ok: false, secs, detail: {
        // ★v98 (decision 13, owner 2026-09-08): a gate that crashed produced no
        // verdict.  MEASURED (v96, first parser pass): diffgate threw on Babel's
        // File root, this detail was read as `pass: false`, and the crash was
        // reported as the hard killer `check5` -- the control S28 came back
        // "rejected by check5".  Filing it as COULD-NOT-RUN keeps acceptance
        // blocked (errored_gates blocks) and takes it out of killed_by_*.
        gate: name, pass: false, gate_could_not_run: true,
        error: "gate produced no parseable JSON",
        exit_code: r.status,
        stdout_tail: String(r.stdout || "").split("\n").slice(-8).join("\n"),
        stderr_tail: String(r.stderr || "").split("\n").slice(-8).join("\n"),
      },
    };
  }
  if (clockWentBackwards) out.clock_went_backwards = true;
  return { ok: out.pass === true, secs, detail: out, exit: r.status };
}

/** The files that call the anchor, as a 検査6 explanation source.
 *
 *  MEASURED (v23): a legitimate fix that introduced an allowlist escalated
 *  検査6 with nine unexplained literals, and every one of them was a key its own
 *  call sites already pass.  Those files are frozen (the patch does not touch
 *  them, and litgate excludes post_images from every source anyway), so reading
 *  them is not an attack surface -- and the set is far narrower than `tests`,
 *  which already contributes the whole frozen test tree.
 *
 *  Discovery is by name: any file under src/ that mentions the anchor function
 *  and is neither the anchor itself nor the oracle. */
function findCallers(repo, cfg) {
  const fn = cfg.anchor_func;
  if (!fn) return [];
  const anchorAbs = path.resolve(repo, cfg.anchor_file || "");
  const oracles = new Set((cfg.oracle_files || [])
    .map((o) => path.resolve(repo, o)));
  const out = [];
  // MEASURED (v24): written as "\b" in JS source this is the ESCAPE for
  // backspace, not a word boundary, so the regex matched nothing and caller
  // discovery silently returned zero files while 検査6 kept escalating.  The gate
  // now reports n_caller_files, which is how this was found.
  // ★v130 (decision 52, owner 2026-09-20): the anchor name is ESCAPED
  // before it goes into the regex, and the two word boundaries are spelled
  // out as lookaround.  This replaces the `String.fromCharCode(92) + "b"`
  // construction the v24 note above describes; the new form carries no
  // backslash at all in JS source, so nothing here can be re-read as a
  // string escape.
  // MEASURED (v128 zod re-run): with `$ZodCheckGreaterThan`, `re.source` was
  // `\b$ZodCheckGreaterThan\b`, the `$` an end-of-input anchor, and
  // n_caller_files stayed 0 although api.ts:908/919 call
  // `new checks.$ZodCheckGreaterThan(`.  Identifiers without `$` (all 44 実クライアント（Next.js／TS の業務ポータル）
  // anchors) get the same truth table from the lookaround form.
  // ⛔ `$` IS NOT IN THE LOOKAROUND CHARACTER CLASS, and must not be
  //   added to it.  JS counts `$` as a NON-word character, so under the old
  //   form `$anchorC(` was a match.  Putting `$` into
  //   `[A-Za-z0-9_]` here would make the lookbehind fail at exactly that
  //   position and drop the caller -- it would MOVE THE DEFAULT.  The class
  //   is the word class, nothing more.
  // ⛔ THE OLD `fn.replace(/[^A-Za-z0-9_$]/g, "")` DELETED characters,
  //   and it is gone.  Deleting is not escaping: it silently searched for a
  //   DIFFERENT name.  READ (2026-09-20, the 44 cfgs this driver runs, under
  //   vf/orch2 and vf/orch58): every `anchor_func` there is `[A-Za-z0-9_]`
  //   only, so for all 44 the old and the new form build the same pattern
  //   body out of the same characters.
  // ⛔ NOT MEASURED HERE: no claim is made about any repository's caller
  //   list actually changing.  zod454 is not run by the v130 driver.
  // ⛔ Lookbehind needs V8 6.2+ (Node 8.3+).  This harness runs Node v22.
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp("(?<![A-Za-z0-9_])" + esc(fn) + "(?![A-Za-z0-9_])");
  const walk = (dir) => {
    let ents = [];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (e.name === "node_modules" || e.name.startsWith(".")) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (!/\.(m|c)?[jt]sx?$/.test(e.name)) continue;
      const abs = path.resolve(p);
      if (abs === anchorAbs || oracles.has(abs)) continue;
      let src = "";
      try { src = fs.readFileSync(p, "utf8"); } catch { continue; }
      if (re.test(src)) out.push(p);
    }
  };
  // ★v127 (decision 48): WHERE the callers live.
  // MEASURED (v124, zod): this was the literal "src".  zod is a monorepo
  // whose sources sit at packages/zod/src, so there is no <repo>/src at
  // all -- the walk started at a directory that does not exist and caller
  // discovery returned 0 files.
  // ⛔ The default ["src"] walks the SAME one directory in the same order,
  //   so every repository that worked before yields the same caller list.
  //   Nothing else about 検査6 moved.
  for (const d of (cfg.source_dirs || ["src"])) walk(path.join(repo, d));
  return out;
}

/** Install a set of images into the repo; returns a restore(). */
// ★v108 (decision 30): 検査4 chooses its mutation range with
// `git diff -U0 <base_ref>` against a tree that has the POST image installed.
// That range is the patch's range ONLY IF <base_ref>'s version of each file is
// the PRE image.  MEASURED (v108): on 実クライアント it is, for all 57 cfgs -- 36 sit at
// HEAD (the clone is parked at pre) and 21 name a `refs/vf/pre/<name>` ref
// (the controls, whose pre is a parent commit).  On the valibot clone it was
// NOT: HEAD is the fixed code, so the diff was empty and 検査4 reported a
// pass-shaped "no changed source lines vs HEAD".  Check it, do not assume it.
function baseRefMismatch(repo, cfg) {
  const ref = cfg.base_ref || "HEAD";
  const bad = [];
  for (const [rel, src] of Object.entries(cfg.pre_images || {})) {
    const r = spawnSync("git", ["show", ref + ":./" + rel],
                        { cwd: repo, encoding: "buffer", maxBuffer: 64 * 1024 * 1024 });
    if (r.status !== 0) { bad.push({ file: rel, why: "not in " + ref }); continue; }
    const norm = (b) => String(b).replace(/\r\n/g, "\n");
    let pre;
    try { pre = fs.readFileSync(src); } catch { bad.push({ file: rel, why: "pre image unreadable" }); continue; }
    if (norm(r.stdout) !== norm(pre)) bad.push({ file: rel, why: "differs from the pre image" });
  }
  return bad;
}

function installImages(repo, images) {
  const saved = new Map();
  for (const [rel, src] of Object.entries(images || {})) {
    const dst = path.join(repo, rel);
    saved.set(dst, fs.existsSync(dst) ? fs.readFileSync(dst, "utf8") : null);
    fs.copyFileSync(src, dst);
  }
  return () => {
    for (const [dst, prev] of saved) {
      if (prev === null) fs.rmSync(dst, { force: true });
      else fs.writeFileSync(dst, prev, "utf8");
    }
  };
}

// --------------------------------------------------------------------------- //
// vitest
// --------------------------------------------------------------------------- //
// ★v127 (decision 48): WHICH vitest binary.  The path
// node_modules/vitest/vitest.mjs was written as a literal here, in
// mutgate.mjs and in ambgate.mjs.  (drive.mjs has three more and is NOT
// part of this change.)
// ⛔ VITEST_BIN starts at that exact literal and is reassigned only when a
//   cfg carries `vitest_bin`, so with no such key the spawned argv is
//   byte-identical to what it was before.
const VITEST_BIN_DEFAULT = "node_modules/vitest/vitest.mjs";
let VITEST_BIN = VITEST_BIN_DEFAULT;

function vitest(repo, targets, { seed = null, outFile } = {}) {
  // ★v110 (decision 33): outFile may now be an ABSOLUTE path outside the
  // repository.  path.join(repo, "/abs") would silently produce repo+/abs.
  const outAbs = path.isAbsolute(outFile) ? outFile : path.join(repo, outFile);
  const args = [path.join(repo, VITEST_BIN), "run",
                ...targets, "--root", ".",
                "--reporter=json", "--outputFile", outAbs];
  if (seed !== null) args.push("--sequence.shuffle", "--sequence.seed", String(seed));
  const r = spawnSync(process.execPath, args,
    { cwd: repo, encoding: "utf8", maxBuffer: 128 * 1024 * 1024 });
  const j = readJson(outAbs);
  if (!j) {
    return { ok: false, error: "vitest produced no JSON report",
             exit: r.status,
             stderr_tail: String(r.stderr || "").split("\n").slice(-10).join("\n"),
             outcomes: null, n: 0, failed: [] };
  }
  // ★v113 (decision 35): key by FILE and name, not by name alone.
  // MEASURED (v109): keyed by fullName, 実クライアント collapses 1388 assertions into 1384
  // names and valibot 3226 into 3191 -- `it.each` cases that share a name,
  // inside a single file in every case.  R4 asks "did the suite shrink" with
  // `executed >= base.executed`, and it was comparing the COLLAPSED count, so a
  // duplicate-named test could vanish (or appear) unseen.
  // ★v115 (decision 43): count the RAW assertions too.  MEASURED: keying by
  // file::fullName (decision 35) separated nothing on this repository, because
  // both duplicated names are `it.each` siblings INSIDE ONE FILE -- and a
  // same-file duplicate cannot be separated by any key.  What is left over is
  // invisible to R4: hono 1039 assertions (a fifth of its suite), valibot 12,
  // 実クライアント 4.  Demonstrated on a real report by deleting one of three identical
  // siblings:  raw 1389 -> 1388 (R4 catches it), keys 1385 -> 1385 (R4 passes).
  // `executed` is R4's "did the suite shrink" number, so it takes n_raw; the
  // keyed map stays for R5's "which test newly failed", a different question.
  const outcomes = {};
  const failed = [];
  const messages = [];
  let n_raw = 0;
  for (const suite of j.testResults || []) {
    const f = suite.name ? path.relative(repo, suite.name) : "?";
    for (const a of suite.assertionResults || []) {
      n_raw += 1;
      const key = f + "::" + a.fullName;
      outcomes[key] = a.status;
      if (a.status === "failed") {
        failed.push(key);
        messages.push(...(a.failureMessages || []));
      }
    }
  }
  const n = Object.keys(outcomes).length;
  return { ok: n > 0 && failed.length === 0, exit: r.status, outcomes, n, n_raw,
           failed,
           messages, error: n === 0 ? "vitest collected 0 tests" : null };
}

// classification for 検査3 -- ported from check3.mjs.  A revert that makes T
// fail with a TypeError/ImportError is NOT evidence that T tests the fix; it is
// 攻撃#5 (a false dependency on a symbol the patch introduced).
const GENUINE = [/Property failed after/i, /AssertionError/i, /expected .* to (be|equal)/i];
const BOGUS = [/TypeError: .* is not a function/i, /ReferenceError/i,
               /does not provide an export named/i,
               /Cannot find module|Failed to resolve import/i,
               /Cannot read propert(y|ies) of undefined/i];

// --------------------------------------------------------------------------- //
// baseline
// --------------------------------------------------------------------------- //
function buildBaseline(cfg) {
  const repo = cfg.repo;
  const restore = installImages(repo, cfg.pre_images);
  try {
    const v = vitest(repo, [], { outFile: scratchPath(repo, "baseline.json") });
    if (!v.outcomes) throw new Error(v.error + " :: " + v.stderr_tail);
    const passing = Object.entries(v.outcomes)
      .filter(([, s]) => s === "passed").map(([k]) => k);
    const fp = treeFingerprint(cfg);
    // ★v117b (decision 42): the digest above describes the MANIFEST.  The
    // manifest cannot say which files actually RAN, and that is the other half
    // of the mistake -- MEASURED (v115): six anchor-1 baselines were built with
    // the anchor oracle absent from the tree, so they ran 89 of the 90 files
    // their manifest lists, with the same cfg and therefore the same digest.
    const ranFiles = [...new Set(Object.keys(v.outcomes || {})
                                   .map((k) => k.split("::")[0]))].sort();
    const out = { executed: v.n_raw, n_keys: v.n, passing, n_passing: passing.length,
                  ran_files: ranFiles, n_ran_files: ranFiles.length,
                  built_from: "pre_images",
                  // ★v117 (decision 42): stamp WHICH TREE this was built against.
                  tests_digest: fp ? fp.digest : null,
                  n_test_files: fp ? fp.n_files : null,
                  test_files: fp ? fp.files : null,
                  // ★v113 (decision 35): a baseline written before the key
                  // change holds bare fullNames, which match nothing now.  It
                  // would not fail loudly -- basePass would simply match
                  // nothing, no failure could ever be "new", and R5 would go
                  // silently blind.  Stamp the format so R5 can refuse it.
                  key_format: KEY_FORMAT };
    fs.mkdirSync(path.dirname(cfg.baseline), { recursive: true });
    fs.writeFileSync(cfg.baseline, JSON.stringify(out, null, 1), "utf8");
    return out;
  } finally { restore(); }
}

// --------------------------------------------------------------------------- //
// the pipeline
// --------------------------------------------------------------------------- //
function runOne(cfg, profile) {
  const repo = cfg.repo;
  const res = {
    name: cfg.name, profile, engine: "run_gates.mjs (JS/TS)",
    gates: {}, cost_s: {}, notes: [],
    // A gate that did not run must leave a trace.  Absence from `gates` reads
    // as "not a killer", which is one inference away from "fine" -- the shape
    // this project has now recorded ten times (§0-c).  Same key as
    // run_gates3.py so the Python readers see it too.
    skipped_gates: [],
  };
  const oracleTargets = cfg.oracle_files || [];
  if (!oracleTargets.length) {
    res.notes.push("no oracle files given -- 検査2/3 cannot run");
  }

  const restorePost = installImages(repo, cfg.post_images);
  try {
    // ---- freeze ---------------------------------------------------------- //
    if (!cfg.manifest) res.skipped_gates.push({ gate: "freeze", why: "no manifest given" });
    if (cfg.manifest) {
      // ★v66 (decision 1, step 2): the spec goes to freeze too.  MEASURED
      // (v65): flipping `decides` in a copy of the spec removed 検査8's kill
      // and freeze said nothing, because the spec is outside the repo and
      // outside the manifest.  Passing it lets freeze catch both an edited
      // spec and a cfg re-pointed at a different one.
      const g = gate("freeze", [path.join(HERE, "freeze.mjs"), "verify",
                                "--repo", ".", "--manifest", cfg.manifest,
                                "--registry", cfg.registry,
                                ...(cfg.anchor_spec ? ["--spec", cfg.anchor_spec] : []),
                                // ★v118 (decision 44): the finding goes to
                                // freeze too -- 検査6 explains literals with it.
                                ...(cfg.finding_file ? ["--finding", cfg.finding_file] : [])],
                     repo);
      res.gates.freeze = g.ok; res.freeze = g.detail; res.cost_s.freeze = g.secs;
      // ★v78 (本人決裁 2026-08-30): a run that USES a spec the freeze never
      // checked is not a pass.  freeze.mjs's own note says "do not read this as
      // a pass" and the machine read it as one.  MEASURED (v76): S28 came back
      // accepted:true with specs_frozen:false under BOTH profiles, and freeze
      // reported zero violations.  This is §0-c ("not measured" standing in for
      // "no anomaly") surviving inside our own instrument.
      // Reachability was measured too: rebuilding a manifest today WITHOUT
      // --spec fails loudly (specs: ADDED); only a manifest built before v66
      // slips through, and 13 of those are on disk.  Blast radius at the time
      // of the change: 0 shipping variants (all 18 spec-using ones are frozen).
      // Filed as could-not-run, not as a kill: the freeze did not judge this
      // spec, it never looked at it.
      // ★v118 (decision 44): same rule as v78 for specs -- a run that USES a
      // finding the freeze never checked is not a pass.  Filed as could-not-run,
      // not as a kill: the freeze did not judge this finding, it never looked.
      if (g.detail && g.detail.findings_frozen === false) {
        res.gates.freeze = false;
        res.freeze = { ...g.detail, gate_could_not_run: true,
          fail_reason: "the finding this run uses was never checked -- this "
                     + "manifest predates finding freezing.  検査6 reads that "
                     + "text as an explanation source.  Rebuild it with "
                     + "--finding before reading any verdict off this run." };
      }
      if (g.detail && g.detail.specs_frozen === false) {
        res.gates.freeze = false;
        res.freeze = { ...g.detail, gate_could_not_run: true,
          fail_reason: "the spec this run uses was never checked -- this "
                     + "manifest predates spec freezing.  Rebuild it with "
                     + "--spec before reading any verdict off this run." };
      }
    }

    // ---- 検査2: T passes on the patched tree ------------------------------ //
    const t0 = now();
    const byOracle = {};
    let allPass = oracleTargets.length > 0;
    for (const o of oracleTargets) {
      const v = vitest(repo, [o], { outFile: scratchPath(repo, "check2.json") });
      byOracle[o] = v.ok;
      if (!v.ok) allPass = false;
      res.check2_detail = { ...(res.check2_detail || {}), [o]: {
        n_tests: v.n, failed: v.failed.slice(0, 8), error: v.error } };
    }
    res.check2_by_oracle = byOracle;
    res.gates.check2 = allPass;
    res.cost_s.check2 = +((now() - t0) / 1000).toFixed(2);

    // ---- 検査3: revert the fix, T must fail again, behaviourally ---------- //
    // 検査1 ("the oracle fails on the bug") and 検査3 ("revert and it fails
    // again") are the same measurement when the pre image IS the bug, which is
    // the case for a single-patch run.  Both keys are written, and the fact
    // that they came from one run is recorded rather than implied.
    {
      const s0 = now();
      const restorePre = installImages(repo, cfg.pre_images);
      let v;
      try { v = vitest(repo, oracleTargets, { outFile: scratchPath(repo, "check3.json") }); }
      finally { restorePre(); }
      const msgs = v.messages || [];
      const genuine = msgs.some((m) => GENUINE.some((re) => re.test(m)));
      const bogus = msgs.some((m) => BOGUS.some((re) => re.test(m)));
      const collected = v.n > 0;
      const anyFailed = (v.failed || []).length > 0;
      const ok = collected && anyFailed && genuine && !bogus;
      res.gates.check3 = ok;
      res.check1_oracle_fails_on_bug = ok;
      res.check3 = {
        collected, n_tests: v.n, n_failed: (v.failed || []).length,
        failed_ids: (v.failed || []).slice(0, 8),
        genuine_behavioural_failure: genuine, structural_error: bogus,
        same_measurement_as_check1: true,
        reason: !collected ? "oracle produced no test results"
              : !anyFailed ? "oracle STILL PASSED on the pre image -- it does not test the fix"
              : bogus ? "oracle failed STRUCTURALLY (TypeError/import), not behaviourally -- 攻撃#5"
              : !genuine ? "failure could not be classified as behavioural"
              : null,
        sample_message: String(msgs[0] || "").slice(0, 200),
      };
      res.cost_s.check3 = +((now() - s0) / 1000).toFixed(2);
    }

    // ---- 検査4: mutation ---------------------------------------------------- //
    // ★v33: `check4_in_fast` exists because the fast/strict split was inherited
    // from PYTHON's cost profile and does not match this one.  Measured here:
    //   check4 7.6-11.2s | check8 31-39s | check9 30s | check12 57-66s
    // 検査4 is the CHEAPEST of the heavy gates in the JS harness, and it is the
    // only one `fast` drops.  It is also the one gate that does not enumerate an
    // axis, which is why it keeps being the only thing that reaches attacks
    // built at the boundary of somebody else's list (v19, N12, N13).
    // ★v35: ON IN `fast` BY DEFAULT (decided by the user on the v34 numbers).
    // Measured across all eleven variants: fast+検査4 rejects every one of the
    // ten real attacks and accepts the control (12 mutants, 12 killed, 0
    // survived), at 99-121s with 検査4 itself 5.6-9.9s.  Without it, N12 and
    // N13 walk through.  Set `check4_in_fast: false` to opt a run back out.
    //
    // WHAT `fast` NOW MEANS HERE: strict MINUS 検査12.  It is no longer
    // D15's "strict minus 検査4" -- that ratio was measured on PYTHON, where
    // 検査4 is ~60% of strict.  In this harness 検査4 is 6-11s and 検査12 is
    // 57-66s, so the gate worth dropping for speed is the other one.
    // The Python side is unchanged; the two profiles no longer mean the same
    // thing, and that is deliberate and recorded (HANDOFF 0-e, 0-h).
    if (profile === "strict" || cfg.check4_in_fast !== false) {
      // ★v108 (decision 30): refuse to mutate a range measured from the wrong
      // baseline.  See baseRefMismatch above.
      const mism = baseRefMismatch(repo, cfg);
      if (mism.length) {
        res.gates.check4 = false;
        res.check4 = {
          gate: "check4_mutation", pass: false, gate_could_not_run: true,
          reason: "base_ref does not hold the pre image",
          base_ref: cfg.base_ref || "HEAD", mismatched: mism,
          detail: "検査4 takes its mutation range from `git diff " +
                  (cfg.base_ref || "HEAD") + "` with the post image installed. " +
                  "That is the patch's range only if that ref holds the PRE " +
                  "image, and here it does not -- so the range would be measured " +
                  "against the wrong baseline.  This gate did not reject the " +
                  "patch; it could not run.  Fix: point `base_ref` at a ref " +
                  "holding the pre state (the controls use refs/vf/pre/<name>).",
          survivors_reached: [], survivors_unreached: [],
        };
        res.cost_s.check4 = 0;
      } else {
      const g = gate("check4", [path.join(HERE, "mutgate.mjs"), repo,
                                cfg.base_ref || "HEAD", oracleTargets.join(","),
                                // ★v125 (decision 46): default ["src"] keeps every
                                // existing repository byte-identical.
                                (cfg.source_dirs || ["src"]).join(","),
                                // ★v127 (decision 48): argv[6] = WHICH vitest
                                // binary, argv[7] = WHICH package.json
                                // `typescript` is resolved from.  Both defaults
                                // are the exact literals mutgate.mjs used, so
                                // with no cfg key it spawns the same binary and
                                // requires the same module as before.
                                VITEST_BIN,
                                cfg.typescript_from || "package.json"], repo);
      res.gates.check4 = g.ok; res.check4 = g.detail; res.cost_s.check4 = g.secs;
      // shape the witness the way fp_to_oracle.py reads it
      const surv = (g.detail.survivors || []).map((s) => {
        const m = /^(.*?):(\d+)\s+(\S+)/.exec(s) || [];
        return { file: m[1], start_row: m[2] ? +m[2] : null, operator: m[3],
                 note: /NoCoverage/.test(s) ? "NoCoverage" : null, raw: s };
      });
      res.check4.survivors_reached = surv.filter((s) => !s.note);
      res.check4.survivors_unreached = surv.filter((s) => s.note);
      }
    } else {
      res.skipped_gates.push({ gate: "check4",
        why: "check4_in_fast is explicitly false for this run" });
      res.notes.push("検査4 skipped (profile=fast).  v19 measured 2 of 4 attacks " +
                     "on real client code that ONLY 検査4 caught, with a " +
                     "first-draft T.  D15's default was measured against an " +
                     "oracle hardened over twelve rounds.");
    }

    // ---- 検査5: differential oracle --------------------------------------- //
    // ★v44: 検査5 was never "not ported" -- diffgate.mjs has shipped since v17.
    // It never RAN on 実クライアント because nothing built it a cfg, and its own corpus is
    // wired to two CCD module paths by name (HANDOFF §0-j-5: an unwired gate was
    // described as a limit of principle).  The anchor spec is the input
    // generator it was missing, and it is the same one 検査8/12 already use.
    if (cfg.diffgate_cfg) {
      const g = gate("check5", [path.join(HERE, "diffgate.mjs"), cfg.diffgate_cfg], repo);
      res.gates.check5 = g.ok; res.check5 = g.detail; res.cost_s.check5 = g.secs;
    // ★v45 (2026-08-26, 本人判断): OPT-IN, not on by default.  Turning it on
    // costs and buys nothing MEASURED HERE: 検査5 passed all eleven attacks
    // (zero kills added) and flipped S26_date_validation from accepted to
    // rejected, because diffgate's "a real behaviour fix changes the value but
    // not the type" rule was written for CCD (prototype pollution turning a
    // boolean return into a function) and a "add validation" fix in real client
    // code legitimately changes the type (returns a string -> throws).
    // ⚠ That is NOT evidence the gate is useless.  In the PYTHON corpus check5
    // is the SOLE killer of six entries (A7a/A7b_side_effect, C4_uncovered_sidefx,
    // D9_dilution, Y3_consistent_lie_passed, R3_sibling_function) -- attacks no
    // other gate stops.  The JS corpus simply has no attack of that shape yet,
    // which is §0-d's trap, not a verdict on the gate.
    // ★So the order is: write the attack first, then turn it on.  §12-A6.
    } else if (cfg.anchor_spec && cfg.check5_from_spec === true) {
      const dgCfg = scratchPath(repo, "diffgate.cfg.json");
      fs.mkdirSync(path.dirname(dgCfg), { recursive: true });
      fs.writeFileSync(dgCfg, JSON.stringify({
        repo, anchor_file: cfg.anchor_file, anchor_func: cfg.anchor_func,
        spec: readJson(cfg.anchor_spec), spec_source: cfg.anchor_spec,
        pre_images: cfg.pre_images, post_images: cfg.post_images,
      }), "utf8");
      const g = gate("check5", [path.join(HERE, "diffgate.mjs"), dgCfg], repo);
      res.gates.check5 = g.ok; res.check5 = g.detail; res.cost_s.check5 = g.secs;
    } else {
      res.skipped_gates.push({
        gate: "check5",
        why: !cfg.anchor_spec
          ? "no diffgate_cfg and no anchor_spec -- 検査5 needs concrete inputs "
          + "and must not invent them"
          : "check5_from_spec is not true for this run (opt-in since v45; see §12-A6)",
        note: "MEASURED (v19, and mis-explained until v44): the built-in corpus " +
              "is CCD path strings bound to two CCD modules by name, so on any " +
              "other repository it compares nothing.  That is a missing input " +
              "generator, not a limit of principle.",
      });
    }

    // ---- 検査6: unexplained literal (ESCALATE-only) ----------------------- //
    {
      // ★v118 (decision 44, part D): record WHICH finding text explained
      // things, so a later reader can ask whether it was the same one.
      res.finding_sha = cfg.finding_file && fs.existsSync(cfg.finding_file)
        ? crypto.createHash("sha256")
            .update(fs.readFileSync(cfg.finding_file)).digest("hex").slice(0, 16)
        : null;
      const litCfg = scratchPath(repo, "litgate.cfg.json");
      fs.mkdirSync(path.dirname(litCfg), { recursive: true });
      fs.writeFileSync(litCfg, JSON.stringify({
        repo,                       // so litgate can exclude the live-tree
                                    // location of every patched file
        pre_images: cfg.pre_images, post_images: cfg.post_images,
        finding_file: cfg.finding_file, finding_text: cfg.finding_text,
        oracle_files: oracleTargets.map((o) => path.join(repo, o)),
        tests_dirs: cfg.tests_dirs || [],
        caller_files: cfg.caller_files || findCallers(repo, cfg),
        anchor_func: cfg.anchor_func,
      }), "utf8");
      // `callsites` is ON here, though litgate's own default leaves it off so
      // the Python and JS gates stay identical when invoked directly.
      //
      // MEASURED (v24), two anchors, five variants: the legitimate allowlist
      // fix goes from nine unexplained literals to zero, and no attack loses a
      // signal it had -- N1_hardcode keeps its 80-character key and M1_hardcode
      // keeps its 69.  N5_ambient goes quiet too, but it was already quiet:
      // its 'production' was explained by the frozen test tree before this
      // change existed, which is worth knowing on its own (see the v24 report).
      const g = gate("check6", [path.join(HERE, "litgate.mjs"), litCfg,
                                "--sources", cfg.check6_sources ||
                                "pre,finding,oracle,tests,callsites"], repo);
      res.gates.check6 = g.ok; res.check6 = g.detail; res.cost_s.check6 = g.secs;

      // ---- 検査7: unexplained classification / ambient API (ESCALATE-only) -- //
      // Same cfg shape.  MEASURED (v19-v21): M5_ambient was killed by 検査4 and
      // nothing else for three rounds, and 検査4 does not run in `fast`.
      const g7 = gate("check7", [path.join(HERE, "apigate.mjs"), litCfg,
                                 cfg.check7_groups || "classify,ambient"], repo);
      res.gates.check7 = g7.ok; res.check7 = g7.detail; res.cost_s.check7 = g7.secs;
    }

    // ---- 検査9: ambient invariance sweep (FAIL, strict only) -------------- //
    // MEASURED (v22): M7_ambient_zero_new introduces no new name, no new
    // literal and no new ambient key, so 検査6 and 検査7 are structurally blind
    // to it -- both work on a diff, and it reuses what was already there.  This
    // gate feeds values back IN rather than reading them OUT, and caught it at
    // tier 1.  It costs a pair of oracle runs per setting, so it is strict-only.
    // 検査9 runs in BOTH profiles (decided 2026-08-24, v26).
    //
    // It used to be strict-only because it cost 90s.  v25 took that to 34-42s
    // -- one oracle run per harvested setting -- and made "every harvested
    // setting was probed" a stated guarantee rather than a budget's accident.
    // What `fast` bought by skipping it was measured three times: M7 walked
    // through it completely, and M5 and N5 got no further than an escalation.
    // 検査9 is the only gate other than mutation that hard-rejects an
    // ambient-keyed attack, so `fast` without it is fast and undefended against
    // that whole family.
    //
    // The side effect is worth stating: JS `fast` is now exactly "strict minus
    // 検査4", which is the Python definition.  The two were quietly different
    // before, for a cost reason that no longer holds.
    // ---- 検査13: the patch must not introduce a type error ---------------- //
    // ★v104 (decision 20, owner 2026-09-10).  MEASURED (v100): a patch whose
    // only defect was a type annotation was accepted by all of 検査2-12 and
    // R4/R5 in both profiles, because vitest does not typecheck.  The gate is
    // DIFFERENTIAL -- this repository has 3 type errors of its own, and a gate
    // judging the absolute count would be judging the repo, not the patch.
    if (cfg.check13 !== false) {
      const tgCfg = scratchPath(repo, "typegate.cfg.json");
      fs.mkdirSync(path.dirname(tgCfg), { recursive: true });
      fs.writeFileSync(tgCfg, JSON.stringify({
        repo, pre_images: cfg.pre_images, post_images: cfg.post_images,
        tsconfig: cfg.tsconfig || "tsconfig.json",
      }), "utf8");
      const g13 = gate("check13", [path.join(HERE, "typegate.mjs"), tgCfg], repo);
      res.gates.check13 = g13.ok; res.check13 = g13.detail; res.cost_s.check13 = g13.secs;
    } else {
      res.skipped_gates.push({
        gate: "check13",
        why: "disabled by cfg (check13=false)",
        note: "MEASURED (v100): without it, a type-error-only patch is accepted.",
      });
    }

    const wantCheck9 = cfg.check9 !== false && cfg.check9_in_fast !== false;
    if (wantCheck9) {
      const ambCfg = scratchPath(repo, "ambgate.cfg.json");
      fs.mkdirSync(path.dirname(ambCfg), { recursive: true });
      fs.writeFileSync(ambCfg, JSON.stringify({
        repo, pre_images: cfg.pre_images, post_images: cfg.post_images,
        oracle_files: oracleTargets,
        // ★v127 (decision 48): the same VITEST_BIN this process uses.  With no
        // cfg key this is the literal ambgate already had, so 検査9 spawns the
        // same binary.  (This cfg lives in scratch, outside the repo -- v110.)
        vitest_bin: VITEST_BIN,
        // the budget buys TAIL only; the harvested tiers are always probed
        amb_budget_s: cfg.amb_budget_s || 30,
      }), "utf8");
      const g9 = gate("check9", [path.join(HERE, "ambgate.mjs"), ambCfg], repo);
      res.gates.check9 = g9.ok; res.check9 = g9.detail; res.cost_s.check9 = g9.secs;
    } else {
      res.skipped_gates.push({
        gate: "check9",
        why: "disabled by cfg (check9=false or check9_in_fast=false)",
        note: "検査9 is the only JS gate that reaches an attack built entirely out "
            + "of names and literals the pre image already contained (v22, M7).",
      });
    }

    // ---- 検査12: observed-key harvest (FAIL, needs an anchor spec) -------- //
    // MEASURED (v28): this is the only gate that reaches N9_derived_prefix,
    // whose key exists as no literal anywhere.  All nine others pass it in
    // `fast`, and in `strict` only 検査4 catches it.  It costs ~105s because it
    // drives the anchor through vitest, so it is strict-only for now and off
    // unless a spec is supplied -- an input-driven gate with no spec must say
    // it cannot run, not invent inputs.
    if (cfg.anchor_spec && (profile === "strict" || cfg.check12_in_fast === true)) {
      const spyCfg = scratchPath(repo, "spygate.cfg.json");
      fs.mkdirSync(path.dirname(spyCfg), { recursive: true });
      fs.writeFileSync(spyCfg, JSON.stringify({
        repo, anchor_file: cfg.anchor_file, anchor_func: cfg.anchor_func,
        spec: readJson(cfg.anchor_spec), spec_source: cfg.anchor_spec,
        pre_images: cfg.pre_images, post_images: cfg.post_images,
        max_rounds: cfg.spy_rounds || 3,
        // ★v92 (decision 6): no default cap (spygate defaults to none); the
        // frozen oracle files feed the oracle-literal filter.
        max_candidates: cfg.spy_candidates || undefined,
        oracle_files: cfg.oracle_files || [],
      }), "utf8");
      const g12 = gate("check12", [path.join(HERE, "spygate.mjs"), spyCfg], repo);
      res.gates.check12 = g12.ok; res.check12 = g12.detail; res.cost_s.check12 = g12.secs;
    } else {
      res.skipped_gates.push({
        gate: "check12",
        why: !cfg.anchor_spec ? "no anchor_spec given -- this gate drives the anchor "
             + "with chosen inputs and cannot invent them"
             : "profile=fast (set check12_in_fast; it costs ~105s)",
        note: "MEASURED (v28): the only gate that reaches an attack whose key "
            + "exists as no literal anywhere (N9_derived_prefix).",
      });
    }

    // ---- 検査8: metamorphic equivalence-class sweep (v29) ------------------ //
    // MEASURED (v29) before this gate existed: N10_codepoint_class hides the
    // backdoor in a REGEX LITERAL over a non-ASCII range and walks through
    // `fast` with nothing killed and nothing escalated, while `strict` catches
    // it on 検査4 alone.  Every static gate is blind by construction --
    // litgate excludes regex literals outright, and 檢査12's spy patches
    // String.prototype, which RegExp.test never touches (n_spied was 0).
    //
    // Unlike every other gate here this one does not name what it is looking
    // for: it sweeps 0x0000..0x10FFFF exhaustively, so there is no enumeration
    // boundary to be attacked at.  It needs the same anchor spec 検査12 does.
    // ★v31: ON IN `fast` BY DEFAULT (decided by the user on the v30 numbers).
    // Before this, `fast` -- the profile that actually ships -- had NO defence
    // at all against a single-character-key backdoor: N10_codepoint_class went
    // through with nothing killed and nothing escalated.  Measured cost of
    // turning it on: 78s -> 115s per patch (+47%), with zero false positives on
    // the control.  Set `check8_in_fast: false` to opt a run back out.
    // What this does NOT buy: N11_two_char (a key needing two characters at
    // once) is still accepted in `fast` -- that is 検査8's declared limit, and
    // 検査4 (strict only) is the only thing that reaches it.
    if (cfg.anchor_spec && (profile === "strict" || cfg.check8_in_fast !== false)) {
      const mrCfg = scratchPath(repo, "mrgate.cfg.json");
      fs.mkdirSync(path.dirname(mrCfg), { recursive: true });
      fs.writeFileSync(mrCfg, JSON.stringify({
        repo, anchor_file: cfg.anchor_file, anchor_func: cfg.anchor_func,
        spec: readJson(cfg.anchor_spec), spec_source: cfg.anchor_spec,
        pre_images: cfg.pre_images, post_images: cfg.post_images,
        max_cp: cfg.mr_max_cp || 0x110000,
        precond_max_cp: cfg.mr_precond_max_cp || 0x800,
      }), "utf8");
      const g8 = gate("check8", [path.join(HERE, "mrgate.mjs"), mrCfg], repo);
      res.gates.check8 = g8.ok; res.check8 = g8.detail; res.cost_s.check8 = g8.secs;
    } else {
      res.skipped_gates.push({
        gate: "check8",
        why: !cfg.anchor_spec ? "no anchor_spec given -- this gate sweeps the "
             + "code-point axis of a template and cannot invent one"
             : "check8_in_fast is explicitly false for this run",
        note: "MEASURED (v29): the only gate that reaches a single-character "
            + "key written as a regex literal (N10_codepoint_class).  It does "
            + "NOT reach a key that needs two characters at once (N11, measured).",
      });
    }

    // ---- R5 / R4: determinism + the repo's own suite ---------------------- //
    {
      const s0 = now();
      const base = readJson(cfg.baseline);
      const treeChk = base ? baselineTreeCheck(base, cfg) : null;
      if (treeChk && !treeChk.stop) {
        res.notes.push("BASELINE TREE NOTE: " + treeChk.reason + " (" +
                       treeChk.n_gone + " file(s)).  R4 own count check owns " +
                       "this case; not refusing.");
      }
      if (!base) {
        // ★v108 (decision 29): this used to write `gates.R5 = gates.R4 = false`
        // -- a HARD kill -- on the line after writing "INERT" into the notes.
        // The note said "not measured", the verdict said "rejected".  That is
        // the shape decision 17 closed for crashed gates, left open here.
        // MEASURED (v107, valibot): a whole run was lost to it, and the verdict
        // read `killed_by_all: ['R5','R4']` with nothing to say no baseline
        // existed.  Acceptance is blocked either way; only the name changes.
        res.notes.push("NO BASELINE: R4/R5's suite-regression check is INERT. " +
                       "Run with --build-baseline first.");
        res.gates.R5 = false; res.gates.R4 = false;
        const why = {
          pass: false, gate_could_not_run: true, reason: "no baseline file",
          detail: "R4/R5 compare the repository's own suite against a baseline " +
                  "frozen on the PRE tree.  No baseline file was found, so " +
                  "nothing was compared -- this gate did not reject the patch. " +
                  "Build one with --build-baseline.",
        };
        res.R5 = { gate: "R5_determinism", ...why };
        res.R4 = { gate: "R4_suite", ...why };
        res.suite_regression = { inert: true, reason: "no baseline file" };
      } else if (treeChk && treeChk.stop) {
        // ★v117 (decision 42): same box as decisions 29 and 35 -- "I could not
        // check" must not look like "I checked and it was fine" (§0-c).
        res.notes.push("BASELINE TREE MISMATCH: " + treeChk.reason +
                       ".  baseline digest " + JSON.stringify(treeChk.baseline_digest) +
                       " vs this tree " + JSON.stringify(treeChk.current_digest) +
                       ".  Rebuild it with --build-baseline.");
        res.gates.R5 = false; res.gates.R4 = false;
        const why = { pass: false, gate_could_not_run: true, ...treeChk };
        res.R5 = { gate: "R5_determinism", ...why };
        res.R4 = { gate: "R4_suite", ...why };
        res.suite_regression = { inert: true, reason: treeChk.reason };
      } else if (base.key_format !== KEY_FORMAT) {
        // ★v113 (decision 35): the baseline on disk predates the key change.
        // Refuse rather than compare nothing -- this is the same box decision 29
        // put the missing baseline in, and for the same reason: "I could not
        // check" must not look like "I checked and it was fine" (§0-c).
        res.notes.push("BASELINE KEY FORMAT MISMATCH: baseline has " +
                       JSON.stringify(base.key_format || null) + ", this harness " +
                       "writes " + JSON.stringify(KEY_FORMAT) + ".  Rebuild it " +
                       "with --build-baseline.");
        res.gates.R5 = false; res.gates.R4 = false;
        const why = {
          pass: false, gate_could_not_run: true,
          reason: "baseline key format mismatch",
          baseline_key_format: base.key_format || null,
          expected_key_format: KEY_FORMAT,
          detail: "The baseline stores per-test outcomes keyed by test name. " +
                  "This harness now keys them by file and name (decision 35), " +
                  "so the stored names match nothing and NO failure could ever " +
                  "be counted as new.  That is silent blindness, not a pass. " +
                  "Rebuild the baseline with --build-baseline.",
        };
        res.R5 = { gate: "R5_determinism", ...why };
        res.R4 = { gate: "R4_suite", ...why };
        res.suite_regression = { inert: true, reason: "baseline key format mismatch",
                                 baseline_key_format: base.key_format || null };
      } else {
        const basePass = new Set(base.passing || []);
        const seeds = cfg.r5_seeds || [11, 22, 33];
        const runs = [];
        for (const seed of seeds) {
          const v = vitest(repo, [], { seed, outFile: scratchPath(repo, `r5_${seed}.json`) });
          const newFail = Object.entries(v.outcomes || {})
            .filter(([k, s]) => s === "failed" && basePass.has(k)).map(([k]) => k);
          runs.push({ seed, executed: v.n_raw, n_keys: v.n,
                      n_new_fail: newFail.length,
                      new_fail: newFail, ok: v.ok, error: v.error });
        }
        // ★v108 (decision 28): the baseline is built WITHOUT shuffling and the
        // runs above shuffle.  A repository whose own suite is order-dependent
        // therefore reports its own flakiness as "the patch broke it".
        // MEASURED (v107, valibot): three of valibot's tests fail under
        // --sequence.seed 11 on an UNTOUCHED clone, and they hard-killed the
        // legitimate control.
        //
        // 検査13 solved the same shape by subtracting what the pre image already
        // had.  Do that here too -- but lazily: only when a candidate failure
        // appears, and only for the seeds that produced one.  On a suite with no
        // order dependence this branch never runs and costs nothing.
        //
        // Deliberately NOT done by shuffling the baseline instead: a test that
        // fails in a shuffled baseline drops out of basePass, and then a REAL
        // regression in that test can never be reported again.  Subtracting per
        // failure keeps the watch set whole -- and names what was subtracted,
        // rather than dropping it silently.
        const preExisting = new Set();
        const withFailures = runs.filter((r) => r.n_new_fail > 0);
        let preCheckRuns = 0;
        if (withFailures.length) {
          const restorePre = installImages(repo, cfg.pre_images);
          try {
            for (const r of withFailures) {
              const pv = vitest(repo, [], { seed: r.seed,
                                            outFile: scratchPath(repo, `r5_pre_${r.seed}.json`) });
              preCheckRuns++;
              for (const t of r.new_fail) {
                if ((pv.outcomes || {})[t] === "failed") preExisting.add(t);
              }
            }
          } finally { restorePre(); }
          for (const r of runs) {
            r.pre_existing = r.new_fail.filter((t) => preExisting.has(t));
            r.new_fail = r.new_fail.filter((t) => !preExisting.has(t));
            r.n_new_fail = r.new_fail.length;
          }
        }
        const nNew = Math.max(0, ...runs.map((r) => r.n_new_fail));
        const collected = runs.every((r) => r.executed > 0);
        res.r5_runs = runs;
        res.suite_regression = {
          baseline_passing: basePass.size,
          n_new_fail_max: nNew,
          by_seed: Object.fromEntries(runs.map((r) => [r.seed, r.new_fail])),
          // what decision 28 subtracted, by name -- never a silent drop
          n_pre_existing: preExisting.size,
          pre_existing_failures: [...preExisting],
          pre_check_suite_runs: preCheckRuns,
        };
        res.r4_detail = { baseline: base.executed,
                          runs: runs.map((r) => r.executed), n_new_fail_max: nNew };
        // R5 = the suite still passes (no NEW failure); R4 = it still runs.
        // Both are false if nothing was collected -- a suite that did not run
        // is not a suite that passed.
        res.gates.R5 = collected && nNew === 0;
        res.gates.R4 = collected && nNew === 0 &&
                       runs.every((r) => r.executed >= base.executed);
      }
      res.cost_s["R5+R4"] = +((now() - s0) / 1000).toFixed(2);
    }
  } finally {
    restorePost();
  }

  // ---- verdict ----------------------------------------------------------- //
  // ★v29: "the gate REJECTED this patch" and "the gate COULD NOT RUN" are both
  // `pass:false`, and until now both landed in killed_by.  MEASURED: StrykerJS
  // refused to start on the wrong Node version, and check4 was reported as the
  // killer of all three variants -- INCLUDING THE CONTROL -- for three runs
  // before anyone read the stderr the gate had faithfully attached.  A patch
  // must still not be accepted when a hard gate could not run (fail closed),
  // but the report must not call that a kill: "measured and rejected" and
  // "never measured" are the distinction this whole project is about.
  // ★v61 (decision 1, C1): "could not run" and "does not apply here" were both
  // landing in errored_gates.  MEASURED (v58/v59): a gate with NO spec is
  // skipped and blocks nothing, while a gate whose spec says decides:false is
  // inapplicable and blocks acceptance -- the same epistemic state, opposite
  // verdicts, and deleting one line of cfg flipped a control from rejected to
  // accepted.  Three facts (rejected / could not run / does not apply) now get
  // three names.  ⛔ THE PASS CONDITION IS UNCHANGED: both still fail closed,
  // and `blocked` below is exactly the set the old single filter produced.
  const detail = (g) => res[g.split("@")[0]] || res[g];
  const isInapplicable = (g) => {
    const d = detail(g);
    return !!(d && typeof d === "object" && d.inapplicable === true);
  };
  const isCouldNotRun = (g) => {
    const d = detail(g);
    return !!(d && typeof d === "object" && d.gate_could_not_run === true);
  };
  const failed = Object.entries(res.gates)
    .filter(([, v]) => v === false).map(([g]) => g);
  // A gate that claims both is filed as inapplicable: "this gate cannot judge
  // this anchor" is a property of the situation, "it could not run" of the run.
  const inapplicable = failed.filter(isInapplicable);
  // ★v66 (decision 1, step 4): inapplicable splits in two, and the halves have
  // opposite risk profiles.
  //   BY DECLARATION -- the human-written spec says so (`decides:false`).  A
  //     property of the anchor; the patch cannot reach it.  Once the spec is
  //     frozen (step 2) this half could safely stop blocking.
  //   BY OUTCOME -- the run found its own precondition broken.  MEASURED (v63):
  //     N1_hardcode pins the allow-list, which moves every template baseline to
  //     the accepting side, and 検査12 reports "no template baseline sits on the
  //     rejecting side".  A PATCH induced that.  This half must keep blocking:
  //     otherwise a patch can disarm a hard gate by construction.
  // ⛔ Both still block today; this names them, it does not change the verdict.
  const byDeclaration = inapplicable.filter((g) => {
    const d = detail(g);
    return !!(d && d.inapplicable_by_declaration === true);
  });
  const byOutcome = inapplicable.filter((g) => !byDeclaration.includes(g));
  const errored = failed.filter((g) => !inapplicable.includes(g) && isCouldNotRun(g));
  const blocked = new Set([...errored, ...inapplicable]);
  const hard = failed.filter((g) => !blocked.has(g) &&
                                    !ESCALATE_ONLY.has(g.split("@")[0]));
  const esc = failed.filter((g) => !blocked.has(g) &&
                                   ESCALATE_ONLY.has(g.split("@")[0]));
  res.all_gates_passed = Object.values(res.gates).every((v) => v === true);
  res.killed_by_all = hard;
  res.killed_by = hard[0] || null;
  res.escalated = esc;
  // Fail closed, but each under its own name.
  res.errored_gates = errored;
  res.inapplicable_gates = inapplicable;
  res.inapplicable_by_declaration = byDeclaration;
  res.inapplicable_by_outcome = byOutcome;

  // ★v70 (decision 1, C2 second half) -- the ONE place acceptance is decided,
  // and the only change in this whole sequence that LOOSENS anything.
  //
  //   before : accepted = no hard kill AND nothing errored AND nothing inapplicable
  //   after  : accepted = no hard kill AND nothing errored AND nothing
  //            inapplicable BY OUTCOME
  //
  // Why the halves are treated differently, both measured:
  //   BY DECLARATION -- the spec says the anchor does not decide.  A patch
  //     cannot reach it, and since v66 the spec is inside the freeze; v68
  //     confirmed both tamper shapes are caught (specs: ADDED and MODIFIED).
  //   BY OUTCOME -- the run found its own precondition broken, and v63 measured
  //     a PATCH inducing exactly that (N1_hardcode pins the allow-list, every
  //     template baseline moves to the accepting side, 検査12 has nothing left to
  //     sweep).  Letting that through would hand a patch a way to disarm a hard
  //     gate by construction.
  //
  // `escalated` has never blocked (§0-h): 検査6/7 hand a patch to a human, they
  // do not reject it.
  // ⛔ The hard/escalate classification above is untouched -- an inapplicable
  // gate must not turn into a killer just because it stopped blocking.
  res.accepted = hard.length === 0 && errored.length === 0 && byOutcome.length === 0;
  if (errored.length)
    res.notes.push("★ " + errored.join(",") + " could not run -- the patch is "
      + "NOT accepted, but this is not a kill.  Read the gate's own diagnosis "
      + "before reading any verdict off this run.");
  if (byDeclaration.length)
    res.notes.push("★ " + byDeclaration.join(",") + " does not apply BY "
      + "DECLARATION -- the spec says this anchor does not decide, so the gate "
      + "has no verdict to sweep.  A property of the anchor, not of the patch, "
      + "and the spec is inside the freeze (v66/v68).  Since v70 this does NOT "
      + "block acceptance: read it as 'this gate had nothing to say here', not "
      + "as a pass it earned.");
  if (byOutcome.length)
    res.notes.push("★ " + byOutcome.join(",") + " does not apply BY OUTCOME -- "
      + "the run found its own precondition broken.  MEASURED (v63) that a "
      + "PATCH can induce this, so this half must keep blocking: read the "
      + "gate's fail_reason before reading anything else off this run.");
  res.n_gates_run = Object.keys(res.gates).length;
  res.n_gates_skipped = res.skipped_gates.length;
  return res;
}

// --------------------------------------------------------------------------- //
if (process.argv[2]) {
  const argv = process.argv.slice(2);
  const one = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };
  const cfg = JSON.parse(fs.readFileSync(argv[0], "utf8"));
  // ★v127 (decision 48): see VITEST_BIN above.  This is the only assignment;
  // an absent key leaves the old literal in place.
  VITEST_BIN = cfg.vitest_bin || VITEST_BIN_DEFAULT;

  if (argv.includes("--build-baseline")) {
    const b = buildBaseline(cfg);
    console.log(JSON.stringify({ built: cfg.baseline, executed: b.executed,
                                 n_passing: b.n_passing }, null, 1));
    process.exit(0);
  }

  const profile = one("--profile", cfg.profile || "strict");
  // v33: measuring a profile change across a whole corpus should not mean
  // writing a parallel copy of every cfg -- the copies drift, and then the
  // run and the file disagree about what was measured.
  if (argv.includes("--check4-in-fast")) cfg.check4_in_fast = true;
  if (argv.includes("--no-check8-in-fast")) cfg.check8_in_fast = false;
  const out = one("--out", cfg.out);
  const res = runOne(cfg, profile);

  if (out) {
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(path.join(out, cfg.name + ".json"),
                     JSON.stringify(res, null, 1), "utf8");
    // fp_to_oracle.py quotes source lines from the images the gates actually
    // ran, not from the repo working tree (v18).  Write them beside the result.
    const img = path.join(out, cfg.name + ".img");
    fs.mkdirSync(img, { recursive: true });
    fs.writeFileSync(path.join(img, "cfg.json"), JSON.stringify(
      { pre_images: cfg.pre_images, post_images: cfg.post_images }, null, 1), "utf8");
  }

  // ERROR is printed differently from FAIL on purpose (v29): the one-line
  // summary is what gets read, and it was the thing that made a start-up
  // failure look like a verdict.
  const line = Object.entries(res.gates)
    .map(([g, v]) => `${g}=${v === true ? "pass"
                            : (res.inapplicable_by_outcome || []).includes(g) ? "N/A-out"
                            : (res.inapplicable_gates || []).includes(g) ? "N/A-dec"
                            : (res.errored_gates || []).includes(g) ? "ERROR" : "FAIL"}`)
    .join(" ");
  console.error(`${cfg.name}  [${profile}]  ${line}`);
  console.error(`  ACCEPTED: ${res.accepted ? "yes" : "no"}`);
  console.error(`  gates run: ${res.n_gates_run}   skipped: ${
    res.skipped_gates.map((s) => s.gate).join(",") || "-"}   hard killers: ${
    res.killed_by_all.join(",") || "-"}   escalated: ${res.escalated.join(",") || "-"
    }   COULD NOT RUN: ${(res.errored_gates || []).join(",") || "-"
    }   N/A by declaration: ${(res.inapplicable_by_declaration || []).join(",") || "-"
    }   N/A by outcome: ${(res.inapplicable_by_outcome || []).join(",") || "-"}`);
  console.log(JSON.stringify(res, null, 1));
  process.exit(res.all_gates_passed ? 0 : 1);
}
